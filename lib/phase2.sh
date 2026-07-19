#!/usr/bin/env bash
# Phase 2: Cloud Asset Discovery
# Discovers AWS, Azure, and GCP assets associated with root domains.

run_phase2() {
    local pdir="${OUTPUT_DIR}/phase2"
    mkdir -p "$pdir"
    CURRENT_PHASE=2

    local root_domains_file="$1"
    local all_subdomains_file="$2"
    local live_web_file="$3"

    log_info "═══ PHASE 2: Cloud Asset Discovery ═══"

    # ── Stage 1: Amass Enum for Cloud Domains ───────────────────────────────
    # Per https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md
    # (verified against cmd/amass/enum.go):
    #
    #   enum         the subcommand for subdomain / asset enumeration
    #   -passive     purely passive — query CT logs / scraping / search
    #                engines, NO active DNS resolution. We want this here
    #                because Phase 1 already did the active work (ShuffleDNS
    #                brute force, Subfinder/Assetfinder scraping) and the
    #                bug-bounty methodology (Ars0n v2) uses passive Amass
    #                as the cloud-asset discovery step.
    #   -alts / -brute — opt-in flags, BOTH DEFAULT OFF. We deliberately
    #                do NOT pass them:
    #                - -brute does DNS brute force with Amass's built-in
    #                  wordlist; Phase 1 ShuffleDNS with our CeWL-derived
    #                  wordlist is far more targeted.
    #                - -alts generates FQDN alteration permutations;
    #                  Subfinder already covers those sources.
    #                (My prior commit passed `-noalts -nobrute` which are
    #                NOT registered flags and made Amass error out with
    #                "flag provided but not defined".)
    #   -nocolor     strip ANSI for clean log capture
    #   -timeout N   minutes of execution (default 5)
    #   -d DOMAIN    target root domain
    #   -rf FILE     path to a file of (untrusted) DNS resolvers
    #   -trf FILE    path to a file of trusted DNS resolvers (preferred
    #                for our use case — trickest's resolvers-trusted.txt
    #                is curated public resolvers, not random user-supplied
    #                ones, so -trf is the right semantic category).
    #                In -passive mode neither flag is actually consulted
    #                (passive skips DNS resolution), but we set -trf so
    #                Amass has the right resolver set if it ever falls
    #                back to active methods.
    #   -rqps N      max DNS queries-per-second per resolver (default 10)
    #   -log FILE    write the structured Amass log here so progress is
    #                visible — passive mode emits only findings to stdout
    #                and progress messages to stderr; without -log you
    #                see nothing for 10+ minutes and assume it's hung.
    #
    # We wrap the whole call in `timeout` (wall-clock cap, default 30 min
    # per root domain) so a single misbehaving data source or resolver
    # can't block Phase 2 indefinitely.
    if command -v amass &>/dev/null && [[ -s "$root_domains_file" ]]; then
        log_info "Stage 1: Amass Enum for cloud domains (passive mode, no brute/alts)"

        : > "${pdir}/amass_enum_output.txt"
        : > "${pdir}/amass.stderr.log"
        while read -r domain; do
            [[ -z "$domain" ]] && continue
            log_info "  Amass Enum on: $domain (wall-clock cap ${AMASS_TIMEOUT:-1800}s)"
            # NOTE: stdout in passive mode is the final graph (appears at
            # the very end), stderr carries progress. We stream stderr to
            # amass.stderr.log for debuggability and stdout to the tee'd
            # amass_enum_output.txt for downstream filtering.
            timeout "${AMASS_TIMEOUT:-1800}" amass enum -passive \
                -nocolor \
                -timeout 5 \
                -d "$domain" \
                -trf /opt/scripts/wordlists/resolvers.txt \
                -rqps 10 \
                -log "${pdir}/amass_${domain}.log" \
                < /dev/null 2>>"${pdir}/amass.stderr.log" \
                | tee -a "${pdir}/amass_enum_output.txt" || true
        done < "$root_domains_file"

        if [[ -s "${pdir}/amass_enum_output.txt" ]]; then
            filter_cloud_domains "${pdir}/amass_enum_output.txt" "${pdir}/amass_cloud_domains.txt"
            local amass_cloud_count=0
            [[ -s "${pdir}/amass_cloud_domains.txt" ]] && amass_cloud_count=$(wc -l < "${pdir}/amass_cloud_domains.txt")
            log_success "Amass findings: $(wc -l < "${pdir}/amass_enum_output.txt") total entries, $amass_cloud_count cloud-related (see ${pdir}/amass.stderr.log)"
        elif [[ -s "${pdir}/amass.stderr.log" ]]; then
            log_warn "Amass produced no output. Last stderr lines:"
            tail -5 "${pdir}/amass.stderr.log" | sed 's/^/    /'
        else
            log_warn "Amass produced no output and no log — tool may have crashed or been killed"
        fi
    else
        log_warn "Amass not available or no root domains — skipping Amass Enum"
    fi

    # ── Stage 2: DNSx for Cloud Domains ─────────────────────────────────────
    # Per https://github.com/projectdiscovery/dnsx README: dnsx is a
    # multi-purpose DNS toolkit. Here we use it to bulk-resolve every
    # subdomain Phase 1 found against A/AAAA/CNAME/MX/NS/TXT/PTR/SRV
    # records. Cloud assets leak through CNAME chains to
    # *.cloudfront.net, *.amazonaws.com, etc., and through TXT/MX
    # records pointing to cloud-hosted email / verification services —
    # these would never be discovered by a simple A-record lookup.
    #
    # Flags (verified against the dnsx README):
    #   -a -aaaa -cname -mx -ns -txt -ptr -srv  record types to query
    #   -re        display full DNS response (not just the answer field)
    #   -json      NDJSON output (NOT -j; -j is also accepted as alias)
    #   -retry N   retries per host before giving up (default 2)
    #   -r FILE    resolver list — file or comma-separated IPs.
    #              (There is no -rf / -resolvers-file; the project uses
    #              -r as both single-value and file-path.)
    #   -timeout N DNS query timeout in seconds (default 3)
    #
    # Wrapped in `timeout` so a stuck resolver can't hang the phase
    # forever; DNSX_TIMEOUT default 600s.
    if command -v dnsx &>/dev/null && [[ -s "$all_subdomains_file" ]]; then
        log_info "Stage 2: DNSx for cloud domains"
        local dnsx_start=$(_now)
        local dnsx_log="${pdir}/dnsx.stderr.log"
        : > "$dnsx_log"

        # `timeout` must wrap dnsx, NOT cat. Wrapping cat (an instant
        # command) left dnsx itself completely uncapped — the previous
        # behaviour, which made DNSX_TIMEOUT a no-op.
        cat "$all_subdomains_file" \
            | timeout "${DNSX_TIMEOUT:-600}" dnsx -a -aaaa -cname -mx -ns -txt -ptr -srv \
                -re -json -retry 3 \
                -r /opt/scripts/wordlists/resolvers.txt \
                -timeout 5 \
                2>>"$dnsx_log" \
            | tee "${pdir}/dnsx_output.json" >/dev/null || \
                log_warn "DNSx exited non-zero (or was killed by DNSX_TIMEOUT) — see ${dnsx_log}"

        if [[ -s "${pdir}/dnsx_output.json" ]]; then
            jq -r '.cname[]?, .a[]?, .aaaa[]?, .mx[]?, .ns[]?, .txt[]?, .ptr[]?, .srv[]?' \
                "${pdir}/dnsx_output.json" 2>/dev/null > "${pdir}/dnsx_all_records.txt" || true
            filter_cloud_domains "${pdir}/dnsx_all_records.txt" "${pdir}/dnsx_cloud_domains.txt"
            local dnsx_cloud_count=0
            [[ -s "${pdir}/dnsx_cloud_domains.txt" ]] && dnsx_cloud_count=$(wc -l < "${pdir}/dnsx_cloud_domains.txt")
            log_success "DNSx: $(wc -l < "${pdir}/dnsx_all_records.txt") records, $dnsx_cloud_count cloud-related ($(_format_duration $(($(_now) - dnsx_start))) elapsed)"
        elif [[ -s "$dnsx_log" ]]; then
            log_warn "DNSx produced no output. Last stderr lines:"
            tail -5 "$dnsx_log" | sed 's/^/    /'
        else
            log_warn "DNSx produced no output and no stderr — tool may have been killed"
        fi
    else
        log_warn "DNSx not available or no subdomains — skipping DNSx cloud scan"
    fi

    # ── Stage 3: Cloud_Enum Brute Force ─────────────────────────────────────
    # Per https://github.com/initstring/cloud_enum — this tool searches the
    # three "big-3" providers (AWS, Azure, GCP) for open / misconfigured
    # cloud storage buckets and exposed cloud services (Azure SQL,
    # Cosmos, GCP Cloud Functions, etc.).
    #
    # Flags:
    #   -k KW[,KW...]   keywords to mutate; we auto-derive keywords from
    #                   the root domains (e.g. "mydigipay" from
    #                   "mydigipay.com") AND accept user-supplied ones
    #                   via --cloud-enum-keywords. Buckets named
    #                   mydigipay-prod, mydigipay-backups, etc. are tried.
    #   -nsf FILE       file of DNS resolvers. Without this, cloud_enum
    #                   uses its own bundled list which may be smaller
    #                   / less curated. We pass our trickest
    #                   resolvers-trusted.txt so it's consistent with
    #                   the rest of the pipeline. (Ars0n v2 does the
    #                   same by default.)
    #   -l FILE         log file path (json output)
    #   -f json         structured output for jq parsing
    #   -t N            threads
    #
    # Wrapped in `timeout` so a bad keyword (causing infinite mutation)
    # or unreachable DNS doesn't hang the phase.
    if [[ -f /opt/tools/cloud_enum/cloud_enum.py ]]; then
        log_info "Stage 3: Cloud_Enum brute force"
        local ce_start=$(_now)
        local ce_log="${pdir}/cloud_enum.stderr.log"
        : > "$ce_log"

        local keywords=""
        if [[ -n "$CLOUD_ENUM_KEYWORDS" ]]; then
            keywords="$CLOUD_ENUM_KEYWORDS"
        fi
        if [[ -s "$root_domains_file" ]]; then
            local domain_keywords
            domain_keywords=$(cat "$root_domains_file" | sed 's/\..*//' | tr '\n' ',' | sed 's/,$//')
            if [[ -n "$keywords" ]]; then
                keywords="${keywords},${domain_keywords}"
            else
                keywords="$domain_keywords"
            fi
        fi

        if [[ -n "$keywords" ]]; then
            log_info "  Cloud_Enum keywords: $keywords (wall-clock cap ${CLOUD_ENUM_TIMEOUT:-1800}s)"
            timeout "${CLOUD_ENUM_TIMEOUT:-1800}" python3 \
                /opt/tools/cloud_enum/cloud_enum.py \
                -k "$keywords" \
                -nsf /opt/scripts/wordlists/resolvers.txt \
                -l "${pdir}/cloud_enum_results.json" \
                -f json \
                -t "$THREADS" 2>>"$ce_log" || \
                    log_warn "Cloud_Enum exited non-zero (or was killed by CLOUD_ENUM_TIMEOUT) — see ${ce_log}"

            if [[ -s "${pdir}/cloud_enum_results.json" ]]; then
                jq -r 'select(.msg != null) | .target' "${pdir}/cloud_enum_results.json" 2>/dev/null | \
                    sort -u > "${pdir}/cloud_enum_assets.txt" || true
                local ce_count=0
                [[ -s "${pdir}/cloud_enum_assets.txt" ]] && ce_count=$(wc -l < "${pdir}/cloud_enum_assets.txt")
                log_success "Cloud_Enum: $ce_count assets discovered ($(_format_duration $(($(_now) - ce_start))) elapsed)"
            elif [[ -s "$ce_log" ]]; then
                log_warn "Cloud_Enum produced no output. Last stderr lines:"
                tail -5 "$ce_log" | sed 's/^/    /'
            else
                log_warn "Cloud_Enum produced no output and no stderr"
            fi
        else
            log_skip "Cloud_Enum skipped (no keywords available — use --cloud-enum-keywords)"
        fi
    else
        log_warn "Cloud_Enum not found — skipping cloud brute force"
    fi

    # ── Stage 4: Katana Crawling for Cloud Assets ───────────────────────────
    # Per https://github.com/projectdiscovery/katana README:
    #
    #   -u URL       seed URL to crawl
    #   -d N         max depth (we use 3 — beyond that the search-space
    #                explodes for bug-bounty corpora)
    #   -jc          parse endpoints from JS files (default off)
    #   -j           emit JSON Lines (matches the rest of the pipeline)
    #   -timeout N   per-HTTP-request timeout (default 10s). NOTE: this is
    #                NOT wall-clock; the wall-clock cap is -ct (crawl
    #                duration, accepts s/m/h/d suffix).
    #   -c N         concurrent fetchers per target
    #   -p N         concurrent input targets (we set low=1 because we
    #                iterate per-URL in a while-loop, so per-target
    #                parallelism is already handled)
    #   -retry N     retries per failed request
    #   -rd N        per-request delay (politeness, also helps avoid
    #                triggering WAFs)
    #   -rl N        global rate-limit (req/s)
    #   -ct DURATION wall-clock cap for the whole crawl (only setting
    #                that bounds Katana by time). Accepts 30s, 5m, 1h.
    #
    # We use -ct (crawl duration) as the per-URL wall-clock cap so a
    # single never-finishing target can't stall Phase 2 forever. For a
    # quick sanity check on whether Katana is making progress, we also
    # tee JSON to raw_output.txt.
    if command -v katana &>/dev/null && [[ -s "$live_web_file" ]]; then
        log_info "Stage 4: Katana crawling for cloud assets (per-host cap ${KATANA_CRAWL_DURATION:-30m})"
        local katana_start=$(_now)
        mkdir -p "${pdir}/katana"
        : > "${pdir}/katana/raw_output.txt"
        : > "${pdir}/katana.stderr.log"

        local ka_hosts=0
        while read -r url; do
            [[ -z "$url" ]] && continue
            ka_hosts=$((ka_hosts + 1))
            log_info "  Crawling $url with Katana..."
            # -ct caps the wall-clock per seed URL. Setting a per-host cap
            # ALSO via the bash `timeout` shell command would be belt-
            # and-braces but `-ct` is enough for Katana since it cleanly
            # tears down on expiry.
            #
            # `< /dev/null` is CRITICAL: katana merges any non-TTY stdin
            # into its crawl-target set (internal/runner/options.go:
            # fileutil.HasStdin() + bufio.Scanner, same `values` map as -u).
            # Inside this `while read ... done < file` loop the loop's stdin
            # IS the seed file, so the first katana call would slurp every
            # remaining seed and end the loop after ONE host — same bug
            # class as gospider in Phase 1, verified live in our tests.
            katana -u "$url" -d 3 -jc -j \
                -timeout 30 -c 20 -p 1 \
                -retry 2 -rd 1 -rl 10 \
                -ct "${KATANA_CRAWL_DURATION:-30m}" \
                -silent \
                < /dev/null 2>>"${pdir}/katana.stderr.log" \
                | tee -a "${pdir}/katana/raw_output.txt" >/dev/null || \
                    log_warn "Katana on $url exited non-zero (likely -ct hit) — see ${pdir}/katana.stderr.log"
        done < "$live_web_file"

        if [[ -s "${pdir}/katana/raw_output.txt" ]]; then
            # Katana's -j emits one JSON object per line. URLs appear in
            # the "request" field (the URL itself) and "response" body
            # sometimes. We pull URL-like strings to keep it simple and
            # format-agnostic.
            grep -oE 'https?://[^"'\''[:space:}]+' "${pdir}/katana/raw_output.txt" 2>/dev/null | \
                sort -u > "${pdir}/katana/all_urls.txt" || true
            filter_cloud_domains "${pdir}/katana/all_urls.txt" "${pdir}/katana_cloud_assets.txt"
            local ka_cloud=0
            [[ -s "${pdir}/katana_cloud_assets.txt" ]] && ka_cloud=$(wc -l < "${pdir}/katana_cloud_assets.txt")
            log_success "Katana: $(wc -l < "${pdir}/katana/raw_output.txt") JSON lines, $ka_cloud cloud-related on $ka_hosts hosts ($(_format_duration $(($(_now) - katana_start))) total)"
        elif [[ -s "${pdir}/katana.stderr.log" ]]; then
            log_warn "Katana produced no output. Last stderr lines:"
            tail -5 "${pdir}/katana.stderr.log" | sed 's/^/    /'
        else
            log_warn "Katana produced no output and no stderr"
        fi
    else
        log_warn "Katana not available or no live web servers — skipping Katana cloud scan"
    fi

    # ── Stage 5: Consolidate Cloud Assets ───────────────────────────────────
    log_info "Consolidating cloud assets"

    cat \
        "${pdir}/amass_cloud_domains.txt" \
        "${pdir}/dnsx_cloud_domains.txt" \
        "${pdir}/cloud_enum_assets.txt" \
        "${pdir}/katana_cloud_assets.txt" \
        2>/dev/null | sort -u > "${pdir}/final_cloud_assets.txt" || true

    if [[ -s "${pdir}/final_cloud_assets.txt" ]]; then
        log_success "Total unique cloud assets: $(wc -l < "${pdir}/final_cloud_assets.txt")"
    else
        log_warn "No cloud assets discovered"
    fi
}
