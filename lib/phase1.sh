#!/usr/bin/env bash
# Phase 1: Root Domains → All Subdomains
# For each root domain, discovers subdomains via scraping, brute forcing, and crawling.

run_phase1() {
    local pdir="${OUTPUT_DIR}/phase1"
    mkdir -p "$pdir"
    CURRENT_PHASE=1

    local root_domains_file="$1"
    if [[ ! -s "$root_domains_file" ]]; then
        log_error "No root domains file provided for Phase 1"
        return 1
    fi

    local domain_count
    domain_count=$(wc -l < "$root_domains_file")
    log_info "═══ PHASE 1: Root Domains → Subdomains (${domain_count} domains) ═══"

    while read -r DOMAIN; do
        [[ -z "$DOMAIN" ]] && continue
        process_domain "$DOMAIN" "$pdir"
    done < "$root_domains_file"
}

process_domain() {
    local domain="$1"
    local pdir="$2"
    local ddir="${pdir}/${domain}"
    mkdir -p "$ddir"

    log_info "────────────────────────────────────────────"
    log_info "Processing domain: $domain"
    log_info "────────────────────────────────────────────"

    cd "$ddir" || return 1

    # ── Stage 1: Web Scraping ───────────────────────────────────────────────
    log_info "Stage 1: Web Scraping for subdomains"

    # Cero (replaces crt.sh — scrapes domain names from TLS certificates)
    if command -v cero &>/dev/null; then
        log_info "Running Cero (certificate transparency)..."
        cero -d "$domain" 2>/dev/null | sort -u > cero_results.txt || true
        local cero_count=0
        [[ -s cero_results.txt ]] && cero_count=$(wc -l < cero_results.txt)
        log_success "Cero subdomains: $cero_count"
    else
        log_warn "Cero not found, skipping certificate transparency scan"
    fi

    # Subfinder
    log_info "Running Subfinder..."
    local subfinder_opts=(-d "$domain" -all -silent -o subfinder_results.txt)
    if [[ -n "$SUBFINDER_PROVIDER_CONFIG" ]]; then
        subfinder_opts+=(-provider-config "$SUBFINDER_PROVIDER_CONFIG")
    fi
    subfinder "${subfinder_opts[@]}" 2>/dev/null || true
    local sf_count=0
    [[ -s subfinder_results.txt ]] && sf_count=$(wc -l < subfinder_results.txt)
    log_success "Subfinder subdomains: $sf_count"

    # Assetfinder
    if command -v assetfinder &>/dev/null; then
        log_info "Running Assetfinder..."
        assetfinder --subs-only "$domain" > assetfinder_results.txt 2>/dev/null || true
        local af_count=0
        [[ -s assetfinder_results.txt ]] && af_count=$(wc -l < assetfinder_results.txt)
        log_success "Assetfinder subdomains: $af_count"
    fi

    # GAU
    if command -v gau &>/dev/null; then
        log_info "Running GAU..."
        echo "$domain" | gau --subs --threads 10 2>/dev/null | \
            grep -oE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' | \
            grep "$domain" | sort -u > gau_results.txt || true
        local gau_count=0
        [[ -s gau_results.txt ]] && gau_count=$(wc -l < gau_results.txt)
        log_success "GAU subdomains: $gau_count"
    fi

    # Sublist3r - capture results despite warnings/errors
    # Sublist3r prints results to stdout even when some engines fail
    if command -v sublist3r &>/dev/null || [[ -f /opt/tools/sublist3r/sublist3r.py ]]; then
        log_info "Running Sublist3r..."
        local sl3_cmd="sublist3r"
        command -v sublist3r &>/dev/null || sl3_cmd="python3 /opt/tools/sublist3r/sublist3r.py"

        # Run sublist3r, capture ALL output (stdout+stderr), then extract valid subdomains
        # Use timeout to prevent hanging, and run with -v for verbose output
        local sublist3r_all_output="sublist3r_all_output.txt"
        : > "$sublist3r_all_output"

        # Capture both stdout and stderr; sublist3r prints discovered subdomains to stdout
        # even when some search engines throw exceptions
        timeout 300 bash -c "$sl3_cmd -d \"$domain\" -t \"$THREADS\" -v 2>&1" > "$sublist3r_all_output" || true

        # Extract subdomains from verbose output. Sublist3r's -v mode prints lines like:
        #   Netcraft: it.idp.vodafone.com
        #   Baidu: sub.domain.com
        # as well as bare domain lines in the final summary.
        # Use grep -oE (no anchors) to extract domains from anywhere on the line,
        # then filter to only those matching the target domain.
        # -- fix: Sublist3r wraps every discovered subdomain in ANSI color escapes
        # (e.g. `\033[0m`, `\033[92m`). grep -oE matches the bytes AFTER the stripped
        # ESC, gluing the trailing color suffix onto the next domain token, producing
        # entries like `0macademy.arvancloud.ir` and `92macademy.arvancloud.ir`.
        # Strip ANSI escapes with sed before applying the domain regex.
        # Also escape literal dots in $domain so multi-label TLDs (e.g. co.uk) match
        # cleanly.
        sed -E $'s/\x1b\\[[0-9;?]*[a-zA-Z]//g' "$sublist3r_all_output" 2>/dev/null | \
            grep -oE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' | \
            grep -E "\.${domain//./\\.}$|^${domain//./\\.}$" | \
            sort -u > sublist3r_results.txt || true

        local sl3_count=0
        [[ -s sublist3r_results.txt ]] && sl3_count=$(wc -l < sublist3r_results.txt)
        log_success "Sublist3r subdomains: $sl3_count (errors from some engines ignored)"

        # Keep full output for debugging
        mv "$sublist3r_all_output" sublist3r_full_output.txt
    fi

    # github-subdomains
    if [[ -n "$GITHUB_TOKENS_FILE" ]] && command -v github-subdomains &>/dev/null; then
        log_info "Running github-subdomains..."
        github-subdomains -d "$domain" \
            -t "$GITHUB_TOKENS_FILE" \
            -o github_subdomains_results.txt 2>/dev/null || true
        local gh_count=0
        [[ -s github_subdomains_results.txt ]] && gh_count=$(wc -l < github_subdomains_results.txt)
        log_success "github-subdomains subdomains: $gh_count"
    else
        if [[ -z "$GITHUB_TOKENS_FILE" ]]; then
            log_skip "github-subdomains skipped (no --github-tokens-file)"
        else
            log_skip "github-subdomains skipped (tool not installed)"
        fi
    fi

    # ── Stage 2: Consolidate & HTTPx Round 1 ────────────────────────────────
    log_info "Stage 2: Consolidating scraping results + HTTPx Round 1"

    cat \
        cero_results.txt \
        subfinder_results.txt \
        assetfinder_results.txt \
        gau_results.txt \
        sublist3r_results.txt \
        github_subdomains_results.txt \
        2>/dev/null | sort -u > all_subdomains_round1.txt || true

    if [[ -s all_subdomains_round1.txt ]]; then
        log_success "Subdomains from scraping: $(wc -l < all_subdomains_round1.txt)"
        httpx_probe all_subdomains_round1.txt httpx_results_round1.json
        [[ -s httpx_results_round1.json ]] && jq -r '.url' httpx_results_round1.json | sort -u > live_subdomains_round1.txt
    else
        log_warn "No subdomains found from scraping for $domain"
        cd "$pdir" || return 1
        return 0
    fi

    # ── Stage 3: Brute Force with Custom Wordlist ──────────────────────────
    log_info "Stage 3: Brute force subdomain discovery"

    # Step 3a: Generate custom wordlist with CeWL
    mkdir -p wordlists
    : > wordlists/custom_wordlist.txt

    if [[ -s live_subdomains_round1.txt ]] && command -v cewl &>/dev/null; then
        while read -r url; do
            [[ -z "$url" ]] && continue
            log_info "  Crawling $url for words..."
            # CeWL output format (per digininja/CeWL cewl.rb line 1242-1244):
            #   WITHOUT -c/--count  →  one bare `word` per line
            #   WITH    -c/--count  →  `word, count` per line (NOT count,word!)
            #
            # We deliberately do NOT pass `-c`; the count column is noise
            # for our use case (ShuffleDNS brute force), and would force
            # us to strip it before piping the list further.
            #
            # `--with-numbers` keeps alphanumeric tokens like `iso9001`
            # in the output; without it, digits are stripped at the
            # source (cewl.rb line 1175-1178). Useful when sites
            # mention versions, dates, or product codes that may also
            # appear as subdomain labels.
            #
            # `-d 2 -m 5` = spider depth 2, minimum word length 5.
            # We let CeWL enforce min length; the outer `awk 'length
            # >= 3 && length <= 20'` is a defensive re-filter that
            # also drops tokens containing whitespace, punctuation,
            # or stray error text (CeWL writes connection errors to
            # STDOUT, not STDERR, when not in -v mode; cewl.rb
            # line 270-281). The strict `/^[a-zA-Z0-9_-]{3,20}$/`
            # filter inside the second awk drops anything that isn't
            # a clean token.
            timeout 600 cewl "$url" -d 2 -m 5 --with-numbers 2>/dev/null | \
                awk 'length >= 3 && length <= 20' | \
                awk '{ orig=$0; if (match($0, /^[a-zA-Z0-9_-]{3,20}$/) && gsub(/[a-zA-Z]/, "&") >= 2) print orig }' | \
                tr '[:upper:]' '[:lower:]' \
                >> wordlists/custom_wordlist.txt || true
        done < live_subdomains_round1.txt
        sort -u wordlists/custom_wordlist.txt -o wordlists/custom_wordlist.txt

        # Drop words whose first non-letter char is a digit too early
        # (would still match the 2-letter floor above — e.g. "a1234b"
        # passes but is never a real subdomain label).
        awk 'length >= 3 && length <= 20' wordlists/custom_wordlist.txt | \
            grep -E '^([a-z][a-z_-]*[a-z]|[a-z])$' | \
            sort -u -o wordlists/custom_wordlist.txt || true
    fi

    # Fallback: use a minimal default wordlist if CeWL didn't produce anything
    if [[ ! -s wordlists/custom_wordlist.txt ]]; then
        log_warn "CeWL produced no results, using default wordlist"
        cat > wordlists/custom_wordlist.txt <<'WORDBASE'
www
mail
api
dev
staging
test
admin
portal
app
blog
shop
store
cdn
docs
git
ci
jenkins
vpn
remote
dashboard
intranet
internal
stg
uat
prod
preview
sandbox
demo
beta
alpha
old
new
backup
db
mysql
postgres
redis
elastic
grafana
kibana
monitor
status
health
metrics
log
logs
s3
assets
static
media
images
img
cdn
content
cms
wp
wordpress
drupal
joomla
api-gw
gateway
auth
login
sso
oauth
id
identity
account
accounts
user
users
profile
manage
manager
panel
control
cpanel
webmail
mx
smtp
imap
pop
ftp
ns1
ns2
dns
WORDBASE
    fi

    log_info "Wordlist size: $(wc -l < wordlists/custom_wordlist.txt) unique words (CeWL-filtered)"

    # Step 3b: ShuffleDNS brute force
    # Per https://github.com/projectdiscovery/shuffledns:
    #   -d <domain>     target domain (only mode where wildcard filtering works)
    #   -w <wordlist>   words to permute against the domain
    #   -r <resolvers>  file of trusted DNS resolvers used by the underlying massdns
    #   -mode bruteforce enumerate via DNS brute force
    #   -sw             strict wildcard check (filters multi-level wildcard pollution)
    #   -t              concurrent massdns resolves (default 10000)
    #   -o              output file
    #   -duc            disable update check (avoids any first-run network call
    #                   to projectdiscovery's release server)
    #   -wt N           concurrent wildcard-check threads (default 250)
    # massdns must be installed in the image (added to the Dockerfile);
    # shuffledns does NOT ship its own copy and silently produces 0 output
    # if /usr/bin/massdns or /usr/local/bin/massdns isn't on PATH.
    if command -v shuffledns &>/dev/null; then
        if ! command -v massdns &>/dev/null; then
            log_warn "massdns not found on PATH — ShuffleDNS brute force will produce 0 results. Re-build the Docker image to include massdns."
        fi

        if [[ ! -s /opt/scripts/wordlists/resolvers.txt ]]; then
            log_warn "resolvers file missing or empty: /opt/scripts/wordlists/resolvers.txt — ShuffleDNS will fail"
        fi

        log_info "Running ShuffleDNS brute force on $(wc -l < wordlists/custom_wordlist.txt) words against $domain..."

        # Capture stderr AND stdout: shuffledns writes subdomains to -o on
        # success but its diagnostic info (massdns progress, errors) goes
        # to stderr. We stream both to a debug log so a "0 results" outcome
        # is always explainable, even when -o is empty.
        local shuffledns_log="shuffledns.debug.log"
        : > "$shuffledns_log"
        local shuffledns_exit=0
        timeout "${SHUFFLEDNS_TIMEOUT:-900}" shuffledns -d "$domain" \
            -w wordlists/custom_wordlist.txt \
            -r /opt/scripts/wordlists/resolvers.txt \
            -mode bruteforce \
            -sw \
            -duc \
            -t "$THREADS" \
            -wt 100 \
            -o shuffledns_results.txt \
            >> "$shuffledns_log" 2>&1 || shuffledns_exit=$?

        if [[ "$shuffledns_exit" -ne 0 ]]; then
            log_warn "ShuffleDNS exited with code ${shuffledns_exit} — see ${shuffledns_log}"
            # Surface a tail of the log to stdout so the user can see
            # what happened without opening the file.
            tail -5 "$shuffledns_log" 2>/dev/null | sed 's/^/    /'
        fi

        if [[ -s shuffledns_results.txt ]]; then
            local bf_count
            bf_count=$(wc -l < shuffledns_results.txt)
            log_success "Subdomains from brute force: ${bf_count} (see ${shuffledns_log})"
        elif [[ -s "$shuffledns_log" ]]; then
            # Distinguish "ran fine, found nothing" from "didn't run" — the
            # log tells us which one. Sample up to 3 lines so the user can
            # immediately tell whether massdns crashed or just had no hits.
            log_info "ShuffleDNS: no output file produced. Last log lines:"
            tail -3 "$shuffledns_log" 2>/dev/null | sed 's/^/    /'
        else
            log_info "ShuffleDNS: no new subdomains found (no log entries captured)"
        fi
    else
        log_warn "ShuffleDNS not found, skipping brute force"
    fi

    # ── Stage 4: Consolidate & HTTPx Round 2 ────────────────────────────────
    log_info "Stage 4: Consolidate + HTTPx Round 2"

    # Build the full set so far (round-1 scraping + brute force).
    cat all_subdomains_round1.txt shuffledns_results.txt 2>/dev/null | \
        sort -u > all_subdomains_round2.txt || true

    # Compute ONLY the newly discovered subdomains from brute force so we don't
    # re-probe the entire round-1 set with httpx again.
    local new_only_subs=0
    : > new_subdomains_round2.txt
    if [[ -s all_subdomains_round1.txt && -s shuffledns_results.txt ]]; then
        comm -13 all_subdomains_round1.txt shuffledns_results.txt \
            > new_subdomains_round2.txt || true
    elif [[ -s shuffledns_results.txt ]]; then
        # No round-1 set (unusual); treat brute-force result as the new set.
        cp shuffledns_results.txt new_subdomains_round2.txt
    fi
    [[ -s new_subdomains_round2.txt ]] && new_only_subs=$(wc -l < new_subdomains_round2.txt)
    log_success "New subdomains from brute force: $new_only_subs"

    if [[ "$new_only_subs" -gt 0 ]]; then
        # Probe ONLY the newly discovered subdomains. We append the new live
        # servers to the round-1 live set to produce the round-2 live set,
        # so crawling (Stage 5) and final consolidation (Stage 6) still see
        # the union of all live hosts.
        httpx_probe new_subdomains_round2.txt httpx_results_round2.json
        if [[ -s httpx_results_round2.json ]]; then
            jq -r '.url' httpx_results_round2.json | sort -u > new_live_subdomains_round2.txt
        else
            : > new_live_subdomains_round2.txt
        fi

        cat live_subdomains_round1.txt new_live_subdomains_round2.txt 2>/dev/null | \
            sort -u > live_subdomains_round2.txt || true

        # Preserve a merged JSON for downstream consumers/debugging.
        # NOTE: we cannot use `cat a b > b` because the redirection truncates
        # the second input before cat reads it. Read into a temp file first.
        cat httpx_results_round1.json httpx_results_round2.json 2>/dev/null \
            > httpx_results_round2.json.tmp || true
        mv -f httpx_results_round2.json.tmp httpx_results_round2.json
    else
        log_info "No new subdomains from brute force — skipping HTTPx Round 2 (reusing Round 1 results)"
        cp live_subdomains_round1.txt live_subdomains_round2.txt 2>/dev/null || : > live_subdomains_round2.txt
        cp httpx_results_round1.json httpx_results_round2.json 2>/dev/null || : > httpx_results_round2.json
    fi

    # ── Stage 5: Web Crawling ───────────────────────────────────────────────
    log_info "Stage 5: Web Crawling & JS Link Discovery"

    # GoSpider
    # Per https://github.com/jaeles-project/gospider:
    #   -s URL    site to crawl
    #   -c N      per-domain concurrency (default 5)
    #   -d N      max depth (0 = infinite; default 1) — we use 3
    #   -t N      parallel threads across sites (default 1) — we use 3
    #   -k N      fixed delay between requests (sec)
    #   -K N      randomized extra delay on top of -k (sec)
    #   -m N      per-request timeout in seconds (gospider's letter M = timeout,
    #             NOT max pages; easy to mis-read)
    #   -a -w -r  pull URLs from Archive.org / CommonCrawl / VirusTotal /
    #             AlienVault; include subdomains found in 3rd-party; crawl
    #             those URLs too. Together they cover sources outside the seed.
    #   --js      run linkfinder on JS files (default true; explicit for clarity)
    #   --sitemap --robots: try those for additional URLs (default true; explicit)
    # Each host is wrapped in `timeout` so a single slow / never-responds
    # URL can't stall the stage for hours (gospider is single-threaded per
    # host; -m 30 only caps the request timeout, not the overall crawl).
    if command -v gospider &>/dev/null && [[ -s live_subdomains_round2.txt ]]; then
        mkdir -p gospider
        : > gospider/raw_output.txt
        # -- fix: prior version reported `${gs_hosts}` (the bash loop counter over
        # live_subdomains_round2.txt) as the "hosts crawled" number. That was
        # misleading in two ways: (a) gospider can internally follow `-a -w -r`
        # (Wayback/CommonCrawl/VirusTotal/AlienVault) subdomains, so the number
        # of distinct `input` URLs gospider emitted in its JSON output can exceed
        # the number of seeds we fed it; (b) if the outer loop gets cut short by
        # a timeout/pipefail glitch, the bash counter understates reality. We
        # now report both numbers so any future divergence is visible.
        local gs_loop_count=0
        while read -r url; do
            [[ -z "$url" ]] && continue
            gs_loop_count=$((gs_loop_count + 1))
            log_info "  Crawling $url with GoSpider..."
            timeout "${GOSPIDER_TIMEOUT:-600}" gospider -s "$url" -c 10 -d 3 -t 1 -k 1 -K 2 -m 30 \
                --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|svg)" \
                -a -w -r --js --sitemap --robots --json -v 2>/dev/null | \
                tee -a gospider/raw_output.txt || true
        done < live_subdomains_round2.txt

        if [[ -s gospider/raw_output.txt ]]; then
            # Count distinct `input` hosts actually processed by gospider (from
            # its JSON output). This is what really got scanned, regardless of
            # whether they came from the seed loop or from `-a -w -r` archives.
            local gs_actual_hosts
            gs_actual_hosts=$(grep -oE '"input":"[^"]+"' gospider/raw_output.txt 2>/dev/null | \
                sort -u | wc -l | tr -d ' ')
            [[ -z "$gs_actual_hosts" ]] && gs_actual_hosts=0

            extract_domains gospider/raw_output.txt gospider/all_domains.txt
            grep "$domain" gospider/all_domains.txt | sort -u > gospider_subdomains.txt || true
            if [[ -s gospider_subdomains.txt ]]; then
                log_success "GoSpider subdomains (${gs_actual_hosts} hosts crawled across ${gs_loop_count} seeds): $(wc -l < gospider_subdomains.txt)"
            else
                log_info "GoSpider: crawled ${gs_actual_hosts} hosts across ${gs_loop_count} seeds, no $domain subdomains discovered"
            fi
        else
            log_info "GoSpider: scanned ${gs_loop_count} seeds, no output captured"
        fi
    fi

    # Subdomainizer
    # Per https://github.com/nsonaniya2010/SubDomainizer:
    #   -u URL         target URL to scan for JS-loaded subdomains
    #   -o FILE        write results to FILE
    #   -c COOKIE      send Cookie header (we don't pass this; no cookies)
    #   -k             --nossl — disable SSL verification (handy for self-signed
    #                   or wildcard subdomains that present the parent's cert)
    # SubDomainizer prints the subdomain list to STDOUT *and* writes the
    # same to -o. We capture BOTH stdout and the -o file so a tool that
    # only prints (e.g. an old version, or a flag that bypasses -o) still
    # flows into raw_output.txt.
    #
    # Previous bug: stdout was discarded (`2>/dev/null` only redirects
    # stderr), which silently dropped any tool output that didn't write
    # to the -o file. That's why subdomainizer_subdomains.txt was always
    # empty in our runs.
    #
    # Each per-host scan is wrapped in `timeout` so a single slow/unreachable
    # URL can't stall the whole stage for hours.
    if [[ -f /opt/tools/SubDomainizer/SubDomainizer.py ]] && [[ -s live_subdomains_round2.txt ]]; then
        mkdir -p subdomainizer
        : > subdomainizer/raw_output.txt
        : > subdomainizer/stdout.log

        local sd_total=0 sd_hosts=0
        while read -r url; do
            [[ -z "$url" ]] && continue
            sd_hosts=$((sd_hosts + 1))
            log_info "  Running Subdomainizer on $url..."

            # -o writes the file; we ALSO redirect stdout into stdout.log so
            # we never lose the tool's output. -k is --nossl here, NOT
            # cookies (cookies are -c).
            timeout "${SUBDOMAINIZER_TIMEOUT:-300}" python3 \
                /opt/tools/SubDomainizer/SubDomainizer.py \
                -u "$url" -k -o subdomainizer/temp_output.txt \
                >> subdomainizer/stdout.log 2>&1 || true

            local sd_added=0
            if [[ -s subdomainizer/temp_output.txt ]]; then
                cat subdomainizer/temp_output.txt >> subdomainizer/raw_output.txt
                sd_added=$(wc -l < subdomainizer/temp_output.txt)
                rm -f subdomainizer/temp_output.txt
            fi
            if [[ "$sd_added" -gt 0 ]]; then
                log_info "    → Subdomainizer found $sd_added entries on $url"
                sd_total=$((sd_total + sd_added))
            fi
        done < live_subdomains_round2.txt

        # Dedupe the union of -o output and any stdout the tool emitted.
        if [[ -s subdomainizer/raw_output.txt ]] || [[ -s subdomainizer/stdout.log ]]; then
            {
                cat subdomainizer/raw_output.txt
                cat subdomainizer/stdout.log 2>/dev/null
            } > /tmp/sd_combined.txt
            extract_domains /tmp/sd_combined.txt subdomainizer/all_domains.txt
            grep "$domain" subdomainizer/all_domains.txt | sort -u > subdomainizer_subdomains.txt || true
            rm -f /tmp/sd_combined.txt
            if [[ -s subdomainizer_subdomains.txt ]]; then
                log_success "Subdomainizer subdomains (${sd_hosts} hosts scanned): $(wc -l < subdomainizer_subdomains.txt)"
            else
                log_info "Subdomainizer: ran on ${sd_hosts} hosts, no $domain subdomains discovered"
            fi
        else
            log_info "Subdomainizer: ran on ${sd_hosts} hosts, nothing found"
        fi
    else
        log_skip "Subdomainizer skipped (tool missing or no live hosts)"
    fi

    # ── Stage 6: Final Consolidation & HTTPx Round 3 ───────────────────────
    log_info "Stage 6: Final consolidation + HTTPx Round 3"

    cat \
        all_subdomains_round2.txt \
        gospider_subdomains.txt \
        subdomainizer_subdomains.txt \
        2>/dev/null | sort -u > all_subdomains_final.txt || true

    local total_subs=0
    [[ -s all_subdomains_final.txt ]] && total_subs=$(wc -l < all_subdomains_final.txt)
    log_success "Total unique subdomains for $domain: $total_subs"

    # Probe ONLY the subdomains discovered since Round 2 (i.e., crawling
    # candidates that aren't already in all_subdomains_round2.txt). Merge
    # their live URLs with the Round 2 live set.
    : > new_subdomains_final.txt
    if [[ -s all_subdomains_round2.txt ]]; then
        comm -13 all_subdomains_round2.txt all_subdomains_final.txt \
            > new_subdomains_final.txt || true
    fi
    local crawl_new=0
    [[ -s new_subdomains_final.txt ]] && crawl_new=$(wc -l < new_subdomains_final.txt)
    log_info "New subdomains since Round 2 (from crawling): $crawl_new"

    if [[ "$crawl_new" -gt 0 ]]; then
        httpx_probe new_subdomains_final.txt httpx_results_final.json
        if [[ -s httpx_results_final.json ]]; then
            jq -r '.url' httpx_results_final.json | sort -u > new_live_subdomains_final.txt
        else
            : > new_live_subdomains_final.txt
        fi
        cat live_subdomains_round2.txt new_live_subdomains_final.txt 2>/dev/null | \
            sort -u > live_subdomains_final.txt || true
        # Merge JSON for downstream/debug consumers. Same redirect-safety
        # caveat as Stage 4: write to a tmp file first, then atomic-rename.
        cat httpx_results_round2.json httpx_results_final.json 2>/dev/null \
            > httpx_results_final.json.tmp || true
        mv -f httpx_results_final.json.tmp httpx_results_final.json
    else
        log_info "No new subdomains from crawling — reusing Round 2 live results"
        cp live_subdomains_round2.txt live_subdomains_final.txt 2>/dev/null || : > live_subdomains_final.txt
        cp httpx_results_round2.json httpx_results_final.json 2>/dev/null || : > httpx_results_final.json
    fi

    local final_live=0
    [[ -s live_subdomains_final.txt ]] && final_live=$(wc -l < live_subdomains_final.txt)
    log_success "FINAL live web servers for $domain: $final_live"

    cd "$pdir" || return 1
}
