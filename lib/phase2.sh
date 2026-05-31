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
    if command -v amass &>/dev/null && [[ -s "$root_domains_file" ]]; then
        log_info "Stage 1: Amass Enum for cloud domains"

        : > "${pdir}/amass_enum_output.txt"
        while read -r domain; do
            [[ -z "$domain" ]] && continue
            log_info "  Amass Enum on: $domain"
            amass enum -passive -alts -brute -nocolor \
                -min-for-recursive 2 -timeout 300 \
                -d "$domain" \
                -r 8.8.8.8 -r 1.1.1.1 -r 9.9.9.9 -r 208.67.222.222 \
                -rqps 10 \
                2>/dev/null | tee -a "${pdir}/amass_enum_output.txt" || true
        done < "$root_domains_file"

        if [[ -s "${pdir}/amass_enum_output.txt" ]]; then
            filter_cloud_domains "${pdir}/amass_enum_output.txt" "${pdir}/amass_cloud_domains.txt"
            [[ -s "${pdir}/amass_cloud_domains.txt" ]] && \
                log_success "Cloud domains from Amass: $(wc -l < "${pdir}/amass_cloud_domains.txt")"
        fi
    else
        log_warn "Amass not available or no root domains — skipping Amass Enum"
    fi

    # ── Stage 2: DNSx for Cloud Domains ─────────────────────────────────────
    if command -v dnsx &>/dev/null && [[ -s "$all_subdomains_file" ]]; then
        log_info "Stage 2: DNSx for cloud domains"

        cat "$all_subdomains_file" | dnsx \
            -a -aaaa -cname -mx -ns -txt -ptr -srv \
            -re -json -retry 3 \
            2>/dev/null | tee "${pdir}/dnsx_output.json" || true

        if [[ -s "${pdir}/dnsx_output.json" ]]; then
            jq -r '.cname[]?, .a[]?, .aaaa[]?, .mx[]?, .ns[]?, .txt[]?, .ptr[]?, .srv[]?' \
                "${pdir}/dnsx_output.json" 2>/dev/null > "${pdir}/dnsx_all_records.txt" || true
            filter_cloud_domains "${pdir}/dnsx_all_records.txt" "${pdir}/dnsx_cloud_domains.txt"
            [[ -s "${pdir}/dnsx_cloud_domains.txt" ]] && \
                log_success "Cloud domains from DNSx: $(wc -l < "${pdir}/dnsx_cloud_domains.txt")"
        fi
    else
        log_warn "DNSx not available or no subdomains — skipping DNSx cloud scan"
    fi

    # ── Stage 3: Cloud_Enum Brute Force ─────────────────────────────────────
    if [[ -f /opt/tools/cloud_enum/cloud_enum.py ]]; then
        log_info "Stage 3: Cloud_Enum brute force"

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
            log_info "  Cloud_Enum keywords: $keywords"
            python3 /opt/tools/cloud_enum/cloud_enum.py \
                -k "$keywords" \
                -l "${pdir}/cloud_enum_results.json" \
                -f json \
                -t "$THREADS" 2>/dev/null || true

            if [[ -s "${pdir}/cloud_enum_results.json" ]]; then
                jq -r 'select(.msg != null) | .target' "${pdir}/cloud_enum_results.json" 2>/dev/null | \
                    sort -u > "${pdir}/cloud_enum_assets.txt" || true
                [[ -s "${pdir}/cloud_enum_assets.txt" ]] && \
                    log_success "Cloud assets from Cloud_Enum: $(wc -l < "${pdir}/cloud_enum_assets.txt")"
            fi
        else
            log_skip "Cloud_Enum skipped (no keywords available — use --cloud-enum-keywords)"
        fi
    else
        log_warn "Cloud_Enum not found — skipping cloud brute force"
    fi

    # ── Stage 4: Katana Crawling for Cloud Assets ───────────────────────────
    if command -v katana &>/dev/null && [[ -s "$live_web_file" ]]; then
        log_info "Stage 4: Katana crawling for cloud assets"

        mkdir -p "${pdir}/katana"
        : > "${pdir}/katana/raw_output.txt"

        while read -r url; do
            [[ -z "$url" ]] && continue
            log_info "  Crawling $url with Katana..."
            katana -u "$url" -d 3 -jc -j -v \
                -timeout 120 -c 20 -p 20 \
                -retry 3 -rd 1 -rl 10 \
                2>/dev/null | tee -a "${pdir}/katana/raw_output.txt" || true
        done < "$live_web_file"

        if [[ -s "${pdir}/katana/raw_output.txt" ]]; then
            grep -oE 'https?://[^"'\''[:space:]]+' "${pdir}/katana/raw_output.txt" 2>/dev/null | \
                sort -u > "${pdir}/katana/all_urls.txt" || true
            filter_cloud_domains "${pdir}/katana/all_urls.txt" "${pdir}/katana_cloud_assets.txt"
            [[ -s "${pdir}/katana_cloud_assets.txt" ]] && \
                log_success "Cloud assets from Katana: $(wc -l < "${pdir}/katana_cloud_assets.txt")"
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
