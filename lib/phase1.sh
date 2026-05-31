#!/usr/bin/env bash
# Phase 1: Company Name → Root Domains
# Discovers ASNs, network ranges, IPs, and root domains from a company name.

run_phase1() {
    local pdir="${OUTPUT_DIR}/phase1"
    mkdir -p "$pdir"
    CURRENT_PHASE=1

    log_info "═══ PHASE 1: Company Name → Root Domains ═══"
    log_info "Target: $COMPANY"

    # ── Stage 1: ASN & Network Range Discovery ──────────────────────────────
    log_info "Stage 1: ASN & Network Range Discovery"

    # Amass Intel
    log_info "Running Amass Intel for: $COMPANY"
    amass intel \
        -org "$COMPANY" \
        -whois \
        -active \
        -timeout 120 \
        -o "${pdir}/amass_intel_results.txt" 2>/dev/null || true

    if [[ -s "${pdir}/amass_intel_results.txt" ]]; then
        log_success "Amass Intel results: $(wc -l < "${pdir}/amass_intel_results.txt") lines"
    else
        log_warn "Amass Intel returned no results"
    fi

    # Metabigor
    if command -v metabigor &>/dev/null; then
        log_info "Running Metabigor for: $COMPANY"
        echo "$COMPANY" | metabigor net --org -v > "${pdir}/metabigor_results.txt" 2>/dev/null || true

        if [[ -s "${pdir}/metabigor_results.txt" ]]; then
            log_success "Metabigor results: $(wc -l < "${pdir}/metabigor_results.txt") lines"
        fi
    else
        log_warn "Metabigor not found, skipping"
    fi

    # Extract ASNs and network ranges
    grep -oE 'AS[0-9]+|^[0-9]+' "${pdir}/amass_intel_results.txt" "${pdir}/metabigor_results.txt" 2>/dev/null \
        | sort -u > "${pdir}/asn_list.txt" || true

    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' "${pdir}/amass_intel_results.txt" "${pdir}/metabigor_results.txt" 2>/dev/null \
        | sort -u > "${pdir}/network_ranges.txt" || true

    if [[ -s "${pdir}/asn_list.txt" ]]; then
        log_success "ASNs discovered: $(wc -l < "${pdir}/asn_list.txt")"
    fi
    if [[ -s "${pdir}/network_ranges.txt" ]]; then
        log_success "Network ranges discovered: $(wc -l < "${pdir}/network_ranges.txt")"
    fi

    # ── Stage 2: Network Range Scanning ─────────────────────────────────────
    if [[ -s "${pdir}/network_ranges.txt" ]]; then
        log_info "Stage 2: Network Range Scanning"

        # Step 2a: Host discovery
        log_info "Discovering live hosts across $(wc -l < "${pdir}/network_ranges.txt") network ranges..."
        : > "${pdir}/live_ips_temp.txt"

        while read -r net; do
            [[ -z "$net" ]] && continue
            log_info "  Scanning: $net"
            nmap -sn -PS80,443,22,8080,8443 -PE -PA80 \
                --min-rate 1000 --max-retries 1 \
                -oG - "$net" 2>/dev/null | \
                grep 'Up' | awk '{print $2}' >> "${pdir}/live_ips_temp.txt"
        done < "${pdir}/network_ranges.txt"

        sort -u -V "${pdir}/live_ips_temp.txt" > "${pdir}/live_ips.txt" 2>/dev/null || true
        rm -f "${pdir}/live_ips_temp.txt"

        if [[ -s "${pdir}/live_ips.txt" ]]; then
            local live_count
            live_count=$(wc -l < "${pdir}/live_ips.txt")
            log_success "Live IPs discovered: $live_count"

            # Step 2b: Port scan
            log_info "Port scanning for web services..."
            nmap -iL "${pdir}/live_ips.txt" \
                -p 80,443,8080,8443,8000,8888,3000,9000,7000,5000 \
                -sV --open --min-rate 500 \
                -oG "${pdir}/port_scan_results.txt" 2>/dev/null || true

            grep '/open/' "${pdir}/port_scan_results.txt" 2>/dev/null | \
                awk '{print $2":"$5}' | sed 's|/open/tcp||g' | sort -u \
                > "${pdir}/ip_port_pairs.txt" || true

            if [[ -s "${pdir}/ip_port_pairs.txt" ]]; then
                log_success "IP:Port pairs with web services: $(wc -l < "${pdir}/ip_port_pairs.txt")"

                # Step 2c: HTTP/HTTPS metadata
                log_info "Gathering HTTP/HTTPS metadata..."
                cat "${pdir}/ip_port_pairs.txt" | while IFS=':' read -r ip port; do
                    if [[ "$port" == "443" || "$port" == "8443" ]]; then
                        echo "https://$ip:$port"
                    else
                        echo "http://$ip:$port"
                    fi
                done > "${pdir}/web_urls.txt"

                httpx_probe "${pdir}/web_urls.txt" "${pdir}/ip_http_metadata.json" "80,443,8080,8443,8000,8888,3000"
            fi

            # Step 2d: DNS metadata
            log_info "Gathering DNS metadata..."
            : > "${pdir}/ip_dns_records.txt"
            : > "${pdir}/ip_dns_metadata.json"

            while read -r ip; do
                [[ -z "$ip" ]] && continue
                host "$ip" 2>/dev/null >> "${pdir}/ip_dns_records.txt" || true

                if command -v dnsx &>/dev/null; then
                    echo "$ip" | dnsx -silent -a -aaaa -cname -ns -txt -mx -ptr -srv \
                        -json -retry 3 2>/dev/null >> "${pdir}/ip_dns_metadata.json" || true
                fi
            done < "${pdir}/live_ips.txt"

            # Step 2e: Extract domain names from metadata
            extract_domains "${pdir}/ip_dns_records.txt" "${pdir}/domains_from_dns.txt"

            if [[ -s "${pdir}/ip_http_metadata.json" ]]; then
                jq -r '.tls.subject_cn?, .tls.subject_an[]?' "${pdir}/ip_http_metadata.json" 2>/dev/null \
                    | grep -v '^null$' | sort -u > "${pdir}/domains_from_ssl.txt" || true
            fi

            if [[ -s "${pdir}/ip_dns_metadata.json" ]]; then
                jq -r '.cname[]?, .mx[]?, .ns[]?, .ptr[]?' "${pdir}/ip_dns_metadata.json" 2>/dev/null \
                    | grep -v '^null$' | sort -u > "${pdir}/domains_from_dns_records.txt" || true
            fi

            cat "${pdir}/domains_from_dns.txt" "${pdir}/domains_from_ssl.txt" "${pdir}/domains_from_dns_records.txt" \
                2>/dev/null | sort -u > "${pdir}/domains_from_ips.txt" || true

            if [[ -s "${pdir}/domains_from_ips.txt" ]]; then
                log_success "Domains from IP metadata: $(wc -l < "${pdir}/domains_from_ips.txt")"
            fi
        else
            log_warn "No live IPs found in network ranges"
        fi
    else
        log_warn "No network ranges discovered, skipping network scanning"
    fi

    # ── Stage 3: Free OSINT Sources ─────────────────────────────────────────
    log_info "Stage 3: Free OSINT Domain Discovery"

    # crt.sh — run per-domain if we already know some, or skip
    : > "${pdir}/crtsh_domains.txt"
    if [[ -n "$DOMAINS" ]]; then
        IFS=',' read -ra domain_arr <<< "$DOMAINS"
        for d in "${domain_arr[@]}"; do
            d=$(echo "$d" | xargs)
            log_info "Querying crt.sh for: $d"
            curl -s "https://crt.sh/?q=%25.${d}&output=json" | \
                jq -r '.[].name_value' 2>/dev/null | \
                sed 's/\*\.//g' | sort -u | \
                grep "\.$(echo "$d" | sed 's/\./\\./g')$" >> "${pdir}/crtsh_domains.txt" || true
        done
    elif [[ -s "${pdir}/domains_from_ips.txt" ]]; then
        # Try crt.sh with domains we found from IPs
        head -5 "${pdir}/domains_from_ips.txt" | while read -r d; do
            log_info "Querying crt.sh for: $d"
            curl -s "https://crt.sh/?q=%25.${d}&output=json" | \
                jq -r '.[].name_value' 2>/dev/null | \
                sed 's/\*\.//g' | sort -u >> "${pdir}/crtsh_domains.txt" || true
        done
    fi

    if [[ -s "${pdir}/crtsh_domains.txt" ]]; then
        log_success "Domains from crt.sh: $(sort -u "${pdir}/crtsh_domains.txt" | wc -l)"
        sort -u "${pdir}/crtsh_domains.txt" -o "${pdir}/crtsh_domains.txt"
    fi

    # WHOIS lookup
    : > "${pdir}/whois_info.txt"
    if [[ -n "$DOMAINS" ]]; then
        IFS=',' read -ra domain_arr <<< "$DOMAINS"
        for d in "${domain_arr[@]}"; do
            d=$(echo "$d" | xargs)
            whois "$d" 2>/dev/null | grep -E 'Registrant|Admin|Tech' | grep -E 'Organization|Email' \
                >> "${pdir}/whois_info.txt" || true
        done
    fi

    log_skip "Manual steps skipped: Google dorking (requires browser), reverse WHOIS browser lookup"

    # ── Stage 4: GitHub Recon ───────────────────────────────────────────────
    : > "${pdir}/github_repos.txt"
    : > "${pdir}/github_domains.txt"

    if [[ -n "$GITHUB_TOKEN" ]]; then
        log_info "Stage 4: GitHub Recon"
        local search_query
        search_query=$(echo "$COMPANY" | tr ' ' '+')
        search_query="${search_query}%20AND%20(site:com%20OR%20site:net%20OR%20site:org)"

        curl -s -H "Authorization: token $GITHUB_TOKEN" \
            "https://api.github.com/search/code?q=${search_query}&per_page=100" | \
            jq -r '.items[].repository.html_url' 2>/dev/null | sort -u > "${pdir}/github_repos.txt" || true

        if [[ -s "${pdir}/github_repos.txt" ]]; then
            log_success "GitHub repositories found: $(wc -l < "${pdir}/github_repos.txt")"

            # Clone top repos and search for domains
            mkdir -p "${pdir}/github_cloned"
            head -10 "${pdir}/github_repos.txt" | while read -r repo_url; do
                local repo_name
                repo_name=$(basename "$repo_url")
                git clone --depth 1 "$repo_url" "${pdir}/github_cloned/$repo_name" 2>/dev/null || true

                grep -r -ohE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' \
                    "${pdir}/github_cloned/$repo_name" 2>/dev/null | \
                    grep -i "$(echo "$COMPANY" | awk '{print tolower($1)}')" | \
                    sort -u >> "${pdir}/github_domains.txt" || true
            done
            rm -rf "${pdir}/github_cloned"

            if [[ -s "${pdir}/github_domains.txt" ]]; then
                sort -u "${pdir}/github_domains.txt" -o "${pdir}/github_domains.txt"
                log_success "Domains from GitHub: $(wc -l < "${pdir}/github_domains.txt")"
            fi
        else
            log_warn "No GitHub repositories found"
        fi
    else
        log_skip "GitHub recon skipped (no --github-token provided)"
    fi

    # ── Stage 5: Consolidate Root Domains ───────────────────────────────────
    log_info "Stage 5: Consolidating root domains"

    cat \
        "${pdir}/domains_from_ips.txt" \
        "${pdir}/crtsh_domains.txt" \
        "${pdir}/github_domains.txt" \
        2>/dev/null | sort -u | \
        grep -E '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$' \
        > "${pdir}/all_root_domains.txt" || true

    # If --domains was provided, ensure they're included
    if [[ -n "$DOMAINS" ]]; then
        IFS=',' read -ra domain_arr <<< "$DOMAINS"
        for d in "${domain_arr[@]}"; do
            echo "$d" | xargs >> "${pdir}/all_root_domains.txt"
        done
        sort -u "${pdir}/all_root_domains.txt" -o "${pdir}/all_root_domains.txt"
    fi

    if [[ -s "${pdir}/all_root_domains.txt" ]]; then
        log_success "Total unique root domains: $(wc -l < "${pdir}/all_root_domains.txt")"
    else
        log_error "No root domains discovered. Check company name or provide --domains."
        return 1
    fi
}
