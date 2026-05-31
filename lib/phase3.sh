#!/usr/bin/env bash
# Phase 3: IP Extraction, ASN Lookup, CDN Filtering, Port Scanning
# Resolves all discovered domains to IPs, maps IPs to ASNs (sorted by occurrence),
# filters out CDN ranges, and port scans non-CDN IPs.

run_phase3() {
    local pdir="${OUTPUT_DIR}/phase3"
    mkdir -p "$pdir"
    CURRENT_PHASE=3

    log_info "═══ PHASE 3: IP Extraction → ASN Mapping → Port Scanning ═══"

    local all_domains_file="${OUTPUT_DIR}/final/final_all_domains.txt"
    if [[ ! -s "$all_domains_file" ]]; then
        cat "${OUTPUT_DIR}"/phase1/*/all_subdomains_final.txt 2>/dev/null | sort -u > "$all_domains_file" || true
    fi

    if [[ ! -s "$all_domains_file" ]]; then
        log_error "No domains available for IP extraction"
        return 1
    fi

    local domain_count
    domain_count=$(wc -l < "$all_domains_file")
    log_info "Resolving IPs for ${domain_count} domains..."

    # ── Stage 1: DNS Resolution → IP Addresses ──────────────────────────────
    log_info "Stage 1: Resolving domains to IP addresses"

    : > "${pdir}/all_ips_raw.txt"

    # Use dnsx for fast bulk resolution if available
    if command -v dnsx &>/dev/null; then
        log_info "Using dnsx for bulk DNS resolution..."
        cat "$all_domains_file" | dnsx -silent -a -json -retry 2 2>/dev/null | \
            jq -r '.host as $host | .a[]? | "\($host) \(. "")"' 2>/dev/null > "${pdir}/dnsx_resolution.json" || true

        # Extract just IPs
        cat "${pdir}/dnsx_resolution.json" 2>/dev/null | \
            jq -r 'select(.a != null) | .a[]?' 2>/dev/null | sort -u > "${pdir}/all_ips_raw.txt" || true

        # Also build domain→IP mapping
        : > "${pdir}/domain_ip_map.txt"
        cat "$all_domains_file" | while read -r dom; do
            [[ -z "$dom" ]] && continue
            local ips
            ips=$(dig +short "$dom" A 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
            for ip in $ips; do
                echo "$dom $ip" >> "${pdir}/domain_ip_map.txt"
                echo "$ip" >> "${pdir}/all_ips_raw.txt"
            done
        done
    else
        # Fallback to dig
        log_info "Using dig for DNS resolution (dnsx not available)..."
        : > "${pdir}/domain_ip_map.txt"

        while read -r dom; do
            [[ -z "$dom" ]] && continue
            local ips
            ips=$(dig +short "$dom" A 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
            for ip in $ips; do
                echo "$dom $ip" >> "${pdir}/domain_ip_map.txt"
                echo "$ip" >> "${pdir}/all_ips_raw.txt"
            done
        done < "$all_domains_file"
    fi

    sort -u "${pdir}/all_ips_raw.txt" > "${pdir}/all_ips.txt" 2>/dev/null || true
    rm -f "${pdir}/all_ips_raw.txt"

    local ip_count=0
    [[ -s "${pdir}/all_ips.txt" ]] && ip_count=$(wc -l < "${pdir}/all_ips.txt")
    log_success "Unique IP addresses resolved: $ip_count"

    if [[ "$ip_count" -eq 0 ]]; then
        log_warn "No IPs resolved, skipping ASN lookup and port scanning"
        return 0
    fi

    # ── Stage 2: IP → ASN Lookup via whois.cymru.com ────────────────────────
    log_info "Stage 2: Looking up ASNs via whois.cymru.com"

    {
        echo "begin"
        echo "verbose"
        cat "${pdir}/all_ips.txt"
        echo "end"
    } | nc whois.cymru.com 43 2>/dev/null | awk -F'|' '
    NR>1 {
        gsub(/^[ \t]+|[ \t]+$/, "", $1);
        gsub(/^[ \t]+|[ \t]+$/, "", $3);
        gsub(/^[ \t]+|[ \t]+$/, "", $7);

        asn="AS"$1
        key=asn "|" $7 "|" $3
        count[key]++
    }
    END {
        for (k in count) {
            split(k, parts, "|")
            printf "%s|%s|%s|%d\n", parts[1], parts[2], parts[3], count[k]
        }
    }' > "${pdir}/asn_raw.txt" || true

    # Build IP→ASN mapping by re-querying
    {
        echo "begin"
        echo "verbose"
        cat "${pdir}/all_ips.txt"
        echo "end"
    } | nc whois.cymru.com 43 2>/dev/null | awk -F'|' '
    NR>1 {
        gsub(/^[ \t]+|[ \t]+$/, "", $1);
        gsub(/^[ \t]+|[ \t]+$/, "", $2);
        gsub(/^[ \t]+|[ \t]+$/, "", $3);
        gsub(/^[ \t]+|[ \t]+$/, "", $7);

        asn="AS"$1
        print $2 "|" asn "|" $3 "|" $7
    }' > "${pdir}/ip_asn_map.txt" || true

    # Build ASN summary sorted by occurrence count (descending)
    : > "${pdir}/asn_summary.txt"
    awk -F'|' '{asn=$1; name=$2; prefix=$3; count=$4} {key=asn"|"name; totals[key]+=count; prefixes[key]=prefix} END {for (k in totals) {split(k,p,"|"); printf "%s|%s|%s|%d\n", p[1], p[2], prefixes[k], totals[k]}}' \
        "${pdir}/asn_raw.txt" 2>/dev/null | \
        sort -t'|' -k4 -rn > "${pdir}/asn_summary.txt" || true

    if [[ -s "${pdir}/asn_summary.txt" ]]; then
        log_success "ASN summary:"
        head -20 "${pdir}/asn_summary.txt" | while IFS='|' read -r asn name prefix count; do
            log_info "  ${asn} | ${name} | ${prefix} | ${count} IPs"
        done
        log_info "  ... (total $(wc -l < "${pdir}/asn_summary.txt") ASNs)"
    fi

    cut -d'|' -f1 "${pdir}/asn_summary.txt" 2>/dev/null | sort -u > "${pdir}/asn_list.txt" || true
    cut -d'|' -f3 "${pdir}/asn_summary.txt" 2>/dev/null | sort -u > "${pdir}/network_ranges.txt" || true

    # ── Stage 3: CDN Filtering ──────────────────────────────────────────────
    log_info "Stage 3: Identifying CDN-associated IPs"

    : > "${pdir}/cdn_ips.txt"
    : > "${pdir}/non_cdn_ips.txt"

    if [[ -s "${pdir}/ip_asn_map.txt" ]]; then
        while IFS='|' read -r ip asn name prefix; do
            [[ -z "$ip" || -z "$asn" ]] && continue
            if is_cdn_asn "$asn"; then
                echo "$ip" >> "${pdir}/cdn_ips.txt"
            else
                echo "$ip" >> "${pdir}/non_cdn_ips.txt"
            fi
        done < "${pdir}/ip_asn_map.txt"
    fi

    sort -u "${pdir}/cdn_ips.txt" -o "${pdir}/cdn_ips.txt" 2>/dev/null || true
    sort -u "${pdir}/non_cdn_ips.txt" -o "${pdir}/non_cdn_ips.txt" 2>/dev/null || true

    local cdn_count=0 non_cdn_count=0
    [[ -s "${pdir}/cdn_ips.txt" ]] && cdn_count=$(wc -l < "${pdir}/cdn_ips.txt")
    [[ -s "${pdir}/non_cdn_ips.txt" ]] && non_cdn_count=$(wc -l < "${pdir}/non_cdn_ips.txt")

    log_info "CDN IPs: $cdn_count | Non-CDN IPs: $non_cdn_count"

    # ── Stage 4: Port Scan on Non-CDN IPs ───────────────────────────────────
    if [[ "$PORT_SCAN" == true && -s "${pdir}/non_cdn_ips.txt" ]]; then
        log_info "Stage 4: Port scanning ${non_cdn_count} non-CDN IPs"

        if command -v nmap &>/dev/null; then
            nmap -iL "${pdir}/non_cdn_ips.txt" \
                -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,5985,5986,6379,6443,8080,8443,8888,9090,9200,9443,27017 \
                --open --min-rate 500 \
                -oG "${pdir}/port_scan_results.txt" 2>/dev/null || true

            # Parse nmap greppable output: extract IP:port pairs
            : > "${pdir}/ip_port_pairs.txt"
            grep '/open/' "${pdir}/port_scan_results.txt" 2>/dev/null | while read -r line; do
                ip=$(echo "$line" | awk '{print $2}')
                echo "$line" | grep -oE '[0-9]+/open/tcp' | \
                    sed 's|/open/tcp||' | \
                    while read -r port; do
                        echo "${ip}:${port}"
                    done
            done | sort -u > "${pdir}/ip_port_pairs.txt" || true

            if [[ -s "${pdir}/ip_port_pairs.txt" ]]; then
                log_success "IP:Port pairs discovered: $(wc -l < "${pdir}/ip_port_pairs.txt")"
            else
                grep '/open/' "${pdir}/port_scan_results.txt" 2>/dev/null | \
                    awk '{print $2}' | sort -u > "${pdir}/non_cdn_live_ips.txt" || true
                log_warn "Detailed port parsing had issues, saved live IPs instead"
            fi
        else
            log_warn "nmap not available, skipping port scan"
        fi
    elif [[ "$PORT_SCAN" != true ]]; then
        log_skip "Port scanning disabled (--no-port-scan)"
    else
        log_warn "No non-CDN IPs to port scan"
    fi

    log_success "Phase 3 complete"
}
