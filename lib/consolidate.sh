#!/usr/bin/env bash
# Final Consolidation: merges all phase outputs into a clean final/ directory
# and generates RECON_SUMMARY.txt

run_consolidation() {
    local fdir="${OUTPUT_DIR}/final"
    mkdir -p "$fdir"

    log_info "═══ CONSOLIDATING ALL RESULTS ═══"

    # ── ASNs ────────────────────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase1/asn_list.txt" 2>/dev/null | sort -u > "${fdir}/final_asn_list.txt" || true
    local asn_total=0
    [[ -s "${fdir}/final_asn_list.txt" ]] && asn_total=$(wc -l < "${fdir}/final_asn_list.txt")

    # ── Network Ranges ──────────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase1/network_ranges.txt" 2>/dev/null | sort -u > "${fdir}/final_network_ranges.txt" || true
    local network_total=0
    [[ -s "${fdir}/final_network_ranges.txt" ]] && network_total=$(wc -l < "${fdir}/final_network_ranges.txt")

    # ── IP Addresses ────────────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase1/live_ips.txt" 2>/dev/null | sort -u -V > "${fdir}/final_ip_addresses.txt" || true
    local ip_total=0
    [[ -s "${fdir}/final_ip_addresses.txt" ]] && ip_total=$(wc -l < "${fdir}/final_ip_addresses.txt")

    # ── All Domains (all subdomains from Phase 2) ───────────────────────────
    cat "${OUTPUT_DIR}"/phase2/*/all_subdomains_final.txt 2>/dev/null | sort -u > "${fdir}/final_all_domains.txt" || true
    local domain_total=0
    [[ -s "${fdir}/final_all_domains.txt" ]] && domain_total=$(wc -l < "${fdir}/final_all_domains.txt")

    # ── Live Web Servers ────────────────────────────────────────────────────
    cat "${OUTPUT_DIR}"/phase2/*/live_subdomains_final.txt 2>/dev/null | sort -u > "${fdir}/final_live_web_servers.txt" || true
    local live_total=0
    [[ -s "${fdir}/final_live_web_servers.txt" ]] && live_total=$(wc -l < "${fdir}/final_live_web_servers.txt")

    # ── Cloud Assets ────────────────────────────────────────────────────────
    cat "${OUTPUT_DIR}/phase3/final_cloud_assets.txt" 2>/dev/null | sort -u > "${fdir}/final_cloud_assets.txt" || true
    local cloud_total=0
    [[ -s "${fdir}/final_cloud_assets.txt" ]] && cloud_total=$(wc -l < "${fdir}/final_cloud_assets.txt")

    # ── Root Domains ────────────────────────────────────────────────────────
    local root_total=0
    [[ -s "${OUTPUT_DIR}/phase1/all_root_domains.txt" ]] && root_total=$(wc -l < "${OUTPUT_DIR}/phase1/all_root_domains.txt")

    # ── Summary Report ──────────────────────────────────────────────────────
    cat > "${OUTPUT_DIR}/RECON_SUMMARY.txt" <<EOF
========================================
RECONNAISSANCE PHASE COMPLETE
========================================

Target Company: ${COMPANY:-N/A}

ASSETS DISCOVERED:
- Root Domains:      ${root_total}
- All Subdomains:    ${domain_total}
- Live Web Servers:  ${live_total}
- Cloud Assets:      ${cloud_total}
- ASNs:              ${asn_total}
- Network Ranges:    ${network_total}
- IP Addresses:      ${ip_total}

FILES CREATED IN final/:
- final_all_domains.txt
- final_live_web_servers.txt
- final_cloud_assets.txt
- final_asn_list.txt
- final_network_ranges.txt
- final_ip_addresses.txt

NEXT STEPS:
Proceed to vulnerability scanning / enumeration on live web servers.

========================================
EOF

    log_success "Summary report written to RECON_SUMMARY.txt"
    echo ""
    cat "${OUTPUT_DIR}/RECON_SUMMARY.txt"
}
