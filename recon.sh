#!/usr/bin/env bash
#
# BB Methodology — Automated Recon Pipeline
#
# Usage:
#   docker run --rm -it -v $(pwd)/results:/output bb-methodology [options]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source all library scripts
source "${SCRIPT_DIR}/lib/utils.sh"
source "${SCRIPT_DIR}/lib/phase1.sh"
source "${SCRIPT_DIR}/lib/phase2.sh"
source "${SCRIPT_DIR}/lib/phase3.sh"
source "${SCRIPT_DIR}/lib/consolidate.sh"

# Parse CLI arguments
parse_args "$@"
validate_args

# Banner
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║        BB Methodology — Recon Pipeline           ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
log_info "Company:    ${COMPANY:-<not set>}"
log_info "Domains:    ${DOMAINS:-<not set>}"
log_info "Domains file: ${DOMAINS_FILE:-<not set>}"
log_info "Auto mode:  ${AUTO}"
log_info "Output:     ${OUTPUT_DIR}"
log_info "Threads:    ${THREADS}"
log_info "Rate limit: ${RATE_LIMIT}/s"
echo ""

# Setup
validate_deps
setup_dirs

# ── Determine root domains file ─────────────────────────────────────────────
ROOT_DOMAINS_FILE=""

# ── Phase 1 ─────────────────────────────────────────────────────────────────
if ! should_skip_phase 1; then
    if [[ -n "$COMPANY" ]]; then
        run_phase1
        ROOT_DOMAINS_FILE="${OUTPUT_DIR}/phase1/all_root_domains.txt"

        local_rc=0
        checkpoint "Phase 1 complete. Root domains: $(wc -l < "${ROOT_DOMAINS_FILE}" 2>/dev/null || echo '?')" || local_rc=$?
        if [[ $local_rc -eq 2 ]]; then
            log_info "Skipping Phase 2 by user request"
        fi
    else
        # No company name — resolve domains from --domains or --domains-file
        log_warn "No --company provided, skipping Phase 1"
        ROOT_DOMAINS_FILE=$(resolve_domain_file "${OUTPUT_DIR}/phase1/all_root_domains.txt")
        log_info "Loaded $(wc -l < "$ROOT_DOMAINS_FILE") root domains from input"
    fi
else
    log_info "Skipping Phase 1 (--skip-phase)"
    ROOT_DOMAINS_FILE=$(resolve_domain_file "${OUTPUT_DIR}/phase1/all_root_domains.txt")
    if [[ -z "$ROOT_DOMAINS_FILE" || ! -s "$ROOT_DOMAINS_FILE" ]]; then
        log_error "Phase 1 skipped but no --domains or --domains-file provided. Nothing to scan."
        exit 1
    fi
    log_info "Loaded $(wc -l < "$ROOT_DOMAINS_FILE") root domains from input"
fi

if [[ ! -s "${ROOT_DOMAINS_FILE:-}" ]]; then
    log_error "No root domains available. Cannot continue."
    exit 1
fi

# ── Phase 2 ─────────────────────────────────────────────────────────────────
if ! should_skip_phase 2; then
    run_phase2 "$ROOT_DOMAINS_FILE"

    checkpoint "Phase 2 complete. Subdomains discovered for $(wc -l < "${ROOT_DOMAINS_FILE}") domain(s)." || true
else
    log_info "Skipping Phase 2 (--skip-phase)"
fi

# ── Phase 3 ─────────────────────────────────────────────────────────────────
if ! should_skip_phase 3; then
    ALL_SUBDOMAINS_FILE="${OUTPUT_DIR}/final/final_all_domains.txt"
    LIVE_WEB_FILE="${OUTPUT_DIR}/final/final_live_web_servers.txt"

    # Build intermediate files if Phase 2 ran
    if ! should_skip_phase 2; then
        cat "${OUTPUT_DIR}"/phase2/*/all_subdomains_final.txt 2>/dev/null | sort -u > "$ALL_SUBDOMAINS_FILE" || true
        cat "${OUTPUT_DIR}"/phase2/*/live_subdomains_final.txt 2>/dev/null | sort -u > "$LIVE_WEB_FILE" || true
    fi

    run_phase3 "$ROOT_DOMAINS_FILE" "$ALL_SUBDOMAINS_FILE" "$LIVE_WEB_FILE"

    checkpoint "Phase 3 complete. Cloud assets: $(wc -l < "${OUTPUT_DIR}/phase3/final_cloud_assets.txt" 2>/dev/null || echo '?')" || true
else
    log_info "Skipping Phase 3 (--skip-phase / --skip-cloud)"
fi

# ── Final Consolidation ────────────────────────────────────────────────────
run_consolidation

log_success "Recon pipeline complete!"
