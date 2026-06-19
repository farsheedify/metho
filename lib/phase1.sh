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

    # Assetfinder
    if command -v assetfinder &>/dev/null; then
        log_info "Running Assetfinder..."
        assetfinder --subs-only "$domain" > assetfinder_results.txt 2>/dev/null || true
    fi

    # GAU
    if command -v gau &>/dev/null; then
        log_info "Running GAU..."
        echo "$domain" | gau --subs --threads 10 2>/dev/null | \
            grep -oE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' | \
            grep "$domain" | sort -u > gau_results.txt || true
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

        # Extract subdomains from output: look for lines that are valid domain names
        # Sublist3r prints results as plain domain names, one per line, after the banner
        grep -oE '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$' "$sublist3r_all_output" 2>/dev/null | \
            grep -E "\.${domain}$|^${domain}$" | \
            sort -u > sublist3r_results.txt || true

        local sl3_count=0
        [[ -s sublist3r_results.txt ]] && sl3_count=$(wc -l < sublist3r_results.txt)
        log_success "Sublist3r subdomains captured: $sl3_count (errors from some engines ignored)"

        # Keep full output for debugging
        mv "$sublist3r_all_output" sublist3r_full_output.txt
    fi

    # github-subdomains
    if [[ -n "$GITHUB_TOKENS_FILE" ]] && command -v github-subdomains &>/dev/null; then
        log_info "Running github-subdomains..."
        github-subdomains -d "$domain" \
            -t "$GITHUB_TOKENS_FILE" \
            -o github_subdomains_results.txt 2>/dev/null || true
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
            timeout 600 cewl "$url" -d 2 -m 5 -c --with-numbers 2>/dev/null | \
                grep -v '^[0-9]' | \
                awk -F',' '{print $1}' | \
                tr '[:upper:]' '[:lower:]' | \
                grep -E '^[a-z0-9]{3,20}$' >> wordlists/custom_wordlist.txt || true
        done < live_subdomains_round1.txt
        sort -u wordlists/custom_wordlist.txt -o wordlists/custom_wordlist.txt
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

    log_info "Wordlist size: $(wc -l < wordlists/custom_wordlist.txt) words"

    # Step 3b: ShuffleDNS brute force
    if command -v shuffledns &>/dev/null; then
        log_info "Running ShuffleDNS brute force..."
        shuffledns -d "$domain" \
            -w wordlists/custom_wordlist.txt \
            -r /opt/scripts/wordlists/resolvers.txt \
            -mode bruteforce \
            -t "$THREADS" \
            -o shuffledns_results.txt 2>/dev/null || true

        if [[ -s shuffledns_results.txt ]]; then
            log_success "Subdomains from brute force: $(wc -l < shuffledns_results.txt)"
        fi
    else
        log_warn "ShuffleDNS not found, skipping brute force"
    fi

    # ── Stage 4: Consolidate & HTTPx Round 2 ────────────────────────────────
    log_info "Stage 4: Consolidate + HTTPx Round 2"

    cat all_subdomains_round1.txt shuffledns_results.txt 2>/dev/null | \
        sort -u > all_subdomains_round2.txt || true

    local new_subs=0
    if [[ -s all_subdomains_round1.txt && -s all_subdomains_round2.txt ]]; then
        new_subs=$(comm -13 all_subdomains_round1.txt all_subdomains_round2.txt | wc -l)
        log_success "New subdomains from brute force: $new_subs"
    fi

    httpx_probe all_subdomains_round2.txt httpx_results_round2.json
    [[ -s httpx_results_round2.json ]] && jq -r '.url' httpx_results_round2.json | sort -u > live_subdomains_round2.txt

    # ── Stage 5: Web Crawling ───────────────────────────────────────────────
    log_info "Stage 5: Web Crawling & JS Link Discovery"

    # GoSpider
    if command -v gospider &>/dev/null && [[ -s live_subdomains_round2.txt ]]; then
        mkdir -p gospider
        : > gospider/raw_output.txt

        while read -r url; do
            [[ -z "$url" ]] && continue
            log_info "  Crawling $url with GoSpider..."
            gospider -s "$url" -c 10 -d 3 -t 3 -k 1 -K 2 -m 30 \
                --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|svg)" \
                -a -w -r --js --sitemap --robots --json -v 2>/dev/null | \
                tee -a gospider/raw_output.txt || true
        done < live_subdomains_round2.txt

        if [[ -s gospider/raw_output.txt ]]; then
            extract_domains gospider/raw_output.txt gospider/all_domains.txt
            grep "$domain" gospider/all_domains.txt | sort -u > gospider_subdomains.txt || true
            [[ -s gospider_subdomains.txt ]] && log_success "GoSpider subdomains: $(wc -l < gospider_subdomains.txt)"
        fi
    fi

    # Subdomainizer
    if [[ -f /opt/tools/SubDomainizer/SubDomainizer.py ]] && [[ -s live_subdomains_round2.txt ]]; then
        mkdir -p subdomainizer
        : > subdomainizer/raw_output.txt

        while read -r url; do
            [[ -z "$url" ]] && continue
            log_info "  Running Subdomainizer on $url..."
            python3 /opt/tools/SubDomainizer/SubDomainizer.py \
                -u "$url" -k -o subdomainizer/temp_output.txt 2>/dev/null || true

            if [[ -s subdomainizer/temp_output.txt ]]; then
                cat subdomainizer/temp_output.txt >> subdomainizer/raw_output.txt
                rm -f subdomainizer/temp_output.txt
            fi
        done < live_subdomains_round2.txt

        if [[ -s subdomainizer/raw_output.txt ]]; then
            extract_domains subdomainizer/raw_output.txt subdomainizer/all_domains.txt
            grep "$domain" subdomainizer/all_domains.txt | sort -u > subdomainizer_subdomains.txt || true
            [[ -s subdomainizer_subdomains.txt ]] && log_success "Subdomainizer subdomains: $(wc -l < subdomainizer_subdomains.txt)"
        fi
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

    httpx_probe all_subdomains_final.txt httpx_results_final.json
    [[ -s httpx_results_final.json ]] && jq -r '.url' httpx_results_final.json | sort -u > live_subdomains_final.txt

    local final_live=0
    [[ -s live_subdomains_final.txt ]] && final_live=$(wc -l < live_subdomains_final.txt)
    log_success "FINAL live web servers for $domain: $final_live"

    cd "$pdir" || return 1
}
