#!/usr/bin/env bash
# Shared utility functions for the BB methodology recon pipeline.

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ── Logging ─────────────────────────────────────────────────────────────────
log_info()    { echo -e "${CYAN}[*]${NC} $*"; }
log_success() { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
log_error()   { echo -e "${RED}[-]${NC} $*"; }
log_skip()    { echo -e "${YELLOW}[SKIP]${NC} $*"; }

# ── CLI Argument Parsing ────────────────────────────────────────────────────
COMPANY=""
DOMAINS=""
DOMAINS_FILE=""
SUBFINDER_PROVIDER_CONFIG=""
AUTO=false
SKIP_PHASES=()
THREADS=50
RATE_LIMIT=100
CHECKPOINT_TIMEOUT=30
OUTPUT_DIR="/output"
GITHUB_TOKEN=""

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --company)        COMPANY="$2"; shift 2 ;;
            --domains)        DOMAINS="$2"; shift 2 ;;
            --domains-file)   DOMAINS_FILE="$2"; shift 2 ;;
            --subfinder-config) SUBFINDER_PROVIDER_CONFIG="$2"; shift 2 ;;
            --auto)           AUTO=true; shift ;;
            --skip-phase)     SKIP_PHASES+=("$2"); shift 2 ;;
            --skip-cloud)     SKIP_PHASES+=("3"); shift ;;
            --threads)        THREADS="$2"; shift 2 ;;
            --rate-limit)     RATE_LIMIT="$2"; shift 2 ;;
            --timeout)        CHECKPOINT_TIMEOUT="$2"; shift 2 ;;
            --output)         OUTPUT_DIR="$2"; shift 2 ;;
            --github-token)   GITHUB_TOKEN="$2"; shift 2 ;;
            -h|--help)
                echo "Usage: recon.sh [options]"
                echo ""
                echo "Options:"
                echo "  --company NAME          Target company name (required for Phase 1)"
                echo "  --domains d1,d2,...     Comma-separated root domains (skips Phase 1)"
                echo "  --domains-file FILE     Line-separated root domains file (skips Phase 1)"
                echo "  --subfinder-config FILE Path to subfinder provider-config.yaml"
                echo "  --auto                  Skip all checkpoint prompts"
                echo "  --skip-phase {1,2,3}    Skip specific phase(s)"
                echo "  --skip-cloud            Shorthand for --skip-phase 3"
                echo "  --threads N             Thread count (default: 50)"
                echo "  --rate-limit N          Requests/second (default: 100)"
                echo "  --timeout N             Checkpoint auto-continue seconds (default: 30)"
                echo "  --output DIR            Output directory (default: /output)"
                echo "  --github-token TOKEN    GitHub API token for recon stage"
                exit 0 ;;
            *) log_error "Unknown argument: $1"; exit 1 ;;
        esac
    done
}

validate_args() {
    if [[ -z "$COMPANY" && -z "$DOMAINS" && -z "$DOMAINS_FILE" ]]; then
        log_error "One of --company, --domains, or --domains-file must be provided."
        exit 1
    fi
    if [[ -n "$DOMAINS_FILE" && ! -f "$DOMAINS_FILE" ]]; then
        log_error "Domains file not found: $DOMAINS_FILE"
        exit 1
    fi
    if [[ -n "$DOMAINS_FILE" && ! -s "$DOMAINS_FILE" ]]; then
        log_error "Domains file is empty: $DOMAINS_FILE"
        exit 1
    fi
    if [[ -n "$SUBFINDER_PROVIDER_CONFIG" && ! -f "$SUBFINDER_PROVIDER_CONFIG" ]]; then
        log_error "Subfinder config file not found: $SUBFINDER_PROVIDER_CONFIG"
        exit 1
    fi
    if [[ -n "$SUBFINDER_PROVIDER_CONFIG" ]]; then
        export SUBFINDER_PROVIDER_CONFIG
        log_info "Subfinder provider config: $SUBFINDER_PROVIDER_CONFIG"
    fi
}

# Resolve domain input (--domains or --domains-file) into a file path.
# Returns the path to a file with one domain per line.
resolve_domain_file() {
    local target="$1"

    if [[ -n "$DOMAINS_FILE" ]]; then
        # Clean and deduplicate the file
        grep -v '^\s*$' "$DOMAINS_FILE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u > "$target"
        echo "$target"
        return
    fi

    if [[ -n "$DOMAINS" ]]; then
        IFS=',' read -ra domain_arr <<< "$DOMAINS"
        for d in "${domain_arr[@]}"; do
            echo "$d" | xargs
        done | sort -u > "$target"
        echo "$target"
        return
    fi

    echo ""
}

should_skip_phase() {
    local phase="$1"
    for p in "${SKIP_PHASES[@]}"; do
        [[ "$p" == "$phase" ]] && return 0
    done
    return 1
}

# ── Checkpoint System ───────────────────────────────────────────────────────
checkpoint() {
    local message="$1"
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}[CHECKPOINT]${NC} $message"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""

    if [[ "$AUTO" == true ]]; then
        log_info "Auto mode — continuing..."
        return 0
    fi

    if [[ ! -t 0 ]]; then
        log_info "Non-interactive terminal — continuing..."
        return 0
    fi

    echo "  [C]ontinue  [S]kip next phase  [Q]uit  [R]eview results"
    echo -n "  > "

    if [[ "$CHECKPOINT_TIMEOUT" -gt 0 ]]; then
        read -t "$CHECKPOINT_TIMEOUT" -r choice < /dev/tty || choice="c"
    else
        read -r choice < /dev/tty
    fi

    case "${choice,,}" in
        c|""|"continue")   return 0 ;;
        s|skip)            return 2 ;;
        q|quit)            log_info "Exiting."; exit 0 ;;
        r|review)
            echo ""
            echo "  Phase output files:"
            ls -la "${OUTPUT_DIR}/phase${CURRENT_PHASE:-?}/" 2>/dev/null | tail -20
            echo ""
            echo -n "  Press Enter to continue... "
            read -r < /dev/tty
            return 0 ;;
        *) return 0 ;;
    esac
}

# ── Directory Setup ─────────────────────────────────────────────────────────
setup_dirs() {
    mkdir -p "${OUTPUT_DIR}"/{phase1,phase2,phase3,final}
    chmod -R 777 "$OUTPUT_DIR" 2>/dev/null
}

# ── Dependency Check ────────────────────────────────────────────────────────
REQUIRED_TOOLS=(nmap jq curl wget git)

validate_deps() {
    local missing=()
    for tool in "${REQUIRED_TOOLS[@]}"; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi
}

# ── HTTPx Probe Helper ─────────────────────────────────────────────────────
HTTPX_PORTS="80,443,7547,8089,8085,8443,8080,4567,7170,8008,2083,8000,2082,8081,2087,2086,8888,8880,60000,40000,9080,5985,9100,2096,3000,1024,30005,81,21,5000,2095"
HTTPX_MATCH_CODES="100,101,200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,307,308,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,421,422,423,424,426,428,429,431,451,500,501,502,503,504,505,506,507,508,510,511"

httpx_probe() {
    local input_file="$1"
    local output_json="$2"
    local ports="${3:-$HTTPX_PORTS}"

    if [[ ! -s "$input_file" ]]; then
        log_warn "No subdomains to probe in $input_file"
        return
    fi

    log_info "Probing $(wc -l < "$input_file") targets with httpx..."

    cat "$input_file" | httpx \
        -ports "$ports" \
        -silent \
        -json \
        -status-code \
        -title \
        -tech-detect \
        -server \
        -content-length \
        -timeout 10 \
        -retries 2 \
        -rate-limit "$RATE_LIMIT" \
        -mc "$HTTPX_MATCH_CODES" \
        -o "$output_json" 2>/dev/null

    if [[ -s "$output_json" ]]; then
        local count
        count=$(wc -l < "$output_json")
        log_success "Live web servers found: $count"
    else
        log_warn "No live web servers found in this round."
    fi
}

# ── Domain Extraction ───────────────────────────────────────────────────────
extract_domains() {
    local input_file="$1"
    local output_file="$2"
    grep -oE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' "$input_file" \
        | sort -u > "$output_file"
}

# ── Cloud Domain Filter ────────────────────────────────────────────────────
filter_cloud_domains() {
    local input_file="$1"
    local output_file="$2"
    grep -iE '(amazonaws|cloudfront|s3[^0-9]|azurewebsites|azure|blob\.core|cloudapp|googleapis|appspot|cloudfunctions|storage\.googleapis)' \
        "$input_file" | sort -u > "$output_file" 2>/dev/null || true
}
