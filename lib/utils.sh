#!/usr/bin/env bash
# Shared utility functions for the Metho recon pipeline.

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ── Logging ─────────────────────────────────────────────────────────────────
LOG_FILE=""

init_log() {
    LOG_FILE="${OUTPUT_DIR}/recon.log"
    : > "$LOG_FILE"
    log_info "Log file: $LOG_FILE"
}

_log_ts() { date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo '?'; }

# Unix-seconds timestamp. Used by phase stages to log wall-clock
# duration without spawning `date` repeatedly. Falls back to the
# timestamp helper if epoch isn't available (e.g. some BSD variants).
_now() { date +%s 2>/dev/null || date '+%Y%m%d%H%M%S' | sed 's/^/0/'; }

# Pretty-print a duration in seconds as e.g. "2m 14s" or "47s".
# Used by Stage timing lines added in Phase 2 to help identify which
# tool stalled when a long-running scan is interrupted.
_format_duration() {
    local secs="$1"
    if [[ "$secs" -lt 60 ]]; then
        echo "${secs}s"
    elif [[ "$secs" -lt 3600 ]]; then
        echo "$((secs / 60))m $((secs % 60))s"
    else
        echo "$((secs / 3600))h $(((secs % 3600) / 60))m"
    fi
}

log_info()    { local msg="[*] $*"; echo -e "${CYAN}${msg}${NC}"; [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; }
log_success() { local msg="[+] $*"; echo -e "${GREEN}${msg}${NC}"; [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; }
log_warn()    { local msg="[!] $*"; echo -e "${YELLOW}${msg}${NC}"; [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; }
log_error()   { local msg="[-] $*"; echo -e "${RED}${msg}${NC}"; [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; }
log_skip()    { local msg="[SKIP] $*"; echo -e "${YELLOW}${msg}${NC}"; [[ -n "$LOG_FILE" ]] && echo "$(_log_ts) ${msg}" >> "$LOG_FILE"; }

# ── CLI Argument Parsing ────────────────────────────────────────────────────
DOMAINS=""
DOMAINS_FILE=""
SUBFINDER_PROVIDER_CONFIG=""
AUTO=false
SKIP_PHASES=()
THREADS=50
RATE_LIMIT=100
CHECKPOINT_TIMEOUT=30
OUTPUT_DIR="/output"
GITHUB_TOKENS_FILE=""
CLOUD_ENUM_KEYWORDS=""
PORT_SCAN=true

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domains)        DOMAINS="$2"; shift 2 ;;
            --domains-file)   DOMAINS_FILE="$2"; shift 2 ;;
            --subfinder-config) SUBFINDER_PROVIDER_CONFIG="$2"; shift 2 ;;
            --auto)           AUTO=true; shift ;;
            --skip-phase)     SKIP_PHASES+=("$2"); shift 2 ;;
            --skip-cloud)     SKIP_PHASES+=("2"); shift ;;
            --no-port-scan)   PORT_SCAN=false; shift ;;
            --threads)        THREADS="$2"; shift 2 ;;
            --rate-limit)     RATE_LIMIT="$2"; shift 2 ;;
            --timeout)        CHECKPOINT_TIMEOUT="$2"; shift 2 ;;
            --output)         OUTPUT_DIR="$2"; shift 2 ;;
            --github-tokens-file) GITHUB_TOKENS_FILE="$2"; shift 2 ;;
            --cloud-enum-keywords) CLOUD_ENUM_KEYWORDS="$2"; shift 2 ;;
            -h|--help)
                echo "Usage: recon.sh [options]"
                echo ""
                echo "Required (one of):"
                echo "  --domains d1,d2,...     Comma-separated root domains"
                echo "  --domains-file FILE     Line-separated root domains file"
                echo ""
                echo "Options:"
                echo "  --subfinder-config FILE Path to subfinder provider-config.yaml"
                echo "  --auto                  Skip all checkpoint prompts"
                echo "  --skip-phase {1,2,3}    Skip specific phase(s)"
                echo "  --skip-cloud            Shorthand for --skip-phase 2"
                echo "  --no-port-scan          Skip port scanning phase"
                echo "  --threads N             Thread count (default: 50)"
                echo "  --rate-limit N          Requests/second (default: 100)"
                echo "  --timeout N             Checkpoint auto-continue seconds (default: 30)"
                echo "  --output DIR            Output directory (default: /output)"
                echo "  --github-tokens-file FILE  File with GitHub tokens (one per line) for github-subdomains"
                echo "  --cloud-enum-keywords KW   Keywords for cloud_enum brute force (comma-sep)"
                exit 0 ;;
            *) log_error "Unknown argument: $1"; exit 1 ;;
        esac
    done
}

validate_args() {
    if [[ -z "$DOMAINS" && -z "$DOMAINS_FILE" ]]; then
        log_error "One of --domains or --domains-file must be provided."
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
    if [[ -n "$GITHUB_TOKENS_FILE" && ! -f "$GITHUB_TOKENS_FILE" ]]; then
        log_error "GitHub tokens file not found: $GITHUB_TOKENS_FILE"
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
REQUIRED_TOOLS=(jq curl wget git)

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
# Default: httpx probes port 443 (HTTPS) then falls back to 80 (HTTP).
# No -ports flag = much faster, covers the vast majority of web services.
# No -mc flag = show all responses (equivalent to listing every status code).

httpx_probe() {
    local input_file="$1"
    local output_json="$2"

    if [[ ! -s "$input_file" ]]; then
        log_warn "No subdomains to probe in $input_file"
        return
    fi

    local target_count
    target_count=$(wc -l < "$input_file")
    log_info "Probing ${target_count} targets with httpx..."

    # httpx log file for full verbose output (for debugging)
    local httpx_log="${output_json%.json}.httpx.log"

    # Run httpx. The -o file captures the JSON results; httpx ALSO prints the
    # same JSON to stdout, which would flood the console with raw JSONL (seen
    # in our runs), so stdout goes to /dev/null. `|| true`: a non-zero httpx
    # exit (no live hosts, resolver failure) must not abort the whole
    # pipeline under set -e + pipefail.
    cat "$input_file" | httpx \
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
        -o "$output_json" > /dev/null 2>"$httpx_log" || true

    local count=0
    if [[ -s "$output_json" ]]; then
        count=$(wc -l < "$output_json")
        log_success "Live web servers found: $count"
    else
        log_warn "No live web servers found in this round."
    fi

    # Append a summary to the httpx log for context
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] httpx run complete: ${count} results from ${target_count} targets" >> "$httpx_log"
}

# ── Domain Extraction ───────────────────────────────────────────────────────
extract_domains() {
    local input_file="$1"
    local output_file="$2"
    # `|| true`: grep exits 1 when the input contains zero domain-like
    # tokens. Without it, set -e + pipefail would abort the ENTIRE pipeline
    # run at Stage 5 with no error message (verified in testing).
    grep -oE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' "$input_file" \
        | sort -u > "$output_file" || true
}

# ── Cloud Domain Filter ────────────────────────────────────────────────────
# Matches any host pointing at a recognized cloud / PaaS provider.
# The regex is a union of provider-specific suffixes plus root-domain
# tokens; we don't try to enumerate every bucket naming convention.
#
# Coverage rationale:
#   AWS:        amazonaws, cloudfront, elasticbeanstalk, apps that
#               front EC2 with the AWS global accelerator
#   Azure:      azurewebsites, azure, blob.core.windows, cloudapp,
#               azure-api (API Management)
#   GCP:        googleapis, appspot, cloudfunctions, storage.googleapis,
#               web.app (Firebase App Hosting)
#   Cloudflare: cloudflarestorage (R2), workers.dev (Workers)
#   DigitalOcean: digitaloceanspaces (Spaces), digitalocean.app /
#               ondigitalocean.app (App Platform)
#   Heroku:     herokuapp.com / heroku.com
#   Vercel:     vercel.app
#   Netlify:    netlify.app
#   Fly.io:     fly.dev
#   Railway:    railway.app
#   Render:     onrender.com
#   Backblaze:  backblazeb2.com
#   Linode:     linodeobjects.com
#   Oracle:     oraclecloud.com / oraclecloudusercontent.com
#   Supabase:   supabase.co / supabase.in
#
# Notes:
#   - `s3[^0-9]` keeps AWS S3 (matches "s3-", "s3.") but excludes
#     unrelated tokens that happen to start with "s3" (e.g. "s395").
#   - All alternatives are case-insensitive (`-i`).
#   - Patterns are written as `(...|...)` groups so adding a new
#     provider is a single-line edit.
filter_cloud_domains() {
    local input_file="$1"
    local output_file="$2"
    grep -iE '(amazonaws|cloudfront|elasticbeanstalk|azurewebsites|azure-api|blob\.core\.windows|cloudapp|googleapis|appspot|cloudfunctions|storage\.googleapis|web\.app|cloudflarestorage|workers\.dev|digitaloceanspaces|digitalocean\.app|ondigitalocean\.app|herokuapp|vercel\.app|netlify\.app|fly\.dev|railway\.app|onrender\.com|backblazeb2|linodeobjects|oraclecloud|supabase\.co|supabase\.in)' \
        "$input_file" | sort -u > "$output_file" 2>/dev/null || true
}

# ── CDN ASN Detection ──────────────────────────────────────────────────────
CDN_ASNS=(
    "AS13335"   # Cloudflare
    "AS54113"   # Fastly
    "AS16509"   # Amazon/AWS
    "AS14618"   # Amazon/AWS
    "AS8075"    # Microsoft/Azure CDN
    "AS15169"   # Google
    "AS20940"   # Akamai
    "AS16625"   # Akamai
    "AS12222"   # Akamai
    "AS53913"   # Akamai
    "AS8403"    # SPB Telecom (some CDN)
    "AS54994"   # Zeit/Vercel
    "AS7604"    # Alibaba CDN
    "AS46606"   # Tumblr
    "AS19551"   # Incapsula/Imperva
    "AS19551"   # Incapsula
    "AS53667"   # FranTech (VPN/Proxy)
    "AS20446"   # Highwinds/StackPath
    "AS30081"   # CacheNetworks
    "AS11427"   # Charter/Time Warner Cable
    "AS8001"    # Netrail/Akamai
)

is_cdn_asn() {
    local asn="$1"
    for cdn_asn in "${CDN_ASNS[@]}"; do
        [[ "$asn" == "$cdn_asn" ]] && return 0
    done
    return 1
}
