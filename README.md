# BB Methodology — Automated Recon Pipeline

A Dockerized, fully automated reconnaissance pipeline for bug bounty hunting. Feed it a company name or a list of root domains and it maps the entire attack surface: domains, subdomains, live web servers, cloud assets, network ranges, and IPs.

Based on the [Ars0n Framework v2 methodology](methodology.md).

---

## Quick Start

```bash
# Build the image
docker build -t bb-methodology .

# Full recon from a company name
docker run --rm -it -v $(pwd)/results:/output bb-methodology \
  --company "Example Corp" --auto

# From a list of root domains (skip Phase 1)
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/my-domains.txt:/input/domains.txt:ro \
  bb-methodology \
  --domains-file /input/domains.txt --auto

# From a comma-separated list of domains
docker run --rm -it -v $(pwd)/results:/output bb-methodology \
  --domains "example.com,test.com" --auto
```

---

## The Methodology

The pipeline has three phases that run sequentially. Each phase builds on the previous one's output.

### Phase 1: Company Name → Root Domains

Starts with a company name and discovers every root domain they own.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | ASN & network range discovery | Amass Intel, Metabigor |
| 2 | IP scanning: host discovery → port scan → HTTP metadata → DNS metadata | Nmap, httpx, dnsx |
| 3 | Certificate transparency lookups | crt.sh |
| 4 | GitHub source code search | GitHub API |
| 5 | Consolidation into deduplicated root domain list | — |

**Output**: `phase1/all_root_domains.txt` — one domain per line.

### Phase 2: Root Domains → All Subdomains

For each root domain, discovers every subdomain through three complementary approaches.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | Web scraping — query OSINT sources | Subfinder, Assetfinder, GAU, crt.sh, Sublist3r |
| 2 | Consolidate + HTTPx probe (Round 1) | httpx |
| 3 | Custom wordlist generation + DNS brute force | CeWL, ShuffleDNS |
| 4 | Consolidate + HTTPx probe (Round 2) | httpx |
| 5 | Web crawling + JavaScript analysis | GoSpider, Subdomainizer |
| 6 | Final consolidation + HTTPx probe (Round 3) | httpx |

Each domain gets its own output subdirectory: `phase2/example.com/`.

### Phase 3: Cloud Asset Discovery

Discovers AWS, Azure, and GCP assets associated with the target.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | DNS enumeration for cloud CNAME/A records | Amass Enum |
| 2 | Advanced DNS queries for cloud infrastructure | DNSx |
| 3 | Brute force cloud storage buckets and services | Cloud_Enum |
| 4 | Crawl web apps for cloud URL references | Katana |
| 5 | Consolidate all cloud assets | — |

---

## Manual Steps

Some steps from the original methodology require human interaction and cannot be automated. The pipeline logs a `[SKIP]` message for each one. You should run these manually after the automated pipeline finishes if you want maximum coverage:

### Google Dorking
Search Google with advanced operators to find domains and pages not indexed by automated tools.
```
site:*.example.com
"Example Corp" site:com
inurl:examplecorp
```

### Reverse WHOIS Lookups
Find other domains registered by the same organization or email.
1. Get WHOIS info: `whois example.com | grep -E 'Registrant|Admin'`
2. Search the organization name or email on:
   - https://viewdns.info/reversewhois/
   - https://whoxy.com/

### Root Domain Verification
After Phase 1, the automated script does its best to filter valid domains, but you should manually review the list and remove false positives — domains that don't actually belong to your target.

---

## Usage

### CLI Flags

```
Usage: recon.sh [options]

Options:
  --company NAME          Target company name (required for Phase 1)
  --domains d1,d2,...     Comma-separated root domains (skips Phase 1)
  --domains-file FILE      Line-separated root domains file (skips Phase 1)
  --subfinder-config FILE  Path to subfinder provider-config.yaml (API keys)
  --auto                   Skip all checkpoint prompts
  --skip-phase {1,2,3}    Skip specific phase(s)
  --skip-cloud            Shorthand for --skip-phase 3
  --threads N             Thread count (default: 50)
  --rate-limit N          Requests/second (default: 100)
  --timeout N             Checkpoint auto-continue timeout in seconds (default: 30)
  --output DIR            Output directory (default: /output)
  --github-token TOKEN    GitHub API token for GitHub recon stage
```

### Examples

**Full recon, fully automated:**
```bash
docker run --rm -it -v $(pwd)/results:/output bb-methodology \
  --company "Example Corp" --auto
```

**Full recon with checkpoints (interactive):**
```bash
docker run --rm -it -v $(pwd)/results:/output bb-methodology \
  --company "Example Corp"
```

**From a domains file, skip cloud phase:**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  bb-methodology \
  --domains-file /input/domains.txt --skip-cloud --auto
```

The domains file is a plain text file with one root domain per line:
```
example.com
example.org
example-cdn.net
```

**From comma-separated domains:**
```bash
docker run --rm -it -v $(pwd)/results:/output bb-methodology \
  --domains "example.com,example.org" --auto
```

**Only run Phase 2 and 3 (skip Phase 1), with GitHub token:**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  bb-methodology \
  --domains-file /input/domains.txt \
  --github-token "ghp_xxxxxxxxxxxx" \
  --auto
```

**Custom thread count and rate limit:**
```bash
docker run --rm -it -v $(pwd)/results:/output bb-methodology \
  --company "Example Corp" --threads 100 --rate-limit 200 --auto
```

**With subfinder provider config (API keys for Shodan, Censys, etc.):**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/provider-config.yaml:/input/provider-config.yaml:ro \
  bb-methodology \
  --company "Example Corp" \
  --subfinder-config /input/provider-config.yaml \
  --auto
```

### Checkpoints

When running without `--auto`, the pipeline pauses after each phase and shows:

```
════════════════════════════════════════════════════════════
[CHECKPOINT] Phase 1 complete. Root domains: 42
════════════════════════════════════════════════════════════

  [C]ontinue  [S]kip next phase  [Q]uit  [R]eview results
  > _
```

- **C** — Continue to the next phase
- **S** — Skip the next phase
- **Q** — Quit the pipeline
- **R** — Review the output files before continuing

If you don't respond within the timeout (default 30 seconds), it auto-continues.

---

## Output Structure

Mount a local directory as `/output`. After the pipeline completes, it looks like this:

```
results/
├── RECON_SUMMARY.txt              # Final summary with all counts
│
├── phase1/
│   ├── all_root_domains.txt       # Master list of root domains
│   ├── asn_list.txt               # Discovered ASNs
│   ├── network_ranges.txt         # CIDR blocks
│   ├── live_ips.txt               # Live IP addresses
│   ├── amass_intel_results.txt    # Raw Amass output
│   ├── metabigor_results.txt      # Raw Metabigor output
│   └── ...
│
├── phase2/
│   ├── example.com/
│   │   ├── all_subdomains_final.txt    # All subdomains discovered
│   │   ├── live_subdomains_final.txt   # Live web server URLs
│   │   ├── httpx_results_final.json    # Full HTTPx metadata (JSON)
│   │   └── ...
│   ├── example.org/
│   │   └── ...
│   └── ...
│
├── phase3/
│   ├── final_cloud_assets.txt     # All cloud assets consolidated
│   ├── amass_cloud_domains.txt
│   ├── dnsx_cloud_domains.txt
│   ├── cloud_enum_assets.txt
│   ├── katana_cloud_assets.txt
│   └── ...
│
└── final/
    ├── final_all_domains.txt          # Every subdomain across all root domains
    ├── final_live_web_servers.txt     # Every live URL across all root domains
    ├── final_cloud_assets.txt         # Every cloud asset
    ├── final_asn_list.txt             # All ASNs
    ├── final_network_ranges.txt       # All network ranges
    └── final_ip_addresses.txt         # All IPs
```

### The `final/` Directory

This is the one you care about. It contains deduplicated, consolidated lists ready for the next stage of your bug bounty workflow — vulnerability scanning and exploitation.

### RECON_SUMMARY.txt

A human-readable summary printed at the end of every run:

```
========================================
RECONNAISSANCE PHASE COMPLETE
========================================

Target Company: Example Corp

ASSETS DISCOVERED:
- Root Domains:      5
- All Subdomains:    1,247
- Live Web Servers:  389
- Cloud Assets:      23
- ASNs:              3
- Network Ranges:    8
- IP Addresses:      156

FILES CREATED IN final/:
- final_all_domains.txt
- final_live_web_servers.txt
- final_cloud_assets.txt
- final_asn_list.txt
- final_network_ranges.txt
- final_ip_addresses.txt
========================================
```

---

## Building the Image

```bash
docker build -t bb-methodology .
```

The build installs all tools at image build time (no runtime downloads). This takes a while on first build because it compiles Go tools from source. Subsequent builds are fast if you don't change the tool installation steps.

### Installed Tools

**Go tools:** amass, subfinder, httpx, katana, dnsx, shuffledns, nuclei, ffuf, gau, assetfinder, gospider, waybackurls, Arjun, unfurl

**Python tools:** sublist3r, parameth

**Git-cloned tools:** CeWL, SubDomainizer, Cloud_Enum, Metabigor

**System tools:** nmap, jq, curl, wget, git, ruby, whois, dnsutils

---

## How It Works Under the Hood

```
┌──────────────────────────────────────────────────────┐
│  recon.sh (orchestrator)                             │
│                                                      │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐           │
│  │ Phase 1  │──▶│ Phase 2  │──▶│ Phase 3  │          │
│  │ lib/     │   │ lib/     │   │ lib/     │           │
│  │ phase1.sh│   │ phase2.sh│   │ phase3.sh│           │
│  └─────────┘   └─────────┘   └─────────┘           │
│        │              │             │                 │
│        ▼              ▼             ▼                 │
│  ┌─────────────────────────────────────────┐         │
│  │         lib/consolidate.sh              │          │
│  │    Merge → final/ → RECON_SUMMARY.txt   │         │
│  └─────────────────────────────────────────┘         │
│                                                      │
│  lib/utils.sh — logging, CLI parsing, checkpoints,   │
│                 httpx helper, domain extraction       │
└──────────────────────────────────────────────────────┘
```

Each phase script sources `lib/utils.sh` for shared functions. The orchestrator (`recon.sh`) runs phases sequentially with checkpoint prompts between them. All output goes to the mounted `/output` volume.

---

## Tips

- **Rate limiting matters.** If you're getting timeouts or empty results, lower `--rate-limit` (e.g., 50 or 25). Some targets have aggressive rate limiting.
- **Threads vs rate limit.** `--threads` controls parallel DNS lookups and brute forcing. `--rate-limit` controls HTTP request speed. They're independent.
- **Cloud phase is optional.** If you're only interested in web vulnerabilities, `--skip-cloud` saves significant time.
- **GitHub token helps.** Without `--github-token`, the GitHub recon stage is skipped. With a token, it searches code repositories for leaked domains and subdomains.
- **Review before moving on.** Even in `--auto` mode, always check `RECON_SUMMARY.txt` and `final/final_all_domains.txt` for false positives before starting vulnerability scanning.
- **Subfinder provider config.** Subfinder works without API keys, but adding keys for Shodan, Censys, SecurityTrails, etc. via `--subfinder-config` significantly increases subdomain coverage. Place your `provider-config.yaml` in your working directory and mount it read-only.
