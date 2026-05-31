# BB Methodology — Automated Recon Pipeline

A Dockerized, fully automated reconnaissance pipeline for bug bounty hunting. Feed it root domains and it maps the entire attack surface: subdomains, live web servers, cloud assets, ASN/network infrastructure, IPs, and open ports.

Based on the [Ars0n Framework v2 methodology](methodology.md).

---

## Quick Start

```bash
# Build the image
docker build -t bb-methodology .

# From a comma-separated list of root domains
docker run --rm -it -v $(pwd)/results:/output bb-methodology \
  --domains "example.com,test.com" --auto

# From a file of root domains (one per line)
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/my-domains.txt:/input/domains.txt:ro \
  bb-methodology \
  --domains-file /input/domains.txt --auto
```

---

## The Methodology

The pipeline has three phases that run sequentially.

### Phase 1: Root Domains → All Subdomains

For each root domain, discovers every subdomain through multiple complementary techniques.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | Certificate transparency, OSINT scraping | Cero, Metabigor, Subfinder, Assetfinder, GAU, Sublist3r, github-subdomains |
| 2 | Consolidate + HTTPx probe (Round 1) | httpx |
| 3 | Custom wordlist generation + DNS brute force | CeWL, ShuffleDNS |
| 4 | Consolidate + HTTPx probe (Round 2) | httpx |
| 5 | Web crawling + JavaScript analysis | GoSpider, Subdomainizer |
| 6 | Final consolidation + HTTPx probe (Round 3) | httpx |

Each domain gets its own output subdirectory: `phase1/example.com/`.

### Phase 2: Cloud Asset Discovery

Discovers AWS, Azure, and GCP assets associated with the root domains.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | DNS enumeration for cloud CNAME/A records | Amass Enum |
| 2 | Advanced DNS queries for cloud infrastructure | DNSx |
| 3 | Brute force cloud storage buckets and services | Cloud_Enum |
| 4 | Crawl web apps for cloud URL references | Katana |
| 5 | Consolidate all cloud assets | — |

### Phase 3: IP Extraction → ASN Mapping → Port Scanning

Resolves all discovered domains to IPs, maps them to ASNs, and port scans non-CDN IPs.

| Stage | What Happens | Tool(s) |
|-------|-------------|---------|
| 1 | DNS resolution of all subdomains | dig, dnsx |
| 2 | IP → ASN lookup sorted by occurrence | whois.cymru.com |
| 3 | CDN IP filtering | built-in CDN ASN list |
| 4 | Port scan on non-CDN IPs | nmap |

---

## Logging

All stage output is logged to `recon.log` in the output directory with timestamps. Every tool invocation, result count, warning, and error is captured. This is useful for debugging or improving the pipeline later.

```
2026-05-31 14:23:01 [*] Phase 1: Root Domains → Subdomains (3 domains)
2026-05-31 14:23:01 [*] Processing domain: example.com
2026-05-31 14:23:01 [*] Running Cero (certificate transparency)...
2026-05-31 14:23:45 [+] Subdomains from scraping: 142
2026-05-31 14:24:02 [*] Probing 142 targets with httpx...
2026-05-31 14:24:18 [+] Live web servers found: 67
...
```

---

## Manual Steps

Some reconnaissance steps are best done manually before running the pipeline:

### Pre-Pipeline: Google Dorking & Reverse WHOIS

Before running the pipeline, do manual reconnaissance to find additional root domains:

**Google Dorking:**
```
site:*.example.com
"Example Corp" site:com
inurl:examplecorp
```

**Reverse WHOIS:**
1. Get WHOIS info: `whois example.com | grep -E 'Registrant|Admin'`
2. Search the organization name or email on:
   - https://viewdns.info/reversewhois/
   - https://whoxy.com/
3. Add discovered domains to your input file

### Post-Pipeline: Review

Always review after the pipeline completes:
- `final/final_all_domains.txt` for false positives
- `final/final_asn_summary.txt` for interesting low-count ASNs
- `final/final_httpx_metadata.json` for technology detection results

---

## Usage

### CLI Flags

```
Usage: recon.sh [options]

Required (one of):
  --domains d1,d2,...     Comma-separated root domains
  --domains-file FILE     Line-separated root domains file

Options:
  --subfinder-config FILE Path to subfinder provider-config.yaml (API keys)
  --auto                  Skip all checkpoint prompts
  --skip-phase {1,2,3}    Skip specific phase(s)
  --skip-cloud            Shorthand for --skip-phase 2
  --no-port-scan          Skip port scanning phase
  --threads N             Thread count (default: 50)
  --rate-limit N          Requests/second (default: 100)
  --timeout N             Checkpoint auto-continue timeout in seconds (default: 30)
  --output DIR            Output directory (default: /output)
  --github-tokens-file FILE  File with GitHub tokens (one per line) for github-subdomains
  --cloud-enum-keywords KW   Keywords for cloud_enum brute force (comma-sep, auto-derived from domains)
```

### Examples

**Basic run with comma-separated domains:**
```bash
docker run --rm -it -v $(pwd)/results:/output bb-methodology \
  --domains "example.com,example.org" --auto
```

**From a domains file with all features:**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  bb-methodology \
  --domains-file /input/domains.txt --auto
```

The domains file is a plain text file with one root domain per line:
```
example.com
example.org
example-cdn.net
```

**With GitHub tokens for github-subdomains:**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  -v $(pwd)/github-tokens.txt:/input/github-tokens.txt:ro \
  bb-methodology \
  --domains-file /input/domains.txt \
  --github-tokens-file /input/github-tokens.txt \
  --auto
```

GitHub tokens file format (one token per line):
```
ghp_xxxxxxxxxxxxxxxxxxxx
ghp_yyyyyyyyyyyyyyyyyyyy
```

**With subfinder provider config (API keys for Shodan, Censys, etc.):**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  -v $(pwd)/provider-config.yaml:/input/provider-config.yaml:ro \
  bb-methodology \
  --domains-file /input/domains.txt \
  --subfinder-config /input/provider-config.yaml \
  --auto
```

**Skip cloud discovery and port scanning:**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  bb-methodology \
  --domains-file /input/domains.txt \
  --skip-cloud --no-port-scan --auto
```

**Custom thread count and rate limit:**
```bash
docker run --rm -it -v $(pwd)/results:/output bb-methodology \
  --domains "example.com" --threads 100 --rate-limit 200 --auto
```

**With cloud enum keywords (for bucket brute forcing):**
```bash
docker run --rm -it \
  -v $(pwd)/results:/output \
  -v $(pwd)/targets.txt:/input/domains.txt:ro \
  bb-methodology \
  --domains-file /input/domains.txt \
  --cloud-enum-keywords "example,examplecorp,example-corp" \
  --auto
```

### Checkpoints

When running without `--auto`, the pipeline pauses after each phase and shows:

```
════════════════════════════════════════════════════════════
[CHECKPOINT] Phase 1 complete. Subdomains discovered for 3 domain(s).
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
├── recon.log                      # Timestamped log of all stages
├── root_domains.txt               # Resolved input root domains
│
├── phase1/
│   ├── example.com/
│   │   ├── all_subdomains_final.txt    # All subdomains discovered
│   │   ├── live_subdomains_final.txt   # Live web server URLs
│   │   ├── httpx_results_final.json    # Full HTTPx metadata (JSON)
│   │   ├── cero_results.txt            # Cero (cert transparency) results
│   │   ├── subfinder_results.txt       # Subfinder results
│   │   ├── github_subdomains_results.txt # GitHub subdomains
│   │   └── ...
│   ├── example.org/
│   │   └── ...
│   └── ...
│
├── phase2/
│   ├── final_cloud_assets.txt     # All cloud assets consolidated
│   ├── amass_cloud_domains.txt
│   ├── dnsx_cloud_domains.txt
│   ├── cloud_enum_assets.txt
│   ├── katana_cloud_assets.txt
│   └── ...
│
├── phase3/
│   ├── all_ips.txt                # All resolved IPs
│   ├── asn_list.txt               # All ASNs
│   ├── asn_summary.txt            # ASNs sorted by IP count (descending)
│   ├── network_ranges.txt         # CIDR blocks from ASNs
│   ├── cdn_ips.txt                # CDN-associated IPs
│   ├── non_cdn_ips.txt            # Non-CDN IPs
│   ├── ip_port_pairs.txt          # Open port scan results
│   ├── domain_ip_map.txt          # Domain → IP mapping
│   └── ip_asn_map.txt             # IP → ASN mapping
│
└── final/
    ├── final_all_domains.txt          # Every subdomain across all root domains
    ├── final_live_web_servers.txt     # Every live URL across all root domains
    ├── final_httpx_metadata.json      # Full httpx JSON output (tech, title, status)
    ├── final_cloud_assets.txt         # Every cloud asset
    ├── final_asn_list.txt             # All ASNs
    ├── final_asn_summary.txt          # ASNs sorted by occurrence count
    ├── final_network_ranges.txt       # All network ranges
    ├── final_ip_addresses.txt         # All IPs
    ├── final_ip_port_pairs.txt        # IP:port from non-CDN scan
    ├── final_cdn_ips.txt              # CDN IPs
    ├── final_non_cdn_ips.txt          # Non-CDN IPs
    └── final_domain_ip_map.txt        # Domain→IP mapping
```

### The `final/` Directory

This is the one you care about. It contains deduplicated, consolidated lists ready for the next stage of your bug bounty workflow.

Key files:
- **`final_asn_summary.txt`** — ASNs sorted by how many IPs map to them. ASNs with only 1-2 IPs are more interesting targets (less infrastructure, more likely misconfigured).
- **`final_httpx_metadata.json`** — Full HTTPx output with status codes, titles, tech detection, TLS info for every live web server.
- **`final_ip_port_pairs.txt`** — Open ports on non-CDN IPs, ready for vulnerability scanning.

### RECON_SUMMARY.txt

A human-readable summary printed at the end of every run:

```
========================================
RECONNAISSANCE PHASE COMPLETE
========================================

Root Domains Provided: 3

ASSETS DISCOVERED:
- All Subdomains:     1,247
- Live Web Servers:   389
- Cloud Assets:       23
- ASNs:               15
- Network Ranges:     28
- IP Addresses:       456
- IP:Port Pairs:      1,102

FILES CREATED IN final/:
...

LOG FILE:
- recon.log                      (timestamped log of all stages)

NEXT STEPS:
Proceed to vulnerability scanning / enumeration on live web servers.
========================================
```

---

## Building the Image

```bash
docker build -t bb-methodology .
```

### Installed Tools

**Go tools:** amass, subfinder, httpx, katana, dnsx, shuffledns, gau, assetfinder, gospider, waybackurls, unfurl, cero, github-subdomains

**Python tools:** parameth

**Git-cloned tools:** CeWL (Ruby), Sublist3r (Python), SubDomainizer (Python), Cloud_Enum (Python), Metabigor (Go)

**System tools:** nmap, jq, curl, wget, git, ruby, whois, dnsutils, netcat

---

## How It Works Under the Hood

```
┌──────────────────────────────────────────────────────────┐
│  recon.sh (orchestrator)                                 │
│                                                          │
│  Input: --domains or --domains-file → root_domains.txt   │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Phase 1   │─▶│ Phase 2   │─▶│ Phase 3   │             │
│  │ Subdomain │  │ Cloud     │  │ IP/ASN    │              │
│  │ Discovery │  │ Assets    │  │ Port Scan │              │
│  │ lib/      │  │ lib/      │  │ lib/      │               │
│  │ phase1.sh │  │ phase2.sh │  │ phase3.sh │              │
│  └──────────┘  └──────────┘  └──────────┘              │
│        │             │             │                      │
│        ▼             ▼             ▼                      │
│  ┌──────────────────────────────────────────┐            │
│  │         lib/consolidate.sh               │             │
│  │    Merge → final/ → RECON_SUMMARY.txt    │            │
│  └──────────────────────────────────────────┘            │
│                                                          │
│  lib/utils.sh — logging (stdout + recon.log), CLI,       │
│                 checkpoints, httpx, CDN ASN detection     │
└──────────────────────────────────────────────────────────┘
```

---

## Tips

- **Rate limiting matters.** If you're getting timeouts or empty results, lower `--rate-limit` (e.g., 50 or 25).
- **ASN occurrence matters.** In `final_asn_summary.txt`, ASNs with fewer IPs are more interesting — they may represent niche hosting or forgotten infrastructure.
- **GitHub tokens increase coverage.** Without `--github-tokens-file`, the github-subdomains stage is skipped.
- **Cloud enum keywords.** By default, the base name of each root domain is used as a keyword. Use `--cloud-enum-keywords` to add extra keywords.
- **Check recon.log.** The timestamped log file captures everything — useful for debugging or tuning the pipeline.
- **Do manual recon first.** Google dorking and reverse WHOIS can find additional root domains. Add them to your input file before running the pipeline.
