# Bug Bounty Launch Pad! - Manual Bug Bounty Methodology Guide

## Introduction

Welcome to the complete manual guide for the Ars0n Framework v2 methodology! This guide will walk you through every step of the bug bounty hunting process, from a company name to a list of testable attack vectors.

This guide is designed to be used on Kali Linux with all necessary tools pre-installed. Each section contains:
- **What**: An explanation of what we're doing
- **Why**: The reasoning behind this step
- **How**: Copy-pastable commands you can run

By following this guide, you'll understand not just how to use the tools, but why each step matters in the bigger picture of bug bounty hunting.

---

## Prerequisites

Before starting, ensure you have the following tools installed on your Kali Linux machine:

```bash
sudo apt update && sudo apt install -y \
    python3 \
    python3-pip \
    ruby \
    golang-go \
    git \
    wget \
    curl \
    jq \
    dnsutils \
    nmap
```

Install the required bug bounty tools:

```bash
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/jaeles-project/gospider@latest
pip3 install sublist3r
git clone https://github.com/digininja/CeWL.git ~/tools/cewl
git clone https://github.com/nsonaniya2010/SubDomainizer.git ~/tools/SubDomainizer && cd ~/tools/SubDomainizer && pip3 install -r requirements.txt
git clone https://github.com/initstring/cloud_enum.git ~/tools/cloud_enum && cd ~/tools/cloud_enum && pip3 install -r requirements.txt
git clone https://github.com/j3ssie/metabigor.git ~/tools/metabigor && cd ~/tools/metabigor && go build
go install github.com/s0md3v/Arjun@latest
pip3 install parameth
go install github.com/tomnomnom/waybackurls@latest
```

Make sure all Go binaries are in your PATH:

```bash
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
```

---

# PART 1: RECONNAISSANCE

Reconnaissance is the foundation of successful bug bounty hunting. The goal is to map out the entire attack surface of your target company - every domain, subdomain, IP address, and cloud asset they own. The more thorough your reconnaissance, the more potential vulnerabilities you'll discover.

---

## Phase 1: Company Name → Root Domains

**Objective**: Start with just a company name and discover all root domains owned by that company, including their network infrastructure.

**Why This Matters**: Many companies own multiple domains beyond their primary website. Finding these hidden domains often reveals forgotten or poorly maintained assets that are more likely to contain vulnerabilities.

---

### Stage 1: Company Name → ASNs & Network Ranges

**What**: Use the company name to identify Autonomous System Numbers (ASNs) and IP network ranges they own.

**Why**: Companies often own entire blocks of IP addresses. By identifying their ASNs, we can discover infrastructure that isn't linked to their main domains - like internal tools, dev environments, and forgotten servers.

**How**: We'll use two complementary tools:

#### Amass Intel

Amass Intel performs OSINT reconnaissance to discover network infrastructure:

```bash
COMPANY_NAME="Example Corp"

docker run --rm caffix/amass intel \
  -org "$COMPANY_NAME" \
  -whois \
  -active \
  -timeout 120 \
  -o amass_intel_results.txt
```

**Expected Output**: You'll see ASN numbers with their associated network ranges:
```
ASN: 12345 - Example Corp - US
    192.0.2.0/24
    198.51.100.0/24
```

Save the results for later use:

```bash
cat amass_intel_results.txt
```

#### Metabigor

Metabigor provides additional network intelligence:

```bash
echo "$COMPANY_NAME" | ~/tools/metabigor/metabigor net --org -v | tee metabigor_results.txt
```

**Expected Output**: Metabigor shows ASN, CIDR blocks, organization info, and country:
```
12345 - 192.0.2.0/24 - Example Corp - US
12345 - 198.51.100.0/24 - Example Corp - US
```

**What to do with the results**:
1. Extract all ASN numbers (lines starting with "AS" or just numbers)
2. Extract all CIDR blocks (IP ranges in format X.X.X.X/XX)
3. Save these to separate files for the next stage

```bash
grep -oE 'AS[0-9]+|^[0-9]+' amass_intel_results.txt metabigor_results.txt | sort -u > asn_list.txt

grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' amass_intel_results.txt metabigor_results.txt | sort -u > network_ranges.txt
```

---

### Stage 2: Network Ranges → IP Addresses & Metadata

**What**: Probe the network ranges we discovered to find live IP addresses, then gather metadata about each IP including DNS records, SSL certificates, and HTTP services.

**Why**: Not all IPs in a network range are active. We need to identify which ones are live and what services they're running. The metadata often reveals:
- Domain names through reverse DNS lookups
- Additional domains through SSL certificate Subject Alternative Names
- Technologies and frameworks that indicate the purpose of the server
- Forgotten or hidden services that aren't linked to main domains

**How**: We'll use a combination of tools for comprehensive discovery:

#### Step 2a: Discover Live IP Addresses

Use Nmap for fast host discovery:

```bash
mkdir -p network_scanning

echo "[*] Starting host discovery across $(wc -l < network_ranges.txt) network ranges..."

while read -r network_range; do
  echo "[*] Scanning network range: $network_range"
  
  nmap -sn -PS80,443,22,8080,8443 -PE -PA80 \
    --min-rate 1000 \
    --max-retries 1 \
    -oG - \
    $network_range | \
    grep 'Up' | \
    awk '{print $2}' >> network_scanning/live_ips_temp.txt
  
done < network_ranges.txt

cat network_scanning/live_ips_temp.txt | sort -u -V > live_ips.txt

LIVE_IP_COUNT=$(wc -l < live_ips.txt)
echo "[+] Live IP addresses discovered: $LIVE_IP_COUNT"
```

**Parameters explained**:
- `-sn`: Ping scan only (no port scanning yet)
- `-PS80,443,22,8080,8443`: TCP SYN ping on these ports
- `-PE`: ICMP echo request
- `-PA80`: TCP ACK ping
- `--min-rate 1000`: Send at least 1000 packets per second
- `--max-retries 1`: Only retry once
- `-oG`: Output in grepable format

#### Step 2b: Port Scan for Web Services

Now scan the live IPs for common web service ports:

```bash
mkdir -p network_scanning/port_scan

echo "[*] Port scanning $LIVE_IP_COUNT live IPs for web services..."

nmap -iL live_ips.txt \
  -p 80,443,8080,8443,8000,8888,3000,9000,7000,5000 \
  -sV \
  --open \
  --min-rate 500 \
  -oG network_scanning/port_scan/results.txt

cat network_scanning/port_scan/results.txt | \
  grep '/open/' | \
  awk '{print $2":"$5}' | \
  sed 's|/open/tcp||g' | \
  sort -u > network_scanning/ip_port_pairs.txt

WEB_SERVICE_COUNT=$(wc -l < network_scanning/ip_port_pairs.txt)
echo "[+] IP:Port pairs with web services: $WEB_SERVICE_COUNT"
```

**Parameters explained**:
- `-p`: Specific ports to scan
- `-sV`: Version detection
- `--open`: Only show open ports
- `-oG`: Grepable output

#### Step 2c: Gather HTTP/HTTPS Metadata

Use httpx to probe the web services and gather detailed information:

```bash
cat network_scanning/ip_port_pairs.txt | while IFS=':' read -r ip port; do
  if [ "$port" == "443" ] || [ "$port" == "8443" ]; then
    echo "https://$ip:$port"
  else
    echo "http://$ip:$port"
  fi
done > network_scanning/web_urls.txt

cat network_scanning/web_urls.txt | httpx \
  -silent \
  -json \
  -status-code \
  -title \
  -tech-detect \
  -server \
  -content-length \
  -tls-grab \
  -timeout 10 \
  -retries 2 \
  -rate-limit 50 \
  -mc all \
  -o ip_http_metadata.json

IP_WEB_COUNT=$(cat ip_http_metadata.json | wc -l)
echo "[+] IP addresses with HTTP/HTTPS services: $IP_WEB_COUNT"
```

**Key flag**: `-tls-grab` extracts SSL certificate information including Subject Alternative Names.

#### Step 2d: Gather DNS Metadata

Perform reverse DNS lookups and comprehensive DNS queries:

```bash
echo "[*] Performing reverse DNS lookups..."

while read -r ip; do
  echo "[*] DNS lookup for: $ip"
  
  host $ip 2>/dev/null >> ip_dns_records.txt
  
  echo "$ip" | dnsx \
    -silent \
    -a -aaaa -cname -ns -txt -mx -ptr -srv \
    -json \
    -retry 3 \
    2>/dev/null >> ip_dns_metadata.json
  
done < live_ips.txt

echo "[+] DNS metadata collection complete"
```

#### Step 2e: Extract Domain Names

Parse all gathered metadata to extract domain names:

```bash
cat ip_dns_records.txt | \
  grep -oE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' | \
  sort -u > domains_from_dns.txt

cat ip_http_metadata.json | \
  jq -r '.tls.subject_cn?, .tls.subject_an[]?' 2>/dev/null | \
  grep -v '^null$' | \
  sort -u > domains_from_ssl.txt

cat ip_dns_metadata.json | \
  jq -r '.cname[]?, .mx[]?, .ns[]?, .ptr[]?' 2>/dev/null | \
  grep -v '^null$' | \
  sort -u > domains_from_dns_records.txt

cat \
  domains_from_dns.txt \
  domains_from_ssl.txt \
  domains_from_dns_records.txt \
  | sort -u > domains_from_ips.txt

DOMAINS_FROM_IPS=$(wc -l < domains_from_ips.txt)
echo "[+] Domain names discovered from IP metadata: $DOMAINS_FROM_IPS"
```

**What to look for in the results**:
- **Reverse DNS entries**: Often reveal internal naming conventions
- **SSL certificate SANs**: Frequently list multiple related domains
- **CNAME records**: Point to other domains or services
- **MX records**: Email servers that might reveal mail domains
- **Technologies detected**: PHP versions, frameworks, CMS systems
- **Response patterns**: Error messages, default pages, dev environments

---

### Stage 3: Company Name → Root Domains (Free Methods)

**What**: Use free public data sources to discover domains associated with the company.

**Why**: Many domains are publicly registered and can be found through certificate transparency logs, search engines, and WHOIS databases. These free methods often discover domains that the company doesn't actively advertise.

#### Google Dorking

Use advanced Google search operators to find domains:

```bash
COMPANY_NAME="Example Corp"

firefox "https://www.google.com/search?q=site:*.$COMPANY_NAME.com" &
firefox "https://www.google.com/search?q=%22$COMPANY_NAME%22+site:com" &
firefox "https://www.google.com/search?q=inurl:$COMPANY_NAME" &
```

**Manual Step**: Browse the search results and manually collect any root domains you find. Save them to `google_dork_domains.txt`, one per line.

#### Certificate Transparency (crt.sh)

Certificate Transparency logs record all SSL certificates issued, making them a goldmine for subdomain discovery:

```bash
DOMAIN="example.com"

curl -s "https://crt.sh/?q=%.$DOMAIN&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | \
  sort -u | \
  grep "\.$(echo $DOMAIN | sed 's/\./\\./g')$" > crtsh_domains.txt
```

**What this does**:
1. Queries crt.sh for all certificates related to the domain
2. Extracts domain names from the certificates
3. Removes wildcard characters
4. Filters to only show the base domain

#### Reverse WHOIS

Find other domains registered by the same organization or email address:

```bash
DOMAIN="example.com"

whois $DOMAIN | grep -E 'Registrant|Admin|Tech' | grep -E 'Organization|Email' > whois_info.txt

cat whois_info.txt
```

**Manual Step**: Take the organization name or email addresses from the WHOIS output and search for them on reverse WHOIS services:
- https://viewdns.info/reversewhois/
- https://whoxy.com/

Save discovered domains to `reverse_whois_domains.txt`.

---

#### GitHub Recon

Search GitHub for domains and subdomains mentioned in code repositories:

```bash
COMPANY_NAME="Example Corp"
GITHUB_TOKEN="your_github_token_here"

SEARCH_QUERY="$(echo $COMPANY_NAME | tr ' ' '+')%20AND%20(site:com%20OR%20site:net%20OR%20site:org)"

curl -s -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/search/code?q=$SEARCH_QUERY&per_page=100" | \
  jq -r '.items[].repository.html_url' | \
  sort -u > github_repos.txt

echo "[+] GitHub repositories found: $(wc -l < github_repos.txt)"
```

**Manual Step**: Clone interesting repositories and search for domains:

```bash
mkdir -p github_repos

cat github_repos.txt | head -10 | while read -r repo_url; do
  repo_name=$(basename "$repo_url")
  git clone "$repo_url" "github_repos/$repo_name" 2>/dev/null
  
  grep -r -ohE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' "github_repos/$repo_name" 2>/dev/null | \
    grep -i "$COMPANY_NAME" | \
    sort -u >> github_domains.txt
done

cat github_domains.txt | sort -u -o github_domains.txt
echo "[+] Domains found from GitHub: $(wc -l < github_domains.txt)"
```

---

### Stage 5: Consolidate Root Domains

**What**: Combine all discovered root domains into a single deduplicated list.

**Why**: We've used multiple tools and techniques, each potentially finding different domains. We need one master list with no duplicates.

**How**: Merge all domain files and remove duplicates:

```bash
cat \
  domains_from_ips.txt \
  google_dork_domains.txt \
  crtsh_domains.txt \
  reverse_whois_domains.txt \
  securitytrails_domains.txt \
  censys_domains.txt \
  shodan_domains.txt \
  github_domains.txt \
  2>/dev/null | \
  sort -u | \
  grep -E '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$' > all_root_domains.txt

DOMAIN_COUNT=$(wc -l < all_root_domains.txt)
echo "[+] Total unique root domains found: $DOMAIN_COUNT"

cat all_root_domains.txt
```

**Verification Step**: Manually review the list to ensure all domains truly belong to your target company. Remove any false positives:

```bash
nano all_root_domains.txt
```

**Result**: You now have a complete list of root domains owned by the company. Each of these will be processed through Phase 2 to discover all their subdomains.

---

## Phase 2: Root Domain → All Subdomains

**Objective**: For each root domain discovered in Phase 1, find every possible subdomain through multiple complementary techniques.

**Why This Matters**: Subdomains often host different applications, APIs, development environments, and staging servers. Many companies have poor subdomain security, making them prime targets for vulnerabilities.

**The Strategy**: We'll use three complementary approaches:
1. **Scraping**: Query public databases and search engines
2. **Brute Forcing**: Try common subdomain names
3. **Crawling**: Discover subdomains mentioned in web content and JavaScript files

We'll run multiple rounds of discovery, each time validating which subdomains are live before proceeding.

---

### Stage 1: Web Scraping

**What**: Query multiple OSINT sources that maintain subdomain databases.

**Why**: Different tools query different sources. Using multiple tools increases our coverage. Some might find subdomains from DNS records, others from web archives, and others from certificate transparency logs.

**How**: We'll run five different subdomain enumeration tools in parallel.

Create a directory for this domain's results:

```bash
DOMAIN="example.com"

mkdir -p recon/$DOMAIN/subdomains
cd recon/$DOMAIN/subdomains
```

#### Sublist3r

Sublist3r searches multiple sources including Google, Bing, Yahoo, Baidu, and more:

```bash
python3 ~/tools/sublist3r/sublist3r.py \
  -d $DOMAIN \
  -v \
  -t 50 \
  -o sublist3r_results.txt
```

**Parameters explained**:
- `-d`: Target domain
- `-v`: Verbose output (shows what it's doing)
- `-t 50`: Use 50 threads for faster scanning
- `-o`: Output file

#### Assetfinder

Assetfinder queries multiple sources and is particularly good at finding related assets:

```bash
assetfinder --subs-only $DOMAIN | tee assetfinder_results.txt
```

#### GAU (Get All URLs)

GAU fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl:

```bash
echo $DOMAIN | gau --subs --threads 10 | \
  unfurl -u domains | \
  grep "$DOMAIN" | \
  sort -u > gau_results.txt
```

**Note**: `unfurl` is used to extract just the domain names from full URLs.

If you don't have unfurl installed:

```bash
echo $DOMAIN | gau --subs --threads 10 | \
  grep -oE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' | \
  grep "$DOMAIN" | \
  sort -u > gau_results.txt
```

#### Certificate Transparency Logs (crt.sh)

Search certificate transparency logs:

```bash
curl -s "https://crt.sh/?q=%.$DOMAIN&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//g' | \
  sort -u > crtsh_results.txt
```

#### Subfinder

Subfinder uses passive sources and has excellent API integrations:

```bash
subfinder -d $DOMAIN -silent -o subfinder_results.txt
```

**All tools complete**: Wait for all tools to finish (this may take several minutes).

---

### Stage 2: Consolidate & HTTPx Round 1

**What**: Combine all discovered subdomains and identify which ones are hosting live web servers.

**Why**: Not all discovered subdomains actually exist or host web applications. We need to validate them and focus only on live targets. HTTPx probes each subdomain to see if it responds to HTTP/HTTPS requests.

**How**: Consolidate the results and run httpx:

```bash
cat \
  sublist3r_results.txt \
  assetfinder_results.txt \
  gau_results.txt \
  crtsh_results.txt \
  subfinder_results.txt \
  | sort -u > all_subdomains_round1.txt

SUBDOMAIN_COUNT=$(wc -l < all_subdomains_round1.txt)
echo "[+] Total unique subdomains from scraping: $SUBDOMAIN_COUNT"
```

Now probe all subdomains with httpx:

```bash
cat all_subdomains_round1.txt | httpx \
  -ports 80,443,8080,8443,8000,8888,3000 \
  -silent \
  -json \
  -status-code \
  -title \
  -tech-detect \
  -server \
  -content-length \
  -timeout 10 \
  -retries 2 \
  -rate-limit 100 \
  -mc 100,101,200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,307,308,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,421,422,423,424,426,428,429,431,451,500,501,502,503,504,505,506,507,508,510,511 \
  -o httpx_results_round1.json
```

**Parameters explained**:
- `-ports`: Check these common web service ports
- `-json`: Output in JSON format for easier parsing
- `-status-code`: Include HTTP status code
- `-title`: Extract page title
- `-tech-detect`: Detect technologies used
- `-mc`: Match these status codes (essentially "all" status codes)
- `-rate-limit 100`: Send max 100 requests per second (adjust based on your connection)

Extract just the URLs of live web servers:

```bash
cat httpx_results_round1.json | jq -r '.url' | sort -u > live_subdomains_round1.txt

LIVE_COUNT=$(wc -l < live_subdomains_round1.txt)
echo "[+] Live web servers found (Round 1): $LIVE_COUNT"
```

---

### Stage 3: Brute Force with Custom Wordlist

**What**: Generate a custom wordlist by crawling the discovered websites, then use it to brute force additional subdomains.

**Why**: Generic wordlists contain common subdomain names, but each company has unique naming conventions. By analyzing their existing subdomains and website content, we can generate a custom wordlist that's much more likely to find additional hidden subdomains.

**How**: We'll use CeWL to crawl websites and extract words, then use ShuffleDNS to brute force.

#### Step 3a: Generate Custom Wordlist with CeWL

CeWL spiders websites and extracts words to create custom wordlists:

```bash
mkdir -p wordlists

touch wordlists/custom_wordlist.txt

while read -r url; do
  echo "[*] Crawling $url for words..."
  
  timeout 600 ruby ~/tools/cewl/cewl.rb \
    "$url" \
    -d 2 \
    -m 5 \
    -c \
    --with-numbers \
    2>/dev/null | \
    grep -v '^[0-9]' | \
    awk -F',' '{print $1}' | \
    tr '[:upper:]' '[:lower:]' | \
    grep -E '^[a-z0-9]{3,20}$' >> wordlists/custom_wordlist.txt
  
done < live_subdomains_round1.txt

sort -u wordlists/custom_wordlist.txt -o wordlists/custom_wordlist.txt

WORD_COUNT=$(wc -l < wordlists/custom_wordlist.txt)
echo "[+] Generated custom wordlist with $WORD_COUNT unique words"
```

**Parameters explained**:
- `-d 2`: Crawl to a depth of 2 pages
- `-m 5`: Minimum word length of 5 characters
- `-c`: Show word count
- `--with-numbers`: Include words with numbers

#### Step 3b: Prepare DNS Resolvers

ShuffleDNS needs a list of reliable DNS resolvers:

```bash
mkdir -p resolvers

cat > resolvers/resolvers.txt << 'EOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
EOF
```

#### Step 3c: Brute Force with ShuffleDNS

ShuffleDNS performs high-speed DNS brute forcing with wildcard filtering:

```bash
shuffledns \
  -d $DOMAIN \
  -w wordlists/custom_wordlist.txt \
  -r resolvers/resolvers.txt \
  -mode bruteforce \
  -o shuffledns_results.txt

BRUTEFORCE_COUNT=$(wc -l < shuffledns_results.txt)
echo "[+] Subdomains found via brute force: $BRUTEFORCE_COUNT"
```

**What this does**:
1. Takes each word from the custom wordlist
2. Creates a subdomain by prepending it to the domain (e.g., `word.example.com`)
3. Performs DNS lookups using the resolver list
4. Filters out wildcard DNS responses
5. Outputs only valid, resolvable subdomains

---

### Stage 4: Consolidate & HTTPx Round 2

**What**: Add newly discovered subdomains from brute forcing to our master list and probe them with HTTPx.

**Why**: We need to validate which of the brute-forced subdomains are actually hosting live web applications.

**How**: Combine with existing results and run httpx again:

```bash
cat \
  all_subdomains_round1.txt \
  shuffledns_results.txt \
  | sort -u > all_subdomains_round2.txt

NEW_SUBS=$(comm -13 all_subdomains_round1.txt all_subdomains_round2.txt | wc -l)
echo "[+] New subdomains discovered from brute forcing: $NEW_SUBS"
```

Probe all subdomains (including new ones) with httpx:

```bash
cat all_subdomains_round2.txt | httpx \
  -ports 80,443,8080,8443,8000,8888,3000 \
  -silent \
  -json \
  -status-code \
  -title \
  -tech-detect \
  -server \
  -content-length \
  -timeout 10 \
  -retries 2 \
  -rate-limit 100 \
  -mc 100,101,200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,307,308,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,421,422,423,424,426,428,429,431,451,500,501,502,503,504,505,506,507,508,510,511 \
  -o httpx_results_round2.json

cat httpx_results_round2.json | jq -r '.url' | sort -u > live_subdomains_round2.txt

LIVE_COUNT_R2=$(wc -l < live_subdomains_round2.txt)
echo "[+] Total live web servers (Round 2): $LIVE_COUNT_R2"
```

---

### Stage 5: Web Crawling & JavaScript Link Discovery

**What**: Crawl all live web applications and analyze JavaScript files to discover subdomains that are referenced in code but might not have DNS records yet.

**Why**: Developers often hardcode subdomain references in JavaScript files, HTML comments, and API calls. These might include development, staging, or internal subdomains that aren't publicly advertised.

**How**: Use GoSpider and Subdomainizer to crawl and analyze:

#### GoSpider

GoSpider crawls websites and extracts URLs, including those in JavaScript:

```bash
mkdir -p gospider

while read -r url; do
  echo "[*] Crawling $url with GoSpider..."
  
  gospider \
    -s "$url" \
    -c 10 \
    -d 3 \
    -t 3 \
    -k 1 \
    -K 2 \
    -m 30 \
    --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|svg)" \
    -a \
    -w \
    -r \
    --js \
    --sitemap \
    --robots \
    --json \
    -v 2>/dev/null | \
    tee -a gospider/raw_output.txt
    
done < live_subdomains_round2.txt

grep -oE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' gospider/raw_output.txt | \
  grep "$DOMAIN" | \
  sort -u > gospider_subdomains.txt

GOSPIDER_COUNT=$(wc -l < gospider_subdomains.txt)
echo "[+] Subdomains found by GoSpider: $GOSPIDER_COUNT"
```

**Parameters explained**:
- `-s`: Start URL
- `-c 10`: Use 10 concurrent threads
- `-d 3`: Crawl to depth of 3
- `-t 3`: Timeout after 3 seconds per request
- `--blacklist`: Skip image and style files
- `-a`: Also crawl assets (JS, CSS)
- `--js`: Parse JavaScript files
- `--sitemap`: Include sitemap.xml
- `--robots`: Include robots.txt

#### Subdomainizer

Subdomainizer analyzes JavaScript files specifically for subdomains:

```bash
mkdir -p subdomainizer

while read -r url; do
  echo "[*] Running Subdomainizer on $url..."
  
  python3 ~/tools/SubDomainizer/SubDomainizer.py \
    -u "$url" \
    -k \
    -o subdomainizer/temp_output.txt \
    2>/dev/null
    
  if [ -f subdomainizer/temp_output.txt ]; then
    cat subdomainizer/temp_output.txt >> subdomainizer/raw_output.txt
    rm subdomainizer/temp_output.txt
  fi
  
done < live_subdomains_round2.txt

grep -oE '([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}' subdomainizer/raw_output.txt | \
  grep "$DOMAIN" | \
  sort -u > subdomainizer_subdomains.txt

SUBDOMAINIZER_COUNT=$(wc -l < subdomainizer_subdomains.txt)
echo "[+] Subdomains found by Subdomainizer: $SUBDOMAINIZER_COUNT"
```

**Parameters explained**:
- `-u`: Target URL
- `-k`: Show secrets found (bonus!)
- `-o`: Output file

---

### Stage 6: Consolidate & HTTPx Round 3

**What**: Final consolidation of all discovered subdomains and validation of live web servers.

**Why**: This is our last round of subdomain discovery. We want to ensure we have every possible subdomain validated and ready for vulnerability testing.

**How**: Final consolidation and httpx scan:

```bash
cat \
  all_subdomains_round2.txt \
  gospider_subdomains.txt \
  subdomainizer_subdomains.txt \
  | sort -u > all_subdomains_final.txt

TOTAL_SUBS=$(wc -l < all_subdomains_final.txt)
echo "[+] Total unique subdomains discovered (all methods): $TOTAL_SUBS"

NEW_FROM_CRAWL=$(comm -13 all_subdomains_round2.txt all_subdomains_final.txt | wc -l)
echo "[+] New subdomains from crawling: $NEW_FROM_CRAWL"
```

Final httpx scan:

```bash
cat all_subdomains_final.txt | httpx \
  -ports 80,443,7547,8089,8085,8443,8080,4567,7170,8008,2083,8000,2082,8081,2087,2086,8888,8880,60000,40000,9080,5985,9100,2096,3000,1024,30005,81,21,5000,2095 \
  -silent \
  -json \
  -status-code \
  -title \
  -tech-detect \
  -server \
  -content-length \
  -timeout 10 \
  -retries 2 \
  -rate-limit 100 \
  -mc 100,101,200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,307,308,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,421,422,423,424,426,428,429,431,451,500,501,502,503,504,505,506,507,508,510,511 \
  -o httpx_results_final.json

cat httpx_results_final.json | jq -r '.url' | sort -u > live_subdomains_final.txt

FINAL_LIVE_COUNT=$(wc -l < live_subdomains_final.txt)
echo "[+] FINAL: Total live web servers discovered: $FINAL_LIVE_COUNT"
```

**Phase 2 Complete!** You now have a comprehensive list of all subdomains and live web servers for this root domain. Repeat this entire phase for each root domain discovered in Phase 1.

---

## Phase 3: Cloud Assets

**Objective**: Discover cloud-hosted assets (AWS, Azure, GCP) associated with the target company.

**Why This Matters**: Companies increasingly use cloud platforms for storage, hosting, and services. Cloud assets are often misconfigured and can expose sensitive data. S3 buckets, Azure storage accounts, and GCP buckets are common sources of vulnerabilities.

**The Strategy**: We'll use multiple specialized tools that check for cloud assets:
1. DNS enumeration (Amass, DNSx) to find cloud domains in DNS records
2. Brute forcing with Cloud_Enum
3. Crawling discovered websites with Katana to find cloud asset references

---

### Stage 1: Amass Enum for Cloud Domains

**What**: Use Amass Enum to perform comprehensive DNS enumeration and extract cloud-related domains.

**Why**: Amass Enum combines passive and active techniques to discover subdomains and DNS records. It's particularly good at finding CNAME records that point to cloud services.

**How**: Run Amass Enum on all discovered root domains:

```bash
cd ../..

mkdir -p cloud_assets

while read -r domain; do
  echo "[*] Running Amass Enum on $domain..."
  
  docker run --rm caffix/amass enum \
    -passive \
    -alts \
    -brute \
    -nocolor \
    -min-for-recursive 2 \
    -timeout 300 \
    -d "$domain" \
    -r 8.8.8.8 \
    -r 1.1.1.1 \
    -r 9.9.9.9 \
    -r 208.67.222.222 \
    -rqps 10 \
    2>/dev/null | tee -a cloud_assets/amass_enum_output.txt
    
done < all_root_domains.txt
```

**Parameters explained**:
- `-passive`: Use passive data sources only
- `-alts`: Find alterations of the domain
- `-brute`: Enable brute forcing
- `-min-for-recursive 2`: Minimum for recursive brute forcing
- `-timeout 300`: 5 minute timeout
- `-r`: DNS resolvers to use
- `-rqps 10`: DNS queries per second (rate limiting)

Now extract cloud domains from the results:

```bash
grep -iE '(amazonaws|cloudfront|s3|azurewebsites|azure|blob\.core|cloudapp|googleapis|appspot|cloudfunctions|storage\.googleapis)' cloud_assets/amass_enum_output.txt | \
  sort -u > cloud_assets/amass_cloud_domains.txt

AMASS_CLOUD_COUNT=$(wc -l < cloud_assets/amass_cloud_domains.txt)
echo "[+] Cloud domains found by Amass Enum: $AMASS_CLOUD_COUNT"
```

**Common cloud domain patterns**:
- AWS: `*.amazonaws.com`, `*.cloudfront.net`, `*.s3.amazonaws.com`
- Azure: `*.azurewebsites.net`, `*.blob.core.windows.net`, `*.cloudapp.azure.com`
- GCP: `*.googleapis.com`, `*.appspot.com`, `*.cloudfunctions.net`

---

### Stage 2: DNSx for Cloud Domains

**What**: Use DNSx to perform advanced DNS queries on all discovered subdomains and parse for cloud infrastructure.

**Why**: DNSx can extract detailed DNS records (A, AAAA, CNAME, MX, NS, TXT, PTR, SRV) which often reveal cloud service relationships. CNAME records are particularly useful as they often point directly to cloud providers.

**How**: Run DNSx on all discovered subdomains:

```bash
cat recon/*/subdomains/all_subdomains_final.txt 2>/dev/null | \
  dnsx \
    -a \
    -aaaa \
    -cname \
    -mx \
    -ns \
    -txt \
    -ptr \
    -srv \
    -re \
    -json \
    -retry 3 \
    2>/dev/null | tee cloud_assets/dnsx_output.json
```

Parse the DNSx output for cloud domains:

```bash
cat cloud_assets/dnsx_output.json | \
  jq -r '.cname[]?, .a[]?, .aaaa[]?, .mx[]?, .ns[]?, .txt[]?, .ptr[]?, .srv[]?' 2>/dev/null | \
  grep -iE '(amazonaws|cloudfront|s3|azurewebsites|azure|blob\.core|cloudapp|googleapis|appspot|cloudfunctions|storage\.googleapis)' | \
  sort -u > cloud_assets/dnsx_cloud_domains.txt

DNSX_CLOUD_COUNT=$(wc -l < cloud_assets/dnsx_cloud_domains.txt)
echo "[+] Cloud domains found by DNSx: $DNSX_CLOUD_COUNT"
```

---

### Stage 3: Cloud_Enum Brute Force

**What**: Use Cloud_Enum to brute force cloud storage buckets and services across AWS, Azure, and GCP.

**Why**: Companies often create cloud buckets with predictable names based on their company name, product names, or common patterns. Cloud_Enum uses wordlists to systematically check for these resources.

**How**: Run Cloud_Enum with the company name:

```bash
COMPANY_NAME="Example Corp"

cd ~/tools/cloud_enum

python3 cloud_enum.py \
  -k "$COMPANY_NAME" \
  -l ../../../cloud_assets/cloud_enum_results.json \
  -f json \
  -t 10

cd -
```

**Parameters explained**:
- `-k`: Keyword(s) to use for enumeration
- `-l`: Log file location
- `-f json`: Output format
- `-t 10`: Number of threads

Parse Cloud_Enum results:

```bash
cat cloud_assets/cloud_enum_results.json | \
  jq -r 'select(.msg != null) | .target' 2>/dev/null | \
  sort -u > cloud_assets/cloud_enum_assets.txt

CLOUDENUM_COUNT=$(wc -l < cloud_assets/cloud_enum_assets.txt)
echo "[+] Cloud assets found by Cloud_Enum: $CLOUDENUM_COUNT"
```

**What Cloud_Enum finds**:
- AWS S3 buckets
- AWS App Runner services
- Azure storage accounts
- Azure app services
- GCP storage buckets
- GCP app engine applications

---

### Stage 4: Katana Crawling for Cloud Assets

**What**: Crawl all discovered live web servers with Katana to find cloud asset URLs referenced in the code.

**Why**: Web applications often reference cloud storage, CDNs, and APIs directly in their HTML, JavaScript, and CSS. Katana can discover these references by deeply crawling the applications.

**How**: Run Katana against all live web servers:

```bash
mkdir -p cloud_assets/katana

cat recon/*/subdomains/live_subdomains_final.txt 2>/dev/null | while read -r url; do
  echo "[*] Crawling $url with Katana..."
  
  katana \
    -u "$url" \
    -d 3 \
    -jc \
    -j \
    -v \
    -timeout 120 \
    -c 20 \
    -p 20 \
    -retry 3 \
    -rd 1 \
    -rl 10 \
    2>/dev/null | tee -a cloud_assets/katana/raw_output.txt
    
done
```

**Parameters explained**:
- `-u`: Target URL
- `-d 3`: Crawl depth of 3
- `-jc`: JavaScript crawling
- `-j`: JSON output
- `-c 20`: Concurrency (20 parallel requests)
- `-p 20`: Parallelism
- `-rl 10`: Rate limit (10 requests/second)

Extract cloud domains from Katana results:

```bash
cat cloud_assets/katana/raw_output.txt | \
  grep -oE 'https?://[^"'\''[:space:]]+' | \
  grep -iE '(amazonaws|cloudfront|s3|azurewebsites|azure|blob\.core|cloudapp|googleapis|appspot|cloudfunctions|storage\.googleapis)' | \
  sort -u > cloud_assets/katana_cloud_assets.txt

KATANA_CLOUD_COUNT=$(wc -l < cloud_assets/katana_cloud_assets.txt)
echo "[+] Cloud assets found by Katana: $KATANA_CLOUD_COUNT"
```

---

### Stage 5: Consolidate All Assets

**What**: Create master consolidated lists of all discovered assets: ASNs, Network Ranges, IP Addresses, Domains, Cloud Assets, and Live Web Servers.

**Why**: We need organized, deduplicated lists of every asset we've discovered. These will be the foundation for all future vulnerability testing.

**How**: Create final consolidated files:

#### ASNs

```bash
cat asn_list.txt 2>/dev/null | sort -u > final_asn_list.txt

ASN_TOTAL=$(wc -l < final_asn_list.txt)
echo "[+] Total unique ASNs: $ASN_TOTAL"
```

#### Network Ranges

```bash
cat network_ranges.txt 2>/dev/null | sort -u > final_network_ranges.txt

NETWORK_TOTAL=$(wc -l < final_network_ranges.txt)
echo "[+] Total unique network ranges: $NETWORK_TOTAL"
```

#### IP Addresses

```bash
cat live_ips.txt 2>/dev/null | sort -u -V > final_ip_addresses.txt

IP_TOTAL=$(wc -l < final_ip_addresses.txt)
echo "[+] Total unique IP addresses: $IP_TOTAL"
```

#### Domains (All Subdomains)

```bash
cat recon/*/subdomains/all_subdomains_final.txt 2>/dev/null | sort -u > final_all_domains.txt

DOMAIN_TOTAL=$(wc -l < final_all_domains.txt)
echo "[+] Total unique domains (all subdomains): $DOMAIN_TOTAL"
```

#### Cloud Assets

```bash
cat \
  cloud_assets/amass_cloud_domains.txt \
  cloud_assets/dnsx_cloud_domains.txt \
  cloud_assets/cloud_enum_assets.txt \
  cloud_assets/katana_cloud_assets.txt \
  2>/dev/null | sort -u > final_cloud_assets.txt

CLOUD_TOTAL=$(wc -l < final_cloud_assets.txt)
echo "[+] Total unique cloud assets: $CLOUD_TOTAL"
```

#### Live Web Servers

```bash
cat recon/*/subdomains/live_subdomains_final.txt 2>/dev/null | sort -u > final_live_web_servers.txt

LIVE_TOTAL=$(wc -l < final_live_web_servers.txt)
echo "[+] Total unique live web servers: $LIVE_TOTAL"
```

#### Create Summary Report

```bash
cat > RECON_SUMMARY.txt << EOF
========================================
RECONNAISSANCE PHASE COMPLETE
========================================

Target Company: $COMPANY_NAME

ASSETS DISCOVERED:
- Root Domains: $(wc -l < all_root_domains.txt)
- All Subdomains: $DOMAIN_TOTAL
- Live Web Servers: $LIVE_TOTAL
- Cloud Assets: $CLOUD_TOTAL
- ASNs: $ASN_TOTAL
- Network Ranges: $NETWORK_TOTAL
- IP Addresses: $IP_TOTAL

FILES CREATED:
- final_all_domains.txt
- final_live_web_servers.txt
- final_cloud_assets.txt
- final_asn_list.txt
- final_network_ranges.txt
- final_ip_addresses.txt

NEXT STEPS:
Proceed to Part 2: Enumeration

========================================
EOF

cat RECON_SUMMARY.txt
```

**PART 1 COMPLETE!** You now have a comprehensive map of the target's entire attack surface. You've discovered:
- Every domain and subdomain
- All live web applications
- Cloud infrastructure
- Network ranges and IP addresses

This reconnaissance data is the foundation for the enumeration phase, where we'll map out specific attack vectors on each live application.

---