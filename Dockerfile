FROM kalilinux/kali-rolling:latest

LABEL maintainer="BB Methodology"
LABEL description="Automated Bug Bounty Reconnaissance Pipeline"

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# ── System Dependencies ─────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    ruby \
    ruby-dev \
    ruby-bundler \
    golang-go \
    git \
    wget \
    curl \
    jq \
    dnsutils \
    nmap \
    whois \
    host \
    netcat-openbsd \
    unzip \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Go Environment ──────────────────────────────────────────────────────────
ENV GOPATH=/root/go
ENV PATH="${PATH}:${GOPATH}/bin:/usr/local/go/bin"

# ── Go-based Recon Tools ───────────────────────────────────────────────────
RUN go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/tomnomnom/unfurl@latest && \
    go install -v github.com/glebarez/cero@latest && \
    go install -v github.com/gwen001/github-subdomains@latest

# ── Python Tools ────────────────────────────────────────────────────────────
RUN pip3 install --break-system-packages parameth 2>/dev/null || true

# ── Git-cloned Tools ───────────────────────────────────────────────────────
RUN mkdir -p /opt/tools

# CeWL - Custom Word List Generator (Ruby)
RUN git clone --depth 1 https://github.com/digininja/CeWL.git /opt/tools/cewl && \
    cd /opt/tools/cewl && \
    bundle install --system 2>/dev/null || gem install nokogiri mime-types mini_magick rubyzip json 2>/dev/null || true && \
    ln -sf /opt/tools/cewl/cewl.rb /usr/local/bin/cewl && \
    chmod +x /opt/tools/cewl/cewl.rb

# Sublist3r - Subdomain Enumeration (Python, git version preferred over pip)
RUN git clone --depth 1 https://github.com/aboul3la/Sublist3r.git /opt/tools/sublist3r && \
    pip3 install --break-system-packages -r /opt/tools/sublist3r/requirements.txt 2>/dev/null || true && \
    chmod +x /opt/tools/sublist3r/sublist3r.py && \
    ln -sf /opt/tools/sublist3r/sublist3r.py /usr/local/bin/sublist3r

# SubDomainizer - JavaScript subdomain/secret discovery
RUN git clone --depth 1 https://github.com/nsonaniya2010/SubDomainizer.git /opt/tools/SubDomainizer && \
    pip3 install --break-system-packages \
        beautifulsoup4 requests termcolor colorama tldextract cffi 2>/dev/null || true

# Cloud_Enum - Cloud bucket/service brute force
RUN git clone --depth 1 https://github.com/initstring/cloud_enum.git /opt/tools/cloud_enum && \
    pip3 install --break-system-packages -r /opt/tools/cloud_enum/requirements.txt 2>/dev/null || true

# Metabigor - OSINT intelligence tool (Go build from source)
RUN git clone --depth 1 https://github.com/j3ssie/metabigor.git /opt/tools/metabigor && \
    cd /opt/tools/metabigor && make build && cp ./bin/metabigor /usr/local/bin/metabigor

# ── Copy Scripts ────────────────────────────────────────────────────────────
COPY recon.sh /opt/scripts/recon.sh
COPY entrypoint.sh /opt/scripts/entrypoint.sh
COPY lib/ /opt/scripts/lib/
COPY wordlists/ /opt/scripts/wordlists/

RUN chmod +x /opt/scripts/recon.sh /opt/scripts/entrypoint.sh

# ── Runtime ─────────────────────────────────────────────────────────────────
WORKDIR /output

# Default mount points:
#   /output        — results (always mount this)
#   /input         — optional, for --domains-file
ENTRYPOINT ["/opt/scripts/entrypoint.sh"]
CMD ["--help"]
