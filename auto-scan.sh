#!/bin/bash

#====================================================================
#  AUTOMATED BUG BOUNTY SCANNER
#====================================================================
#  Usage: ./auto-scan.sh <target-domain>
#  Example: ./auto-scan.sh example.com
#
#  This script automates the entire bug bounty workflow:
#  1. Subdomain Enumeration
#  2. Live Host Detection
#  3. Port Scanning
#  4. URL Collection
#  5. Technology Detection
#  6. Vulnerability Scanning
#  7. Directory Fuzzing
#  8. Parameter Discovery
#  9. XSS Testing
#  10. SQL Injection Testing
#
#  DISCLAIMER: Only use on authorized targets!
#====================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║         AUTOMATED BUG BOUNTY SCANNER                      ║"
    echo "║                                                           ║"
    echo "║   ⚠️  Only use on authorized targets!                     ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }
section() {
    echo ""
    echo -e "${PURPLE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}  $1${NC}"
    echo -e "${PURPLE}════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Check if target is provided
if [[ $# -lt 1 ]]; then
    banner
    echo "Usage: $0 <target-domain> [options]"
    echo ""
    echo "Options:"
    echo "  --quick       Quick scan (skip intensive scans)"
    echo "  --full        Full scan with all modules (default)"
    echo "  --passive     Passive recon only (no active scanning)"
    echo "  --no-vuln     Skip vulnerability scanning"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 example.com --quick"
    echo "  $0 https://example.com --passive"
    exit 1
fi

# Parse arguments
TARGET="$1"
MODE="full"
SKIP_VULN=false

shift
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick) MODE="quick" ;;
        --full) MODE="full" ;;
        --passive) MODE="passive" ;;
        --no-vuln) SKIP_VULN=true ;;
        *) warn "Unknown option: $1" ;;
    esac
    shift
done

# Clean target (remove protocol if present)
DOMAIN=$(echo "$TARGET" | sed -e 's|^https\?://||' -e 's|/.*$||')
TARGET_URL="https://$DOMAIN"

# Setup output directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$HOME/HackTools/results/${DOMAIN}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"/{subdomains,ports,urls,vulns,fuzzing,params,screenshots}

# Log file
LOGFILE="$OUTPUT_DIR/scan.log"
exec > >(tee -a "$LOGFILE") 2>&1

banner
log "Target: $DOMAIN"
log "Mode: $MODE"
log "Output: $OUTPUT_DIR"
log "Started: $(date)"
echo ""

#====================================================================
# PHASE 1: SUBDOMAIN ENUMERATION
#====================================================================
subdomain_enum() {
    section "PHASE 1: Subdomain Enumeration"
    
    SUBS_DIR="$OUTPUT_DIR/subdomains"
    
    # Subfinder
    if command -v subfinder &> /dev/null; then
        log "Running Subfinder..."
        subfinder -d "$DOMAIN" -silent -o "$SUBS_DIR/subfinder.txt" 2>/dev/null || true
        log "Subfinder found: $(wc -l < "$SUBS_DIR/subfinder.txt" 2>/dev/null || echo 0) subdomains"
    fi
    
    # Amass (passive mode for speed)
    if command -v amass &> /dev/null && [[ "$MODE" != "quick" ]]; then
        log "Running Amass (passive)..."
        timeout 300 amass enum -passive -d "$DOMAIN" -o "$SUBS_DIR/amass.txt" 2>/dev/null || true
        log "Amass found: $(wc -l < "$SUBS_DIR/amass.txt" 2>/dev/null || echo 0) subdomains"
    fi
    
    # Assetfinder
    if command -v assetfinder &> /dev/null; then
        log "Running Assetfinder..."
        assetfinder --subs-only "$DOMAIN" > "$SUBS_DIR/assetfinder.txt" 2>/dev/null || true
        log "Assetfinder found: $(wc -l < "$SUBS_DIR/assetfinder.txt" 2>/dev/null || echo 0) subdomains"
    fi
    
    # Findomain
    if command -v findomain &> /dev/null; then
        log "Running Findomain..."
        findomain -t "$DOMAIN" -q > "$SUBS_DIR/findomain.txt" 2>/dev/null || true
        log "Findomain found: $(wc -l < "$SUBS_DIR/findomain.txt" 2>/dev/null || echo 0) subdomains"
    fi
    
    # Merge and deduplicate
    log "Merging and deduplicating subdomains..."
    cat "$SUBS_DIR"/*.txt 2>/dev/null | sort -u | grep -E "^[a-zA-Z0-9]" > "$OUTPUT_DIR/all_subdomains.txt" || true
    
    TOTAL_SUBS=$(wc -l < "$OUTPUT_DIR/all_subdomains.txt" 2>/dev/null || echo 0)
    log "Total unique subdomains: $TOTAL_SUBS"
}

#====================================================================
# PHASE 2: LIVE HOST DETECTION
#====================================================================
live_hosts() {
    section "PHASE 2: Live Host Detection"
    
    if [[ ! -s "$OUTPUT_DIR/all_subdomains.txt" ]]; then
        warn "No subdomains found, using main domain only"
        echo "$DOMAIN" > "$OUTPUT_DIR/all_subdomains.txt"
    fi
    
    # Httpx for live detection
    if command -v httpx &> /dev/null; then
        log "Probing for live hosts with httpx..."
        cat "$OUTPUT_DIR/all_subdomains.txt" | httpx -silent -threads 50 \
            -status-code -title -tech-detect -follow-redirects \
            -o "$OUTPUT_DIR/live_hosts_full.txt" 2>/dev/null || true
        
        # Extract just URLs
        cat "$OUTPUT_DIR/live_hosts_full.txt" | awk '{print $1}' > "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null || true
        
        LIVE_COUNT=$(wc -l < "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null || echo 0)
        log "Live hosts found: $LIVE_COUNT"
    else
        # Fallback to httprobe
        if command -v httprobe &> /dev/null; then
            log "Probing with httprobe..."
            cat "$OUTPUT_DIR/all_subdomains.txt" | httprobe > "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null || true
        fi
    fi
    
    # If no live hosts, use main target
    if [[ ! -s "$OUTPUT_DIR/live_hosts.txt" ]]; then
        echo "$TARGET_URL" > "$OUTPUT_DIR/live_hosts.txt"
    fi
}

#====================================================================
# PHASE 3: PORT SCANNING
#====================================================================
port_scan() {
    section "PHASE 3: Port Scanning"
    
    if [[ "$MODE" == "passive" ]]; then
        warn "Skipping port scan (passive mode)"
        return
    fi
    
    PORTS_DIR="$OUTPUT_DIR/ports"
    
    # Naabu (fast port scanner)
    if command -v naabu &> /dev/null; then
        log "Running Naabu port scan..."
        if [[ "$MODE" == "quick" ]]; then
            naabu -host "$DOMAIN" -top-ports 100 -silent -o "$PORTS_DIR/naabu.txt" 2>/dev/null || true
        else
            naabu -host "$DOMAIN" -top-ports 1000 -silent -o "$PORTS_DIR/naabu.txt" 2>/dev/null || true
        fi
        log "Open ports: $(wc -l < "$PORTS_DIR/naabu.txt" 2>/dev/null || echo 0)"
    fi
    
    # Nmap service detection on found ports
    if command -v nmap &> /dev/null && [[ -s "$PORTS_DIR/naabu.txt" ]]; then
        log "Running Nmap service detection..."
        PORTS=$(cat "$PORTS_DIR/naabu.txt" | cut -d':' -f2 | tr '\n' ',' | sed 's/,$//')
        if [[ -n "$PORTS" ]]; then
            nmap -sV -sC -p"$PORTS" "$DOMAIN" -oN "$PORTS_DIR/nmap_services.txt" 2>/dev/null || true
        fi
    fi
}

#====================================================================
# PHASE 4: URL COLLECTION
#====================================================================
url_collection() {
    section "PHASE 4: URL Collection"
    
    URLS_DIR="$OUTPUT_DIR/urls"
    
    # Waybackurls
    if command -v waybackurls &> /dev/null; then
        log "Fetching URLs from Wayback Machine..."
        echo "$DOMAIN" | waybackurls > "$URLS_DIR/wayback.txt" 2>/dev/null || true
        log "Wayback URLs: $(wc -l < "$URLS_DIR/wayback.txt" 2>/dev/null || echo 0)"
    fi
    
    # GAU (GetAllUrls)
    if command -v gau &> /dev/null; then
        log "Fetching URLs with GAU..."
        echo "$DOMAIN" | gau --threads 5 > "$URLS_DIR/gau.txt" 2>/dev/null || true
        log "GAU URLs: $(wc -l < "$URLS_DIR/gau.txt" 2>/dev/null || echo 0)"
    fi
    
    # Katana (crawling)
    if command -v katana &> /dev/null && [[ "$MODE" != "passive" ]]; then
        log "Crawling with Katana..."
        katana -u "$TARGET_URL" -d 3 -silent -o "$URLS_DIR/katana.txt" 2>/dev/null || true
        log "Katana URLs: $(wc -l < "$URLS_DIR/katana.txt" 2>/dev/null || echo 0)"
    fi
    
    # GoSpider
    if command -v gospider &> /dev/null && [[ "$MODE" == "full" ]]; then
        log "Crawling with GoSpider..."
        gospider -s "$TARGET_URL" -d 2 -c 10 --other-source -o "$URLS_DIR/gospider_raw" 2>/dev/null || true
        cat "$URLS_DIR/gospider_raw"/* 2>/dev/null | grep -oP 'https?://[^\s"]+' | sort -u > "$URLS_DIR/gospider.txt" || true
    fi
    
    # Merge all URLs
    log "Merging and filtering URLs..."
    cat "$URLS_DIR"/*.txt 2>/dev/null | sort -u | grep -E "^https?://" > "$OUTPUT_DIR/all_urls.txt" || true
    
    # Filter for interesting endpoints
    grep -iE "\.(php|asp|aspx|jsp|json|xml|conf|config|bak|backup|old|sql|log|txt)$" "$OUTPUT_DIR/all_urls.txt" > "$OUTPUT_DIR/interesting_files.txt" 2>/dev/null || true
    grep -iE "\?(.*=)" "$OUTPUT_DIR/all_urls.txt" > "$OUTPUT_DIR/urls_with_params.txt" 2>/dev/null || true
    grep -iE "(api|graphql|rest|v1|v2)" "$OUTPUT_DIR/all_urls.txt" > "$OUTPUT_DIR/api_endpoints.txt" 2>/dev/null || true
    
    log "Total URLs: $(wc -l < "$OUTPUT_DIR/all_urls.txt" 2>/dev/null || echo 0)"
    log "URLs with params: $(wc -l < "$OUTPUT_DIR/urls_with_params.txt" 2>/dev/null || echo 0)"
    log "Interesting files: $(wc -l < "$OUTPUT_DIR/interesting_files.txt" 2>/dev/null || echo 0)"
    log "API endpoints: $(wc -l < "$OUTPUT_DIR/api_endpoints.txt" 2>/dev/null || echo 0)"
}

#====================================================================
# PHASE 5: VULNERABILITY SCANNING
#====================================================================
vuln_scan() {
    section "PHASE 5: Vulnerability Scanning"
    
    if [[ "$SKIP_VULN" == true ]] || [[ "$MODE" == "passive" ]]; then
        warn "Skipping vulnerability scan"
        return
    fi
    
    VULNS_DIR="$OUTPUT_DIR/vulns"
    
    # Nuclei
    if command -v nuclei &> /dev/null; then
        log "Running Nuclei vulnerability scanner..."
        
        if [[ "$MODE" == "quick" ]]; then
            # Quick scan - critical and high only
            nuclei -l "$OUTPUT_DIR/live_hosts.txt" -severity critical,high \
                -silent -o "$VULNS_DIR/nuclei_critical.txt" 2>/dev/null || true
        else
            # Full scan
            nuclei -l "$OUTPUT_DIR/live_hosts.txt" -severity critical,high,medium \
                -silent -o "$VULNS_DIR/nuclei_results.txt" 2>/dev/null || true
            
            # Also scan URLs with params for injection vulnerabilities
            if [[ -s "$OUTPUT_DIR/urls_with_params.txt" ]]; then
                log "Scanning parameterized URLs..."
                nuclei -l "$OUTPUT_DIR/urls_with_params.txt" -t cves,vulnerabilities \
                    -severity critical,high -silent -o "$VULNS_DIR/nuclei_params.txt" 2>/dev/null || true
            fi
        fi
        
        VULN_COUNT=$(wc -l < "$VULNS_DIR/nuclei_results.txt" 2>/dev/null || wc -l < "$VULNS_DIR/nuclei_critical.txt" 2>/dev/null || echo 0)
        if [[ "$VULN_COUNT" -gt 0 ]]; then
            warn "Vulnerabilities found: $VULN_COUNT"
        else
            log "No critical vulnerabilities found"
        fi
    fi
}

#====================================================================
# PHASE 6: DIRECTORY FUZZING
#====================================================================
dir_fuzz() {
    section "PHASE 6: Directory Fuzzing"
    
    if [[ "$MODE" == "passive" ]]; then
        warn "Skipping directory fuzzing (passive mode)"
        return
    fi
    
    FUZZ_DIR="$OUTPUT_DIR/fuzzing"
    WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
    
    # Fallback wordlists
    [[ ! -f "$WORDLIST" ]] && WORDLIST="/usr/share/wordlists/dirb/common.txt"
    [[ ! -f "$WORDLIST" ]] && WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
    
    if [[ ! -f "$WORDLIST" ]]; then
        warn "No wordlist found, skipping directory fuzzing"
        return
    fi
    
    # FFUF
    if command -v ffuf &> /dev/null; then
        log "Running FFUF directory fuzzing..."
        ffuf -u "${TARGET_URL}/FUZZ" -w "$WORDLIST" -mc 200,201,202,204,301,302,307,401,403,405 \
            -t 50 -timeout 10 -o "$FUZZ_DIR/ffuf.json" -of json 2>/dev/null || true
        
        # Parse results
        if [[ -f "$FUZZ_DIR/ffuf.json" ]]; then
            cat "$FUZZ_DIR/ffuf.json" | jq -r '.results[]? | "\(.status) \(.url)"' > "$FUZZ_DIR/ffuf_results.txt" 2>/dev/null || true
            log "Directories found: $(wc -l < "$FUZZ_DIR/ffuf_results.txt" 2>/dev/null || echo 0)"
        fi
    elif command -v gobuster &> /dev/null; then
        log "Running Gobuster..."
        gobuster dir -u "$TARGET_URL" -w "$WORDLIST" -t 50 -q -o "$FUZZ_DIR/gobuster.txt" 2>/dev/null || true
    elif command -v feroxbuster &> /dev/null; then
        log "Running Feroxbuster..."
        feroxbuster -u "$TARGET_URL" -w "$WORDLIST" -t 50 -q -o "$FUZZ_DIR/feroxbuster.txt" 2>/dev/null || true
    fi
}

#====================================================================
# PHASE 7: PARAMETER DISCOVERY
#====================================================================
param_discovery() {
    section "PHASE 7: Parameter Discovery"
    
    if [[ "$MODE" == "passive" ]] || [[ "$MODE" == "quick" ]]; then
        warn "Skipping parameter discovery"
        return
    fi
    
    PARAMS_DIR="$OUTPUT_DIR/params"
    
    # Arjun
    if command -v arjun &> /dev/null; then
        log "Running Arjun parameter discovery..."
        arjun -u "$TARGET_URL" -oT "$PARAMS_DIR/arjun.txt" 2>/dev/null || true
        
        if [[ -s "$PARAMS_DIR/arjun.txt" ]]; then
            log "Parameters found: $(wc -l < "$PARAMS_DIR/arjun.txt" 2>/dev/null || echo 0)"
        fi
    fi
}

#====================================================================
# PHASE 8: XSS TESTING
#====================================================================
xss_test() {
    section "PHASE 8: XSS Testing"
    
    if [[ "$MODE" == "passive" ]]; then
        warn "Skipping XSS testing (passive mode)"
        return
    fi
    
    XSS_DIR="$OUTPUT_DIR/vulns/xss"
    mkdir -p "$XSS_DIR"
    
    # Dalfox
    if command -v dalfox &> /dev/null && [[ -s "$OUTPUT_DIR/urls_with_params.txt" ]]; then
        log "Running Dalfox XSS scanner..."
        
        # Test first 50 URLs with params (to avoid long scans)
        head -50 "$OUTPUT_DIR/urls_with_params.txt" | dalfox pipe --silence \
            -o "$XSS_DIR/dalfox_results.txt" 2>/dev/null || true
        
        XSS_COUNT=$(wc -l < "$XSS_DIR/dalfox_results.txt" 2>/dev/null || echo 0)
        if [[ "$XSS_COUNT" -gt 0 ]]; then
            warn "Potential XSS found: $XSS_COUNT"
        else
            log "No XSS vulnerabilities detected"
        fi
    else
        warn "Dalfox not available or no parameterized URLs"
    fi
}

#====================================================================
# PHASE 9: SQL INJECTION TESTING
#====================================================================
sqli_test() {
    section "PHASE 9: SQL Injection Testing"
    
    if [[ "$MODE" == "passive" ]] || [[ "$MODE" == "quick" ]]; then
        warn "Skipping SQLi testing"
        return
    fi
    
    SQLI_DIR="$OUTPUT_DIR/vulns/sqli"
    mkdir -p "$SQLI_DIR"
    
    # SQLMap (test first 10 URLs)
    if command -v sqlmap &> /dev/null && [[ -s "$OUTPUT_DIR/urls_with_params.txt" ]]; then
        log "Running SQLMap on parameterized URLs..."
        
        head -10 "$OUTPUT_DIR/urls_with_params.txt" | while read -r url; do
            log "Testing: $url"
            timeout 120 sqlmap -u "$url" --batch --level=1 --risk=1 \
                --output-dir="$SQLI_DIR" --forms 2>/dev/null || true
        done
        
        log "SQLMap testing complete"
    fi
}

#====================================================================
# GENERATE REPORT
#====================================================================
generate_report() {
    section "GENERATING FINAL REPORT"
    
    REPORT="$OUTPUT_DIR/SCAN_REPORT.md"
    
    cat > "$REPORT" << EOF
# Bug Bounty Scan Report

## Target Information
- **Domain:** $DOMAIN
- **Scan Mode:** $MODE
- **Date:** $(date)
- **Output Directory:** $OUTPUT_DIR

---

## Summary

| Category | Count |
|----------|-------|
| Subdomains | $(wc -l < "$OUTPUT_DIR/all_subdomains.txt" 2>/dev/null || echo 0) |
| Live Hosts | $(wc -l < "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null || echo 0) |
| Total URLs | $(wc -l < "$OUTPUT_DIR/all_urls.txt" 2>/dev/null || echo 0) |
| URLs with Params | $(wc -l < "$OUTPUT_DIR/urls_with_params.txt" 2>/dev/null || echo 0) |
| Interesting Files | $(wc -l < "$OUTPUT_DIR/interesting_files.txt" 2>/dev/null || echo 0) |
| API Endpoints | $(wc -l < "$OUTPUT_DIR/api_endpoints.txt" 2>/dev/null || echo 0) |

---

## Live Hosts (with technologies)
\`\`\`
$(head -50 "$OUTPUT_DIR/live_hosts_full.txt" 2>/dev/null || echo "No data")
\`\`\`

---

## Vulnerabilities Found
\`\`\`
$(cat "$OUTPUT_DIR/vulns/nuclei_results.txt" "$OUTPUT_DIR/vulns/nuclei_critical.txt" 2>/dev/null | head -50 || echo "No vulnerabilities detected")
\`\`\`

---

## XSS Results
\`\`\`
$(cat "$OUTPUT_DIR/vulns/xss/dalfox_results.txt" 2>/dev/null | head -20 || echo "No XSS found")
\`\`\`

---

## Interesting Files
\`\`\`
$(head -30 "$OUTPUT_DIR/interesting_files.txt" 2>/dev/null || echo "None found")
\`\`\`

---

## API Endpoints
\`\`\`
$(head -30 "$OUTPUT_DIR/api_endpoints.txt" 2>/dev/null || echo "None found")
\`\`\`

---

## Directory Fuzzing Results
\`\`\`
$(cat "$OUTPUT_DIR/fuzzing/ffuf_results.txt" "$OUTPUT_DIR/fuzzing/gobuster.txt" 2>/dev/null | head -30 || echo "No directories found")
\`\`\`

---

## Open Ports
\`\`\`
$(cat "$OUTPUT_DIR/ports/naabu.txt" 2>/dev/null || echo "No port scan data")
\`\`\`

---

## Files Generated
$(find "$OUTPUT_DIR" -type f -name "*.txt" | sort)

---

**⚠️ DISCLAIMER:** This scan was performed for authorized security testing only.

EOF

    log "Report saved to: $REPORT"
}

#====================================================================
# MAIN EXECUTION
#====================================================================
main() {
    # Check for authorization
    echo ""
    warn "You are about to scan: $DOMAIN"
    warn "Make sure you have WRITTEN AUTHORIZATION to test this target!"
    echo ""
    read -p "Do you have authorization to scan this target? (yes/no): " CONFIRM
    
    if [[ "$CONFIRM" != "yes" ]]; then
        error "Scan aborted. Only scan targets you have permission to test."
        exit 1
    fi
    
    # Run all phases
    subdomain_enum
    live_hosts
    port_scan
    url_collection
    vuln_scan
    dir_fuzz
    param_discovery
    xss_test
    sqli_test
    generate_report
    
    # Final summary
    section "SCAN COMPLETE"
    log "Target: $DOMAIN"
    log "Duration: $SECONDS seconds"
    log "Results saved to: $OUTPUT_DIR"
    log "Report: $OUTPUT_DIR/SCAN_REPORT.md"
    echo ""
    info "To view the report:"
    echo "  cat $OUTPUT_DIR/SCAN_REPORT.md"
    echo ""
    info "Key findings:"
    echo "  - Subdomains: $(wc -l < "$OUTPUT_DIR/all_subdomains.txt" 2>/dev/null || echo 0)"
    echo "  - Live hosts: $(wc -l < "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null || echo 0)"
    echo "  - URLs found: $(wc -l < "$OUTPUT_DIR/all_urls.txt" 2>/dev/null || echo 0)"
    echo "  - Vulnerabilities: $(cat "$OUTPUT_DIR/vulns/"*.txt 2>/dev/null | wc -l || echo 0)"
    echo ""
}

# Run
main
