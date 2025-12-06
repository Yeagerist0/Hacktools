#!/bin/bash

#====================================================================
#  FULL RECONNAISSANCE AUTOMATION SCRIPT
#====================================================================
#  Complete reconnaissance workflow for bug bounty
#  
#  Usage: ./full-recon.sh <domain> [output_dir]
#  Example: ./full-recon.sh example.com ./output
#====================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check arguments
if [[ -z "$1" ]]; then
    echo -e "${RED}Usage: $0 <domain> [output_dir]${NC}"
    echo "Example: $0 example.com ./output"
    exit 1
fi

DOMAIN="$1"
OUTPUT_DIR="${2:-$HOME/HackTools/output/$DOMAIN}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCRIPTS_DIR="$HOME/HackTools/scripts"
WORDLIST_DIR="$HOME/HackTools/wordlists"

# Create output directories
mkdir -p "$OUTPUT_DIR"/{recon,urls,params,vulns,screenshots}

banner() {
    echo -e "${PURPLE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo "║           FULL RECONNAISSANCE AUTOMATION                  ║"
    echo "║                                                           ║"
    echo "║   Target: $DOMAIN"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1"
}

section() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

banner

#====================================================================
# PHASE 1: SUBDOMAIN ENUMERATION
#====================================================================
section "PHASE 1: SUBDOMAIN ENUMERATION"

# Run subdomain enumeration script
if [[ -f "$SCRIPTS_DIR/recon/subdomain-enum.sh" ]]; then
    bash "$SCRIPTS_DIR/recon/subdomain-enum.sh" "$DOMAIN" "$OUTPUT_DIR/recon"
else
    log "Running inline subdomain enumeration..."
    
    # Subfinder
    if command -v subfinder &> /dev/null; then
        log "Running Subfinder..."
        subfinder -d "$DOMAIN" -silent -o "$OUTPUT_DIR/recon/subfinder.txt" 2>/dev/null || true
    fi
    
    # Assetfinder  
    if command -v assetfinder &> /dev/null; then
        log "Running Assetfinder..."
        assetfinder --subs-only "$DOMAIN" > "$OUTPUT_DIR/recon/assetfinder.txt" 2>/dev/null || true
    fi
    
    # Combine
    cat "$OUTPUT_DIR/recon"/*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/recon/all-subdomains.txt" || true
fi

SUBDOMAINS="$OUTPUT_DIR/recon/all-subdomains.txt"
log "Found $(wc -l < "$SUBDOMAINS" 2>/dev/null || echo 0) subdomains"

#====================================================================
# PHASE 2: DNS RESOLUTION & HTTP PROBING
#====================================================================
section "PHASE 2: DNS RESOLUTION & HTTP PROBING"

# DNS Resolution
if command -v dnsx &> /dev/null; then
    log "Resolving DNS with DNSx..."
    dnsx -l "$SUBDOMAINS" -silent -o "$OUTPUT_DIR/recon/resolved.txt" 2>/dev/null || true
fi

# HTTP Probing
LIVE_HOSTS="$OUTPUT_DIR/recon/live-hosts.txt"
if command -v httpx &> /dev/null; then
    log "Probing HTTP/HTTPS with Httpx..."
    httpx -l "$OUTPUT_DIR/recon/resolved.txt" -silent \
        -status-code -title -tech-detect -follow-redirects \
        -o "$OUTPUT_DIR/recon/httpx-full.txt" 2>/dev/null || true
    
    httpx -l "$OUTPUT_DIR/recon/resolved.txt" -silent \
        -o "$LIVE_HOSTS" 2>/dev/null || true
fi

log "Found $(wc -l < "$LIVE_HOSTS" 2>/dev/null || echo 0) live hosts"

#====================================================================
# PHASE 3: URL COLLECTION
#====================================================================
section "PHASE 3: URL COLLECTION"

URL_FILE="$OUTPUT_DIR/urls/all-urls.txt"

# Waybackurls
if command -v waybackurls &> /dev/null; then
    log "Collecting URLs from Wayback Machine..."
    cat "$SUBDOMAINS" | waybackurls > "$OUTPUT_DIR/urls/wayback.txt" 2>/dev/null || true
fi

# Gau (GetAllUrls)
if command -v gau &> /dev/null; then
    log "Collecting URLs with Gau..."
    cat "$SUBDOMAINS" | gau --threads 5 > "$OUTPUT_DIR/urls/gau.txt" 2>/dev/null || true
fi

# Katana (crawling)
if command -v katana &> /dev/null && [[ -f "$LIVE_HOSTS" ]]; then
    log "Crawling with Katana..."
    katana -list "$LIVE_HOSTS" -silent -d 3 -o "$OUTPUT_DIR/urls/katana.txt" 2>/dev/null || true
fi

# GoSpider
if command -v gospider &> /dev/null && [[ -f "$LIVE_HOSTS" ]]; then
    log "Crawling with GoSpider..."
    gospider -S "$LIVE_HOSTS" -d 2 -t 5 --no-redirect -o "$OUTPUT_DIR/urls/gospider/" 2>/dev/null || true
    cat "$OUTPUT_DIR/urls/gospider/"* 2>/dev/null | grep -oP 'http[s]?://[^\s"]+' | sort -u > "$OUTPUT_DIR/urls/gospider.txt" || true
fi

# Combine all URLs
cat "$OUTPUT_DIR/urls/"*.txt 2>/dev/null | sort -u > "$URL_FILE" || true
log "Collected $(wc -l < "$URL_FILE" 2>/dev/null || echo 0) unique URLs"

#====================================================================
# PHASE 4: PARAMETER DISCOVERY
#====================================================================
section "PHASE 4: PARAMETER DISCOVERY"

# Extract URLs with parameters
grep "=" "$URL_FILE" 2>/dev/null | sort -u > "$OUTPUT_DIR/params/urls-with-params.txt" || true

# Arjun for parameter discovery
if command -v arjun &> /dev/null && [[ -f "$LIVE_HOSTS" ]]; then
    log "Running Arjun for parameter discovery..."
    head -20 "$LIVE_HOSTS" | while read -r url; do
        arjun -u "$url" -oT "$OUTPUT_DIR/params/arjun-params.txt" 2>/dev/null || true
    done
fi

# ParamSpider
if command -v paramspider &> /dev/null; then
    log "Running ParamSpider..."
    paramspider -d "$DOMAIN" -o "$OUTPUT_DIR/params/" 2>/dev/null || true
fi

log "Found $(wc -l < "$OUTPUT_DIR/params/urls-with-params.txt" 2>/dev/null || echo 0) URLs with parameters"

#====================================================================
# PHASE 5: JAVASCRIPT ANALYSIS
#====================================================================
section "PHASE 5: JAVASCRIPT FILE ANALYSIS"

# Extract JS files
grep -iE "\.js(\?|$)" "$URL_FILE" 2>/dev/null | sort -u > "$OUTPUT_DIR/urls/js-files.txt" || true
log "Found $(wc -l < "$OUTPUT_DIR/urls/js-files.txt" 2>/dev/null || echo 0) JavaScript files"

# Download JS files for analysis
mkdir -p "$OUTPUT_DIR/urls/js-downloaded"
if [[ -s "$OUTPUT_DIR/urls/js-files.txt" ]]; then
    log "Downloading JS files for analysis..."
    head -50 "$OUTPUT_DIR/urls/js-files.txt" | while read -r jsurl; do
        filename=$(echo "$jsurl" | md5sum | cut -d' ' -f1).js
        curl -s "$jsurl" -o "$OUTPUT_DIR/urls/js-downloaded/$filename" 2>/dev/null || true
    done
fi

#====================================================================
# PHASE 6: TECHNOLOGY DETECTION
#====================================================================
section "PHASE 6: TECHNOLOGY DETECTION"

# Extract technologies from httpx results
if [[ -f "$OUTPUT_DIR/recon/httpx-full.txt" ]]; then
    log "Extracting technology information..."
    cat "$OUTPUT_DIR/recon/httpx-full.txt" | grep -oP '\[.*?\]' | sort | uniq -c | sort -rn > "$OUTPUT_DIR/recon/technologies.txt" || true
fi

#====================================================================
# PHASE 7: VULNERABILITY PATTERNS (GF)
#====================================================================
section "PHASE 7: VULNERABILITY PATTERN MATCHING"

if command -v gf &> /dev/null && [[ -f "$URL_FILE" ]]; then
    log "Running GF patterns for vulnerability discovery..."
    
    mkdir -p "$OUTPUT_DIR/params/gf-patterns"
    
    # XSS patterns
    cat "$URL_FILE" | gf xss 2>/dev/null | sort -u > "$OUTPUT_DIR/params/gf-patterns/xss.txt" || true
    
    # SQLi patterns
    cat "$URL_FILE" | gf sqli 2>/dev/null | sort -u > "$OUTPUT_DIR/params/gf-patterns/sqli.txt" || true
    
    # SSRF patterns
    cat "$URL_FILE" | gf ssrf 2>/dev/null | sort -u > "$OUTPUT_DIR/params/gf-patterns/ssrf.txt" || true
    
    # LFI patterns
    cat "$URL_FILE" | gf lfi 2>/dev/null | sort -u > "$OUTPUT_DIR/params/gf-patterns/lfi.txt" || true
    
    # Redirect patterns
    cat "$URL_FILE" | gf redirect 2>/dev/null | sort -u > "$OUTPUT_DIR/params/gf-patterns/redirect.txt" || true
    
    # IDOR patterns
    cat "$URL_FILE" | gf idor 2>/dev/null | sort -u > "$OUTPUT_DIR/params/gf-patterns/idor.txt" || true
    
    log "GF pattern matching complete"
fi

#====================================================================
# PHASE 8: INITIAL VULNERABILITY SCANNING
#====================================================================
section "PHASE 8: VULNERABILITY SCANNING"

# Nuclei scanning
if command -v nuclei &> /dev/null && [[ -f "$LIVE_HOSTS" ]]; then
    log "Running Nuclei vulnerability scanner..."
    nuclei -l "$LIVE_HOSTS" -severity critical,high,medium \
        -o "$OUTPUT_DIR/vulns/nuclei-results.txt" 2>/dev/null || true
    
    log "Nuclei scan complete: $(wc -l < "$OUTPUT_DIR/vulns/nuclei-results.txt" 2>/dev/null || echo 0) findings"
fi

#====================================================================
# SUMMARY REPORT
#====================================================================
section "RECONNAISSANCE SUMMARY"

# Generate summary
cat > "$OUTPUT_DIR/SUMMARY.md" << EOF
# Reconnaissance Summary for $DOMAIN

**Date:** $(date '+%Y-%m-%d %H:%M:%S')

## Statistics

| Metric | Count |
|--------|-------|
| Total Subdomains | $(wc -l < "$SUBDOMAINS" 2>/dev/null || echo 0) |
| Resolved Hosts | $(wc -l < "$OUTPUT_DIR/recon/resolved.txt" 2>/dev/null || echo 0) |
| Live HTTP Hosts | $(wc -l < "$LIVE_HOSTS" 2>/dev/null || echo 0) |
| Total URLs | $(wc -l < "$URL_FILE" 2>/dev/null || echo 0) |
| URLs with Params | $(wc -l < "$OUTPUT_DIR/params/urls-with-params.txt" 2>/dev/null || echo 0) |
| JS Files | $(wc -l < "$OUTPUT_DIR/urls/js-files.txt" 2>/dev/null || echo 0) |
| Nuclei Findings | $(wc -l < "$OUTPUT_DIR/vulns/nuclei-results.txt" 2>/dev/null || echo 0) |

## Key Files

- \`recon/all-subdomains.txt\` - All discovered subdomains
- \`recon/live-hosts.txt\` - Live HTTP/HTTPS hosts
- \`urls/all-urls.txt\` - All collected URLs
- \`params/urls-with-params.txt\` - URLs with parameters
- \`params/gf-patterns/\` - Vulnerability pattern matches
- \`vulns/nuclei-results.txt\` - Nuclei scan results

## Next Steps

1. Review live hosts for interesting targets
2. Test XSS patterns in \`params/gf-patterns/xss.txt\`
3. Test SQLi patterns in \`params/gf-patterns/sqli.txt\`
4. Analyze JavaScript files for sensitive data
5. Run targeted Nuclei templates on specific findings
6. Manual testing on high-value targets

EOF

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           RECONNAISSANCE COMPLETE                         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo -e "Target:            ${YELLOW}$DOMAIN${NC}"
echo -e "Subdomains:        ${GREEN}$(wc -l < "$SUBDOMAINS" 2>/dev/null || echo 0)${NC}"
echo -e "Live Hosts:        ${GREEN}$(wc -l < "$LIVE_HOSTS" 2>/dev/null || echo 0)${NC}"
echo -e "URLs Collected:    ${GREEN}$(wc -l < "$URL_FILE" 2>/dev/null || echo 0)${NC}"
echo -e "Nuclei Findings:   ${GREEN}$(wc -l < "$OUTPUT_DIR/vulns/nuclei-results.txt" 2>/dev/null || echo 0)${NC}"
echo ""
echo -e "Output Directory:  ${BLUE}$OUTPUT_DIR${NC}"
echo -e "Summary Report:    ${BLUE}$OUTPUT_DIR/SUMMARY.md${NC}"
echo ""
