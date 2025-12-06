#!/bin/bash

#====================================================================
#  SUBDOMAIN ENUMERATION SCRIPT
#====================================================================
#  Comprehensive subdomain enumeration using multiple tools
#  
#  Usage: ./subdomain-enum.sh <domain> [output_dir]
#  Example: ./subdomain-enum.sh example.com ./output
#====================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check arguments
if [[ -z "$1" ]]; then
    echo -e "${RED}Usage: $0 <domain> [output_dir]${NC}"
    echo "Example: $0 example.com ./output"
    exit 1
fi

DOMAIN="$1"
OUTPUT_DIR="${2:-$HOME/HackTools/output/$DOMAIN/recon}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           SUBDOMAIN ENUMERATION                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${GREEN}[+] Target: ${NC}$DOMAIN"
echo -e "${GREEN}[+] Output: ${NC}$OUTPUT_DIR"
echo ""

#====================================================================
# PASSIVE ENUMERATION
#====================================================================
echo -e "${YELLOW}[*] Starting Passive Enumeration...${NC}"

# Subfinder
if command -v subfinder &> /dev/null; then
    echo -e "${BLUE}[>] Running Subfinder...${NC}"
    subfinder -d "$DOMAIN" -silent -o "$OUTPUT_DIR/subfinder.txt" 2>/dev/null
    echo -e "${GREEN}[+] Subfinder: $(wc -l < "$OUTPUT_DIR/subfinder.txt" 2>/dev/null || echo 0) subdomains${NC}"
fi

# Assetfinder
if command -v assetfinder &> /dev/null; then
    echo -e "${BLUE}[>] Running Assetfinder...${NC}"
    assetfinder --subs-only "$DOMAIN" > "$OUTPUT_DIR/assetfinder.txt" 2>/dev/null
    echo -e "${GREEN}[+] Assetfinder: $(wc -l < "$OUTPUT_DIR/assetfinder.txt" 2>/dev/null || echo 0) subdomains${NC}"
fi

# Amass (passive only for speed)
if command -v amass &> /dev/null; then
    echo -e "${BLUE}[>] Running Amass (passive)...${NC}"
    timeout 300 amass enum -passive -d "$DOMAIN" -o "$OUTPUT_DIR/amass.txt" 2>/dev/null || true
    echo -e "${GREEN}[+] Amass: $(wc -l < "$OUTPUT_DIR/amass.txt" 2>/dev/null || echo 0) subdomains${NC}"
fi

# Findomain
if command -v findomain &> /dev/null; then
    echo -e "${BLUE}[>] Running Findomain...${NC}"
    findomain -t "$DOMAIN" -q -o 2>/dev/null
    mv "$DOMAIN.txt" "$OUTPUT_DIR/findomain.txt" 2>/dev/null || true
    echo -e "${GREEN}[+] Findomain: $(wc -l < "$OUTPUT_DIR/findomain.txt" 2>/dev/null || echo 0) subdomains${NC}"
fi

# crt.sh (Certificate Transparency)
echo -e "${BLUE}[>] Querying crt.sh...${NC}"
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | \
    sort -u > "$OUTPUT_DIR/crtsh.txt" || true
echo -e "${GREEN}[+] crt.sh: $(wc -l < "$OUTPUT_DIR/crtsh.txt" 2>/dev/null || echo 0) subdomains${NC}"

# Wayback Machine subdomains
echo -e "${BLUE}[>] Querying Wayback Machine...${NC}"
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=text&fl=original&collapse=urlkey" 2>/dev/null | \
    awk -F/ '{print $3}' | \
    sort -u > "$OUTPUT_DIR/wayback.txt" || true
echo -e "${GREEN}[+] Wayback: $(wc -l < "$OUTPUT_DIR/wayback.txt" 2>/dev/null || echo 0) subdomains${NC}"

#====================================================================
# COMBINE AND DEDUPLICATE
#====================================================================
echo ""
echo -e "${YELLOW}[*] Combining Results...${NC}"

cat "$OUTPUT_DIR"/*.txt 2>/dev/null | \
    grep -E "^[a-zA-Z0-9]" | \
    grep "$DOMAIN" | \
    sort -u > "$OUTPUT_DIR/all-subdomains.txt"

TOTAL=$(wc -l < "$OUTPUT_DIR/all-subdomains.txt")
echo -e "${GREEN}[+] Total Unique Subdomains: $TOTAL${NC}"

#====================================================================
# DNS RESOLUTION
#====================================================================
echo ""
echo -e "${YELLOW}[*] Resolving DNS...${NC}"

if command -v dnsx &> /dev/null; then
    echo -e "${BLUE}[>] Running DNSx...${NC}"
    dnsx -l "$OUTPUT_DIR/all-subdomains.txt" -silent -a -resp-only -o "$OUTPUT_DIR/resolved-ips.txt" 2>/dev/null
    dnsx -l "$OUTPUT_DIR/all-subdomains.txt" -silent -o "$OUTPUT_DIR/resolved-subdomains.txt" 2>/dev/null
    RESOLVED=$(wc -l < "$OUTPUT_DIR/resolved-subdomains.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Resolved Subdomains: $RESOLVED${NC}"
else
    # Fallback to basic resolution
    echo -e "${BLUE}[>] Running basic DNS resolution...${NC}"
    while read -r subdomain; do
        if host "$subdomain" &>/dev/null; then
            echo "$subdomain" >> "$OUTPUT_DIR/resolved-subdomains.txt"
        fi
    done < "$OUTPUT_DIR/all-subdomains.txt"
fi

#====================================================================
# HTTP PROBING
#====================================================================
echo ""
echo -e "${YELLOW}[*] Probing for HTTP/HTTPS...${NC}"

if command -v httpx &> /dev/null; then
    echo -e "${BLUE}[>] Running Httpx...${NC}"
    httpx -l "$OUTPUT_DIR/resolved-subdomains.txt" -silent -status-code -title -tech-detect \
        -o "$OUTPUT_DIR/httpx-results.txt" 2>/dev/null
    
    # Extract just live URLs
    httpx -l "$OUTPUT_DIR/resolved-subdomains.txt" -silent -o "$OUTPUT_DIR/live-hosts.txt" 2>/dev/null
    LIVE=$(wc -l < "$OUTPUT_DIR/live-hosts.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Live Hosts: $LIVE${NC}"
elif command -v httprobe &> /dev/null; then
    echo -e "${BLUE}[>] Running Httprobe...${NC}"
    cat "$OUTPUT_DIR/resolved-subdomains.txt" | httprobe > "$OUTPUT_DIR/live-hosts.txt" 2>/dev/null
    LIVE=$(wc -l < "$OUTPUT_DIR/live-hosts.txt" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Live Hosts: $LIVE${NC}"
fi

#====================================================================
# SUMMARY
#====================================================================
echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}SUBDOMAIN ENUMERATION COMPLETE${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Target Domain:     ${YELLOW}$DOMAIN${NC}"
echo -e "Total Subdomains:  ${GREEN}$TOTAL${NC}"
echo -e "Resolved:          ${GREEN}$(wc -l < "$OUTPUT_DIR/resolved-subdomains.txt" 2>/dev/null || echo 0)${NC}"
echo -e "Live Hosts:        ${GREEN}$(wc -l < "$OUTPUT_DIR/live-hosts.txt" 2>/dev/null || echo 0)${NC}"
echo ""
echo -e "Output Directory:  ${BLUE}$OUTPUT_DIR${NC}"
echo ""
echo "Key Files:"
echo "  - all-subdomains.txt     : All discovered subdomains"
echo "  - resolved-subdomains.txt: DNS-resolved subdomains"
echo "  - live-hosts.txt         : HTTP/HTTPS responsive hosts"
echo "  - httpx-results.txt      : Detailed HTTP probe results"
echo ""
