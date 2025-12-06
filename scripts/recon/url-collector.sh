#!/bin/bash

#====================================================================
#  URL & ENDPOINT COLLECTION SCRIPT
#====================================================================
#  Collects URLs from multiple sources for a target domain
#  
#  Usage: ./url-collector.sh <domain> [output_dir]
#====================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ -z "$1" ]]; then
    echo -e "${RED}Usage: $0 <domain> [output_dir]${NC}"
    exit 1
fi

DOMAIN="$1"
OUTPUT_DIR="${2:-$HOME/HackTools/output/$DOMAIN/urls}"
mkdir -p "$OUTPUT_DIR"

echo -e "${CYAN}[*] Collecting URLs for: $DOMAIN${NC}"
echo ""

# Waybackurls
if command -v waybackurls &> /dev/null; then
    echo -e "${BLUE}[>] Waybackurls...${NC}"
    echo "$DOMAIN" | waybackurls > "$OUTPUT_DIR/wayback.txt" 2>/dev/null || true
    echo -e "${GREEN}[+] $(wc -l < "$OUTPUT_DIR/wayback.txt" 2>/dev/null || echo 0) URLs${NC}"
fi

# Gau
if command -v gau &> /dev/null; then
    echo -e "${BLUE}[>] Gau...${NC}"
    echo "$DOMAIN" | gau --threads 5 > "$OUTPUT_DIR/gau.txt" 2>/dev/null || true
    echo -e "${GREEN}[+] $(wc -l < "$OUTPUT_DIR/gau.txt" 2>/dev/null || echo 0) URLs${NC}"
fi

# Hakrawler (if live hosts exist)
if command -v hakrawler &> /dev/null; then
    echo -e "${BLUE}[>] Hakrawler...${NC}"
    echo "https://$DOMAIN" | hakrawler -d 3 > "$OUTPUT_DIR/hakrawler.txt" 2>/dev/null || true
    echo -e "${GREEN}[+] $(wc -l < "$OUTPUT_DIR/hakrawler.txt" 2>/dev/null || echo 0) URLs${NC}"
fi

# Common Crawl
echo -e "${BLUE}[>] Common Crawl...${NC}"
curl -s "http://index.commoncrawl.org/CC-MAIN-2023-50-index?url=*.$DOMAIN&output=json" 2>/dev/null | \
    jq -r '.url' 2>/dev/null | sort -u > "$OUTPUT_DIR/commoncrawl.txt" || true
echo -e "${GREEN}[+] $(wc -l < "$OUTPUT_DIR/commoncrawl.txt" 2>/dev/null || echo 0) URLs${NC}"

# AlienVault OTX
echo -e "${BLUE}[>] AlienVault OTX...${NC}"
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$DOMAIN/url_list?limit=500" 2>/dev/null | \
    jq -r '.url_list[].url' 2>/dev/null | sort -u > "$OUTPUT_DIR/otx.txt" || true
echo -e "${GREEN}[+] $(wc -l < "$OUTPUT_DIR/otx.txt" 2>/dev/null || echo 0) URLs${NC}"

# Combine all
echo ""
echo -e "${YELLOW}[*] Combining results...${NC}"
cat "$OUTPUT_DIR"/*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/all-urls.txt"

# Categorize URLs
echo -e "${YELLOW}[*] Categorizing URLs...${NC}"

# URLs with parameters
grep "=" "$OUTPUT_DIR/all-urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/params.txt" || true

# JavaScript files
grep -iE "\.js(\?|$)" "$OUTPUT_DIR/all-urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/js-files.txt" || true

# JSON endpoints
grep -iE "\.json(\?|$)" "$OUTPUT_DIR/all-urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/json-endpoints.txt" || true

# PHP files
grep -iE "\.php(\?|$)" "$OUTPUT_DIR/all-urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/php-files.txt" || true

# API endpoints
grep -iE "/api/|/v[0-9]/|/graphql" "$OUTPUT_DIR/all-urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/api-endpoints.txt" || true

# Potential sensitive files
grep -iE "\.(bak|old|backup|sql|config|env|log|txt)(\?|$)" "$OUTPUT_DIR/all-urls.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/sensitive-files.txt" || true

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}URL COLLECTION COMPLETE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Total URLs:      ${CYAN}$(wc -l < "$OUTPUT_DIR/all-urls.txt" 2>/dev/null || echo 0)${NC}"
echo -e "With Parameters: ${CYAN}$(wc -l < "$OUTPUT_DIR/params.txt" 2>/dev/null || echo 0)${NC}"
echo -e "JS Files:        ${CYAN}$(wc -l < "$OUTPUT_DIR/js-files.txt" 2>/dev/null || echo 0)${NC}"
echo -e "API Endpoints:   ${CYAN}$(wc -l < "$OUTPUT_DIR/api-endpoints.txt" 2>/dev/null || echo 0)${NC}"
echo -e "Sensitive Files: ${CYAN}$(wc -l < "$OUTPUT_DIR/sensitive-files.txt" 2>/dev/null || echo 0)${NC}"
echo ""
echo -e "Output: ${BLUE}$OUTPUT_DIR${NC}"
