#!/bin/bash

#====================================================================
#  NUCLEI VULNERABILITY SCANNER WRAPPER
#====================================================================
#  Automated vulnerability scanning with Nuclei templates
#  
#  Usage: ./nuclei-scan.sh <target|target_file> [scan_type]
#  Scan types: quick, full, cve, misconfig, exposure, custom
#====================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ -z "$1" ]]; then
    echo -e "${RED}Usage: $0 <target|target_file> [scan_type]${NC}"
    echo ""
    echo "Scan types:"
    echo "  quick     - Critical and High severity only"
    echo "  full      - All severities"
    echo "  cve       - CVE templates only"
    echo "  misconfig - Misconfiguration templates"
    echo "  exposure  - Exposed panels, files, etc."
    echo "  takeover  - Subdomain takeover checks"
    echo "  tech      - Technology detection"
    echo "  custom    - Use custom template path"
    exit 1
fi

TARGET="$1"
SCAN_TYPE="${2:-quick}"
OUTPUT_DIR="$HOME/HackTools/output/nuclei-scans"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

# Determine target type
if [[ -f "$TARGET" ]]; then
    TARGET_FLAG="-l $TARGET"
    TARGET_NAME="multi-target"
else
    TARGET_FLAG="-u $TARGET"
    TARGET_NAME=$(echo "$TARGET" | sed 's|https\?://||' | sed 's/[^a-zA-Z0-9]/_/g')
fi

OUTPUT_FILE="$OUTPUT_DIR/${TARGET_NAME}-${SCAN_TYPE}-${TIMESTAMP}.txt"

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              NUCLEI VULNERABILITY SCANNER                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${GREEN}[+] Target: ${NC}$TARGET"
echo -e "${GREEN}[+] Scan Type: ${NC}$SCAN_TYPE"
echo -e "${GREEN}[+] Output: ${NC}$OUTPUT_FILE"
echo ""

# Check if nuclei is installed
if ! command -v nuclei &> /dev/null; then
    echo -e "${RED}[-] Nuclei is not installed!${NC}"
    echo "Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    exit 1
fi

# Update templates if needed
echo -e "${YELLOW}[*] Checking for template updates...${NC}"
nuclei -update-templates -silent 2>/dev/null || true

run_scan() {
    local flags="$1"
    local description="$2"
    
    echo -e "${BLUE}[>] Running: $description${NC}"
    
    nuclei $TARGET_FLAG $flags \
        -o "$OUTPUT_FILE" \
        -stats \
        -silent 2>/dev/null || true
}

case $SCAN_TYPE in
    quick)
        run_scan "-severity critical,high" "Quick scan (Critical & High)"
        ;;
    full)
        run_scan "-severity critical,high,medium,low,info" "Full scan (All severities)"
        ;;
    cve)
        run_scan "-t cves/ -severity critical,high,medium" "CVE scan"
        ;;
    misconfig)
        run_scan "-t misconfiguration/ -t misconfigurations/" "Misconfiguration scan"
        ;;
    exposure)
        run_scan "-t exposures/ -t exposed-panels/" "Exposure scan"
        ;;
    takeover)
        run_scan "-t takeovers/" "Subdomain takeover scan"
        ;;
    tech)
        run_scan "-t technologies/" "Technology detection"
        ;;
    custom)
        read -p "Enter template path: " TEMPLATE_PATH
        run_scan "-t $TEMPLATE_PATH" "Custom template scan"
        ;;
    *)
        echo -e "${RED}[-] Invalid scan type: $SCAN_TYPE${NC}"
        exit 1
        ;;
esac

# Summary
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}SCAN COMPLETE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""

if [[ -f "$OUTPUT_FILE" ]]; then
    FINDINGS=$(wc -l < "$OUTPUT_FILE")
    echo -e "Total Findings: ${CYAN}$FINDINGS${NC}"
    
    # Count by severity
    CRITICAL=$(grep -c "\[critical\]" "$OUTPUT_FILE" 2>/dev/null || echo 0)
    HIGH=$(grep -c "\[high\]" "$OUTPUT_FILE" 2>/dev/null || echo 0)
    MEDIUM=$(grep -c "\[medium\]" "$OUTPUT_FILE" 2>/dev/null || echo 0)
    LOW=$(grep -c "\[low\]" "$OUTPUT_FILE" 2>/dev/null || echo 0)
    INFO=$(grep -c "\[info\]" "$OUTPUT_FILE" 2>/dev/null || echo 0)
    
    echo ""
    echo -e "Severity Breakdown:"
    echo -e "  ${RED}Critical: $CRITICAL${NC}"
    echo -e "  ${YELLOW}High: $HIGH${NC}"
    echo -e "  ${BLUE}Medium: $MEDIUM${NC}"
    echo -e "  ${GREEN}Low: $LOW${NC}"
    echo -e "  Info: $INFO"
    
    if [[ $CRITICAL -gt 0 || $HIGH -gt 0 ]]; then
        echo ""
        echo -e "${RED}[!] Critical/High findings detected! Review immediately:${NC}"
        grep -E "\[critical\]|\[high\]" "$OUTPUT_FILE" 2>/dev/null | head -10
    fi
else
    echo -e "${YELLOW}No findings detected${NC}"
fi

echo ""
echo -e "Output: ${BLUE}$OUTPUT_FILE${NC}"
