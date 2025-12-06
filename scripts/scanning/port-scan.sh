#!/bin/bash

#====================================================================
#  PORT SCANNING AUTOMATION SCRIPT
#====================================================================
#  Comprehensive port scanning with multiple tools
#  
#  Usage: ./port-scan.sh <target> [output_dir]
#  Target can be: IP, hostname, or file with list of targets
#====================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ -z "$1" ]]; then
    echo -e "${RED}Usage: $0 <target|target_file> [output_dir]${NC}"
    echo "Examples:"
    echo "  $0 192.168.1.1"
    echo "  $0 example.com"
    echo "  $0 targets.txt ./output"
    exit 1
fi

TARGET="$1"
OUTPUT_DIR="${2:-$HOME/HackTools/output/scans}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Determine if target is a file or single target
if [[ -f "$TARGET" ]]; then
    TARGET_FILE="$TARGET"
    TARGET_NAME="multi-target"
else
    TARGET_FILE=""
    TARGET_NAME=$(echo "$TARGET" | sed 's/[^a-zA-Z0-9]/_/g')
fi

OUTPUT_DIR="$OUTPUT_DIR/$TARGET_NAME-$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║               PORT SCANNING AUTOMATION                    ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${GREEN}[+] Target: ${NC}$TARGET"
echo -e "${GREEN}[+] Output: ${NC}$OUTPUT_DIR"
echo ""

#====================================================================
# QUICK SCAN - TOP PORTS
#====================================================================
quick_scan() {
    echo -e "${YELLOW}[*] Running Quick Scan (Top 1000 ports)...${NC}"
    
    if command -v naabu &> /dev/null; then
        echo -e "${BLUE}[>] Using Naabu...${NC}"
        if [[ -n "$TARGET_FILE" ]]; then
            naabu -list "$TARGET_FILE" -top-ports 1000 -silent -o "$OUTPUT_DIR/quick-ports.txt" 2>/dev/null || true
        else
            naabu -host "$TARGET" -top-ports 1000 -silent -o "$OUTPUT_DIR/quick-ports.txt" 2>/dev/null || true
        fi
    elif command -v rustscan &> /dev/null; then
        echo -e "${BLUE}[>] Using RustScan...${NC}"
        rustscan -a "$TARGET" --top -g 2>/dev/null | tee "$OUTPUT_DIR/quick-ports.txt" || true
    else
        echo -e "${BLUE}[>] Using Nmap...${NC}"
        if [[ -n "$TARGET_FILE" ]]; then
            nmap -iL "$TARGET_FILE" --top-ports 1000 -T4 -oG "$OUTPUT_DIR/quick-nmap.gnmap" 2>/dev/null || true
        else
            nmap "$TARGET" --top-ports 1000 -T4 -oG "$OUTPUT_DIR/quick-nmap.gnmap" 2>/dev/null || true
        fi
        grep "open" "$OUTPUT_DIR/quick-nmap.gnmap" 2>/dev/null > "$OUTPUT_DIR/quick-ports.txt" || true
    fi
    
    echo -e "${GREEN}[+] Quick scan complete${NC}"
}

#====================================================================
# FULL PORT SCAN
#====================================================================
full_scan() {
    echo -e "${YELLOW}[*] Running Full Port Scan (All 65535 ports)...${NC}"
    
    if command -v rustscan &> /dev/null; then
        echo -e "${BLUE}[>] Using RustScan for speed...${NC}"
        rustscan -a "$TARGET" -r 1-65535 --ulimit 5000 -g 2>/dev/null | \
            tee "$OUTPUT_DIR/all-ports.txt" || true
    elif command -v masscan &> /dev/null; then
        echo -e "${BLUE}[>] Using Masscan...${NC}"
        sudo masscan "$TARGET" -p1-65535 --rate=1000 -oL "$OUTPUT_DIR/masscan.txt" 2>/dev/null || true
        grep "open" "$OUTPUT_DIR/masscan.txt" 2>/dev/null > "$OUTPUT_DIR/all-ports.txt" || true
    else
        echo -e "${BLUE}[>] Using Nmap (this will take a while)...${NC}"
        nmap "$TARGET" -p- -T4 --min-rate=1000 -oG "$OUTPUT_DIR/full-nmap.gnmap" 2>/dev/null || true
        grep "open" "$OUTPUT_DIR/full-nmap.gnmap" 2>/dev/null > "$OUTPUT_DIR/all-ports.txt" || true
    fi
    
    echo -e "${GREEN}[+] Full scan complete${NC}"
}

#====================================================================
# SERVICE DETECTION
#====================================================================
service_scan() {
    echo -e "${YELLOW}[*] Running Service Detection...${NC}"
    
    # Extract ports from previous scans
    PORTS=""
    if [[ -f "$OUTPUT_DIR/quick-ports.txt" ]]; then
        PORTS=$(grep -oE '[0-9]+/open' "$OUTPUT_DIR/quick-ports.txt" 2>/dev/null | cut -d'/' -f1 | sort -u | tr '\n' ',' | sed 's/,$//')
    fi
    
    if [[ -z "$PORTS" && -f "$OUTPUT_DIR/all-ports.txt" ]]; then
        PORTS=$(grep -oE '[0-9]+/open' "$OUTPUT_DIR/all-ports.txt" 2>/dev/null | cut -d'/' -f1 | sort -u | tr '\n' ',' | sed 's/,$//')
    fi
    
    if [[ -z "$PORTS" ]]; then
        PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443"
    fi
    
    echo -e "${BLUE}[>] Scanning ports: $PORTS${NC}"
    
    nmap "$TARGET" -p "$PORTS" -sV -sC -O --script=banner \
        -oN "$OUTPUT_DIR/service-scan.txt" \
        -oX "$OUTPUT_DIR/service-scan.xml" 2>/dev/null || true
    
    echo -e "${GREEN}[+] Service detection complete${NC}"
}

#====================================================================
# VULNERABILITY SCAN
#====================================================================
vuln_scan() {
    echo -e "${YELLOW}[*] Running Vulnerability Scan...${NC}"
    
    # Extract ports
    PORTS=""
    if [[ -f "$OUTPUT_DIR/quick-ports.txt" ]]; then
        PORTS=$(grep -oE '[0-9]+/open' "$OUTPUT_DIR/quick-ports.txt" 2>/dev/null | cut -d'/' -f1 | sort -u | tr '\n' ',' | sed 's/,$//')
    fi
    
    if [[ -n "$PORTS" ]]; then
        echo -e "${BLUE}[>] Running Nmap vulnerability scripts...${NC}"
        nmap "$TARGET" -p "$PORTS" --script=vuln \
            -oN "$OUTPUT_DIR/vuln-scan.txt" 2>/dev/null || true
    fi
    
    # Nuclei network scan
    if command -v nuclei &> /dev/null; then
        echo -e "${BLUE}[>] Running Nuclei network templates...${NC}"
        echo "$TARGET" | nuclei -t network/ -severity critical,high,medium \
            -o "$OUTPUT_DIR/nuclei-network.txt" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}[+] Vulnerability scan complete${NC}"
}

#====================================================================
# UDP SCAN
#====================================================================
udp_scan() {
    echo -e "${YELLOW}[*] Running UDP Scan (Top 100 ports)...${NC}"
    
    sudo nmap "$TARGET" -sU --top-ports 100 -T4 \
        -oN "$OUTPUT_DIR/udp-scan.txt" 2>/dev/null || true
    
    echo -e "${GREEN}[+] UDP scan complete${NC}"
}

#====================================================================
# GENERATE REPORT
#====================================================================
generate_report() {
    echo -e "${YELLOW}[*] Generating Report...${NC}"
    
    cat > "$OUTPUT_DIR/REPORT.md" << EOF
# Port Scan Report

**Target:** $TARGET
**Date:** $(date '+%Y-%m-%d %H:%M:%S')

## Open Ports Summary

\`\`\`
$(cat "$OUTPUT_DIR/quick-ports.txt" 2>/dev/null || echo "No results")
\`\`\`

## Service Detection

\`\`\`
$(cat "$OUTPUT_DIR/service-scan.txt" 2>/dev/null || echo "No results")
\`\`\`

## Vulnerability Findings

\`\`\`
$(cat "$OUTPUT_DIR/vuln-scan.txt" 2>/dev/null | grep -A5 "VULNERABLE" || echo "No critical vulnerabilities detected")
\`\`\`

## Files Generated

- quick-ports.txt - Quick scan results
- all-ports.txt - Full port scan results
- service-scan.txt - Service detection results
- service-scan.xml - XML format for tools
- vuln-scan.txt - Vulnerability scan results
- udp-scan.txt - UDP scan results

EOF

    echo -e "${GREEN}[+] Report generated: $OUTPUT_DIR/REPORT.md${NC}"
}

#====================================================================
# MAIN MENU
#====================================================================
show_menu() {
    echo ""
    echo "Select scan type:"
    echo ""
    echo "  1) Quick Scan (Top 1000 ports)"
    echo "  2) Full Scan (All 65535 ports)"
    echo "  3) Service Detection"
    echo "  4) Vulnerability Scan"
    echo "  5) UDP Scan"
    echo "  6) Complete Scan (All of the above)"
    echo "  7) Exit"
    echo ""
    read -p "Enter choice [1-7]: " choice
    
    case $choice in
        1) quick_scan ;;
        2) full_scan ;;
        3) quick_scan; service_scan ;;
        4) quick_scan; vuln_scan ;;
        5) udp_scan ;;
        6)
            quick_scan
            full_scan
            service_scan
            vuln_scan
            udp_scan
            generate_report
            ;;
        7) exit 0 ;;
        *) echo "Invalid choice"; show_menu ;;
    esac
}

# Run with argument or show menu
if [[ "$2" == "--full" ]]; then
    quick_scan
    full_scan
    service_scan
    vuln_scan
    udp_scan
    generate_report
elif [[ "$2" == "--quick" ]]; then
    quick_scan
    service_scan
    generate_report
else
    show_menu
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}SCAN COMPLETE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "Output Directory: ${BLUE}$OUTPUT_DIR${NC}"
echo ""
