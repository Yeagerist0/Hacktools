#!/bin/bash

#====================================================================
#  AUTOSCAN - Quick Automated Security Scanner
#  Lightweight wrapper for common scanning tasks
#====================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }

banner() {
    echo -e "${CYAN}"
    echo " ????????? ????????? ????????? ????????? ?????? ????????? ????????? ????????????"
    echo " ????????? ????????? ????????? ????????? ?????? ????????? ????????? ????????????"
    echo -e "${NC}"
    echo -e "  ${GREEN}Quick Security Scanner${NC}"
    echo ""
}

usage() {
    banner
    echo "Usage: $0 <target> [scan-type]"
    echo ""
    echo "Scan Types:"
    echo "  quick     Quick recon (subdomains + live hosts)"
    echo "  web       Web vulnerability scan"
    echo "  ports     Port scan"
    echo "  all       Full scan (default)"
    echo ""
    echo "Examples:"
    echo "  $0 example.com              # Full scan"
    echo "  $0 example.com quick        # Quick recon only"
    echo "  $0 example.com web          # Web vulns only"
    echo ""
}

quick_scan() {
    local target="$1"
    log "Quick scan: $target"
    
    # Subdomain enumeration
    if command -v subfinder &>/dev/null; then
        log "Finding subdomains..."
        subfinder -d "$target" -silent | tee "/tmp/autoscan_${target}_subs.txt"
    fi
    
    # Live host check
    if command -v httpx &>/dev/null; then
        log "Probing live hosts..."
        cat "/tmp/autoscan_${target}_subs.txt" 2>/dev/null | httpx -silent -status-code -title
    fi
}

web_scan() {
    local target="$1"
    log "Web vulnerability scan: $target"
    
    if command -v nuclei &>/dev/null; then
        log "Running Nuclei..."
        echo "https://$target" | nuclei -severity critical,high,medium -silent
    else
        warn "Nuclei not installed"
    fi
}

port_scan() {
    local target="$1"
    log "Port scan: $target"
    
    if command -v naabu &>/dev/null; then
        naabu -host "$target" -top-ports 1000 -silent
    elif command -v nmap &>/dev/null; then
        nmap -T4 --top-ports 1000 "$target"
    else
        warn "No port scanner found (naabu/nmap)"
    fi
}

full_scan() {
    local target="$1"
    log "Full scan: $target"
    "$SCRIPT_DIR/hackstrike" "$target" --full
}

# Main
TARGET="$1"
SCAN_TYPE="${2:-all}"

if [[ -z "$TARGET" ]]; then
    usage
    exit 1
fi

banner
log "Target: $TARGET"
log "Type: $SCAN_TYPE"
echo ""

case "$SCAN_TYPE" in
    quick) quick_scan "$TARGET" ;;
    web) web_scan "$TARGET" ;;
    ports) port_scan "$TARGET" ;;
    all|full) full_scan "$TARGET" ;;
    *) error "Unknown scan type: $SCAN_TYPE"; usage; exit 1 ;;
esac

log "Scan complete!"
