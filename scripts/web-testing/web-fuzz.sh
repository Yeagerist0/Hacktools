#!/bin/bash

#====================================================================
#  WEB FUZZING AUTOMATION SCRIPT
#====================================================================
#  Directory and file fuzzing with ffuf/gobuster
#  
#  Usage: ./web-fuzz.sh <url> [wordlist] [output_dir]
#====================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ -z "$1" ]]; then
    echo -e "${RED}Usage: $0 <url> [wordlist] [output_dir]${NC}"
    echo "Example: $0 https://example.com"
    exit 1
fi

URL="$1"
WORDLIST_DIR="$HOME/HackTools/wordlists"
WORDLIST="${2:-$WORDLIST_DIR/SecLists/Discovery/Web-Content/common.txt}"
OUTPUT_DIR="${3:-$HOME/HackTools/output/fuzzing}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Clean URL for filename
URL_CLEAN=$(echo "$URL" | sed 's|https\?://||' | sed 's/[^a-zA-Z0-9]/_/g')
OUTPUT_DIR="$OUTPUT_DIR/$URL_CLEAN-$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║               WEB FUZZING AUTOMATION                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${GREEN}[+] Target URL: ${NC}$URL"
echo -e "${GREEN}[+] Wordlist: ${NC}$WORDLIST"
echo -e "${GREEN}[+] Output: ${NC}$OUTPUT_DIR"
echo ""

# Check wordlist
if [[ ! -f "$WORDLIST" ]]; then
    echo -e "${YELLOW}[!] Wordlist not found, using fallback...${NC}"
    WORDLIST="$WORDLIST_DIR/common/directories.txt"
    if [[ ! -f "$WORDLIST" ]]; then
        echo -e "${RED}[-] No wordlist available. Run install script first.${NC}"
        exit 1
    fi
fi

#====================================================================
# DIRECTORY FUZZING
#====================================================================
dir_fuzz() {
    echo -e "${YELLOW}[*] Starting Directory Fuzzing...${NC}"
    
    if command -v ffuf &> /dev/null; then
        echo -e "${BLUE}[>] Using ffuf...${NC}"
        
        ffuf -u "${URL}/FUZZ" \
            -w "$WORDLIST" \
            -mc 200,201,202,204,301,302,307,308,401,403,405,500 \
            -fc 404 \
            -t 50 \
            -o "$OUTPUT_DIR/directories.json" \
            -of json \
            -s 2>/dev/null || true
        
        # Convert to readable format
        if [[ -f "$OUTPUT_DIR/directories.json" ]]; then
            cat "$OUTPUT_DIR/directories.json" | jq -r '.results[] | "\(.status) \(.url) [\(.length)]"' 2>/dev/null | \
                sort > "$OUTPUT_DIR/directories.txt" || true
        fi
        
    elif command -v gobuster &> /dev/null; then
        echo -e "${BLUE}[>] Using Gobuster...${NC}"
        
        gobuster dir -u "$URL" \
            -w "$WORDLIST" \
            -t 50 \
            -o "$OUTPUT_DIR/directories.txt" \
            -s "200,201,202,204,301,302,307,308,401,403,405,500" \
            --no-error 2>/dev/null || true
            
    elif command -v feroxbuster &> /dev/null; then
        echo -e "${BLUE}[>] Using Feroxbuster...${NC}"
        
        feroxbuster -u "$URL" \
            -w "$WORDLIST" \
            -t 50 \
            -o "$OUTPUT_DIR/directories.txt" \
            --no-state \
            -s 200,201,202,204,301,302,307,308,401,403,405,500 2>/dev/null || true
    else
        echo -e "${RED}[-] No fuzzing tool found!${NC}"
        return
    fi
    
    echo -e "${GREEN}[+] Directory fuzzing complete${NC}"
}

#====================================================================
# FILE EXTENSION FUZZING
#====================================================================
extension_fuzz() {
    echo -e "${YELLOW}[*] Starting Extension Fuzzing...${NC}"
    
    EXTENSIONS="php,asp,aspx,jsp,html,js,txt,xml,json,bak,old,backup,sql,log,config,env,ini,yml,yaml"
    
    if command -v ffuf &> /dev/null; then
        ffuf -u "${URL}/FUZZ" \
            -w "$WORDLIST_DIR/SecLists/Discovery/Web-Content/raft-small-words.txt:WORD" \
            -w <(echo "$EXTENSIONS" | tr ',' '\n'):EXT \
            -u "${URL}/WORD.EXT" \
            -mc 200,204,301,302,307,403 \
            -t 50 \
            -o "$OUTPUT_DIR/extensions.json" \
            -of json \
            -s 2>/dev/null || true
    fi
    
    echo -e "${GREEN}[+] Extension fuzzing complete${NC}"
}

#====================================================================
# PARAMETER FUZZING
#====================================================================
param_fuzz() {
    echo -e "${YELLOW}[*] Starting Parameter Fuzzing...${NC}"
    
    PARAM_WORDLIST="$WORDLIST_DIR/SecLists/Discovery/Web-Content/burp-parameter-names.txt"
    
    if [[ ! -f "$PARAM_WORDLIST" ]]; then
        PARAM_WORDLIST="$WORDLIST"
    fi
    
    if command -v ffuf &> /dev/null; then
        # GET parameters
        echo -e "${BLUE}[>] Fuzzing GET parameters...${NC}"
        ffuf -u "${URL}?FUZZ=test" \
            -w "$PARAM_WORDLIST" \
            -mc 200 \
            -fs 0 \
            -t 50 \
            -o "$OUTPUT_DIR/get-params.json" \
            -of json \
            -s 2>/dev/null || true
        
        # POST parameters
        echo -e "${BLUE}[>] Fuzzing POST parameters...${NC}"
        ffuf -u "$URL" \
            -X POST \
            -d "FUZZ=test" \
            -w "$PARAM_WORDLIST" \
            -mc 200 \
            -fs 0 \
            -t 50 \
            -o "$OUTPUT_DIR/post-params.json" \
            -of json \
            -s 2>/dev/null || true
    fi
    
    echo -e "${GREEN}[+] Parameter fuzzing complete${NC}"
}

#====================================================================
# VHOST FUZZING
#====================================================================
vhost_fuzz() {
    echo -e "${YELLOW}[*] Starting VHost Fuzzing...${NC}"
    
    # Extract domain from URL
    DOMAIN=$(echo "$URL" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
    
    VHOST_WORDLIST="$WORDLIST_DIR/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
    if [[ ! -f "$VHOST_WORDLIST" ]]; then
        VHOST_WORDLIST="$WORDLIST_DIR/common/subdomains-5000.txt"
    fi
    
    if command -v ffuf &> /dev/null && [[ -f "$VHOST_WORDLIST" ]]; then
        ffuf -u "$URL" \
            -H "Host: FUZZ.$DOMAIN" \
            -w "$VHOST_WORDLIST" \
            -mc 200 \
            -fs 0 \
            -t 50 \
            -o "$OUTPUT_DIR/vhosts.json" \
            -of json \
            -s 2>/dev/null || true
    fi
    
    echo -e "${GREEN}[+] VHost fuzzing complete${NC}"
}

#====================================================================
# RECURSIVE FUZZING
#====================================================================
recursive_fuzz() {
    echo -e "${YELLOW}[*] Starting Recursive Fuzzing...${NC}"
    
    if command -v feroxbuster &> /dev/null; then
        feroxbuster -u "$URL" \
            -w "$WORDLIST" \
            -t 30 \
            -d 3 \
            -o "$OUTPUT_DIR/recursive.txt" \
            --no-state \
            -s 200,201,202,204,301,302,307,308,401,403,405,500 2>/dev/null || true
    fi
    
    echo -e "${GREEN}[+] Recursive fuzzing complete${NC}"
}

#====================================================================
# MAIN MENU
#====================================================================
show_menu() {
    echo ""
    echo "Select fuzzing type:"
    echo ""
    echo "  1) Directory Fuzzing"
    echo "  2) File Extension Fuzzing"
    echo "  3) Parameter Fuzzing"
    echo "  4) Virtual Host Fuzzing"
    echo "  5) Recursive Fuzzing (deep)"
    echo "  6) All Fuzzing Types"
    echo "  7) Exit"
    echo ""
    read -p "Enter choice [1-7]: " choice
    
    case $choice in
        1) dir_fuzz ;;
        2) extension_fuzz ;;
        3) param_fuzz ;;
        4) vhost_fuzz ;;
        5) recursive_fuzz ;;
        6)
            dir_fuzz
            extension_fuzz
            param_fuzz
            vhost_fuzz
            ;;
        7) exit 0 ;;
        *) echo "Invalid choice"; show_menu ;;
    esac
}

# Check for --all flag
if [[ "$2" == "--all" || "$4" == "--all" ]]; then
    dir_fuzz
    extension_fuzz
    param_fuzz
    vhost_fuzz
else
    show_menu
fi

# Summary
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}FUZZING COMPLETE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Results saved to: $OUTPUT_DIR"
echo ""
ls -la "$OUTPUT_DIR/" 2>/dev/null
