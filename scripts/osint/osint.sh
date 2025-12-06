#!/bin/bash

#====================================================================
#  OSINT AUTOMATION SCRIPT
#====================================================================
#  Open Source Intelligence gathering for a target
#  
#  Usage: ./osint.sh <target_domain_or_name>
#====================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ -z "$1" ]]; then
    echo -e "${RED}Usage: $0 <domain|company|person>${NC}"
    exit 1
fi

TARGET="$1"
OUTPUT_DIR="$HOME/HackTools/output/osint-$TARGET"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║               OSINT AUTOMATION                            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${GREEN}[+] Target: ${NC}$TARGET"
echo -e "${GREEN}[+] Output: ${NC}$OUTPUT_DIR"
echo ""

#====================================================================
# DOMAIN OSINT
#====================================================================
domain_osint() {
    echo -e "${YELLOW}[*] Running Domain OSINT...${NC}"
    
    # WHOIS
    echo -e "${BLUE}[>] WHOIS lookup...${NC}"
    whois "$TARGET" > "$OUTPUT_DIR/whois.txt" 2>/dev/null || true
    
    # DNS Records
    echo -e "${BLUE}[>] DNS records...${NC}"
    {
        echo "=== A Records ==="
        dig +short "$TARGET" A
        echo ""
        echo "=== AAAA Records ==="
        dig +short "$TARGET" AAAA
        echo ""
        echo "=== MX Records ==="
        dig +short "$TARGET" MX
        echo ""
        echo "=== TXT Records ==="
        dig +short "$TARGET" TXT
        echo ""
        echo "=== NS Records ==="
        dig +short "$TARGET" NS
        echo ""
        echo "=== SOA Records ==="
        dig +short "$TARGET" SOA
    } > "$OUTPUT_DIR/dns-records.txt" 2>/dev/null
    
    # Certificate Transparency
    echo -e "${BLUE}[>] Certificate transparency...${NC}"
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | \
        sort -u > "$OUTPUT_DIR/crtsh.txt" || true
    
    echo -e "${GREEN}[+] Domain OSINT complete${NC}"
}

#====================================================================
# EMAIL HARVESTING
#====================================================================
email_harvest() {
    echo -e "${YELLOW}[*] Harvesting Emails...${NC}"
    
    # theHarvester
    if command -v theHarvester &> /dev/null; then
        echo -e "${BLUE}[>] Running theHarvester...${NC}"
        theHarvester -d "$TARGET" -b all -f "$OUTPUT_DIR/theharvester" 2>/dev/null || true
    fi
    
    # Hunter.io (requires API key)
    # curl -s "https://api.hunter.io/v2/domain-search?domain=$TARGET&api_key=YOUR_KEY"
    
    echo -e "${GREEN}[+] Email harvesting complete${NC}"
}

#====================================================================
# SOCIAL MEDIA
#====================================================================
social_media() {
    echo -e "${YELLOW}[*] Social Media Enumeration...${NC}"
    
    # Sherlock - Username search
    if command -v sherlock &> /dev/null; then
        echo -e "${BLUE}[>] Running Sherlock...${NC}"
        sherlock "$TARGET" --output "$OUTPUT_DIR/sherlock.txt" 2>/dev/null || true
    fi
    
    # Check common platforms manually
    echo -e "${BLUE}[>] Checking common platforms...${NC}"
    {
        echo "=== Social Media Links to Check ==="
        echo "Twitter: https://twitter.com/$TARGET"
        echo "GitHub: https://github.com/$TARGET"
        echo "LinkedIn: https://linkedin.com/company/$TARGET"
        echo "Facebook: https://facebook.com/$TARGET"
        echo "Instagram: https://instagram.com/$TARGET"
        echo "YouTube: https://youtube.com/@$TARGET"
    } > "$OUTPUT_DIR/social-media-links.txt"
    
    echo -e "${GREEN}[+] Social media enumeration complete${NC}"
}

#====================================================================
# TECHNOLOGY DETECTION
#====================================================================
tech_detection() {
    echo -e "${YELLOW}[*] Technology Detection...${NC}"
    
    # Check if it's a domain
    if [[ "$TARGET" == *"."* ]]; then
        # HTTP headers
        echo -e "${BLUE}[>] Checking HTTP headers...${NC}"
        curl -sI "https://$TARGET" > "$OUTPUT_DIR/http-headers.txt" 2>/dev/null || \
        curl -sI "http://$TARGET" >> "$OUTPUT_DIR/http-headers.txt" 2>/dev/null || true
        
        # Wappalyzer (if installed)
        if command -v wappalyzer &> /dev/null; then
            wappalyzer "https://$TARGET" > "$OUTPUT_DIR/wappalyzer.json" 2>/dev/null || true
        fi
        
        # WhatWeb
        if command -v whatweb &> /dev/null; then
            whatweb "$TARGET" > "$OUTPUT_DIR/whatweb.txt" 2>/dev/null || true
        fi
    fi
    
    echo -e "${GREEN}[+] Technology detection complete${NC}"
}

#====================================================================
# BREACH DATA CHECK
#====================================================================
breach_check() {
    echo -e "${YELLOW}[*] Checking Breach Databases...${NC}"
    
    echo -e "${BLUE}[>] Manual checks required for:${NC}"
    {
        echo "=== Breach Database Links ==="
        echo "HaveIBeenPwned: https://haveibeenpwned.com/DomainSearch"
        echo "DeHashed: https://dehashed.com/"
        echo "LeakCheck: https://leakcheck.io/"
        echo "IntelligenceX: https://intelx.io/"
    } > "$OUTPUT_DIR/breach-check-links.txt"
    
    cat "$OUTPUT_DIR/breach-check-links.txt"
    
    echo -e "${GREEN}[+] Breach check links generated${NC}"
}

#====================================================================
# GOOGLE DORKS
#====================================================================
google_dorks() {
    echo -e "${YELLOW}[*] Generating Google Dorks...${NC}"
    
    cat > "$OUTPUT_DIR/google-dorks.txt" << EOF
=== Google Dorks for $TARGET ===

# Subdomains and related sites
site:$TARGET
site:*.$TARGET

# Sensitive files
site:$TARGET filetype:pdf
site:$TARGET filetype:doc
site:$TARGET filetype:xls
site:$TARGET filetype:sql
site:$TARGET filetype:log
site:$TARGET filetype:bak
site:$TARGET filetype:config
site:$TARGET filetype:env
site:$TARGET filetype:yml

# Login and admin pages
site:$TARGET inurl:login
site:$TARGET inurl:admin
site:$TARGET inurl:dashboard
site:$TARGET intitle:"login"
site:$TARGET intitle:"admin"

# Sensitive information
site:$TARGET intext:"password"
site:$TARGET intext:"username"
site:$TARGET intext:"api_key"
site:$TARGET intext:"secret"

# Error messages
site:$TARGET intext:"error"
site:$TARGET intext:"exception"
site:$TARGET intext:"warning"
site:$TARGET intext:"stack trace"

# Directory listings
site:$TARGET intitle:"index of"
site:$TARGET intitle:"directory listing"

# Exposed databases
site:$TARGET inurl:phpmyadmin
site:$TARGET inurl:adminer
site:$TARGET intext:"phpMyAdmin"

# GitHub exposure
site:github.com "$TARGET"
site:github.com "$TARGET" password
site:github.com "$TARGET" api_key
site:github.com "$TARGET" secret

# Pastebin exposure
site:pastebin.com "$TARGET"

# Cloud storage
site:s3.amazonaws.com "$TARGET"
site:blob.core.windows.net "$TARGET"
site:storage.googleapis.com "$TARGET"
EOF

    echo -e "${GREEN}[+] Google dorks saved to: $OUTPUT_DIR/google-dorks.txt${NC}"
}

#====================================================================
# MAIN
#====================================================================

# Run all OSINT modules
domain_osint
email_harvest
social_media
tech_detection
breach_check
google_dorks

# Generate summary
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}OSINT COMPLETE${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Results saved to: $OUTPUT_DIR"
echo ""
echo "Files generated:"
ls -la "$OUTPUT_DIR/"
echo ""
