#!/bin/bash

#====================================================================
#  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
#  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
#  ███████║███████║██║     █████╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
#  ██╔══██║██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
#  ██║  ██║██║  ██║╚██████╗██║  ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
#  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
#                        
#  🤖 AI-Powered Bug Bounty Assistant v1.0
#  Interactive natural language security scanner
#====================================================================

set -o pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m'
BOLD='\033[1m'

# Config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
THREADS=50
RATE_LIMIT=150
CURRENT_TARGET=""
OUTPUT_DIR=""
HISTORY_FILE="$SCRIPT_DIR/.hackstrike_history"
NUCLEI_TEMPLATES="$HOME/nuclei-templates"

# Initialize
mkdir -p "$RESULTS_DIR"
touch "$HISTORY_FILE"

#====================================================================
# UI FUNCTIONS
#====================================================================

banner() {
    clear
    echo -e "${RED}"
    cat << "EOF"
    ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
    ███████║███████║██║     █████╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
    ██╔══██║██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
    ██║  ██║██║  ██║╚██████╗██║  ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}    ═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}              🤖 AI-Powered Bug Bounty Assistant ${YELLOW}v1.0${NC}"
    echo -e "${CYAN}    ═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

ai_think() {
    local msg="$1"
    echo -ne "${PURPLE}🤖 "
    for ((i=0; i<${#msg}; i++)); do
        echo -n "${msg:$i:1}"
        sleep 0.02
    done
    echo -e "${NC}"
}

ai_say() {
    echo -e "${CYAN}🤖 $1${NC}"
}

ai_action() {
    echo -e "${GREEN}⚡ $1${NC}"
}

ai_warn() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

ai_error() {
    echo -e "${RED}❌ $1${NC}"
}

ai_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

ai_finding() {
    echo -e "${RED}🔥 FINDING: $1${NC}"
}

ai_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

show_prompt() {
    if [[ -n "$CURRENT_TARGET" ]]; then
        echo -ne "${GREEN}[$CURRENT_TARGET]${NC} ${PURPLE}hackstrike>${NC} "
    else
        echo -ne "${PURPLE}hackstrike>${NC} "
    fi
}

spinner() {
    local pid=$1
    local msg=$2
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 $pid 2>/dev/null; do
        printf "\r${CYAN}[${spin:$((i++%10)):1}]${NC} $msg"
        sleep 0.1
    done
    printf "\r"
}

#====================================================================
# NATURAL LANGUAGE PARSER
#====================================================================

parse_intent() {
    local input="$1"
    local input_lower=$(echo "$input" | tr '[:upper:]' '[:lower:]')
    
    # Check if input contains a target (for determining SET_TARGET vs action)
    local has_target=false
    if [[ "$input" =~ (https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,} ]] || \
       [[ "$input" =~ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        has_target=true
    fi
    
    # Determine intent - check for action keywords FIRST before simple target setting
    case "$input_lower" in
        # Help commands
        *help*|*"what can"*|*commands*|*"how to"*)
            echo "HELP"
            ;;
        
        # Full scan - check this BEFORE simple scan/target setting
        *"full scan"*|*"complete scan"*|*"scan everything"*|*"find all"*|*"all vulnerabilities"*|*"full pentest"*|*"full assessment"*|*"find vulnerabilit"*)
            echo "FULL_SCAN"
            ;;
        
        # Subdomain enumeration
        *subdomain*|*"find domain"*|*"enum domain"*|*"discover domain"*)
            echo "SUBDOMAINS"
            ;;
        
        # Recon
        *recon*|*reconnaissance*|*"gather info"*|*"information gathering"*|*footprint*)
            echo "RECON"
            ;;
        
        # Port scanning
        *port*|*"open port"*|*"scan port"*|*service*|*nmap*)
            echo "PORTS"
            ;;
        
        # Vulnerability scanning
        *vuln*|*"security scan"*|*"find bug"*|*"find vuln"*|*nuclei*|*"security issue"*|*cve*)
            echo "VULNS"
            ;;
        
        # XSS
        *xss*|*"cross site"*|*"script injection"*|*"javascript injection"*)
            echo "XSS"
            ;;
        
        # SQL Injection
        *sql*|*sqli*|*"database injection"*|*"sql injection"*)
            echo "SQLI"
            ;;
        
        # SSRF
        *ssrf*|*"server side request"*)
            echo "SSRF"
            ;;
        
        # LFI/RFI
        *lfi*|*rfi*|*"file inclusion"*|*"local file"*|*"path traversal"*)
            echo "LFI"
            ;;
        
        # Directory fuzzing
        *fuzz*|*directory*|*"hidden file"*|*"hidden folder"*|*brute*|*wordlist*)
            echo "FUZZ"
            ;;
        
        # CORS
        *cors*|*"cross origin"*)
            echo "CORS"
            ;;
        
        # Secrets
        *secret*|*"api key"*|*"exposed key"*|*credential*|*password*|*token*|*"sensitive data"*)
            echo "SECRETS"
            ;;
        
        # Takeover
        *takeover*|*"subdomain takeover"*|*dangling*)
            echo "TAKEOVER"
            ;;
        
        # Tech stack
        *tech*|*stack*|*framework*|*cms*|*wordpress*|*"what is running"*)
            echo "TECH"
            ;;
        
        # WAF
        *waf*|*firewall*|*"web application firewall"*|*cloudflare*|*akamai*)
            echo "WAF"
            ;;
        
        # URLs
        *url*|*endpoint*|*crawl*|*spider*|*wayback*)
            echo "URLS"
            ;;
        
        # Parameters
        *param*|*"hidden param"*|*arjun*)
            echo "PARAMS"
            ;;
        
        # Report
        *report*|*summary*|*result*|*finding*)
            echo "REPORT"
            ;;
        
        # Status
        *status*|*"current target"*|*"what target"*)
            echo "STATUS"
            ;;
        
        # Clear
        *clear*|*cls*)
            echo "CLEAR"
            ;;
        
        # Exit
        *exit*|*quit*|*bye*|*"see you"*)
            echo "EXIT"
            ;;
        
        # Simple scan/target commands (must be after specific scans)
        *"scan "*|*"attack "*|*"hack "*|*"test "*|*"check "*|*"analyze "*|*"pentest "*|*"target "*|*"set target"*)
            if [[ "$has_target" == true ]]; then
                echo "SET_TARGET"
            else
                echo "NEED_TARGET"
            fi
            ;;
        
        # Default - try to understand
        *)
            if [[ "$has_target" == true ]]; then
                echo "SET_TARGET"
            else
                echo "UNKNOWN"
            fi
            ;;
    esac
}

#====================================================================
# SETUP FUNCTIONS
#====================================================================

setup_output_dir() {
    if [[ -n "$CURRENT_TARGET" ]]; then
        OUTPUT_DIR="$RESULTS_DIR/${CURRENT_TARGET}_${TIMESTAMP}"
        mkdir -p "$OUTPUT_DIR"/{recon,subdomains,urls,ports,vulns,web,exploits,secrets,params,reports}
    fi
}

check_target() {
    if [[ -z "$CURRENT_TARGET" ]]; then
        ai_warn "No target set. Tell me what to scan!"
        ai_say "Example: 'scan example.com' or 'test hackerone.com for vulnerabilities'"
        return 1
    fi
    return 0
}

#====================================================================
# SCANNING FUNCTIONS
#====================================================================

do_subdomains() {
    check_target || return
    
    ai_think "Hunting for subdomains of $CURRENT_TARGET..."
    echo ""
    
    local count=0
    
    # Subfinder
    if command -v subfinder &> /dev/null; then
        ai_action "Running Subfinder..."
        subfinder -d "$CURRENT_TARGET" -all -silent -t $THREADS \
            -o "$OUTPUT_DIR/subdomains/subfinder.txt" 2>/dev/null
        count=$((count + $(wc -l < "$OUTPUT_DIR/subdomains/subfinder.txt" 2>/dev/null || echo 0)))
    fi
    
    # Amass
    if command -v amass &> /dev/null; then
        ai_action "Running Amass (passive mode)..."
        timeout 300 amass enum -passive -d "$CURRENT_TARGET" \
            -o "$OUTPUT_DIR/subdomains/amass.txt" 2>/dev/null
    fi
    
    # Assetfinder
    if command -v assetfinder &> /dev/null; then
        ai_action "Running Assetfinder..."
        assetfinder --subs-only "$CURRENT_TARGET" \
            > "$OUTPUT_DIR/subdomains/assetfinder.txt" 2>/dev/null
    fi
    
    # Merge results
    cat "$OUTPUT_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains/all.txt"
    local total=$(wc -l < "$OUTPUT_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
    
    echo ""
    ai_success "Found $total unique subdomains!"
    
    if [[ $total -gt 0 ]]; then
        ai_say "Here are some interesting ones:"
        echo ""
        # Show interesting subdomains
        grep -iE '(admin|dev|test|staging|api|internal|vpn|mail|ftp|db|jenkins|git|jira|confluence)' \
            "$OUTPUT_DIR/subdomains/all.txt" 2>/dev/null | head -15 | while read sub; do
            echo -e "  ${YELLOW}→${NC} $sub"
        done
        echo ""
        ai_info "Full list saved to: $OUTPUT_DIR/subdomains/all.txt"
    fi
}

do_recon() {
    check_target || return
    
    ai_think "Starting reconnaissance on $CURRENT_TARGET..."
    echo ""
    
    # Subdomains first
    do_subdomains
    
    # Live host detection
    ai_action "Probing for live hosts..."
    if [[ -s "$OUTPUT_DIR/subdomains/all.txt" ]]; then
        httpx -l "$OUTPUT_DIR/subdomains/all.txt" -silent -t $THREADS \
            -status-code -title -tech-detect -follow-redirects \
            -o "$OUTPUT_DIR/recon/live_hosts.txt" 2>/dev/null
        
        cat "$OUTPUT_DIR/recon/live_hosts.txt" 2>/dev/null | awk '{print $1}' \
            > "$OUTPUT_DIR/recon/live_urls.txt"
        
        local live=$(wc -l < "$OUTPUT_DIR/recon/live_urls.txt" 2>/dev/null || echo 0)
        ai_success "Found $live live hosts!"
    fi
    
    # Technology detection
    ai_action "Detecting technologies..."
    if command -v whatweb &> /dev/null && [[ -s "$OUTPUT_DIR/recon/live_urls.txt" ]]; then
        head -20 "$OUTPUT_DIR/recon/live_urls.txt" | while read url; do
            whatweb "$url" --no-errors -q 2>/dev/null
        done | tee "$OUTPUT_DIR/recon/technologies.txt"
    fi
    
    echo ""
    ai_success "Reconnaissance complete!"
    ai_info "Results saved to: $OUTPUT_DIR/recon/"
}

do_ports() {
    check_target || return
    
    ai_think "Scanning ports on $CURRENT_TARGET..."
    echo ""
    
    # Quick naabu scan
    if command -v naabu &> /dev/null; then
        ai_action "Fast port scan with Naabu..."
        naabu -host "$CURRENT_TARGET" -top-ports 1000 -silent \
            -o "$OUTPUT_DIR/ports/naabu.txt" 2>/dev/null
        
        local ports=$(wc -l < "$OUTPUT_DIR/ports/naabu.txt" 2>/dev/null || echo 0)
        ai_success "Found $ports open ports!"
        
        if [[ -s "$OUTPUT_DIR/ports/naabu.txt" ]]; then
            echo ""
            ai_say "Open ports:"
            cat "$OUTPUT_DIR/ports/naabu.txt" | while read line; do
                echo -e "  ${GREEN}→${NC} $line"
            done
        fi
    fi
    
    # Nmap for service detection
    ai_action "Running Nmap for service detection..."
    nmap -sV -T4 --top-ports 100 "$CURRENT_TARGET" \
        -oN "$OUTPUT_DIR/ports/nmap.txt" 2>/dev/null | \
        grep -E '^[0-9]+/' | while read line; do
        echo -e "  ${CYAN}→${NC} $line"
    done
    
    echo ""
    ai_success "Port scan complete!"
    ai_info "Results saved to: $OUTPUT_DIR/ports/"
}

do_vulns() {
    check_target || return
    
    ai_think "Scanning for vulnerabilities on $CURRENT_TARGET..."
    echo ""
    
    # Ensure we have live hosts
    if [[ ! -s "$OUTPUT_DIR/recon/live_urls.txt" ]]; then
        ai_action "First, let me find live hosts..."
        echo "https://$CURRENT_TARGET" > "$OUTPUT_DIR/recon/live_urls.txt"
        echo "http://$CURRENT_TARGET" >> "$OUTPUT_DIR/recon/live_urls.txt"
    fi
    
    # Update nuclei templates
    ai_action "Updating vulnerability templates..."
    nuclei -ut 2>/dev/null
    
    # Run nuclei
    ai_action "Running Nuclei vulnerability scanner..."
    nuclei -l "$OUTPUT_DIR/recon/live_urls.txt" \
        -severity critical,high,medium \
        -c $THREADS -rl $RATE_LIMIT \
        -o "$OUTPUT_DIR/vulns/nuclei.txt" \
        -je "$OUTPUT_DIR/vulns/nuclei.json" 2>/dev/null | while read line; do
        if [[ "$line" == *"critical"* ]] || [[ "$line" == *"high"* ]]; then
            echo -e "  ${RED}🔥${NC} $line"
        elif [[ "$line" == *"medium"* ]]; then
            echo -e "  ${YELLOW}⚠️${NC} $line"
        else
            echo -e "  ${BLUE}ℹ️${NC} $line"
        fi
    done
    
    local vuln_count=$(wc -l < "$OUTPUT_DIR/vulns/nuclei.txt" 2>/dev/null || echo 0)
    
    echo ""
    if [[ $vuln_count -gt 0 ]]; then
        ai_finding "Found $vuln_count potential vulnerabilities!"
    else
        ai_success "No major vulnerabilities detected with standard templates."
    fi
    
    ai_info "Results saved to: $OUTPUT_DIR/vulns/"
}

do_xss() {
    check_target || return
    
    ai_think "Testing for XSS vulnerabilities on $CURRENT_TARGET..."
    echo ""
    
    if ! command -v dalfox &> /dev/null; then
        ai_error "Dalfox not installed. Run install-tools.sh first."
        return
    fi
    
    # Collect URLs with params first
    ai_action "Collecting URLs with parameters..."
    
    if command -v gau &> /dev/null; then
        echo "$CURRENT_TARGET" | gau 2>/dev/null | grep '=' | sort -u \
            > "$OUTPUT_DIR/params/gau_params.txt"
    fi
    
    if command -v waybackurls &> /dev/null; then
        echo "$CURRENT_TARGET" | waybackurls 2>/dev/null | grep '=' | sort -u \
            >> "$OUTPUT_DIR/params/gau_params.txt"
    fi
    
    sort -u "$OUTPUT_DIR/params/gau_params.txt" -o "$OUTPUT_DIR/params/gau_params.txt" 2>/dev/null
    
    local param_count=$(wc -l < "$OUTPUT_DIR/params/gau_params.txt" 2>/dev/null || echo 0)
    ai_info "Found $param_count URLs with parameters"
    
    if [[ $param_count -eq 0 ]]; then
        ai_warn "No parameterized URLs found. Testing main target..."
        echo "https://$CURRENT_TARGET/?q=test" > "$OUTPUT_DIR/params/gau_params.txt"
    fi
    
    # Run Dalfox
    ai_action "Running Dalfox XSS scanner..."
    head -100 "$OUTPUT_DIR/params/gau_params.txt" | \
    dalfox pipe --silence --no-color --no-spinner \
        -w $THREADS \
        -o "$OUTPUT_DIR/exploits/xss.txt" 2>/dev/null | while read line; do
        if [[ -n "$line" ]]; then
            echo -e "  ${RED}🔥${NC} $line"
        fi
    done
    
    local xss_count=$(wc -l < "$OUTPUT_DIR/exploits/xss.txt" 2>/dev/null || echo 0)
    
    echo ""
    if [[ $xss_count -gt 0 ]]; then
        ai_finding "Found $xss_count potential XSS vulnerabilities!"
        ai_say "Check $OUTPUT_DIR/exploits/xss.txt for details"
    else
        ai_success "No XSS vulnerabilities found with automated testing."
        ai_info "Try manual testing with Burp Suite for better coverage."
    fi
}

do_sqli() {
    check_target || return
    
    ai_think "Testing for SQL Injection on $CURRENT_TARGET..."
    echo ""
    
    if ! command -v sqlmap &> /dev/null; then
        ai_error "SQLMap not installed. Run install-tools.sh first."
        return
    fi
    
    # Get URLs with params
    if [[ ! -s "$OUTPUT_DIR/params/gau_params.txt" ]]; then
        ai_action "Collecting URLs with parameters..."
        if command -v gau &> /dev/null; then
            echo "$CURRENT_TARGET" | gau 2>/dev/null | grep '=' | sort -u \
                > "$OUTPUT_DIR/params/gau_params.txt"
        fi
    fi
    
    local param_count=$(wc -l < "$OUTPUT_DIR/params/gau_params.txt" 2>/dev/null || echo 0)
    
    if [[ $param_count -eq 0 ]]; then
        ai_warn "No parameterized URLs found to test."
        return
    fi
    
    ai_action "Testing $param_count URLs for SQL injection..."
    ai_warn "This may take a while..."
    
    mkdir -p "$OUTPUT_DIR/exploits/sqlmap"
    
    head -10 "$OUTPUT_DIR/params/gau_params.txt" | while read url; do
        ai_info "Testing: $url"
        sqlmap -u "$url" --batch --random-agent --level=1 --risk=1 \
            --output-dir="$OUTPUT_DIR/exploits/sqlmap/" \
            --answers="follow=Y" 2>/dev/null | \
            grep -E '(is vulnerable|Parameter|injectable|Type:)' | while read line; do
            echo -e "  ${RED}🔥${NC} $line"
            echo "$url: $line" >> "$OUTPUT_DIR/exploits/sqli.txt"
        done
    done
    
    local sqli_count=$(wc -l < "$OUTPUT_DIR/exploits/sqli.txt" 2>/dev/null || echo 0)
    
    echo ""
    if [[ $sqli_count -gt 0 ]]; then
        ai_finding "Found potential SQL injection points!"
        ai_say "Check $OUTPUT_DIR/exploits/sqli.txt for details"
    else
        ai_success "No SQL injection vulnerabilities found."
    fi
}

do_ssrf() {
    check_target || return
    
    ai_think "Testing for SSRF vulnerabilities on $CURRENT_TARGET..."
    echo ""
    
    # Get URLs with potential SSRF params
    ai_action "Looking for SSRF-prone parameters..."
    
    if [[ ! -s "$OUTPUT_DIR/params/gau_params.txt" ]]; then
        echo "$CURRENT_TARGET" | gau 2>/dev/null | grep '=' \
            > "$OUTPUT_DIR/params/gau_params.txt" 2>/dev/null
    fi
    
    grep -iE '(url=|link=|redirect=|dest=|uri=|path=|site=|page=|file=|load=|fetch=|callback=|next=|data=|reference=|src=|imageurl=)' \
        "$OUTPUT_DIR/params/gau_params.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/params/ssrf_params.txt"
    
    local ssrf_count=$(wc -l < "$OUTPUT_DIR/params/ssrf_params.txt" 2>/dev/null || echo 0)
    
    if [[ $ssrf_count -eq 0 ]]; then
        ai_warn "No SSRF-prone parameters found."
        return
    fi
    
    ai_info "Found $ssrf_count potential SSRF parameters"
    ai_action "Testing with SSRF payloads..."
    
    local payloads=(
        "http://169.254.169.254/latest/meta-data/"
        "http://127.0.0.1:22"
        "http://127.0.0.1:6379"
        "http://localhost:80"
        "http://[::1]/"
    )
    
    head -20 "$OUTPUT_DIR/params/ssrf_params.txt" | while read url; do
        for payload in "${payloads[@]}"; do
            local test_url=$(echo "$url" | sed "s|=.*|=$payload|")
            local response=$(curl -sk --max-time 5 "$test_url" 2>/dev/null)
            if echo "$response" | grep -qiE '(root:|ami-|instance-id|redis_version|SSH-|OpenSSH)'; then
                echo -e "  ${RED}🔥${NC} SSRF: $test_url"
                echo "$test_url" >> "$OUTPUT_DIR/exploits/ssrf.txt"
            fi
        done
    done
    
    local found=$(wc -l < "$OUTPUT_DIR/exploits/ssrf.txt" 2>/dev/null || echo 0)
    
    echo ""
    if [[ $found -gt 0 ]]; then
        ai_finding "Found $found potential SSRF vulnerabilities!"
    else
        ai_success "No SSRF vulnerabilities confirmed."
    fi
}

do_lfi() {
    check_target || return
    
    ai_think "Testing for LFI/Path Traversal on $CURRENT_TARGET..."
    echo ""
    
    # Get URLs with file params
    ai_action "Looking for file inclusion parameters..."
    
    if [[ ! -s "$OUTPUT_DIR/params/gau_params.txt" ]]; then
        echo "$CURRENT_TARGET" | gau 2>/dev/null | grep '=' \
            > "$OUTPUT_DIR/params/gau_params.txt" 2>/dev/null
    fi
    
    grep -iE '(file=|page=|include=|path=|doc=|document=|folder=|root=|pg=|style=|template=|php_path=|lang=|view=|content=|layout=)' \
        "$OUTPUT_DIR/params/gau_params.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/params/lfi_params.txt"
    
    local lfi_count=$(wc -l < "$OUTPUT_DIR/params/lfi_params.txt" 2>/dev/null || echo 0)
    
    if [[ $lfi_count -eq 0 ]]; then
        ai_warn "No file inclusion parameters found."
        return
    fi
    
    ai_info "Found $lfi_count potential LFI parameters"
    ai_action "Testing with LFI payloads..."
    
    local payloads=(
        "../../../../etc/passwd"
        "....//....//....//etc/passwd"
        "/etc/passwd%00"
        "php://filter/convert.base64-encode/resource=/etc/passwd"
        "..\\..\\..\\..\\windows\\win.ini"
    )
    
    head -20 "$OUTPUT_DIR/params/lfi_params.txt" | while read url; do
        for payload in "${payloads[@]}"; do
            local test_url=$(echo "$url" | sed "s|=.*|=$payload|")
            local response=$(curl -sk --max-time 5 "$test_url" 2>/dev/null)
            if echo "$response" | grep -qE '(root:|daemon:|bin:|; for 16-bit app support|\[fonts\])'; then
                echo -e "  ${RED}🔥${NC} LFI: $test_url"
                echo "$test_url" >> "$OUTPUT_DIR/exploits/lfi.txt"
                break
            fi
        done
    done
    
    local found=$(wc -l < "$OUTPUT_DIR/exploits/lfi.txt" 2>/dev/null || echo 0)
    
    echo ""
    if [[ $found -gt 0 ]]; then
        ai_finding "Found $found potential LFI vulnerabilities!"
    else
        ai_success "No LFI vulnerabilities confirmed."
    fi
}

do_fuzz() {
    check_target || return
    
    ai_think "Fuzzing directories and files on $CURRENT_TARGET..."
    echo ""
    
    local wordlist="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    [[ ! -f "$wordlist" ]] && wordlist="/usr/share/wordlists/dirb/common.txt"
    [[ ! -f "$wordlist" ]] && wordlist="/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"
    
    if [[ ! -f "$wordlist" ]]; then
        ai_error "No wordlist found. Please install seclists or dirb."
        return
    fi
    
    ai_action "Using wordlist: $(basename $wordlist)"
    
    local target_url="https://$CURRENT_TARGET"
    
    if command -v feroxbuster &> /dev/null; then
        ai_action "Running Feroxbuster..."
        feroxbuster -u "$target_url" -w "$wordlist" -t $THREADS -k -q --no-state \
            -o "$OUTPUT_DIR/web/fuzz.txt" 2>/dev/null | \
            grep -E '200|301|302|403' | head -50 | while read line; do
            echo -e "  ${GREEN}→${NC} $line"
        done
    elif command -v ffuf &> /dev/null; then
        ai_action "Running FFUF..."
        ffuf -u "${target_url}/FUZZ" -w "$wordlist" -t $THREADS -mc 200,301,302,403 \
            -o "$OUTPUT_DIR/web/fuzz.json" -of json 2>/dev/null
        
        cat "$OUTPUT_DIR/web/fuzz.json" 2>/dev/null | \
            grep -oP '"url":"[^"]+' | sed 's/"url":"//' | while read url; do
            echo -e "  ${GREEN}→${NC} $url"
        done
    elif command -v gobuster &> /dev/null; then
        ai_action "Running Gobuster..."
        gobuster dir -u "$target_url" -w "$wordlist" -t $THREADS -q \
            -o "$OUTPUT_DIR/web/fuzz.txt" 2>/dev/null | while read line; do
            echo -e "  ${GREEN}→${NC} $line"
        done
    else
        ai_error "No fuzzing tool available. Install ffuf, feroxbuster, or gobuster."
        return
    fi
    
    echo ""
    ai_success "Directory fuzzing complete!"
    ai_info "Results saved to: $OUTPUT_DIR/web/"
}

do_cors() {
    check_target || return
    
    ai_think "Testing CORS configuration on $CURRENT_TARGET..."
    echo ""
    
    local urls=("https://$CURRENT_TARGET" "http://$CURRENT_TARGET")
    
    if [[ -s "$OUTPUT_DIR/recon/live_urls.txt" ]]; then
        readarray -t urls < <(head -20 "$OUTPUT_DIR/recon/live_urls.txt")
    fi
    
    ai_action "Testing ${#urls[@]} URLs for CORS misconfigurations..."
    
    for url in "${urls[@]}"; do
        local cors=$(curl -skI -H "Origin: https://evil.com" "$url" 2>/dev/null | grep -i 'access-control-allow')
        
        if echo "$cors" | grep -qi 'evil.com'; then
            echo -e "  ${RED}🔥${NC} Reflects Origin: $url"
            echo "REFLECTS_ORIGIN: $url" >> "$OUTPUT_DIR/exploits/cors.txt"
        elif echo "$cors" | grep -qi 'null'; then
            echo -e "  ${YELLOW}⚠️${NC} Allows null origin: $url"
            echo "ALLOWS_NULL: $url" >> "$OUTPUT_DIR/exploits/cors.txt"
        elif echo "$cors" | grep -q '\*'; then
            echo -e "  ${YELLOW}⚠️${NC} Allows wildcard: $url"
            echo "WILDCARD: $url" >> "$OUTPUT_DIR/exploits/cors.txt"
        fi
    done
    
    local found=$(wc -l < "$OUTPUT_DIR/exploits/cors.txt" 2>/dev/null || echo 0)
    
    echo ""
    if [[ $found -gt 0 ]]; then
        ai_finding "Found $found CORS misconfigurations!"
    else
        ai_success "CORS configuration appears secure."
    fi
}

do_secrets() {
    check_target || return
    
    ai_think "Hunting for exposed secrets on $CURRENT_TARGET..."
    echo ""
    
    mkdir -p "$OUTPUT_DIR/secrets"
    
    # Check for exposed .git
    ai_action "Checking for exposed .git directory..."
    local git_check=$(curl -sk --max-time 5 "https://$CURRENT_TARGET/.git/HEAD" 2>/dev/null)
    if echo "$git_check" | grep -q 'ref:'; then
        echo -e "  ${RED}🔥${NC} EXPOSED: https://$CURRENT_TARGET/.git/"
        echo "https://$CURRENT_TARGET/.git/" >> "$OUTPUT_DIR/secrets/exposed.txt"
    fi
    
    # Check for exposed .env
    ai_action "Checking for exposed .env file..."
    local env_check=$(curl -sk --max-time 5 "https://$CURRENT_TARGET/.env" 2>/dev/null)
    if echo "$env_check" | grep -qiE '(DB_|APP_|API_|SECRET|PASSWORD|KEY=)'; then
        echo -e "  ${RED}🔥${NC} EXPOSED: https://$CURRENT_TARGET/.env"
        echo "https://$CURRENT_TARGET/.env" >> "$OUTPUT_DIR/secrets/exposed.txt"
    fi
    
    # Check common sensitive files
    ai_action "Checking for other sensitive files..."
    local sensitive_files=(
        ".htaccess"
        "wp-config.php.bak"
        "config.php.bak"
        ".DS_Store"
        "backup.sql"
        "database.sql"
        "phpinfo.php"
        "info.php"
        "server-status"
        "debug.log"
        "error.log"
        "composer.json"
        "package.json"
    )
    
    for file in "${sensitive_files[@]}"; do
        local response=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "https://$CURRENT_TARGET/$file" 2>/dev/null)
        if [[ "$response" == "200" ]]; then
            echo -e "  ${YELLOW}⚠️${NC} Found: https://$CURRENT_TARGET/$file"
            echo "https://$CURRENT_TARGET/$file" >> "$OUTPUT_DIR/secrets/files.txt"
        fi
    done
    
    # Scan JS files for secrets
    if [[ -s "$OUTPUT_DIR/urls/all_urls.txt" ]]; then
        ai_action "Scanning JavaScript files for hardcoded secrets..."
        grep -iE '\.js(\?|$)' "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null | head -30 | while read js_url; do
            local content=$(curl -sk --max-time 10 "$js_url" 2>/dev/null)
            if echo "$content" | grep -qiE '(api[_-]?key|apikey|api[_-]?secret|aws[_-]?access|firebase|stripe[_-]?key|private[_-]?key)'; then
                echo -e "  ${RED}🔥${NC} Secrets in: $js_url"
                echo "$js_url" >> "$OUTPUT_DIR/secrets/js_secrets.txt"
            fi
        done
    fi
    
    local found=$(wc -l < "$OUTPUT_DIR/secrets/exposed.txt" 2>/dev/null || echo 0)
    local files=$(wc -l < "$OUTPUT_DIR/secrets/files.txt" 2>/dev/null || echo 0)
    local js=$(wc -l < "$OUTPUT_DIR/secrets/js_secrets.txt" 2>/dev/null || echo 0)
    
    echo ""
    ai_success "Secret hunting complete!"
    [[ $found -gt 0 ]] && ai_finding "Found $found exposed critical files!"
    [[ $files -gt 0 ]] && ai_warn "Found $files potentially sensitive files."
    [[ $js -gt 0 ]] && ai_finding "Found secrets in $js JavaScript files!"
    ai_info "Results saved to: $OUTPUT_DIR/secrets/"
}

do_takeover() {
    check_target || return
    
    ai_think "Checking for subdomain takeover on $CURRENT_TARGET..."
    echo ""
    
    if [[ ! -s "$OUTPUT_DIR/subdomains/all.txt" ]]; then
        ai_action "First, let me find subdomains..."
        do_subdomains
    fi
    
    if command -v nuclei &> /dev/null; then
        ai_action "Running takeover detection with Nuclei..."
        nuclei -l "$OUTPUT_DIR/subdomains/all.txt" \
            -t "$NUCLEI_TEMPLATES/takeovers/" \
            -c $THREADS \
            -o "$OUTPUT_DIR/exploits/takeover.txt" 2>/dev/null | while read line; do
            echo -e "  ${RED}🔥${NC} $line"
        done
    else
        ai_warn "Nuclei not available. Manual check required."
    fi
    
    local found=$(wc -l < "$OUTPUT_DIR/exploits/takeover.txt" 2>/dev/null || echo 0)
    
    echo ""
    if [[ $found -gt 0 ]]; then
        ai_finding "Found $found potential subdomain takeovers!"
    else
        ai_success "No subdomain takeover vulnerabilities found."
    fi
}

do_tech() {
    check_target || return
    
    ai_think "Detecting technology stack on $CURRENT_TARGET..."
    echo ""
    
    if command -v whatweb &> /dev/null; then
        ai_action "Running WhatWeb..."
        whatweb "https://$CURRENT_TARGET" --no-errors -v 2>/dev/null | tee "$OUTPUT_DIR/recon/tech.txt"
    fi
    
    if command -v httpx &> /dev/null; then
        echo ""
        ai_action "Additional tech detection with httpx..."
        echo "$CURRENT_TARGET" | httpx -silent -tech-detect -status-code -title 2>/dev/null
    fi
    
    echo ""
    ai_success "Technology detection complete!"
}

do_waf() {
    check_target || return
    
    ai_think "Detecting WAF/Firewall on $CURRENT_TARGET..."
    echo ""
    
    if command -v wafw00f &> /dev/null; then
        ai_action "Running wafw00f..."
        wafw00f "https://$CURRENT_TARGET" 2>/dev/null | tee "$OUTPUT_DIR/recon/waf.txt"
    else
        ai_action "Basic WAF detection..."
        local response=$(curl -sk -H "User-Agent: () { :; }; echo vulnerable" \
            -H "X-Forwarded-For: 127.0.0.1' OR '1'='1" \
            "https://$CURRENT_TARGET/?test=<script>alert(1)</script>" 2>/dev/null)
        
        if echo "$response" | grep -qi 'cloudflare'; then
            echo -e "  ${YELLOW}⚠️${NC} Cloudflare detected"
        elif echo "$response" | grep -qi 'akamai'; then
            echo -e "  ${YELLOW}⚠️${NC} Akamai detected"
        elif echo "$response" | grep -qi 'incapsula'; then
            echo -e "  ${YELLOW}⚠️${NC} Incapsula detected"
        elif echo "$response" | grep -qi 'blocked\|forbidden\|denied'; then
            echo -e "  ${YELLOW}⚠️${NC} WAF detected (blocked request)"
        else
            echo -e "  ${GREEN}→${NC} No obvious WAF detected"
        fi
    fi
    
    echo ""
    ai_success "WAF detection complete!"
}

do_urls() {
    check_target || return
    
    ai_think "Collecting all URLs for $CURRENT_TARGET..."
    echo ""
    
    if command -v gau &> /dev/null; then
        ai_action "Running GAU..."
        echo "$CURRENT_TARGET" | gau --threads $THREADS > "$OUTPUT_DIR/urls/gau.txt" 2>/dev/null &
        local pid1=$!
    fi
    
    if command -v waybackurls &> /dev/null; then
        ai_action "Running Waybackurls..."
        echo "$CURRENT_TARGET" | waybackurls > "$OUTPUT_DIR/urls/wayback.txt" 2>/dev/null &
        local pid2=$!
    fi
    
    wait $pid1 2>/dev/null
    wait $pid2 2>/dev/null
    
    # Crawl if we have live hosts
    if command -v katana &> /dev/null && [[ -s "$OUTPUT_DIR/recon/live_urls.txt" ]]; then
        ai_action "Crawling with Katana..."
        katana -list "$OUTPUT_DIR/recon/live_urls.txt" -silent -d 2 -jc -t $THREADS \
            -o "$OUTPUT_DIR/urls/katana.txt" 2>/dev/null
    fi
    
    # Merge
    cat "$OUTPUT_DIR/urls/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/urls/all_urls.txt"
    local total=$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)
    
    echo ""
    ai_success "Collected $total unique URLs!"
    
    # Extract interesting patterns
    ai_action "Extracting interesting patterns..."
    
    grep -iE '\.js(\?|$)' "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null | wc -l | xargs -I {} echo -e "  ${CYAN}→${NC} {} JavaScript files"
    grep -E '\?' "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null | wc -l | xargs -I {} echo -e "  ${CYAN}→${NC} {} URLs with parameters"
    grep -iE '(api|v[0-9]|graphql)' "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null | wc -l | xargs -I {} echo -e "  ${CYAN}→${NC} {} API endpoints"
    
    ai_info "Results saved to: $OUTPUT_DIR/urls/"
}

do_params() {
    check_target || return
    
    ai_think "Discovering hidden parameters on $CURRENT_TARGET..."
    echo ""
    
    if ! command -v arjun &> /dev/null; then
        ai_error "Arjun not installed. Run install-tools.sh first."
        return
    fi
    
    ai_action "Running Arjun parameter discovery..."
    arjun -u "https://$CURRENT_TARGET" -t $THREADS \
        -o "$OUTPUT_DIR/params/arjun.json" 2>/dev/null
    
    if [[ -s "$OUTPUT_DIR/params/arjun.json" ]]; then
        ai_success "Parameter discovery complete!"
        cat "$OUTPUT_DIR/params/arjun.json"
    else
        ai_warn "No hidden parameters found."
    fi
}

do_full_scan() {
    check_target || return
    
    ai_think "Starting FULL automated scan on $CURRENT_TARGET..."
    ai_warn "This will take a while. Grab some coffee! ☕"
    echo ""
    
    # Phase 1: Recon
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                    PHASE 1: RECONNAISSANCE${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    do_recon
    
    # Phase 2: URL Collection
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                    PHASE 2: URL COLLECTION${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    do_urls
    
    # Phase 3: Scanning
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                    PHASE 3: SCANNING${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    do_ports
    do_fuzz
    do_vulns
    
    # Phase 4: Exploitation Testing
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                 PHASE 4: EXPLOITATION TESTING${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    do_xss
    do_sqli
    do_ssrf
    do_lfi
    do_cors
    do_secrets
    do_takeover
    
    # Generate report
    echo ""
    do_report
}

do_report() {
    check_target || return
    
    ai_think "Generating scan report..."
    echo ""
    
    local report="$OUTPUT_DIR/reports/report.md"
    
    cat << EOF > "$report"
# 🔥 HackStrike AI Scan Report

## Target: $CURRENT_TARGET
**Scan Date:** $(date)
**Output Directory:** $OUTPUT_DIR

---

## 📊 Summary

| Category | Count |
|----------|-------|
| Subdomains | $(wc -l < "$OUTPUT_DIR/subdomains/all.txt" 2>/dev/null || echo 0) |
| Live Hosts | $(wc -l < "$OUTPUT_DIR/recon/live_urls.txt" 2>/dev/null || echo 0) |
| URLs Collected | $(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0) |
| Vulnerabilities | $(wc -l < "$OUTPUT_DIR/vulns/nuclei.txt" 2>/dev/null || echo 0) |

---

## 🔥 Vulnerability Findings

### XSS
$(cat "$OUTPUT_DIR/exploits/xss.txt" 2>/dev/null || echo "None found")

### SQL Injection
$(cat "$OUTPUT_DIR/exploits/sqli.txt" 2>/dev/null || echo "None found")

### SSRF
$(cat "$OUTPUT_DIR/exploits/ssrf.txt" 2>/dev/null || echo "None found")

### LFI/RFI
$(cat "$OUTPUT_DIR/exploits/lfi.txt" 2>/dev/null || echo "None found")

### CORS Misconfigurations
$(cat "$OUTPUT_DIR/exploits/cors.txt" 2>/dev/null || echo "None found")

### Subdomain Takeover
$(cat "$OUTPUT_DIR/exploits/takeover.txt" 2>/dev/null || echo "None found")

---

## 🔑 Exposed Secrets
$(cat "$OUTPUT_DIR/secrets/exposed.txt" 2>/dev/null || echo "None found")

---

## 📁 Files

All results are saved in: \`$OUTPUT_DIR\`

---

*Generated by HackStrike AI*
EOF

    ai_success "Report generated: $report"
    
    # Print summary
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                    ${WHITE}SCAN SUMMARY${NC}                              ${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  Target: ${GREEN}$CURRENT_TARGET${NC}"
    echo -e "${CYAN}║${NC}  Subdomains: ${YELLOW}$(wc -l < "$OUTPUT_DIR/subdomains/all.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "${CYAN}║${NC}  Live Hosts: ${YELLOW}$(wc -l < "$OUTPUT_DIR/recon/live_urls.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "${CYAN}║${NC}  URLs: ${YELLOW}$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${RED}Vulnerabilities: $(wc -l < "$OUTPUT_DIR/vulns/nuclei.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "${CYAN}║${NC}  ${RED}XSS: $(wc -l < "$OUTPUT_DIR/exploits/xss.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "${CYAN}║${NC}  ${RED}SQLi: $(wc -l < "$OUTPUT_DIR/exploits/sqli.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "${CYAN}║${NC}  ${RED}SSRF: $(wc -l < "$OUTPUT_DIR/exploits/ssrf.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "${CYAN}║${NC}  ${RED}LFI: $(wc -l < "$OUTPUT_DIR/exploits/lfi.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "${CYAN}║${NC}  ${RED}Secrets: $(wc -l < "$OUTPUT_DIR/secrets/exposed.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    ai_info "Full report: $report"
}

show_help() {
    echo ""
    ai_say "Here's what I can do for you:"
    echo ""
    echo -e "  ${CYAN}🎯 Set Target:${NC}"
    echo -e "     ${WHITE}scan example.com${NC}"
    echo -e "     ${WHITE}test hackerone.com${NC}"
    echo -e "     ${WHITE}hack target.com${NC}"
    echo ""
    echo -e "  ${CYAN}🔍 Reconnaissance:${NC}"
    echo -e "     ${WHITE}find subdomains${NC}"
    echo -e "     ${WHITE}do recon${NC}"
    echo -e "     ${WHITE}collect urls${NC}"
    echo -e "     ${WHITE}detect technology${NC}"
    echo -e "     ${WHITE}check waf${NC}"
    echo ""
    echo -e "  ${CYAN}🔓 Scanning:${NC}"
    echo -e "     ${WHITE}scan ports${NC}"
    echo -e "     ${WHITE}find vulnerabilities${NC}"
    echo -e "     ${WHITE}fuzz directories${NC}"
    echo -e "     ${WHITE}find parameters${NC}"
    echo ""
    echo -e "  ${CYAN}💉 Exploitation:${NC}"
    echo -e "     ${WHITE}test for xss${NC}"
    echo -e "     ${WHITE}check sql injection${NC}"
    echo -e "     ${WHITE}find ssrf${NC}"
    echo -e "     ${WHITE}test lfi${NC}"
    echo -e "     ${WHITE}check cors${NC}"
    echo -e "     ${WHITE}find secrets${NC}"
    echo -e "     ${WHITE}check subdomain takeover${NC}"
    echo ""
    echo -e "  ${CYAN}📊 Reports:${NC}"
    echo -e "     ${WHITE}show report${NC}"
    echo -e "     ${WHITE}status${NC}"
    echo ""
    echo -e "  ${CYAN}🚀 Full Auto:${NC}"
    echo -e "     ${WHITE}full scan${NC}"
    echo -e "     ${WHITE}find all vulnerabilities${NC}"
    echo -e "     ${WHITE}scan everything${NC}"
    echo ""
    echo -e "  ${CYAN}⚡ Other:${NC}"
    echo -e "     ${WHITE}help${NC} - Show this message"
    echo -e "     ${WHITE}clear${NC} - Clear screen"
    echo -e "     ${WHITE}exit${NC} - Quit"
    echo ""
}

show_status() {
    echo ""
    if [[ -n "$CURRENT_TARGET" ]]; then
        ai_say "Current target: $CURRENT_TARGET"
        ai_info "Output directory: $OUTPUT_DIR"
        
        if [[ -d "$OUTPUT_DIR" ]]; then
            echo ""
            echo -e "  ${WHITE}Scan data:${NC}"
            [[ -f "$OUTPUT_DIR/subdomains/all.txt" ]] && echo -e "    Subdomains: $(wc -l < "$OUTPUT_DIR/subdomains/all.txt")"
            [[ -f "$OUTPUT_DIR/recon/live_urls.txt" ]] && echo -e "    Live hosts: $(wc -l < "$OUTPUT_DIR/recon/live_urls.txt")"
            [[ -f "$OUTPUT_DIR/urls/all_urls.txt" ]] && echo -e "    URLs: $(wc -l < "$OUTPUT_DIR/urls/all_urls.txt")"
            [[ -f "$OUTPUT_DIR/vulns/nuclei.txt" ]] && echo -e "    Vulnerabilities: $(wc -l < "$OUTPUT_DIR/vulns/nuclei.txt")"
        fi
    else
        ai_warn "No target set. Tell me what to scan!"
    fi
    echo ""
}

#====================================================================
# MAIN LOOP
#====================================================================

extract_target() {
    local input="$1"
    local extracted_target=""
    
    # Match URLs
    if [[ "$input" =~ (https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}(/[^\ ]*)? ]]; then
        extracted_target="${BASH_REMATCH[0]}"
        extracted_target=$(echo "$extracted_target" | sed 's|https\?://||' | sed 's|/.*||')
    fi
    
    # Match IP addresses
    if [[ -z "$extracted_target" ]] && [[ "$input" =~ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        extracted_target="${BASH_REMATCH[0]}"
    fi
    
    echo "$extracted_target"
}

main() {
    banner
    
    ai_say "Hello! I'm HackStrike AI, your bug bounty assistant."
    ai_say "Tell me what you want to do. Type 'help' for commands."
    echo ""
    
    # Read history
    if [[ -f "$HISTORY_FILE" ]]; then
        history -r "$HISTORY_FILE"
    fi
    
    while true; do
        show_prompt
        read -r input
        
        # Skip empty input
        [[ -z "$input" ]] && continue
        
        # Save to history
        echo "$input" >> "$HISTORY_FILE"
        
        # Extract target FIRST (in main shell, not subshell)
        local new_target=$(extract_target "$input")
        if [[ -n "$new_target" ]]; then
            CURRENT_TARGET="$new_target"
            setup_output_dir
        fi
        
        # Parse intent
        local intent=$(parse_intent "$input")
        
        echo ""
        
        case "$intent" in
            HELP)
                show_help
                ;;
            SET_TARGET|SET_TARGET:*)
                ai_success "Target set to: $CURRENT_TARGET"
                ai_say "What would you like me to do? Try 'full scan' or 'find vulnerabilities'"
                ;;
            NEED_TARGET)
                ai_warn "I need a target! Example: 'scan example.com'"
                ;;
            FULL_SCAN)
                do_full_scan
                ;;
            SUBDOMAINS)
                do_subdomains
                ;;
            RECON)
                do_recon
                ;;
            PORTS)
                do_ports
                ;;
            VULNS)
                do_vulns
                ;;
            XSS)
                do_xss
                ;;
            SQLI)
                do_sqli
                ;;
            SSRF)
                do_ssrf
                ;;
            LFI)
                do_lfi
                ;;
            FUZZ)
                do_fuzz
                ;;
            CORS)
                do_cors
                ;;
            SECRETS)
                do_secrets
                ;;
            TAKEOVER)
                do_takeover
                ;;
            TECH)
                do_tech
                ;;
            WAF)
                do_waf
                ;;
            URLS)
                do_urls
                ;;
            PARAMS)
                do_params
                ;;
            REPORT)
                do_report
                ;;
            STATUS)
                show_status
                ;;
            CLEAR)
                banner
                ;;
            EXIT)
                ai_say "Goodbye! Happy hunting! 🎯"
                exit 0
                ;;
            UNKNOWN)
                ai_warn "I didn't understand that. Try 'help' to see what I can do."
                ;;
        esac
    done
}

# Run
main
