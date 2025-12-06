#!/bin/bash

#====================================================================
#  BUG BOUNTY TOOLKIT - MASTER INSTALLATION SCRIPT
#====================================================================
#  This script installs all essential bug bounty and penetration
#  testing tools for ethical security research.
#
#  DISCLAIMER: Only use these tools on systems you own or have
#  explicit written authorization to test.
#====================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="$HOME/HackTools/install.log"
TOOLS_DIR="$HOME/HackTools"

log() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[-]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
}

header() {
    echo ""
    echo -e "${PURPLE}========================================${NC}"
    echo -e "${PURPLE}  $1${NC}"
    echo -e "${PURPLE}========================================${NC}"
    echo ""
}

#====================================================================
# CHECK REQUIREMENTS
#====================================================================
check_requirements() {
    header "Checking Requirements"
    
    # Check if running as root for certain installations
    if [[ $EUID -eq 0 ]]; then
        warn "Running as root. Some Go tools should be installed as regular user."
    fi
    
    # Check for package managers
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        log "Detected Debian/Ubuntu system"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        log "Detected Fedora/RHEL system"
    elif command -v pacman &> /dev/null; then
        PKG_MANAGER="pacman"
        log "Detected Arch Linux system"
    elif command -v brew &> /dev/null; then
        PKG_MANAGER="brew"
        log "Detected macOS with Homebrew"
    else
        error "No supported package manager found!"
        exit 1
    fi
    
    # Check for Go
    if ! command -v go &> /dev/null; then
        warn "Go is not installed. Installing Go..."
        install_go
    else
        log "Go is installed: $(go version)"
    fi
    
    # Check for Python
    if ! command -v python3 &> /dev/null; then
        warn "Python3 is not installed. Installing..."
        install_python
    else
        log "Python3 is installed: $(python3 --version)"
    fi
    
    # Check for pip
    if ! command -v pip3 &> /dev/null; then
        warn "pip3 is not installed. Installing..."
        install_pip
    else
        log "pip3 is installed"
    fi
}

#====================================================================
# INSTALL BASE DEPENDENCIES
#====================================================================
install_base_dependencies() {
    header "Installing Base Dependencies"
    
    case $PKG_MANAGER in
        apt)
            sudo apt-get update
            sudo apt-get install -y \
                git curl wget unzip jq \
                build-essential libssl-dev libffi-dev \
                python3-dev python3-pip python3-venv \
                ruby ruby-dev \
                nmap masscan \
                whois dnsutils \
                netcat-openbsd \
                chromium-browser || sudo apt-get install -y chromium
            ;;
        dnf)
            sudo dnf install -y \
                git curl wget unzip jq \
                gcc openssl-devel libffi-devel \
                python3-devel python3-pip \
                ruby ruby-devel \
                nmap masscan \
                whois bind-utils \
                nmap-ncat \
                chromium
            ;;
        pacman)
            sudo pacman -Syu --noconfirm \
                git curl wget unzip jq \
                base-devel openssl libffi \
                python python-pip \
                ruby \
                nmap masscan \
                whois bind-tools \
                gnu-netcat \
                chromium
            ;;
        brew)
            brew install \
                git curl wget unzip jq \
                openssl libffi \
                python3 \
                ruby \
                nmap masscan \
                whois bind \
                netcat
            ;;
    esac
    
    log "Base dependencies installed"
}

install_go() {
    log "Installing Go..."
    GO_VERSION="1.21.5"
    wget "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    
    # Add to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zshrc 2>/dev/null || true
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    
    log "Go installed: $(go version)"
}

install_python() {
    case $PKG_MANAGER in
        apt) sudo apt-get install -y python3 python3-pip python3-venv ;;
        dnf) sudo dnf install -y python3 python3-pip ;;
        pacman) sudo pacman -S --noconfirm python python-pip ;;
        brew) brew install python3 ;;
    esac
}

install_pip() {
    curl https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
    python3 /tmp/get-pip.py --user
    rm /tmp/get-pip.py
}

#====================================================================
# RECONNAISSANCE TOOLS
#====================================================================
install_recon_tools() {
    header "Installing Reconnaissance Tools"
    
    # Amass - Subdomain enumeration
    log "Installing Amass..."
    go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null || warn "Amass installation failed"
    
    # Subfinder - Fast subdomain discovery
    log "Installing Subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || warn "Subfinder installation failed"
    
    # Assetfinder - Find related domains
    log "Installing Assetfinder..."
    go install -v github.com/tomnomnom/assetfinder@latest 2>/dev/null || warn "Assetfinder installation failed"
    
    # Httpx - HTTP probing
    log "Installing Httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || warn "Httpx installation failed"
    
    # Httprobe - HTTP/HTTPS probe
    log "Installing Httprobe..."
    go install -v github.com/tomnomnom/httprobe@latest 2>/dev/null || warn "Httprobe installation failed"
    
    # Waybackurls - Fetch URLs from Wayback Machine
    log "Installing Waybackurls..."
    go install -v github.com/tomnomnom/waybackurls@latest 2>/dev/null || warn "Waybackurls installation failed"
    
    # Gau - Get All URLs
    log "Installing Gau..."
    go install -v github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || warn "Gau installation failed"
    
    # Hakrawler - Web crawler
    log "Installing Hakrawler..."
    go install -v github.com/hakluke/hakrawler@latest 2>/dev/null || warn "Hakrawler installation failed"
    
    # GoSpider - Web spider
    log "Installing GoSpider..."
    go install -v github.com/jaeles-project/gospider@latest 2>/dev/null || warn "GoSpider installation failed"
    
    # Katana - Next-gen crawling
    log "Installing Katana..."
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || warn "Katana installation failed"
    
    # DNSx - DNS toolkit
    log "Installing DNSx..."
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || warn "DNSx installation failed"
    
    # Findomain - Subdomain finder
    log "Installing Findomain..."
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux-i386.zip -O /tmp/findomain.zip 2>/dev/null || warn "Findomain download failed"
        unzip -o /tmp/findomain.zip -d /tmp/ 2>/dev/null
        chmod +x /tmp/findomain 2>/dev/null
        sudo mv /tmp/findomain /usr/local/bin/ 2>/dev/null || warn "Findomain installation failed"
    fi
    
    log "Reconnaissance tools installed"
}

#====================================================================
# SCANNING TOOLS
#====================================================================
install_scanning_tools() {
    header "Installing Scanning Tools"
    
    # Nmap should already be installed via base dependencies
    log "Nmap: $(nmap --version | head -1)"
    
    # RustScan - Fast port scanner
    log "Installing RustScan..."
    if command -v cargo &> /dev/null; then
        cargo install rustscan 2>/dev/null || warn "RustScan installation failed"
    else
        # Try downloading binary
        wget https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.1.1_amd64.deb -O /tmp/rustscan.deb 2>/dev/null
        sudo dpkg -i /tmp/rustscan.deb 2>/dev/null || warn "RustScan installation failed"
    fi
    
    # Nuclei - Vulnerability scanner
    log "Installing Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || warn "Nuclei installation failed"
    
    # Update Nuclei templates
    log "Updating Nuclei templates..."
    nuclei -update-templates 2>/dev/null || warn "Nuclei templates update failed"
    
    # Nikto - Web server scanner
    log "Installing Nikto..."
    if [[ ! -d "$TOOLS_DIR/scanning/nikto" ]]; then
        git clone https://github.com/sullo/nikto.git "$TOOLS_DIR/scanning/nikto" 2>/dev/null || warn "Nikto installation failed"
    fi
    
    # Naabu - Port scanner
    log "Installing Naabu..."
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || warn "Naabu installation failed"
    
    log "Scanning tools installed"
}

#====================================================================
# WEB VULNERABILITY TOOLS
#====================================================================
install_web_tools() {
    header "Installing Web Vulnerability Tools"
    
    # Ffuf - Fast web fuzzer
    log "Installing Ffuf..."
    go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null || warn "Ffuf installation failed"
    
    # Feroxbuster - Content discovery
    log "Installing Feroxbuster..."
    if command -v cargo &> /dev/null; then
        cargo install feroxbuster 2>/dev/null || warn "Feroxbuster installation failed"
    else
        curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s "$HOME/.local/bin" 2>/dev/null || warn "Feroxbuster installation failed"
    fi
    
    # Gobuster - Directory/DNS/VHost busting
    log "Installing Gobuster..."
    go install -v github.com/OJ/gobuster/v3@latest 2>/dev/null || warn "Gobuster installation failed"
    
    # Dirsearch - Web path scanner
    log "Installing Dirsearch..."
    pip3 install dirsearch --user 2>/dev/null || warn "Dirsearch installation failed"
    
    # SQLMap - SQL injection tool
    log "Installing SQLMap..."
    if [[ ! -d "$TOOLS_DIR/web-testing/sqlmap" ]]; then
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$TOOLS_DIR/web-testing/sqlmap" 2>/dev/null || warn "SQLMap installation failed"
    fi
    
    # XSStrike - XSS scanner
    log "Installing XSStrike..."
    if [[ ! -d "$TOOLS_DIR/web-testing/XSStrike" ]]; then
        git clone https://github.com/s0md3v/XSStrike.git "$TOOLS_DIR/web-testing/XSStrike" 2>/dev/null || warn "XSStrike installation failed"
        pip3 install -r "$TOOLS_DIR/web-testing/XSStrike/requirements.txt" --user 2>/dev/null || true
    fi
    
    # Dalfox - XSS scanner
    log "Installing Dalfox..."
    go install -v github.com/hahwul/dalfox/v2@latest 2>/dev/null || warn "Dalfox installation failed"
    
    # Arjun - HTTP parameter discovery
    log "Installing Arjun..."
    pip3 install arjun --user 2>/dev/null || warn "Arjun installation failed"
    
    # ParamSpider - Parameter discovery
    log "Installing ParamSpider..."
    pip3 install paramspider --user 2>/dev/null || warn "ParamSpider installation failed"
    
    # Kxss - XSS parameter finder
    log "Installing Kxss..."
    go install -v github.com/Emoe/kxss@latest 2>/dev/null || warn "Kxss installation failed"
    
    # Qsreplace - Query string replacer
    log "Installing Qsreplace..."
    go install -v github.com/tomnomnom/qsreplace@latest 2>/dev/null || warn "Qsreplace installation failed"
    
    # Unfurl - URL parser
    log "Installing Unfurl..."
    go install -v github.com/tomnomnom/unfurl@latest 2>/dev/null || warn "Unfurl installation failed"
    
    # WPScan - WordPress scanner
    log "Installing WPScan..."
    sudo gem install wpscan 2>/dev/null || warn "WPScan installation failed"
    
    # CMSeeK - CMS detection
    log "Installing CMSeeK..."
    if [[ ! -d "$TOOLS_DIR/web-testing/CMSeeK" ]]; then
        git clone https://github.com/Tuhinshubhra/CMSeeK.git "$TOOLS_DIR/web-testing/CMSeeK" 2>/dev/null || warn "CMSeeK installation failed"
        pip3 install -r "$TOOLS_DIR/web-testing/CMSeeK/requirements.txt" --user 2>/dev/null || true
    fi
    
    log "Web vulnerability tools installed"
}

#====================================================================
# ENUMERATION TOOLS
#====================================================================
install_enumeration_tools() {
    header "Installing Enumeration Tools"
    
    # Enum4linux - SMB enumeration
    log "Installing Enum4linux-ng..."
    pip3 install enum4linux-ng --user 2>/dev/null || warn "Enum4linux-ng installation failed"
    
    # SMBMap - SMB enumeration
    log "Installing SMBMap..."
    pip3 install smbmap --user 2>/dev/null || warn "SMBMap installation failed"
    
    # Ldapdomaindump - LDAP enumeration
    log "Installing Ldapdomaindump..."
    pip3 install ldapdomaindump --user 2>/dev/null || warn "Ldapdomaindump installation failed"
    
    # Kerbrute - Kerberos bruteforce
    log "Installing Kerbrute..."
    go install -v github.com/ropnop/kerbrute@latest 2>/dev/null || warn "Kerbrute installation failed"
    
    log "Enumeration tools installed"
}

#====================================================================
# OSINT TOOLS
#====================================================================
install_osint_tools() {
    header "Installing OSINT Tools"
    
    # theHarvester - Email/domain harvester
    log "Installing theHarvester..."
    pip3 install theHarvester --user 2>/dev/null || warn "theHarvester installation failed"
    
    # Sherlock - Username hunter
    log "Installing Sherlock..."
    pip3 install sherlock-project --user 2>/dev/null || warn "Sherlock installation failed"
    
    # Holehe - Email OSINT
    log "Installing Holehe..."
    pip3 install holehe --user 2>/dev/null || warn "Holehe installation failed"
    
    # Photon - OSINT crawler
    log "Installing Photon..."
    if [[ ! -d "$TOOLS_DIR/osint/Photon" ]]; then
        git clone https://github.com/s0md3v/Photon.git "$TOOLS_DIR/osint/Photon" 2>/dev/null || warn "Photon installation failed"
        pip3 install -r "$TOOLS_DIR/osint/Photon/requirements.txt" --user 2>/dev/null || true
    fi
    
    # Recon-ng - OSINT framework
    log "Installing Recon-ng..."
    pip3 install recon-ng --user 2>/dev/null || warn "Recon-ng installation failed"
    
    # Social Analyzer
    log "Installing Social Analyzer..."
    pip3 install social-analyzer --user 2>/dev/null || warn "Social Analyzer installation failed"
    
    log "OSINT tools installed"
}

#====================================================================
# MOBILE SECURITY TOOLS
#====================================================================
install_mobile_tools() {
    header "Installing Mobile Security Tools"
    
    # Apktool - Android APK tool
    log "Installing Apktool..."
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        sudo apt-get install -y apktool 2>/dev/null || warn "Apktool installation failed"
    else
        wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /tmp/apktool 2>/dev/null
        wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.1.jar -O /tmp/apktool.jar 2>/dev/null
        chmod +x /tmp/apktool
        sudo mv /tmp/apktool /tmp/apktool.jar /usr/local/bin/ 2>/dev/null || warn "Apktool installation failed"
    fi
    
    # Jadx - Dex to Java decompiler
    log "Installing Jadx..."
    if [[ ! -d "$TOOLS_DIR/mobile/jadx" ]]; then
        wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.4.7.zip -O /tmp/jadx.zip 2>/dev/null
        unzip -o /tmp/jadx.zip -d "$TOOLS_DIR/mobile/jadx" 2>/dev/null || warn "Jadx installation failed"
    fi
    
    # MobSF - Mobile Security Framework (Docker)
    log "MobSF can be installed via Docker: docker pull opensecurity/mobile-security-framework-mobsf"
    
    log "Mobile security tools installed"
}

#====================================================================
# CLOUD SECURITY TOOLS
#====================================================================
install_cloud_tools() {
    header "Installing Cloud Security Tools"
    
    # AWS CLI
    log "Installing AWS CLI..."
    pip3 install awscli --user 2>/dev/null || warn "AWS CLI installation failed"
    
    # ScoutSuite - Multi-cloud security auditing
    log "Installing ScoutSuite..."
    pip3 install scoutsuite --user 2>/dev/null || warn "ScoutSuite installation failed"
    
    # Prowler - AWS security tool
    log "Installing Prowler..."
    pip3 install prowler --user 2>/dev/null || warn "Prowler installation failed"
    
    # CloudBrute - Cloud enumeration
    log "Installing CloudBrute..."
    go install -v github.com/0xsha/CloudBrute@latest 2>/dev/null || warn "CloudBrute installation failed"
    
    # S3Scanner - S3 bucket scanner
    log "Installing S3Scanner..."
    pip3 install s3scanner --user 2>/dev/null || warn "S3Scanner installation failed"
    
    log "Cloud security tools installed"
}

#====================================================================
# WORDLISTS
#====================================================================
download_wordlists() {
    header "Downloading Wordlists"
    
    WORDLIST_DIR="$TOOLS_DIR/wordlists"
    
    # SecLists
    log "Downloading SecLists..."
    if [[ ! -d "$WORDLIST_DIR/SecLists" ]]; then
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLIST_DIR/SecLists" 2>/dev/null || warn "SecLists download failed"
    fi
    
    # Assetnote Wordlists (smaller essential ones)
    log "Downloading common wordlists..."
    mkdir -p "$WORDLIST_DIR/common"
    
    # Common subdomain wordlist
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
        -O "$WORDLIST_DIR/common/subdomains-5000.txt" 2>/dev/null || true
    
    # Common directory wordlist
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
        -O "$WORDLIST_DIR/common/directories.txt" 2>/dev/null || true
    
    # Common passwords
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt \
        -O "$WORDLIST_DIR/common/passwords-10k.txt" 2>/dev/null || true
    
    log "Wordlists downloaded"
}

#====================================================================
# ADDITIONAL UTILITIES
#====================================================================
install_utilities() {
    header "Installing Additional Utilities"
    
    # Anew - Append unique lines
    log "Installing Anew..."
    go install -v github.com/tomnomnom/anew@latest 2>/dev/null || warn "Anew installation failed"
    
    # Gf - Grep patterns
    log "Installing Gf..."
    go install -v github.com/tomnomnom/gf@latest 2>/dev/null || warn "Gf installation failed"
    
    # Install gf patterns
    log "Installing Gf patterns..."
    mkdir -p ~/.gf
    if [[ ! -d "$TOOLS_DIR/scripts/gf-patterns" ]]; then
        git clone https://github.com/1ndianl33t/Gf-Patterns.git "$TOOLS_DIR/scripts/gf-patterns" 2>/dev/null
        cp "$TOOLS_DIR/scripts/gf-patterns/"*.json ~/.gf/ 2>/dev/null || true
    fi
    
    # Notify - Send notifications
    log "Installing Notify..."
    go install -v github.com/projectdiscovery/notify/cmd/notify@latest 2>/dev/null || warn "Notify installation failed"
    
    # Interactsh - OOB interaction
    log "Installing Interactsh..."
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>/dev/null || warn "Interactsh installation failed"
    
    log "Utilities installed"
}

#====================================================================
# SETUP PATH AND ALIASES
#====================================================================
setup_environment() {
    header "Setting Up Environment"
    
    # Create aliases file
    cat > "$TOOLS_DIR/aliases.sh" << 'ALIASES'
# Bug Bounty Toolkit Aliases
# Source this file in your .bashrc or .zshrc

# Quick tool access
alias sqlmap='python3 $HOME/HackTools/web-testing/sqlmap/sqlmap.py'
alias xsstrike='python3 $HOME/HackTools/web-testing/XSStrike/xsstrike.py'
alias cmseek='python3 $HOME/HackTools/web-testing/CMSeeK/cmseek.py'
alias photon='python3 $HOME/HackTools/osint/Photon/photon.py'
alias nikto='perl $HOME/HackTools/scanning/nikto/program/nikto.pl'

# Recon shortcuts
alias subenum='$HOME/HackTools/scripts/recon/subdomain-enum.sh'
alias fullrecon='$HOME/HackTools/scripts/recon/full-recon.sh'
alias portscan='$HOME/HackTools/scripts/scanning/port-scan.sh'

# Quick commands
alias webcheck='httpx -silent -status-code -title -tech-detect'
alias quicknuclei='nuclei -severity critical,high,medium -silent'
alias quickffuf='ffuf -w $HOME/HackTools/wordlists/common/directories.txt -mc 200,301,302,403'

# Output directory
alias hackout='cd $HOME/HackTools/output'

ALIASES
    
    # Add to shell config
    ALIAS_SOURCE="source $TOOLS_DIR/aliases.sh"
    
    if ! grep -q "HackTools/aliases.sh" ~/.bashrc 2>/dev/null; then
        echo "" >> ~/.bashrc
        echo "# Bug Bounty Toolkit" >> ~/.bashrc
        echo "$ALIAS_SOURCE" >> ~/.bashrc
    fi
    
    if [[ -f ~/.zshrc ]] && ! grep -q "HackTools/aliases.sh" ~/.zshrc 2>/dev/null; then
        echo "" >> ~/.zshrc
        echo "# Bug Bounty Toolkit" >> ~/.zshrc
        echo "$ALIAS_SOURCE" >> ~/.zshrc
    fi
    
    log "Environment configured"
}

#====================================================================
# VERIFY INSTALLATION
#====================================================================
verify_installation() {
    header "Verifying Installation"
    
    echo -e "\n${CYAN}Checking installed tools...${NC}\n"
    
    tools=(
        "amass"
        "subfinder"
        "httpx"
        "nuclei"
        "ffuf"
        "nmap"
        "gobuster"
        "feroxbuster"
        "dalfox"
        "katana"
        "gau"
        "waybackurls"
        "dnsx"
        "naabu"
        "arjun"
        "wpscan"
        "theHarvester"
        "sherlock"
    )
    
    installed=0
    failed=0
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $tool"
            ((installed++))
        else
            echo -e "  ${RED}✗${NC} $tool"
            ((failed++))
        fi
    done
    
    echo ""
    echo -e "${CYAN}Installation Summary:${NC}"
    echo -e "  ${GREEN}Installed:${NC} $installed"
    echo -e "  ${RED}Failed:${NC} $failed"
    echo ""
}

#====================================================================
# BURP SUITE INSTALLATION
#====================================================================
install_burpsuite() {
    section "Installing Burp Suite"
    
    BURP_SCRIPT="$SCRIPT_DIR/scripts/web-testing/install-burpsuite.sh"
    
    if [[ -f "$BURP_SCRIPT" ]]; then
        chmod +x "$BURP_SCRIPT"
        bash "$BURP_SCRIPT"
    else
        error "Burp Suite installation script not found at: $BURP_SCRIPT"
        info "Please ensure the script exists in scripts/web-testing/"
    fi
}

#====================================================================
# METASPLOIT INSTALLATION
#====================================================================
install_metasploit() {
    section "Installing Metasploit Framework"
    
    MSF_SCRIPT="$SCRIPT_DIR/scripts/exploitation/install-metasploit.sh"
    
    if [[ -f "$MSF_SCRIPT" ]]; then
        chmod +x "$MSF_SCRIPT"
        bash "$MSF_SCRIPT"
    else
        error "Metasploit installation script not found at: $MSF_SCRIPT"
        info "Please ensure the script exists in scripts/exploitation/"
    fi
}

#====================================================================
# MAIN MENU
#====================================================================
show_menu() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║           BUG BOUNTY TOOLKIT INSTALLER                    ║"
    echo "║                                                           ║"
    echo "║   DISCLAIMER: Only use on authorized systems!             ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "Select installation option:"
    echo ""
    echo "  1) Full Installation (All tools)"
    echo "  2) Recon Tools Only"
    echo "  3) Scanning Tools Only"
    echo "  4) Web Testing Tools Only"
    echo "  5) OSINT Tools Only"
    echo "  6) Cloud Security Tools Only"
    echo "  7) Download Wordlists Only"
    echo "  8) Verify Installation"
    echo "  9) Install Burp Suite"
    echo "  10) Install Metasploit Framework"
    echo "  11) Exit"
    echo ""
    read -p "Enter your choice [1-11]: " choice
    
    case $choice in
        1)
            check_requirements
            install_base_dependencies
            install_recon_tools
            install_scanning_tools
            install_web_tools
            install_enumeration_tools
            install_osint_tools
            install_mobile_tools
            install_cloud_tools
            download_wordlists
            install_utilities
            setup_environment
            verify_installation
            ;;
        2)
            check_requirements
            install_base_dependencies
            install_recon_tools
            ;;
        3)
            check_requirements
            install_base_dependencies
            install_scanning_tools
            ;;
        4)
            check_requirements
            install_base_dependencies
            install_web_tools
            ;;
        5)
            check_requirements
            install_base_dependencies
            install_osint_tools
            ;;
        6)
            check_requirements
            install_base_dependencies
            install_cloud_tools
            ;;
        7)
            download_wordlists
            ;;
        8)
            verify_installation
            ;;
        9)
            install_burpsuite
            ;;
        10)
            install_metasploit
            ;;
        11)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            error "Invalid choice"
            show_menu
            ;;
    esac
}

#====================================================================
# RUN
#====================================================================
mkdir -p "$TOOLS_DIR"
touch "$LOG_FILE"

if [[ "$1" == "--full" ]]; then
    check_requirements
    install_base_dependencies
    install_recon_tools
    install_scanning_tools
    install_web_tools
    install_enumeration_tools
    install_osint_tools
    install_mobile_tools
    install_cloud_tools
    download_wordlists
    install_utilities
    setup_environment
    verify_installation
else
    show_menu
fi

echo ""
log "Installation complete! Check $LOG_FILE for details."
echo -e "${YELLOW}Remember to restart your terminal or run: source ~/.bashrc${NC}"
echo ""
