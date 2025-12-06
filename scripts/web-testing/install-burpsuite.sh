#!/bin/bash

#====================================================================
#  BURP SUITE INSTALLATION SCRIPT
#====================================================================
#  Installs Burp Suite Community Edition for web application testing
#  
#  Note: Burp Suite Professional requires a license purchase
#====================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="$HOME/HackTools/web-testing/burpsuite"

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           BURP SUITE INSTALLATION                         ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

#====================================================================
# CHECK JAVA
#====================================================================
check_java() {
    echo -e "${YELLOW}[*] Checking Java installation...${NC}"
    
    if command -v java &> /dev/null; then
        JAVA_VERSION=$(java -version 2>&1 | head -1 | cut -d'"' -f2)
        echo -e "${GREEN}[+] Java installed: $JAVA_VERSION${NC}"
    else
        echo -e "${YELLOW}[!] Java not found. Installing...${NC}"
        
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y default-jdk
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y java-latest-openjdk
        elif command -v pacman &> /dev/null; then
            sudo pacman -S --noconfirm jdk-openjdk
        elif command -v brew &> /dev/null; then
            brew install openjdk
        fi
        
        echo -e "${GREEN}[+] Java installed${NC}"
    fi
}

#====================================================================
# INSTALL BURP SUITE COMMUNITY
#====================================================================
install_burp_community() {
    echo -e "${YELLOW}[*] Installing Burp Suite Community Edition...${NC}"
    
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    
    # Check if already installed
    if [[ -f "$INSTALL_DIR/burpsuite_community.jar" ]]; then
        echo -e "${GREEN}[+] Burp Suite already installed at $INSTALL_DIR${NC}"
        return
    fi
    
    # Download latest version
    echo -e "${BLUE}[>] Downloading Burp Suite Community...${NC}"
    
    # Method 1: Direct JAR download (stable)
    BURP_VERSION="2024.1.1.6"
    BURP_URL="https://portswigger-cdn.net/burp/releases/download?product=community&version=${BURP_VERSION}&type=Jar"
    
    wget -q --show-progress -O burpsuite_community.jar "$BURP_URL" 2>/dev/null || {
        # Method 2: Try alternative download
        echo -e "${YELLOW}[!] Direct download failed, trying alternative...${NC}"
        
        # Check if available in package manager
        if command -v apt-get &> /dev/null; then
            # On Kali, Burp is in repos
            sudo apt-get install -y burpsuite 2>/dev/null && {
                echo -e "${GREEN}[+] Burp Suite installed via package manager${NC}"
                return
            }
        fi
        
        echo -e "${YELLOW}[!] Please download manually from: https://portswigger.net/burp/communitydownload${NC}"
        echo -e "${YELLOW}[!] Save the JAR file to: $INSTALL_DIR/burpsuite_community.jar${NC}"
        return
    }
    
    echo -e "${GREEN}[+] Burp Suite Community downloaded${NC}"
    
    # Create launcher script
    create_launcher
}

#====================================================================
# INSTALL BURP SUITE PRO (Manual)
#====================================================================
install_burp_pro_instructions() {
    echo -e "${CYAN}"
    echo "═══════════════════════════════════════════════════════════"
    echo "  BURP SUITE PROFESSIONAL INSTALLATION"
    echo "═══════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo ""
    echo "Burp Suite Professional requires a license purchase."
    echo ""
    echo "Steps to install:"
    echo "  1. Purchase license at: https://portswigger.net/burp/pro"
    echo "  2. Download the installer from your account"
    echo "  3. Run the installer:"
    echo "     - Linux: chmod +x burpsuite_pro_linux.sh && ./burpsuite_pro_linux.sh"
    echo "     - macOS: Open the .dmg file"
    echo "  4. Enter your license key when prompted"
    echo ""
    echo "Or place the JAR file at: $INSTALL_DIR/burpsuite_pro.jar"
    echo ""
}

#====================================================================
# CREATE LAUNCHER
#====================================================================
create_launcher() {
    echo -e "${YELLOW}[*] Creating launcher script...${NC}"
    
    # Launcher for Community
    cat > "$INSTALL_DIR/burp.sh" << 'EOF'
#!/bin/bash
# Burp Suite Launcher
# Allocates 2GB RAM by default, adjust -Xmx as needed

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/burpsuite_pro.jar" ]]; then
    java -Xmx2g -jar "$SCRIPT_DIR/burpsuite_pro.jar" "$@"
elif [[ -f "$SCRIPT_DIR/burpsuite_community.jar" ]]; then
    java -Xmx2g -jar "$SCRIPT_DIR/burpsuite_community.jar" "$@"
else
    echo "Burp Suite JAR not found in $SCRIPT_DIR"
    echo "Please download from https://portswigger.net/burp"
    exit 1
fi
EOF
    
    chmod +x "$INSTALL_DIR/burp.sh"
    
    # Create symlink in /usr/local/bin
    sudo ln -sf "$INSTALL_DIR/burp.sh" /usr/local/bin/burp 2>/dev/null || {
        echo -e "${YELLOW}[!] Could not create symlink. Run with: $INSTALL_DIR/burp.sh${NC}"
    }
    
    echo -e "${GREEN}[+] Launcher created. Run 'burp' or '$INSTALL_DIR/burp.sh'${NC}"
}

#====================================================================
# BURP EXTENSIONS RECOMMENDATIONS
#====================================================================
show_extensions() {
    echo -e "${CYAN}"
    echo "═══════════════════════════════════════════════════════════"
    echo "  RECOMMENDED BURP EXTENSIONS"
    echo "═══════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo ""
    echo "Install via Extender > BApp Store:"
    echo ""
    echo "Essential Extensions:"
    echo "  • Logger++          - Enhanced logging"
    echo "  • Autorize          - Authorization testing"
    echo "  • Param Miner       - Hidden parameter discovery"
    echo "  • Active Scan++     - Enhanced scanning"
    echo "  • Turbo Intruder    - Fast fuzzing (Pro)"
    echo "  • Collaborator Everywhere - OOB testing (Pro)"
    echo ""
    echo "Useful Extensions:"
    echo "  • JSON Beautifier"
    echo "  • JWT Editor"
    echo "  • Hackvertor"
    echo "  • Software Vulnerability Scanner"
    echo "  • JS Link Finder"
    echo "  • Upload Scanner"
    echo "  • Reflected Parameters"
    echo ""
}

#====================================================================
# BURP CONFIGURATION TIPS
#====================================================================
show_config_tips() {
    echo -e "${CYAN}"
    echo "═══════════════════════════════════════════════════════════"
    echo "  BURP SUITE CONFIGURATION TIPS"
    echo "═══════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo ""
    echo "1. PROXY SETUP:"
    echo "   - Burp listens on 127.0.0.1:8080 by default"
    echo "   - Configure browser to use this proxy"
    echo "   - Install Burp's CA certificate for HTTPS"
    echo ""
    echo "2. BROWSER SETUP:"
    echo "   - Use Burp's embedded browser (Proxy > Intercept > Open Browser)"
    echo "   - Or configure Firefox with FoxyProxy extension"
    echo ""
    echo "3. SCOPE CONFIGURATION:"
    echo "   - Target > Scope > Add target domain"
    echo "   - Enable 'Use advanced scope control'"
    echo ""
    echo "4. CERTIFICATE INSTALLATION:"
    echo "   - Visit http://burp in browser while proxy is running"
    echo "   - Download CA Certificate"
    echo "   - Import to browser/system trust store"
    echo ""
    echo "5. PERFORMANCE:"
    echo "   - Increase memory: java -Xmx4g -jar burpsuite.jar"
    echo "   - Disable unused extensions"
    echo ""
}

#====================================================================
# CREATE BURP PROJECT CONFIG
#====================================================================
create_project_config() {
    echo -e "${YELLOW}[*] Creating default project configuration...${NC}"
    
    mkdir -p "$INSTALL_DIR/configs"
    
    cat > "$INSTALL_DIR/configs/default-project.json" << 'EOF'
{
    "project_options": {
        "connections": {
            "platform_authentication": {
                "prompt_on_authentication_failure": false
            }
        },
        "http": {
            "redirections": {
                "follow_redirections": true
            }
        },
        "misc": {
            "logging": {
                "requests": {
                    "all_tools": true
                },
                "responses": {
                    "all_tools": true
                }
            }
        }
    },
    "proxy": {
        "http_history_display_filter": {
            "by_file_extension": {
                "hide_specific": [".css", ".gif", ".png", ".jpg", ".jpeg", ".ico", ".woff", ".woff2", ".svg"]
            }
        },
        "intercept": {
            "intercept_client_requests": {
                "automatically_fix_missing_or_superfluous_new_lines_at_end_of_request": true
            }
        }
    },
    "target": {
        "scope": {
            "advanced_mode": true
        }
    }
}
EOF

    echo -e "${GREEN}[+] Default config created at: $INSTALL_DIR/configs/${NC}"
}

#====================================================================
# MAIN
#====================================================================
main() {
    echo ""
    echo "Select option:"
    echo ""
    echo "  1) Install Burp Suite Community Edition"
    echo "  2) Show Burp Suite Pro installation instructions"
    echo "  3) Show recommended extensions"
    echo "  4) Show configuration tips"
    echo "  5) Create launcher script only"
    echo "  6) Full setup (install + config + tips)"
    echo "  7) Exit"
    echo ""
    read -p "Enter choice [1-7]: " choice
    
    case $choice in
        1)
            check_java
            install_burp_community
            create_project_config
            ;;
        2)
            install_burp_pro_instructions
            ;;
        3)
            show_extensions
            ;;
        4)
            show_config_tips
            ;;
        5)
            create_launcher
            ;;
        6)
            check_java
            install_burp_community
            create_project_config
            show_extensions
            show_config_tips
            ;;
        7)
            exit 0
            ;;
        *)
            echo "Invalid choice"
            ;;
    esac
}

# Run with argument or show menu
if [[ "$1" == "--install" ]]; then
    check_java
    install_burp_community
    create_project_config
elif [[ "$1" == "--help" ]]; then
    echo "Usage: $0 [--install|--help]"
    echo "  --install  : Auto-install Burp Suite Community"
    echo "  --help     : Show this help"
    echo "  (no args)  : Interactive menu"
else
    main
fi

echo ""
echo -e "${GREEN}[+] Done!${NC}"
