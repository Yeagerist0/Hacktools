# Bug Bounty Toolkit

A comprehensive collection of tools, scripts, and resources for ethical bug bounty hunting and penetration testing.

```
 ____              ____                   _         _____           _ _    _ _   
| __ ) _   _  __ _| __ )  ___  _   _ _ __ | |_ _   _|_   _|__   ___ | | | _(_) |_ 
|  _ \| | | |/ _\` |  _ \ / _ \| | | | '_ \| __| | | | | |/ _ \ / _ \| | |/ / | __|
| |_) | |_| | (_| | |_) | (_) | |_| | | | | |_| |_| | | | (_) | (_) | |   <| | |_ 
|____/ \__,_|\__, |____/ \___/ \__,_|_| |_|\__|\__, | |_|\___/ \___/|_|_|\_\_|\__|
             |___/                             |___/                              
```

---

## ?????? Disclaimer

**This toolkit is for ETHICAL, LEGAL security testing only.**

Only use these tools on:
- Systems you own
- Systems you have explicit written authorization to test
- Bug bounty programs within their defined scope

Unauthorized access to computer systems is illegal. The authors are not responsible for misuse.

---

## ???? Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/HackTools.git
cd HackTools
```

### 2. Install Dependencies

```bash
# Make installer executable
chmod +x install-tools.sh hackstrike hackstrike-ai auto-hunt.sh autoscan.sh

# Run full installation (installs all security tools)
./install-tools.sh --full

# Or run interactively to choose specific tools
./install-tools.sh
```

### 3. Setup MCP Agent (Optional - for AI-powered scanning)

```bash
cd mcp-agent
npm install
npm run build
cd ..
```

### 4. Run HackStrike

```bash
# Basic scan
./hackstrike target.com

# Recon only
./hackstrike target.com --recon

# Interactive AI mode
./hackstrike-ai
```

---

## ???? Main Tools

### HackStrike - Automated Scanner

```bash
./hackstrike <target> [options]

Options:
  -f, --full        Full scan (default)
  -r, --recon       Recon only (subdomains + URLs)
  -v, --vulns       Vulnerability scan only
  -x, --xss         XSS testing only
  -s, --sqli        SQLi testing only
  -p, --ports       Port scan only
  -t, --threads N   Number of threads (default: 50)

Examples:
  ./hackstrike example.com              # Full scan
  ./hackstrike example.com --recon      # Recon only
  ./hackstrike example.com --vulns      # Vuln scan only
```

### HackStrike AI - Interactive Mode

```bash
./hackstrike-ai

Commands:
  scan <domain>        Set target
  full scan            Run complete scan
  recon                Subdomain enumeration
  find vulnerabilities Nuclei scan
  find xss             XSS testing
  find sqli            SQL injection testing
  show results         View scan results
  help                 Show all commands
```

### Auto-Hunt - Continuous Monitoring

```bash
./auto-hunt.sh targets.txt [options]

Options:
  -i, --interval N    Scan interval in hours (default: 24)
  -n, --notify        Enable notifications

Examples:
  ./auto-hunt.sh targets.txt              # Hunt with default settings
  ./auto-hunt.sh targets.txt -i 12        # Scan every 12 hours
  ./auto-hunt.sh targets.txt --notify     # With notifications
```

### AutoScan - Quick Scanner

```bash
./autoscan.sh <target> [scan-type]

Scan Types:
  quick     Quick recon (subdomains + live hosts)
  web       Web vulnerability scan
  ports     Port scan
  all       Full scan (default)

Examples:
  ./autoscan.sh example.com           # Full scan
  ./autoscan.sh example.com quick     # Quick recon
```

---

## ???? Directory Structure

```
HackTools/
????????? hackstrike            # Main automated scanner
????????? hackstrike-ai         # Interactive AI-powered scanner
????????? hackstrike.sh         # Extended scanner with more features
????????? auto-hunt.sh          # Continuous monitoring script
????????? autoscan.sh           # Quick scanner wrapper
????????? install-tools.sh      # Master installation script
????????? mcp-agent/            # AI agent (requires npm install)
????????? scripts/              # Individual tool scripts
???   ????????? recon/            # Reconnaissance scripts
???   ????????? scanning/         # Scanning scripts
???   ????????? web-testing/      # Web testing scripts
???   ????????? osint/            # OSINT scripts
????????? checklists/           # Security testing checklists
????????? reports/              # Report templates
????????? lab-setup/            # Docker lab environments
????????? wordlists/            # Wordlists (downloaded during install)
????????? results/              # Scan results (gitignored)
????????? output/               # Output files (gitignored)
```

---

## ??????? Post-Clone Setup

After cloning from GitHub, run these commands:

```bash
# 1. Make scripts executable
chmod +x hackstrike hackstrike-ai hackstrike.sh auto-hunt.sh autoscan.sh install-tools.sh

# 2. Install security tools
./install-tools.sh --full

# 3. (Optional) Setup MCP Agent for AI features
cd mcp-agent
npm install
npm run build
cd ..

# 4. Reload shell to update PATH
source ~/.bashrc   # or source ~/.zshrc
```

---

## ???? Required Tools

The `install-tools.sh` script installs these tools:

| Category | Tools |
|----------|-------|
| **Recon** | subfinder, amass, assetfinder, httpx, waybackurls, gau, katana |
| **Scanning** | nmap, naabu, nuclei, nikto |
| **Web Testing** | ffuf, gobuster, dalfox, sqlmap, arjun |
| **OSINT** | theHarvester, sherlock, recon-ng |

---

## ???? Lab Setup

Practice with vulnerable applications:

```bash
cd lab-setup
docker-compose up -d
```

| Application | URL |
|-------------|-----|
| DVWA | http://localhost:8081 |
| Juice Shop | http://localhost:3000 |
| WebGoat | http://localhost:8080/WebGoat |
| bWAPP | http://localhost:8082/bWAPP |

---

## ???? Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---

## ?????? License

This project is for educational purposes. Use responsibly and ethically.

---

**Happy (Ethical) Hacking! ????**
