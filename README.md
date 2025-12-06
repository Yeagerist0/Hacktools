# Bug Bounty Toolkit

A comprehensive collection of tools, scripts, and resources for ethical bug bounty hunting and penetration testing.

```
 ____              ____                   _         _____           _ _    _ _   
| __ ) _   _  __ _| __ )  ___  _   _ _ __ | |_ _   _|_   _|__   ___ | | | _(_) |_ 
|  _ \| | | |/ _` |  _ \ / _ \| | | | '_ \| __| | | | | |/ _ \ / _ \| | |/ / | __|
| |_) | |_| | (_| | |_) | (_) | |_| | | | | |_| |_| | | | (_) | (_) | |   <| | |_ 
|____/ \__,_|\__, |____/ \___/ \__,_|_| |_|\__|\__, | |_|\___/ \___/|_|_|\_\_|\__|
             |___/                             |___/                              
```

---

## ⚠️ Disclaimer

**This toolkit is for ETHICAL, LEGAL security testing only.**

Only use these tools on:
- Systems you own
- Systems you have explicit written authorization to test
- Bug bounty programs within their defined scope

Unauthorized access to computer systems is illegal. The authors are not responsible for misuse.

---

## 📁 Directory Structure

```
HackTools/
├── install-tools.sh          # Master installation script
├── scripts/
│   ├── recon/
│   │   ├── subdomain-enum.sh # Subdomain enumeration
│   │   ├── full-recon.sh     # Complete recon automation
│   │   └── url-collector.sh  # URL collection
│   ├── scanning/
│   │   ├── port-scan.sh      # Port scanning
│   │   └── nuclei-scan.sh    # Vulnerability scanning
│   ├── web-testing/
│   │   ├── web-fuzz.sh       # Directory/file fuzzing
│   │   ├── xss-test.sh       # XSS testing
│   │   └── sqli-test.sh      # SQL injection testing
│   └── osint/
│       └── osint.sh          # OSINT automation
├── checklists/
│   ├── bug-bounty-methodology.md
│   ├── owasp-top10-checklist.md
│   └── recon-methodology.md
├── reports/
│   ├── bug-report-template.md
│   └── poc-template.md
├── lab-setup/
│   ├── lab-setup-guide.md
│   └── docker-compose.yml
├── wordlists/                # Downloaded wordlists
├── output/                   # Scan results
└── aliases.sh               # Shell aliases
```

---

## 🚀 Quick Start

### 1. Install Tools

```bash
# Make installer executable
chmod +x install-tools.sh

# Run full installation
./install-tools.sh --full

# Or run interactively
./install-tools.sh
```

### 2. Set Up Aliases

```bash
# Add to your shell config
source ~/HackTools/aliases.sh

# Or add permanently
echo 'source ~/HackTools/aliases.sh' >> ~/.bashrc
source ~/.bashrc
```

### 3. Run Your First Recon

```bash
# Make scripts executable
chmod +x scripts/**/*.sh

# Run subdomain enumeration
./scripts/recon/subdomain-enum.sh target.com

# Or run full recon
./scripts/recon/full-recon.sh target.com
```

---

## 🛠️ Available Scripts

### Reconnaissance

| Script | Description | Usage |
|--------|-------------|-------|
| `subdomain-enum.sh` | Enumerate subdomains | `./subdomain-enum.sh domain.com` |
| `full-recon.sh` | Complete recon pipeline | `./full-recon.sh domain.com` |
| `url-collector.sh` | Collect URLs from sources | `./url-collector.sh domain.com` |

### Scanning

| Script | Description | Usage |
|--------|-------------|-------|
| `port-scan.sh` | Port scanning with Nmap/RustScan | `./port-scan.sh target` |
| `nuclei-scan.sh` | Vulnerability scanning | `./nuclei-scan.sh target.com quick` |

### Web Testing

| Script | Description | Usage |
|--------|-------------|-------|
| `web-fuzz.sh` | Directory/file fuzzing | `./web-fuzz.sh https://target.com` |
| `xss-test.sh` | XSS vulnerability testing | `./xss-test.sh urls.txt` |
| `sqli-test.sh` | SQL injection testing | `./sqli-test.sh url` |

### OSINT

| Script | Description | Usage |
|--------|-------------|-------|
| `osint.sh` | Open source intelligence | `./osint.sh target` |

---

## 📋 Checklists

- **Bug Bounty Methodology** - Complete workflow from recon to reporting
- **OWASP Top 10** - Testing checklist for all OWASP categories
- **Recon Methodology** - Detailed reconnaissance guide

---

## 📝 Report Templates

- **Bug Report Template** - Professional vulnerability report format
- **PoC Template** - Proof of concept documentation

---

## 🧪 Lab Setup

Start practice environments with Docker:

```bash
cd lab-setup
docker-compose up -d
```

Access vulnerable applications:
- DVWA: http://localhost:8081
- Juice Shop: http://localhost:3000
- WebGoat: http://localhost:8080/WebGoat
- bWAPP: http://localhost:8082/bWAPP

---

## 🔧 Tool Categories

### Reconnaissance
- Subfinder, Amass, Assetfinder, Findomain
- Httpx, Httprobe
- Waybackurls, Gau, Katana
- DNSx, MassDNS

### Scanning
- Nmap, Masscan, RustScan, Naabu
- Nuclei, Nikto

### Web Testing
- Ffuf, Gobuster, Feroxbuster
- SQLMap, Dalfox, XSStrike
- Arjun, ParamSpider
- Burp Suite (manual install required)

### OSINT
- theHarvester, Sherlock
- Recon-ng, Photon

### Enumeration
- Enum4linux-ng, SMBMap
- Kerbrute, Ldapdomaindump

---

## 📚 Resources

### Learning Platforms
- [Hack The Box](https://hackthebox.com)
- [TryHackMe](https://tryhackme.com)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [PentesterLab](https://pentesterlab.com)

### Documentation
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

### Bug Bounty Platforms
- [HackerOne](https://hackerone.com)
- [Bugcrowd](https://bugcrowd.com)
- [Intigriti](https://intigriti.com)
- [YesWeHack](https://yeswehack.com)

---

## 🔄 Updating

```bash
# Update tools
./install-tools.sh  # Select option 8 to verify, then reinstall as needed

# Update Nuclei templates
nuclei -update-templates
```

---

## 📄 License

This project is for educational purposes. Use responsibly and ethically.

---

## 🤝 Contributing

Feel free to add more scripts, tools, or checklists to enhance this toolkit.

---

**Happy (Ethical) Hacking! 🎯**
