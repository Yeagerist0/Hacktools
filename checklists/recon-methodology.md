# Reconnaissance Methodology

A comprehensive guide to reconnaissance for bug bounty hunting.

---

## Phase 1: Passive Reconnaissance

### 1.1 Domain Information

#### WHOIS Lookup
```bash
whois target.com
```
**What to look for:**
- Registrar information
- Registration/expiration dates
- Name servers
- Contact information
- Related domains

#### DNS Records
```bash
# All records
dig target.com ANY

# Specific records
dig target.com A
dig target.com AAAA
dig target.com MX
dig target.com TXT
dig target.com NS
dig target.com CNAME
dig target.com SOA

# Using nslookup
nslookup -type=any target.com
```

### 1.2 Subdomain Enumeration

#### Automated Tools
```bash
# Subfinder
subfinder -d target.com -o subdomains.txt

# Amass (passive)
amass enum -passive -d target.com -o amass.txt

# Assetfinder
assetfinder --subs-only target.com > assetfinder.txt

# Findomain
findomain -t target.com -o

# Combine results
cat *.txt | sort -u > all-subdomains.txt
```

#### Certificate Transparency
```bash
# crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true" | jq -r '.[].dns_names[]' | sort -u
```

#### Historical Data
```bash
# Wayback Machine
waybackurls target.com | unfurl -u domains | sort -u

# Common Crawl
curl "http://index.commoncrawl.org/CC-MAIN-2023-50-index?url=*.target.com&output=json" | jq -r '.url' | unfurl -u domains | sort -u
```

### 1.3 Google Dorking

```
# Find subdomains
site:target.com -www

# Find sensitive files
site:target.com filetype:pdf
site:target.com filetype:doc
site:target.com filetype:xls
site:target.com filetype:sql
site:target.com filetype:log
site:target.com filetype:bak
site:target.com filetype:config

# Find login pages
site:target.com inurl:login
site:target.com inurl:admin
site:target.com inurl:dashboard
site:target.com intitle:"login"

# Find exposed information
site:target.com intext:"password"
site:target.com intext:"username"
site:target.com ext:env
site:target.com ext:yml

# Find errors
site:target.com intext:"error"
site:target.com intext:"exception"
site:target.com intext:"warning"
```

### 1.4 GitHub Reconnaissance

```
# Search queries
"target.com" password
"target.com" api_key
"target.com" secret
"target.com" token
org:targetcompany password
org:targetcompany aws_key
```

**Tools:**
- [Gitrob](https://github.com/michenriksen/gitrob)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [GitDorker](https://github.com/obheda12/GitDorker)

### 1.5 OSINT

#### Employee Information
- LinkedIn for employee names
- Email format discovery
- Role enumeration

#### Technology Stack
```bash
# Wappalyzer CLI
wappalyzer https://target.com

# whatweb
whatweb https://target.com

# Builtwith
# https://builtwith.com/target.com
```

#### Shodan/Censys
```bash
# Shodan
shodan search hostname:target.com
shodan search ssl.cert.subject.cn:target.com

# Censys
# Use web interface
```

---

## Phase 2: Active Reconnaissance

### 2.1 DNS Bruteforcing

```bash
# Amass bruteforce
amass enum -brute -d target.com -o amass-brute.txt

# Gobuster DNS
gobuster dns -d target.com -w wordlist.txt -o gobuster-dns.txt

# Massdns
massdns -r resolvers.txt -t A -o S subdomains.txt > massdns.txt
```

### 2.2 DNS Zone Transfer

```bash
# Check for zone transfer
dig axfr target.com @ns1.target.com
dig axfr @ns1.target.com target.com

# Automated
dnsrecon -d target.com -t axfr
```

### 2.3 Virtual Host Discovery

```bash
# ffuf
ffuf -w vhosts.txt -u http://target.com -H "Host: FUZZ.target.com" -fs <size>

# Gobuster vhost
gobuster vhost -u http://target.com -w wordlist.txt
```

### 2.4 HTTP Probing

```bash
# Httpx (recommended)
cat subdomains.txt | httpx -silent -status-code -title -tech-detect -o httpx.txt

# Httprobe
cat subdomains.txt | httprobe > live-hosts.txt
```

### 2.5 Port Scanning

```bash
# Quick scan
nmap -T4 --top-ports 1000 -iL live-hosts.txt -oA nmap-quick

# Full scan
nmap -T4 -p- -iL live-hosts.txt -oA nmap-full

# Service detection
nmap -sV -sC -p <ports> -iL live-hosts.txt -oA nmap-services

# Masscan (fast)
masscan -p1-65535 --rate=1000 -iL ips.txt -oL masscan.txt

# RustScan (very fast)
rustscan -a target.com --ulimit 5000
```

### 2.6 Directory Enumeration

```bash
# ffuf
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403,500 -o dirs.json

# Gobuster
gobuster dir -u https://target.com -w wordlist.txt -o dirs.txt

# Feroxbuster (recursive)
feroxbuster -u https://target.com -w wordlist.txt -o dirs.txt
```

### 2.7 URL Collection

```bash
# Waybackurls
waybackurls target.com > wayback.txt

# Gau
gau target.com > gau.txt

# Katana (crawling)
katana -u https://target.com -d 3 -o katana.txt

# GoSpider
gospider -s https://target.com -d 2 -o gospider/

# Combine
cat wayback.txt gau.txt katana.txt | sort -u > all-urls.txt
```

### 2.8 JavaScript Analysis

```bash
# Extract JS files
grep -iE "\.js(\?|$)" all-urls.txt | sort -u > js-files.txt

# Download and analyze
while read url; do
    curl -s "$url" >> all-js.txt
done < js-files.txt

# Find endpoints in JS
cat all-js.txt | grep -oE '"\/[^"]+"|"https?://[^"]+' | sort -u > js-endpoints.txt

# LinkFinder
python3 linkfinder.py -i https://target.com/app.js -o cli
```

### 2.9 Parameter Discovery

```bash
# Arjun
arjun -u https://target.com/page

# ParamSpider
paramspider -d target.com

# Extract from URLs
cat all-urls.txt | grep "=" | sort -u > params.txt
```

---

## Phase 3: Organization & Analysis

### 3.1 Categorize Assets

```bash
# Categorize by status code
cat httpx.txt | grep "200" > 200-responses.txt
cat httpx.txt | grep "403" > 403-responses.txt

# Categorize by technology
cat httpx.txt | grep -i "wordpress" > wordpress-sites.txt
cat httpx.txt | grep -i "nginx" > nginx-servers.txt

# Categorize URLs by type
grep -iE "\.php(\?|$)" all-urls.txt > php-files.txt
grep -iE "/api/" all-urls.txt > api-endpoints.txt
grep -iE "\.json(\?|$)" all-urls.txt > json-endpoints.txt
```

### 3.2 Identify Attack Surface

Priority targets:
1. Login/registration pages
2. Password reset functionality
3. File upload features
4. API endpoints
5. Admin panels
6. Forms with parameters
7. Search functionality
8. User profile pages

### 3.3 Technology Mapping

Create a map of:
- Web servers (Apache, Nginx, IIS)
- Programming languages (PHP, Python, Java, Node.js)
- Frameworks (Laravel, Django, Spring, Express)
- CMS platforms (WordPress, Drupal, Joomla)
- Database technologies
- CDN providers
- Cloud services

---

## Automation Script

Save as `recon.sh`:

```bash
#!/bin/bash

DOMAIN=$1
OUTPUT="./recon-$DOMAIN"

mkdir -p $OUTPUT

echo "[*] Starting recon for $DOMAIN"

# Subdomain enumeration
echo "[*] Subdomain enumeration..."
subfinder -d $DOMAIN -silent -o $OUTPUT/subfinder.txt
assetfinder --subs-only $DOMAIN > $OUTPUT/assetfinder.txt
amass enum -passive -d $DOMAIN -o $OUTPUT/amass.txt

# Combine and dedupe
cat $OUTPUT/*.txt | sort -u > $OUTPUT/all-subdomains.txt
echo "[+] Found $(wc -l < $OUTPUT/all-subdomains.txt) subdomains"

# DNS resolution
echo "[*] DNS resolution..."
dnsx -l $OUTPUT/all-subdomains.txt -silent -o $OUTPUT/resolved.txt

# HTTP probing
echo "[*] HTTP probing..."
httpx -l $OUTPUT/resolved.txt -silent -status-code -title -tech-detect -o $OUTPUT/httpx.txt
httpx -l $OUTPUT/resolved.txt -silent -o $OUTPUT/live-hosts.txt

echo "[+] Found $(wc -l < $OUTPUT/live-hosts.txt) live hosts"

# URL collection
echo "[*] URL collection..."
cat $OUTPUT/all-subdomains.txt | waybackurls > $OUTPUT/wayback.txt
cat $OUTPUT/all-subdomains.txt | gau > $OUTPUT/gau.txt
cat $OUTPUT/wayback.txt $OUTPUT/gau.txt | sort -u > $OUTPUT/all-urls.txt

echo "[+] Found $(wc -l < $OUTPUT/all-urls.txt) URLs"

# Vulnerability scanning
echo "[*] Running Nuclei..."
nuclei -l $OUTPUT/live-hosts.txt -severity critical,high,medium -o $OUTPUT/nuclei.txt

echo "[+] Recon complete! Results in $OUTPUT/"
```

---

## Recommended Wordlists

- **Subdomains:** SecLists/Discovery/DNS/subdomains-top1million-5000.txt
- **Directories:** SecLists/Discovery/Web-Content/raft-medium-directories.txt
- **Files:** SecLists/Discovery/Web-Content/raft-medium-files.txt
- **Parameters:** SecLists/Discovery/Web-Content/burp-parameter-names.txt
- **Passwords:** SecLists/Passwords/Common-Credentials/10k-most-common.txt

---

## Tips

1. **Document everything** - Keep notes of what you find
2. **Use multiple tools** - Each tool has different sources
3. **Check historical data** - Wayback Machine is valuable
4. **Monitor for changes** - Set up continuous monitoring
5. **Look for patterns** - Naming conventions reveal structure
6. **Don't skip small findings** - They might lead to bigger issues
7. **Correlate data** - Cross-reference different sources
