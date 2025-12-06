# Bug Bounty Methodology Checklist

## Pre-Engagement Checklist

- [ ] Read and understand the program's scope
- [ ] Identify in-scope domains and applications
- [ ] Note out-of-scope items
- [ ] Understand vulnerability types they're interested in
- [ ] Check payout ranges and severity definitions
- [ ] Review program rules and disclosure policies
- [ ] Set up dedicated testing environment

---

## Phase 1: Reconnaissance

### 1.1 Passive Reconnaissance
- [ ] WHOIS lookup for domain information
- [ ] DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME)
- [ ] Subdomain enumeration
  - [ ] Subfinder
  - [ ] Amass (passive)
  - [ ] Assetfinder
  - [ ] crt.sh (Certificate Transparency)
  - [ ] SecurityTrails API
  - [ ] Wayback Machine
- [ ] Google dorking for sensitive information
- [ ] GitHub/GitLab reconnaissance
- [ ] Shodan/Censys for exposed services
- [ ] Social media OSINT
- [ ] Employee enumeration (LinkedIn)
- [ ] Technology stack identification
- [ ] Check for acquisitions/related companies

### 1.2 Active Reconnaissance
- [ ] Subdomain bruteforcing
- [ ] DNS zone transfer attempts
- [ ] Virtual host discovery
- [ ] Port scanning (top 1000, then full)
- [ ] Service version detection
- [ ] Web application fingerprinting
- [ ] WAF detection
- [ ] CMS identification
- [ ] Directory/file bruteforcing
- [ ] JavaScript file analysis
- [ ] API endpoint discovery

---

## Phase 2: Scanning & Enumeration

### 2.1 Port Scanning
- [ ] TCP scan (top ports)
- [ ] TCP scan (all ports)
- [ ] UDP scan (common ports)
- [ ] Service version detection
- [ ] OS fingerprinting
- [ ] Script scanning (safe scripts)

### 2.2 Web Application Scanning
- [ ] HTTP methods enumeration
- [ ] Directory enumeration
- [ ] File extension bruteforcing
- [ ] Parameter discovery
- [ ] Hidden parameter mining
- [ ] Backup file detection
- [ ] Configuration file exposure
- [ ] robots.txt and sitemap.xml analysis
- [ ] Technology detection (Wappalyzer)

### 2.3 Vulnerability Scanning
- [ ] Nuclei scanning (all severities)
- [ ] Nikto scanning
- [ ] SSL/TLS configuration check
- [ ] Security header analysis
- [ ] Cookie security flags

---

## Phase 3: Vulnerability Assessment

### 3.1 Authentication Testing
- [ ] Default credentials
- [ ] Brute force protection
- [ ] Account lockout mechanism
- [ ] Password policy strength
- [ ] Password reset functionality
- [ ] Remember me functionality
- [ ] Session management
- [ ] Multi-factor authentication bypass
- [ ] OAuth/SAML misconfiguration

### 3.2 Authorization Testing
- [ ] Horizontal privilege escalation
- [ ] Vertical privilege escalation
- [ ] IDOR vulnerabilities
- [ ] Missing function level access control
- [ ] Insecure direct object references
- [ ] Path traversal

### 3.3 Injection Testing
- [ ] SQL Injection
  - [ ] Error-based
  - [ ] Union-based
  - [ ] Blind (Boolean)
  - [ ] Blind (Time-based)
  - [ ] Out-of-band
- [ ] Cross-Site Scripting (XSS)
  - [ ] Reflected XSS
  - [ ] Stored XSS
  - [ ] DOM-based XSS
- [ ] Command Injection
- [ ] LDAP Injection
- [ ] XML Injection
- [ ] XPath Injection
- [ ] Template Injection (SSTI)
- [ ] Header Injection
- [ ] NoSQL Injection

### 3.4 Client-Side Vulnerabilities
- [ ] Cross-Site Request Forgery (CSRF)
- [ ] Clickjacking
- [ ] Open Redirects
- [ ] HTML Injection
- [ ] CSS Injection
- [ ] WebSocket vulnerabilities

### 3.5 Business Logic Flaws
- [ ] Price manipulation
- [ ] Quantity manipulation
- [ ] Coupon/discount abuse
- [ ] Race conditions
- [ ] Workflow bypass
- [ ] Function abuse

### 3.6 File Upload Vulnerabilities
- [ ] Unrestricted file upload
- [ ] File type bypass
- [ ] File size limits
- [ ] Path traversal in filename
- [ ] Metadata injection

### 3.7 API Security
- [ ] API authentication
- [ ] Rate limiting
- [ ] Input validation
- [ ] Mass assignment
- [ ] Excessive data exposure
- [ ] Security misconfiguration
- [ ] Injection attacks
- [ ] Broken object level authorization

### 3.8 Server-Side Vulnerabilities
- [ ] Server-Side Request Forgery (SSRF)
- [ ] XML External Entity (XXE)
- [ ] Remote Code Execution
- [ ] Local File Inclusion
- [ ] Remote File Inclusion
- [ ] Insecure Deserialization

### 3.9 Information Disclosure
- [ ] Error messages
- [ ] Stack traces
- [ ] Debug information
- [ ] Comments in source code
- [ ] Exposed admin panels
- [ ] Exposed documentation
- [ ] Version disclosure
- [ ] Internal IP disclosure

---

## Phase 4: Exploitation & Validation

- [ ] Validate all findings
- [ ] Determine actual impact
- [ ] Chain vulnerabilities if possible
- [ ] Document reproduction steps
- [ ] Create proof of concept
- [ ] Capture evidence (screenshots, videos)
- [ ] Test in multiple browsers/environments
- [ ] Verify scope compliance

---

## Phase 5: Reporting

- [ ] Clear vulnerability title
- [ ] Severity assessment (CVSS)
- [ ] Detailed description
- [ ] Step-by-step reproduction
- [ ] Proof of concept code/screenshots
- [ ] Impact assessment
- [ ] Remediation recommendations
- [ ] References and resources
- [ ] Review report before submission

---

## Tools by Phase

### Reconnaissance
```
subfinder, amass, assetfinder, findomain
httpx, httprobe
waybackurls, gau, katana
dnsx, massdns
```

### Scanning
```
nmap, masscan, rustscan, naabu
nuclei, nikto
ffuf, gobuster, feroxbuster
```

### Web Testing
```
burp suite, OWASP ZAP
sqlmap, dalfox, xsstrike
arjun, paramspider
```

### Exploitation
```
metasploit (if authorized)
custom scripts
```

---

## Notes
- Always stay within scope
- Document everything
- Don't cause damage
- Report responsibly
- Follow program rules
