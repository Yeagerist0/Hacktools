# OWASP Top 10 Testing Checklist (2021)

A comprehensive checklist for testing the OWASP Top 10 vulnerabilities.

---

## A01:2021 - Broken Access Control

### Tests to Perform
- [ ] Test for horizontal privilege escalation
- [ ] Test for vertical privilege escalation
- [ ] Test IDOR (Insecure Direct Object References)
- [ ] Test for missing function level access control
- [ ] Test directory traversal
- [ ] Test forced browsing to authenticated pages
- [ ] Test for metadata manipulation (JWT, cookies, hidden fields)
- [ ] Test CORS misconfiguration
- [ ] Test access control bypass via:
  - [ ] URL manipulation
  - [ ] Parameter tampering
  - [ ] Referrer manipulation
  - [ ] Method changing (GET/POST)
- [ ] Test for missing access controls on APIs

### Test Payloads
```
# IDOR Testing
/api/users/1 -> /api/users/2
/profile?id=123 -> /profile?id=124

# Directory Traversal
../../../etc/passwd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd

# Forced Browsing
/admin
/dashboard
/internal
/config
```

---

## A02:2021 - Cryptographic Failures

### Tests to Perform
- [ ] Check for sensitive data in transit (HTTPS)
- [ ] Check for sensitive data at rest
- [ ] Test SSL/TLS configuration
- [ ] Check for weak cryptographic algorithms
- [ ] Test for sensitive data in URL parameters
- [ ] Check password storage mechanisms
- [ ] Test for insecure random number generation
- [ ] Check for sensitive data in error messages
- [ ] Test for sensitive data in browser cache
- [ ] Check certificate validity and chain

### Tools
```
# SSL/TLS Testing
testssl.sh https://target.com
sslyze --regular target.com
nmap --script ssl-enum-ciphers -p 443 target.com
```

---

## A03:2021 - Injection

### Tests to Perform

#### SQL Injection
- [ ] Test all input fields for SQLi
- [ ] Test URL parameters
- [ ] Test cookies
- [ ] Test HTTP headers (User-Agent, Referer, etc.)
- [ ] Test for different database types
- [ ] Test for blind SQLi (time-based, boolean-based)
- [ ] Test for second-order SQLi

#### XSS (Cross-Site Scripting)
- [ ] Test for reflected XSS
- [ ] Test for stored XSS
- [ ] Test for DOM-based XSS
- [ ] Test all input fields
- [ ] Test URL parameters
- [ ] Test file upload names
- [ ] Test JSON/XML responses

#### Command Injection
- [ ] Test for OS command injection
- [ ] Test parameter manipulation
- [ ] Test file operations

#### Other Injections
- [ ] LDAP Injection
- [ ] XPath Injection
- [ ] XML Injection
- [ ] NoSQL Injection
- [ ] Template Injection (SSTI)
- [ ] Header Injection

### Common Payloads
```
# SQL Injection
' OR '1'='1
" OR "1"="1
' OR 1=1--
' UNION SELECT NULL--
1' AND SLEEP(5)--

# XSS
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)

# Command Injection
; whoami
| whoami
`whoami`
$(whoami)
```

---

## A04:2021 - Insecure Design

### Tests to Perform
- [ ] Review threat modeling documentation
- [ ] Test for business logic flaws
- [ ] Test for race conditions
- [ ] Test for lack of rate limiting
- [ ] Test password recovery flows
- [ ] Test account creation process
- [ ] Test for predictable resource locations
- [ ] Test for trust boundary violations
- [ ] Review security requirements

### Business Logic Tests
- [ ] Price manipulation
- [ ] Quantity manipulation
- [ ] Coupon/discount abuse
- [ ] Multi-step process bypass
- [ ] Workflow circumvention

---

## A05:2021 - Security Misconfiguration

### Tests to Perform
- [ ] Check for default credentials
- [ ] Check for unnecessary features enabled
- [ ] Test error handling and stack traces
- [ ] Check security headers
- [ ] Test for directory listing
- [ ] Check for exposed admin interfaces
- [ ] Test cloud storage permissions
- [ ] Check for verbose error messages
- [ ] Test for unnecessary HTTP methods
- [ ] Check XML parser configuration (XXE)
- [ ] Review server hardening

### Security Headers to Check
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: ...
Strict-Transport-Security: max-age=...
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: ...
```

---

## A06:2021 - Vulnerable and Outdated Components

### Tests to Perform
- [ ] Identify all components and versions
- [ ] Check for known vulnerabilities (CVEs)
- [ ] Test for outdated libraries
- [ ] Check JavaScript libraries
- [ ] Test server software versions
- [ ] Check framework versions
- [ ] Review dependency list
- [ ] Test for unpatched systems

### Tools
```
# JavaScript Libraries
retire.js
npm audit
snyk test

# General
OWASP Dependency Check
nuclei (CVE templates)
```

---

## A07:2021 - Identification and Authentication Failures

### Tests to Perform
- [ ] Test for credential stuffing protection
- [ ] Test for brute force protection
- [ ] Test password strength requirements
- [ ] Test for default credentials
- [ ] Test password recovery mechanism
- [ ] Test session management
- [ ] Test for session fixation
- [ ] Test MFA implementation
- [ ] Test for weak session IDs
- [ ] Test logout functionality
- [ ] Test "remember me" functionality
- [ ] Test for account enumeration
- [ ] Test for concurrent session handling

### Session Tests
- [ ] Session ID entropy
- [ ] Session timeout
- [ ] Session invalidation on logout
- [ ] Session invalidation on password change
- [ ] Session cookie flags (HttpOnly, Secure, SameSite)

---

## A08:2021 - Software and Data Integrity Failures

### Tests to Perform
- [ ] Test for insecure deserialization
- [ ] Check for unsigned updates
- [ ] Test CI/CD pipeline security
- [ ] Check for untrusted data in serialization
- [ ] Test integrity verification mechanisms
- [ ] Check code signing
- [ ] Review plugin/module sources

### Deserialization Tests
```
# Java
ysoserial payloads

# PHP
phpggc payloads

# .NET
ysoserial.net payloads

# Python
pickle payloads
```

---

## A09:2021 - Security Logging and Monitoring Failures

### Tests to Perform
- [ ] Test if login attempts are logged
- [ ] Test if high-value transactions are logged
- [ ] Test if logs contain sensitive data
- [ ] Check log integrity mechanisms
- [ ] Test alerting mechanisms
- [ ] Check for monitoring coverage
- [ ] Test incident response procedures
- [ ] Check log retention policies

### What Should Be Logged
- Authentication successes and failures
- Access control failures
- Input validation failures
- Output encoding failures
- Security events
- High-value transactions

---

## A10:2021 - Server-Side Request Forgery (SSRF)

### Tests to Perform
- [ ] Test URL input parameters
- [ ] Test file upload URLs
- [ ] Test webhook configurations
- [ ] Test import/export features
- [ ] Test PDF generators
- [ ] Test image processors
- [ ] Test any URL fetching functionality

### SSRF Payloads
```
# Internal Services
http://localhost
http://127.0.0.1
http://[::1]
http://169.254.169.254 (AWS metadata)
http://metadata.google.internal (GCP)

# Bypass Techniques
http://127.0.0.1:80
http://127.0.0.1:443
http://0.0.0.0
http://0
http://127.1
http://2130706433 (decimal)
http://0x7f000001 (hex)

# Protocol Smuggling
file:///etc/passwd
gopher://127.0.0.1:25/
dict://127.0.0.1:11211/
```

---

## Quick Reference Commands

```bash
# Subdomain Enumeration
subfinder -d target.com -silent | httpx -silent

# Directory Fuzzing
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403

# SQLi Testing
sqlmap -u "https://target.com/page?id=1" --batch --random-agent

# XSS Testing
dalfox url "https://target.com/search?q=test"

# Nuclei Scanning
nuclei -u https://target.com -severity critical,high,medium

# Security Headers
curl -I https://target.com | grep -iE "x-|content-security|strict-"
```

---

## Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10](https://owasp.org/Top10/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
