# Proof of Concept (PoC) Documentation Template

This template helps you document exploits and proof of concepts properly for bug bounty submissions.

---

## Vulnerability Information

| Field | Value |
|-------|-------|
| **Vulnerability Type** | [XSS/SQLi/SSRF/etc.] |
| **Target** | [URL or Asset] |
| **Discovery Date** | [YYYY-MM-DD] |
| **Severity** | [Critical/High/Medium/Low] |
| **CVSS Score** | [X.X] |

---

## Environment Setup

### Testing Environment
- **Browser:** [Chrome/Firefox/Safari + Version]
- **Operating System:** [Windows/Linux/macOS]
- **Proxy Tool:** [Burp Suite/OWASP ZAP]
- **Other Tools:** [List any other tools used]

### Account Requirements
- **Account Type:** [Guest/User/Admin]
- **Permissions Needed:** [List any required permissions]
- **Test Account:** [If applicable, how to create test account]

---

## Vulnerability Details

### Vulnerable Endpoint
```
URL: https://example.com/api/endpoint
Method: POST
Content-Type: application/json
```

### Vulnerable Parameter
```
Parameter Name: user_input
Location: [Body/Query/Header/Cookie]
Type: [String/Integer/File/etc.]
```

### Root Cause
[Explain why this vulnerability exists - missing validation, improper encoding, etc.]

---

## Exploitation Steps

### Step 1: [Title]
**Action:** [What to do]
**Expected Result:** [What should happen]

```
[Any code, command, or request]
```

**Screenshot:**
![Step 1](screenshots/step1.png)

---

### Step 2: [Title]
**Action:** [What to do]
**Expected Result:** [What should happen]

```
[Any code, command, or request]
```

**Screenshot:**
![Step 2](screenshots/step2.png)

---

### Step 3: [Title]
**Action:** [What to do]
**Expected Result:** [What should happen]

```
[Any code, command, or request]
```

**Screenshot:**
![Step 3](screenshots/step3.png)

---

## Payloads

### Basic Payload
```
[Your basic payload]
```

### Encoded Payload (if needed)
```
[URL encoded or otherwise encoded version]
```

### Explanation
[Explain what the payload does and why it works]

---

## HTTP Traffic

### Request
```http
POST /api/vulnerable HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: application/json
Content-Type: application/json
Cookie: session=eyJhbGciOiJIUzI1NiJ9...
Content-Length: 50

{
  "parameter": "malicious_payload_here"
}
```

### Response
```http
HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 12:00:00 GMT
Content-Type: application/json
Content-Length: 150

{
  "status": "success",
  "data": {
    "sensitive_info": "exposed_data"
  }
}
```

---

## Automated PoC Script

### Python Script
```python
#!/usr/bin/env python3
"""
PoC for [Vulnerability Name]
Target: [URL]
Author: [Your Name]
Date: [Date]

Usage: python3 poc.py [arguments]
"""

import requests
import sys

def exploit(target, payload):
    """
    Exploit the vulnerability
    """
    url = f"{target}/vulnerable-endpoint"
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0"
    }
    
    data = {
        "parameter": payload
    }
    
    try:
        response = requests.post(url, json=data, headers=headers)
        
        if "expected_indicator" in response.text:
            print(f"[+] Vulnerability confirmed!")
            print(f"[+] Response: {response.text}")
            return True
        else:
            print(f"[-] Exploitation failed")
            return False
            
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    payload = "your_payload_here"
    
    print(f"[*] Target: {target}")
    print(f"[*] Payload: {payload}")
    
    exploit(target, payload)
```

### Curl Command
```bash
curl -X POST "https://example.com/api/vulnerable" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=your_session_here" \
  -d '{"parameter": "payload_here"}'
```

---

## Impact Demonstration

### What was accessed/modified
- [List specific data or functionality compromised]
- [Include evidence like database contents, file contents, etc.]

### Screenshots/Evidence
1. **Before exploitation:** [Screenshot showing normal state]
2. **During exploitation:** [Screenshot showing payload execution]
3. **After exploitation:** [Screenshot showing impact/result]

### Video Demonstration
[Link to video or note that video is attached]

---

## Limitations & Notes

### Limitations
- [Any limitations of the exploit]
- [Required conditions]
- [What doesn't work]

### Detection
- [How this attack might be detected]
- [Log entries that would be created]

### Notes for Triagers
- [Any additional context]
- [Known issues with reproduction]
- [Alternative exploitation methods]

---

## Remediation Verification

### How to verify the fix
1. [Step to verify fix works]
2. [Expected behavior after fix]

### Test cases
```
[Payload that should now fail]
Expected result: [Blocked/Error/etc.]
```

---

## References

- **CWE:** [CWE-XXX - Vulnerability Name](https://cwe.mitre.org/data/definitions/XXX.html)
- **OWASP:** [Relevant OWASP page](https://owasp.org/...)
- **Related Research:** [Links to related research or blog posts]

---

## Files Included

- [ ] `poc.py` - Automated exploit script
- [ ] `request.txt` - Raw HTTP request
- [ ] `response.txt` - HTTP response
- [ ] `screenshots/` - Directory with screenshots
- [ ] `video.mp4` - Video demonstration

---

## Disclaimer

This proof of concept is provided for authorized security testing only. Only use on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.
