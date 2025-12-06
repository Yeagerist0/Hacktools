# Burp Suite Cheat Sheet

Quick reference for Burp Suite usage in bug bounty hunting.

---

## Getting Started

### Starting Burp Suite
```bash
# If installed via toolkit
burp

# Or directly
java -Xmx2g -jar burpsuite_community.jar
```

### Proxy Configuration

**Burp Default Proxy:** `127.0.0.1:8080`

**Firefox Setup:**
1. Settings > Network Settings > Manual proxy configuration
2. HTTP Proxy: `127.0.0.1` Port: `8080`
3. Check "Also use this proxy for HTTPS"

**Or use FoxyProxy extension** (recommended)

### CA Certificate Installation

1. With proxy configured, visit: `http://burp`
2. Click "CA Certificate" to download
3. Import to browser:
   - Firefox: Settings > Privacy & Security > Certificates > Import
   - Chrome: Settings > Security > Manage certificates > Import

---

## Essential Tabs

### Target Tab
- **Site map:** Visual representation of application
- **Scope:** Define what's in scope for testing
- **Issue definitions:** Vulnerability descriptions

### Proxy Tab
- **Intercept:** Capture and modify requests
- **HTTP history:** All proxied requests
- **WebSockets history:** WebSocket messages
- **Options:** Proxy listener configuration

### Intruder Tab
- **Positions:** Mark injection points
- **Payloads:** Configure attack payloads
- **Options:** Attack configuration
- **Attack types:**
  - Sniper: Single payload, one position at a time
  - Battering ram: Same payload all positions
  - Pitchfork: Different payloads, synchronized
  - Cluster bomb: All payload combinations

### Repeater Tab
- Manually modify and resend requests
- Compare responses
- Track request history

### Scanner Tab (Pro only)
- Automated vulnerability scanning
- Passive and active scanning
- Issue reporting

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+R` | Send to Repeater |
| `Ctrl+I` | Send to Intruder |
| `Ctrl+S` | Send to Scanner (Pro) |
| `Ctrl+U` | URL encode selection |
| `Ctrl+Shift+U` | URL decode selection |
| `Ctrl+B` | Base64 encode selection |
| `Ctrl+Shift+B` | Base64 decode selection |
| `Ctrl+H` | HTML encode selection |
| `Ctrl+F` | Search |
| `Ctrl+Space` | Toggle intercept |

---

## Common Workflows

### 1. Mapping the Application
```
1. Set scope (Target > Scope > Add)
2. Browse the application with proxy on
3. Review Site map for all endpoints
4. Right-click > "Spider this host" (Pro)
```

### 2. Testing Parameters
```
1. Find request in HTTP history
2. Right-click > Send to Repeater
3. Modify parameter values
4. Click "Send" to test
5. Compare responses
```

### 3. Fuzzing with Intruder
```
1. Send request to Intruder (Ctrl+I)
2. Clear default positions (Clear §)
3. Select parameter value > Add §
4. Go to Payloads tab
5. Load payload list
6. Start attack
```

### 4. Authentication Testing
```
1. Capture login request
2. Send to Intruder
3. Mark username/password fields
4. Use Cluster bomb attack
5. Load username and password lists
6. Analyze responses by length/status
```

---

## Useful Intruder Payloads

### SQL Injection
```
'
"
' OR '1'='1
" OR "1"="1
' OR 1=1--
' UNION SELECT NULL--
1' AND SLEEP(5)--
```

### XSS
```
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
```

### Directory Traversal
```
../../../etc/passwd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
/etc/passwd
```

### Command Injection
```
; whoami
| whoami
`whoami`
$(whoami)
& whoami
&& whoami
```

---

## Intruder Attack Types

### Sniper
- **Use for:** Testing single parameter
- **Positions:** One at a time
- **Example:** Testing each parameter for SQLi

### Battering Ram
- **Use for:** Same value everywhere
- **Positions:** All simultaneously
- **Example:** Testing session tokens

### Pitchfork
- **Use for:** Correlated data
- **Positions:** Parallel iteration
- **Example:** Username/password pairs

### Cluster Bomb
- **Use for:** All combinations
- **Positions:** All permutations
- **Example:** Brute forcing login

---

## Useful Extensions

### Must-Have (Free)
- **Logger++** - Enhanced logging
- **Autorize** - Authorization testing
- **Param Miner** - Hidden parameter discovery
- **JSON Beautifier** - Format JSON responses
- **Hackvertor** - Encoding/decoding

### Must-Have (Pro)
- **Turbo Intruder** - Fast fuzzing
- **Active Scan++** - Enhanced scanning
- **Collaborator Everywhere** - OOB testing

### Other Useful
- **JWT Editor** - JWT manipulation
- **Upload Scanner** - File upload testing
- **Reflected Parameters** - Find reflections
- **Software Vulnerability Scanner** - CVE detection
- **JS Link Finder** - Extract JS links
- **HTTP Request Smuggler** - Smuggling tests

---

## Match and Replace Rules

### Add Custom Headers
```
Match: ^
Replace: X-Custom-Header: value\r\n
Type: Request header
```

### Modify User-Agent
```
Match: ^User-Agent:.*$
Replace: User-Agent: Custom-Agent
Type: Request header
```

### Remove Security Headers
```
Match: ^X-Frame-Options:.*$
Replace: (empty)
Type: Response header
```

---

## Burp Collaborator (Pro)

### Generate Payload
1. Burp menu > Burp Collaborator client
2. Click "Copy to clipboard"
3. Use in payloads: `http://xyz.burpcollaborator.net`

### Use Cases
- Blind XSS
- Blind SSRF
- Blind XXE
- Out-of-band SQL injection
- Email header injection

---

## Project Configuration

### Save Project
```
Project > Save project
```

### Export Settings
```
Burp menu > User options > Save user options
```

### Import Settings
```
Burp menu > User options > Load user options
```

---

## Tips & Tricks

1. **Use scope filtering:** Target > Scope > Filter by in-scope items only
2. **Color-code requests:** Right-click in history > Highlight
3. **Add comments:** Right-click > Add comment
4. **Compare responses:** Right-click two responses > Compare
5. **Use hotkeys:** Much faster than mouse clicking
6. **Search everywhere:** Burp menu > Search (Ctrl+Shift+F)
7. **Save interesting requests:** Right-click > Copy as curl command
8. **Use match/replace:** For persistent header modifications

---

## Troubleshooting

### Proxy Not Intercepting
1. Check Intercept is ON (Proxy > Intercept)
2. Verify browser proxy settings
3. Check Burp is listening (Proxy > Options)

### HTTPS Not Working
1. Install CA certificate
2. Check "Generate CA-signed per-host certificates"
3. Verify no other proxy interfering

### Slow Performance
1. Increase Java heap: `-Xmx4g`
2. Disable unused extensions
3. Clear project history
4. Use scope to limit traffic

---

## Resources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [BApp Store](https://portswigger.net/bappstore)
