# Bug Bounty Report Template

Use this template when submitting vulnerability reports to bug bounty programs.

---

## Report Title

**[Vulnerability Type] - [Where it occurs] - [Brief Impact]**

Examples:
- "Stored XSS in User Profile Bio Field Allows Session Hijacking"
- "IDOR in /api/users Endpoint Allows Access to Other Users' Data"
- "SQL Injection in Search Function Leads to Database Dump"

---

## Summary

[Provide a 2-3 sentence overview of the vulnerability, its location, and impact]

**Example:**
> A stored Cross-Site Scripting (XSS) vulnerability exists in the user profile bio field at https://example.com/profile/edit. An attacker can inject malicious JavaScript that executes when other users view the profile, potentially leading to session hijacking or credential theft.

---

## Severity

**CVSS Score:** [X.X] ([Vector String])
**Severity:** [Critical/High/Medium/Low/Informational]

### Severity Justification
- Attack Vector: [Network/Adjacent/Local/Physical]
- Attack Complexity: [Low/High]
- Privileges Required: [None/Low/High]
- User Interaction: [None/Required]
- Scope: [Unchanged/Changed]
- Confidentiality Impact: [None/Low/High]
- Integrity Impact: [None/Low/High]
- Availability Impact: [None/Low/High]

---

## Affected Asset

- **URL/Endpoint:** https://example.com/vulnerable-endpoint
- **Parameter:** `parameter_name`
- **HTTP Method:** GET/POST/PUT/DELETE
- **Asset Type:** Web Application / API / Mobile App

---

## Steps to Reproduce

### Prerequisites
- [Any account requirements]
- [Any setup needed]

### Reproduction Steps

1. Navigate to [URL]
2. [Specific action]
3. [Another action]
4. Observe [expected behavior demonstrating vulnerability]

### HTTP Request (if applicable)

```http
POST /api/endpoint HTTP/1.1
Host: example.com
Content-Type: application/json
Cookie: session=abc123

{
    "parameter": "payload_here"
}
```

### HTTP Response (if applicable)

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "status": "success",
    "data": "sensitive_data_exposed"
}
```

---

## Proof of Concept

### Payload Used

```
[Your payload here]
```

### Screenshots/Video

[Attach screenshots or video demonstrating the vulnerability]

1. **Screenshot 1:** [Description]
2. **Screenshot 2:** [Description]
3. **Video:** [Link or attachment]

### PoC Code (if applicable)

```python
# Example PoC script
import requests

url = "https://example.com/vulnerable-endpoint"
payload = {"param": "malicious_value"}

response = requests.post(url, json=payload)
print(response.text)
```

---

## Impact

### Technical Impact
[Describe what an attacker can technically achieve]

### Business Impact
[Describe the potential business consequences]

### Attack Scenario
1. Attacker [first action]
2. Victim [action or state]
3. Attacker [exploitation]
4. Result: [outcome]

---

## Remediation Recommendations

### Short-term Fix
[Immediate actions to mitigate the vulnerability]

### Long-term Fix
[Proper remediation approach]

### Code Example (if applicable)

**Vulnerable Code:**
```python
# Example of vulnerable code
user_input = request.get('input')
query = "SELECT * FROM users WHERE name = '" + user_input + "'"
```

**Fixed Code:**
```python
# Example of secure code
user_input = request.get('input')
query = "SELECT * FROM users WHERE name = %s"
cursor.execute(query, (user_input,))
```

---

## References

- [OWASP Reference](https://owasp.org/...)
- [CWE Reference](https://cwe.mitre.org/...)
- [CVE Reference](https://cve.mitre.org/...) (if applicable)
- [Related Blog Post/Research]

---

## Supporting Material

- [ ] Screenshots attached
- [ ] Video demonstration attached
- [ ] PoC script attached
- [ ] HTTP request/response logs attached

---

## Timeline

| Date | Action |
|------|--------|
| YYYY-MM-DD | Vulnerability discovered |
| YYYY-MM-DD | Report submitted |
| YYYY-MM-DD | [Any updates] |

---

## Additional Notes

[Any additional information that might help the security team understand or reproduce the issue]

---

## Checklist Before Submission

- [ ] Clear and descriptive title
- [ ] Accurate severity assessment
- [ ] Step-by-step reproduction instructions
- [ ] Proof of concept (screenshots/video/code)
- [ ] Impact clearly explained
- [ ] Remediation recommendations provided
- [ ] All sensitive data redacted
- [ ] Tested reproduction steps work
- [ ] Within program scope
- [ ] No duplicate of known issue
