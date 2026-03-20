# Missed Vulnerabilities Analysis — Full Red Team Engagement 1770049

## Accuracy Score
- **F1: 23.0%** | Precision: 14.1% | Recall: 61.9%
- True Positives: 26 | False Positives: 158 | False Negatives: 16
- Total Findings: 184 | Ground Truth: 42

## 16 Missed Vulnerabilities (Juice Shop)

### 1. NoSQL DoS
- **Category**: Denial of Service / NoSQL Injection
- **CWE**: CWE-400 (Uncontrolled Resource Consumption)
- **How to detect**: Send crafted NoSQL query that causes excessive CPU/memory usage (e.g., `$where` with infinite loop, `$regex` with catastrophic backtracking)
- **Exploit**: `{"$where": "function(){while(1){}}"}` or `{"email": {"$regex": "^(a+)+$"}}` in product search/review endpoints
- **Why missed**: Scanner only tested for NoSQL injection data extraction, not DoS payloads

### 2. Stored XSS via API
- **Category**: Cross-Site Scripting (Stored)
- **CWE**: CWE-79
- **How to detect**: POST XSS payloads via REST API endpoints (not browser forms) — product reviews, user profiles
- **Exploit**: `POST /api/Products` with `{"description": "<iframe src='javascript:alert(1)'>"}` or `POST /api/Feedbacks` with XSS in comment field
- **Why missed**: Scanner tested reflected XSS in search but didn't test stored XSS via direct API calls

### 3. Video XSS
- **Category**: Cross-Site Scripting via media
- **CWE**: CWE-79
- **How to detect**: Upload/embed video with XSS payload in subtitle track or video metadata
- **Exploit**: Craft `.mp4` with XSS in metadata, or use `<video><source onerror=alert(1)>` in product descriptions
- **Why missed**: Scanner doesn't test media-based XSS vectors

### 4. Two-Factor Authentication Bypass
- **Category**: Authentication Bypass
- **CWE**: CWE-287, CWE-304
- **How to detect**: Test 2FA flow for bypass via response manipulation, direct endpoint access, or TOTP brute-force
- **Exploit**: Intercept 2FA response, change `{"success": false}` to `{"success": true}`, or access authenticated endpoints directly skipping 2FA step
- **Why missed**: Scanner detected broken auth but didn't specifically test 2FA bypass flow

### 5. Forged Feedback
- **Category**: Broken Access Control / Input Validation
- **CWE**: CWE-284
- **How to detect**: Submit feedback as another user by manipulating userId in the request body
- **Exploit**: `POST /api/Feedbacks` with `{"UserId": 1, "comment": "...", "rating": 5}` while authenticated as different user
- **Why missed**: Scanner didn't test user ID manipulation in feedback submission

### 6. Product Tampering
- **Category**: Broken Access Control / Mass Assignment
- **CWE**: CWE-915
- **How to detect**: Modify product attributes (price, description) via PUT/PATCH requests
- **Exploit**: `PUT /api/Products/1` with `{"price": 0, "description": "tampered"}` — check if non-admin can modify products
- **Why missed**: Scanner didn't test mass assignment on product endpoints

### 7. Manipulate Basket
- **Category**: Broken Access Control / IDOR
- **CWE**: CWE-639
- **How to detect**: Add items to other users' baskets, modify quantities, or access other baskets
- **Exploit**: `POST /api/BasketItems` with `{"BasketId": 2, "ProductId": 1, "quantity": 1}` while owning basket 1
- **Why missed**: Scanner detected IDOR on basket viewing but not on basket item manipulation

### 8. Forged Signed JWT
- **Category**: Cryptographic Failure
- **CWE**: CWE-347
- **How to detect**: Forge JWT with known/leaked signing key, or crack weak JWT secret
- **Exploit**: Extract JWT, crack secret (Juice Shop uses weak secret), forge token with admin role: `jwt_tool token -S hs256 -p 'secret'`
- **Why missed**: Scanner tested JWT none algorithm but not JWT secret cracking/forging

### 9. Weak Crypto - MD5 Password Hashes
- **Category**: Cryptographic Failure
- **CWE**: CWE-328
- **How to detect**: Find exposed password hashes and identify weak hashing algorithm (MD5 without salt)
- **Exploit**: Access `/api/Users` endpoint, find MD5 hashes, crack with rainbow tables or hashcat
- **Why missed**: Scanner detected password hash leak but didn't analyze the hashing algorithm strength

### 10. XXE DoS
- **Category**: Denial of Service via XXE
- **CWE**: CWE-611, CWE-776
- **How to detect**: Send XML with billion laughs payload to XML-accepting endpoints
- **Exploit**: `<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;...">]>` (exponential entity expansion)
- **Why missed**: Scanner tested XXE for data access but not for DoS payloads

### 11. Insecure Deserialization
- **Category**: Insecure Deserialization
- **CWE**: CWE-502
- **How to detect**: Find serialized objects in cookies, request bodies, or file uploads; test with crafted payloads
- **Exploit**: Modify serialized object in cookie/request to execute arbitrary code or escalate privileges
- **Why missed**: No deserialization testing was performed — scanner lacks serialization payload generation

### 12. Information Disclosure - Error Messages
- **Category**: Information Disclosure
- **CWE**: CWE-209
- **How to detect**: Trigger application errors and check for stack traces, database details, internal paths
- **Exploit**: Send malformed input to trigger 500 errors, check response for Express.js stack traces, SQL error details
- **Why missed**: Scanner found some info disclosure but didn't specifically test error message verbosity

### 13. Deprecated Interface
- **Category**: Security Misconfiguration
- **CWE**: CWE-477
- **How to detect**: Find deprecated API endpoints, old file upload interfaces, legacy admin panels
- **Exploit**: Access `/api/Uploads` or B2B interface that accepts XML uploads (deprecated but still active)
- **Why missed**: Scanner didn't enumerate deprecated/legacy endpoints

### 14. Outdated Dependencies
- **Category**: Vulnerable Components
- **CWE**: CWE-1104
- **How to detect**: Check `package.json`, response headers, and error messages for library versions
- **Exploit**: Access `/package.json` or analyze response headers for outdated framework versions, cross-reference with CVE databases
- **Why missed**: Scanner didn't perform software composition analysis (SCA)

### 15. Vulnerable Library
- **Category**: Vulnerable Components
- **CWE**: CWE-1104
- **How to detect**: Identify specific vulnerable libraries (e.g., sanitize-html, jsonwebtoken) and their known CVEs
- **Exploit**: Exploit known CVEs in identified libraries (e.g., prototype pollution in lodash, ReDoS in validator)
- **Why missed**: No SCA tool was run; scanner relies on network-level detection, not code analysis

### 16. Zero Stars Feedback
- **Category**: Input Validation / Business Logic
- **CWE**: CWE-20
- **How to detect**: Submit feedback with rating=0 (should be 1-5), test boundary conditions
- **Exploit**: `POST /api/Feedbacks` with `{"rating": 0, "comment": "test"}` — intercept and modify the rating field
- **Why missed**: Scanner didn't test business logic boundary conditions on rating fields

## Root Causes for Misses

1. **LLM Feedback Loop Failed** (403 Forbidden — providers exhausted) → 0 re-scans executed
2. **No business logic testing** — scanner relies on passive/active network tools, not application-level logic testing
3. **No SCA (Software Composition Analysis)** — outdated dependencies and vulnerable libraries require code-level analysis
4. **No serialization testing** — insecure deserialization requires crafted payloads
5. **No DoS payload testing** — NoSQL DoS and XXE DoS require specific payload patterns
6. **Limited API-level testing** — stored XSS via API, product tampering, basket manipulation need direct API interaction
7. **No 2FA-specific testing** — broken auth was detected generically but 2FA bypass needs targeted flow testing
8. **No JWT secret cracking** — JWT none algorithm was tested but not weak secret brute-forcing
