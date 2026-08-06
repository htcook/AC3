# ScanForge Industry Research — Best-in-Class Features

## Current ScanForge Status
- ScanForge exists as a standalone REST API + tRPC router
- NOT yet wired into the engagement orchestrator pipeline
- Engagement pipeline uses Nuclei + ZAP + Hydra directly via SSH
- ScanForge has: template engine, protocol scanners, TI enrichment, context engine, FP/FN prevention, dedup/coverage

## Industry Leader Features (from Invicti, Checkmarx, Burp, Acunetix, Qualys)

### 1. Proof-Based Scanning (Invicti)
- Automatically confirms vulnerabilities by attempting safe, read-only exploits
- 99.98% accuracy on confirmed results
- Covers 94%+ of direct-impact vulnerabilities
- Key: after detecting a potential vuln, the scanner attempts a safe exploit to PROVE it exists
- **ScanForge gap**: We have verification phase but it only enriches with TI data, doesn't actually re-exploit

### 2. Advanced Crawling & Authentication
- Chromium-based crawling (Burp uses built-in Chromium)
- Multi-step form handling, SPA/JavaScript rendering
- Session management: SSO, MFA, token-based auth
- Authenticated vs unauthenticated scan modes
- **ScanForge gap**: No authenticated scanning support, no browser-based crawling

### 3. API & Microservices Testing
- OpenAPI/Swagger/Postman collection import
- REST, SOAP, GraphQL endpoint testing
- Parameter fuzzing specific to API patterns
- OWASP API Top 10 coverage
- **ScanForge gap**: No API spec import, no GraphQL testing

### 4. Incremental/Differential Scanning (Acunetix)
- Only scan new/changed pages since last scan
- Dramatically reduces scan time for repeat assessments
- **ScanForge gap**: No scan history comparison

### 5. AI-Driven DAST (2025-2026 trend)
- LLM-powered payload generation
- Adaptive testing based on application behavior
- Context-aware vulnerability detection
- **ScanForge strength**: Already has LLM context engine — ahead of most tools here

### 6. CI/CD Integration
- Trigger scans from Jenkins, GitHub Actions, GitLab CI
- Scan-on-commit, scan-on-PR
- **ScanForge gap**: No CI/CD hooks (but not needed for engagement pipeline)

### 7. Out-of-Band Detection (OOB)
- Detect blind SSRF, blind XSS, blind SQLi via callback servers
- Burp Collaborator, Interactsh (ProjectDiscovery)
- **ScanForge gap**: No OOB detection mechanism

### 8. Compliance Mapping
- Auto-map findings to OWASP Top 10, PCI DSS, HIPAA, SOC 2
- **ScanForge partial**: Templates have OWASP tags but no compliance report generation

## Priority Improvements for ScanForge

### HIGH PRIORITY (implement now)
1. **Proof-Based Verification** — After detecting a vuln, attempt safe exploit to confirm
2. **Out-of-Band Detection** — Integrate Interactsh for blind vuln detection
3. **Wire into Engagement Pipeline** — Run ScanForge as parallel phase alongside Nuclei/ZAP
4. **Authenticated Scanning** — Support cookie/token injection for authenticated scans

### MEDIUM PRIORITY
5. **API Spec Import** — Parse OpenAPI/Swagger for endpoint discovery
6. **Incremental Scanning** — Track scan history, only test new/changed endpoints
7. **Compliance Report Generation** — Map findings to PCI DSS, HIPAA, SOC 2

### LOWER PRIORITY
8. **Browser-Based Crawling** — Headless Chromium for SPA/JS rendering
9. **CI/CD Webhooks** — Trigger scans from external CI/CD
