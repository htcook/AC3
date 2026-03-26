# FedRAMP 3PAO Penetration Test Plan Requirements — Research Summary

## FedRAMP SAP (Security Assessment Plan) Template Structure
The FedRAMP SAP template (which contains the pen test plan) requires:

### Required Sections
1. **System Overview** — System name, FIPS 199 level, authorization boundary description
2. **Assessment Scope** — Components, services, data flows within boundary
3. **Assumptions & Constraints** — Testing limitations, environmental factors
4. **Security Testing Methodology** — Approach, tools, techniques
5. **Test Plan & Schedule** — Detailed test cases, timeline, milestones
6. **Penetration Test Plan** — Specific to pen testing within the SAP:
   - Scope definition (all 6 attack vectors)
   - Target systems and components
   - Testing methodology per vector
   - Tools and techniques to be used
   - Rules of Engagement
   - Communication plan
   - Escalation procedures
   - Success criteria
   - Risk mitigation during testing
7. **Roles & Responsibilities** — 3PAO team, CSP contacts, agency POCs
8. **Deliverables** — SAR, POA&M, evidence packages

## 6 Mandatory FedRAMP Attack Vectors
1. External to Corporate (Phishing)
2. External to CSP Target System (External Network / Insider Threat)
3. Tenant to CSP Management System (Web App)
4. Tenant-to-Tenant (Web App)
5. Mobile Application to Target System
6. Client-Side Application/Agents to Target System

## FedRAMP Pen Test Guidance v3.0 Key Requirements
- Production-only testing (no staging/QA)
- Phishing allowed through email filters
- MITRE ATT&CK mapping mandatory
- Updated threat models
- Comprehensive scoping of authorization boundary
- All 6 attack vectors must be assessed (no skipping without AO approval)

## NIST SP 800-115 Test Plan Structure
1. **Planning Phase**
   - Scope definition
   - Goals and objectives
   - Rules of Engagement
   - Resource allocation
   - Timeline
   - Legal considerations
2. **Discovery Phase** (maps to our passive/active recon)
   - Network discovery
   - Service identification
   - Vulnerability scanning
3. **Attack Phase** (maps to our exploitation)
   - Vulnerability validation
   - Exploitation attempts
   - Privilege escalation
   - Lateral movement
4. **Reporting Phase**
   - Findings documentation
   - Risk assessment
   - Remediation recommendations

## Optimal Test Plan Generation Stage — Analysis

### The Answer: After Passive Discovery + Scoping, Before Active Scanning

**Why this stage is optimal:**

1. **Passive recon provides the intelligence foundation** — At this point we have:
   - Complete asset inventory (subdomains, IPs, services)
   - Technology stack identification
   - Cloud provider detection
   - WAF/CDN detection
   - Certificate transparency data
   - DNS records and email security posture
   - Breach exposure data
   - Historical URLs and archived content

2. **Scoping is complete** — RoE defines:
   - Authorized targets (domains, IPs, CIDRs)
   - Excluded systems
   - Testing windows
   - Escalation procedures
   - Emergency contacts

3. **We can accurately plan** — With passive intel + scope:
   - Map attack vectors to specific targets
   - Select appropriate tools per target type
   - Estimate timeline based on attack surface size
   - Identify which of the 6 FedRAMP vectors apply
   - Plan MITRE ATT&CK TTP coverage
   - Identify risk areas requiring special handling

4. **Customer approval gate** — The test plan becomes a formal deliverable:
   - Customer reviews and approves before active scanning begins
   - Ensures alignment on scope, methodology, and expectations
   - Satisfies FedRAMP requirement for documented test plan
   - Creates audit trail for compliance

## Proposed New Pipeline Architecture

### Phase Flow
```
1. Domain Recon (passive OSINT — no RoE needed)
   ↓
2. Passive Discovery & Enumeration (passive — no RoE needed)
   ↓
3. Scoping & RoE (customer approval gate)
   ↓
4. TEST PLAN GENERATION ← optimal stage (LLM-generated, FedRAMP-compliant)
   ↓
5. Customer Test Plan Approval (approval gate)
   ↓
6. Active Discovery & Enumeration (nmap, httpx — requires RoE)
   ↓
7. Vulnerability Scanning (nuclei, ZAP, cloud checks)
   ↓
8. Penetration Testing / Exploitation (Metasploit, manual)
   ↓
9. Post-Exploitation (C2, lateral movement, objectives)
   ↓
10. Reporting (FedRAMP SAR format)
```

### Key Design Decisions
- **Domain Recon** = current "Domain Intelligence" scan, renamed for clarity
- **Passive Discovery** = subdomain enum, DNS, cert transparency, Shodan, breach data — all passive
- **Active Discovery** = nmap, httpx, banner grabbing — requires RoE authorization
- **Test Plan** generated after passive phases because we have full asset inventory and tech stack
- **Red Team plans** follow same structure but add: C2 infrastructure planning, persistence objectives, data exfiltration goals, lateral movement strategy
