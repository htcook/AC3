# RoE Research Notes — NIST SP 800-115 + FedRAMP Pentest Guidance v4.0

## NIST SP 800-115 Appendix B — ROE Template Structure (7 Sections)

### 1. Introduction
- 1.1 Purpose — org being tested, group conducting testing, purpose of security test
- 1.2 Scope — test boundaries in terms of actions and expected outcomes
- 1.3 Assumptions and Limitations — assumptions by org and test team
- 1.4 Risks — inherent risks, mitigation techniques, actions to reduce them
- 1.5 Document Structure — outlines ROE structure

### 2. Logistics
- 2.1 Personnel — all personnel by name, POC table, clearances/background checks
- 2.2 Test Schedule — schedule, critical tests/milestones, hours of testing
- 2.3 Test Site — authorized locations, building/equipment access, badges/escorts
- 2.4 Test Equipment — hardware, tools authorized for use, MAC identification

### 3. Communication Strategy
- 3.1 General Communication — frequency, methods, meeting schedule
- 3.2 Incident Handling and Response — criteria for halting, course of action, call tree/chain of command, process for resuming

### 4. Target System/Network
- Authorized/unauthorized IP addresses, systems (servers, workstations, firewalls, routers), OS, applications
- "Exclude list" — systems NOT authorized for testing

### 5. Testing Execution
- 5.1 Nontechnical Test Components — policies, procedures, interviews, site surveys, physical security
- 5.2 Technical Test Components — type of testing (scanning, discovery, pentest), file install/create/modify/execute authorization
- 5.3 Data Handling — gathering, storing, transmitting, destroying test data

### 6. Reporting
- Report deliverables, minimum info per report, frequency of delivery

### 7. Signature Page
- Test team leader + org senior management (CSO, CISO, CIO) sign

---

## FedRAMP Pentest Guidance v4.0 — ROE Requirements

### 6 Mandatory Attack Vectors
1. **External to Corporate** — social engineering (phishing) against CSP admins
2. **External to CSP Target System** — external threats, internal threats, poor separation
3. **Tenant to CSP Management System** — tenant trying to access CSP management
4. **Tenant-to-Tenant** — one tenant trying to compromise another
5. **Mobile Application to Target System** — mobile app user attacking CSP
6. **Client-side Application/Agents to Target System** — client-side components

### ROE Must Include (Section 5)
- Description of approach, constraints, methodologies for each planned attack
- Detailed test schedule (start/end date/times, content of each test period)
- Technical POCs with backup for each subsystem/application
- Local CIRT requirements
- Physical penetration constraints
- Acceptable social engineering pretexts (fully worked out before signing)
- Summary/reference to third-party agreements
- Clause: critical high-impact vulns reported to AO, CIO, CISO, ISSO immediately

### ROE/Test Plan Template (Appendix C)
- System Scope — boundaries, IP addresses, URIs, devices, components, software, hardware
- Assumptions and Limitations — legal constraints, third-party agreements
- Testing Schedule — phases, initiation/completion dates, deliverable tracking
- Testing Methodology — per Section 5
- Relevant Personnel — System Owner, Trusted Agent, PT Team Lead, PT Members, Escalation POCs
- Incident Response Procedures — chain of communications
- Evidence Handling Procedures — transmission and storage of evidence

### Red Team Exercise Phases (Appendix D — CA-8(2))
- Phase I: Objective Setting
- Phase II: Reconnaissance and Threat Modeling
- Phase III: Initial Access
- Phase IV: Establish Persistence
- Phase V: Escalation/Lateral Movement
- Phase VI: Data Exfiltration
- Phase VII: Reporting and Debrief

### Reporting Requirements (Section 6)
- 6.1 Scope of Target System
- 6.2 Attack Vectors Assessed
- 6.3 Timeline for Assessment Activity
- 6.4 Actual Tests Performed and Results
- 6.5 Findings and Evidence (description, impact, recommendation, risk rating, evidence)
- 6.6 Access Paths (chain of attack vectors, exploitations, post-exploitations)

---

## ACE C3 Testing Types to Offer

### Penetration Testing
- External Network Penetration Testing
- Internal Network Penetration Testing
- Web Application Penetration Testing
- API Penetration Testing
- Wireless Network Penetration Testing
- Cloud Infrastructure Penetration Testing
- Mobile Application Penetration Testing
- Social Engineering (Phishing, Vishing, Physical)
- IoT/ICS/SCADA Penetration Testing

### Red Team Operations
- Full-scope Red Team Engagement
- Assumed Breach Assessment
- Purple Team Exercise
- Adversary Emulation (MITRE ATT&CK-based)
- Physical Security Assessment
- Social Engineering Campaign

### Compliance-Specific
- FedRAMP Penetration Test (6 mandatory attack vectors)
- PCI DSS Penetration Test
- HIPAA Security Assessment
- SOC 2 Penetration Test


## PTES Pre-Engagement — ROE Requirements

### ROE Sections (PTES)
1. **Timeline** — GANTT charts, work breakdown structures, schedule flexibility
2. **Locations** — travel, VPN for remote testing, multi-site considerations
3. **Evidence Handling** — encryption, machine sanitization, no data reuse between clients
4. **Regular Status Meetings** — daily meetings covering plans, progress, problems
5. **Time of Day to Test** — business hours vs after-hours testing windows
6. **Dealing with Shunning** — whether IDS/IPS blocking is acceptable during test
7. **Permission to Test** — signed document acknowledging scope, liability waiver, system instability risk
8. **Legal Considerations** — local law compliance (wiretapping, VOIP, data privacy)

### PTES Sensitive Data Handling
- PHI under HIPAA must be protected
- PII must not be in tester possession
- Prove access without exfiltrating data (screenshots of schema, file listings)
- Illegal data discovery → notify law enforcement immediately, then customer

### PTES Questionnaires (Scoping)
- Network Pentest: IP ranges, internal/external, wireless, VPN
- Web App: number of apps, static/dynamic, authentication, roles
- Wireless: number of locations, SSIDs, guest networks
- Physical: number of locations, floors, badge systems
- Social Engineering: number of employees, email domains, pretexts
