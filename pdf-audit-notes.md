# PDF Audit Notes — ACE C3 FedRAMP 20x KSI Positioning

## Document 1: FedRAMP 20x KSI Positioning & Productization Strategy (35 pages)

### Executive Summary Claims:
- ACE C3 "meets its own KSI obligations" when deployed in FedRAMP-authorized AWS
- "productized KSI compliance enablement platform" for other CSPs
- Claims to be only platform combining offensive security testing + compliance evidence + continuous automated validation
- Positions as "Offensive Security KSI Compliance Platform"

### Section 1: FedRAMP 20x Architecture Overview
- 55 outcome-based KSIs across 9 themes
- Persistent Validation Requirements table (Low=7 days, Moderate=3 days, High=TBD)
- 6 Mandatory Penetration Testing Attack Vectors mapped to ACE C3 modules
- Coverage tiers: Direct, Supporting, Complementary

### Section 2: Capability-to-KSI Mapping (starting page 5)
#### 2.1 Change Management (KSI-CMT) — 4 KSIs
- KSI-CMT-ACM: Claims "Continuous Validation Engine" + "NGFW Validation" + "EDR Validation" → Supporting
- KSI-CMT-CDB: Claims "Domain Intel (33 connectors)" + "SIEM Connectors" → Supporting
- KSI-CMT-DCH: Claims "Audit Log" + "RoE Version History" → Direct
- KSI-CMT-PVD: Need to read more

### Attack Vector Mapping Claims:
- External to Corporate → Phishing Ops, Email Security, Domain Intel
- External to CSO → Web App Scanner, API Security, Nuclei Scanner
- Tenant to CSO → Cloud Attack Paths, Cloud Credentials
- Tenant to Tenant → Cloud Attack Paths, Agentless BAS
- Mobile Application → API Security Testing
- Internal → AD Attack Sim, Attack Paths, Post-Exploit Playbooks

## NEED TO VERIFY:
- "Continuous Validation Engine" — does this exist?
- "NGFW Validation" — does this exist?
- "EDR Validation" — does this exist?
- "SIEM Connectors" — does this exist?
- "33 connectors" claim for Domain Intel
- "Agentless BAS" — does this exist?
- "AD Attack Sim" — does this exist?
- "API Security Testing" — does this exist?
- "Cloud Credentials" module — does this exist?
