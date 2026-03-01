# Nav Structure Analysis — Role Access Mapping

## SOC-Relevant Modules (by nav group)

### COMMAND CENTER (command)
- cmd-ops: Engagements, Dashboard, Campaigns, Campaign Wizard, Automation Hub, Engagement Pipeline, Timeline
- cmd-scoring: CARVER Scoring, ATT&CK Coverage, Risk Trending, Corroboration Engine

### ATTACK SURFACE (surface) — SOC needs read access for defensive context
- surf-discovery: Discovery Chain, Domain Intel, Web Crawler, Bug Bounty, OSINT Monitor, Email Security
- surf-tools: Discovery Toolkit, HTTPX, Port Scanner, Vuln Scanning, Vuln Scanner, Scan Management, Config Baseline
- surf-paths: Attack Paths, Path Discovery, Vector Engine, Cloud Paths, AD Security, AD Attack Graph, AD Connector, BloodHound, Forest Mapper

### EMULATION & TESTING (emulation)
- emu-agents: Agents, Playbooks, Ability Graph, ATT&CK Tests, Evasion Engine, Agentless BAS, Agent Manager
- emu-validation: Purple Team, Defense Testing, Coverage Matrix, Validation Ops, NGFW Validation, AI Security, Remediation

### INTELLIGENCE (intelligence) — CRITICAL for SOC
- intel-threats: Threat Intel Hub, Vuln Intel, Darkweb Intel, IOC Feed, Actor Intel, Threat Enrichment, Ransomware Groups, NVD CVE Matcher, KEV Catalog
- intel-credentials: Credential Center, Data Export, OSCAL Export, Pentest Export

### KSI (ksi)
- ksi-core: KSI Dashboard, Auto Collector, Evidence Chain, Threat Map, Compliance Center, Compliance Mapper, Compensating Controls

### REPORTS (reports)
- rpt-all: Reports, Pentest Report, Guides, Knowledge Base, Training, Report Templates, Evidence Vault

## SOC Role Access Decision
- SOC needs: command (monitoring), surface (defensive context), emulation (emu-agents for threat actor emulation + emu-validation for defense testing), intelligence (FULL), ksi, reports
- SOC should NOT have: exploits (offensive tooling), platform (admin)
- Key: SOC gets emu-agents for threat actor emulation context (read playbooks, understand TTPs being tested)
