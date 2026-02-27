# Active Scanning Tools Audit — ROE-Covered Asset Scanning

**Author:** Harrison Cook — AceofCloud  
**Date:** February 26, 2026  
**Scope:** Complete inventory of active scan tools executed against in-scope discovered assets after the engagement transitions from passive reconnaissance to ROE-covered active scanning.

---

## Executive Summary

When the Ace C3 platform transitions from passive reconnaissance to ROE-covered active scanning, **18 distinct active tool categories** are invoked against discovered in-scope assets. These tools are orchestrated through the **Unified Attack Lifecycle Pipeline** (`server/lib/unified-pipeline.ts`), gated by the **SSIL Scan Policy Engine** (`server/lib/scan-policy-engine.ts`), and enforced by the **ROE Guard** (`server/lib/roe-guard.ts`). The pipeline progresses through six sequential phases — Recon, Enumeration, Vulnerability Assessment, Exploitation, Post-Exploitation, and Reporting — with each phase unlocking progressively more aggressive tooling.

---

## 1. Pipeline Architecture and ROE Gating

The transition from passive to active scanning is governed by three interlocking systems:

### 1.1 ROE Guard (`server/lib/roe-guard.ts`)

The ROE Guard classifies all operations into three risk tiers. **Yellow** tier operations (passive probing) are logged but not blocked. **Orange** tier operations (active scanning, auxiliary modules) require a valid, non-expired ROE with status `"signed"`. **Red** tier operations (exploitation, payload delivery, C2 operations) also require a signed ROE and are subject to additional scope validation. The `enforceROE()` function is called before any Orange or Red operation, checking the engagement's `roeStatus`, `roeSignedDate`, and `roeExpiryDate` fields. If the ROE is `"none"`, `"pending"`, or `"expired"`, the operation is blocked with a descriptive error.

### 1.2 Scan Policy Engine (`server/lib/scan-policy-engine.ts`)

The SSIL Scan Policy Engine provides a second layer of gating through three scan profiles:

| Profile | Allowed Scanners | Allowed Modes | Key Restrictions |
|---------|-----------------|---------------|------------------|
| **strict_passive** | ZGrab2, custom_dns, custom_tls, custom_http_headers | passive only | No active scanning, no fuzzing, no auth guessing, no payload injection (SP-01 through SP-05) |
| **balanced** | ZGrab2, Nuclei, custom_dns, custom_tls, custom_http_headers | passive, active-low | No exploitation, no brute force; escalation rules can promote passive → active-low based on signal confidence |
| **aggressive_internal** | ZGrab2, Nuclei, Nmap, ZAP, vuln_scanner, web_crawler, protocol_scanner | passive, active-low, active-standard, active-aggressive | No restrictions; for explicitly authorized internal environments only |

Every scanner must call `canExecute()` before probing a target. The engine enforces controls SP-01 (no payload injection), SP-02 (no auth guessing), SP-03 (no exploit modules), SP-04 (rate limiting with token bucket), and SP-05 (header redaction). Three built-in escalation rules can automatically promote scanning intensity when high-confidence signals are detected (e.g., admin surface discovered → allow active-low Nuclei templates).

### 1.3 Unified Pipeline Phases (`server/lib/unified-pipeline.ts`)

The pipeline defines six sequential phases, each with a specific set of tools. Phases after Recon require the prior phase to complete (`requiresPriorPhase: true`), and the Exploitation and Post-Exploitation phases cannot run in parallel (`canRunParallel: false`), ensuring controlled escalation.

---

## 2. Complete Active Tool Inventory

The following table enumerates every active scan tool that runs against in-scope discovered assets, organized by pipeline phase. Tools marked with **(ROE Required)** are gated behind a signed ROE via the Orange or Red risk tier.

### Phase 1: Recon (Estimated: ~10 minutes)

While primarily passive, this phase includes light active components:

| Tool | Module | What It Does on Discovered Assets |
|------|--------|----------------------------------|
| **ZAP Passive Spider** | `zap_passive` via `server/lib/zap-scanner.ts` | Crawls web application structure, discovers links, forms, and JavaScript endpoints without injecting payloads. Passive-only spider mode. |
| **Nuclei Info Templates** | `nuclei_info` via `server/routers/nuclei-scanner.ts` | Runs ~1,500 info-level templates for technology stack fingerprinting (web servers, CMS, frameworks, CDNs). Non-intrusive GET requests only. |
| **ProjectDiscovery Subfinder** | `server/lib/projectdiscovery.ts` | Fast passive subdomain enumeration using certificate transparency logs, DNS datasets, and web archives. |
| **ProjectDiscovery httpx** | `server/lib/projectdiscovery.ts` | HTTP probing toolkit that validates discovered hosts are alive, captures response headers, status codes, technologies, and TLS certificate metadata. |
| **Atomic Red Team Recon Tests** | `atomic_red_team` via `server/lib/atomic-red-team.ts` | Executes ATT&CK recon techniques (T1595 Active Scanning, T1592 Gather Victim Host Information) to validate what an attacker would observe. |

### Phase 2: Enumeration (Estimated: ~20 minutes) — **(ROE Required)**

| Tool | Module | What It Does on Discovered Assets |
|------|--------|----------------------------------|
| **ZAP Active/AJAX Spider** | `zap_active` via `server/lib/zap-scanner.ts` | Deep crawling of JavaScript-heavy applications using headless browser. Discovers hidden endpoints, API routes, and dynamic content. Supports authenticated scanning with session tokens. |
| **Nuclei Medium Templates** | `nuclei_info` (medium severity) | ~1,200 templates that enumerate services, configurations, exposed admin panels, default credentials pages, and technology versions. |
| **API Security Engine** | `api_security` via `server/lib/api-security-engine.ts` | Imports and tests OpenAPI/Swagger, GraphQL, and SOAP/WSDL specifications. Discovers undocumented endpoints, tests OWASP API Top 10 categories (BOLA, broken auth, SSRF, etc.). Includes fuzzing strategies. |
| **ProjectDiscovery Naabu** | `server/lib/projectdiscovery.ts` | Fast port scanner (Go-based) that validates open ports on discovered hosts. Supports SYN/CONNECT scanning, service detection, and top-ports mode. |
| **ZGrab2 Protocol Probes** | Scan Policy Engine `zgrab2` | Protocol-level banner grabbing and metadata extraction for TLS, HTTP, SSH, SMTP, FTP, and other services discovered during recon. |
| **Active DNS Verification** | Scan Policy Engine `custom_dns` | Validates passive DNS findings with live resolution, checks for dangling CNAMEs, zone transfer attempts, and DNSSEC validation. |

### Phase 3: Vulnerability Assessment (Estimated: ~45 minutes) — **(ROE Required)**

| Tool | Module | What It Does on Discovered Assets |
|------|--------|----------------------------------|
| **ZAP Active Scanner (DAST)** | `zap_active` via `server/lib/zap-scanner.ts` | Full OWASP Top 10 testing: XSS (reflected/stored/DOM), SQL injection, CSRF, SSRF, command injection, path traversal, insecure deserialization. LLM-powered scan configuration auto-tunes attack vectors based on tech stack. Supports OpenAPI, GraphQL, and SOAP spec import for targeted API testing. |
| **Nuclei High/Critical Templates** | `nuclei_vuln` + `nuclei_critical` | ~2,500 CVE detection templates + ~100 critical-only templates (RCE, auth bypass, SSRF, critical misconfigurations). Includes subdomain takeover detection, default login checks, and known exploit validation. |
| **NVD/CISA KEV Matcher** | `nvd_kev` via `server/lib/nvd-cve-matcher.ts` | Correlates discovered services and versions against the NVD database and CISA Known Exploited Vulnerabilities catalog. Batch-matches products to CVEs with CVSS scoring. |
| **Active Verification Probes** | `server/lib/active-verification.ts` | 8+ built-in verification probes (HTTP, TCP, DNS, TLS, Nuclei-based) that safely confirm specific CVEs. Each probe has a `safeForProduction` flag. Runs a full verification suite against targets with CVE-specific and tag-based filtering. |
| **Vulnerability Scanner Imports** | `vuln_scanner` via `server/lib/vuln-scanner-parser.ts` | Ingests and correlates results from Nessus, Qualys, Rapid7, and OpenVAS scans. Auto-triggers the corroboration engine for cross-source validation. |
| **Corroboration Engine** | `corroboration` via `server/lib/corroboration-engine.ts` | Cross-references findings from all sources (ZAP, Nuclei, vuln scanners, OSINT, BAS tests, threat intel) with weighted confidence scoring. Reduces false positives by 30–40%. Produces verdicts: confirmed, likely, unverified, likely_false_positive, false_positive. |
| **API Security OWASP Testing** | `api_security` | Executes the full OWASP API Top 10 test catalog against discovered API endpoints: BOLA (API1), Broken Authentication (API2), Object Property Level Authorization (API3), Unrestricted Resource Consumption (API4), Broken Function Level Authorization (API5), SSRF (API6), Security Misconfiguration (API7), and more. |

### Phase 4: Exploitation (Estimated: ~60 minutes) — **(ROE Required, Red Tier)**

| Tool | Module | What It Does on Discovered Assets |
|------|--------|----------------------------------|
| **Metasploit Framework** | `metasploit` via `server/routers/metasploit-catalog.ts` + `server/routers/msf-sessions.ts` | Executes matched exploits against confirmed vulnerabilities. Auto-provisioned exploit servers on DigitalOcean with SSH tunnel connectivity. Full module catalog (exploit, auxiliary, post, payload). Meterpreter session management with interactive shell, file transfer, and privilege escalation. The **Exploit-to-Asset Matcher** (`server/lib/exploit-asset-matcher.ts`) uses LLM-driven ranking to select the most appropriate exploits from the unified catalog based on discovered asset profiles. |
| **Sliver C2 Framework** | `sliver_c2` via `server/routers/sliver-c2.ts` | Deploys cross-platform implants via mTLS, HTTPS, DNS, or WireGuard transport. Generates implants for Windows/Linux/macOS in EXE, shared library, service, or shellcode format. Supports obfuscation and evasion (canary domains, datetime limits, hostname/username restrictions). Manages listeners and active sessions. |
| **Cobalt Strike** | `cobaltstrike` via `server/lib/cobalt-strike-adapter.ts` | Full Team Server REST API integration with beacon management. 40+ MITRE ATT&CK technique mappings for built-in commands and BOFs. Listener management (HTTP, HTTPS, DNS, SMB, TCP). Payload generation (staged/stageless, EXE/DLL/shellcode). Sleep/jitter control and Aggressor Script/BOF code generation. |
| **MITRE Caldera** | `caldera` via Caldera API integration | Runs adversary emulation operations with ATT&CK-mapped abilities. Multi-step operations that chain techniques across the kill chain. Integrates with the Ability Graph Engine for DAG-based execution with precondition evaluation and safety-tier gating. |
| **Empire C2** | Part of C2 Abstraction Layer | PowerShell/Python-based post-exploitation framework. Registered in the C2 Registry alongside Caldera, Metasploit, Sliver, and Cobalt Strike. |
| **GoPhish Phishing Engine** | `gophish` via `server/routers/phishing-ops.ts` | Launches social engineering campaigns for initial access testing. Campaign management with email templates, landing pages, and credential harvesting. Tracks email delivery, opens, clicks, and credential submissions. Integrates with the C2 Orchestrator for phishing-to-C2 pipeline (payload delivery → callback → post-exploitation). |
| **Atomic Red Team** | `atomic_red_team` via `server/lib/atomic-red-team.ts` | Executes ATT&CK-mapped atomic tests to validate detection gaps. GitHub-synced test library with technique-specific test cases. Cross-module integration with Attack Planner, Purple Team, Detection Rules, and EDR Validation. |
| **Payload Generator** | `server/routers/payload-generator.ts` | Wraps msfvenom execution through SSH tunnel to the exploit server. Generates custom payloads for Windows, Linux, macOS, Android, and multi-platform targets. Supports 30+ payload types including Meterpreter, shell, and language-specific payloads. Stores generated payloads in S3 with hash verification. |

### Phase 5: Post-Exploitation (Estimated: variable) — **(ROE Required, Red Tier)**

| Tool | Module | What It Does on Discovered Assets |
|------|--------|----------------------------------|
| **Sliver C2 Session Management** | `sliver_c2` | Manages active implant sessions for ongoing access. Executes post-exploitation commands, file operations, and pivoting. |
| **Caldera Multi-Step Operations** | `caldera` | Orchestrates complex multi-step operations: lateral movement, persistence installation, credential harvesting, data collection, and exfiltration — all mapped to ATT&CK techniques. |
| **Metasploit Post-Exploitation** | `metasploit` | Post-exploitation modules: hashdump, credential collection, SSH credential gathering, cached domain credential dumping. Meterpreter commands for system reconnaissance, privilege escalation, and lateral movement. |
| **Post-Exploit Playbooks** | `server/routers/post-exploit-playbooks.ts` | Pre-built command sequences that auto-execute on new sessions: System Reconnaissance (sysinfo, getuid, ipconfig, route, arp, getprivs), Credential Harvesting (hashdump, credential_collector, ssh_creds, cachedump), and more. |
| **BloodHound/SharpHound** | `bloodhound` via `server/routers/bloodhound-import.ts` + `server/lib/bloodhound-parser.ts` | Imports SharpHound collection data (JSON/ZIP). Discovers Active Directory attack paths: privilege escalation routes, Kerberoasting targets, DCSync opportunities, delegation abuse paths. Feeds into the AD Attack Path Graph for visualization. |
| **AD Attack Simulation** | `server/routers/ad-attack-sim.ts` | Simulates 17 AD attack types: Kerberoasting, AS-REP Roasting, DCSync, Golden/Silver Ticket, Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, Skeleton Key, DCShadow, SID History Injection, GPO Abuse, Certificate Abuse, Constrained/Unconstrained/RBCD Delegation, and AD Enumeration. |
| **Atomic Red Team Post-Exploitation** | `atomic_red_team` | Validates detection of post-exploitation techniques (persistence, privilege escalation, defense evasion, credential access, lateral movement). |
| **Cross-C2 Orchestrator** | `server/lib/c2-orchestrator.ts` | Coordinates operations across all five C2 frameworks (Caldera, Metasploit, Sliver, Empire, Cobalt Strike) plus GoPhish. Manages cross-C2 ability chains, automatic handoff based on kill chain phase and framework strengths, shared agent context (credentials, sessions, pivots), coordinated timing, and fallback chains. |

### Phase 6: Reporting (Automated)

| Tool | Module | What It Does |
|------|--------|--------------|
| **Corroboration Engine** | `corroboration` | Final cross-source validation of all findings across all phases. |
| **CARVER+Shock/CVSS Hybrid Scoring** | `scoring` via SSIL Risk Cards | Computes hybrid risk scores: CVSS (40%) + CARVER (40%) + BIA (20%). Generates risk cards with contributing signals, evidence artifacts, and prioritized remediations. |
| **Detection Rule Validation** | `detection_rules` via `server/routers/detection-rules.ts` | Tests SIEM/EDR detection rules against atomic test results and C2 activity. Identifies detection gaps. |
| **ATT&CK Coverage Heatmap** | `server/routers/attack-coverage.ts` | Generates technique coverage matrix showing tested vs. untested techniques across all 14 ATT&CK tactics. |

---

## 3. Additional Active Scanning Capabilities (Specialized Modules)

Beyond the core pipeline, the platform includes specialized active scanning modules that can be invoked against in-scope assets:

| Module | Router | Capability |
|--------|--------|------------|
| **Agentless BAS** | `server/routers/agentless-bas.ts` | 5 test types without deploying agents: cloud_api probes, network_probe, email_payload delivery, dns_exfil simulation, http_c2_sim callback testing |
| **Email Security Testing** | `server/routers/email-security.ts` | Tests email gateways (Proofpoint, Mimecast, Defender, Barracuda) with 5 payload types: phishing links, malware attachments, credential harvesting, BEC impersonation, macro documents |
| **NGFW Validation** | `server/routers/ngfw-validation.ts` | 6 test types against firewalls: port probing, protocol testing, lateral movement simulation, exfiltration attempts, C2 callback simulation, network segmentation validation |
| **EDR Validation** | `server/routers/edr-validation.ts` | Tests EDR product effectiveness against a built-in test catalog. Supports known products and calculates coverage matrices. |
| **Evasion Engine** | `server/routers/evasion-engine.ts` | 3-tier SIEM/EDR evasion: (1) SIEM Rule Mutation Engine — tests Sigma rule robustness, (2) Payload Transformation Pipeline — applies evasion techniques, (3) Evasion Scorecard — Purple Team loop for iterative improvement |
| **ICS/OT Security** | `server/routers/ics-ot-security.ts` | ICS device discovery (Shodan ICS, Censys, protocol fingerprinting), ICS exploit catalog (ICS-CERT, ExploitDB SCADA, Metasploit ICS), APT threat matching (11 ICS-targeting groups), OT protocol vulnerability analysis (9 protocols) |
| **Cloud Attack Paths** | `server/routers/cloud-attack-paths.ts` | Cloud-native attack path discovery for AWS, Azure, and GCP. IAM misconfiguration scanning, identity analysis, and privilege escalation path discovery. |
| **Config Baseline Scanning** | `server/routers/config-baseline.ts` | CIS Benchmark compliance scanning with drift detection and alerting. |
| **CI/CD Pipeline Security** | `server/routers/cicd-pipeline.ts` | Integrates security scanning into CI/CD workflows (GitHub Actions, Jenkins, GitLab CI, Azure DevOps). |
| **AI Security Validation** | `server/services/ai-security/validation-engine.ts` | MITRE ATLAS-aligned testing with 23 techniques and 31 payloads across 8 attack categories targeting customer AI/LLM deployments. |
| **Remediation Verification** | `server/routers/remediation-verification.ts` | Re-tests previously found vulnerabilities after remediation: re-exploit, scan recheck, config audit, or manual verification methods. SLA tracking by severity. |

---

## 4. Asset Scope Filtering

In-scope assets are determined through multiple mechanisms:

**ROE Scope Definition** (`server/routers/roe-builder.ts`): The ROE builder captures explicit scope boundaries including in-scope domains (with subdomain inclusion flags), IP ranges (CIDR notation with VLAN and location metadata), applications (web, API, mobile, desktop, thick client), cloud environments (AWS/Azure/GCP with account IDs and regions), and credential accounts. It also captures out-of-scope exclusions and allowed attack vectors.

**Pipeline Target Configuration** (`server/lib/unified-pipeline.ts`): Each pipeline run is initialized with a `PipelineTarget` that includes the primary domain, in-scope patterns (wildcards supported), and explicit out-of-scope exclusions. The `getPhaseTools()` function uses this scope to recommend tools and prioritize scanning based on discovered asset types.

**Scan Policy Engine Gating** (`server/lib/scan-policy-engine.ts`): Every scan request includes a `ScanAsset` with host, port, protocol, and tags. The `canExecute()` function validates each request against the active scan profile before any probe touches the target.

**Engagement-Level Scope** (`server/routers/engagement-automation.ts`): Engagements are created with scope metadata that flows through to all child operations. The engagement pipeline tracks which assets have been scanned, which tools have been run, and which findings have been produced.

---

## 5. SSIL Observation Flow

All active scan results are automatically ingested into the SSIL (Structured Security Intelligence Layer) through the **Observation Ingestor** (`server/lib/observation-ingestor.ts`). Six scanner-specific adapters normalize raw results into a unified `NormalizedObservation` schema:

| Adapter | Source Tools | Observation Types |
|---------|-------------|-------------------|
| `adaptNmapResults` | Nmap, Naabu | open_port, service_banner, os_fingerprint |
| `adaptNucleiResults` | Nuclei (all severity levels) | vulnerability, misconfiguration, exposure, technology |
| `adaptZgrab2Results` | ZGrab2 protocol probes | tls_certificate, http_header, service_banner, protocol_metadata |
| `adaptWebCrawlerResults` | Web Crawler, ZAP Spider | web_page, form, api_endpoint, javascript_resource |
| `adaptDomainIntelResults` | Domain Intel Pipeline (27 connectors) | dns_record, subdomain, certificate, breach_credential |
| `adaptVulnScanResults` | Nessus, Qualys, Rapid7, OpenVAS | vulnerability, misconfiguration, compliance_finding |

Observations flow through signal derivation and risk card generation (CVSS 40% + CARVER 40% + BIA 20%), producing a unified risk posture view with cross-scanner correlation.

---

## 6. Summary: Tool Count by Phase

| Pipeline Phase | Active Tools | Risk Tier | ROE Required |
|---------------|-------------|-----------|--------------|
| Recon | 5 (passive + light active) | Yellow | No |
| Enumeration | 6 | Orange | **Yes** |
| Vulnerability Assessment | 7 | Orange | **Yes** |
| Exploitation | 8 | Red | **Yes** |
| Post-Exploitation | 8 | Red | **Yes** |
| Reporting | 4 (automated) | Yellow | No |
| **Specialized Modules** | **11** | Orange/Red | **Yes** |
| **Total Unique Tool Categories** | **~30** | — | — |

The platform's active scanning arsenal positions it competitively against Picus (BAS-focused), Pentera (automated pentesting), Cymulate (BAS + exposure management), and Horizon3.ai (autonomous pentesting) by combining all four approaches — BAS, automated pentesting, exposure management, and adversary emulation — into a single unified pipeline with ROE-gated escalation and cross-source corroboration.
