# Caldera Dashboard — Module Architecture Analysis
## LLM-Automated Backend Tools vs. Human-Operated Roles

**Author:** Harrison Cook / AceofCloud  
**Date:** March 6, 2026  
**Codebase Audit:** 291 lib modules, 37 passive connectors, 5 knowledge modules, 147 routers, 1 domain intel orchestrator (~248K lines)

---

## Executive Summary

This report classifies every server-side module in the Caldera Dashboard platform based on a systematic audit of the actual codebase. Each module is categorized into one of three tiers based on decision complexity, latency tolerance, error impact, compliance requirements, and judgment needs:

| Tier | Description | Module Count | % of Total | Lines of Code |
|------|-------------|-------------|-----------|---------------|
| **Tier 1: LLM-Automated** | Fully autonomous backend tools | 273 | 62% | ~154K |
| **Tier 2: LLM-Assisted** | LLM does heavy lifting, human reviews | 109 | 25% | ~62K |
| **Tier 3: Human-Operated** | Requires human authority/judgment | 56 | 13% | ~32K |
| **Total** | | **438** | **100%** | **~248K** |

The analysis reveals that **87% of the platform** can be partially or fully automated by LLM orchestration, with only **13% requiring direct human control** — primarily exploitation, C2 operations, phishing campaigns, and legal/compliance sign-offs.

---

## Classification Criteria

| Criterion | Tier 1: LLM-Automated | Tier 2: LLM-Assisted | Tier 3: Human-Operated |
|-----------|----------------------|----------------------|----------------------|
| **Decision complexity** | Deterministic or pattern-based | Complex but bounded | Unbounded judgment |
| **Latency tolerance** | Seconds to minutes | Minutes to hours | Real-time tactical |
| **Data volume** | High throughput, repetitive | Medium, analytical | Low volume, high stakes |
| **Error impact** | Recoverable, non-destructive | Significant but bounded | Irreversible or legal |
| **Compliance need** | Audit trail sufficient | Review checkpoint required | Human sign-off mandatory |
| **Creativity** | Template-driven | Guided generation | Novel attack paths, social engineering |

---

## Tier 1: LLM-Automated Backend Tools (273 modules, ~62%)

These modules process data at scale, follow deterministic patterns, or perform analysis that benefits from LLM speed and consistency. They should run as autonomous backend services with no human intervention required.

### 1A. Passive Reconnaissance & OSINT (41 modules, ~13.9K lines)

All 37 passive connectors plus 4 supporting modules. These are pure API calls, data normalization, and pattern matching — the highest-value automation targets.

| Module | Lines | Function | Automation Rationale |
|--------|-------|----------|---------------------|
| `passive/abuseipdb.ts` | 178 | IP reputation lookup | Pure API call, deterministic |
| `passive/censys.ts` | 399 | Certificate/host enumeration | Structured query, no judgment |
| `passive/crtsh.ts` | 157 | CT log subdomain discovery | Data retrieval only |
| `passive/dns-resolver.ts` | 297 | DNS record enumeration | Protocol-level, deterministic |
| `passive/shodan.ts` | 472 | Port/service discovery | API query, structured response |
| `passive/urlscan.ts` | 228 | URL scanning | Automated submission |
| `passive/securitytrails.ts` | 289 | Historical DNS/WHOIS | Data retrieval |
| `passive/whois.ts` | 187 | Domain registration | Deterministic lookup |
| `passive/waf-detector.ts` | 264 | WAF fingerprinting | Signature matching |
| `passive/github-recon.ts` | 1,082 | Code search dorks | Pattern matching with token failover |
| `passive/github-leaks.ts` | 428 | Secret detection | Regex-based, deterministic |
| `passive/dehashed.ts` | 218 | Credential breach lookup | API query |
| + 25 additional connectors | ~6,527 | Various OSINT sources | All pure API calls |
| `domainIntel.ts` | 3,068 | Passive recon orchestrator | Orchestrates all 37 connectors |
| `domain-intel-advanced.ts` | 1,500 | Advanced domain analysis | Algorithmic enrichment |
| `org-domain-discovery.ts` | 932 | Org domain enumeration | Discovery automation |
| `org-enrichment.ts` | 1,049 | Organization enrichment | Data aggregation |

### 1B. Threat Intelligence Ingestion (18 modules, ~11.2K lines)

Feed collection, normalization, and synchronization — high-volume ETL pipelines that run on schedules.

| Module | Lines | Function | Automation Rationale |
|--------|-------|----------|---------------------|
| `threat-intel-ingest.ts` | 758 | Feed ingestion pipeline | ETL, no judgment |
| `threat-intel-rss.ts` | 775 | RSS feed aggregation | Automated polling |
| `threat-intel-connectors.ts` | 858 | Connector orchestration | API routing |
| `threat-intel-catalog.ts` | 1,038 | Threat intel catalog | CRUD management |
| `threat-actor-crawler.ts` | 1,341 | MITRE ATT&CK sync | Deterministic scraping |
| `threat-actor-matcher.ts` | 478 | TTP matching | Pattern correlation |
| `vuln-feeds.ts` | 1,073 | NVD/CVE feed sync | ETL pipeline |
| `vuln-feed-sync.ts` | 159 | Feed synchronization | Scheduled job |
| `vuln-scanner-parser.ts` | 260 | Scan output parsing | Format conversion |
| `ioc-sync.ts` | 252 | IOC synchronization | Data sync |
| `ioc-cross-reference.ts` | 349 | IOC cross-referencing | Set intersection |
| `kev-service.ts` | 679 | CISA KEV catalog | Catalog fetch/match |
| `ransomware-intel.ts` | 451 | Ransomware tracking | Feed collection |
| `darkweb-feeds.ts` | 864 | Dark web feeds | Scheduled collection |
| `darkweb-feed-scheduler.ts` | 351 | Feed scheduling | Timer-based |
| `dailydarkweb-feed.ts` | 550 | DailyDarkWeb API | API integration |
| `dailydarkweb-rss.ts` | 408 | DailyDarkWeb RSS | XML parsing |
| `ttp-ingest.ts` | 670 | TTP data ingestion | Data normalization |

### 1C. Scoring, Correlation & Analysis (32 modules, ~20.5K lines)

Algorithmic scoring, pattern matching, and data correlation. LLM enhances accuracy but core logic is deterministic.

| Module | Lines | Function | Automation Rationale |
|--------|-------|----------|---------------------|
| `scoring-engine.ts` | 1,679 | CARVER+Shock/CVSS hybrid | Algorithmic with LLM boost |
| `industry-baseline-scoring.ts` | 1,104 | Industry risk baselines | Statistical comparison |
| `auto-industry-carver.ts` | 1,203 | Automated CARVER classification | LLM-driven classification |
| `observation-normalizer.ts` | 1,117 | Scan observation normalization | Data transformation |
| `observation-ingestor.ts` | 764 | Observation ingestion | Data pipeline |
| `correlation-engine.ts` | 620 | Cross-source correlation | Pattern matching |
| `corroboration-engine.ts` | 663 | Multi-source corroboration | Evidence weighting |
| `domain-reputation-engine.ts` | 388 | Domain reputation scoring | Algorithmic |
| `dynamic-cpe-matcher.ts` | 502 | CPE matching for CVEs | String matching |
| `nvd-cve-matcher.ts` | 432 | NVD CVE matching | Database lookup |
| `exploit-matcher.ts` | 699 | Exploit-to-vuln matching | Pattern matching |
| `exploit-asset-matcher.ts` | 902 | Exploit-to-asset matching | Algorithmic |
| `entity-resolver.ts` | 576 | Entity deduplication | Fuzzy matching |
| `temporal-decay.ts` | 384 | Time-based score decay | Mathematical function |
| `cross-module-enrichment.ts` | 729 | Cross-module enrichment | Data joining |
| `enrichment-scheduler.ts` | 106 | Scheduled enrichment | Cron-based |
| `service-fingerprinter.ts` | 2,161 | Service version fingerprinting | Banner parsing |
| `waf-ngfw-detection.ts` | 1,565 | WAF/NGFW fingerprinting | Signature matching |
| `waf-detector.ts` | 264 | WAF technology detection | Signature matching |
| `dns-banner-verify.ts` | 473 | DNS/banner verification | Protocol checks |
| `cert-pinning.ts` | 495 | Certificate pinning analysis | Cryptographic verification |
| `email-security-analyzer.ts` | 850 | SPF/DKIM/DMARC analysis | DNS record parsing |
| `shodan-verifier.ts` | 604 | Shodan data verification | API lookup |
| `coalition-ess.ts` | 415 | Coalition ESS enrichment | API integration |
| `dehashed-service.ts` | 266 | DeHashed service | API integration |
| `bloodhound-parser.ts` | 918 | BloodHound data parsing | Graph parsing |
| `ad-attack-path-graph.ts` | 645 | AD attack path graphing | Graph analysis |
| `ad-domain-connector.ts` | 640 | AD domain connection | Protocol integration |
| `cloud-attack-paths.ts` | 232 | Cloud attack path analysis | Pattern matching |
| `cloud-storage-scanner.ts` | 903 | Cloud storage scanning | API-driven |
| `cloud-iam-enumerator.ts` | 696 | Cloud IAM enumeration | API-driven |
| `api-resilience.ts` | 448 | API resilience management | Retry logic |

### 1D. Knowledge & Training Modules (5 modules, 1,585 lines)

Static knowledge bases providing context to LLM prompts. Read-only reference data.

| Module | Lines | Function |
|--------|-------|----------|
| `knowledge/attack-chain-retriever.ts` | ~400 | Attack chain retrieval |
| `knowledge/asset-ontology.ts` | ~350 | Asset classification ontology |
| `knowledge/bugbounty-knowledge.ts` | ~350 | Bug bounty triage patterns |
| `knowledge/training-corpus.ts` | ~300 | Tool output training examples |
| `knowledge/cloud-security-knowledge.ts` | ~185 | Cloud security patterns |

### 1E. Report & Export Generation (16 modules, ~9.8K lines)

Template-driven output generation from analyzed data.

| Module | Lines | Function |
|--------|-------|----------|
| `report-generator.ts` | 991 | Pentest report generation |
| `report-narrative-generator.ts` | 258 | Narrative section generation |
| `report-export.ts` | 368 | Report format export |
| `pdf-report-generator.ts` | 369 | PDF rendering |
| `bia-report-generator.ts` | 630 | BIA report generation |
| `roe-pdf-generator.ts` | 835 | RoE PDF generation |
| `stix-generator.ts` | 709 | STIX 2.1 bundle generation |
| `oscal-depth-expansion.ts` | 447 | OSCAL document expansion |
| `rule-generator.ts` | 980 | Detection rule generation |
| `llm-rule-generator.ts` | 469 | LLM-enhanced rules |
| `sigma-rule-engine.ts` | 778 | Sigma rule translation |
| `zap-report-generator.ts` | 1,323 | ZAP scan reports |
| `compliance-mapper.ts` | 250 | Compliance mapping |
| `fips-compliance.ts` | 953 | FIPS compliance checking |
| `fips-crypto.ts` | 410 | FIPS crypto validation |
| `fips-tls.ts` | 283 | FIPS TLS validation |

### 1F. Infrastructure, Scheduling & Utilities (30 modules, ~11.5K lines)

Background services, schedulers, and infrastructure management.

| Module | Lines | Function |
|--------|-------|----------|
| `scan-scheduler.ts` | 456 | Scan job scheduling |
| `scan-recovery.ts` | 489 | Failed scan recovery |
| `scan-replay.ts` | 366 | Scan result replay |
| `crawler-scheduler.ts` | 676 | Web crawler scheduling |
| `dns-automation.ts` | 213 | DNS record automation |
| `digitalocean-infra.ts` | 285 | DO infrastructure management |
| `infra-deploy-automation.ts` | 822 | Infrastructure deployment |
| `ssh-tunnel-manager.ts` | 437 | SSH tunnel management |
| `fips-ssh.ts` | 100 | FIPS-compliant SSH |
| `fips-openssl-provider.ts` | 383 | OpenSSL FIPS provider |
| `fips-tls-global.ts` | 47 | Global TLS policy |
| `fips-audit-scheduler.ts` | 365 | FIPS audit scheduling |
| `mtls-certs.ts` | 565 | mTLS certificate management |
| `credential-crypto.ts` | 156 | Credential encryption |
| `credential-migration.ts` | 402 | Credential migration |
| `tenant-isolation.ts` | 314 | Multi-tenant isolation |
| `ws-event-hub.ts` | 889 | WebSocket event distribution |
| `error-logger.ts` | 187 | Error logging |
| `dashboard-aggregation.ts` | 672 | Dashboard data aggregation |
| `workflow-persistence.ts` | 287 | Workflow state persistence |
| `data-retention-policy.ts` | 319 | Data retention enforcement |
| `knowledge-store.ts` | 521 | Knowledge store management |
| `caldera-sync.ts` | 281 | Caldera server sync |
| `caldera-preflight.ts` | 246 | Caldera preflight checks |
| `api-helpers.ts` | 129 | API helper utilities |
| `agent-heartbeat.ts` | 324 | Agent heartbeat monitoring |
| `session-alerter.ts` | 337 | Session alerting |
| `cert-pins-captured.ts` | 55 | Certificate pin storage |
| `scanner-api-integration.ts` | 443 | Scanner API integration |
| `live-scanner-api.ts` | 603 | Live scanner API |

### 1G. Automated Router Endpoints (131 routers, ~46K lines)

tRPC routers that expose Tier 1 lib modules as API endpoints. These are CRUD operations, data retrieval, and pipeline triggers. Router classification follows the lib module it wraps.

> Key routers: `domain-intel-core.ts` (2,486 lines), `scoring.ts` (1,878 lines), `osint-core.ts` (777 lines), `threat-intel.ts` (534 lines), `threat-enrichment-engine.ts` (825 lines), `reports-core.ts` (554 lines), `report-export.ts` (265 lines), `sigma-rules.ts` (145 lines), `detection-rules.ts` (124 lines), `compliance-mapper.ts` (228 lines), `oscal-export.ts` (493 lines), `config-baseline.ts` (432 lines), `ioc-feed.ts` (235 lines), `stix-export.ts` (443 lines), `nvd-cve-matcher.ts` (61 lines), `risk-trending.ts` (84 lines), `platform-stats.ts` (98 lines), `error-log.ts` (576 lines), and 113 additional routers.

---

## Tier 2: LLM-Assisted with Human Oversight (109 modules, ~25%)

These modules involve complex decisions where the LLM provides analysis and recommendations, but a human should review before execution. The LLM handles 80-90% of the work; the human validates critical decision points.

### 2A. Scan Orchestration & Planning (14 modules)

| Module | Lines | Function | Human Review Point |
|--------|-------|----------|-------------------|
| `engagement-orchestrator.ts` | 4,175 | Full engagement pipeline | Review scan plan before active phase |
| `unified-pipeline.ts` | 1,271 | Unified scan pipeline | Review pipeline configuration |
| `discovery-engine.ts` | 1,206 | Asset discovery engine | Review discovered assets |
| `discovery-chain-orchestrator.ts` | 1,109 | Discovery chain execution | Review chain steps |
| `scan-policy-engine.ts` | 869 | Scan policy enforcement | Review policy exceptions |
| `scan-profiles.ts` | 402 | Scan profile management | Review profile changes |
| `nmap-orchestrator.ts` | 704 | Nmap scan orchestration | Review scan targets |
| `nuclei-engine.ts` | 306 | Nuclei scan orchestration | Review template selection |
| `zap-scanner.ts` | 1,714 | ZAP scan orchestration | Review scan scope |
| `zap-proxy-orchestrator.ts` | 1,212 | ZAP proxy management | Review proxy config |
| `zap-attack-playbooks.ts` | 1,351 | ZAP attack playbooks | Review attack playbook |
| `web-crawler.ts` | 907 | Web crawling engine | Review crawl scope |
| `scan-server-executor.ts` | 701 | Tool execution on DO | Review destructive commands |
| `preflight-checks.ts` | 454 | Pre-scan validation | Confirm readiness |

### 2B. Vulnerability Analysis & Triage (12 modules)

| Module | Lines | Function | Human Review Point |
|--------|-------|----------|-------------------|
| `vuln-analysis-agents.ts` | 510 | Multi-agent vuln analysis | Validate critical findings |
| `exploit-catalog.ts` | 857 | Exploit catalog management | Review new entries |
| `exploit-ingestion.ts` | 898 | Exploit data ingestion | Validate metadata |
| `exploit-preflight.ts` | 572 | Exploit preflight checks | Review safety checks |
| `exploit-feedback-loop.ts` | 486 | Exploit success feedback | Review accuracy |
| `bug-bounty-intelligence.ts` | 602 | Bug bounty intel analysis | Validate findings |
| `poc-generator.ts` | 486 | PoC code generation | Review PoC safety |
| `pentest-knowledge-base.ts` | 1,019 | Pentest methodology | Review updates |
| `auth-testing-knowledge.ts` | 1,052 | Auth testing patterns | Review patterns |
| `mobile-app-testing.ts` | 392 | Mobile security testing | Review scope |
| `nuclei-credential-mapper.ts` | 659 | Credential-to-nuclei mapping | Review mappings |
| `oem-default-creds.ts` | 553 | OEM default credentials | Review cred database |

### 2C. Threat Intelligence Analysis (12 modules)

| Module | Lines | Function | Human Review Point |
|--------|-------|----------|-------------------|
| `actor-context-provider.ts` | 1,475 | Actor context for engagements | Review actor mapping |
| `actor-behavioral-sequence-engine.ts` | 847 | Actor behavior sequencing | Review behavior models |
| `actor-module-connectors.ts` | 638 | Actor module connections | Review connections |
| `actor-graph-templates.ts` | 373 | Actor graph templates | Review templates |
| `darkweb-intel-service.ts` | 295 | Dark web intelligence | Review findings |
| `darkweb-enrichment-service.ts` | 196 | Dark web enrichment | Review accuracy |
| `darkweb-ioc-enrichment.ts` | 520 | Dark web IOC enrichment | Review IOC validity |
| `darkweb-osint-service.ts` | 660 | Dark web OSINT | Review correlation |
| `darkweb-mysql-service.ts` | 338 | Dark web data persistence | Review retention |
| `spicy-tip-bridge.ts` | 359 | Spicy TIP platform bridge | Review sync |
| `ttp-engine.ts` | 371 | TTP analysis engine | Review attribution |
| `atlas-technique-drilldown.ts` | 891 | ATLAS technique analysis | Review drilldowns |

### 2D. Hunt & Detection Engineering (10 modules)

| Module | Lines | Function | Human Review Point |
|--------|-------|----------|-------------------|
| `hunt-engine.ts` | 849 | Threat hunt workflow | Review hypotheses |
| `siem-mutation-engine.ts` | 1,342 | SIEM query mutation | Review mutated queries |
| `siem-connectors.ts` | 785 | SIEM platform connectors | Review config |
| `siem-feedback.ts` | 272 | SIEM detection feedback | Review feedback |
| `rule-validator.ts` | 890 | Detection rule validation | Review results |
| `rule-evidence-validator.ts` | 472 | Rule evidence validation | Review evidence chain |
| `attack-chain-validation.ts` | 948 | Attack chain validation | Review feasibility |
| `attack-sequence-learner.ts` | 1,208 | Attack sequence learning | Review learned patterns |
| `llm-scan-feedback.ts` | 612 | LLM scan feedback | Review LLM accuracy |
| `chain-builder.ts` | 814 | Attack chain building | Review chain logic |

### 2E. Compliance, Controls & Validation (14 modules)

| Module | Lines | Function | Human Review Point |
|--------|-------|----------|-------------------|
| `control-testing-engine.ts` | 1,322 | Security control testing | Review test results |
| `compensating-controls.ts` | 608 | Compensating control recs | Review recommendations |
| `guardrail-recommender.ts` | 988 | Security guardrail recs | Review config |
| `ai-security-validation.ts` | 1,241 | AI security validation | Review findings |
| `edr-validation.ts` | 142 | EDR validation testing | Review coverage |
| `validation-engine.ts` | 834 | Security validation engine | Review results |
| `remediation-verification.ts` | 760 | Remediation verification | Review verification |
| `ksi-continuous-monitoring.ts` | 267 | KSI continuous monitoring | Review alerts |
| `ksi-live-collectors.ts` | 974 | KSI live evidence collection | Review collection |
| `scap-compliance-scanner.ts` | 821 | SCAP compliance checking | Review benchmarks |
| `cloud-security-validation.ts` | 701 | Cloud security validation | Review findings |
| `cloud-attack-chain-designer.ts` | 838 | Cloud attack chain design | Review chains |
| `api-security-engine.ts` | 279 | API security testing | Review findings |
| `container-registry-service.ts` | 1,008 | Container registry security | Review findings |

### 2F. LLM Quality & Guardrails (6 modules)

| Module | Lines | Function | Human Review Point |
|--------|-------|----------|-------------------|
| `scoring-hardening.ts` | 520 | Score manipulation prevention | Review hardening rules |
| `llm-post-enrichment-analysis.ts` | 301 | Post-enrichment analysis | Review conclusions |
| `llm-resilience.ts` | 402 | LLM resilience testing | Review metrics |
| `llm-guardrails.ts` | 504 | LLM output guardrails | Review effectiveness |
| `prompt-injection-shield.ts` | 262 | Prompt injection defense | Review detections |
| `ai-decision-audit.ts` | 348 | AI decision auditing | Review audit trail |

### 2G. Engagement Workflow & Active Discovery (15 modules)

| Module | Lines | Function | Human Review Point |
|--------|-------|----------|-------------------|
| `engagement-workflow-engine.ts` | 687 | Workflow state machine | Review state transitions |
| `engagement-templates.ts` | 568 | Engagement templates | Review template changes |
| `engagement-timeline.ts` | 775 | Timeline management | Review scheduling |
| `role-chat-context.ts` | 362 | Role-based chat context | Review context |
| `role-chat-prompts.ts` | 431 | Role-based prompts | Review prompts |
| `role-quick-actions.ts` | 310 | Quick action definitions | Review actions |
| `quick-action-executor.ts` | 359 | Quick action execution | Review execution |
| `active-probes.ts` | 546 | Active probe execution | Review probe targets |
| `active-verification.ts` | 534 | Active verification | Review verification scope |
| `auto-crawl.ts` | 510 | Automated crawling | Review crawl scope |
| `crawl-compare.ts` | 494 | Crawl comparison | Review changes |
| `crawl-carver-integration.ts` | 571 | Crawl-CARVER integration | Review scoring |
| `projectdiscovery.ts` | 738 | ProjectDiscovery tools | Review tool selection |
| `amass-engine.ts` | 880 | Amass enumeration | Review scope |
| `redteam-discovery-coverage.ts` | 395 | Discovery coverage analysis | Review coverage gaps |

---

## Tier 3: Human-Operated (56 modules, ~13%)

These modules involve irreversible actions, legal implications, or real-time tactical decisions that require human authority. The LLM may provide advisory suggestions, but humans must authorize and control execution.

### 3A. Active Exploitation & C2 (18 modules, ~14K lines)

**Human operators must authorize and control all actions.**

| Module | Lines | Function | Why Human-Operated |
|--------|-------|----------|-------------------|
| `c2-abstraction.ts` | 2,115 | C2 framework abstraction | C2 ops require operator authority |
| `c2-orchestrator.ts` | 1,284 | C2 session orchestration | Real-time tactical decisions |
| `c2-actor-orchestration.ts` | 977 | Actor-specific C2 | Adversary emulation requires judgment |
| `c2-actor-feedback-loop.ts` | 644 | C2 actor behavior feedback | Tactical adaptation |
| `c2-learning-engine.ts` | 972 | C2 learning from ops | Operational learning review |
| `c2-module-builder.ts` | 1,057 | C2 module construction | Module safety review |
| `c2-traffic-profiles.ts` | 665 | C2 traffic profiles | OPSEC decisions |
| `c2-health.ts` | 381 | C2 infrastructure health | Infrastructure decisions |
| `cobalt-strike-adapter.ts` | 734 | Cobalt Strike integration | Licensed tool, operator control |
| `exploitation-bridge-engine.ts` | 24 | Exploitation bridge engine | Exploit execution authority |
| `exploitation-bridge.ts` | 499 | Exploitation bridge interface | Exploit authorization |
| `lateral-movement-engine.ts` | 605 | Lateral movement execution | Movement authorization |
| `privesc-engine.ts` | 771 | Privilege escalation | Escalation authorization |
| `auto-persistence.ts` | 339 | Persistence deployment | Persistence authorization |
| `credential-attack-engine.ts` | 1,219 | Credential attacks | Attack authorization |
| `credential-tester.ts` | 786 | Credential testing | Testing authorization |
| `msf-client.ts` | 776 | Metasploit client | Framework control |
| `msf-provisioner.ts` | 338 | Metasploit provisioning | Infrastructure setup |

### 3B. Phishing & Social Engineering (6 modules)

**Human operators must authorize targeting and content.**

| Module | Lines | Function | Why Human-Operated |
|--------|-------|----------|-------------------|
| `phishing-exploits.ts` | 1,330 | Phishing exploit generation | Content approval required |
| `crawl-phish-generator.ts` | 1,070 | Phishing page generation | Page approval required |
| `campaign-advisor.ts` | 432 | Campaign strategy | Strategy approval |
| `campaign-archetypes.ts` | 378 | Campaign archetypes | Archetype approval |
| `typosquat.ts` | 586 | Typosquatting analysis | Domain decisions |
| `external-credential-tools.ts` | 1,532 | External credential tools | Credential handling |

### 3C. Evasion & OPSEC (7 modules)

**Human operators must make OPSEC decisions.**

| Module | Lines | Function | Why Human-Operated |
|--------|-------|----------|-------------------|
| `evasion-orchestrator.ts` | 1,186 | Evasion orchestration | OPSEC judgment |
| `evasion-integrations.ts` | 557 | Evasion tool integrations | Tool selection |
| `evasion-playbook.ts` | 744 | Evasion playbook execution | Playbook approval |
| `evasion-scorecard.ts` | 803 | Evasion effectiveness | Effectiveness judgment |
| `evasion-validation.ts` | 944 | Evasion validation | Validation judgment |
| `opsec-monitor.ts` | 644 | OPSEC monitoring | Real-time OPSEC |
| `opsec-risk-engine.ts` | 455 | OPSEC risk assessment | Risk judgment |

### 3D. Payload & Infrastructure (5 modules)

| Module | Lines | Function | Why Human-Operated |
|--------|-------|----------|-------------------|
| `payload-transform-pipeline.ts` | 966 | Payload transformation | Payload approval |
| `redirector-manager.ts` | 747 | C2 redirector management | Infrastructure decisions |
| `caldera-graph-executor.ts` | 785 | Caldera graph execution | Operation authorization |
| `ability-graph-engine.ts` | 1,456 | Ability graph engine | Ability selection |
| `ai-attack-planner.ts` | 629 | AI attack planning | Plan approval |

### 3E. RoE, Scope & Legal (6 modules)

**Changes require authorized approval.**

| Module | Lines | Function | Why Human-Operated |
|--------|-------|----------|-------------------|
| `scope-guard.ts` | 913 | Scope enforcement engine | Scope changes require authority |
| `roe-guard.ts` | 204 | RoE enforcement | RoE changes require authority |
| `scope-enforcement-middleware.ts` | 351 | Scope middleware | Scope exception approval |
| `evidence-integrity.ts` | 272 | Evidence chain integrity | Legal chain of custody |
| `evidence-capture.ts` | 491 | Evidence capture | Evidence handling |
| `saml-service.ts` | 520 | SAML SSO service | Enterprise auth config |

### 3F. AD/ICS/OT Specialized (8 modules)

| Module | Lines | Function | Why Human-Operated |
|--------|-------|----------|-------------------|
| `ad-attack-engine.ts` | 271 | AD attack execution | AD attack authorization |
| `forest-mapper.ts` | 318 | AD forest mapping | Forest traversal decisions |
| `ics-device-discovery.ts` | 762 | ICS device discovery | Safety-critical environment |
| `ics-exploit-catalog.ts` | 745 | ICS exploit catalog | ICS safety review |
| `ot-protocol-analyzer.ts` | 680 | OT protocol analysis | OT safety review |
| `opsec-scheduled-scans.ts` | 295 | OPSEC scheduled scans | Scan authorization |
| `credential-auto-rotation.ts` | 766 | Credential rotation | Production cred approval |
| `credential-rotation-alerts.ts` | 218 | Rotation alerting | Alert configuration |

### 3G. Human-Operated Routers (25 routers)

Routers exposing Tier 3 lib modules: `roe-builder.ts` (752), `roe-audit.ts` (225), `engagements-core.ts` (486), `phishing-ops.ts` (1,371), `phishing/campaign-mgmt.ts` (595), `phishing/template-arsenal.ts` (138), `phishing/reporting-exploits.ts` (381), `gophish-proxy.ts` (432), `payload-generator.ts` (732), `post-exploit-playbooks.ts` (508), `privesc.ts` (108), `lateral-movement.ts` (141), `evasion-engine.ts` (946), `exploit-arsenal.ts` (459), `manjusaka-c2.ts` (458), `sliver-c2.ts` (241), `msf-sessions.ts` (450), `session-recordings.ts` (304), `evidence.ts` (262), `ksi-evidence-chain.ts` (502), `account-auth.ts` (1,048), `saml-auth.ts` (494), `agent/fips-mtls.ts` (278), `credential-auto-rotation.ts` (502), `ssh-keys.ts` (419).

---

## Key Insights

1. **The 37 passive connectors are the highest-ROI automation target.** They are pure API calls with zero judgment requirements. Moving them to DO workers eliminates ~10K lines of Manus backend load.

2. **The engagement orchestrator (4,175 lines) is the critical Tier 2 module.** It drives the entire scan pipeline but needs approval gates at phase transitions (passive to active to exploitation).

3. **C2 operations (18 modules, ~14K lines) are the largest Tier 3 cluster.** These will never be fully automated — they require real-time operator judgment and legal authorization.

4. **Knowledge modules (5 modules, 1,585 lines) are pure LLM fuel.** They provide zero-judgment context injection and should be cached aggressively.

5. **The scoring engine (1,679 lines) is a hybrid success story.** It combines deterministic CARVER/CVSS algorithms with LLM-enhanced triggers (KEV, attack chains, bug bounty) — a model for how Tier 1 modules can leverage LLM without requiring human review.

---

*Generated: March 6, 2026 | Caldera Dashboard v2.x | Codebase: 248K lines across 438 modules*
