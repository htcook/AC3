# Tool Audit: Functional vs Stub Status

## Exploit & Emulation (all have backend routers)
| Tool | Frontend | LOC | tRPC Calls | Status |
|------|----------|-----|------------|--------|
| Exploit Arsenal | ExploitArsenal.tsx | 1202 | 15 | FUNCTIONAL |
| Exploit Catalog | ExploitArsenal.tsx (shared) | 1202 | 15 | FUNCTIONAL (alias) |
| Exploitation Bridge | ExploitationBridge.tsx | 314 | 4 | FUNCTIONAL |
| Abilities Library | AbilitiesLibrary.tsx | 560 | 1 | FUNCTIONAL |
| Ability Graph | AbilityGraph.tsx | 1622 | 13 | FUNCTIONAL |
| Atomic Red Team | AtomicRedTeam.tsx | 793 | 7 | FUNCTIONAL |
| Emulation Playbooks | EmulationPlaybooks.tsx | 467 | 8 | FUNCTIONAL |
| Post-Exploit Playbooks | PostExploitPlaybooks.tsx | 686 | 11 | FUNCTIONAL |
| Payload Generator | PayloadGenerator.tsx | 780 | 6 | FUNCTIONAL |
| Evasion Engine | EvasionEngine.tsx | 2239 | 17 | FUNCTIONAL |
| Privilege Escalation | PrivilegeEscalation.tsx | 300 | 7 | FUNCTIONAL |
| Lateral Movement | LateralMovement.tsx | 221 | 3 | FUNCTIONAL |
| File Transfers | FileTransfers.tsx | 651 | 8 | FUNCTIONAL |
| Session Recordings | SessionRecordings.tsx | 580 | 5 | FUNCTIONAL |
| Data Exfil Simulation | DataExfilSimulation.tsx | 510 | 6 | FUNCTIONAL |
| Exploit Guardrails | ExploitGuardrails.tsx | 398 | 6 | FUNCTIONAL |

## C2 & Agents
| Tool | Frontend | LOC | tRPC Calls | Status |
|------|----------|-----|------------|--------|
| Agent Management | AgentManagement.tsx | 556 | 7 | FUNCTIONAL |
| C2 Command Center | C2CommandCenter.tsx | 729 | 12 | FUNCTIONAL |
| Ember Fleet | EmberFleetOverview.tsx | 445 | 4 | FUNCTIONAL |
| Ember Deploy | AgentManagement.tsx | 556 | 7 | SHARED |
| Ember Tasks | EmberTaskConsole.tsx | 560 | 6 | FUNCTIONAL |
| Ember Payloads | EmberPayloadArmory.tsx | 265 | 4 | FUNCTIONAL |
| Ember Swarm | EmberSwarmControl.tsx | 228 | 3 | FUNCTIONAL |
| Ember Intelligence | EmberIntelligence.tsx | 142 | 1 | LIGHT |

## Scanning & Assessment
| Tool | Frontend | LOC | tRPC Calls | Status |
|------|----------|-----|------------|--------|
| Web App Scanner | WebAppScanner.tsx | 1043 | 17 | FUNCTIONAL |
| ZAP Proxy | ZapProxySessions.tsx | 653 | 7 | FUNCTIONAL |
| Nuclei Scanner | NucleiScanner.tsx | 297 | 5 | FUNCTIONAL |
| Amass Scanner | AmassScanner.tsx | 594 | 7 | FUNCTIONAL |
| Batch Scanner | BatchDomainScanner.tsx | 890 | 12 | FUNCTIONAL |
| Vuln Scanner | VulnScanner.tsx | 526 | 10 | FUNCTIONAL |
| API Security Testing | APISecurityTesting.tsx | 440 | 8 | FUNCTIONAL |
| Auth Assessment | AuthAssessment.tsx | 401 | 1 | LIGHT |
| Web Crawler | WebCrawler.tsx | 1373 | 6 | FUNCTIONAL |
| Subfinder | DiscoveryToolkitHub.tsx | 44 | 0 | STUB |
| Httpx | DiscoveryToolkitHub.tsx | 44 | 0 | STUB |
| Naabu | DiscoveryToolkitHub.tsx | 44 | 0 | STUB |
| Active Verification | ActiveVerification.tsx | 239 | 4 | FUNCTIONAL |

## AD & Cloud
| Tool | Frontend | LOC | tRPC Calls | Status |
|------|----------|-----|------------|--------|
| AD Domain Connector | ADDomainConnector.tsx | 473 | 7 | FUNCTIONAL |
| AD Attack Path Graph | ADAttackPathGraph.tsx | 554 | 6 | FUNCTIONAL |
| AD Attack Sim | ADAttackSim.tsx | 373 | 6 | FUNCTIONAL |
| Bloodhound Import | BloodHoundImport.tsx | 670 | 10 | FUNCTIONAL |
| Forest Mapper | ADSecurityHub.tsx | 39 | 0 | STUB |
| Cloud Attack Paths | CloudAttackPaths.tsx | 945 | 6 | FUNCTIONAL |
| Cloud Credentials | CloudCredentials.tsx | 457 | 7 | FUNCTIONAL |
| ICS/OT Security | IcsOtSecurity.tsx | 1132 | 14 | FUNCTIONAL |

## Summary
- FUNCTIONAL: 30 tools with real UI + backend integration
- LIGHT: 2 tools with minimal backend integration (AuthAssessment, EmberIntelligence)
- STUB: 3 tools (Subfinder, Httpx, Naabu — all in DiscoveryToolkitHub.tsx, 44 LOC)
- MISSING PAGE: 0 tools (all previously missing pages have been created)

## Backend Routers: 222 total router files
Key tool routers confirmed: nuclei-scanner, nmap, exploit-arsenal, exploitation-bridge, payload-generator, evasion-engine, lateral-movement, web-app-scanning, scan-server, ember-agent, sliver-c2, manjusaka-c2
