# ACE C3 Platform Capability Audit

## Platform Statistics (Verified)
- 79 backend router files
- 831 tRPC procedures
- 122 frontend pages
- 168 database tables

## Verified Modules (with router + page + DB tables)

### Offensive Operations
1. Campaign Execution (campaigns, campaignAgents, campaignAbilities)
2. Adversary Emulation / Caldera Integration (emulationPlaybooks, playbookExecutions)
3. Purple Team Exercises (purpleTeam router)
4. Phishing Operations / GoPhish (phishingOps, phishingDrafts)
5. Metasploit Integration (metasploit, exploitJobs)
6. Sliver C2 (sliverC2 router)
7. Payload Generator (payloadGenerator)
8. Post-Exploit Playbooks (postExploitPlaybooks)
9. File Transfers (fileTransfers)
10. Session Recordings (sessionRecordings, recordingChunks)
11. Evasion Engine (evasionEngine)
12. AI Attack Planner (aiAttackPlanner, aiAttackPlans)

### Vulnerability & Scanning
13. Vulnerability Scanner (vulnScanner)
14. Nuclei Scanner (nucleiScanner)
15. Web App Scanner (webAppScanning, webAppScans, webAppFindings)
16. API Security Testing (apiSecurity)
17. Domain Intel (domainIntel, domainIntelScans, discoveredAssets)
18. Email Security (emailSecurity)

### Network & Infrastructure
19. Cloud Attack Paths (cloudAttackPaths)
20. Cloud Credentials (cloudCredentials)
21. AD Attack Simulation (adAttackSim)
22. AD Domain Connector (adDomainConnector)
23. AD Attack Path Graph (adAttackPathGraph)
24. Forest Mapper (forestMapper)
25. BloodHound Import (bloodhoundImport)
26. Credential Alerts (credentialAlerts)
27. Credential Auto-Rotation (credentialAutoRotation)
28. ICS/OT Security (icsOtSecurity, icsDevices, otNetworks, icsExploits)
29. Attack Path Discovery (attackPathDiscovery, attackPaths)

### Defense Validation
30. SIEM Connectors (siemConnectors)
31. SIEM Feedback Loop (siemFeedback)
32. EDR Validation (edrValidation)
33. NGFW Validation (ngfwValidation)
34. Agentless BAS (agentlessBAS)
35. Detection Rules (detectionRules, detectionTests, generatedDetectionRules)
36. Validation Scheduler (validationScheduler, validationRuns, validationResults)
37. SOAR Connectors (soarConnector, soarEvents)

### Intelligence
38. Threat Intel Hub (threatIntel, threatActors, threatActorAbilities, threatActorIocs)
39. Darkweb Intel (darkwebIntel, ransomwareGroups, ransomwareEvents)
40. Darkweb Bridge (darkwebBridge, accessBrokerListings, infoOpsCampaigns)
41. IOC Feed (iocFeed in routers.ts, iocFeeds, iocSyncLogs)
42. Threat Enrichment Engine (threatEnrichment)
43. TTP Knowledge Base (ttpKnowledge)
44. Campaign Archetypes (campaignArchetypes, archetypeActorMappings)
45. Threat Intel Training (threatIntelTraining)

### Compliance & Evidence
46. Compliance Mapper (complianceMapper)
47. Evidence Collection (evidence, evidenceItems, evidenceChainOfCustody)
48. STIX/TAXII Export (stixExport)
49. ROE Builder (roeBuilder, roeDocuments, roePersonnel, roeSignatures, roeVersions)
50. ROE Audit (roeAudit)

### FedRAMP / KSI
51. KSI Evidence Chain (ksiEvidenceChain, ksiEvidence, ksiEvidenceChains, ksiControlMappings)
52. KSI Validation Scheduler (ksiValidationScheduler, ksiValidationRuns, ksiValidationSchedules)
53. OSCAL Export (oscalExport, oscalExports)
54. Config Baseline (configBaseline, configBaselines, configBaselineRules, configScanResults, configDriftAlerts)
55. KSI Auto-Collector (ksiAutoCollector, collectionSchedules, collectionJobHistory)
56. KSI Threat Map (ksiThreatMap)
57. Attack Vector Engine (attackVectorEngine, attackVectors, attackVectorEvidence, attackPlaybooks)
58. KSI Scheduled Collection (ksiScheduledCollection)
59. Engagement Automation (engagementAutomation)
60. KSI Dashboard (KsiDashboard.tsx, ksiDefinitions)

### Reporting & Management
61. Report Generator (reportGenerator in routers.ts)
62. Report Templates (reportTemplates)
63. Template Generator (templateGenerator in routers.ts)
64. Post-Engagement Report (PostEngagementReport.tsx)
65. BIA Report (biaReport in routers.ts)
66. Engagement Manager (engagements, engagementPipelines)
67. Client Portal (clientPortal, engagementShares)
68. Scoring Hub (scoring, scoringProfiles, scoringAuditLog)
69. Risk Trending (riskTrending, defenseScores)
70. Bug Bounty Hub (bugBounty, bugBountyPrograms, bugBountyFindings)
71. Webhooks (webhooks, webhookEndpoints, webhookDeliveries)
72. Tenants (tenants)
73. Audit Log (offensiveAuditLog)
74. CI/CD Pipeline (cicdPipeline)
75. Compensating Controls (compensatingControls)
76. Pre-Flight Checks (preflightChecks)
77. Active Verification (activeVerification)
78. Corroboration Engine (corroborationEngine, corroborationResults)
79. NVD CVE Matcher (nvdCveMatcher)
80. Unified Pipeline (unifiedPipeline)
81. Atomic Red Team (atomicRedTeam, atomicTests, atomicTestExecutions)
82. Attack Coverage Matrix (attackCoverage)
83. Landing Page Builder (LandingPageBuilder.tsx)
84. Accuracy Engine (accuracyEngine)

## NOT Built (Referenced in Documents but Missing)
- Trust Center Portal (no router, no page, no DB tables)
- OAR Generator (no router, no page)
- IAM Configuration Auditor (no router, no page)
- Recovery Validation Module (no router, no page)
- Encryption & Data Handling Validator (no router, no page)
- SCG Generator (no router, no page)
- Agency ISSO Dashboard (no router, no page)
- Trust Center Aggregator (no router, no page)
- Cross-CSP Vulnerability Correlator (no router, no page)
- Agency Feedback Hub (no router, no page)
- Significant Change Monitor (no router, no page)
- Dual Deployment Mode (no config flag, no mode switching)
- OSCAL Bidirectional Pipeline (export exists, import does not)
- FRMR Schema Ingestion (not implemented)
- Multi-Tenant KSI Isolation (basic tenants exist, no KSI-specific row-level security)

## Coverage Corrections
- Original claim: "87% KSI coverage (47% direct, 40% supporting)"
- Audited reality: ~65% coverage (16 direct, 14 supporting, 16 planned/gap)
- The 87% figure counted phantom modules that don't exist
