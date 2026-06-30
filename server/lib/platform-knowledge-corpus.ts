/**
 * Platform Knowledge Corpus — Comprehensive AI Training Context
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Provides the AI with deep knowledge of the entire platform — all tools,
 * functions, threat actors, TTPs, ICS data, engagement types, ROE types,
 * and operational procedures.
 *
 * The AI should LEARN the platform, not just catalog it. This module builds
 * contextual knowledge that enables the AI to:
 *   1. Recommend the right tools for any engagement scenario
 *   2. Chain techniques across multiple modules
 *   3. Map threat actor TTPs to defensive recommendations
 *   4. Guide operators through complex multi-phase engagements
 *   5. Generate accurate, context-aware reports
 *   6. Understand ROE boundaries and autonomy constraints
 *
 * Integration:
 *   - Injected into AI chat system prompts via knowledge-lazy.ts
 *   - Used by campaign-advisor for engagement planning
 *   - Used by agent-chat-enhancer for specialist agent context
 *   - Used by report generation for comprehensive coverage
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export interface KnowledgeModule {
  id: string;
  name: string;
  category: KnowledgeCategory;
  description: string;
  /** Key concepts the AI must understand */
  concepts: string[];
  /** How this module connects to other modules */
  integrationPoints: string[];
  /** When to surface this knowledge */
  triggerContexts: string[];
  /** Depth level: overview (always included), detailed (on-demand), expert (specialist only) */
  depth: "overview" | "detailed" | "expert";
}

export type KnowledgeCategory =
  | "platform_capabilities"
  | "engagement_operations"
  | "threat_intelligence"
  | "offensive_techniques"
  | "defensive_recommendations"
  | "compliance_frameworks"
  | "ics_ot_security"
  | "ai_safety"
  | "reporting";

// ─── Platform Capability Knowledge ──────────────────────────────────────────

export const PLATFORM_CAPABILITIES: KnowledgeModule[] = [
  {
    id: "cap-engagement-orchestrator",
    name: "Engagement Orchestrator",
    category: "platform_capabilities",
    description: "Core engine that drives automated engagement execution through phases: passive recon → active scanning → vulnerability assessment → exploitation → post-exploitation → reporting. Manages approval gates (yellow/orange/red risk tiers), training lab mode, and ROE scope enforcement.",
    concepts: [
      "Phase-based execution pipeline with configurable depth",
      "Risk-tiered approval gates: yellow (informational), orange (moderate), red (destructive/C2)",
      "Training lab mode bypasses all approval gates for safe practice",
      "ROE scope guard enforces authorized domains/IPs at every phase",
      "Scan profiles: quick (5min), standard (30min), deep (2hr), stealth (low-and-slow)",
      "DAST integration with configurable crawl depth, scope, and rate limiting",
      "Exhaustive exploit mode: test every opportunity, not just first success",
      "Evidence collection at every phase with S3 storage",
    ],
    integrationPoints: ["graduated-autonomy.ts", "safety-engine.ts", "post-pipeline-graduation.ts", "roe-engagement-templates.ts"],
    triggerContexts: ["engagement planning", "scan execution", "approval decisions", "phase transitions"],
    depth: "detailed",
  },
  {
    id: "cap-graduated-autonomy",
    name: "Graduated Autonomy Framework",
    category: "platform_capabilities",
    description: "4-level autonomy model governing AI decision-making during engagements. Level 0 (Advisory): AI recommends only. Level 1 (Assisted): AI executes low-risk scans. Level 2 (Supervised): AI runs full chains with phase approval. Level 3 (Autonomous): AI operates independently within ROE.",
    concepts: [
      "Autonomy levels 0-3 with increasing AI independence",
      "ROE type caps: vuln_scan→L3, cicd→L3, pentest→L2, red_purple→L2, phishing→L1",
      "Graduation tier certification: Tier 1→L3, Tier 2→L2, Tier 3/4→L1, Tier 5→L0",
      "Operator can only lower autonomy, never raise above caps",
      "Anomaly detection auto-suspends to Level 0 on critical events",
      "Scope boundary approach triggers immediate suspension",
      "Red-tier actions always require dual operator approval regardless of level",
      "Autonomy state includes full audit trail of level changes",
    ],
    integrationPoints: ["engagement-orchestrator.ts", "graduation-lab-bridge.ts", "safety-engine.ts"],
    triggerContexts: ["autonomy decisions", "approval gates", "anomaly handling", "engagement configuration"],
    depth: "detailed",
  },
  {
    id: "cap-safety-engine",
    name: "Safety Engine",
    category: "platform_capabilities",
    description: "Production-safe autonomous mode with 4 safety levels: passive_only (zero target interaction), low_impact (non-destructive scanning), standard (controlled exploitation), full_exploitation (all techniques). Pre-execution risk assessment, blast radius estimation, and safety audit trail.",
    concepts: [
      "Safety profiles gate every tool execution and phase transition",
      "Tool category allowlists per safety level",
      "Predictive blast radius estimation before exploitation",
      "Dual-approval required for full_exploitation level",
      "Blocked scan flags and Nuclei tags per safety level",
      "Rate limiting per host to prevent DoS",
      "Integration with ScanPolicyEngine for SSIL controls",
    ],
    integrationPoints: ["engagement-orchestrator.ts", "graduated-autonomy.ts", "scan-policy-engine.ts"],
    triggerContexts: ["tool execution", "safety assessment", "risk evaluation"],
    depth: "detailed",
  },
  {
    id: "cap-llm-graduation",
    name: "LLM Graduation Pipeline",
    category: "platform_capabilities",
    description: "5-tier graduation system for 6 specialist AI models (recon_analyst, exploit_selector, evasion_optimizer, cognitive_core, cloud_assessor, supply_chain_analyst). Models progress from Tier 5 (Untested) to Tier 1 (Ready) based on benchmark performance, lab scenarios, and dual-sign-off promotion gates.",
    concepts: [
      "6 specialist models with distinct capabilities and scoring criteria",
      "5 graduation tiers: Ready(1), Near(2), Emerging(3), Training(4), Untested(5)",
      "Tier 1/2 promotions require dual operator sign-off (72hr expiry)",
      "Lab scenarios unlocked by tier: basic→operational→advanced→full",
      "Training data collected from every pipeline execution",
      "Benchmark scoring across multiple dimensions per specialist",
      "Model rollback capability if performance degrades",
    ],
    integrationPoints: ["graduation-lab-bridge.ts", "training-corpus.ts", "graduated-autonomy.ts"],
    triggerContexts: ["model evaluation", "training data review", "promotion decisions"],
    depth: "expert",
  },
  {
    id: "cap-tenant-isolation",
    name: "Multi-Tenant Isolation",
    category: "platform_capabilities",
    description: "Row-level security enforcement across all tenant-scoped tables. Every protected procedure uses tenant context from middleware. Cross-tenant access is structurally impossible when using scoped query helpers.",
    concepts: [
      "TenantMiddleware resolves active tenant from membership table",
      "Tenant context injected into tRPC context (tenantId, tenantRole, tenantName, tenantPlan)",
      "Scoped query helpers enforce WHERE tenant_id = ? on all queries",
      "X-Tenant-Id header for multi-tenant users",
      "Tenant roles: owner, admin, operator, viewer",
      "Tenant plans: free, pro, enterprise (gate feature access)",
    ],
    integrationPoints: ["ai-chat-safety.ts", "all routers using protectedProcedure"],
    triggerContexts: ["data access", "authorization", "multi-tenant operations"],
    depth: "detailed",
  },
  {
    id: "cap-ai-governance",
    name: "AI Governance (NIST AI 600-1)",
    category: "ai_safety",
    description: "Comprehensive AI governance framework implementing NIST AI 600-1 risk management. Includes prompt injection detection (12+ patterns), jailbreak defense, PII scrubbing, confabulation detection, and MITRE ATLAS adversarial test suite.",
    concepts: [
      "12 prompt injection detection patterns with severity classification",
      "Homoglyph normalization for Unicode-based attacks",
      "Encoding attack detection (base64, rot13, hex)",
      "Dangerous code filtering in AI outputs",
      "PII detection and scrubbing (SSN, credit cards, emails)",
      "Confabulation detection via confidence scoring",
      "MITRE ATLAS test categories: prompt injection, model extraction, adversarial evasion, data poisoning",
    ],
    integrationPoints: ["ai-chat-safety.ts", "llm-guardrails.ts", "ai-security-validation.ts"],
    triggerContexts: ["AI interactions", "security validation", "compliance audits"],
    depth: "detailed",
  },
];

// ─── Engagement Operations Knowledge ────────────────────────────────────────

export const ENGAGEMENT_OPERATIONS: KnowledgeModule[] = [
  {
    id: "ops-roe-types",
    name: "ROE Engagement Types",
    category: "engagement_operations",
    description: "5 engagement types with distinct scope, guardrails, and autonomy caps. Each type has calibrated legal language, liability protections, and compliance mappings.",
    concepts: [
      "Vulnerability Scanning: Non-intrusive, automated, broad scope. Max autonomy L3. No exploitation.",
      "Penetration Testing: Controlled exploitation within defined scope. Max autonomy L2. Evidence-based.",
      "Red/Purple Team: Adversary emulation with stealth objectives. Max autonomy L2. Kill chain execution.",
      "CI/CD Integration: Automated pipeline security testing. Max autonomy L3. Shift-left focus.",
      "Phishing: Human-targeted social engineering. Max autonomy L1. Legal sensitivity, reputation risk.",
      "Each type has: scope template, guardrails, liability language, compliance mappings, autonomy cap",
      "NIST SP 800-115 alignment for all types",
      "FedRAMP and CISA BOD compliance requirements mapped to wizard fields",
    ],
    integrationPoints: ["roe-engagement-templates.ts", "roe-self-service.ts", "graduated-autonomy.ts"],
    triggerContexts: ["ROE creation", "engagement planning", "scope definition", "compliance questions"],
    depth: "detailed",
  },
  {
    id: "ops-scan-profiles",
    name: "Scan Profiles & Tooling",
    category: "engagement_operations",
    description: "Configurable scan profiles that balance thoroughness with stealth. Integrates ScanForge (Nmap), Nuclei, ZAP, Burp Suite, and custom tools.",
    concepts: [
      "Quick profile: 5min, top-1000 ports, basic vuln templates, high rate",
      "Standard profile: 30min, full TCP, comprehensive templates, moderate rate",
      "Deep profile: 2hr, TCP+UDP, all templates + custom, thorough crawling",
      "Stealth profile: low-and-slow, randomized timing, evasion techniques",
      "ScanForge: Nmap wrapper with SSIL policy enforcement",
      "Nuclei: Template-based vulnerability scanning with severity filtering",
      "ZAP/Burp: DAST scanning with authenticated crawling",
      "Tool chaining: recon → port scan → service detection → vuln scan → exploitation",
    ],
    integrationPoints: ["engagement-orchestrator.ts", "scan-policy-engine.ts", "scanforge-knowledge.ts"],
    triggerContexts: ["scan configuration", "tool selection", "profile recommendations"],
    depth: "detailed",
  },
  {
    id: "ops-evidence-collection",
    name: "Evidence Collection & Reporting",
    category: "engagement_operations",
    description: "Comprehensive evidence collection at every engagement phase. Screenshots, terminal output, HTTP request/response pairs, exploit code, tool output, PCAPs, and video recordings. All stored in S3 with integrity hashing.",
    concepts: [
      "Evidence types: screenshot, terminal_output, http_request_response, exploit_code, tool_output, notes, pcap, video, document",
      "S3 storage with presigned URLs for secure access",
      "Evidence integrity via SHA-256 hashing (KSI evidence chain)",
      "Automatic evidence capture during automated phases",
      "Manual evidence upload for operator-driven phases",
      "Report generation from collected evidence (executive, technical, compliance)",
      "CVSS scoring and risk rating for each finding",
    ],
    integrationPoints: ["ksi-evidence-chain.ts", "ac3-reports.ts", "engagement-orchestrator.ts"],
    triggerContexts: ["evidence review", "report generation", "finding documentation"],
    depth: "detailed",
  },
];

// ─── Threat Intelligence Knowledge ──────────────────────────────────────────

export const THREAT_INTELLIGENCE: KnowledgeModule[] = [
  {
    id: "ti-government-sources",
    name: "Government Threat Intelligence Sources",
    category: "threat_intelligence",
    description: "Automated ingestion from 7 government sources: OFAC SDN (sanctions), Rewards for Justice (bounties), FBI Cyber Most Wanted, DOJ indictments, NSA advisories, ACSC (Australia), CCCS (Canada). Daily pipeline at 03:30 UTC.",
    concepts: [
      "OFAC SDN: Sanctioned entities with cyber program designations",
      "Rewards for Justice: Up to $10M bounties for cyber threat actors",
      "FBI Cyber Most Wanted: Active investigations with known aliases",
      "DOJ: Indictments revealing TTPs, infrastructure, and co-conspirators",
      "NSA: Technical advisories on nation-state TTPs and mitigations",
      "ACSC: Australian threat landscape and critical infrastructure alerts",
      "CCCS: Canadian cyber threat assessments and advisories",
      "Cross-referencing across sources for comprehensive actor profiles",
    ],
    integrationPoints: ["government-intel-sources.ts", "threat-intel-daily-scheduler.ts", "threat-actor-learning-context.ts"],
    triggerContexts: ["threat actor research", "attribution", "sanctions compliance", "actor profiles"],
    depth: "detailed",
  },
  {
    id: "ti-ics-scada",
    name: "ICS/SCADA Threat Intelligence",
    category: "ics_ot_security",
    description: "Specialized ICS/OT intelligence covering CISA ICS advisories, CSAF OT parsing, Siemens ProductCERT, ICS malware families (Stuxnet, TRITON, Industroyer, PIPEDREAM), open-source tools, and 19 Dragos-named threat groups.",
    concepts: [
      "14 ICS protocols: Modbus, DNP3, S7comm, BACnet, EtherNet/IP, OPC UA, IEC 104, Profinet, CODESYS, TriStation, MQTT, M-Bus, HART, Foundation Fieldbus",
      "10 ICS vendors: Siemens, Schneider, Rockwell, ABB, Honeywell, OMRON, Emerson, GE, Yokogawa, Mitsubishi",
      "8+ ICS malware families with detailed TTPs and affected systems",
      "19 Dragos threat groups (CHERNOVITE, ELECTRUM, XENOTIME, etc.)",
      "CISA ICS-CERT advisory RSS feed integration",
      "CSAF (Common Security Advisory Framework) OT-specific parsing",
      "ICS-capable actor auto-tagging based on TTPs and targets",
      "Dragos WorldView, Claroty Team82, Nozomi Labs RSS feeds",
    ],
    integrationPoints: ["ics-scada-intel.ts", "threat-intel-daily-scheduler.ts", "engagement-orchestrator.ts"],
    triggerContexts: ["ICS engagement", "OT security assessment", "critical infrastructure", "ICS threat actors"],
    depth: "detailed",
  },
  {
    id: "ti-threat-actors",
    name: "Threat Actor Knowledge Base",
    category: "threat_intelligence",
    description: "Comprehensive threat actor catalog with 1600+ actors. Includes nation-state APTs, cybercrime groups, hacktivists, and insider threats. Each actor has aliases, TTPs, target sectors, tools, and campaign history.",
    concepts: [
      "Actor types: nation_state, cybercrime, hacktivist, insider, unknown",
      "Attribution confidence levels and multi-source correlation",
      "MITRE ATT&CK TTP mapping for each actor",
      "Tool and malware associations",
      "Target sector and geography preferences",
      "Campaign timeline and evolution tracking",
      "Cross-referencing with government sources (OFAC, FBI, DOJ)",
      "Threat level scoring: critical, high, medium, low",
    ],
    integrationPoints: ["threat-group-knowledge.ts", "threat-actor-learning-context.ts", "government-intel-sources.ts"],
    triggerContexts: ["actor research", "attribution", "threat modeling", "adversary emulation"],
    depth: "detailed",
  },
];

// ─── Offensive Techniques Knowledge ─────────────────────────────────────────

export const OFFENSIVE_TECHNIQUES: KnowledgeModule[] = [
  {
    id: "off-file-upload-bypass",
    name: "File Upload Bypass Techniques",
    category: "offensive_techniques",
    description: "80+ file upload bypass techniques covering extension manipulation, MIME confusion, magic bytes, polyglots, race conditions, path traversal, and WAF evasion. Tech-stack-specific strategies for PHP, ASP.NET, Java, Node.js, and Python.",
    concepts: [
      "Extension manipulation: case, double, null byte, special chars (newline, tab, space, dot, semicolon)",
      "MIME confusion: Content-Type spoofing, magic bytes injection, SVG/HTML for XSS",
      "Polyglot files: GIF+PHP, PHAR+JPEG, HTML+Image, GIFAR",
      "Race conditions: TOCTOU, parallel upload, chunked reassembly",
      "Path traversal: basic, encoded, IIS-specific, overlong UTF-8",
      "WAF evasion: boundary manipulation, Content-Disposition tricks, chunked encoding",
      "Post-upload: web shell execution, LFI chaining, stored XSS, SSRF to cloud metadata",
      "Tech-stack profiles with recommended bypass order and known weaknesses",
    ],
    integrationPoints: ["file-upload-bypass-knowledge.ts", "offensive-techniques-knowledge.ts", "training-corpus.ts"],
    triggerContexts: ["file upload testing", "web application pentest", "bypass strategy", "exploit development"],
    depth: "expert",
  },
  {
    id: "off-owasp-top10",
    name: "OWASP Top 10 & Web Application Security",
    category: "offensive_techniques",
    description: "Deep knowledge of OWASP Top 10 (2021) vulnerabilities with detection, exploitation, and remediation. Includes injection, broken auth, sensitive data exposure, XXE, broken access control, security misconfiguration, XSS, insecure deserialization, vulnerable components, and insufficient logging.",
    concepts: [
      "A01:2021 Broken Access Control: IDOR, privilege escalation, CORS misconfiguration",
      "A02:2021 Cryptographic Failures: weak algorithms, key management, TLS issues",
      "A03:2021 Injection: SQLi, NoSQLi, LDAP, OS command, template injection",
      "A04:2021 Insecure Design: threat modeling failures, business logic flaws",
      "A05:2021 Security Misconfiguration: default creds, unnecessary features, verbose errors",
      "A06:2021 Vulnerable Components: outdated libraries, known CVEs, supply chain",
      "A07:2021 Auth Failures: credential stuffing, session management, MFA bypass",
      "A08:2021 Software Integrity: CI/CD compromise, unsigned updates, deserialization",
      "A09:2021 Logging Failures: insufficient monitoring, alert fatigue, log injection",
      "A10:2021 SSRF: internal service access, cloud metadata, port scanning",
    ],
    integrationPoints: ["owasp-knowledge.ts", "engagement-orchestrator.ts", "nuclei templates"],
    triggerContexts: ["web app testing", "vulnerability assessment", "remediation guidance"],
    depth: "detailed",
  },
  {
    id: "off-mitre-attack",
    name: "MITRE ATT&CK Framework",
    category: "offensive_techniques",
    description: "Complete MITRE ATT&CK Enterprise matrix knowledge covering 14 tactics, 200+ techniques, and 600+ sub-techniques. Used for adversary emulation, detection engineering, and gap analysis.",
    concepts: [
      "14 tactics from Initial Access through Impact",
      "Technique-to-tool mapping for automated execution",
      "Sub-technique granularity for precise emulation",
      "ATT&CK Navigator overlay generation",
      "Procedure examples from real-world campaigns",
      "Detection opportunities at each technique",
      "Data sources required for visibility",
      "Red team vs blue team perspective on each technique",
    ],
    integrationPoints: ["threat-group-knowledge.ts", "caldera-proxy.ts", "attack-chains.ts"],
    triggerContexts: ["adversary emulation", "detection engineering", "gap analysis", "purple team"],
    depth: "detailed",
  },
];

// ─── Compliance Framework Knowledge ─────────────────────────────────────────

export const COMPLIANCE_FRAMEWORKS: KnowledgeModule[] = [
  {
    id: "comp-nist-800-115",
    name: "NIST SP 800-115 Technical Guide",
    category: "compliance_frameworks",
    description: "Technical guide to information security testing and assessment. Defines ROE requirements, test planning, execution methodology, and reporting standards for federal systems.",
    concepts: [
      "ROE must define: scope, rules, timeline, communication, escalation, evidence handling",
      "Test types: review, target identification, target vulnerability validation, target exploitation",
      "Planning phase: objectives, scope, approach, logistics, legal considerations",
      "Execution phase: coordination, data handling, incident response, status reporting",
      "Post-testing: analysis, reporting, remediation verification",
      "Assessment methodology: passive (review), active (scanning), exploitation (validation)",
    ],
    integrationPoints: ["roe-self-service.ts", "roe-engagement-templates.ts", "ac3-reports.ts"],
    triggerContexts: ["ROE creation", "test planning", "compliance validation", "federal engagements"],
    depth: "detailed",
  },
  {
    id: "comp-fedramp",
    name: "FedRAMP Security Assessment",
    category: "compliance_frameworks",
    description: "Federal Risk and Authorization Management Program requirements for cloud security assessments. Defines control testing methodology, evidence requirements, and continuous monitoring.",
    concepts: [
      "FedRAMP baselines: Low, Moderate, High impact levels",
      "Control families: AC, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PS, RA, SA, SC, SI",
      "Penetration testing requirements per FedRAMP guidance",
      "Continuous monitoring: monthly vuln scans, annual assessments",
      "POA&M (Plan of Action and Milestones) for findings",
      "3PAO (Third Party Assessment Organization) requirements",
    ],
    integrationPoints: ["roe-self-service.ts", "roe-engagement-templates.ts"],
    triggerContexts: ["FedRAMP assessment", "federal cloud testing", "compliance reporting"],
    depth: "detailed",
  },
  {
    id: "comp-fips-140-3",
    name: "FIPS 140-3 Cryptographic Standards",
    category: "compliance_frameworks",
    description: "Federal Information Processing Standard for cryptographic module validation. Defines approved algorithms, key lengths, and operational requirements for protecting sensitive information.",
    concepts: [
      "Approved symmetric: AES-128/192/256 (GCM, CCM, CBC)",
      "Approved asymmetric: RSA-2048+, ECDSA P-256/P-384/P-521, Ed25519",
      "Approved hash: SHA-256, SHA-384, SHA-512, SHA-3",
      "Approved KDF: HKDF, PBKDF2, SP 800-108",
      "TLS 1.2+ required, TLS 1.3 preferred",
      "Approved cipher suites for TLS",
      "Key management: generation, storage, distribution, destruction",
      "Security levels 1-4 with increasing physical security requirements",
    ],
    integrationPoints: ["fips-crypto-policy.ts", "roe-engagement-templates.ts"],
    triggerContexts: ["cryptographic decisions", "federal compliance", "secure communications"],
    depth: "expert",
  },
];

// ─── Knowledge Assembly Functions ───────────────────────────────────────────

/**
 * Builds the complete platform knowledge context for AI system prompts.
 * Returns a structured overview suitable for injection into LLM context.
 */
export function buildPlatformKnowledgeContext(options?: {
  depth?: "overview" | "detailed" | "expert";
  categories?: KnowledgeCategory[];
  triggerContext?: string;
}): string {
  const depth = options?.depth ?? "overview";
  const categories = options?.categories;
  const trigger = options?.triggerContext;

  const allModules = [
    ...PLATFORM_CAPABILITIES,
    ...ENGAGEMENT_OPERATIONS,
    ...THREAT_INTELLIGENCE,
    ...OFFENSIVE_TECHNIQUES,
    ...COMPLIANCE_FRAMEWORKS,
  ];

  let filtered = allModules;

  // Filter by depth
  const depthOrder: Record<string, number> = { overview: 0, detailed: 1, expert: 2 };
  filtered = filtered.filter((m) => depthOrder[m.depth] <= depthOrder[depth]);

  // Filter by category
  if (categories) {
    filtered = filtered.filter((m) => categories.includes(m.category));
  }

  // Filter by trigger context
  if (trigger) {
    const triggerLower = trigger.toLowerCase();
    filtered = filtered.filter(
      (m) => m.triggerContexts.some((tc) => triggerLower.includes(tc.toLowerCase())) ||
             m.description.toLowerCase().includes(triggerLower)
    );
  }

  // Build context string
  let context = `# AC3 Platform Knowledge Base\n\n`;
  context += `You have deep knowledge of the AC3 (AceofCloud Cyber Command) platform.\n`;
  context += `This platform is a comprehensive red team / threat intelligence system.\n\n`;

  // Group by category
  const grouped = new Map<KnowledgeCategory, KnowledgeModule[]>();
  for (const mod of filtered) {
    const existing = grouped.get(mod.category) ?? [];
    existing.push(mod);
    grouped.set(mod.category, existing);
  }

  const categoryNames: Record<KnowledgeCategory, string> = {
    platform_capabilities: "Platform Capabilities",
    engagement_operations: "Engagement Operations",
    threat_intelligence: "Threat Intelligence",
    offensive_techniques: "Offensive Techniques",
    defensive_recommendations: "Defensive Recommendations",
    compliance_frameworks: "Compliance Frameworks",
    ics_ot_security: "ICS/OT Security",
    ai_safety: "AI Safety & Governance",
    reporting: "Reporting & Documentation",
  };

  for (const [category, modules] of grouped) {
    context += `## ${categoryNames[category]}\n\n`;
    for (const mod of modules) {
      context += `### ${mod.name}\n`;
      context += `${mod.description}\n\n`;
      if (depth !== "overview") {
        context += `Key concepts:\n`;
        for (const concept of mod.concepts.slice(0, depth === "expert" ? undefined : 4)) {
          context += `- ${concept}\n`;
        }
        context += `\n`;
      }
    }
  }

  return context;
}

/**
 * Builds engagement-specific knowledge context based on the engagement type.
 */
export function buildEngagementKnowledgeContext(
  engagementType: "vulnerability_scanning" | "penetration_testing" | "red_purple_team" | "cicd_integration" | "phishing"
): string {
  const typeContexts: Record<string, string> = {
    vulnerability_scanning: `
# Vulnerability Scanning Engagement Context

You are assisting with a vulnerability scanning engagement. Key parameters:
- Autonomy Level: Up to Level 3 (Autonomous within ROE)
- Scope: Non-intrusive scanning only. NO exploitation.
- Tools: Nuclei, Nmap (ScanForge), DAST scanners
- Objective: Identify vulnerabilities without exploiting them
- Reporting: CVSS scoring, remediation priorities, compliance mapping
- Constraints: Rate limiting, scan windows, excluded hosts

Recommended approach:
1. Passive recon (DNS, certificates, OSINT)
2. Port scanning with service detection
3. Vulnerability scanning with severity-appropriate templates
4. False positive validation (non-intrusive verification)
5. Risk-prioritized reporting with remediation guidance
`,
    penetration_testing: `
# Penetration Testing Engagement Context

You are assisting with a penetration test. Key parameters:
- Autonomy Level: Up to Level 2 (Supervised — pause between phases)
- Scope: Controlled exploitation within defined boundaries
- Tools: Full toolkit — Nuclei, Metasploit, Burp, custom exploits
- Objective: Demonstrate real-world impact through exploitation
- Reporting: Evidence-based findings with proof of exploitation
- Constraints: ROE boundaries, excluded systems, business hours

Recommended approach:
1. Comprehensive reconnaissance (passive + active)
2. Vulnerability identification and prioritization
3. Exploitation of confirmed vulnerabilities (with evidence)
4. Post-exploitation assessment (privilege escalation, lateral movement if in scope)
5. Detailed technical report with attack narratives
`,
    red_purple_team: `
# Red/Purple Team Engagement Context

You are assisting with a red/purple team exercise. Key parameters:
- Autonomy Level: Up to Level 2 (Supervised — operator approves phases)
- Scope: Adversary emulation with stealth objectives
- Tools: Full offensive toolkit + C2 frameworks (Caldera, custom)
- Objective: Test detection and response capabilities
- Reporting: Kill chain documentation, detection gaps, MITRE ATT&CK mapping
- Constraints: Rules of engagement, no-strike list, deconfliction procedures

Recommended approach:
1. Threat modeling — select adversary to emulate (APT group, TTPs)
2. Infrastructure setup (C2, redirectors, phishing infrastructure)
3. Initial access (phishing, exploit, supply chain)
4. Establish persistence and C2 communications
5. Lateral movement toward objectives
6. Objective completion (data access, domain admin, etc.)
7. Purple team: share findings with blue team for detection improvement
`,
    cicd_integration: `
# CI/CD Integration Engagement Context

You are assisting with CI/CD security integration. Key parameters:
- Autonomy Level: Up to Level 3 (Autonomous within pipeline)
- Scope: Automated security testing in development pipeline
- Tools: SAST, DAST, SCA, container scanning, IaC scanning
- Objective: Shift-left security — find vulnerabilities before production
- Reporting: Developer-friendly findings with fix guidance
- Constraints: Pipeline time budgets, false positive tolerance

Recommended approach:
1. Pipeline analysis — identify integration points
2. SAST integration for code-level vulnerabilities
3. SCA for dependency vulnerabilities (CVE matching, KEV)
4. DAST for runtime vulnerabilities in staging
5. Container/IaC scanning for infrastructure issues
6. Automated gating — block deployments above threshold
`,
    phishing: `
# Phishing Engagement Context

You are assisting with a phishing engagement. Key parameters:
- Autonomy Level: Up to Level 1 (Assisted — operator approves all actions)
- Scope: Social engineering testing of human targets
- Tools: GoPhish, custom templates, domain infrastructure
- Objective: Assess human vulnerability to social engineering
- Reporting: Click rates, credential submission rates, awareness gaps
- Constraints: Legal requirements, HR coordination, target list approval, no real malware

Recommended approach:
1. Target research — roles, communication patterns, technology
2. Pretext development — realistic scenarios for the organization
3. Infrastructure setup — lookalike domains, landing pages, tracking
4. Campaign execution — phased delivery with monitoring
5. Results analysis — who clicked, who reported, response times
6. Awareness recommendations based on findings
`,
  };

  return typeContexts[engagementType] ?? typeContexts.penetration_testing;
}

/**
 * Returns the total count of knowledge modules available.
 */
export function getKnowledgeModuleCount(): number {
  return (
    PLATFORM_CAPABILITIES.length +
    ENGAGEMENT_OPERATIONS.length +
    THREAT_INTELLIGENCE.length +
    OFFENSIVE_TECHNIQUES.length +
    COMPLIANCE_FRAMEWORKS.length
  );
}

/**
 * Returns all knowledge module IDs for registration in knowledge-lazy.ts.
 */
export function getAllKnowledgeModuleIds(): string[] {
  const allModules = [
    ...PLATFORM_CAPABILITIES,
    ...ENGAGEMENT_OPERATIONS,
    ...THREAT_INTELLIGENCE,
    ...OFFENSIVE_TECHNIQUES,
    ...COMPLIANCE_FRAMEWORKS,
  ];
  return allModules.map((m) => m.id);
}
