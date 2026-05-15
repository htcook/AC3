import {
  init_llm,
  invokeLLM
} from "./chunk-NS7EEW5R.js";

// server/lib/test-plan-generator.ts
init_llm();
async function generateTestPlan(input) {
  const planId = `TP-${input.engagementId}-${Date.now()}`;
  const isRedTeam = input.planType === "red_team_exercise" || input.engagementType === "red_team" || input.engagementType === "purple_team";
  const context = buildPlanContext(input);
  const sections = await generatePlanSections(input, context, isRedTeam);
  const structuredData = await generateStructuredData(input, context, isRedTeam);
  const now = Date.now();
  const dateStr = new Date(now).toISOString().split("T")[0];
  const plan = {
    id: planId,
    engagementId: input.engagementId,
    planType: input.planType,
    version: "1.0",
    generatedAt: now,
    generatedBy: input.operatorName || "AceofCloud AC3 Platform",
    title: isRedTeam ? `Red Team Exercise Plan \u2014 ${input.organizationName}` : `Penetration Test Plan \u2014 ${input.organizationName}`,
    subtitle: input.systemName ? `${input.systemName} \u2014 Security Assessment` : `Security Assessment for ${input.engagementName}`,
    classification: "CONFIDENTIAL \u2014 FOR AUTHORIZED PERSONNEL ONLY",
    documentControl: {
      version: "1.0",
      date: dateStr,
      author: input.operatorName || "AceofCloud AC3 Platform",
      reviewer: void 0,
      approver: void 0,
      status: "draft"
    },
    sections,
    structuredData,
    approvalStatus: "pending",
    approvalHistory: [{
      action: "generated",
      by: input.operatorName || "AC3 Platform",
      at: now,
      notes: "Auto-generated from passive reconnaissance and RoE data"
    }]
  };
  return plan;
}
function buildPlanContext(input) {
  const lines = [];
  lines.push(`# Engagement Context for Test Plan Generation`);
  lines.push(``);
  lines.push(`## Organization: ${input.organizationName}`);
  if (input.systemName) lines.push(`## System: ${input.systemName}`);
  if (input.dataSensitivity) lines.push(`## Data Sensitivity: ${input.dataSensitivity.toUpperCase()}`);
  lines.push(`## Engagement Type: ${input.engagementType}`);
  lines.push(`## Plan Type: ${input.planType.replace(/_/g, " ")}`);
  lines.push(``);
  lines.push(`## Rules of Engagement`);
  lines.push(`- Status: ${input.roe.status}`);
  lines.push(`- Authorized Domains: ${input.roe.authorizedDomains.join(", ")}`);
  lines.push(`- Authorized IPs: ${input.roe.authorizedIps.join(", ")}`);
  if (input.roe.excludedTargets?.length) {
    lines.push(`- Excluded Targets: ${input.roe.excludedTargets.join(", ")}`);
  }
  if (input.roe.testingWindows?.length) {
    lines.push(`- Testing Windows: ${input.roe.testingWindows.join("; ")}`);
  }
  if (input.roe.escalationContacts?.length) {
    lines.push(`- Escalation Contacts:`);
    for (const c of input.roe.escalationContacts) {
      lines.push(`  - ${c.name} (${c.role}): ${c.email || ""} ${c.phone || ""}`);
    }
  }
  lines.push(``);
  lines.push(`## Asset Inventory (${input.assets.length} assets)`);
  for (const asset of input.assets) {
    lines.push(`### ${asset.hostname}${asset.ip ? ` (${asset.ip})` : ""}`);
    lines.push(`- Type: ${asset.type}`);
    if (asset.cloudProvider) lines.push(`- Cloud Provider: ${asset.cloudProvider}`);
    if (asset.wafDetected) lines.push(`- WAF Detected: ${asset.wafDetected}`);
    if (asset.technologies?.length) lines.push(`- Technologies: ${asset.technologies.join(", ")}`);
    if (asset.services?.length) {
      lines.push(`- Services:`);
      for (const svc of asset.services) {
        lines.push(`  - Port ${svc.port}: ${svc.service}${svc.version ? ` (${svc.version})` : ""}`);
      }
    }
  }
  lines.push(``);
  lines.push(`## Passive Reconnaissance Summary`);
  for (const [domain, recon] of Object.entries(input.passiveReconResults)) {
    lines.push(`### ${domain}`);
    lines.push(`- Subdomains: ${recon.subdomains.length} discovered`);
    lines.push(`- IP Addresses: ${recon.ipAddresses.join(", ")}`);
    lines.push(`- Technologies: ${recon.technologies.join(", ")}`);
    if (recon.wafDetected) lines.push(`- WAF: ${recon.wafDetected}`);
    if (recon.cloudProvider) lines.push(`- Cloud: ${recon.cloudProvider}`);
    if (recon.emailSecurity) {
      lines.push(`- Email Security: SPF=${recon.emailSecurity.spf}, DKIM=${recon.emailSecurity.dkim}, DMARC=${recon.emailSecurity.dmarc}`);
    }
    if (recon.breachExposure && recon.breachExposure.count > 0) {
      lines.push(`- Breach Exposure: ${recon.breachExposure.count} records from ${recon.breachExposure.sources.join(", ")}`);
    }
    if (recon.riskSignals.length > 0) {
      lines.push(`- Risk Signals: ${recon.riskSignals.length}`);
      for (const sig of recon.riskSignals.slice(0, 5)) {
        lines.push(`  - [${sig.severity}] ${sig.type}: ${sig.rationale}`);
      }
    }
    if (recon.dnsRecords) {
      lines.push(`- DNS Records:`);
      if (recon.dnsRecords.ns.length) lines.push(`  - NS: ${recon.dnsRecords.ns.join(", ")}`);
      if (recon.dnsRecords.mx.length) lines.push(`  - MX: ${recon.dnsRecords.mx.join(", ")}`);
      if (recon.dnsRecords.cname.length) {
        lines.push(`  - CNAME Records: ${recon.dnsRecords.cname.length}`);
        for (const cn of recon.dnsRecords.cname) {
          lines.push(`    - ${cn.name} \u2192 ${cn.target}`);
        }
      }
      if (recon.dnsRecords.soa) {
        lines.push(`  - SOA: primary=${recon.dnsRecords.soa.primary}, refresh=${recon.dnsRecords.soa.refresh}s, retry=${recon.dnsRecords.soa.retry}s, TTL=${recon.dnsRecords.soa.ttl}s`);
      }
      lines.push(`  - DNSSEC Signed: ${recon.dnsRecords.dnssecSigned ? "Yes" : "No"}`);
      if (recon.dnsRecords.dnssecAlgorithm) lines.push(`  - DNSSEC Algorithm: ${recon.dnsRecords.dnssecAlgorithm}`);
    }
  }
  lines.push(``);
  if (input.dnsAssessmentData) {
    lines.push(`## DNS Infrastructure Assessment Data (NIST SP 800-81r3 Aligned)`);
    lines.push(`- Domains: ${input.dnsAssessmentData.domains.join(", ")}`);
    if (input.dnsAssessmentData.nameservers?.length) {
      lines.push(`- Nameservers:`);
      for (const ns of input.dnsAssessmentData.nameservers) {
        lines.push(`  - ${ns.hostname} (${ns.ip})${ns.provider ? ` \u2014 ${ns.provider}` : ""}`);
      }
    }
    lines.push(`- DNSSEC Enabled: ${input.dnsAssessmentData.dnssecEnabled ? "Yes" : "No"}`);
    if (input.dnsAssessmentData.encryptedDnsSupport) {
      const eds = input.dnsAssessmentData.encryptedDnsSupport;
      lines.push(`- Encrypted DNS: DoT=${eds.dot}, DoH=${eds.doh}, DoQ=${eds.doq}`);
    }
    lines.push(`- Protective DNS Deployed: ${input.dnsAssessmentData.protectiveDnsDeployed ? "Yes" : "No/Unknown"}`);
    if (input.dnsAssessmentData.danglingCnames?.length) {
      lines.push(`- Dangling CNAME Records Detected: ${input.dnsAssessmentData.danglingCnames.join(", ")}`);
    }
    if (input.dnsAssessmentData.lameDelegations?.length) {
      lines.push(`- Lame Delegations Detected: ${input.dnsAssessmentData.lameDelegations.join(", ")}`);
    }
    if (input.dnsAssessmentData.zoneTransferExposed) {
      lines.push(`- Zone Transfer Exposure: DETECTED (AXFR/IXFR open)`);
    }
    lines.push(``);
  }
  if (input.complianceFrameworks?.length) {
    lines.push(`## Compliance Frameworks: ${input.complianceFrameworks.join(", ")}`);
  }
  if (input.planType === "red_team_exercise") {
    lines.push(`## Red Team Objectives`);
    if (input.redTeamObjectives?.length) {
      for (const obj of input.redTeamObjectives) {
        lines.push(`- ${obj}`);
      }
    }
    if (input.c2Plan) {
      lines.push(`## C2 Infrastructure Plan`);
      if (input.c2Plan.framework) lines.push(`- Framework: ${input.c2Plan.framework}`);
      if (input.c2Plan.infrastructure?.length) lines.push(`- Infrastructure: ${input.c2Plan.infrastructure.join(", ")}`);
      if (input.c2Plan.communicationChannels?.length) lines.push(`- Channels: ${input.c2Plan.communicationChannels.join(", ")}`);
    }
  }
  return lines.join("\n");
}
async function generatePlanSections(input, context, isRedTeam) {
  const sectionDefinitions = getSectionDefinitions(input, isRedTeam);
  const sections = [];
  for (const sectionDef of sectionDefinitions) {
    try {
      const content = await generateSectionContent(sectionDef, context, input, isRedTeam);
      sections.push({
        id: sectionDef.id,
        title: sectionDef.title,
        content,
        nistReference: sectionDef.nistReference,
        standardsReference: sectionDef.standardsReference
      });
    } catch (err) {
      console.error(`[TestPlanGen] Failed to generate section ${sectionDef.id}: ${err.message}`);
      sections.push({
        id: sectionDef.id,
        title: sectionDef.title,
        content: `[Section generation failed: ${err.message}. Please complete manually.]`,
        nistReference: sectionDef.nistReference,
        standardsReference: sectionDef.standardsReference
      });
    }
  }
  return sections;
}
function getSectionDefinitions(input, isRedTeam) {
  const hasDnsData = !!input.dnsAssessmentData || Object.values(input.passiveReconResults).some((r) => r.dnsRecords);
  let sectionNum = 1;
  const sections = [
    {
      id: "executive_summary",
      title: `${sectionNum++}. Executive Summary`,
      prompt: `Write a concise executive summary for this ${isRedTeam ? "red team exercise" : "penetration test"} plan. Include the purpose, scope, methodology overview, and expected outcomes. This should be understandable by non-technical stakeholders. Reference the applicable standards (NIST SP 800-115, PTES, OWASP) without making compliance certification claims.`,
      nistReference: "NIST SP 800-115 \xA73.1",
      standardsReference: "PTES \xA71"
    },
    {
      id: "scope_and_objectives",
      title: `${sectionNum++}. Scope and Objectives`,
      prompt: `Define the detailed scope and objectives. Include:
- System/application boundaries being tested
- Specific objectives for each target
- In-scope and out-of-scope items
- Network and system boundary definition
- Success criteria for the assessment
- Data sensitivity classification and handling requirements
${isRedTeam ? "- Red team specific objectives (data exfiltration targets, persistence goals, lateral movement objectives)" : ""}`,
      nistReference: "NIST SP 800-115 \xA73.2",
      standardsReference: "PTES \xA72 \u2014 Intelligence Gathering"
    },
    {
      id: "rules_of_engagement",
      title: `${sectionNum++}. Rules of Engagement`,
      prompt: `Document the complete Rules of Engagement including:
- Authorized testing scope (domains, IPs, CIDRs)
- Excluded targets and systems
- Testing windows and blackout periods
- Escalation procedures and emergency contacts
- Data handling and classification requirements
- Communication protocols during testing
- Incident response procedures if testing causes issues
- Legal and regulatory considerations
- Evidence handling and chain of custody requirements`,
      nistReference: "NIST SP 800-115 \xA73.3",
      standardsReference: "PTES \xA72.1 \u2014 Pre-engagement Interactions"
    },
    {
      id: "methodology",
      title: `${sectionNum++}. Testing Methodology`,
      prompt: `Describe the detailed testing methodology aligned with NIST SP 800-115 and PTES standards. Include:
- Overall approach (black box, gray box, white box)
- Phase-by-phase methodology:
  1. Domain Reconnaissance (passive OSINT, DNS intelligence)
  2. Passive Discovery and Enumeration
  3. Active Discovery and Enumeration
  4. Vulnerability Assessment (automated + manual)
  5. ${isRedTeam ? "Red Team Operations (exploitation, persistence, lateral movement, objective completion)" : "Penetration Testing (exploitation, privilege escalation, evidence collection)"}
  6. ${isRedTeam ? "Post-Exploitation and Objective Validation" : "Post-Exploitation Verification"}
- MITRE ATT&CK framework mapping for each phase
- OWASP Testing Guide v4.2 alignment for web applications
- NIST SP 800-81r3 alignment for DNS infrastructure testing
- Assessment attack vector coverage:
  AV1: Social Engineering / Phishing
  AV2: External Network Attack Surface / Insider Threat
  AV3: Web Application Attack Surface
  AV4: Multi-Tenant Isolation Testing
  AV5: Mobile Application Security
  AV6: Client-Side Application/Agent Testing
  AV7: DNS Infrastructure Security
  AV8: Cloud Infrastructure Misconfiguration
  AV9: API Security Testing`,
      nistReference: "NIST SP 800-115 \xA74",
      standardsReference: "PTES \xA73-7 \u2014 Full Methodology"
    },
    {
      id: "attack_vectors",
      title: `${sectionNum++}. Assessment Attack Vectors`,
      prompt: `For each applicable assessment attack vector, provide:
- Detailed description of the attack scenario
- Specific targets within the assessment scope
- Tools and techniques to be used
- Expected outcomes and success criteria
- Risk mitigation measures during testing
- MITRE ATT&CK technique mapping

Cover all applicable attack vectors:
1. Social Engineering / Phishing \u2014 social engineering campaign targeting system administrators and users
2. External Network Attack Surface \u2014 external network reconnaissance, scanning, and exploitation + insider threat assessment
3. Web Application Attack Surface \u2014 OWASP Top 10 testing of web interfaces and management portals
4. Multi-Tenant Isolation \u2014 cross-tenant isolation testing (if applicable)
5. Mobile Application Security \u2014 mobile app security assessment (if applicable)
6. Client-Side Application/Agents \u2014 client-side application and agent testing
7. DNS Infrastructure Security \u2014 per NIST SP 800-81r3: DNSSEC validation, zone transfer exposure, dangling CNAMEs, lame delegations, encrypted DNS, protective DNS assessment
8. Cloud Infrastructure \u2014 cloud misconfiguration, IAM, storage exposure (if applicable)
9. API Security \u2014 REST/GraphQL API authentication, authorization, injection testing

For each vector, note whether it is applicable based on the asset inventory and scope. If not applicable, explain why.`,
      nistReference: "NIST SP 800-115 \xA74.3",
      standardsReference: "PTES \xA74 \u2014 Vulnerability Analysis"
    }
  ];
  if (hasDnsData) {
    sections.push({
      id: "dns_security_assessment",
      title: `${sectionNum++}. DNS Security Assessment (NIST SP 800-81r3)`,
      prompt: `Generate a comprehensive DNS security assessment plan aligned with NIST SP 800-81r3 (March 2026). This section must cover:

**DNS Infrastructure Security:**
- Authoritative server architecture assessment (dedicated servers, separation from recursive)
- Geographic distribution and redundancy of nameservers
- Hidden primary server configuration
- Server software version and patch status

**DNS Protocol Security:**
- DNSSEC signing validation (algorithm strength: prefer ECDSA P-256/P-384, Ed25519/Ed448 over RSA)
- RRSIG validity period assessment (recommended: 5-7 days)
- NSEC vs NSEC3 configuration review
- Encrypted DNS support assessment (DoT on TCP 853, DoH on TCP/UDP 443, DoQ on UDP 853)
- Zone transfer security (AXFR/IXFR access control, TSIG authentication)

**External Domain Integrity:**
- Dangling CNAME detection (subdomain takeover risk)
- Lame delegation identification (subdomain hijacking risk)
- Lookalike/typosquat domain monitoring
- Retired domain parking verification

**Zone Content Security:**
- Information leakage assessment (HINFO, TXT, LOC, RP records)
- SOA parameter validation (Refresh: 1200-432000s, Retry < Refresh)
- TTL value compliance (range: 1800-86400s, TTL=0 prohibited)
- Dynamic update security (TSIG/SIG(0) authentication)
- DNS NOTIFY configuration review

**Protective DNS Assessment:**
- DNS firewall / Response Policy Zone (RPZ) deployment
- Threat intelligence feed integration
- DNS query logging and SIEM integration
- DHCP lease correlation capability for incident response

**Recursive/Forwarding Service Security:**
- Encrypted DNS enforcement
- Public DNS resolver bypass detection (blocking direct queries to 8.8.8.8, 1.1.1.1)
- QNAME minimization support
- DNS tunneling/data exfiltration detection capability
- DNSSEC validation on recursive resolvers

**Compliance Mapping:**
- NIST SP 800-53: SC-20 (Secure Name/Address Resolution), SC-21 (Recursive Resolver Security), SC-22 (Architecture and Provisioning)
- NIST SP 800-81r3: Full DNS deployment security guide
- CIS Controls: Control 9, Control 12

Use the DNS assessment data from the context to tailor the plan to the specific targets.`,
      nistReference: "NIST SP 800-115 \xA74.2",
      standardsReference: "NIST SP 800-81r3 (March 2026) \u2014 Secure DNS Deployment Guide"
    });
  }
  sections.push(
    {
      id: "tools_and_techniques",
      title: `${sectionNum++}. Tools and Techniques`,
      prompt: `List all tools to be used during the assessment, organized by phase. For each tool include:
- Tool name and version
- Purpose and capability
- Phase(s) where it will be used
- License type
- Configuration notes

Include tools for:
- Passive reconnaissance (OSINT, DNS, certificate transparency)
- Active scanning (port scanning, service enumeration)
- Vulnerability assessment (DAST, SAST, configuration audit)
- Web application testing (proxy, fuzzing, authentication testing)
- DNS security testing (zone transfer, DNSSEC validation, encrypted DNS probing)
- ${isRedTeam ? "C2 framework, persistence tools, lateral movement tools" : "Exploitation frameworks, privilege escalation tools"}
- Evidence collection and documentation
- Cloud-specific tools if applicable`,
      nistReference: "NIST SP 800-115 \xA74.2",
      standardsReference: "PTES \xA74.4 \u2014 Active Vulnerability Scanning"
    },
    {
      id: "schedule",
      title: `${sectionNum++}. Test Schedule`,
      prompt: `Create a detailed test schedule with:
- Phase-by-phase timeline (start/end dates relative to engagement start)
- Key milestones and checkpoints
- Approval gates (test plan approval, RoE signing, exploitation approval)
- Reporting deadlines
- Daily standup/sync schedule with the customer
- Buffer time for re-testing and validation

Base the schedule on the asset count, complexity, and scope from the context.`,
      nistReference: "NIST SP 800-115 \xA73.4",
      standardsReference: "PTES \xA72.1 \u2014 Timeline"
    },
    {
      id: "risk_management",
      title: `${sectionNum++}. Risk Management During Testing`,
      prompt: `Document risk management procedures including:
- Potential risks to production systems during testing
- Mitigation measures for each identified risk
- Rollback procedures if testing causes issues
- Communication plan for incidents during testing
- Data protection measures for sensitive findings
- ${isRedTeam ? "Deconfliction procedures with defensive team (if not blind)" : "Coordination with system administrators"}
- Evidence integrity and chain of custody procedures
- DNS-specific risks: potential for zone disruption during AXFR testing, DNSSEC validation impact`,
      nistReference: "NIST SP 800-115 \xA73.5",
      standardsReference: "PTES \xA72.1 \u2014 Risk Management"
    },
    {
      id: "communication_plan",
      title: `${sectionNum++}. Communication Plan`,
      prompt: `Define the communication plan including:
- Primary and secondary points of contact (both sides)
- Communication channels (secure email, encrypted messaging)
- Status reporting frequency and format
- Critical finding notification procedures (immediate, 24hr, weekly)
- Escalation matrix with response times
- Out-of-hours contact procedures
- Final report delivery timeline and format`,
      nistReference: "NIST SP 800-115 \xA73.6"
    },
    {
      id: "deliverables",
      title: `${sectionNum++}. Deliverables`,
      prompt: `List all deliverables including:
- ${isRedTeam ? "Red Team Exercise Report" : "Penetration Test Report"}
- Remediation Roadmap with prioritized findings
- Executive Summary (separate document)
- Technical Findings Detail with CVSS scoring
- Evidence Package (screenshots, logs, proof-of-concept)
- ${isRedTeam ? "Red Team Narrative Report (kill chain documentation)" : "Vulnerability Assessment Matrix"}
- DNS Security Assessment Report (per NIST SP 800-81r3)
- Compliance Control Mapping (NIST SP 800-53, CIS Controls)
- Re-test results (if applicable)

For each deliverable, specify format, content outline, and delivery timeline.`,
      nistReference: "NIST SP 800-115 \xA75",
      standardsReference: "PTES \xA77 \u2014 Reporting"
    },
    {
      id: "team_and_qualifications",
      title: `${sectionNum++}. Assessment Team and Qualifications`,
      prompt: `Document the assessment team including:
- Team lead and members (roles and responsibilities)
- Relevant certifications (OSCP, OSCE, GPEN, GXPN, CREST, etc.)
- Organization credentials and accreditations
- Years of experience and relevant engagements
- Conflict of interest disclosure
- Background check status (if required)`,
      nistReference: "NIST SP 800-115 \xA73.7",
      standardsReference: "PTES \xA72.1 \u2014 Team Qualifications"
    }
  );
  if (isRedTeam) {
    sections.push(
      {
        id: "c2_infrastructure",
        title: `${sectionNum++}. C2 Infrastructure and Operations Plan`,
        prompt: `Detail the Command and Control infrastructure plan:
- C2 framework selection and justification
- Infrastructure setup (redirectors, domain fronting, CDN abuse prevention)
- Communication channels and protocols
- Persistence mechanisms to be tested
- Lateral movement strategy
- Data exfiltration channels and methods
- Operational security measures
- Deconfliction with defensive operations (if applicable)
- Cleanup and decommission procedures
- DNS-based C2 channels (if applicable) and detection evasion`
      },
      {
        id: "objectives_and_scenarios",
        title: `${sectionNum++}. Red Team Objectives and Scenarios`,
        prompt: `Define specific red team objectives and attack scenarios:
- Primary objectives (e.g., access crown jewels, exfiltrate PII, establish persistence)
- Secondary objectives
- Scenario descriptions (realistic threat actor emulation)
- Threat actor profile being emulated (if applicable)
- Success criteria for each objective
- Rules for objective completion evidence
- Time-boxed phases and decision points`
      }
    );
  }
  sections.push({
    id: "appendices",
    title: `${sectionNum++}. Appendices`,
    prompt: `Create appendix sections including:
A. Asset Inventory Table (all in-scope assets with IPs, services, technologies)
B. MITRE ATT&CK Technique Coverage Matrix
C. Compliance Control Mapping (NIST SP 800-53, NIST SP 800-81r3, CIS Controls)
D. DNS Security Checklist (per NIST SP 800-81r3)
E. Glossary of Terms
F. Document Revision History
G. Approval Signatures Page`,
    nistReference: "NIST SP 800-115 Appendix",
    standardsReference: "NIST SP 800-81r3 \u2014 DNS Security Checklist"
  });
  return sections;
}
async function generateSectionContent(sectionDef, context, input, isRedTeam) {
  const systemPrompt = `You are a senior penetration tester and security assessment author at AceofCloud. You are generating a formal ${isRedTeam ? "Red Team Exercise Plan" : "Penetration Test Plan"} aligned with the following standards:

1. NIST SP 800-115 Technical Guide to Information Security Testing and Assessment
2. NIST SP 800-53 Rev 5 Security and Privacy Controls
3. NIST SP 800-81r3 (March 2026) Secure Domain Name System (DNS) Deployment Guide
4. OWASP Testing Guide v4.2 (for web application testing)
5. PTES (Penetration Testing Execution Standard)
6. MITRE ATT&CK Framework

Write in a formal, professional tone suitable for government and enterprise review. Be specific about targets, tools, and methodology \u2014 avoid vague or generic language. Reference specific MITRE ATT&CK techniques (T-codes), CWE IDs, and NIST control families where applicable.

The plan must be detailed enough that:
- A customer can review and approve it before testing begins
- A qualified reviewer can verify it meets industry standards
- An assessor can execute the plan without additional guidance
- An auditor can trace test activities back to the plan

Do NOT make compliance certification claims (e.g., do not claim the plan is "FedRAMP certified" or "DISA STIG compliant"). Instead, reference the standards the methodology is aligned with.

Use markdown formatting for the section content.`;
  const response = await invokeLLM({
    _caller: "test-plan-generator.generateSection",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: `## Engagement Context

${context}

## Section to Generate

Section: ${sectionDef.title}
${sectionDef.nistReference ? `NIST Reference: ${sectionDef.nistReference}` : ""}
${sectionDef.standardsReference ? `Standards Reference: ${sectionDef.standardsReference}` : ""}

Instructions: ${sectionDef.prompt}

Generate the complete section content in markdown format. Be specific to the targets, technologies, and scope described in the context. Do not include the section title \u2014 just the content.` }
    ]
  });
  return response?.choices?.[0]?.message?.content || "[Content generation failed]";
}
async function generateStructuredData(input, context, isRedTeam) {
  const systemPrompt = `You are generating structured data for a ${isRedTeam ? "Red Team Exercise Plan" : "Penetration Test Plan"}. Return valid JSON matching the requested schema. Be specific to the targets and scope provided. Include DNS infrastructure testing as a distinct phase.`;
  try {
    const response = await invokeLLM({
      _caller: "test-plan-generator.generateStructuredData",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: `## Context

${context}

## Task

Generate structured test plan data as JSON with these fields:

1. estimatedDuration: string (e.g., "10 business days")
2. attackVectors: array of objects with {id, name, description, targets: string[], methodology, tools: string[], estimatedDuration, riskLevel: "low"|"medium"|"high", mitreTechniques: string[]}
3. toolInventory: array of {tool, purpose, phase, license}
4. schedule: array of {phase, startDay: number, endDay: number, activities: string[]}
5. riskMitigation: array of {risk, mitigation, owner}
6. successCriteria: string[]
7. deliverables: array of {name, description, dueDate}

Base attack vectors on the actual assets and services discovered. Include a DNS infrastructure security vector (per NIST SP 800-81r3). Include ${isRedTeam ? "red team specific vectors (C2, persistence, lateral movement, exfiltration)" : "standard pentest vectors"}. Map tools to specific phases.` }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "test_plan_structured_data",
          strict: true,
          schema: {
            type: "object",
            properties: {
              estimatedDuration: { type: "string" },
              attackVectors: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    id: { type: "string" },
                    name: { type: "string" },
                    description: { type: "string" },
                    targets: { type: "array", items: { type: "string" } },
                    methodology: { type: "string" },
                    tools: { type: "array", items: { type: "string" } },
                    estimatedDuration: { type: "string" },
                    riskLevel: { type: "string", enum: ["low", "medium", "high"] },
                    mitreTechniques: { type: "array", items: { type: "string" } }
                  },
                  required: ["id", "name", "description", "targets", "methodology", "tools", "estimatedDuration", "riskLevel", "mitreTechniques"],
                  additionalProperties: false
                }
              },
              toolInventory: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    tool: { type: "string" },
                    purpose: { type: "string" },
                    phase: { type: "string" },
                    license: { type: "string" }
                  },
                  required: ["tool", "purpose", "phase", "license"],
                  additionalProperties: false
                }
              },
              schedule: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    phase: { type: "string" },
                    startDay: { type: "integer" },
                    endDay: { type: "integer" },
                    activities: { type: "array", items: { type: "string" } }
                  },
                  required: ["phase", "startDay", "endDay", "activities"],
                  additionalProperties: false
                }
              },
              riskMitigation: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    risk: { type: "string" },
                    mitigation: { type: "string" },
                    owner: { type: "string" }
                  },
                  required: ["risk", "mitigation", "owner"],
                  additionalProperties: false
                }
              },
              successCriteria: { type: "array", items: { type: "string" } },
              deliverables: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    description: { type: "string" },
                    dueDate: { type: "string" }
                  },
                  required: ["name", "description", "dueDate"],
                  additionalProperties: false
                }
              }
            },
            required: ["estimatedDuration", "attackVectors", "toolInventory", "schedule", "riskMitigation", "successCriteria", "deliverables"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response?.choices?.[0]?.message?.content;
    if (content) {
      return JSON.parse(content);
    }
  } catch (err) {
    console.error(`[TestPlanGen] Structured data generation failed: ${err.message}`);
  }
  return buildFallbackStructuredData(input, isRedTeam);
}
function buildFallbackStructuredData(input, isRedTeam) {
  const assetCount = input.assets.length;
  const hasDns = !!input.dnsAssessmentData;
  const estimatedDays = Math.max(5, Math.ceil(assetCount * 1.5) + (isRedTeam ? 5 : 0) + (hasDns ? 1 : 0));
  return {
    estimatedDuration: `${estimatedDays} business days`,
    attackVectors: [
      {
        id: "av_external_recon",
        name: "External Reconnaissance",
        description: "Passive and active reconnaissance of external-facing assets",
        targets: input.roe.authorizedDomains,
        methodology: "OSINT collection, DNS enumeration, certificate transparency, Shodan/Censys queries",
        tools: ["subfinder", "amass", "httpx", "scanforge-discovery", "Shodan API", "crt.sh"],
        estimatedDuration: "1-2 days",
        riskLevel: "low",
        mitreTechniques: ["T1595", "T1592", "T1589", "T1590"]
      },
      {
        id: "av_dns_infrastructure",
        name: "DNS Infrastructure Security Assessment",
        description: "Comprehensive DNS security assessment per NIST SP 800-81r3 including DNSSEC validation, zone transfer exposure, dangling CNAME detection, lame delegation identification, encrypted DNS support, and protective DNS evaluation",
        targets: input.dnsAssessmentData?.domains || input.roe.authorizedDomains,
        methodology: "DNS record enumeration, DNSSEC chain validation, zone transfer testing, CNAME resolution verification, SOA parameter analysis, encrypted DNS probing (DoT/DoH/DoQ), information leakage assessment",
        tools: ["dig", "dnsx", "dnsrecon", "dnssec-verify", "subfinder", "ScanForge DNS Scanner"],
        estimatedDuration: "0.5-1 day",
        riskLevel: "low",
        mitreTechniques: ["T1584.001", "T1583.001", "T1071.004"]
      },
      {
        id: "av_network_scan",
        name: "Network Scanning and Enumeration",
        description: "Active port scanning and service enumeration of authorized targets",
        targets: input.roe.authorizedIps,
        methodology: "TCP/UDP port scanning, service fingerprinting, OS detection",
        tools: ["scanforge-discovery", "masscan", "httpx"],
        estimatedDuration: "1-2 days",
        riskLevel: "medium",
        mitreTechniques: ["T1046", "T1018"]
      },
      {
        id: "av_vuln_assessment",
        name: "Vulnerability Assessment",
        description: "Automated and manual vulnerability scanning",
        targets: input.assets.map((a) => a.hostname),
        methodology: "Template-based scanning, DAST, configuration audit",
        tools: ["Nuclei", "ZAP", "ScanForge"],
        estimatedDuration: "2-3 days",
        riskLevel: "medium",
        mitreTechniques: ["T1190", "T1210"]
      }
    ],
    toolInventory: [
      { tool: "scanforge-discovery", purpose: "Port scanning and service enumeration", phase: "Active Discovery", license: "GPL-2.0" },
      { tool: "Nuclei", purpose: "Template-based vulnerability scanning", phase: "Vulnerability Assessment", license: "MIT" },
      { tool: "ZAP", purpose: "Web application DAST scanning", phase: "Vulnerability Assessment", license: "Apache-2.0" },
      { tool: "ScanForge", purpose: "Multi-protocol vulnerability scanning with FP/FN prevention", phase: "Vulnerability Assessment", license: "Proprietary (AceofCloud)" },
      { tool: "dig/dnsx", purpose: "DNS record enumeration and DNSSEC validation", phase: "DNS Security Assessment", license: "ISC/MIT" },
      { tool: "dnsrecon", purpose: "DNS reconnaissance and zone transfer testing", phase: "DNS Security Assessment", license: "GPL-2.0" },
      { tool: "Metasploit", purpose: "Exploitation framework", phase: "Exploitation", license: "BSD-3-Clause" }
    ],
    schedule: [
      { phase: "Domain Reconnaissance", startDay: 1, endDay: 2, activities: ["OSINT collection", "DNS enumeration", "Technology fingerprinting", "Breach exposure check"] },
      { phase: "DNS Security Assessment", startDay: 2, endDay: 3, activities: ["DNSSEC validation", "Zone transfer testing", "Dangling CNAME detection", "Encrypted DNS assessment", "SOA/TTL analysis"] },
      { phase: "Active Discovery", startDay: 3, endDay: 5, activities: ["Port scanning", "Service enumeration", "Web crawling"] },
      { phase: "Vulnerability Assessment", startDay: 5, endDay: 8, activities: ["Automated scanning", "Manual testing", "Configuration audit"] },
      { phase: "Exploitation", startDay: 8, endDay: estimatedDays - 2, activities: ["Vulnerability validation", "Exploitation attempts", "Evidence collection"] },
      { phase: "Reporting", startDay: estimatedDays - 2, endDay: estimatedDays, activities: ["Report writing", "Evidence packaging", "Remediation guidance"] }
    ],
    riskMitigation: [
      { risk: "Service disruption during scanning", mitigation: "Rate-limited scanning, testing during approved windows", owner: "Assessment Team" },
      { risk: "Data exposure during exploitation", mitigation: "No real data exfiltration, proof-of-concept only", owner: "Assessment Team" },
      { risk: "DNS zone disruption during AXFR testing", mitigation: "Read-only zone transfer attempts, no modification of DNS records", owner: "Assessment Team" },
      { risk: "False positive impact on operations", mitigation: "Multi-signal validation, ScanForge FP/FN prevention engine", owner: "Assessment Team Lead" }
    ],
    successCriteria: [
      "All in-scope assets have been tested",
      "All applicable attack vectors have been assessed",
      "DNS infrastructure assessed per NIST SP 800-81r3 requirements",
      "Findings are validated with multi-signal evidence",
      "Report meets NIST SP 800-115 standards",
      "Customer has received and acknowledged the report"
    ],
    deliverables: [
      { name: isRedTeam ? "Red Team Exercise Report" : "Penetration Test Report", description: "Comprehensive findings report with evidence", dueDate: `Day ${estimatedDays + 5}` },
      { name: "Executive Summary", description: "Non-technical overview for leadership", dueDate: `Day ${estimatedDays + 5}` },
      { name: "DNS Security Assessment Report", description: "NIST SP 800-81r3 aligned DNS security findings", dueDate: `Day ${estimatedDays + 5}` },
      { name: "Remediation Roadmap", description: "Prioritized remediation plan with CVSS scoring", dueDate: `Day ${estimatedDays + 5}` },
      { name: "Evidence Package", description: "Screenshots, logs, and proof-of-concept artifacts", dueDate: `Day ${estimatedDays + 5}` }
    ]
  };
}
function testPlanToMarkdown(plan) {
  const lines = [];
  lines.push(`# ${plan.title}`);
  lines.push(``);
  lines.push(`**${plan.subtitle}**`);
  lines.push(``);
  lines.push(`**Classification:** ${plan.classification}`);
  lines.push(``);
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| Document ID | ${plan.id} |`);
  lines.push(`| Version | ${plan.documentControl.version} |`);
  lines.push(`| Date | ${plan.documentControl.date} |`);
  lines.push(`| Author | ${plan.documentControl.author} |`);
  lines.push(`| Status | ${plan.documentControl.status} |`);
  lines.push(`| Plan Type | ${plan.planType.replace(/_/g, " ")} |`);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);
  lines.push(`## Table of Contents`);
  lines.push(``);
  for (const section of plan.sections) {
    lines.push(`- [${section.title}](#${section.id})`);
  }
  lines.push(``);
  lines.push(`---`);
  lines.push(``);
  for (const section of plan.sections) {
    lines.push(`<a id="${section.id}"></a>`);
    lines.push(``);
    lines.push(`## ${section.title}`);
    lines.push(``);
    if (section.nistReference || section.standardsReference) {
      const refs = [];
      if (section.nistReference) refs.push(section.nistReference);
      if (section.standardsReference) refs.push(section.standardsReference);
      lines.push(`> **Standards Alignment:** ${refs.join(" | ")}`);
      lines.push(``);
    }
    lines.push(section.content);
    lines.push(``);
    lines.push(`---`);
    lines.push(``);
  }
  lines.push(`## Appendix: Structured Test Data`);
  lines.push(``);
  lines.push(`### Estimated Duration: ${plan.structuredData.estimatedDuration}`);
  lines.push(``);
  lines.push(`### Attack Vectors`);
  lines.push(``);
  lines.push(`| ID | Name | Risk | Duration | MITRE Techniques |`);
  lines.push(`|----|------|------|----------|------------------|`);
  for (const av of plan.structuredData.attackVectors) {
    lines.push(`| ${av.id} | ${av.name} | ${av.riskLevel} | ${av.estimatedDuration} | ${av.mitreTechniques.join(", ")} |`);
  }
  lines.push(``);
  lines.push(`### Tool Inventory`);
  lines.push(``);
  lines.push(`| Tool | Purpose | Phase | License |`);
  lines.push(`|------|---------|-------|---------|`);
  for (const tool of plan.structuredData.toolInventory) {
    lines.push(`| ${tool.tool} | ${tool.purpose} | ${tool.phase} | ${tool.license} |`);
  }
  lines.push(``);
  lines.push(`### Test Schedule`);
  lines.push(``);
  lines.push(`| Phase | Start | End | Activities |`);
  lines.push(`|-------|-------|-----|------------|`);
  for (const phase of plan.structuredData.schedule) {
    lines.push(`| ${phase.phase} | Day ${phase.startDay} | Day ${phase.endDay} | ${phase.activities.join("; ")} |`);
  }
  lines.push(``);
  lines.push(`---`);
  lines.push(``);
  lines.push(`## Approval Signatures`);
  lines.push(``);
  lines.push(`| Role | Name | Signature | Date |`);
  lines.push(`|------|------|-----------|------|`);
  lines.push(`| Assessment Team Lead | ${plan.documentControl.author} | _________________ | ________ |`);
  lines.push(`| Customer POC | _________________ | _________________ | ________ |`);
  lines.push(`| ${plan.planType === "red_team_exercise" ? "Red Team Director" : "Technical Reviewer"} | _________________ | _________________ | ________ |`);
  lines.push(``);
  return lines.join("\n");
}

export {
  generateTestPlan,
  testPlanToMarkdown
};
