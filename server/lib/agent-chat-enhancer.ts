/**
 * Agent Chat Enhancer — Agency-Agents Architecture Integration
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Enhances the existing role-based chat system with patterns from the
 * agency-agents MIT project:
 *
 *   1. Structured Reasoning Chains (THINK → PLAN → ACT → VERIFY)
 *   2. Agent-to-Agent Delegation (operator invokes specialist agents)
 *   3. Confidence Scoring (LLM self-rates response quality)
 *   4. Mission-Scoped Guardrails (explicit boundary enforcement)
 *   5. Deliverable Templates (structured output formats)
 *   6. Quality Gates (evidence-based response validation)
 */

import {
  ALL_OFFENSIVE_AGENTS,
  matchCallerToAgent,
  buildAgentSystemPrompt,
} from "./agent-definitions";
import type { InsertAgentDefinition } from "../../drizzle/schema";

/** Alias for agent definition type used throughout this module */
type OffensiveAgentDefinition = Omit<InsertAgentDefinition, "id">;

// ─── Structured Reasoning Chain ─────────────────────────────────────────────

/**
 * Injects a structured reasoning chain into the system prompt.
 * This forces the LLM to follow a THINK → PLAN → ACT → VERIFY pattern
 * before producing its final response.
 */
export function buildReasoningChainPrompt(role: string): string {
  const chains: Record<string, string> = {
    operator: `
STRUCTURED REASONING PROTOCOL (apply to all complex requests):
When the user asks a question that requires analysis, planning, or multi-step reasoning:

1. **ASSESS** — Identify the objective, constraints, and available intelligence
   - What is the user trying to achieve?
   - What are the Rules of Engagement boundaries?
   - What data/context is available?

2. **PLAN** — Outline the approach before executing
   - Break down into discrete steps
   - Identify tools, techniques, and prerequisites
   - Consider OPSEC implications and detection risk
   - Map to MITRE ATT&CK where applicable

3. **EXECUTE** — Provide the actionable guidance
   - Give exact commands, code, or procedures
   - Include alternative approaches ranked by stealth
   - Reference specific tools and their flags

4. **VERIFY** — Validate the approach
   - How to confirm success without triggering alerts
   - What artifacts to check for
   - Cleanup/anti-forensics considerations
   - Rate your confidence: [HIGH/MEDIUM/LOW] with reasoning

For simple factual questions, skip directly to the answer.`,

    analyst: `
STRUCTURED REASONING PROTOCOL (apply to all analysis requests):

1. **OBSERVE** — Gather and correlate available data points
   - What indicators are present?
   - What data sources can we cross-reference?
   - What is the temporal context?

2. **HYPOTHESIZE** — Form threat hypotheses
   - What TTPs could explain the observations?
   - What threat actors use these techniques?
   - What is the kill chain stage?

3. **INVESTIGATE** — Deep-dive into the hypothesis
   - Provide detection logic (Sigma/YARA rules)
   - Suggest pivot points for further investigation
   - Correlate with known IOCs and threat intel

4. **CONCLUDE** — Deliver findings with confidence
   - Classification: true positive / false positive / suspicious
   - Severity and business impact assessment
   - Recommended response actions
   - Confidence: [HIGH/MEDIUM/LOW] with evidence basis`,

    executive: `
STRUCTURED REASONING PROTOCOL (apply to all strategic questions):

1. **CONTEXT** — Frame the business environment
   - What is the organization's risk posture?
   - What regulatory/compliance requirements apply?
   - What is the current threat landscape?

2. **ANALYZE** — Translate technical findings to business impact
   - Financial exposure (direct costs, fines, lost revenue)
   - Operational impact (downtime, productivity loss)
   - Reputational risk (customer trust, market position)

3. **RECOMMEND** — Provide prioritized strategic options
   - Quick wins vs. long-term investments
   - Cost-benefit analysis for each option
   - Resource requirements and timeline

4. **QUANTIFY** — Support with metrics
   - Risk reduction percentages
   - ROI projections
   - Industry benchmarks
   - Confidence: [HIGH/MEDIUM/LOW] with data basis`,

    team_lead: `
STRUCTURED REASONING PROTOCOL (apply to all planning requests):

1. **SCOPE** — Define the engagement boundaries
   - What are the objectives and success criteria?
   - What is in-scope vs. out-of-scope?
   - What resources are available?

2. **PLAN** — Build the operational plan
   - Phase breakdown with timelines
   - Team assignments and skill requirements
   - Tool and infrastructure needs
   - Risk mitigation strategies

3. **EXECUTE** — Provide actionable guidance
   - Step-by-step procedures for each phase
   - Communication protocols and escalation paths
   - Evidence collection requirements

4. **REVIEW** — Quality assurance
   - Coverage assessment against objectives
   - Finding validation methodology
   - Report preparation checklist
   - Confidence: [HIGH/MEDIUM/LOW] with coverage basis`,

    soc: `
STRUCTURED REASONING PROTOCOL (apply to all detection/response requests):

1. **TRIAGE** — Assess the alert/incident
   - What is the alert source and fidelity?
   - What is the potential impact?
   - Is this a known pattern or novel?

2. **INVESTIGATE** — Gather evidence
   - Log sources to query
   - IOCs to pivot on
   - Timeline reconstruction steps

3. **RESPOND** — Take action
   - Containment measures
   - Eradication steps
   - Recovery procedures

4. **DOCUMENT** — Record findings
   - Incident timeline
   - Root cause analysis
   - Lessons learned
   - Confidence: [HIGH/MEDIUM/LOW] with evidence basis`,
  };

  return chains[role] || chains.operator;
}

// ─── Agent-to-Agent Delegation ──────────────────────────────────────────────

/**
 * Detects when a user's message would benefit from a specialist agent's
 * expertise and returns the relevant agent definition for prompt injection.
 */
export function detectAgentDelegation(
  userMessage: string,
  currentRole: string
): OffensiveAgentDefinition | null {
  const msg = userMessage.toLowerCase();

  // OSINT/Recon delegation triggers
  const osintTriggers = [
    "osint", "recon", "reconnaissance", "footprint", "attack surface",
    "subdomain", "email harvest", "breach data", "credential dump",
    "whois", "dns enum", "certificate transparency", "shodan",
    "censys", "dark web", "darkweb", "paste site", "data leak",
    "social media intel", "linkedin", "employee list", "org chart",
  ];
  if (osintTriggers.some(t => msg.includes(t))) {
    return ALL_OFFENSIVE_AGENTS.find(a => a.agentId === "offensive-osint-analyst-v1") || null;
  }

  // Social Engineering delegation triggers
  const seTriggers = [
    "phishing", "social engineer", "pretext", "vishing", "smishing",
    "typosquat", "lookalike domain", "spear phish", "whaling",
    "landing page", "email template", "gophish", "campaign design",
    "credential harvest", "awareness test", "business email compromise",
    "bec", "impersonation", "pretexting",
  ];
  if (seTriggers.some(t => msg.includes(t))) {
    return ALL_OFFENSIVE_AGENTS.find(a => a.agentId === "offensive-social-engineer-v1") || null;
  }

  // Red Team Operator delegation triggers
  const rtTriggers = [
    "red team", "adversary emulation", "apt simulation", "c2 setup",
    "command and control", "caldera campaign", "kill chain", "ttps",
    "threat emulation", "atomic red team", "mitre caldera", "cobalt strike",
    "sliver", "empire", "mythic", "havoc", "implant", "beacon",
    "lateral movement", "persistence", "defense evasion",
  ];
  if (rtTriggers.some(t => msg.includes(t))) {
    return ALL_OFFENSIVE_AGENTS.find(a => a.agentId === "offensive-red-team-operator-v1") || null;
  }

  // Pentester delegation triggers
  const pentestTriggers = [
    "exploit", "vulnerability", "privilege escalation", "privesc",
    "buffer overflow", "injection", "sqli", "xss", "ssrf", "rce",
    "remote code execution", "metasploit", "payload", "shellcode",
    "web app test", "api test", "fuzzing", "binary exploit",
    "heap spray", "rop chain", "deserialization",
  ];
  if (pentestTriggers.some(t => msg.includes(t))) {
    return ALL_OFFENSIVE_AGENTS.find(a => a.agentId === "offensive-pentester-v1") || null;
  }

  // Report Writer delegation triggers
  const reportTriggers = [
    "write report", "generate report", "executive summary", "finding",
    "remediation", "compliance report", "pentest report", "ac3 report",
    "fedramp", "nist", "risk rating", "cvss", "business impact",
    "report template", "deliverable",
  ];
  if (reportTriggers.some(t => msg.includes(t))) {
    return ALL_OFFENSIVE_AGENTS.find(a => a.agentId === "offensive-report-writer-v1") || null;
  }

  return null;
}

/**
 * Builds a delegation context block that injects the specialist agent's
 * persona and rules into the current chat session.
 */
export function buildDelegationContext(
  agent: OffensiveAgentDefinition,
  userMessage: string
): string {
  const rules = typeof agent.coreRules === "string"
    ? agent.coreRules
    : Array.isArray(agent.coreRules)
      ? (agent.coreRules as string[]).join("\n")
      : JSON.stringify(agent.coreRules);

  const tools = typeof agent.toolAccess === "string"
    ? agent.toolAccess
    : Array.isArray(agent.toolAccess)
      ? (agent.toolAccess as string[]).join(", ")
      : JSON.stringify(agent.toolAccess);

  const mitre = typeof agent.mitreTactics === "string"
    ? agent.mitreTactics
    : Array.isArray(agent.mitreTactics)
      ? (agent.mitreTactics as string[]).join(", ")
      : JSON.stringify(agent.mitreTactics);

  return `
--- SPECIALIST AGENT DELEGATION ---
The user's request activates the ${agent.name} specialist agent.
Adopt this agent's expertise and methodology for this response.

SPECIALIST PERSONA: ${agent.persona}
SPECIALIST MISSION: ${agent.mission}

METHODOLOGY RULES:
${rules}

AVAILABLE TOOLS: ${tools}
MITRE ATT&CK COVERAGE: ${mitre}

Apply this specialist's methodology to answer the user's question.
Maintain your primary role identity but leverage the specialist's deep expertise.
--- END DELEGATION ---`;
}

// ─── Confidence Scoring ─────────────────────────────────────────────────────

/**
 * Appends a confidence scoring instruction to the system prompt.
 * The LLM will self-rate its response confidence at the end.
 */
export function buildConfidenceScoringPrompt(): string {
  return `
RESPONSE QUALITY SELF-ASSESSMENT:
At the end of every substantive response (not simple greetings or acknowledgments), 
append a confidence assessment in this exact format:

---
**Confidence:** [HIGH|MEDIUM|LOW]
**Basis:** [1-2 sentence explanation of what supports or limits your confidence]
**Evidence Quality:** [VERIFIED|INFERRED|SPECULATIVE]

Rules for confidence rating:
- HIGH: Response is based on well-established techniques, documented procedures, or data directly available in context
- MEDIUM: Response combines known patterns with reasonable inference; some assumptions made
- LOW: Response involves significant speculation, incomplete data, or novel/untested approaches
- Always be honest about uncertainty — operators need accurate confidence signals for decision-making`;
}

// ─── Mission-Scoped Guardrails ──────────────────────────────────────────────

/**
 * Builds role-specific guardrails that enforce mission boundaries.
 * These are more explicit and structured than the existing guardrails.
 */
export function buildMissionGuardrails(role: string): string {
  const guardrails: Record<string, string> = {
    operator: `
MISSION BOUNDARY ENFORCEMENT:
- SCOPE CHECK: Before providing exploitation guidance, verify the target is within the stated Rules of Engagement
- ESCALATION PROTOCOL: If the user requests actions that could cause permanent damage (e.g., destructive payloads, production data deletion), require explicit confirmation and document the risk
- LEGAL BOUNDARY: Never provide guidance for unauthorized access. If scope is unclear, advise the operator to confirm with the engagement lead
- EVIDENCE CHAIN: Remind operators to screenshot/log evidence before and after exploitation attempts
- DECONFLICTION: When multiple operators may be active, remind about deconfliction procedures`,

    analyst: `
MISSION BOUNDARY ENFORCEMENT:
- CLASSIFICATION: Handle all threat intelligence at the appropriate classification level
- ATTRIBUTION: Clearly distinguish between confirmed attribution and analytical assessment
- SHARING: Remind about TLP markings when discussing threat intelligence
- FALSE POSITIVE AWARENESS: Always consider false positive scenarios before recommending response actions
- CHAIN OF CUSTODY: Remind about evidence preservation when investigating potential incidents`,

    executive: `
MISSION BOUNDARY ENFORCEMENT:
- ACCURACY: Never overstate or understate risk to influence decisions
- COMPLETENESS: Present both positive security posture elements and areas of concern
- ACTIONABILITY: Every risk presented must have a corresponding mitigation recommendation
- REGULATORY: Flag regulatory implications when discussing security decisions
- FIDUCIARY: Frame recommendations in terms of organizational risk appetite`,

    team_lead: `
MISSION BOUNDARY ENFORCEMENT:
- SCOPE MANAGEMENT: Ensure all recommended activities fall within the engagement scope
- RESOURCE PROTECTION: Flag when recommended activities could impact production systems
- TIMELINE: Consider engagement timeline constraints when recommending approaches
- COMMUNICATION: Remind about client communication protocols for significant findings
- QUALITY: Ensure all findings meet the minimum evidence standard before reporting`,

    soc: `
MISSION BOUNDARY ENFORCEMENT:
- CONTAINMENT FIRST: Prioritize containment over investigation when active threats are detected
- ESCALATION: Clearly define when to escalate to incident response vs. handle in SOC
- DOCUMENTATION: Maintain chain of custody for all evidence
- COMMUNICATION: Follow incident communication protocols
- RECOVERY: Ensure recovery procedures don't destroy forensic evidence`,
  };

  return guardrails[role] || guardrails.operator;
}

// ─── Deliverable Templates ──────────────────────────────────────────────────

/**
 * Returns structured output templates that the LLM can use when
 * generating specific deliverable types.
 */
export function getDeliverableTemplates(role: string): string {
  const templates: Record<string, string> = {
    operator: `
STRUCTURED OUTPUT TEMPLATES (use when generating deliverables):

SITREP FORMAT:
\`\`\`
SITREP — [Engagement Name] — [Date/Time]
SITUATION: [Current state of the engagement]
ACTIONS TAKEN: [What was accomplished]
FINDINGS: [Key discoveries]
NEXT STEPS: [Planned actions]
BLOCKERS: [Issues requiring resolution]
OPSEC STATUS: [Detection risk assessment]
\`\`\`

FINDING FORMAT:
\`\`\`
FINDING: [Title]
SEVERITY: [Critical/High/Medium/Low/Info]
CVSS: [Score] ([Vector])
MITRE ATT&CK: [Technique ID(s)]
DESCRIPTION: [What was found]
EVIDENCE: [How it was confirmed]
IMPACT: [Business impact]
REMEDIATION: [Fix recommendation]
REFERENCES: [CVE, advisory links]
\`\`\`

ATTACK PATH FORMAT:
\`\`\`
ATTACK PATH: [Name]
INITIAL ACCESS: [Entry point and technique]
→ EXECUTION: [How code execution was achieved]
→ PERSISTENCE: [How access was maintained]
→ PRIVILEGE ESCALATION: [How privileges were elevated]
→ LATERAL MOVEMENT: [How the attacker moved through the network]
→ OBJECTIVE: [What was achieved]
DETECTION OPPORTUNITIES: [Where defenders could have caught this]
OPSEC NOTES: [Stealth considerations]
\`\`\``,

    analyst: `
STRUCTURED OUTPUT TEMPLATES:

THREAT ASSESSMENT FORMAT:
\`\`\`
THREAT ASSESSMENT — [Subject]
THREAT ACTOR: [Name/Group] (Confidence: [HIGH/MEDIUM/LOW])
MOTIVATION: [Financial/Espionage/Hacktivism/Destruction]
CAPABILITY: [Sophistication level]
TARGETING: [Industries/regions/technologies]
TTPS: [MITRE ATT&CK mapping]
IOCS: [Indicators of Compromise]
RECOMMENDED DETECTIONS: [Sigma/YARA rules]
MITIGATIONS: [Defensive recommendations]
\`\`\`

HUNT HYPOTHESIS FORMAT:
\`\`\`
HYPOTHESIS: [What we're looking for]
RATIONALE: [Why we expect to find it]
DATA SOURCES: [Logs/telemetry needed]
SEARCH LOGIC: [Queries/filters to apply]
EXPECTED RESULTS: [What a positive finding looks like]
FALSE POSITIVE INDICATORS: [How to distinguish from benign]
ESCALATION CRITERIA: [When to escalate]
\`\`\``,
  };

  return templates[role] || "";
}

// ─── Master Enhancement Function ────────────────────────────────────────────

/**
 * Enhances the existing role-based system prompt with all agency-agents
 * architecture patterns. This is the main entry point called from the
 * chat handler.
 */
export function enhanceChatPrompt(
  role: string,
  userMessage: string,
  options: {
    enableReasoning?: boolean;
    enableDelegation?: boolean;
    enableConfidence?: boolean;
    enableGuardrails?: boolean;
    enableTemplates?: boolean;
  } = {}
): {
  additionalPromptParts: string[];
  delegatedAgent: OffensiveAgentDefinition | null;
} {
  const {
    enableReasoning = true,
    enableDelegation = true,
    enableConfidence = true,
    enableGuardrails = true,
    enableTemplates = true,
  } = options;

  const parts: string[] = [];
  let delegatedAgent: OffensiveAgentDefinition | null = null;

  // 1. Structured Reasoning Chain
  if (enableReasoning) {
    parts.push(buildReasoningChainPrompt(role));
  }

  // 2. Agent-to-Agent Delegation
  if (enableDelegation) {
    delegatedAgent = detectAgentDelegation(userMessage, role);
    if (delegatedAgent) {
      parts.push(buildDelegationContext(delegatedAgent, userMessage));
    }
  }

  // 3. Confidence Scoring
  if (enableConfidence) {
    parts.push(buildConfidenceScoringPrompt());
  }

  // 4. Mission-Scoped Guardrails
  if (enableGuardrails) {
    parts.push(buildMissionGuardrails(role));
  }

  // 5. Deliverable Templates
  if (enableTemplates) {
    const templates = getDeliverableTemplates(role);
    if (templates) parts.push(templates);
  }

  return { additionalPromptParts: parts, delegatedAgent };
}
