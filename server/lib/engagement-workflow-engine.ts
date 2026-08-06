/**
 * Engagement Workflow Engine — LLM-Driven Kill Chain State Machine
 *
 * Orchestrates the entire engagement lifecycle through kill chain phases.
 * The LLM autonomously:
 *   - Decides when to advance phases based on findings
 *   - Triggers auto-handoff between modules
 *   - Generates phase objectives and success criteria
 *   - Recommends next actions based on accumulated intelligence
 *   - Produces engagement summaries per phase
 *
 * Deterministic fallback: rule-based phase transitions when LLM is unavailable.
 */

// ─── Kill Chain Phase Definitions ────────────────────────────────────────────

export const KILL_CHAIN_PHASES = [
  "pre_engagement",
  "reconnaissance",
  "threat_modeling",
  "vulnerability_analysis",
  "exploitation",
  "post_exploitation",
  "lateral_movement",
  "collection_exfiltration",
  "reporting",
  "completed",
] as const;

export type KillChainPhase = (typeof KILL_CHAIN_PHASES)[number];

export interface PhaseDefinition {
  id: KillChainPhase;
  name: string;
  description: string;
  mitrePhases: string[];
  requiredModules: string[];
  successCriteria: string[];
  autoHandoffTriggers: HandoffTrigger[];
  opsecConsiderations: string[];
}

export interface HandoffTrigger {
  condition: string;
  description: string;
  minFindings: number;
  findingTypes: string[];
  autoAdvance: boolean;
}

export interface PhaseRecommendation {
  phase: KillChainPhase;
  confidence: number;
  reasoning: string;
  nextActions: NextAction[];
  objectivesForPhase: string[];
  estimatedDuration: string;
  opsecLevel: "stealth" | "low" | "moderate" | "loud";
}

export interface NextAction {
  module: string;
  action: string;
  priority: "critical" | "high" | "medium" | "low";
  description: string;
  attackTechnique?: string;
  opsecRisk: number;
  automatable: boolean;
}

export interface EngagementState {
  engagementId: number;
  currentPhase: KillChainPhase;
  phaseProgress: Record<KillChainPhase, number>;
  findingsCounts: Record<KillChainPhase, number>;
  completedPhases: KillChainPhase[];
  activeObjectives: string[];
  completedObjectives: string[];
  totalFindings: number;
  shellsObtained: number;
  credentialsFound: number;
  pivotHostsEstablished: number;
  overallProgress: number;
}

export interface TimelineEntry {
  engagementId: number;
  phase: string;
  eventType: string;
  severity: string;
  title: string;
  description: string;
  metadata: Record<string, unknown>;
  sourceModule: string;
  sourceId?: string;
  targetHost?: string;
  targetPort?: number;
  attackTechnique?: string;
  timestamp: number;
}

// ─── Phase Knowledge Base ────────────────────────────────────────────────────

export const PHASE_DEFINITIONS: Record<KillChainPhase, PhaseDefinition> = {
  pre_engagement: {
    id: "pre_engagement",
    name: "Pre-Engagement",
    description: "Scope definition, ROE signing, infrastructure setup, and engagement planning.",
    mitrePhases: [],
    requiredModules: ["roe-builder", "engagement-automation", "infra-deploy"],
    successCriteria: [
      "ROE document signed and uploaded",
      "Scope defined (target IPs, domains, exclusions)",
      "C2 infrastructure provisioned",
      "Team roles assigned",
    ],
    autoHandoffTriggers: [
      { condition: "roe_signed", description: "ROE signed → advance to recon", minFindings: 0, findingTypes: [], autoAdvance: true },
    ],
    opsecConsiderations: ["Ensure all infrastructure is clean", "Verify redirectors are functional", "Test C2 callbacks from target network perspective"],
  },
  reconnaissance: {
    id: "reconnaissance",
    name: "Reconnaissance",
    description: "Passive and active intelligence gathering. OSINT, DNS enumeration, service discovery, technology fingerprinting.",
    mitrePhases: ["TA0043"],
    requiredModules: ["domain-intel", "scanforge-discovery", "projectdiscovery", "shodan", "censys", "service-fingerprinter", "org-enrichment"],
    successCriteria: [
      "Target attack surface mapped (domains, subdomains, IPs)",
      "Services and versions identified",
      "Technology stack fingerprinted",
      "Email addresses and personnel identified",
      "Potential entry points cataloged",
    ],
    autoHandoffTriggers: [
      { condition: "sufficient_recon", description: "Enough recon data to model threats", minFindings: 10, findingTypes: ["domain", "service", "technology"], autoAdvance: true },
      { condition: "critical_finding", description: "Critical exposure found → fast-track to vuln analysis", minFindings: 1, findingTypes: ["critical_exposure"], autoAdvance: true },
    ],
    opsecConsiderations: ["Prefer passive recon first", "Rate-limit active scans", "Use distributed scanning infrastructure"],
  },
  threat_modeling: {
    id: "threat_modeling",
    name: "Threat Modeling",
    description: "Map attack surface to threat actors, identify likely attack paths, prioritize targets using CARVER+Shock scoring.",
    mitrePhases: [],
    requiredModules: ["scoring-engine", "threat-actor-matcher", "attack-vector-engine", "attack-path-discovery"],
    successCriteria: [
      "CARVER+Shock scores calculated for all targets",
      "Threat actors mapped to target profile",
      "Attack paths identified and prioritized",
      "High-value targets identified",
    ],
    autoHandoffTriggers: [
      { condition: "targets_prioritized", description: "Targets scored and prioritized → advance to vuln analysis", minFindings: 5, findingTypes: ["scored_target", "attack_path"], autoAdvance: true },
    ],
    opsecConsiderations: ["This phase is entirely analytical — no network noise"],
  },
  vulnerability_analysis: {
    id: "vulnerability_analysis",
    name: "Vulnerability Analysis",
    description: "Active vulnerability scanning, web app testing, vendor/OEM default credential testing, and generic credential testing against prioritized targets.",
    mitrePhases: ["TA0043"],
    requiredModules: ["zap-scanner", "nuclei-scanner", "scanforge-discovery", "credential-attack-engine", "oem-default-creds", "web-crawler", "vuln-scanner-parser"],
    successCriteria: [
      "Vulnerability scan completed on all in-scope targets",
      "Web application vulnerabilities identified",
      "Vendor/OEM default credentials tested against all login services (SSH, FTP, RDP, web admin, databases)",
      "Generic/common credential wordlists tested as fallback",
      "CVEs mapped to exploits",
    ],
    autoHandoffTriggers: [
      { condition: "exploitable_vulns", description: "Exploitable vulnerabilities found → advance to exploitation", minFindings: 1, findingTypes: ["critical_vuln", "high_vuln", "weak_credential"], autoAdvance: true },
    ],
    opsecConsiderations: ["Vulnerability scanning is noisy", "Consider time-delayed scanning", "Use authenticated scans where possible to reduce noise"],
  },
  exploitation: {
    id: "exploitation",
    name: "Exploitation",
    description: "Exploit confirmed vulnerabilities to gain initial access. Use Metasploit, manual exploits, or credential stuffing.",
    mitrePhases: ["TA0001", "TA0002"],
    requiredModules: ["exploit-matcher", "msf-client", "credential-attack-engine", "external-credential-tools", "exploit-preflight"],
    successCriteria: [
      "At least one shell obtained on target",
      "Initial access documented with evidence",
      "Access level determined (user/admin/system)",
    ],
    autoHandoffTriggers: [
      { condition: "shell_obtained", description: "Shell obtained → advance to post-exploitation", minFindings: 1, findingTypes: ["shell", "session"], autoAdvance: true },
    ],
    opsecConsiderations: ["Exploitation is the highest-risk phase", "Use staged payloads", "Prefer memory-only execution", "Have backup exploits ready"],
  },
  post_exploitation: {
    id: "post_exploitation",
    name: "Post-Exploitation",
    description: "Privilege escalation, persistence, credential harvesting, and local enumeration on compromised hosts.",
    mitrePhases: ["TA0004", "TA0003", "TA0006", "TA0007"],
    requiredModules: ["privesc-engine", "credential-attack-engine", "evasion-orchestrator", "saml-offensive-engine", "k8s-post-exploit", "cloud-exploit-frameworks"],
    successCriteria: [
      "Privileges escalated where possible",
      "Credentials harvested from compromised hosts",
      "Persistence mechanisms established",
      "Local network enumeration completed",
    ],
    autoHandoffTriggers: [
      { condition: "domain_creds", description: "Domain credentials found → advance to lateral movement", minFindings: 1, findingTypes: ["domain_credential", "ntlm_hash", "kerberos_ticket"], autoAdvance: true },
      { condition: "admin_access", description: "Admin/root access achieved → advance to lateral movement", minFindings: 1, findingTypes: ["admin_shell", "root_shell"], autoAdvance: true },
    ],
    opsecConsiderations: ["Minimize disk writes", "Use LOLBins where possible", "Clean up artifacts after each action"],
  },
  lateral_movement: {
    id: "lateral_movement",
    name: "Lateral Movement",
    description: "Move through the network using obtained credentials and access. Establish pivots, reach high-value targets.",
    mitrePhases: ["TA0008"],
    requiredModules: ["lateral-movement-engine", "ssh-tunnel-manager", "credential-attack-engine", "k8s-post-exploit", "cloud-exploit-frameworks", "gitops-offensive-engine"],
    successCriteria: [
      "Additional hosts compromised",
      "Pivot points established",
      "Domain controller or high-value target reached",
      "Network topology mapped from inside",
    ],
    autoHandoffTriggers: [
      { condition: "objective_reached", description: "High-value target compromised → advance to collection", minFindings: 1, findingTypes: ["domain_controller", "database_server", "crown_jewel"], autoAdvance: true },
    ],
    opsecConsiderations: ["Use legitimate admin tools where possible", "Avoid mass scanning from compromised hosts", "Rotate credentials to avoid lockouts"],
  },
  collection_exfiltration: {
    id: "collection_exfiltration",
    name: "Collection & Exfiltration",
    description: "Collect target data, stage for exfiltration, and demonstrate data access as proof of impact.",
    mitrePhases: ["TA0009", "TA0010"],
    requiredModules: [],
    successCriteria: [
      "Sensitive data identified and cataloged",
      "Proof of access documented (screenshots, file listings)",
      "Exfiltration path demonstrated (if in scope)",
    ],
    autoHandoffTriggers: [
      { condition: "data_collected", description: "Sufficient evidence collected → advance to reporting", minFindings: 3, findingTypes: ["data_access", "screenshot", "file_listing"], autoAdvance: true },
    ],
    opsecConsiderations: ["Never exfiltrate actual sensitive data unless explicitly authorized", "Use proof-of-concept files", "Document everything for the report"],
  },
  reporting: {
    id: "reporting",
    name: "Reporting",
    description: "Generate comprehensive engagement report with findings, evidence, and remediation recommendations.",
    mitrePhases: [],
    requiredModules: ["report-generator", "pdf-report-generator"],
    successCriteria: [
      "Executive summary written",
      "All findings documented with evidence",
      "Remediation recommendations provided",
      "MITRE ATT&CK mapping completed",
      "Report delivered to client",
    ],
    autoHandoffTriggers: [
      { condition: "report_delivered", description: "Report delivered → engagement complete", minFindings: 0, findingTypes: [], autoAdvance: true },
    ],
    opsecConsiderations: ["Clean up all persistence mechanisms", "Remove all implants and backdoors", "Verify all artifacts are removed from target"],
  },
  completed: {
    id: "completed",
    name: "Completed",
    description: "Engagement completed. All phases finished, report delivered, cleanup verified.",
    mitrePhases: [],
    requiredModules: [],
    successCriteria: ["All cleanup verified", "Report accepted by client"],
    autoHandoffTriggers: [],
    opsecConsiderations: ["Verify no residual access remains"],
  },
};

// ─── LLM System Prompt ──────────────────────────────────────────────────────

const WORKFLOW_SYSTEM_PROMPT = `You are the AC3 Engagement Workflow Engine — an autonomous red team engagement orchestrator.

You manage the full kill chain lifecycle for penetration tests and red team exercises. Your role is to:
1. Analyze the current engagement state (findings, shells, credentials, phase progress)
2. Decide whether to advance to the next phase or continue the current one
3. Recommend specific next actions with priority and OPSEC risk ratings
4. Generate phase-specific objectives tailored to the engagement context
5. Predict which modules and tools should be activated next

KILL CHAIN PHASES (in order):
${KILL_CHAIN_PHASES.map((p, i) => `${i + 1}. ${p}: ${PHASE_DEFINITIONS[p].description}`).join("\n")}

DECISION FRAMEWORK:
- Advance phase when success criteria are met OR when a high-priority trigger fires
- Never skip phases unless explicitly authorized (e.g., "fast-track to exploitation")
- Always consider OPSEC implications before recommending loud actions
- Prioritize actions that yield the most intelligence with the least noise
- If exploitation stalls, recommend returning to recon for additional attack surface

CREDENTIAL TESTING REQUIREMENTS:
- During vulnerability_analysis phase, ALWAYS test vendor/OEM default credentials before generic wordlists
- Use the OEM default credential database to match detected technologies (from httpx, ScanForge service detection, banner grabs) against known vendor defaults
- For every login service discovered (SSH, FTP, RDP, web admin panels, databases, SNMP, telnet), first attempt vendor-specific default credentials, then fall back to common wordlists
- When recommending credential testing actions, explicitly include "OEM default credential test" as a high-priority action
- Flag any successful default credential login as a CRITICAL finding — default credentials are among the highest-risk vulnerabilities

OUTPUT FORMAT (JSON):
{
  "shouldAdvance": boolean,
  "nextPhase": string | null,
  "confidence": number (0-100),
  "reasoning": string,
  "nextActions": [{ "module": string, "action": string, "priority": "critical"|"high"|"medium"|"low", "description": string, "attackTechnique": string, "opsecRisk": number (1-10), "automatable": boolean }],
  "objectivesForPhase": [string],
  "estimatedDuration": string,
  "opsecLevel": "stealth"|"low"|"moderate"|"loud",
  "phaseSummary": string
}`;

// ─── Core Engine Functions ───────────────────────────────────────────────────

/**
 * Evaluate the current engagement state and produce LLM-driven recommendations.
 * Falls back to deterministic rules if LLM is unavailable.
 */
export async function evaluateEngagementState(
  state: EngagementState,
  recentFindings?: string[],
  constraints?: { maxOpsecLevel?: string; fastTrack?: boolean; focusPhase?: KillChainPhase }
): Promise<PhaseRecommendation> {
  try {
    return await llmEvaluateState(state, recentFindings, constraints);
  } catch (err) {
    console.warn("[EngagementWorkflow] LLM unavailable, using deterministic fallback:", (err as Error).message);
    return deterministicEvaluateState(state, recentFindings);
  }
}

async function llmEvaluateState(
  state: EngagementState,
  recentFindings?: string[],
  constraints?: { maxOpsecLevel?: string; fastTrack?: boolean; focusPhase?: KillChainPhase }
): Promise<PhaseRecommendation> {
  const { invokeLLM } = await import("../_core/llm");

  const userPrompt = `ENGAGEMENT STATE:
- Engagement ID: ${state.engagementId}
- Current Phase: ${state.currentPhase}
- Overall Progress: ${state.overallProgress}%
- Completed Phases: ${state.completedPhases.join(", ") || "none"}
- Total Findings: ${state.totalFindings}
- Shells Obtained: ${state.shellsObtained}
- Credentials Found: ${state.credentialsFound}
- Pivot Hosts: ${state.pivotHostsEstablished}
- Active Objectives: ${state.activeObjectives.join("; ") || "none set"}
- Completed Objectives: ${state.completedObjectives.join("; ") || "none"}

PHASE PROGRESS:
${Object.entries(state.phaseProgress).filter(([_, v]) => v > 0).map(([k, v]) => `  ${k}: ${v}%`).join("\n") || "  No progress recorded"}

FINDINGS PER PHASE:
${Object.entries(state.findingsCounts).filter(([_, v]) => v > 0).map(([k, v]) => `  ${k}: ${v} findings`).join("\n") || "  No findings yet"}

RECENT FINDINGS:
${recentFindings?.join("\n") || "None"}

CONSTRAINTS:
${constraints ? JSON.stringify(constraints) : "None"}

Analyze this state and provide your recommendation as JSON.`;

  const response = await invokeLLM({
    _caller: "engagement-workflow-engine.llmEvaluateState",
    messages: [
      { role: "system", content: WORKFLOW_SYSTEM_PROMPT },
      { role: "user", content: userPrompt },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "phase_recommendation",
        strict: true,
        schema: {
          type: "object",
          properties: {
            shouldAdvance: { type: "boolean" },
            nextPhase: { type: ["string", "null"] },
            confidence: { type: "number" },
            reasoning: { type: "string" },
            nextActions: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  module: { type: "string" },
                  action: { type: "string" },
                  priority: { type: "string", enum: ["critical", "high", "medium", "low"] },
                  description: { type: "string" },
                  attackTechnique: { type: "string" },
                  opsecRisk: { type: "number" },
                  automatable: { type: "boolean" },
                },
                required: ["module", "action", "priority", "description", "attackTechnique", "opsecRisk", "automatable"],
                additionalProperties: false,
              },
            },
            objectivesForPhase: { type: "array", items: { type: "string" } },
            estimatedDuration: { type: "string" },
            opsecLevel: { type: "string", enum: ["stealth", "low", "moderate", "loud"] },
            phaseSummary: { type: "string" },
          },
          required: ["shouldAdvance", "nextPhase", "confidence", "reasoning", "nextActions", "objectivesForPhase", "estimatedDuration", "opsecLevel", "phaseSummary"],
          additionalProperties: false,
        },
      },
    },
  });

  const parsed = JSON.parse(response.choices[0].message.content as string);
  return {
    phase: parsed.shouldAdvance && parsed.nextPhase ? (parsed.nextPhase as KillChainPhase) : state.currentPhase,
    confidence: parsed.confidence,
    reasoning: parsed.reasoning,
    nextActions: parsed.nextActions,
    objectivesForPhase: parsed.objectivesForPhase,
    estimatedDuration: parsed.estimatedDuration,
    opsecLevel: parsed.opsecLevel,
  };
}

/**
 * Deterministic fallback — rule-based phase transition logic.
 */
export function deterministicEvaluateState(
  state: EngagementState,
  recentFindings?: string[]
): PhaseRecommendation {
  const currentIdx = KILL_CHAIN_PHASES.indexOf(state.currentPhase);
  const phaseDef = PHASE_DEFINITIONS[state.currentPhase];
  const progress = state.phaseProgress[state.currentPhase] || 0;

  // Check auto-handoff triggers
  for (const trigger of phaseDef.autoHandoffTriggers) {
    const findingsInPhase = state.findingsCounts[state.currentPhase] || 0;
    if (findingsInPhase >= trigger.minFindings && trigger.autoAdvance) {
      const nextPhase = KILL_CHAIN_PHASES[currentIdx + 1];
      if (nextPhase) {
        return buildDeterministicRecommendation(nextPhase, true, state, `Auto-handoff triggered: ${trigger.description}`);
      }
    }
  }

  // Check if phase progress warrants advancement
  if (progress >= 80) {
    const nextPhase = KILL_CHAIN_PHASES[currentIdx + 1];
    if (nextPhase) {
      return buildDeterministicRecommendation(nextPhase, true, state, `Phase ${state.currentPhase} is ${progress}% complete — ready to advance.`);
    }
  }

  // Special fast-track: shell obtained during vuln analysis → skip to exploitation
  if (state.currentPhase === "vulnerability_analysis" && state.shellsObtained > 0) {
    return buildDeterministicRecommendation("exploitation", true, state, "Shell obtained during vulnerability analysis — fast-tracking to exploitation phase.");
  }

  // Special: credentials found during exploitation → advance to post-exploitation
  if (state.currentPhase === "exploitation" && state.credentialsFound > 0 && state.shellsObtained > 0) {
    return buildDeterministicRecommendation("post_exploitation", true, state, "Shell and credentials obtained — advancing to post-exploitation.");
  }

  // Stay in current phase
  return buildDeterministicRecommendation(state.currentPhase, false, state, `Continuing ${state.currentPhase} — ${progress}% complete, ${state.findingsCounts[state.currentPhase] || 0} findings so far.`);
}

function buildDeterministicRecommendation(
  phase: KillChainPhase,
  shouldAdvance: boolean,
  state: EngagementState,
  reasoning: string
): PhaseRecommendation {
  const phaseDef = PHASE_DEFINITIONS[phase];
  const nextActions: NextAction[] = phaseDef.requiredModules.slice(0, 5).map((mod, i) => ({
    module: mod,
    action: `Run ${mod} against engagement targets`,
    priority: i === 0 ? "high" as const : "medium" as const,
    description: `Execute ${mod} module as part of ${phaseDef.name} phase`,
    attackTechnique: phaseDef.mitrePhases[0] || "N/A",
    opsecRisk: phase === "exploitation" ? 8 : phase === "reconnaissance" ? 3 : 5,
    automatable: true,
  }));

  return {
    phase,
    confidence: shouldAdvance ? 85 : 60,
    reasoning,
    nextActions,
    objectivesForPhase: phaseDef.successCriteria,
    estimatedDuration: estimatePhaseDuration(phase),
    opsecLevel: phase === "exploitation" || phase === "lateral_movement" ? "loud" : phase === "reconnaissance" ? "low" : "moderate",
  };
}

function estimatePhaseDuration(phase: KillChainPhase): string {
  const estimates: Record<KillChainPhase, string> = {
    pre_engagement: "1-2 days",
    reconnaissance: "2-5 days",
    threat_modeling: "1-2 days",
    vulnerability_analysis: "3-5 days",
    exploitation: "2-5 days",
    post_exploitation: "2-4 days",
    lateral_movement: "2-5 days",
    collection_exfiltration: "1-2 days",
    reporting: "3-5 days",
    completed: "0 days",
  };
  return estimates[phase];
}

// ─── Timeline Event Emitter ──────────────────────────────────────────────────

/**
 * Create a timeline event for the engagement.
 * All modules should call this to feed the unified timeline.
 */
export function createTimelineEvent(
  engagementId: number,
  phase: KillChainPhase,
  eventType: string,
  title: string,
  opts?: Partial<Omit<TimelineEntry, "engagementId" | "phase" | "eventType" | "title" | "timestamp">>
): TimelineEntry {
  return {
    engagementId,
    phase,
    eventType,
    title,
    severity: opts?.severity || "info",
    description: opts?.description || "",
    metadata: opts?.metadata || {},
    sourceModule: opts?.sourceModule || "engagement-workflow-engine",
    sourceId: opts?.sourceId,
    targetHost: opts?.targetHost,
    targetPort: opts?.targetPort,
    attackTechnique: opts?.attackTechnique,
    timestamp: Date.now(),
  };
}

// ─── Phase Transition Logic ──────────────────────────────────────────────────

/**
 * Advance the engagement to the next phase.
 * Validates the transition is legal and generates handoff context.
 */
export function validatePhaseTransition(
  currentPhase: KillChainPhase,
  targetPhase: KillChainPhase
): { valid: boolean; reason: string } {
  const currentIdx = KILL_CHAIN_PHASES.indexOf(currentPhase);
  const targetIdx = KILL_CHAIN_PHASES.indexOf(targetPhase);

  if (targetIdx < 0) return { valid: false, reason: `Unknown phase: ${targetPhase}` };
  if (targetIdx === currentIdx) return { valid: false, reason: "Already in this phase" };
  if (targetIdx < currentIdx) return { valid: true, reason: "Returning to earlier phase (allowed for iterative testing)" };
  if (targetIdx > currentIdx + 1) return { valid: true, reason: "Skipping phases (fast-track authorized)" };
  return { valid: true, reason: "Normal sequential advancement" };
}

/**
 * Generate a handoff context when transitioning between phases.
 * The LLM uses this to brief the next phase on what was discovered.
 */
export async function generatePhaseHandoff(
  state: EngagementState,
  fromPhase: KillChainPhase,
  toPhase: KillChainPhase,
  findings: string[]
): Promise<{ briefing: string; prioritizedTargets: string[]; recommendedApproach: string }> {
  try {
    const { invokeLLM } = await import("../_core/llm");
    const response = await invokeLLM({
      _caller: "engagement-workflow-engine.generatePhaseHandoff",
      messages: [
        {
          role: "system",
          content: `You are the AC3 phase handoff briefer. Generate a concise operational briefing for the team transitioning from "${fromPhase}" to "${toPhase}". Include: key findings summary, prioritized targets, and recommended approach for the next phase.`,
        },
        {
          role: "user",
          content: `TRANSITION: ${fromPhase} → ${toPhase}\n\nFINDINGS FROM ${fromPhase}:\n${findings.join("\n")}\n\nSHELLS: ${state.shellsObtained}, CREDS: ${state.credentialsFound}, PIVOTS: ${state.pivotHostsEstablished}\n\nGenerate the handoff briefing as JSON with fields: briefing (string), prioritizedTargets (string[]), recommendedApproach (string).`,
        },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "phase_handoff",
          strict: true,
          schema: {
            type: "object",
            properties: {
              briefing: { type: "string" },
              prioritizedTargets: { type: "array", items: { type: "string" } },
              recommendedApproach: { type: "string" },
            },
            required: ["briefing", "prioritizedTargets", "recommendedApproach"],
            additionalProperties: false,
          },
        },
      },
    });
    return JSON.parse(response.choices[0].message.content as string);
  } catch {
    return {
      briefing: `Transitioning from ${fromPhase} to ${toPhase}. ${findings.length} findings from previous phase.`,
      prioritizedTargets: findings.slice(0, 5),
      recommendedApproach: PHASE_DEFINITIONS[toPhase].description,
    };
  }
}

// ─── Engagement Initialization ───────────────────────────────────────────────

/**
 * Initialize a new engagement workflow state with LLM-generated objectives.
 */
export async function initializeEngagementWorkflow(
  engagementId: number,
  engagementType: string,
  targetDomain?: string,
  targetIpRange?: string,
  notes?: string
): Promise<{ state: EngagementState; recommendation: PhaseRecommendation }> {
  const state: EngagementState = {
    engagementId,
    currentPhase: "pre_engagement",
    phaseProgress: Object.fromEntries(KILL_CHAIN_PHASES.map(p => [p, 0])) as Record<KillChainPhase, number>,
    findingsCounts: Object.fromEntries(KILL_CHAIN_PHASES.map(p => [p, 0])) as Record<KillChainPhase, number>,
    completedPhases: [],
    activeObjectives: PHASE_DEFINITIONS.pre_engagement.successCriteria,
    completedObjectives: [],
    totalFindings: 0,
    shellsObtained: 0,
    credentialsFound: 0,
    pivotHostsEstablished: 0,
    overallProgress: 0,
  };

  const recommendation = await evaluateEngagementState(state, [
    `New ${engagementType} engagement initialized`,
    targetDomain ? `Target domain: ${targetDomain}` : "",
    targetIpRange ? `Target IP range: ${targetIpRange}` : "",
    notes || "",
  ].filter(Boolean));

  return { state, recommendation };
}

/**
 * Get the full phase definition for display or reference.
 */
export function getPhaseDefinition(phase: KillChainPhase): PhaseDefinition {
  return PHASE_DEFINITIONS[phase];
}

/**
 * Get all phase definitions for the guided workflow view.
 */
export function getAllPhaseDefinitions(): PhaseDefinition[] {
  return KILL_CHAIN_PHASES.map(p => PHASE_DEFINITIONS[p]);
}

/**
 * Calculate overall engagement progress from phase progress.
 */
export function calculateOverallProgress(phaseProgress: Record<KillChainPhase, number>): number {
  const weights: Record<KillChainPhase, number> = {
    pre_engagement: 5,
    reconnaissance: 15,
    threat_modeling: 10,
    vulnerability_analysis: 15,
    exploitation: 20,
    post_exploitation: 10,
    lateral_movement: 10,
    collection_exfiltration: 5,
    reporting: 10,
    completed: 0,
  };
  let totalWeight = 0;
  let weightedProgress = 0;
  for (const [phase, weight] of Object.entries(weights)) {
    totalWeight += weight;
    weightedProgress += (phaseProgress[phase as KillChainPhase] || 0) * weight;
  }
  return Math.round(weightedProgress / totalWeight);
}
