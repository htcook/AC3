/**
 * Campaign Advisor — LLM Chat Engine
 * 
 * Queries all five engines simultaneously (Engagement Workflow, Lateral Movement,
 * Exploitation Bridge, Privilege Escalation, OPSEC Risk) to recommend the next
 * best action based on current engagement state, OPSEC exposure, and available
 * attack paths. Provides a conversational interface for operators.
 */

import { invokeLLM } from "../_core/llm";
import { getDb } from "../db";
import { eq, desc } from "drizzle-orm";
import {
  engagementTimelineEvents,
  opsecEvents,
  engagementWorkflowStates,
} from "../../drizzle/schema";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AdvisorContext {
  engagementId?: string;
  currentPhase?: string;
  recentActions?: Array<{ action: string; timestamp: number; success: boolean }>;
  opsecScore?: number;
  compromisedHosts?: string[];
  availableCredentials?: string[];
  knownVulnerabilities?: Array<{ cve: string; host: string; cvss: number }>;
  objectives?: string[];
}

export interface AdvisorMessage {
  role: "user" | "assistant" | "system";
  content: string;
}

export interface AdvisorRecommendation {
  nextAction: string;
  reasoning: string;
  phase: string;
  opsecRisk: number;
  engine: string;
  steps: string[];
  alternatives: Array<{ action: string; opsecRisk: number; reasoning: string }>;
  warnings: string[];
}

// ─── System Prompt ───────────────────────────────────────────────────────────

const CAMPAIGN_ADVISOR_SYSTEM_PROMPT = `You are the Campaign Advisor for AC3 — a professional red team and penetration testing platform. You are an expert red team operator with deep knowledge of:

## Your Capabilities
You have access to five specialized engines that you can reason about:

1. **Engagement Workflow Engine** — Manages the kill chain phases: pre_engagement → recon → scanning → gaining_access → maintaining_access → escalation → lateral_movement → collection → exfiltration → reporting → cleanup
2. **Lateral Movement Engine** — Plans pivot paths using PtH, WinRM, SSH, DCOM, PSExec, RDP, and more. Understands network topology, firewall segmentation, and credential types.
3. **Exploitation Bridge** — Maps CVEs to Metasploit modules and manual techniques. Knows 20+ CVE-to-exploit mappings including EternalBlue, Log4Shell, ProxyShell, Zerologon.
4. **Privilege Escalation Engine** — Analyzes WinPEAS/LinPEAS output. Covers Windows (SeImpersonate, JuicyPotato, PrintSpoofer, DLL hijack), Linux (SUID, sudo, cron, kernel), Kerberos (Kerberoasting, AS-REP, Golden/Silver Ticket, DCSync), and Cloud (AWS IAM, Azure RBAC, GCP).
5. **OPSEC Risk Engine** — Scores every action against EDR, SIEM, NDR, AV, and UEBA detection technologies. Tracks cumulative noise and burn indicators.

## Your Role
- Recommend the **next best action** based on the current engagement state
- Consider OPSEC risk for every recommendation — always provide the risk score
- Suggest **alternatives** with different risk/reward tradeoffs
- Warn about potential detection triggers and burned indicators
- Guide operators through the kill chain phases in order
- When asked about specific techniques, provide detailed step-by-step guidance
- Reference MITRE ATT&CK technique IDs when relevant

## Response Format
Always structure your responses clearly:
1. **Recommendation** — The primary next action
2. **Reasoning** — Why this is the best choice given the current state
3. **OPSEC Assessment** — Risk score and detection concerns
4. **Steps** — Concrete steps to execute
5. **Alternatives** — Other options with their tradeoffs
6. **Warnings** — Any red flags or concerns

Be direct, tactical, and professional. You are advising experienced operators.`;

// ─── Context Gathering ───────────────────────────────────────────────────────

/**
 * Gather current engagement context from the database for the advisor.
 */
export async function gatherEngagementContext(engagementId?: string): Promise<AdvisorContext> {
  const context: AdvisorContext = { engagementId };

  try {
    // Get recent timeline events
    const dbInstance = await getDb();
    if (!dbInstance) return context;
    const recentEvents = await dbInstance
      .select()
      .from(engagementTimelineEvents)
      .where(engagementId ? eq(engagementTimelineEvents.engagementId, engagementId) : undefined)
      .orderBy(desc(engagementTimelineEvents.createdAt))
      .limit(20);

    context.recentActions = recentEvents.map(e => ({
      action: e.title || "unknown",
      timestamp: Number(e.createdAt) || Date.now(),
      success: e.eventType === "action_completed",
    }));

    // Get current OPSEC score
    const recentOpsec = await dbInstance
      .select()
      .from(opsecEvents)
      .where(engagementId ? eq(opsecEvents.engagementId, parseInt(engagementId) || 0) : undefined)
      .orderBy(desc(opsecEvents.createdAt))
      .limit(10);

    if (recentOpsec.length > 0) {
      const avgScore = recentOpsec.reduce((sum, s) => sum + (s.riskScore || 0), 0) / recentOpsec.length;
      context.opsecScore = Math.round(avgScore);
    }

    // Get workflow state
    if (engagementId) {
      const workflowStates = await dbInstance
        .select()
        .from(engagementWorkflowStates)
        .where(eq(engagementWorkflowStates.engagementId, engagementId))
        .orderBy(desc(engagementWorkflowStates.createdAt))
        .limit(1);

      if (workflowStates.length > 0) {
        context.currentPhase = workflowStates[0].currentPhase || undefined;
      }
    }
  } catch (err) {
    console.error("[CampaignAdvisor] Context gathering failed:", err);
  }

  return context;
}

// ─── Build Context Summary ───────────────────────────────────────────────────

function buildContextSummary(ctx: AdvisorContext): string {
  const parts: string[] = [];

  if (ctx.engagementId) parts.push(`Engagement: ${ctx.engagementId}`);
  if (ctx.currentPhase) parts.push(`Current Phase: ${ctx.currentPhase}`);
  if (ctx.opsecScore !== undefined) parts.push(`Average OPSEC Risk Score: ${ctx.opsecScore}/100`);
  if (ctx.compromisedHosts?.length) parts.push(`Compromised Hosts: ${ctx.compromisedHosts.join(", ")}`);
  if (ctx.availableCredentials?.length) parts.push(`Available Credentials: ${ctx.availableCredentials.join(", ")}`);
  if (ctx.knownVulnerabilities?.length) {
    parts.push(`Known Vulnerabilities:\n${ctx.knownVulnerabilities.map(v => `  - ${v.cve} on ${v.host} (CVSS: ${v.cvss})`).join("\n")}`);
  }
  if (ctx.objectives?.length) parts.push(`Objectives: ${ctx.objectives.join(", ")}`);
  if (ctx.recentActions?.length) {
    const recent = ctx.recentActions.slice(0, 5);
    parts.push(`Recent Actions:\n${recent.map(a => `  - ${a.action} (${a.success ? "✓" : "✗"})`).join("\n")}`);
  }

  return parts.length > 0
    ? `\n## Current Engagement State\n${parts.join("\n")}`
    : "\n## Current Engagement State\nNo engagement context available. Starting fresh.";
}

// ─── Chat with Advisor ───────────────────────────────────────────────────────

/**
 * Send a message to the Campaign Advisor and get a response.
 * Automatically gathers engagement context and queries all engines.
 */
export async function chatWithAdvisor(
  messages: AdvisorMessage[],
  context?: AdvisorContext,
  engagementId?: string,
): Promise<{ response: string; context: AdvisorContext }> {
  // Gather context if not provided
  const ctx = context || await gatherEngagementContext(engagementId);
  const contextSummary = buildContextSummary(ctx);

  const systemMessage = CAMPAIGN_ADVISOR_SYSTEM_PROMPT + contextSummary;

  const llmMessages = [
    { role: "system" as const, content: systemMessage },
    ...messages.map(m => ({ role: m.role as "user" | "assistant", content: m.content })),
  ];

  const response = await invokeLLM({ _caller: "campaign-advisor.chatWithAdvisor", _priority: 'bulk', messages: llmMessages });
  const content = response.choices?.[0]?.message?.content || "I'm unable to provide a recommendation at this time. Please try again.";

  return { response: content, context: ctx };
}

// ─── Quick Recommendation (No Chat History) ──────────────────────────────────

/**
 * Get a quick recommendation based on current engagement state.
 * No chat history needed — just asks "what should I do next?"
 */
export async function getQuickRecommendation(
  engagementId?: string,
  specificQuestion?: string,
): Promise<{ response: string; context: AdvisorContext }> {
  const ctx = await gatherEngagementContext(engagementId);

  const question = specificQuestion || "Based on the current engagement state, what should I do next? Provide your top recommendation with OPSEC assessment and alternatives.";

  return chatWithAdvisor(
    [{ role: "user", content: question }],
    ctx,
    engagementId,
  );
}

// ─── Deterministic Quick Advice (No LLM) ────────────────────────────────────

/**
 * Provide deterministic advice based on current phase without LLM.
 * Useful as a fallback or for instant responses.
 */
export function getDeterministicAdvice(ctx: AdvisorContext): AdvisorRecommendation {
  const phase = ctx.currentPhase || "recon";
  const opsecScore = ctx.opsecScore || 0;

  const PHASE_ADVICE: Record<string, AdvisorRecommendation> = {
    pre_engagement: {
      nextAction: "Define scope and rules of engagement",
      reasoning: "Before any technical work begins, establish clear boundaries, authorized targets, and communication protocols with the client.",
      phase: "pre_engagement",
      opsecRisk: 0,
      engine: "engagement-workflow",
      steps: [
        "Create engagement document with scope, timeline, and emergency contacts",
        "Define authorized IP ranges and domains",
        "Set up secure communication channels",
        "Configure C2 infrastructure",
        "Verify legal authorization and signed agreements",
      ],
      alternatives: [
        { action: "Start passive recon while finalizing paperwork", opsecRisk: 5, reasoning: "Low risk OSINT can begin early" },
      ],
      warnings: ["Never begin active testing without signed authorization"],
    },
    recon: {
      nextAction: "Run comprehensive OSINT and passive reconnaissance",
      reasoning: "Passive recon has zero OPSEC risk and builds the foundation for all subsequent phases. Maximize information gathering before touching the target.",
      phase: "recon",
      opsecRisk: 5,
      engine: "engagement-workflow",
      steps: [
        "Run domain enumeration (subfinder, amass)",
        "Harvest email addresses and employee names",
        "Search for leaked credentials (dehashed, breach databases)",
        "Map the external attack surface",
        "Identify technology stack via passive fingerprinting",
      ],
      alternatives: [
        { action: "Begin active DNS enumeration", opsecRisk: 15, reasoning: "More complete results but generates DNS logs" },
        { action: "Run Shodan/Censys queries", opsecRisk: 5, reasoning: "Uses cached scan data, no direct contact" },
      ],
      warnings: opsecScore > 30 ? ["OPSEC score is elevated — stick to passive techniques"] : [],
    },
    scanning: {
      nextAction: "Run targeted port scans and service enumeration",
      reasoning: "With recon data in hand, identify live services and potential entry points through controlled scanning.",
      phase: "scanning",
      opsecRisk: 35,
      engine: "engagement-workflow",
      steps: [
        "Run targeted Nmap scans on high-value hosts",
        "Enumerate web applications with httpx",
        "Run vulnerability scanners on discovered services",
        "Identify default credentials on management interfaces",
        "Map the internal network topology from external perspective",
      ],
      alternatives: [
        { action: "Use ZAP for web app scanning", opsecRisk: 40, reasoning: "Deeper web vuln coverage but more noise" },
        { action: "Run Nuclei templates", opsecRisk: 30, reasoning: "Fast, targeted CVE checks" },
      ],
      warnings: opsecScore > 50 ? ["High OPSEC exposure — consider slowing scan rate and using decoy traffic"] : [],
    },
    gaining_access: {
      nextAction: "Exploit the highest-confidence vulnerability",
      reasoning: "Select the vulnerability with the best success probability and lowest detection risk for initial access.",
      phase: "gaining_access",
      opsecRisk: 60,
      engine: "exploitation-bridge",
      steps: [
        "Review vulnerability findings and rank by exploitability",
        "Use the Exploitation Bridge to match CVEs to exploits",
        "Set up payload with appropriate evasion",
        "Execute exploit with evidence capture enabled",
        "Establish initial foothold and verify access",
      ],
      alternatives: [
        { action: "Try credential stuffing with leaked creds", opsecRisk: 45, reasoning: "Lower noise than exploitation" },
        { action: "Launch targeted phishing campaign", opsecRisk: 50, reasoning: "Social engineering bypass for hardened targets" },
      ],
      warnings: ["Always have a rollback plan", "Capture all evidence before and after exploitation"],
    },
    maintaining_access: {
      nextAction: "Establish persistent access and deploy C2",
      reasoning: "Secure your foothold before the blue team can respond. Deploy lightweight persistence that survives reboots.",
      phase: "maintaining_access",
      opsecRisk: 55,
      engine: "engagement-workflow",
      steps: [
        "Deploy C2 implant with encrypted comms",
        "Establish persistence mechanism (scheduled task, service, registry)",
        "Set up backup access method",
        "Begin local enumeration from compromised host",
        "Dump local credentials for lateral movement",
      ],
      alternatives: [
        { action: "Use living-off-the-land techniques only", opsecRisk: 30, reasoning: "No custom tools = harder to detect" },
      ],
      warnings: ["EDR may detect persistence mechanisms — test in sandbox first"],
    },
    escalation: {
      nextAction: "Enumerate and exploit privilege escalation vectors",
      reasoning: "Elevate from standard user to admin/SYSTEM to unlock lateral movement capabilities.",
      phase: "escalation",
      opsecRisk: 50,
      engine: "privesc-engine",
      steps: [
        "Run enumeration tools (WinPEAS/LinPEAS)",
        "Analyze output with the Privesc Engine",
        "Execute the highest-confidence escalation technique",
        "Verify elevated access",
        "Dump credentials from elevated context",
      ],
      alternatives: [
        { action: "Try Kerberoasting for service account hashes", opsecRisk: 35, reasoning: "Normal AD traffic, hard to detect" },
        { action: "Check for unquoted service paths", opsecRisk: 25, reasoning: "Simple check, low noise" },
      ],
      warnings: ctx.opsecScore && ctx.opsecScore > 60 ? ["Consider using LOLBins to avoid EDR triggers"] : [],
    },
    lateral_movement: {
      nextAction: "Move laterally to high-value targets",
      reasoning: "Use obtained credentials and access to reach domain controllers, file servers, and other objectives.",
      phase: "lateral_movement",
      opsecRisk: 65,
      engine: "lateral-movement-engine",
      steps: [
        "Identify high-value targets (DC, file servers, databases)",
        "Use the Lateral Movement Engine to plan pivot paths",
        "Execute movement using the lowest-risk technique available",
        "Establish access on new host",
        "Repeat enumeration on each new host",
      ],
      alternatives: [
        { action: "Use WinRM for Windows lateral movement", opsecRisk: 40, reasoning: "Legitimate admin protocol, less suspicious" },
        { action: "Use SSH for Linux lateral movement", opsecRisk: 35, reasoning: "Standard admin access, encrypted" },
      ],
      warnings: ["PsExec creates service on remote host — high detection risk", "Monitor for account lockouts"],
    },
    collection: {
      nextAction: "Collect target data and evidence",
      reasoning: "Gather the data that demonstrates impact — sensitive files, database dumps, email access.",
      phase: "collection",
      opsecRisk: 45,
      engine: "engagement-workflow",
      steps: [
        "Identify sensitive data locations",
        "Collect proof-of-access screenshots",
        "Extract sample data (not full dumps unless authorized)",
        "Document access paths and methods used",
        "Timestamp all evidence",
      ],
      alternatives: [
        { action: "Focus on crown jewels only", opsecRisk: 30, reasoning: "Minimal data touch = minimal risk" },
      ],
      warnings: ["Never exfiltrate real PII/PHI without explicit authorization"],
    },
    exfiltration: {
      nextAction: "Demonstrate data exfiltration capability",
      reasoning: "Show the client that data can leave the network through their controls.",
      phase: "exfiltration",
      opsecRisk: 70,
      engine: "opsec-risk-engine",
      steps: [
        "Test exfiltration via HTTPS to external server",
        "Test DNS exfiltration as backup channel",
        "Document DLP bypass methods",
        "Record evidence of successful exfiltration",
        "Clean up exfiltrated test data",
      ],
      alternatives: [
        { action: "Document theoretical exfil paths without executing", opsecRisk: 10, reasoning: "Zero risk, still demonstrates the gap" },
      ],
      warnings: ["DLP systems may alert on large transfers", "Use encrypted channels only"],
    },
    reporting: {
      nextAction: "Compile findings into the engagement report",
      reasoning: "Document everything with evidence, attack paths, and remediation recommendations.",
      phase: "reporting",
      opsecRisk: 0,
      engine: "engagement-workflow",
      steps: [
        "Compile all findings with evidence",
        "Map findings to MITRE ATT&CK techniques",
        "Write remediation recommendations",
        "Create executive summary",
        "Prepare technical appendix with full attack chain",
      ],
      alternatives: [],
      warnings: ["Ensure all evidence is properly timestamped and attributed"],
    },
    cleanup: {
      nextAction: "Remove all artifacts and restore systems",
      reasoning: "Professional red teams leave no trace. Remove all tools, persistence, and test data.",
      phase: "cleanup",
      opsecRisk: 0,
      engine: "engagement-workflow",
      steps: [
        "Remove all C2 implants and persistence mechanisms",
        "Delete uploaded tools and scripts",
        "Remove test accounts and credentials",
        "Verify cleanup with fresh scans",
        "Document any artifacts that couldn't be removed",
      ],
      alternatives: [],
      warnings: ["Coordinate cleanup timing with the client's blue team"],
    },
  };

  return PHASE_ADVICE[phase] || PHASE_ADVICE.recon;
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export {
  CAMPAIGN_ADVISOR_SYSTEM_PROMPT,
  buildContextSummary,
};
