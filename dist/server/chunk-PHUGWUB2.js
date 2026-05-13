import {
  init_llm,
  invokeLLM
} from "./chunk-4BQS7LEI.js";
import {
  getDb,
  init_db
} from "./chunk-VL2KRLTM.js";
import {
  burpScanHistory,
  engagementTimelineEvents,
  engagementWorkflowStates,
  init_schema,
  opsecEvents
} from "./chunk-IG2G4XDA.js";

// server/lib/campaign-advisor.ts
init_llm();
init_db();
init_schema();
import { eq, desc } from "drizzle-orm";
var CAMPAIGN_ADVISOR_SYSTEM_PROMPT = `You are the Campaign Advisor for AC3 \u2014 a professional red team and penetration testing platform. You are an expert red team operator with deep knowledge of:

## Your Capabilities
You have access to five specialized engines that you can reason about:

1. **Engagement Workflow Engine** \u2014 Manages the kill chain phases: pre_engagement \u2192 recon \u2192 scanning \u2192 gaining_access \u2192 maintaining_access \u2192 escalation \u2192 lateral_movement \u2192 collection \u2192 exfiltration \u2192 reporting \u2192 cleanup
2. **Lateral Movement Engine** \u2014 Plans pivot paths using PtH, WinRM, SSH, DCOM, PSExec, RDP, and more. Understands network topology, firewall segmentation, and credential types.
3. **Exploitation Bridge** \u2014 Maps CVEs to Metasploit modules and manual techniques. Knows 20+ CVE-to-exploit mappings including EternalBlue, Log4Shell, ProxyShell, Zerologon.
4. **Privilege Escalation Engine** \u2014 Analyzes WinPEAS/LinPEAS output. Covers Windows (SeImpersonate, JuicyPotato, PrintSpoofer, DLL hijack), Linux (SUID, sudo, cron, kernel), Kerberos (Kerberoasting, AS-REP, Golden/Silver Ticket, DCSync), and Cloud (AWS IAM, Azure RBAC, GCP).
5. **OPSEC Risk Engine** \u2014 Scores every action against EDR, SIEM, NDR, AV, and UEBA detection technologies. Tracks cumulative noise and burn indicators.
6. **Burp Suite Integration** \u2014 When Burp scan results are available in the engagement context, factor them into your recommendations. Cross-reference Burp findings with ZAP results for corroboration. Prioritize findings that both tools flagged (cross-tool escalation). Use Burp's severity breakdown to guide exploitation ordering.

## Your Role
- Recommend the **next best action** based on the current engagement state
- Consider OPSEC risk for every recommendation \u2014 always provide the risk score
- Suggest **alternatives** with different risk/reward tradeoffs
- Warn about potential detection triggers and burned indicators
- Guide operators through the kill chain phases in order
- When asked about specific techniques, provide detailed step-by-step guidance
- Reference MITRE ATT&CK technique IDs when relevant

## Response Format
Always structure your responses clearly:
1. **Recommendation** \u2014 The primary next action
2. **Reasoning** \u2014 Why this is the best choice given the current state
3. **OPSEC Assessment** \u2014 Risk score and detection concerns
4. **Steps** \u2014 Concrete steps to execute
5. **Alternatives** \u2014 Other options with their tradeoffs
6. **Warnings** \u2014 Any red flags or concerns

Be direct, tactical, and professional. You are advising experienced operators.`;
async function gatherEngagementContext(engagementId) {
  const context = { engagementId };
  try {
    const dbInstance = await getDb();
    if (!dbInstance) return context;
    const recentEvents = await dbInstance.select().from(engagementTimelineEvents).where(engagementId ? eq(engagementTimelineEvents.engagementId, engagementId) : void 0).orderBy(desc(engagementTimelineEvents.createdAt)).limit(20);
    context.recentActions = recentEvents.map((e) => ({
      action: e.title || "unknown",
      timestamp: Number(e.createdAt) || Date.now(),
      success: e.eventType === "action_completed"
    }));
    const recentOpsec = await dbInstance.select().from(opsecEvents).where(engagementId ? eq(opsecEvents.engagementId, parseInt(engagementId) || 0) : void 0).orderBy(desc(opsecEvents.createdAt)).limit(10);
    if (recentOpsec.length > 0) {
      const avgScore = recentOpsec.reduce((sum, s) => sum + (s.riskScore || 0), 0) / recentOpsec.length;
      context.opsecScore = Math.round(avgScore);
    }
    if (engagementId) {
      const workflowStates = await dbInstance.select().from(engagementWorkflowStates).where(eq(engagementWorkflowStates.engagementId, engagementId)).orderBy(desc(engagementWorkflowStates.createdAt)).limit(1);
      if (workflowStates.length > 0) {
        context.currentPhase = workflowStates[0].currentPhase || void 0;
      }
    }
    if (engagementId) {
      try {
        const burpScans = await dbInstance.select().from(burpScanHistory).where(eq(burpScanHistory.engagementId, parseInt(engagementId) || 0)).orderBy(desc(burpScanHistory.startedAt)).limit(1);
        if (burpScans.length > 0) {
          const scan = burpScans[0];
          const metadata = scan.metadata;
          context.burpScanResults = {
            scanId: scan.scanId,
            status: scan.status,
            targetUrls: Array.isArray(scan.targetUrls) ? scan.targetUrls : [],
            issueCount: scan.issueCount,
            importedCount: scan.importedCount,
            completedAt: scan.completedAt,
            edition: scan.edition,
            severityBreakdown: metadata?.severityBreakdown,
            escalatedCount: metadata?.escalatedCount,
            priorityFlaggedCount: metadata?.priorityFlaggedCount
          };
        }
      } catch (burpErr) {
        console.warn("[CampaignAdvisor] Burp scan query failed:", burpErr);
      }
    }
  } catch (err) {
    console.error("[CampaignAdvisor] Context gathering failed:", err);
  }
  return context;
}
function buildContextSummary(ctx) {
  const parts = [];
  if (ctx.engagementId) parts.push(`Engagement: ${ctx.engagementId}`);
  if (ctx.currentPhase) parts.push(`Current Phase: ${ctx.currentPhase}`);
  if (ctx.opsecScore !== void 0) parts.push(`Average OPSEC Risk Score: ${ctx.opsecScore}/100`);
  if (ctx.compromisedHosts?.length) parts.push(`Compromised Hosts: ${ctx.compromisedHosts.join(", ")}`);
  if (ctx.availableCredentials?.length) parts.push(`Available Credentials: ${ctx.availableCredentials.join(", ")}`);
  if (ctx.knownVulnerabilities?.length) {
    parts.push(`Known Vulnerabilities:
${ctx.knownVulnerabilities.map((v) => `  - ${v.cve} on ${v.host} (CVSS: ${v.cvss})`).join("\n")}`);
  }
  if (ctx.objectives?.length) parts.push(`Objectives: ${ctx.objectives.join(", ")}`);
  if (ctx.recentActions?.length) {
    const recent = ctx.recentActions.slice(0, 5);
    parts.push(`Recent Actions:
${recent.map((a) => `  - ${a.action} (${a.success ? "\u2713" : "\u2717"})`).join("\n")}`);
  }
  if (ctx.burpScanResults) {
    const b = ctx.burpScanResults;
    const burpParts = [
      `Status: ${b.status} | Edition: ${b.edition}`,
      `Targets: ${b.targetUrls.join(", ") || "none"}`,
      `Issues Found: ${b.issueCount} | Imported: ${b.importedCount}`
    ];
    if (b.severityBreakdown) {
      burpParts.push(`Severity Breakdown: ${Object.entries(b.severityBreakdown).map(([s, c]) => `${s}: ${c}`).join(", ")}`);
    }
    if (b.escalatedCount && b.escalatedCount > 0) {
      burpParts.push(`Cross-Tool Escalations: ${b.escalatedCount} findings escalated by ZAP+Burp correlation`);
    }
    if (b.priorityFlaggedCount && b.priorityFlaggedCount > 0) {
      burpParts.push(`Priority Exploitation Targets: ${b.priorityFlaggedCount} findings flagged`);
    }
    if (b.completedAt) {
      burpParts.push(`Completed: ${new Date(b.completedAt).toISOString()}`);
    }
    parts.push(`Burp Suite Scan Results:
${burpParts.map((p) => `  - ${p}`).join("\n")}`);
    if (ctx.burpDataFresh) {
      parts.push(`
\u26A1 FRESH BURP DATA: Burp scan just completed \u2014 factor these results into your recommendations.`);
    }
  }
  return parts.length > 0 ? `
## Current Engagement State
${parts.join("\n")}` : "\n## Current Engagement State\nNo engagement context available. Starting fresh.";
}
async function chatWithAdvisor(messages, context, engagementId) {
  const ctx = context || await gatherEngagementContext(engagementId);
  const contextSummary = buildContextSummary(ctx);
  const systemMessage = CAMPAIGN_ADVISOR_SYSTEM_PROMPT + contextSummary;
  const llmMessages = [
    { role: "system", content: systemMessage },
    ...messages.map((m) => ({ role: m.role, content: m.content }))
  ];
  const response = await invokeLLM({ _caller: "campaign-advisor.chatWithAdvisor", _priority: "bulk", messages: llmMessages });
  const content = response.choices?.[0]?.message?.content || "I'm unable to provide a recommendation at this time. Please try again.";
  return { response: content, context: ctx };
}
async function getQuickRecommendation(engagementId, specificQuestion) {
  const ctx = await gatherEngagementContext(engagementId);
  const question = specificQuestion || "Based on the current engagement state, what should I do next? Provide your top recommendation with OPSEC assessment and alternatives.";
  return chatWithAdvisor(
    [{ role: "user", content: question }],
    ctx,
    engagementId
  );
}
function getDeterministicAdvice(ctx) {
  const phase = ctx.currentPhase || "recon";
  const opsecScore = ctx.opsecScore || 0;
  const PHASE_ADVICE = {
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
        "Verify legal authorization and signed agreements"
      ],
      alternatives: [
        { action: "Start passive recon while finalizing paperwork", opsecRisk: 5, reasoning: "Low risk OSINT can begin early" }
      ],
      warnings: ["Never begin active testing without signed authorization"]
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
        "Identify technology stack via passive fingerprinting"
      ],
      alternatives: [
        { action: "Begin active DNS enumeration", opsecRisk: 15, reasoning: "More complete results but generates DNS logs" },
        { action: "Run Shodan/Censys queries", opsecRisk: 5, reasoning: "Uses cached scan data, no direct contact" }
      ],
      warnings: opsecScore > 30 ? ["OPSEC score is elevated \u2014 stick to passive techniques"] : []
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
        "Map the internal network topology from external perspective"
      ],
      alternatives: [
        { action: "Use ZAP for web app scanning", opsecRisk: 40, reasoning: "Deeper web vuln coverage but more noise" },
        { action: "Run Nuclei templates", opsecRisk: 30, reasoning: "Fast, targeted CVE checks" }
      ],
      warnings: opsecScore > 50 ? ["High OPSEC exposure \u2014 consider slowing scan rate and using decoy traffic"] : []
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
        "Establish initial foothold and verify access"
      ],
      alternatives: [
        { action: "Try credential stuffing with leaked creds", opsecRisk: 45, reasoning: "Lower noise than exploitation" },
        { action: "Launch targeted phishing campaign", opsecRisk: 50, reasoning: "Social engineering bypass for hardened targets" }
      ],
      warnings: ["Always have a rollback plan", "Capture all evidence before and after exploitation"]
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
        "Dump local credentials for lateral movement"
      ],
      alternatives: [
        { action: "Use living-off-the-land techniques only", opsecRisk: 30, reasoning: "No custom tools = harder to detect" }
      ],
      warnings: ["EDR may detect persistence mechanisms \u2014 test in sandbox first"]
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
        "Dump credentials from elevated context"
      ],
      alternatives: [
        { action: "Try Kerberoasting for service account hashes", opsecRisk: 35, reasoning: "Normal AD traffic, hard to detect" },
        { action: "Check for unquoted service paths", opsecRisk: 25, reasoning: "Simple check, low noise" }
      ],
      warnings: ctx.opsecScore && ctx.opsecScore > 60 ? ["Consider using LOLBins to avoid EDR triggers"] : []
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
        "Repeat enumeration on each new host"
      ],
      alternatives: [
        { action: "Use WinRM for Windows lateral movement", opsecRisk: 40, reasoning: "Legitimate admin protocol, less suspicious" },
        { action: "Use SSH for Linux lateral movement", opsecRisk: 35, reasoning: "Standard admin access, encrypted" }
      ],
      warnings: ["PsExec creates service on remote host \u2014 high detection risk", "Monitor for account lockouts"]
    },
    collection: {
      nextAction: "Collect target data and evidence",
      reasoning: "Gather the data that demonstrates impact \u2014 sensitive files, database dumps, email access.",
      phase: "collection",
      opsecRisk: 45,
      engine: "engagement-workflow",
      steps: [
        "Identify sensitive data locations",
        "Collect proof-of-access screenshots",
        "Extract sample data (not full dumps unless authorized)",
        "Document access paths and methods used",
        "Timestamp all evidence"
      ],
      alternatives: [
        { action: "Focus on crown jewels only", opsecRisk: 30, reasoning: "Minimal data touch = minimal risk" }
      ],
      warnings: ["Never exfiltrate real PII/PHI without explicit authorization"]
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
        "Clean up exfiltrated test data"
      ],
      alternatives: [
        { action: "Document theoretical exfil paths without executing", opsecRisk: 10, reasoning: "Zero risk, still demonstrates the gap" }
      ],
      warnings: ["DLP systems may alert on large transfers", "Use encrypted channels only"]
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
        "Prepare technical appendix with full attack chain"
      ],
      alternatives: [],
      warnings: ["Ensure all evidence is properly timestamped and attributed"]
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
        "Document any artifacts that couldn't be removed"
      ],
      alternatives: [],
      warnings: ["Coordinate cleanup timing with the client's blue team"]
    }
  };
  return PHASE_ADVICE[phase] || PHASE_ADVICE.recon;
}
var freshBurpData = /* @__PURE__ */ new Map();
function injectBurpCompletionContext(engagementId, burpData) {
  const key = String(engagementId);
  freshBurpData.set(key, burpData);
  console.log(`[CampaignAdvisor] Injected fresh Burp data for engagement #${key}: ${burpData.issueCount} issues, ${burpData.importedCount} imported`);
  setTimeout(() => freshBurpData.delete(key), 30 * 6e4);
}
async function gatherEngagementContextWithBurp(engagementId) {
  const ctx = await gatherEngagementContext(engagementId);
  if (engagementId && freshBurpData.has(engagementId)) {
    ctx.burpScanResults = freshBurpData.get(engagementId);
    ctx.burpDataFresh = true;
  }
  return ctx;
}
function registerBurpCompletionListener() {
  import("./burp-auto-scan-PJCWACEA.js").then(({ onBurpScanComplete }) => {
    onBurpScanComplete(async (config, state) => {
      injectBurpCompletionContext(config.engagementId, {
        scanId: state.scanId,
        status: state.status,
        targetUrls: state.targetUrls,
        issueCount: state.issueCount,
        importedCount: state.importedCount,
        completedAt: state.completedAt,
        edition: state.edition
      });
      console.log(
        `[CampaignAdvisor] Burp completion callback: engagement #${config.engagementId}, ${state.issueCount} issues, ${state.importedCount} imported \u2014 advisor context refreshed`
      );
    });
    console.log("[CampaignAdvisor] Registered Burp completion listener");
  }).catch((err) => {
    console.warn("[CampaignAdvisor] Failed to register Burp completion listener:", err.message);
  });
}

export {
  CAMPAIGN_ADVISOR_SYSTEM_PROMPT,
  gatherEngagementContext,
  buildContextSummary,
  chatWithAdvisor,
  getQuickRecommendation,
  getDeterministicAdvice,
  freshBurpData,
  injectBurpCompletionContext,
  gatherEngagementContextWithBurp,
  registerBurpCompletionListener
};
