import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-YKJATTT4.js";
import {
  buildAttackPlannerToolContext,
  init_offensive_tools_knowledge
} from "./chunk-SSYKZXNO.js";
import {
  buildMethodologyContext,
  buildScanPlanningContext,
  init_bugbounty_methodology_knowledge
} from "./chunk-WP62CKNZ.js";
import {
  getDb,
  init_db
} from "./chunk-JP5I5SRV.js";
import {
  aiAttackPlans,
  init_schema
} from "./chunk-FLBHZBVD.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/ai-attack-planner.ts
import { desc } from "drizzle-orm";
function filterByPlatform(techniques, platforms) {
  if (!platforms.length) return techniques;
  const normalizedPlatforms = platforms.map((p) => p.toLowerCase().replace(/\s+/g, ""));
  return techniques.filter(
    (t) => t.platforms.some((tp) => normalizedPlatforms.some(
      (np) => np.includes(tp) || tp.includes(np)
    ))
  );
}
function filterByStealth(techniques, stealthLevel) {
  const minStealth = stealthLevel === "high" ? 6 : stealthLevel === "medium" ? 3 : 0;
  return techniques.filter((t) => t.stealthScore >= minStealth);
}
function scoreThreatActorAlignment(techniques, actorKey) {
  return techniques.map((t) => {
    const actorMatch = t.threatActors.includes(actorKey) ? 3 : 0;
    return {
      ...t,
      relevanceScore: actorMatch,
      applicabilityScore: 0,
      compositeScore: 0
    };
  });
}
function scoreEnvironmentApplicability(techniques, env) {
  if (!env) return techniques;
  return techniques.map((t) => {
    let envScore = 0;
    if (env.adDomain && (t.prerequisites.includes("ad-domain") || t.name.includes("Domain") || t.name.includes("Kerber"))) {
      envScore += 2;
    }
    if (env.knownVulnerabilities?.length && t.id === "T1190") {
      envScore += 2.5;
    }
    if (env.securityTools?.length) {
      const toolLower = env.securityTools.map((s) => s.toLowerCase());
      if (toolLower.some((s) => s.includes("edr") || s.includes("crowdstrike") || s.includes("sentinel"))) {
        if (t.detectionRisk === "high") envScore -= 1.5;
      }
      if (toolLower.some((s) => s.includes("mfa") || s.includes("duo"))) {
        if (t.id === "T1078" || t.id === "T1110.003") envScore -= 2;
      }
    }
    if (env.cloudProviders?.length && t.platforms.includes("cloud")) {
      envScore += 1;
    }
    return {
      ...t,
      applicabilityScore: envScore,
      compositeScore: t.relevanceScore + envScore + t.stealthScore / 3
    };
  });
}
function prerequisitesSatisfied(technique, selectedTactics, hasAD) {
  for (const prereq of technique.prerequisites) {
    if (prereq === "ad-domain" && !hasAD) return false;
    if (prereq === "known-vulnerability") continue;
    if (prereq === "initial-access" && !selectedTactics.has("initial-access")) return false;
    if (prereq === "execution" && !selectedTactics.has("execution")) return false;
    if (prereq === "privilege-escalation" && !selectedTactics.has("privilege-escalation")) return false;
    if (prereq === "credential-access" && !selectedTactics.has("credential-access")) return false;
    if (prereq === "discovery" && !selectedTactics.has("discovery")) return false;
    if (prereq === "collection" && !selectedTactics.has("collection")) return false;
    if (prereq === "command-and-control" && !selectedTactics.has("command-and-control")) return false;
    if (prereq === "lateral-movement" && !selectedTactics.has("lateral-movement")) return false;
    if (prereq.startsWith("T") && !selectedTactics.has(prereq)) return false;
  }
  return true;
}
function buildGraphPlan(request, maxSteps) {
  let candidates = [...TECHNIQUE_GRAPH];
  const platforms = request.environmentContext?.operatingSystem || [];
  if (platforms.length) candidates = filterByPlatform(candidates, platforms);
  if (request.constraints?.stealthLevel) {
    candidates = filterByStealth(candidates, request.constraints.stealthLevel);
  }
  if (request.constraints?.avoidTechniques?.length) {
    const avoid = new Set(request.constraints.avoidTechniques.map((t) => t.toUpperCase()));
    candidates = candidates.filter((t) => !avoid.has(t.id.toUpperCase()));
  }
  const actorKey = request.threatActorProfile?.toLowerCase().replace(/[^a-z0-9]/g, "") || "";
  let scored = scoreThreatActorAlignment(candidates, actorKey);
  scored = scoreEnvironmentApplicability(scored, request.environmentContext);
  const selectedTechniques = [];
  const selectedTactics = /* @__PURE__ */ new Set();
  const selectedIds = /* @__PURE__ */ new Set();
  const hasAD = request.environmentContext?.adDomain || false;
  const tacticGroups = /* @__PURE__ */ new Map();
  for (const t of scored) {
    const group = tacticGroups.get(t.tactic) || [];
    group.push(t);
    tacticGroups.set(t.tactic, group);
  }
  const sortedTactics = Array.from(tacticGroups.entries()).sort(([, a], [, b]) => (a[0]?.tacticOrder || 0) - (b[0]?.tacticOrder || 0));
  for (const [tactic, techniques] of sortedTactics) {
    if (selectedTechniques.length >= maxSteps) break;
    const eligible = techniques.filter((t) => !selectedIds.has(t.id) && prerequisitesSatisfied(t, selectedTactics, hasAD)).sort((a, b) => b.compositeScore - a.compositeScore);
    const toSelect = tactic === "initial-access" || tactic === "defense-evasion" ? 2 : 1;
    for (let i = 0; i < Math.min(toSelect, eligible.length); i++) {
      if (selectedTechniques.length >= maxSteps) break;
      selectedTechniques.push(eligible[i]);
      selectedTactics.add(tactic);
      selectedIds.add(eligible[i].id);
    }
  }
  const phaseMap = /* @__PURE__ */ new Map();
  for (const t of selectedTechniques) {
    const group = phaseMap.get(t.tactic) || [];
    group.push(t);
    phaseMap.set(t.tactic, group);
  }
  const phases = [];
  let stepOrder = 1;
  for (const [tactic, techniques] of Array.from(phaseMap.entries()).sort(
    ([, a], [, b]) => (a[0]?.tacticOrder || 0) - (b[0]?.tacticOrder || 0)
  )) {
    const phaseName = tactic.split("-").map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
    phases.push({
      name: phaseName,
      objective: `Achieve ${phaseName.toLowerCase()} objectives using selected techniques`,
      steps: techniques.map((t) => ({
        order: stepOrder++,
        phase: t.tactic,
        techniqueId: t.id,
        techniqueName: t.name,
        tactic: phaseName,
        description: t.description,
        prerequisites: t.prerequisites,
        expectedOutcome: `Successful ${t.name.toLowerCase()} enabling next phase`,
        detectionRisk: t.detectionRisk,
        tools: t.tools,
        mitigations: t.mitigations
      }))
    });
  }
  return { selectedTechniques, phases };
}
async function generateAttackPlan(request, invokeLLM) {
  const maxSteps = request.constraints?.maxSteps || 12;
  const { selectedTechniques, phases } = buildGraphPlan(request, maxSteps);
  if (phases.length === 0) {
    throw new Error("No applicable techniques found for the given environment and constraints");
  }
  const skeleton = {
    name: `Attack Plan for ${request.targetDescription.slice(0, 50)}`,
    summary: `Graph-generated plan with ${selectedTechniques.length} techniques across ${phases.length} phases`,
    threatActorEmulated: request.threatActorProfile || "Generic Advanced Persistent Threat",
    estimatedRiskScore: Math.round(selectedTechniques.reduce((sum, t) => sum + t.compositeScore, 0) / selectedTechniques.length * 2),
    phases,
    totalSteps: selectedTechniques.length,
    estimatedDuration: selectedTechniques.length <= 5 ? "1-2 days" : selectedTechniques.length <= 10 ? "1-2 weeks" : "2-4 weeks",
    detectionOpportunities: [],
    recommendations: []
  };
  try {
    const toolsContext = buildAttackPlannerToolContext();
    const methodologyCtx = buildMethodologyContext();
    const scanPlanCtx = buildScanPlanningContext(void 0, "exploitation");
    const userPrompt = `Enrich this attack plan skeleton for the following target:

**Target:** ${request.targetDescription}
${request.threatActorProfile ? `**Threat Actor:** ${request.threatActorProfile}` : ""}
${request.environmentContext ? `**Environment:** ${JSON.stringify(request.environmentContext, null, 2)}` : ""}

${toolsContext}

${methodologyCtx ? `=== ATTACK METHODOLOGY KNOWLEDGE ===
${methodologyCtx.slice(0, 3e3)}
` : ""}
${scanPlanCtx ? `=== SCAN PLANNING CONTEXT ===
${scanPlanCtx.slice(0, 2e3)}
` : ""}

**Plan Skeleton:**
${JSON.stringify(skeleton, null, 2)}`;
    const response = await throttledLLMCall({
      _priority: "essential",
      messages: [
        { role: "system", content: ATTACK_PLANNING_SYSTEM_PROMPT },
        { role: "user", content: userPrompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "attack_plan",
          strict: true,
          schema: {
            type: "object",
            properties: {
              name: { type: "string" },
              summary: { type: "string" },
              threatActorEmulated: { type: "string" },
              estimatedRiskScore: { type: "number" },
              phases: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    objective: { type: "string" },
                    steps: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          order: { type: "number" },
                          phase: { type: "string" },
                          techniqueId: { type: "string" },
                          techniqueName: { type: "string" },
                          tactic: { type: "string" },
                          description: { type: "string" },
                          prerequisites: { type: "array", items: { type: "string" } },
                          expectedOutcome: { type: "string" },
                          detectionRisk: { type: "string" },
                          tools: { type: "array", items: { type: "string" } },
                          mitigations: { type: "array", items: { type: "string" } }
                        },
                        required: ["order", "phase", "techniqueId", "techniqueName", "tactic", "description", "prerequisites", "expectedOutcome", "detectionRisk", "tools", "mitigations"],
                        additionalProperties: false
                      }
                    }
                  },
                  required: ["name", "objective", "steps"],
                  additionalProperties: false
                }
              },
              totalSteps: { type: "number" },
              estimatedDuration: { type: "string" },
              detectionOpportunities: { type: "array", items: { type: "string" } },
              recommendations: { type: "array", items: { type: "string" } }
            },
            required: ["name", "summary", "threatActorEmulated", "estimatedRiskScore", "phases", "totalSteps", "estimatedDuration", "detectionOpportunities", "recommendations"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (content) {
      const enrichedPlan = JSON.parse(content);
      await persistPlan(request, enrichedPlan);
      return enrichedPlan;
    }
  } catch (err) {
    console.error("[AttackPlanner] LLM enrichment failed, returning graph-only plan:", err);
  }
  skeleton.detectionOpportunities = selectedTechniques.filter((t) => t.detectionRisk !== "low").map((t) => `Monitor for ${t.name} (${t.id}) \u2014 detection risk: ${t.detectionRisk}`);
  skeleton.recommendations = selectedTechniques.flatMap((t) => t.mitigations).filter((m, i, arr) => arr.indexOf(m) === i).slice(0, 10);
  await persistPlan(request, skeleton);
  return skeleton;
}
function generateGraphOnlyPlan(request) {
  const maxSteps = request.constraints?.maxSteps || 12;
  const { selectedTechniques, phases } = buildGraphPlan(request, maxSteps);
  if (phases.length === 0) {
    throw new Error("No applicable techniques found for the given environment and constraints");
  }
  return {
    name: `Attack Plan for ${request.targetDescription.slice(0, 50)}`,
    summary: `Deterministic graph-generated plan with ${selectedTechniques.length} techniques across ${phases.length} phases, ordered by MITRE ATT&CK kill chain.`,
    threatActorEmulated: request.threatActorProfile || "Generic Advanced Persistent Threat",
    estimatedRiskScore: Math.min(10, Math.max(1, Math.round(selectedTechniques.reduce((sum, t) => sum + t.compositeScore, 0) / selectedTechniques.length * 2))),
    phases,
    totalSteps: selectedTechniques.length,
    estimatedDuration: selectedTechniques.length <= 5 ? "1-2 days" : selectedTechniques.length <= 10 ? "1-2 weeks" : "2-4 weeks",
    detectionOpportunities: selectedTechniques.filter((t) => t.detectionRisk !== "low").map((t) => `Monitor for ${t.name} (${t.id}) \u2014 detection risk: ${t.detectionRisk}`),
    recommendations: selectedTechniques.flatMap((t) => t.mitigations).filter((m, i, arr) => arr.indexOf(m) === i).slice(0, 10)
  };
}
async function persistPlan(request, plan) {
  const db = await getDb();
  if (!db) return;
  try {
    await db.insert(aiAttackPlans).values({
      name: plan.name,
      targetDescription: request.targetDescription,
      threatActorProfile: plan.threatActorEmulated,
      generatedPlan: plan,
      attackSteps: plan.phases,
      estimatedRiskScore: plan.estimatedRiskScore,
      status: "ready"
    });
  } catch (err) {
    console.error("[AttackPlanner] DB persist failed:", err);
  }
}
async function getAttackPlanHistory(limit = 20) {
  const db = await getDb();
  if (!db) return [];
  try {
    return await db.select().from(aiAttackPlans).orderBy(desc(aiAttackPlans.createdAt)).limit(limit);
  } catch (err) {
    console.error("[AttackPlanner] DB history query failed:", err);
    return [];
  }
}
var TECHNIQUE_GRAPH, ATTACK_PLANNING_SYSTEM_PROMPT, THREAT_ACTOR_PROFILES;
var init_ai_attack_planner = __esm({
  "server/lib/ai-attack-planner.ts"() {
    init_db();
    init_schema();
    init_offensive_tools_knowledge();
    init_bugbounty_methodology_knowledge();
    init_llm_throttle();
    TECHNIQUE_GRAPH = [
      // Initial Access
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "initial-access", tacticOrder: 2, description: "Send malicious email attachment to gain initial foothold", platforms: ["windows", "linux", "macos"], prerequisites: [], detectionRisk: "medium", tools: ["custom-mailer", "gophish"], mitigations: ["Email filtering", "User training", "Attachment sandboxing"], stealthScore: 5, threatActors: ["apt29", "apt28", "fin7", "lazarus"] },
      { id: "T1566.002", name: "Spearphishing Link", tactic: "initial-access", tacticOrder: 2, description: "Send email with malicious link to credential harvesting or exploit page", platforms: ["windows", "linux", "macos"], prerequisites: [], detectionRisk: "medium", tools: ["gophish", "evilginx2"], mitigations: ["URL filtering", "User training", "MFA"], stealthScore: 6, threatActors: ["apt28", "apt29", "lazarus"] },
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access", tacticOrder: 2, description: "Exploit vulnerability in internet-facing application", platforms: ["windows", "linux"], prerequisites: ["known-vulnerability"], detectionRisk: "low", tools: ["metasploit", "nuclei", "custom-exploit"], mitigations: ["Patching", "WAF", "Network segmentation"], stealthScore: 4, threatActors: ["apt41", "lazarus", "apt28"] },
      { id: "T1078", name: "Valid Accounts", tactic: "initial-access", tacticOrder: 2, description: "Use compromised credentials for initial access", platforms: ["windows", "linux", "macos", "cloud"], prerequisites: ["credential-access"], detectionRisk: "low", tools: ["hydra", "spray"], mitigations: ["MFA", "Account monitoring", "Password policy"], stealthScore: 8, threatActors: ["apt29", "apt28", "fin7"] },
      { id: "T1195.002", name: "Supply Chain Compromise: Software Supply Chain", tactic: "initial-access", tacticOrder: 2, description: "Compromise software supply chain to distribute malware", platforms: ["windows", "linux", "macos"], prerequisites: [], detectionRisk: "low", tools: ["custom-implant"], mitigations: ["Software verification", "SBOM", "Code signing"], stealthScore: 9, threatActors: ["apt29", "apt41"] },
      // Execution
      { id: "T1059.001", name: "PowerShell", tactic: "execution", tacticOrder: 3, description: "Execute commands via PowerShell", platforms: ["windows"], prerequisites: ["initial-access"], detectionRisk: "medium", tools: ["powershell"], mitigations: ["Script block logging", "Constrained language mode", "AMSI"], stealthScore: 4, threatActors: ["apt29", "apt28", "fin7", "conti"] },
      { id: "T1059.004", name: "Unix Shell", tactic: "execution", tacticOrder: 3, description: "Execute commands via bash/sh", platforms: ["linux", "macos"], prerequisites: ["initial-access"], detectionRisk: "medium", tools: ["bash", "sh"], mitigations: ["Auditd", "Command logging"], stealthScore: 5, threatActors: ["apt41", "lazarus"] },
      { id: "T1204.002", name: "Malicious File", tactic: "execution", tacticOrder: 3, description: "User executes malicious file delivered via phishing", platforms: ["windows", "linux", "macos"], prerequisites: ["T1566.001"], detectionRisk: "medium", tools: ["macro-pack", "custom-dropper"], mitigations: ["Application whitelisting", "AV/EDR"], stealthScore: 3, threatActors: ["fin7", "lazarus", "apt28"] },
      // Persistence
      { id: "T1053.005", name: "Scheduled Task", tactic: "persistence", tacticOrder: 4, description: "Create scheduled task for persistence", platforms: ["windows"], prerequisites: ["execution"], detectionRisk: "medium", tools: ["schtasks"], mitigations: ["Task auditing", "Least privilege"], stealthScore: 5, threatActors: ["apt29", "conti", "fin7"] },
      { id: "T1136.001", name: "Local Account", tactic: "persistence", tacticOrder: 4, description: "Create local account for persistent access", platforms: ["windows", "linux", "macos"], prerequisites: ["privilege-escalation"], detectionRisk: "high", tools: ["net-user", "useradd"], mitigations: ["Account auditing", "Baseline monitoring"], stealthScore: 2, threatActors: ["conti", "alphv"] },
      { id: "T1543.003", name: "Windows Service", tactic: "persistence", tacticOrder: 4, description: "Install malicious Windows service", platforms: ["windows"], prerequisites: ["privilege-escalation"], detectionRisk: "medium", tools: ["sc.exe", "custom-service"], mitigations: ["Service auditing", "Application whitelisting"], stealthScore: 5, threatActors: ["apt29", "apt28"] },
      // Privilege Escalation
      { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "privilege-escalation", tacticOrder: 5, description: "Exploit software vulnerability for elevated privileges", platforms: ["windows", "linux", "macos"], prerequisites: ["execution"], detectionRisk: "low", tools: ["metasploit", "custom-exploit"], mitigations: ["Patching", "Exploit protection"], stealthScore: 4, threatActors: ["apt28", "apt41", "lazarus"] },
      { id: "T1548.002", name: "Bypass User Account Control", tactic: "privilege-escalation", tacticOrder: 5, description: "Bypass Windows UAC to elevate privileges", platforms: ["windows"], prerequisites: ["execution"], detectionRisk: "medium", tools: ["uacme", "fodhelper"], mitigations: ["UAC to highest level", "Admin approval mode"], stealthScore: 6, threatActors: ["apt29", "conti"] },
      // Defense Evasion
      { id: "T1027", name: "Obfuscated Files or Information", tactic: "defense-evasion", tacticOrder: 6, description: "Obfuscate payloads to evade detection", platforms: ["windows", "linux", "macos"], prerequisites: ["execution"], detectionRisk: "low", tools: ["confuserex", "pyarmor", "custom-packer"], mitigations: ["Behavioral detection", "Sandbox analysis"], stealthScore: 7, threatActors: ["apt29", "apt41", "lazarus", "fin7"] },
      { id: "T1070.004", name: "File Deletion", tactic: "defense-evasion", tacticOrder: 6, description: "Delete artifacts to cover tracks", platforms: ["windows", "linux", "macos"], prerequisites: ["execution"], detectionRisk: "low", tools: ["del", "rm", "sdelete"], mitigations: ["File integrity monitoring", "Backup logging"], stealthScore: 7, threatActors: ["apt29", "apt28", "lazarus"] },
      { id: "T1562.001", name: "Disable or Modify Tools", tactic: "defense-evasion", tacticOrder: 6, description: "Disable security tools (AV, EDR, logging)", platforms: ["windows", "linux"], prerequisites: ["privilege-escalation"], detectionRisk: "high", tools: ["custom-script"], mitigations: ["Tamper protection", "Centralized logging"], stealthScore: 3, threatActors: ["conti", "alphv"] },
      // Credential Access
      { id: "T1003.001", name: "LSASS Memory", tactic: "credential-access", tacticOrder: 7, description: "Dump credentials from LSASS process memory", platforms: ["windows"], prerequisites: ["privilege-escalation"], detectionRisk: "high", tools: ["mimikatz", "procdump", "comsvcs.dll"], mitigations: ["Credential Guard", "LSA protection", "EDR"], stealthScore: 3, threatActors: ["apt29", "apt28", "conti", "fin7"] },
      { id: "T1558.003", name: "Kerberoasting", tactic: "credential-access", tacticOrder: 7, description: "Request service tickets and crack offline", platforms: ["windows"], prerequisites: ["initial-access", "ad-domain"], detectionRisk: "medium", tools: ["rubeus", "impacket"], mitigations: ["Strong service account passwords", "AES encryption", "Monitoring"], stealthScore: 6, threatActors: ["apt29", "conti", "fin7"] },
      { id: "T1110.003", name: "Password Spraying", tactic: "credential-access", tacticOrder: 7, description: "Try common passwords against many accounts", platforms: ["windows", "linux", "cloud"], prerequisites: [], detectionRisk: "medium", tools: ["spray", "ruler", "o365spray"], mitigations: ["Account lockout", "MFA", "Monitoring"], stealthScore: 5, threatActors: ["apt28", "apt29"] },
      // Discovery
      { id: "T1087.002", name: "Domain Account Discovery", tactic: "discovery", tacticOrder: 8, description: "Enumerate domain accounts and groups", platforms: ["windows"], prerequisites: ["initial-access", "ad-domain"], detectionRisk: "low", tools: ["net.exe", "bloodhound", "adfind"], mitigations: ["Audit logging", "Least privilege"], stealthScore: 6, threatActors: ["apt29", "apt28", "conti", "fin7"] },
      { id: "T1046", name: "Network Service Discovery", tactic: "discovery", tacticOrder: 8, description: "Scan for network services and open ports", platforms: ["windows", "linux", "macos"], prerequisites: ["initial-access"], detectionRisk: "medium", tools: ["scanforge-discovery", "masscan"], mitigations: ["Network segmentation", "IDS"], stealthScore: 4, threatActors: ["apt41", "lazarus", "conti"] },
      // Lateral Movement
      { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "lateral-movement", tacticOrder: 9, description: "Move laterally via SMB admin shares", platforms: ["windows"], prerequisites: ["credential-access", "ad-domain"], detectionRisk: "medium", tools: ["psexec", "smbclient", "impacket"], mitigations: ["Disable admin shares", "Network segmentation", "EDR"], stealthScore: 4, threatActors: ["apt29", "conti", "fin7"] },
      { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "lateral-movement", tacticOrder: 9, description: "Use RDP for lateral movement", platforms: ["windows"], prerequisites: ["credential-access"], detectionRisk: "medium", tools: ["mstsc", "xfreerdp"], mitigations: ["NLA", "MFA", "Network segmentation"], stealthScore: 5, threatActors: ["conti", "alphv", "fin7"] },
      { id: "T1021.006", name: "Windows Remote Management", tactic: "lateral-movement", tacticOrder: 9, description: "Use WinRM/PSRemoting for lateral movement", platforms: ["windows"], prerequisites: ["credential-access"], detectionRisk: "low", tools: ["winrm", "evil-winrm"], mitigations: ["Disable WinRM", "Network segmentation"], stealthScore: 6, threatActors: ["apt29", "apt28"] },
      // Collection
      { id: "T1560.001", name: "Archive via Utility", tactic: "collection", tacticOrder: 10, description: "Compress collected data before exfiltration", platforms: ["windows", "linux", "macos"], prerequisites: ["discovery"], detectionRisk: "low", tools: ["7zip", "tar", "rar"], mitigations: ["DLP", "File monitoring"], stealthScore: 6, threatActors: ["apt29", "apt41", "lazarus"] },
      // C2
      { id: "T1071.001", name: "Web Protocols", tactic: "command-and-control", tacticOrder: 11, description: "Use HTTP/HTTPS for C2 communication", platforms: ["windows", "linux", "macos"], prerequisites: ["execution"], detectionRisk: "low", tools: ["cobalt-strike", "sliver", "covenant"], mitigations: ["SSL inspection", "Domain reputation", "Network monitoring"], stealthScore: 7, threatActors: ["apt29", "apt28", "fin7", "conti"] },
      { id: "T1572", name: "Protocol Tunneling", tactic: "command-and-control", tacticOrder: 11, description: "Tunnel C2 traffic through legitimate protocols", platforms: ["windows", "linux", "macos"], prerequisites: ["execution"], detectionRisk: "low", tools: ["dnscat2", "iodine", "chisel"], mitigations: ["DNS monitoring", "Protocol analysis"], stealthScore: 8, threatActors: ["apt29", "apt41"] },
      // Exfiltration
      { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "exfiltration", tacticOrder: 12, description: "Exfiltrate data over existing C2 channel", platforms: ["windows", "linux", "macos"], prerequisites: ["collection", "command-and-control"], detectionRisk: "medium", tools: ["cobalt-strike", "custom-exfil"], mitigations: ["DLP", "Network monitoring", "Egress filtering"], stealthScore: 6, threatActors: ["apt29", "apt41", "lazarus"] },
      { id: "T1567.002", name: "Exfiltration to Cloud Storage", tactic: "exfiltration", tacticOrder: 12, description: "Upload stolen data to cloud storage services", platforms: ["windows", "linux", "macos"], prerequisites: ["collection"], detectionRisk: "low", tools: ["rclone", "megacmd"], mitigations: ["Cloud access monitoring", "DLP", "Egress filtering"], stealthScore: 7, threatActors: ["conti", "alphv", "apt29"] },
      // Impact
      { id: "T1486", name: "Data Encrypted for Impact", tactic: "impact", tacticOrder: 13, description: "Encrypt data for ransomware/destruction", platforms: ["windows", "linux"], prerequisites: ["privilege-escalation", "lateral-movement"], detectionRisk: "high", tools: ["custom-ransomware"], mitigations: ["Backups", "EDR", "Network segmentation"], stealthScore: 1, threatActors: ["conti", "alphv", "lazarus"] },
      { id: "T1531", name: "Account Access Removal", tactic: "impact", tacticOrder: 13, description: "Remove account access to disrupt operations", platforms: ["windows", "linux", "cloud"], prerequisites: ["privilege-escalation"], detectionRisk: "high", tools: ["custom-script"], mitigations: ["Account backup", "MFA", "Monitoring"], stealthScore: 2, threatActors: ["lazarus", "alphv"] }
    ];
    ATTACK_PLANNING_SYSTEM_PROMPT = `You are an expert red team attack planner. You will be given a pre-computed attack plan skeleton based on MITRE ATT&CK graph analysis. Your job is to ENRICH this plan with:

1. A descriptive name and executive summary
2. Detailed, realistic step descriptions tailored to the specific target environment
3. Phase objectives that explain the strategic reasoning
4. Detection opportunities for the blue team
5. Defensive recommendations

Your response MUST be valid JSON matching this schema:
{
  "name": "string - descriptive name for the attack plan",
  "summary": "string - 2-3 sentence executive summary",
  "threatActorEmulated": "string - the threat actor being emulated",
  "estimatedRiskScore": "number 1-10",
  "phases": [
    {
      "name": "string - phase name",
      "objective": "string - enriched strategic objective",
      "steps": [
        {
          "order": "number",
          "phase": "string - ATT&CK tactic",
          "techniqueId": "string - e.g., T1566.001",
          "techniqueName": "string",
          "tactic": "string",
          "description": "string - ENRICHED detailed step description for this specific environment",
          "prerequisites": ["string array"],
          "expectedOutcome": "string - ENRICHED expected outcome",
          "detectionRisk": "low|medium|high",
          "tools": ["string array"],
          "mitigations": ["string array"]
        }
      ]
    }
  ],
  "totalSteps": "number",
  "estimatedDuration": "string - e.g., 2-3 weeks",
  "detectionOpportunities": ["string array - where blue team can detect"],
  "recommendations": ["string array - defensive recommendations"]
}

## Living Off the Land Knowledge
When enriching exploitation and post-exploitation steps, prefer Living Off The Land (LOTL) techniques:
- **Windows:** Reference LOLBAS binaries (certutil, mshta, regsvr32, rundll32, wmic) for execution, persistence, and defense evasion
- **Linux:** Reference GTFOBins (curl, wget, python, perl, awk, find) for privilege escalation and file exfiltration
- **macOS:** Reference LOOBins for native binary abuse
- **DLL Hijacking:** Reference HijackLibs for persistence via DLL search order hijacking
- **Driver Abuse:** Reference LOLDrivers for kernel-level EDR/AV bypass
- **Legitimate Domain Abuse:** Reference LOTS Project for C2 and exfiltration via trusted domains (GitHub, Slack, Discord, Cloudflare Workers)

## Evasion Techniques
- For firewall/WAF bypass: packet fragmentation, timing evasion, DNS/HTTP tunneling, encrypted payloads
- For AV/EDR bypass: LOTL binaries, process injection via legitimate APIs (MalAPI.io), driver-level bypass
- Always include detection opportunities for each evasion technique used

## CARVER+Shock Target Prioritization
When analyzing targets, apply the CARVER+Shock scoring model to prioritize attack paths:
- **Criticality:** Business importance of the target system (1-10)
- **Accessibility:** Exposure level and ease of reaching the target (1-10)
- **Recuperability:** Target's ability to recover from attack (1-10, lower = harder to recover = higher priority)
- **Vulnerability:** Known exploitability of the target (1-10)
- **Effect:** Operational impact if compromised (1-10)
- **Recognizability:** How visible/identifiable the target is to attackers (1-10)
- **Shock:** Reputational and psychological impact of compromise (1-10)
Include a CARVER+Shock composite score (sum of all 7 factors) in the plan summary for each major target.

## Strategic Planning Framework
Follow this strategic planning model when building attack plans:
1. Identify critical business functions of the target organization
2. Map supporting systems and infrastructure dependencies
3. Identify crown jewels (highest-value data/systems)
4. Map likely threat actors and their TTPs
5. Build attack scenarios that chain techniques toward crown jewels

## Tactical Execution Phases
Each phase in the attack plan must define:
- **Goal:** Clear objective for this phase
- **Method:** Specific techniques and tools to be used
- **Evidence of success:** Observable indicators that the phase objective was achieved
Phases follow the red team kill chain: Reconnaissance \u2192 Initial Access \u2192 Privilege Escalation \u2192 Lateral Movement \u2192 Objective Execution

IMPORTANT: Keep the same techniqueId, techniqueName, and order from the skeleton. Only enrich descriptions, objectives, outcomes, and add detection/recommendations.`;
    THREAT_ACTOR_PROFILES = {
      apt29: "APT29 (Cozy Bear / The Dukes) - Russian SVR-linked group. Known for spearphishing, supply chain attacks, cloud exploitation, and long-term persistence. Uses custom malware and living-off-the-land techniques.",
      apt28: "APT28 (Fancy Bear / Sofacy) - Russian GRU Unit 26165. Known for credential harvesting, zero-day exploitation, and destructive operations. Uses X-Agent, Zebrocy, and OAuth token theft.",
      apt41: "APT41 (Winnti / Double Dragon) - Chinese state-sponsored group. Dual espionage and financial crime. Known for supply chain compromise, rootkits, and extensive use of publicly available tools.",
      lazarus: "Lazarus Group (Hidden Cobra) - North Korean RGB-linked. Known for destructive attacks, cryptocurrency theft, and social engineering. Uses custom malware families and watering hole attacks.",
      fin7: "FIN7 (Carbanak) - Financially motivated group. Known for spearphishing with malicious documents, POS malware, and Cobalt Strike. Targets retail, hospitality, and financial sectors.",
      conti: "Conti Ransomware Group - Known for double extortion, BazarLoader initial access, Cobalt Strike for lateral movement, and rapid encryption. Targets healthcare, manufacturing, and government.",
      alphv: "ALPHV/BlackCat - Ransomware-as-a-Service. Uses Rust-based ransomware, triple extortion, and targets ESXi/Linux. Known for data leak sites and affiliate model."
    };
  }
});

export {
  generateAttackPlan,
  generateGraphOnlyPlan,
  getAttackPlanHistory,
  THREAT_ACTOR_PROFILES,
  init_ai_attack_planner
};
