// server/lib/opsec-risk-engine.ts
var DETECTION_TECHNOLOGIES = [
  {
    id: "crowdstrike",
    name: "CrowdStrike Falcon",
    category: "edr",
    vendor: "CrowdStrike",
    detectionCapabilities: [
      "Process injection detection",
      "Credential dumping (LSASS access)",
      "Lateral movement via SMB",
      "PowerShell script block logging",
      "Fileless malware detection",
      "Behavioral IOAs",
      "Kernel-level monitoring",
      "Memory scanning"
    ],
    bypassDifficulty: 9,
    commonRules: ["LSASS memory access", "Suspicious PowerShell", "Service creation", "Named pipe impersonation", "Process hollowing"]
  },
  {
    id: "defender_atp",
    name: "Microsoft Defender for Endpoint",
    category: "edr",
    vendor: "Microsoft",
    detectionCapabilities: [
      "AMSI integration",
      "Attack surface reduction rules",
      "Tamper protection",
      "Network protection",
      "Controlled folder access",
      "Credential guard integration"
    ],
    bypassDifficulty: 7,
    commonRules: ["AMSI bypass attempts", "ASR rule violations", "Suspicious WMI activity", "Credential theft indicators"]
  },
  {
    id: "sentinel_one",
    name: "SentinelOne",
    category: "edr",
    vendor: "SentinelOne",
    detectionCapabilities: [
      "Static AI analysis",
      "Behavioral AI",
      "Rollback capability",
      "Fileless attack detection",
      "Lateral movement detection"
    ],
    bypassDifficulty: 8,
    commonRules: ["AI-detected anomalies", "Ransomware behavior", "Exploit detection", "Suspicious script execution"]
  },
  {
    id: "splunk",
    name: "Splunk Enterprise Security",
    category: "siem",
    vendor: "Splunk",
    detectionCapabilities: [
      "Log correlation",
      "Sigma rule matching",
      "MITRE ATT&CK mapping",
      "User behavior analytics",
      "Threat intelligence matching"
    ],
    bypassDifficulty: 6,
    commonRules: ["Brute force detection", "Anomalous login patterns", "Privilege escalation indicators", "Data exfiltration patterns"]
  },
  {
    id: "elastic_security",
    name: "Elastic Security",
    category: "siem",
    vendor: "Elastic",
    detectionCapabilities: [
      "EQL detection rules",
      "Machine learning anomaly detection",
      "Endpoint telemetry",
      "Network flow analysis"
    ],
    bypassDifficulty: 6,
    commonRules: ["Process anomalies", "Network beaconing", "Credential access patterns", "Lateral movement indicators"]
  },
  {
    id: "zeek",
    name: "Zeek (Bro) NDR",
    category: "ndr",
    vendor: "Zeek Project",
    detectionCapabilities: [
      "Network protocol analysis",
      "DNS tunneling detection",
      "SSL/TLS inspection",
      "HTTP anomaly detection",
      "File extraction from network streams"
    ],
    bypassDifficulty: 5,
    commonRules: ["DNS exfiltration", "Beaconing patterns", "Unusual protocol usage", "Certificate anomalies"]
  }
];
var ACTION_RISK_PROFILES = {
  // Reconnaissance
  port_scan: { category: "reconnaissance", baseRisk: 4, description: "Network port scanning", commonDetections: ["IDS/IPS alerts", "Firewall logs", "NDR anomaly"], mitigations: ["Slow scan rate", "Distributed scanning", "Use legitimate services"] },
  service_enum: { category: "reconnaissance", baseRisk: 3, description: "Service enumeration and banner grabbing", commonDetections: ["Service logs", "WAF alerts"], mitigations: ["Passive fingerprinting first", "Rate limiting"] },
  dns_enum: { category: "reconnaissance", baseRisk: 2, description: "DNS enumeration and zone transfer attempts", commonDetections: ["DNS query logs", "Zone transfer alerts"], mitigations: ["Passive DNS sources", "Distributed resolvers"] },
  web_crawl: { category: "reconnaissance", baseRisk: 3, description: "Web application crawling and spidering", commonDetections: ["WAF alerts", "Rate limiting triggers", "Bot detection"], mitigations: ["Respect robots.txt", "Randomize user agents", "Slow crawl rate"] },
  // Exploitation
  exploit_attempt: { category: "exploitation", baseRisk: 8, description: "Active exploitation of vulnerability", commonDetections: ["IDS/IPS signatures", "EDR behavioral detection", "WAF rules"], mitigations: ["Use encrypted payloads", "Obfuscate exploit traffic", "Test in lab first"] },
  brute_force: { category: "credential_access", baseRisk: 7, description: "Credential brute force or spray attack", commonDetections: ["Account lockout alerts", "SIEM correlation", "Failed login monitoring"], mitigations: ["Low and slow approach", "Spray across many accounts", "Respect lockout thresholds"] },
  phishing_send: { category: "initial_access", baseRisk: 6, description: "Sending phishing emails", commonDetections: ["Email gateway alerts", "SPF/DKIM/DMARC failures", "User reports"], mitigations: ["Proper email infrastructure", "Domain aging", "Targeted recipients"] },
  // Post-Exploitation
  credential_dump: { category: "credential_access", baseRisk: 9, description: "Dumping credentials from memory or files", commonDetections: ["LSASS access alerts", "EDR memory scanning", "Sysmon events"], mitigations: ["Use in-memory techniques", "Avoid touching LSASS directly", "Use comsvcs.dll minidump"] },
  lateral_movement: { category: "lateral_movement", baseRisk: 7, description: "Moving to another host in the network", commonDetections: ["SMB lateral movement", "WinRM connections", "Unusual authentication"], mitigations: ["Use WinRM over PsExec", "Blend with admin activity", "Use Kerberos auth"] },
  persistence: { category: "persistence", baseRisk: 6, description: "Establishing persistence mechanism", commonDetections: ["Registry modification", "Scheduled task creation", "Service installation"], mitigations: ["Use legitimate mechanisms", "Avoid common persistence locations", "Use memory-only persistence"] },
  data_exfil: { category: "exfiltration", baseRisk: 8, description: "Exfiltrating data from target network", commonDetections: ["DLP alerts", "Unusual data transfers", "DNS tunneling detection"], mitigations: ["Encrypt data", "Use legitimate channels", "Small data chunks"] },
  privesc_attempt: { category: "privilege_escalation", baseRisk: 7, description: "Attempting privilege escalation", commonDetections: ["EDR behavioral alerts", "Sysmon process creation", "Token manipulation"], mitigations: ["Use LOLBins", "Avoid kernel exploits", "Use legitimate admin tools"] },
  // C2
  c2_callback: { category: "command_control", baseRisk: 5, description: "C2 beacon callback", commonDetections: ["Beaconing detection", "JA3/JA3S fingerprinting", "Domain reputation"], mitigations: ["Jitter on callbacks", "Domain fronting", "Legitimate-looking traffic profiles"] },
  c2_data_transfer: { category: "command_control", baseRisk: 6, description: "Transferring data over C2 channel", commonDetections: ["Data volume anomaly", "Protocol anomaly", "Encrypted traffic analysis"], mitigations: ["Chunk data transfers", "Use HTTPS", "Blend with normal traffic"] }
};
var BURN_INDICATORS = [
  { id: "account_lockout", name: "Account Lockout Triggered", severity: "high", description: "Target account has been locked out, indicating detection of brute force.", evidence: ["Account lockout event", "Multiple failed logins"], recommendedAction: "Stop credential attacks immediately. Switch to different accounts or techniques." },
  { id: "c2_blocked", name: "C2 Channel Blocked", severity: "critical", description: "C2 callbacks are failing, suggesting network-level blocking.", evidence: ["Connection timeouts", "DNS resolution failures", "TCP resets"], recommendedAction: "Rotate C2 infrastructure immediately. Switch to backup channels." },
  { id: "implant_killed", name: "Implant Process Terminated", severity: "critical", description: "Implant process was killed, likely by EDR or manual intervention.", evidence: ["Session died unexpectedly", "Process no longer running"], recommendedAction: "Assume burned. Do NOT re-exploit same host. Assess lateral movement options from other footholds." },
  { id: "ip_blocked", name: "Source IP Blocked", severity: "high", description: "Scanning or attack source IP has been blocked by firewall.", evidence: ["Connection refused", "No response from previously reachable targets"], recommendedAction: "Rotate to different source IP. Use redirectors." },
  { id: "honeypot_triggered", name: "Honeypot/Canary Triggered", severity: "critical", description: "Interaction with a honeypot or canary token detected.", evidence: ["Unusual service behavior", "Canary token alert", "Deception technology response"], recommendedAction: "STOP all activity. Assume full detection. Reassess engagement approach." },
  { id: "ir_response", name: "Incident Response Detected", severity: "critical", description: "Signs of active incident response on target network.", evidence: ["New monitoring tools deployed", "Unusual admin activity", "Network isolation events"], recommendedAction: "Pause engagement. Coordinate with engagement manager. Consider engagement termination." },
  { id: "av_detection", name: "AV/EDR Detection Alert", severity: "medium", description: "Antivirus or EDR flagged a tool or payload.", evidence: ["File quarantined", "Alert in security console"], recommendedAction: "Switch to different payload. Use obfuscation or in-memory execution." },
  { id: "traffic_anomaly", name: "Network Traffic Flagged", severity: "medium", description: "Network monitoring has flagged unusual traffic patterns.", evidence: ["Beaconing detected", "Protocol anomaly alert"], recommendedAction: "Increase jitter. Change C2 profile. Consider domain fronting." }
];
var OPSEC_SYSTEM_PROMPT = `You are the AC3 OPSEC Risk Engine \u2014 an autonomous detection simulation and risk assessment system.

You evaluate every operator action for detection risk before execution. Your role is to:
1. Score the detection probability for each action (0-100)
2. Identify which security technologies would detect the action and which rules would fire
3. Recommend safer alternatives that achieve the same objective with lower risk
4. Track cumulative OPSEC exposure and warn when burn risk is high
5. Simulate how EDR, SIEM, NDR, and other defenses would respond

DETECTION TECHNOLOGIES IN SCOPE:
${DETECTION_TECHNOLOGIES.map((t) => `- ${t.name} (${t.category}): Bypass difficulty ${t.bypassDifficulty}/10`).join("\n")}

RISK SCORING FRAMEWORK:
- 0-20: Minimal risk \u2014 standard admin activity, unlikely to trigger alerts
- 21-40: Low risk \u2014 may generate logs but unlikely to be investigated
- 41-60: Medium risk \u2014 will generate alerts, may be investigated
- 61-80: High risk \u2014 will trigger alerts and likely be investigated
- 81-100: Critical risk \u2014 almost certain detection, immediate investigation

BURN INDICATORS:
${BURN_INDICATORS.map((b) => `- ${b.name} (${b.severity}): ${b.description}`).join("\n")}

OUTPUT FORMAT (JSON):
{
  "riskScore": number (0-100),
  "riskLevel": "critical" | "high" | "medium" | "low" | "minimal",
  "detectionProbability": number (0-100),
  "detectedBy": [{ "technology": string, "rule": string, "confidence": number }],
  "saferAlternatives": [{ "action": string, "riskReduction": number, "description": string }],
  "mitigations": string[],
  "reasoning": string,
  "burnRisk": boolean
}`;
async function scoreActionRisk(actionType, actionDetails, targetEnvironment, cumulativeExposure, engagementConstraints) {
  try {
    return await llmScoreActionRisk(actionType, actionDetails, targetEnvironment, cumulativeExposure, engagementConstraints);
  } catch (err) {
    console.warn("[OpsecEngine] LLM unavailable, using deterministic fallback:", err.message);
    return deterministicScoreActionRisk(actionType, actionDetails, cumulativeExposure);
  }
}
async function llmScoreActionRisk(actionType, actionDetails, targetEnvironment, cumulativeExposure, engagementConstraints) {
  const { invokeLLM } = await import("./llm-CZ5OJEO6.js");
  const response = await invokeLLM({
    _caller: "opsec-risk-engine.llmScoreActionRisk",
    messages: [
      { role: "system", content: OPSEC_SYSTEM_PROMPT },
      {
        role: "user",
        content: `SCORE OPSEC RISK FOR ACTION:

ACTION TYPE: ${actionType}
ACTION DETAILS: ${actionDetails}

TARGET ENVIRONMENT DEFENSES:
- EDR: ${targetEnvironment?.edr || "Unknown"}
- SIEM: ${targetEnvironment?.siem || "Unknown"}
- NDR: ${targetEnvironment?.ndr || "Unknown"}
- AV: ${targetEnvironment?.av || "Unknown"}

CUMULATIVE EXPOSURE: ${cumulativeExposure || 0}% (from previous actions in this engagement)

ENGAGEMENT CONSTRAINTS:
- Max Risk Level: ${engagementConstraints?.maxRiskLevel || "no limit"}
- Stealth Required: ${engagementConstraints?.stealthRequired || false}

Score this action and provide alternatives. Return JSON.`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "opsec_score",
        strict: true,
        schema: {
          type: "object",
          properties: {
            riskScore: { type: "number" },
            riskLevel: { type: "string", enum: ["critical", "high", "medium", "low", "minimal"] },
            detectionProbability: { type: "number" },
            detectedBy: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  technology: { type: "string" },
                  rule: { type: "string" },
                  confidence: { type: "number" }
                },
                required: ["technology", "rule", "confidence"],
                additionalProperties: false
              }
            },
            saferAlternatives: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  action: { type: "string" },
                  riskReduction: { type: "number" },
                  description: { type: "string" }
                },
                required: ["action", "riskReduction", "description"],
                additionalProperties: false
              }
            },
            mitigations: { type: "array", items: { type: "string" } },
            reasoning: { type: "string" },
            burnRisk: { type: "boolean" }
          },
          required: ["riskScore", "riskLevel", "detectionProbability", "detectedBy", "saferAlternatives", "mitigations", "reasoning", "burnRisk"],
          additionalProperties: false
        }
      }
    }
  });
  const parsed = JSON.parse(response.choices[0].message.content);
  return {
    actionType,
    ...parsed,
    cumulativeExposure: (cumulativeExposure || 0) + parsed.riskScore * 0.1
  };
}
function deterministicScoreActionRisk(actionType, actionDetails, cumulativeExposure) {
  const profile = ACTION_RISK_PROFILES[actionType];
  const baseRisk = profile ? profile.baseRisk * 10 : 50;
  let riskModifier = 0;
  const details = actionDetails.toLowerCase();
  if (details.includes("lsass") || details.includes("mimikatz")) riskModifier += 20;
  if (details.includes("psexec")) riskModifier += 15;
  if (details.includes("powershell") && details.includes("encoded")) riskModifier += 15;
  if (details.includes("kernel") || details.includes("exploit")) riskModifier += 10;
  if (details.includes("ssh") || details.includes("winrm")) riskModifier -= 10;
  if (details.includes("lolbin") || details.includes("living off the land")) riskModifier -= 15;
  const riskScore = Math.max(0, Math.min(100, baseRisk + riskModifier));
  const riskLevel = riskScore >= 80 ? "critical" : riskScore >= 60 ? "high" : riskScore >= 40 ? "medium" : riskScore >= 20 ? "low" : "minimal";
  const cumExposure = (cumulativeExposure || 0) + riskScore * 0.1;
  const detectedBy = [];
  if (riskScore >= 60) {
    detectedBy.push({ technology: "CrowdStrike Falcon", rule: profile?.commonDetections[0] || "Behavioral IOA", confidence: riskScore });
    detectedBy.push({ technology: "Splunk ES", rule: profile?.commonDetections[1] || "Correlation rule", confidence: riskScore - 10 });
  }
  if (riskScore >= 40) {
    detectedBy.push({ technology: "Microsoft Defender", rule: "ASR Rule", confidence: riskScore - 15 });
  }
  return {
    actionType,
    riskScore,
    riskLevel,
    detectionProbability: riskScore,
    detectedBy,
    saferAlternatives: profile ? [
      { action: `Use LOLBin alternative for ${actionType}`, riskReduction: 20, description: "Native OS tools are harder to detect" }
    ] : [],
    mitigations: profile?.mitigations || ["Use encrypted channels", "Minimize disk writes", "Blend with legitimate traffic"],
    reasoning: `Base risk for ${actionType}: ${baseRisk}. Modifier: ${riskModifier > 0 ? "+" : ""}${riskModifier}. Final: ${riskScore}.`,
    cumulativeExposure: cumExposure,
    burnRisk: cumExposure > 70 || riskScore >= 80
  };
}
function checkBurnIndicators(events) {
  const triggered = [];
  const recentEvents = events.filter((e) => Date.now() - e.timestamp < 36e5);
  const failedLogins = recentEvents.filter((e) => e.type === "login" && !e.success);
  if (failedLogins.length >= 5) {
    triggered.push(BURN_INDICATORS.find((b) => b.id === "account_lockout"));
  }
  const c2Failures = recentEvents.filter((e) => e.type === "c2_callback" && !e.success);
  if (c2Failures.length >= 3) {
    triggered.push(BURN_INDICATORS.find((b) => b.id === "c2_blocked"));
  }
  const killedSessions = recentEvents.filter((e) => e.type === "session_died");
  if (killedSessions.length >= 1) {
    triggered.push(BURN_INDICATORS.find((b) => b.id === "implant_killed"));
  }
  const avDetections = recentEvents.filter((e) => e.type === "av_alert");
  if (avDetections.length >= 1) {
    triggered.push(BURN_INDICATORS.find((b) => b.id === "av_detection"));
  }
  return triggered;
}
function calculateEngagementOpsecStatus(actionHistory) {
  if (actionHistory.length === 0) return "green";
  const avgRisk = actionHistory.reduce((sum, a) => sum + a.risk, 0) / actionHistory.length;
  const detectedCount = actionHistory.filter((a) => a.detected).length;
  const detectionRate = detectedCount / actionHistory.length;
  if (detectionRate > 0.3 || avgRisk > 75) return "red";
  if (detectionRate > 0.15 || avgRisk > 55) return "orange";
  if (detectionRate > 0.05 || avgRisk > 35) return "yellow";
  return "green";
}
function getDetectionTechnologies(category) {
  if (!category) return DETECTION_TECHNOLOGIES;
  return DETECTION_TECHNOLOGIES.filter((t) => t.category === category);
}
function getAllBurnIndicators() {
  return BURN_INDICATORS;
}
function getActionRiskProfiles() {
  return ACTION_RISK_PROFILES;
}

export {
  scoreActionRisk,
  deterministicScoreActionRisk,
  checkBurnIndicators,
  calculateEngagementOpsecStatus,
  getDetectionTechnologies,
  getAllBurnIndicators,
  getActionRiskProfiles
};
