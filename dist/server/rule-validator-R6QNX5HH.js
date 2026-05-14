import {
  init_llm,
  invokeLLM
} from "./chunk-L5VXSJ4F.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-GN2OC6SU.js";
import "./chunk-KFQGP6VL.js";

// server/lib/rule-validator.ts
init_llm();
function validateSigmaSyntax(content) {
  const errors = [];
  const lines = content.split("\n");
  const requiredFields = ["title", "logsource", "detection"];
  const foundFields = /* @__PURE__ */ new Set();
  let inDetection = false;
  let hasCondition = false;
  let hasSelection = false;
  let yamlIndentValid = true;
  let prevIndent = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    if (!line.startsWith(" ") && !line.startsWith("	") && trimmed.includes(":")) {
      const field = trimmed.split(":")[0].trim();
      foundFields.add(field);
      if (field === "detection") inDetection = true;
      else inDetection = false;
    }
    if (inDetection && (line.startsWith("    ") || line.startsWith("	"))) {
      if (trimmed.startsWith("condition:")) hasCondition = true;
      if (trimmed.startsWith("selection") || trimmed.startsWith("filter")) hasSelection = true;
    }
    if (trimmed.includes("	") && trimmed.includes(" ")) {
      errors.push({
        line: i + 1,
        message: "Mixed tabs and spaces in indentation",
        severity: "warning"
      });
    }
    if (!trimmed.startsWith("-") && !trimmed.startsWith("#") && trimmed.includes(":") && !trimmed.includes(": ") && !trimmed.endsWith(":")) {
      if (!trimmed.match(/:\s*$/)) {
        errors.push({
          line: i + 1,
          message: `Possible malformed YAML: missing space after colon`,
          severity: "warning"
        });
      }
    }
  }
  for (const field of requiredFields) {
    if (!foundFields.has(field)) {
      errors.push({
        line: 1,
        message: `Missing required field: ${field}`,
        severity: "error"
      });
    }
  }
  if (foundFields.has("detection") && !hasCondition) {
    errors.push({
      line: 1,
      message: "Detection section missing 'condition' field",
      severity: "error"
    });
  }
  const recommended = ["status", "level", "description", "author", "date"];
  for (const field of recommended) {
    if (!foundFields.has(field)) {
      errors.push({
        line: 1,
        message: `Missing recommended field: ${field}`,
        severity: "warning"
      });
    }
  }
  return errors;
}
function analyzeSigmaSemantics(content) {
  const warnings = [];
  const lower = content.toLowerCase();
  if (lower.includes("selection:") && lower.includes("'*'")) {
    warnings.push({
      field: "detection.selection",
      message: "Wildcard-only selection may produce excessive false positives",
      severity: "critical"
    });
  }
  if (!lower.includes("filter")) {
    warnings.push({
      field: "detection",
      message: "No filter clause found. Consider adding filters to reduce false positives.",
      severity: "warning"
    });
  }
  if (lower.includes("logsource:") && !lower.includes("product:") && !lower.includes("service:")) {
    warnings.push({
      field: "logsource",
      message: "Log source lacks product or service specification. This may cause compatibility issues.",
      severity: "warning"
    });
  }
  if (lower.includes("falsepositives:") && lower.includes("unknown")) {
    warnings.push({
      field: "falsepositives",
      message: "Consider documenting known false positive scenarios instead of 'unknown'",
      severity: "info"
    });
  }
  if (lower.includes("level: informational") || lower.includes("level: low")) {
    warnings.push({
      field: "level",
      message: "Low severity rules may be deprioritized in SIEM. Ensure this matches the actual threat level.",
      severity: "info"
    });
  }
  return warnings;
}
function validateYaraSyntax(content) {
  const errors = [];
  const lines = content.split("\n");
  let hasRule = false;
  let hasStrings = false;
  let hasCondition = false;
  let braceCount = 0;
  let inRule = false;
  let inStrings = false;
  let inCondition = false;
  let stringNames = /* @__PURE__ */ new Set();
  let usedStrings = /* @__PURE__ */ new Set();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("/*")) continue;
    if (trimmed.match(/^rule\s+\w+/)) {
      hasRule = true;
      inRule = true;
    }
    braceCount += (trimmed.match(/{/g) || []).length;
    braceCount -= (trimmed.match(/}/g) || []).length;
    if (trimmed === "strings:") {
      hasStrings = true;
      inStrings = true;
      inCondition = false;
    }
    if (trimmed === "condition:") {
      hasCondition = true;
      inCondition = true;
      inStrings = false;
    }
    if (inStrings && trimmed.startsWith("$")) {
      const match = trimmed.match(/^\$(\w+)\s*=/);
      if (match) stringNames.add(match[1]);
    }
    if (inCondition && trimmed.includes("$")) {
      const matches = trimmed.match(/\$\w+/g);
      if (matches) {
        matches.forEach((m) => usedStrings.add(m.substring(1)));
      }
    }
    if (inStrings && trimmed.includes("=") && !trimmed.startsWith("$")) {
      errors.push({
        line: i + 1,
        message: "String definition must start with $",
        severity: "error"
      });
    }
    if (inStrings && trimmed.includes("{ ") && !trimmed.match(/\{[\s0-9a-fA-F?[\]|()]+\}/)) {
      if (trimmed.match(/\{[^}]*[g-zG-Z][^}]*\}/)) {
        errors.push({
          line: i + 1,
          message: "Hex string contains invalid characters (only 0-9, a-f, A-F, ?, [, ], |, (, ) allowed)",
          severity: "error"
        });
      }
    }
  }
  if (!hasRule) {
    errors.push({ line: 1, message: "No rule declaration found", severity: "error" });
  }
  if (hasRule && !hasCondition) {
    errors.push({ line: 1, message: "Rule missing 'condition:' section", severity: "error" });
  }
  if (braceCount !== 0) {
    errors.push({ line: 1, message: "Unbalanced braces in rule", severity: "error" });
  }
  for (const name of Array.from(stringNames)) {
    if (!usedStrings.has(name) && !usedStrings.has("them")) {
      errors.push({
        line: 1,
        message: `String $${name} is defined but not used in condition`,
        severity: "warning"
      });
    }
  }
  return errors;
}
function analyzeYaraSemantics(content) {
  const warnings = [];
  const lower = content.toLowerCase();
  if (lower.includes("condition:") && lower.includes("any of them")) {
    warnings.push({
      field: "condition",
      message: "'any of them' may be too broad. Consider requiring multiple string matches.",
      severity: "warning"
    });
  }
  if (!lower.includes("meta:")) {
    warnings.push({
      field: "meta",
      message: "Missing meta section. Add author, description, date, and reference.",
      severity: "info"
    });
  }
  if (lower.includes("wide") && lower.includes("ascii") && lower.includes("nocase")) {
    warnings.push({
      field: "strings",
      message: "Combining wide, ascii, and nocase modifiers may impact scanning performance.",
      severity: "warning"
    });
  }
  if (!lower.includes("filesize")) {
    warnings.push({
      field: "condition",
      message: "Consider adding filesize constraint to improve scanning performance.",
      severity: "info"
    });
  }
  return warnings;
}
function validateSuricataSyntax(content) {
  const errors = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    if (!line.match(/^(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s+/)) {
      errors.push({
        line: i + 1,
        message: "Rule must start with an action (alert, drop, pass, reject)",
        severity: "error"
      });
      continue;
    }
    if (!line.includes("(") || !line.includes(")")) {
      errors.push({
        line: i + 1,
        message: "Rule missing options section (parentheses)",
        severity: "error"
      });
      continue;
    }
    const options = line.substring(line.indexOf("("), line.lastIndexOf(")") + 1);
    if (!options.includes("sid:")) {
      errors.push({
        line: i + 1,
        message: "Missing required 'sid' option",
        severity: "error"
      });
    }
    if (!options.includes("msg:")) {
      errors.push({
        line: i + 1,
        message: "Missing 'msg' option (recommended)",
        severity: "warning"
      });
    }
    if (!options.includes("rev:")) {
      errors.push({
        line: i + 1,
        message: "Missing 'rev' option (recommended)",
        severity: "warning"
      });
    }
  }
  return errors;
}
function validateSplunkSyntax(content) {
  const errors = [];
  const lower = content.toLowerCase().trim();
  if (!lower.startsWith("index=") && !lower.startsWith("search") && !lower.startsWith("|") && !lower.startsWith("source")) {
    errors.push({
      line: 1,
      message: "SPL query should start with index=, search, source, or a pipe command",
      severity: "warning"
    });
  }
  const singleQuotes = (content.match(/'/g) || []).length;
  const doubleQuotes = (content.match(/"/g) || []).length;
  if (singleQuotes % 2 !== 0) {
    errors.push({ line: 1, message: "Unbalanced single quotes", severity: "error" });
  }
  if (doubleQuotes % 2 !== 0) {
    errors.push({ line: 1, message: "Unbalanced double quotes", severity: "error" });
  }
  const openParens = (content.match(/\(/g) || []).length;
  const closeParens = (content.match(/\)/g) || []).length;
  if (openParens !== closeParens) {
    errors.push({ line: 1, message: "Unbalanced parentheses", severity: "error" });
  }
  const openBrackets = (content.match(/\[/g) || []).length;
  const closeBrackets = (content.match(/\]/g) || []).length;
  if (openBrackets !== closeBrackets) {
    errors.push({ line: 1, message: "Unbalanced brackets", severity: "error" });
  }
  return errors;
}
function validateKQLSyntax(content) {
  const errors = [];
  const lower = content.toLowerCase().trim();
  const commonTables = [
    "securityevent",
    "deviceprocessevents",
    "devicenetworkevents",
    "devicefileevents",
    "deviceregistryevents",
    "devicelogoninfo",
    "emailevents",
    "identitylogoninfo",
    "syslog",
    "commonlogs",
    "signinlogs",
    "auditlogs",
    "deviceinfo",
    "alertevidence"
  ];
  const hasTable = commonTables.some((t) => lower.includes(t));
  if (!hasTable && !lower.startsWith("let ") && !lower.startsWith("//")) {
    errors.push({
      line: 1,
      message: "KQL query should reference a data table (e.g., SecurityEvent, DeviceProcessEvents)",
      severity: "warning"
    });
  }
  const doubleQuotes = (content.match(/"/g) || []).length;
  if (doubleQuotes % 2 !== 0) {
    errors.push({ line: 1, message: "Unbalanced double quotes", severity: "error" });
  }
  const openParens = (content.match(/\(/g) || []).length;
  const closeParens = (content.match(/\)/g) || []).length;
  if (openParens !== closeParens) {
    errors.push({ line: 1, message: "Unbalanced parentheses", severity: "error" });
  }
  return errors;
}
function generateSampleLogData(techniqueId) {
  const sampleLogs = {
    "T1059.001": `EventID: 4688
CommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==
ParentProcess: cmd.exe
User: DOMAIN\\admin
Timestamp: 2026-02-14T10:30:00Z`,
    "T1059.003": `EventID: 4688
CommandLine: cmd.exe /c whoami /all & net user & net localgroup administrators
ParentProcess: explorer.exe
User: DOMAIN\\user1
Timestamp: 2026-02-14T10:31:00Z`,
    "T1003.001": `EventID: 10
TargetImage: C:\\Windows\\System32\\lsass.exe
SourceImage: C:\\Windows\\System32\\rundll32.exe
GrantedAccess: 0x1010
User: NT AUTHORITY\\SYSTEM
Timestamp: 2026-02-14T10:32:00Z`,
    "T1055": `EventID: 8
SourceImage: C:\\Users\\admin\\malware.exe
TargetImage: C:\\Windows\\System32\\svchost.exe
StartFunction: LoadLibraryA
User: DOMAIN\\admin
Timestamp: 2026-02-14T10:33:00Z`,
    "T1078": `EventID: 4624
LogonType: 10
TargetUserName: admin
TargetDomainName: CORP
IpAddress: 10.0.0.50
WorkstationName: WORKSTATION01
Timestamp: 2026-02-14T10:34:00Z`,
    "T1566.001": `From: hr-department@company-update.com
To: employee@target.com
Subject: Urgent: Update Your Benefits Information
Attachment: Benefits_Update_2026.xlsm
X-Mailer: Microsoft Outlook 16.0
Received: from mail.suspicious-domain.com
Timestamp: 2026-02-14T10:35:00Z`,
    "T1190": `src_ip: 203.0.113.50
dst_ip: 10.0.1.100
dst_port: 443
http_method: POST
http_uri: /api/v1/users?id=1' OR '1'='1
http_user_agent: sqlmap/1.7
http_status: 500
Timestamp: 2026-02-14T10:36:00Z`,
    "T1021.001": `EventID: 4624
LogonType: 3
TargetUserName: admin
SourceNetworkAddress: 10.0.0.100
AuthenticationPackage: NTLM
Timestamp: 2026-02-14T10:37:00Z`,
    "T1082": `EventID: 4688
CommandLine: systeminfo
ParentProcess: cmd.exe
User: DOMAIN\\user1
Timestamp: 2026-02-14T10:38:00Z`,
    "T1027": `EventID: 4688
CommandLine: certutil.exe -encode payload.exe payload.b64
ParentProcess: cmd.exe
User: DOMAIN\\admin
Timestamp: 2026-02-14T10:39:00Z`,
    "T1486": `EventID: 4663
ObjectName: C:\\Users\\Documents\\important.docx.encrypted
ProcessName: C:\\Users\\admin\\ransom.exe
AccessMask: 0x2
User: DOMAIN\\admin
Timestamp: 2026-02-14T10:40:00Z`,
    "T1071.001": `src_ip: 10.0.0.50
dst_ip: 198.51.100.10
dst_port: 443
http_method: POST
http_host: cdn-update.suspicious.com
http_uri: /api/beacon
bytes_out: 4096
Timestamp: 2026-02-14T10:41:00Z`
  };
  if (sampleLogs[techniqueId]) return sampleLogs[techniqueId];
  const parent = techniqueId.split(".")[0];
  if (sampleLogs[parent]) return sampleLogs[parent];
  return `EventID: 4688
CommandLine: suspicious_process.exe --flag
ParentProcess: explorer.exe
User: DOMAIN\\user
TargetTechnique: ${techniqueId}
Timestamp: 2026-02-14T10:45:00Z`;
}
function scoreEffectiveness(ruleType, syntaxErrors, semanticWarnings, content) {
  let score = 100;
  let fpScore = 0;
  const criticalErrors = syntaxErrors.filter((e) => e.severity === "error").length;
  const warningErrors = syntaxErrors.filter((e) => e.severity === "warning").length;
  score -= criticalErrors * 15;
  score -= warningErrors * 5;
  const criticalWarnings = semanticWarnings.filter((w) => w.severity === "critical").length;
  const normalWarnings = semanticWarnings.filter((w) => w.severity === "warning").length;
  score -= criticalWarnings * 10;
  score -= normalWarnings * 3;
  fpScore += criticalWarnings * 20;
  fpScore += normalWarnings * 10;
  const lower = content.toLowerCase();
  if (lower.includes("author:") || lower.includes("meta:")) score += 2;
  if (lower.includes("description:")) score += 2;
  if (lower.includes("reference:") || lower.includes("references:")) score += 3;
  if (lower.includes("falsepositives:")) score += 3;
  if (lower.includes("tags:") || lower.includes("attack.")) score += 3;
  if (ruleType === "sigma") {
    if (lower.includes("filter")) {
      score += 5;
      fpScore -= 10;
    }
    if (lower.includes("level:")) score += 2;
    if (lower.includes("status:")) score += 2;
  }
  if (ruleType === "yara") {
    if (lower.includes("filesize")) {
      score += 3;
      fpScore -= 5;
    }
    if (lower.includes("meta:")) score += 3;
  }
  score = Math.max(0, Math.min(100, score));
  const fpRisk = fpScore > 30 ? "high" : fpScore > 15 ? "medium" : "low";
  return { score, fpRisk };
}
function assessCoverage(ruleType, content, techniqueId) {
  const lower = content.toLowerCase();
  const techniques = [];
  const dataSources = [];
  const logSources = [];
  const platforms = [];
  const techMatches = content.match(/T\d{4}(\.\d{3})?/g);
  if (techMatches) techniques.push(...Array.from(new Set(techMatches)));
  if (techniqueId && !techniques.includes(techniqueId)) techniques.push(techniqueId);
  if (ruleType === "sigma") {
    if (lower.includes("product: windows")) {
      platforms.push("Windows");
      logSources.push("Windows Event Log");
    }
    if (lower.includes("product: linux")) {
      platforms.push("Linux");
      logSources.push("Syslog");
    }
    if (lower.includes("service: sysmon")) {
      logSources.push("Sysmon");
      dataSources.push("Process Creation");
    }
    if (lower.includes("service: security")) {
      logSources.push("Windows Security");
      dataSources.push("Authentication Logs");
    }
    if (lower.includes("service: powershell")) {
      logSources.push("PowerShell");
      dataSources.push("Script Execution");
    }
    if (lower.includes("category: process_creation")) dataSources.push("Process Creation");
    if (lower.includes("category: network_connection")) dataSources.push("Network Connections");
    if (lower.includes("category: file_event")) dataSources.push("File Events");
    if (lower.includes("category: registry_event")) dataSources.push("Registry Events");
  }
  if (ruleType === "yara") {
    platforms.push("Cross-platform");
    dataSources.push("File Content", "Memory Dumps");
    logSources.push("Endpoint Scanner");
  }
  if (ruleType === "suricata") {
    platforms.push("Network");
    dataSources.push("Network Traffic");
    logSources.push("Network IDS/IPS");
  }
  if (ruleType === "splunk") {
    if (lower.includes("index=")) {
      const indexMatch = lower.match(/index=(\w+)/);
      if (indexMatch) logSources.push(`Splunk Index: ${indexMatch[1]}`);
    }
    platforms.push("Splunk");
    dataSources.push("SIEM Logs");
  }
  if (ruleType === "kql") {
    platforms.push("Microsoft Sentinel", "Microsoft Defender");
    if (lower.includes("securityevent")) {
      logSources.push("SecurityEvent");
      dataSources.push("Windows Security Logs");
    }
    if (lower.includes("deviceprocessevents")) {
      logSources.push("DeviceProcessEvents");
      dataSources.push("Endpoint Telemetry");
    }
    if (lower.includes("signinlogs")) {
      logSources.push("SigninLogs");
      dataSources.push("Azure AD");
    }
  }
  return {
    techniquesCovered: techniques,
    dataSourcesRequired: dataSources.length > 0 ? dataSources : ["General Logs"],
    logSourcesNeeded: logSources.length > 0 ? logSources : ["SIEM"],
    platformCompatibility: platforms.length > 0 ? platforms : ["Unknown"]
  };
}
async function performLLMAnalysis(input) {
  const sampleData = input.sampleData || generateSampleLogData(input.techniqueId || "T1059");
  const prompt = `You are a detection engineering expert. Analyze this ${input.ruleType.toUpperCase()} rule for quality, effectiveness, and correctness.

RULE (${input.ruleType}):
\`\`\`
${input.ruleContent}
\`\`\`

${input.techniqueId ? `TARGET TECHNIQUE: ${input.techniqueId}` : ""}

SAMPLE LOG DATA TO TEST AGAINST:
\`\`\`
${sampleData}
\`\`\`

Provide:
1. Whether this rule would match the sample data (and why/why not)
2. Specific improvement suggestions (max 5)
3. False positive risk assessment
4. Overall quality assessment

Return JSON:
{
  "analysis": "Detailed analysis paragraph",
  "suggestions": ["suggestion1", "suggestion2", ...],
  "wouldMatch": true/false,
  "matchExplanation": "Why it would/wouldn't match",
  "matchedFields": ["field1", "field2"],
  "matchConfidence": 0-100
}`;
  try {
    const response = await invokeLLM({
      _caller: "rule-validator.performLLMAnalysis",
      messages: [
        { role: "system", content: "You are a detection engineering expert. Return valid JSON only." },
        { role: "user", content: prompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "rule_analysis",
          strict: true,
          schema: {
            type: "object",
            properties: {
              analysis: { type: "string" },
              suggestions: { type: "array", items: { type: "string" } },
              wouldMatch: { type: "boolean" },
              matchExplanation: { type: "string" },
              matchedFields: { type: "array", items: { type: "string" } },
              matchConfidence: { type: "number" }
            },
            required: ["analysis", "suggestions", "wouldMatch", "matchExplanation", "matchedFields", "matchConfidence"],
            additionalProperties: false
          }
        }
      }
    });
    const rawContent = response.choices?.[0]?.message?.content || "{}";
    const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);
    const parsed = JSON.parse(content);
    return {
      analysis: parsed.analysis || "Analysis unavailable",
      suggestions: parsed.suggestions || [],
      sampleMatches: [{
        matched: parsed.wouldMatch || false,
        matchedFields: parsed.matchedFields || [],
        confidence: parsed.matchConfidence || 0,
        explanation: parsed.matchExplanation || ""
      }]
    };
  } catch (error) {
    console.error("LLM rule analysis failed:", error);
    return {
      analysis: "LLM analysis unavailable. Rule was validated using static analysis only.",
      suggestions: [],
      sampleMatches: []
    };
  }
}
async function validateRule(input, useLLM = true) {
  let syntaxErrors = [];
  let semanticWarnings = [];
  switch (input.ruleType) {
    case "sigma":
      syntaxErrors = validateSigmaSyntax(input.ruleContent);
      semanticWarnings = analyzeSigmaSemantics(input.ruleContent);
      break;
    case "yara":
      syntaxErrors = validateYaraSyntax(input.ruleContent);
      semanticWarnings = analyzeYaraSemantics(input.ruleContent);
      break;
    case "suricata":
      syntaxErrors = validateSuricataSyntax(input.ruleContent);
      break;
    case "splunk":
      syntaxErrors = validateSplunkSyntax(input.ruleContent);
      break;
    case "kql":
      syntaxErrors = validateKQLSyntax(input.ruleContent);
      break;
  }
  const { score, fpRisk } = scoreEffectiveness(
    input.ruleType,
    syntaxErrors,
    semanticWarnings,
    input.ruleContent
  );
  const coverage = assessCoverage(input.ruleType, input.ruleContent, input.techniqueId);
  let llmResult = null;
  if (useLLM) {
    llmResult = await performLLMAnalysis(input);
  }
  const hasErrors = syntaxErrors.some((e) => e.severity === "error");
  return {
    valid: !hasErrors,
    syntaxErrors,
    semanticWarnings,
    effectivenessScore: score,
    falsePositiveRisk: fpRisk,
    coverage,
    suggestions: llmResult?.suggestions || [],
    sampleMatches: llmResult?.sampleMatches || [],
    llmAnalysis: llmResult?.analysis
  };
}
async function validateRuleBatch(rules, useLLM = false) {
  const results = [];
  for (const rule of rules) {
    const result = await validateRule(rule, useLLM);
    results.push({
      ruleName: rule.ruleName || `${rule.ruleType}-rule`,
      ruleType: rule.ruleType,
      techniqueId: rule.techniqueId,
      result
    });
  }
  const validCount = results.filter((r) => r.result.valid).length;
  const avgEffectiveness = results.length > 0 ? Math.round(results.reduce((sum, r) => sum + r.result.effectivenessScore, 0) / results.length) : 0;
  return {
    totalRules: results.length,
    validRules: validCount,
    invalidRules: results.length - validCount,
    averageEffectiveness: avgEffectiveness,
    results
  };
}
export {
  generateSampleLogData,
  validateRule,
  validateRuleBatch
};
