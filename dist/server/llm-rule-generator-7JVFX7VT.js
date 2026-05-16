import {
  getDb,
  init_db
} from "./chunk-L5ZLWR7T.js";
import "./chunk-NRYVRXXR.js";
import {
  generatedDetectionRules,
  init_schema
} from "./chunk-L4JENJ4Z.js";
import "./chunk-KFQGP6VL.js";

// server/lib/llm-rule-generator.ts
init_db();
init_schema();
import { eq, desc } from "drizzle-orm";
var ruleCache = /* @__PURE__ */ new Map();
var ruleCounter = 0;
var cacheLoaded = false;
async function persistRule(rule) {
  const db = await getDb();
  if (!db) return;
  try {
    await db.insert(generatedDetectionRules).values({
      ruleId: rule.id,
      cveId: rule.cveIds[0] || "UNKNOWN",
      format: rule.format,
      title: rule.name,
      content: rule.content,
      severity: rule.severity,
      mitreTactics: rule.tags.filter((t) => t.startsWith("attack.")),
      mitreTechniques: rule.mitreTechniques,
      dataSources: rule.tags,
      validated: rule.validated,
      validationErrors: rule.validationNotes ? [rule.validationNotes] : null
    });
  } catch (err) {
    console.error("[RuleGen] DB persist failed:", err);
  }
}
async function loadRulesFromDb() {
  if (cacheLoaded) return;
  const db = await getDb();
  if (!db) {
    cacheLoaded = true;
    return;
  }
  try {
    const rows = await db.select().from(generatedDetectionRules).orderBy(desc(generatedDetectionRules.createdAt));
    for (const row of rows) {
      const rule = {
        id: row.ruleId,
        format: row.format,
        name: row.title,
        description: `Auto-generated ${row.format.toUpperCase()} rule for ${row.cveId}`,
        content: row.content,
        severity: row.severity || "medium",
        mitreTechniques: row.mitreTechniques || [],
        cveIds: [row.cveId],
        confidence: row.validated ? "high" : "medium",
        falsePositiveRisk: "medium",
        tags: row.dataSources || [],
        generatedAt: row.createdAt ? new Date(row.createdAt).getTime() : Date.now(),
        validated: row.validated || false,
        validationNotes: row.validationErrors ? row.validationErrors.join("; ") : null
      };
      ruleCache.set(rule.id, rule);
    }
    cacheLoaded = true;
  } catch (err) {
    console.error("[RuleGen] DB load failed:", err);
    cacheLoaded = true;
  }
}
function buildSigmaPrompt(request) {
  return `Generate a Sigma detection rule for the following validated exploit:

**Exploit Module:** ${request.exploitModule}
**CVE(s):** ${request.cveIds.join(", ") || "N/A"}
**Target Service:** ${request.targetService}${request.targetPort ? ` (port ${request.targetPort})` : ""}
**MITRE ATT&CK Technique:** ${request.attackTechnique}
**Severity:** ${request.severity}

${request.exploitOutput ? `**Exploit Output (partial):**
\`\`\`
${request.exploitOutput.slice(0, 2e3)}
\`\`\`` : ""}

Generate a complete Sigma rule in YAML format that:
1. Detects the specific attack pattern from this exploit
2. Includes appropriate log sources (sysmon, windows, network, etc.)
3. Has a low false positive rate
4. Includes MITRE ATT&CK tags
5. Includes a description explaining what the rule detects

Return ONLY the YAML content, no markdown fences or explanations.`;
}
function buildYaraPrompt(request) {
  return `Generate a YARA detection rule for the following validated exploit:

**Exploit Module:** ${request.exploitModule}
**CVE(s):** ${request.cveIds.join(", ") || "N/A"}
**Target Service:** ${request.targetService}
**Severity:** ${request.severity}

${request.exploitOutput ? `**Exploit Output (partial):**
\`\`\`
${request.exploitOutput.slice(0, 2e3)}
\`\`\`` : ""}

Generate a complete YARA rule that:
1. Detects file artifacts or memory patterns from this exploit
2. Uses specific byte patterns, strings, or conditions
3. Minimizes false positives with multiple conditions
4. Includes metadata (author, description, severity, CVE reference)

Return ONLY the YARA rule content, no markdown fences or explanations.`;
}
function buildSnortPrompt(request) {
  return `Generate a Snort/Suricata IDS rule for the following validated exploit:

**Exploit Module:** ${request.exploitModule}
**CVE(s):** ${request.cveIds.join(", ") || "N/A"}
**Target Service:** ${request.targetService}${request.targetPort ? ` (port ${request.targetPort})` : ""}
**Severity:** ${request.severity}

${request.exploitOutput ? `**Exploit Output (partial):**
\`\`\`
${request.exploitOutput.slice(0, 2e3)}
\`\`\`` : ""}

Generate a complete Snort rule that:
1. Detects the network traffic pattern from this exploit
2. Uses appropriate protocol, ports, and content matches
3. Includes flow directives for accuracy
4. Has appropriate SID and classification

Return ONLY the rule content (one rule per line), no markdown fences or explanations.`;
}
function buildKqlPrompt(request) {
  return `Generate a KQL (Kusto Query Language) detection query for Microsoft Sentinel/Defender for the following validated exploit:

**Exploit Module:** ${request.exploitModule}
**CVE(s):** ${request.cveIds.join(", ") || "N/A"}
**Target Service:** ${request.targetService}
**MITRE ATT&CK Technique:** ${request.attackTechnique}
**Severity:** ${request.severity}

Generate a complete KQL query that:
1. Detects the attack pattern in Microsoft security logs
2. Uses appropriate tables (SecurityEvent, DeviceProcessEvents, etc.)
3. Includes time filtering and severity classification
4. Minimizes false positives

Return ONLY the KQL query, no markdown fences or explanations.`;
}
function buildSplPrompt(request) {
  return `Generate a Splunk SPL detection query for the following validated exploit:

**Exploit Module:** ${request.exploitModule}
**CVE(s):** ${request.cveIds.join(", ") || "N/A"}
**Target Service:** ${request.targetService}
**MITRE ATT&CK Technique:** ${request.attackTechnique}
**Severity:** ${request.severity}

Generate a complete SPL query that:
1. Detects the attack pattern in Splunk logs
2. Uses appropriate sourcetypes and indexes
3. Includes statistical analysis for anomaly detection
4. Minimizes false positives

Return ONLY the SPL query, no markdown fences or explanations.`;
}
async function generateDetectionRules(request, llmInvoke) {
  await loadRulesFromDb();
  const start = Date.now();
  const requestId = `rulegen-${Date.now()}-${++ruleCounter}`;
  const rules = [];
  for (const format of request.requestedFormats) {
    try {
      const prompt = getPromptForFormat(format, request);
      let ruleContent;
      if (llmInvoke) {
        const response = await llmInvoke({
          messages: [
            { role: "system", content: "You are a cybersecurity detection engineer specializing in writing detection rules. Generate precise, low-false-positive rules based on validated exploit evidence." },
            { role: "user", content: prompt }
          ]
        });
        ruleContent = response?.choices?.[0]?.message?.content || generateFallbackRule(format, request);
      } else {
        ruleContent = generateFallbackRule(format, request);
      }
      const rule = {
        id: `rule-${format}-${Date.now()}-${++ruleCounter}`,
        format,
        name: `Detect ${request.exploitModule} (${request.cveIds[0] || request.attackTechnique})`,
        description: `Auto-generated ${format.toUpperCase()} rule for detecting ${request.exploitModule} targeting ${request.targetService}`,
        content: ruleContent,
        severity: request.severity,
        mitreTechniques: [request.attackTechnique],
        cveIds: request.cveIds,
        confidence: llmInvoke ? "medium" : "low",
        falsePositiveRisk: "medium",
        tags: [format, request.targetService, request.attackTechnique, ...request.cveIds],
        generatedAt: Date.now(),
        validated: false,
        validationNotes: null
      };
      await persistRule(rule);
      ruleCache.set(rule.id, rule);
      rules.push(rule);
    } catch (err) {
      console.error(`[RuleGen] Failed to generate ${format} rule: ${err.message}`);
    }
  }
  return {
    requestId,
    exploitModule: request.exploitModule,
    rules,
    totalGenerated: rules.length,
    generationDurationMs: Date.now() - start,
    llmModel: llmInvoke ? "platform-llm" : "template-fallback",
    summary: `Generated ${rules.length} detection rule(s) in ${request.requestedFormats.join(", ")} format(s) for ${request.exploitModule}.`
  };
}
async function getRule(ruleId) {
  await loadRulesFromDb();
  return ruleCache.get(ruleId) || null;
}
async function getRulesForCve(cveId) {
  await loadRulesFromDb();
  return Array.from(ruleCache.values()).filter((r) => r.cveIds.includes(cveId));
}
async function getRulesByFormat(format) {
  await loadRulesFromDb();
  return Array.from(ruleCache.values()).filter((r) => r.format === format);
}
async function validateRule(ruleId, validated, notes) {
  await loadRulesFromDb();
  const rule = ruleCache.get(ruleId);
  if (!rule) return null;
  rule.validated = validated;
  rule.validationNotes = notes;
  if (validated) rule.confidence = "high";
  const db = await getDb();
  if (db) {
    try {
      await db.update(generatedDetectionRules).set({
        validated,
        validationErrors: notes ? [notes] : null
      }).where(eq(generatedDetectionRules.ruleId, ruleId));
    } catch (err) {
      console.error("[RuleGen] DB validation update failed:", err);
    }
  }
  return rule;
}
async function getRuleLibrary() {
  await loadRulesFromDb();
  const all = Array.from(ruleCache.values());
  const byFormat = { sigma: 0, yara: 0, snort: 0, suricata: 0, kql: 0, spl: 0 };
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const rule of all) {
    byFormat[rule.format]++;
    bySeverity[rule.severity]++;
  }
  return {
    totalRules: all.length,
    byFormat,
    bySeverity,
    validated: all.filter((r) => r.validated).length,
    unvalidated: all.filter((r) => !r.validated).length,
    recentlyGenerated: all.sort((a, b) => b.generatedAt - a.generatedAt).slice(0, 10)
  };
}
function getPromptForFormat(format, request) {
  switch (format) {
    case "sigma":
      return buildSigmaPrompt(request);
    case "yara":
      return buildYaraPrompt(request);
    case "snort":
    case "suricata":
      return buildSnortPrompt(request);
    case "kql":
      return buildKqlPrompt(request);
    case "spl":
      return buildSplPrompt(request);
    default:
      return buildSigmaPrompt(request);
  }
}
function generateFallbackRule(format, request) {
  const cveStr = request.cveIds[0] || "UNKNOWN";
  const now = (/* @__PURE__ */ new Date()).toISOString().split("T")[0];
  switch (format) {
    case "sigma":
      return `title: Detect ${request.exploitModule}
id: ${Date.now()}
status: experimental
description: Detects exploitation attempt of ${cveStr} targeting ${request.targetService}
author: AC3 Auto-Generator
date: ${now}
modified: ${now}
tags:
  - attack.${request.attackTechnique.toLowerCase()}
  - cve.${cveStr.toLowerCase()}
logsource:
  category: network_connection
  product: any
detection:
  selection:
    dst_port: ${request.targetPort || 0}
    Initiated: 'true'
  condition: selection
falsepositives:
  - Legitimate ${request.targetService} traffic
level: ${request.severity}`;
    case "yara":
      return `rule detect_${request.exploitModule.replace(/[^a-zA-Z0-9]/g, "_")} {
  meta:
    description = "Detects ${request.exploitModule} exploit artifacts (${cveStr})"
    author = "AC3 Auto-Generator"
    date = "${now}"
    severity = "${request.severity}"
    reference = "https://nvd.nist.gov/vuln/detail/${cveStr}"
  strings:
    $service = "${request.targetService}" ascii nocase
    $exploit_marker = "${request.exploitModule}" ascii nocase
  condition:
    any of them
}`;
    case "snort":
    case "suricata":
      return `alert tcp any any -> any ${request.targetPort || "any"} (msg:"AC3 - ${request.exploitModule} (${cveStr})"; flow:to_server,established; content:"${request.targetService}"; nocase; classtype:attempted-admin; sid:${1e6 + ruleCounter}; rev:1; metadata:created_at ${now.replace(/-/g, "_")};)`;
    case "kql":
      return `// Detect ${request.exploitModule} (${cveStr})
// Auto-generated by AC3
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort == ${request.targetPort || 0}
| where RemoteUrl has "${request.targetService}"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp desc`;
    case "spl":
      return `| tstats count from datamodel=Network_Traffic where All_Traffic.dest_port=${request.targetPort || 0} by All_Traffic.src All_Traffic.dest All_Traffic.dest_port _time span=1h
| rename All_Traffic.* as *
| where count > 10
| sort -count`;
    default:
      return `# Detection rule for ${request.exploitModule} (${cveStr})`;
  }
}
function clearRuleStore() {
  ruleCache.clear();
  ruleCounter = 0;
  cacheLoaded = false;
}
export {
  clearRuleStore,
  generateDetectionRules,
  getRule,
  getRuleLibrary,
  getRulesByFormat,
  getRulesForCve,
  validateRule
};
