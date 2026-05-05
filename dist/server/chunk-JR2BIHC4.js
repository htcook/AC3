import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/nuclei-output-parser.ts
function parseNucleiJsonOutput(rawOutput) {
  const findings = [];
  const parseErrors = [];
  const stats = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const cveSet = /* @__PURE__ */ new Set();
  const cweSet = /* @__PURE__ */ new Set();
  const templateSet = /* @__PURE__ */ new Set();
  const allExtractedData = [];
  const curlCommands = [];
  if (!rawOutput || rawOutput.trim().length === 0) {
    return {
      findings,
      stats,
      cves: [],
      cwes: [],
      matchedTemplates: [],
      hasExploitableFindings: false,
      highestSeverity: "unknown",
      allExtractedData: [],
      curlCommands: [],
      parseErrors: []
    };
  }
  const lines = rawOutput.split("\n").filter((l) => l.trim().length > 0);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      const raw = JSON.parse(trimmed);
      const finding = normalizeNucleiJson(raw);
      if (finding) {
        findings.push(finding);
        stats.total++;
        const sev = finding.info.severity;
        if (sev === "critical") stats.critical++;
        else if (sev === "high") stats.high++;
        else if (sev === "medium") stats.medium++;
        else if (sev === "low") stats.low++;
        else stats.info++;
        if (finding.info.classification?.cveId) {
          cveSet.add(finding.info.classification.cveId);
        }
        if (/^CVE-\d{4}-\d+$/i.test(finding.templateId)) {
          cveSet.add(finding.templateId.toUpperCase());
        }
        if (finding.info.classification?.cweId) {
          for (const cwe of finding.info.classification.cweId) {
            cweSet.add(cwe);
          }
        }
        templateSet.add(finding.templateId);
        if (finding.extractedResults.length > 0) {
          allExtractedData.push(...finding.extractedResults);
        }
        if (finding.curlCommand) {
          curlCommands.push(finding.curlCommand);
        }
      }
    } catch (err) {
      if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
        parseErrors.push(`Failed to parse JSON line: ${trimmed.slice(0, 100)}... Error: ${err.message}`);
      }
    }
  }
  const severityOrder = ["critical", "high", "medium", "low", "info", "unknown"];
  let highestSeverity = "unknown";
  for (const sev of severityOrder) {
    if (findings.some((f) => f.info.severity === sev)) {
      highestSeverity = sev;
      break;
    }
  }
  const hasExploitableFindings = findings.some(
    (f) => (f.info.severity === "critical" || f.info.severity === "high") && f.matcherStatus && (f.extractedResults.length > 0 || f.info.tags.some((t) => /rce|lfi|sqli|xss|ssrf|cmdi|upload|deserialization|auth.?bypass/i.test(t)))
  );
  return {
    findings,
    stats,
    cves: Array.from(cveSet),
    cwes: Array.from(cweSet),
    matchedTemplates: Array.from(templateSet),
    hasExploitableFindings,
    highestSeverity,
    allExtractedData,
    curlCommands,
    parseErrors
  };
}
function normalizeNucleiJson(raw) {
  if (!raw || typeof raw !== "object") return null;
  const templateId = raw["template-id"] || raw.templateId || raw.template_id;
  if (!templateId) return null;
  const info = raw.info || {};
  const classification = info.classification || {};
  return {
    templateId,
    templatePath: raw["template-path"] || raw.templatePath || raw.template_path,
    info: {
      name: info.name || templateId,
      author: Array.isArray(info.author) ? info.author : info.author ? [info.author] : [],
      tags: Array.isArray(info.tags) ? info.tags : info.tags ? String(info.tags).split(",").map((t) => t.trim()) : [],
      severity: normalizeSeverity(info.severity),
      description: info.description,
      reference: Array.isArray(info.reference) ? info.reference : info.reference ? [info.reference] : [],
      classification: {
        cveId: classification["cve-id"] || classification.cveId || classification.cve_id,
        cweId: Array.isArray(classification["cwe-id"] || classification.cweId || classification.cwe_id) ? classification["cwe-id"] || classification.cweId || classification.cwe_id : classification["cwe-id"] || classification.cweId || classification.cwe_id ? [classification["cwe-id"] || classification.cweId || classification.cwe_id] : void 0,
        cvssMetrics: classification["cvss-metrics"] || classification.cvssMetrics || classification.cvss_metrics,
        cvssScore: classification["cvss-score"] || classification.cvssScore || classification.cvss_score
      }
    },
    type: raw.type || "http",
    host: raw.host || "",
    matchedAt: raw["matched-at"] || raw.matchedAt || raw.matched_at || "",
    extractedResults: Array.isArray(raw["extracted-results"] || raw.extractedResults || raw.extracted_results) ? raw["extracted-results"] || raw.extractedResults || raw.extracted_results : [],
    ip: raw.ip,
    timestamp: raw.timestamp || (/* @__PURE__ */ new Date()).toISOString(),
    curlCommand: raw["curl-command"] || raw.curlCommand || raw.curl_command,
    matcherStatus: raw["matcher-status"] ?? raw.matcherStatus ?? raw.matcher_status ?? true,
    matchedLine: raw["matched-line"] || raw.matchedLine || raw.matched_line || null,
    interaction: raw.interaction
  };
}
function normalizeSeverity(sev) {
  if (!sev) return "unknown";
  const s = String(sev).toLowerCase().trim();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  if (s === "info" || s === "informational") return "info";
  return "unknown";
}
function assessNucleiAccessLevel(result) {
  if (result.findings.length === 0) {
    return { accessLevel: "none", confidence: 90, reasoning: "No Nuclei findings", evidence: [] };
  }
  const evidence = [];
  let accessLevel = "info_disclosure";
  let confidence = 50;
  const allExtracted = result.allExtractedData.join("\n");
  if (/uid=0\(root\)|root:x:0:0/i.test(allExtracted)) {
    accessLevel = "root_shell";
    confidence = 85;
    evidence.push("Root user information extracted (uid=0 or /etc/passwd root entry)");
  }
  if (/uid=\d+|whoami|hostname|uname/i.test(allExtracted) && accessLevel !== "root_shell") {
    accessLevel = "command_execution";
    confidence = 80;
    evidence.push("OS command output extracted (uid, whoami, hostname, or uname)");
  }
  if (/root:.*:0:0|\/bin\/bash|\/etc\/|\/var\/|\/home\//i.test(allExtracted) && accessLevel === "info_disclosure") {
    accessLevel = "file_read";
    confidence = 80;
    evidence.push("File system content extracted (passwd entries, file paths)");
  }
  if (/password[=:]\s*\S+|credentials|api[_-]?key|secret[_-]?key|token[=:]\s*\S+/i.test(allExtracted)) {
    if (accessLevel === "info_disclosure" || accessLevel === "file_read") {
      accessLevel = "credential_access";
      confidence = 75;
      evidence.push("Credentials or API keys extracted from response");
    }
  }
  if (/SELECT|INSERT|UPDATE|DELETE|information_schema|mysql|postgresql/i.test(allExtracted)) {
    accessLevel = "database_access";
    confidence = 80;
    evidence.push("SQL query results or database information extracted");
  }
  const allTags = result.findings.flatMap((f) => f.info.tags);
  if (allTags.some((t) => /^rce$/i.test(t))) {
    if (accessLevel === "info_disclosure" || accessLevel === "file_read") {
      accessLevel = "command_execution";
      confidence = Math.max(confidence, 70);
      evidence.push("Template tagged as RCE (Remote Code Execution)");
    }
  }
  if (allTags.some((t) => /^lfi$/i.test(t) || /^file-inclusion$/i.test(t))) {
    if (accessLevel === "info_disclosure") {
      accessLevel = "file_read";
      confidence = Math.max(confidence, 70);
      evidence.push("Template tagged as LFI (Local File Inclusion)");
    }
  }
  if (allTags.some((t) => /^sqli$/i.test(t) || /^sql-injection$/i.test(t))) {
    if (accessLevel === "info_disclosure") {
      accessLevel = "database_access";
      confidence = Math.max(confidence, 65);
      evidence.push("Template tagged as SQLi (SQL Injection)");
    }
  }
  if (allTags.some((t) => /^auth.?bypass$/i.test(t) || /^default.?login$/i.test(t))) {
    if (accessLevel === "info_disclosure") {
      accessLevel = "credential_access";
      confidence = Math.max(confidence, 65);
      evidence.push("Template tagged as auth bypass or default login");
    }
  }
  if (result.highestSeverity === "critical" && result.allExtractedData.length > 0) {
    confidence = Math.min(95, confidence + 15);
    evidence.push(`Critical severity with ${result.allExtractedData.length} extracted data items`);
  } else if (result.highestSeverity === "high" && result.allExtractedData.length > 0) {
    confidence = Math.min(90, confidence + 10);
    evidence.push(`High severity with ${result.allExtractedData.length} extracted data items`);
  }
  if (result.highestSeverity === "info" && result.allExtractedData.length === 0) {
    accessLevel = "info_disclosure";
    confidence = 60;
    evidence.push("Only informational findings with no extracted data");
  }
  const reasoning = evidence.length > 0 ? `Access level ${accessLevel} determined from: ${evidence.join("; ")}` : `Default info_disclosure \u2014 ${result.stats.total} findings at ${result.highestSeverity} severity`;
  return { accessLevel, confidence, reasoning, evidence };
}
function formatNucleiExploitOutput(result) {
  if (result.findings.length === 0) return "";
  const sections = [];
  sections.push(`\u2550\u2550\u2550 Nuclei Scan Results \u2550\u2550\u2550`);
  sections.push(`Total: ${result.stats.total} findings (Critical: ${result.stats.critical}, High: ${result.stats.high}, Medium: ${result.stats.medium}, Low: ${result.stats.low}, Info: ${result.stats.info})`);
  if (result.cves.length > 0) {
    sections.push(`CVEs: ${result.cves.join(", ")}`);
  }
  sections.push("");
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
  const sorted = [...result.findings].sort(
    (a, b) => (severityOrder[a.info.severity] ?? 5) - (severityOrder[b.info.severity] ?? 5)
  );
  for (const finding of sorted.slice(0, 20)) {
    const sev = finding.info.severity.toUpperCase();
    sections.push(`[${sev}] ${finding.info.name} (${finding.templateId})`);
    sections.push(`  Matched: ${finding.matchedAt}`);
    if (finding.info.classification?.cveId) {
      sections.push(`  CVE: ${finding.info.classification.cveId}`);
    }
    if (finding.info.classification?.cvssScore) {
      sections.push(`  CVSS: ${finding.info.classification.cvssScore}`);
    }
    if (finding.extractedResults.length > 0) {
      sections.push(`  Extracted: ${finding.extractedResults.slice(0, 5).join(" | ").slice(0, 300)}`);
    }
    if (finding.curlCommand) {
      sections.push(`  Reproduce: ${finding.curlCommand.slice(0, 200)}`);
    }
    sections.push("");
  }
  if (sorted.length > 20) {
    sections.push(`... and ${sorted.length - 20} more findings`);
  }
  return sections.join("\n");
}
function addJsonFlag(nucleiCommand) {
  if (/-json\b|-jsonl\b/.test(nucleiCommand)) return nucleiCommand;
  let cmd = nucleiCommand.replace(/\s*2>&1\s*\|\s*head\s+-\d+/, "");
  const pipeIdx = cmd.indexOf("|");
  if (pipeIdx > 0) {
    cmd = cmd.slice(0, pipeIdx).trim() + " -json " + cmd.slice(pipeIdx);
  } else {
    cmd = cmd.trim() + " -json";
  }
  return cmd;
}
var init_nuclei_output_parser = __esm({
  "server/lib/nuclei-output-parser.ts"() {
  }
});

export {
  parseNucleiJsonOutput,
  assessNucleiAccessLevel,
  formatNucleiExploitOutput,
  addJsonFlag,
  init_nuclei_output_parser
};
