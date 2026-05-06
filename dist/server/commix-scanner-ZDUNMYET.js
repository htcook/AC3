import {
  init_zap_scanner,
  mapToMitre
} from "./chunk-JD453J2F.js";
import "./chunk-UK4O2S6Y.js";
import "./chunk-IU7QQ35X.js";
import "./chunk-KKLFDDL7.js";
import {
  executeTool,
  init_scan_server_executor
} from "./chunk-F4SK4FEZ.js";
import "./chunk-YBXDAJGB.js";
import "./chunk-C4KWO5EH.js";
import "./chunk-5TJ6FS74.js";
import "./chunk-UYX5D64U.js";
import "./chunk-SD56WPOS.js";
import "./chunk-435DEVD7.js";
import "./chunk-RUIEEOYK.js";
import {
  getDb,
  init_db
} from "./chunk-MZ5XD5V3.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  webAppFindings
} from "./chunk-GM677ZS3.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/scanners/commix-scanner.ts
function buildCommixCommand(config) {
  const parts = ["commix"];
  parts.push(`--url="${config.targetUrl}"`);
  parts.push("--batch");
  if (config.parameter) parts.push(`-p "${config.parameter}"`);
  if (config.method === "POST") parts.push("--method=POST");
  if (config.postData) parts.push(`--data="${config.postData}"`);
  if (config.cookie) parts.push(`--cookie="${config.cookie}"`);
  if (config.headers) {
    for (const [key, value] of Object.entries(config.headers)) {
      parts.push(`--header="${key}: ${value}"`);
    }
  }
  const level = config.level || 2;
  parts.push(`--level=${level}`);
  if (config.targetOs) parts.push(`--os=${config.targetOs}`);
  if (config.tamper) parts.push(`--tamper="${config.tamper}"`);
  parts.push("--technique=CEFT");
  parts.push("-v 2");
  return parts.join(" ");
}
function parseCommixOutput(output, targetUrl) {
  const findings = [];
  const lines = output.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (/the\s+.*parameter.*is\s+injectable/i.test(trimmed) || /command\s+injection.*identified/i.test(trimmed)) {
      const paramMatch = trimmed.match(/['"]([^'"]+)['"]\s+parameter/i) || trimmed.match(/parameter\s+['"]([^'"]+)['"]/i);
      const techMatch = trimmed.match(/via\s+(.*?)(?:\s+technique|\s+injection|$)/i);
      findings.push({
        type: "cmdi",
        severity: "critical",
        title: `[Commix] Command Injection: ${paramMatch?.[1] || "unknown param"} via ${techMatch?.[1] || "classic"}`,
        url: targetUrl,
        parameter: paramMatch?.[1],
        technique: techMatch?.[1] || "classic",
        rawOutput: trimmed
      });
    }
    if (/time-based\s+blind/i.test(trimmed) && /injectable/i.test(trimmed)) {
      const paramMatch = trimmed.match(/['"]([^'"]+)['"]/);
      findings.push({
        type: "blind_cmdi",
        severity: "critical",
        title: `[Commix] Blind Command Injection (time-based): ${paramMatch?.[1] || "unknown param"}`,
        url: targetUrl,
        parameter: paramMatch?.[1],
        technique: "time-based blind",
        rawOutput: trimmed
      });
    }
    if (/file-based/i.test(trimmed) && /injectable/i.test(trimmed)) {
      const paramMatch = trimmed.match(/['"]([^'"]+)['"]/);
      findings.push({
        type: "blind_cmdi",
        severity: "critical",
        title: `[Commix] Blind Command Injection (file-based): ${paramMatch?.[1] || "unknown param"}`,
        url: targetUrl,
        parameter: paramMatch?.[1],
        technique: "file-based blind",
        rawOutput: trimmed
      });
    }
    if (/^\s*(uid=\d+|root:|www-data:|Linux\s|Windows\s|MINGW)/i.test(trimmed)) {
      if (findings.length > 0) {
        findings[findings.length - 1].osOutput = trimmed;
        findings[findings.length - 1].payload = trimmed;
      }
    }
    if (/eval-based/i.test(trimmed) && /injectable/i.test(trimmed)) {
      const paramMatch = trimmed.match(/['"]([^'"]+)['"]/);
      findings.push({
        type: "cmdi",
        severity: "critical",
        title: `[Commix] Eval-Based Command Injection: ${paramMatch?.[1] || "unknown param"}`,
        url: targetUrl,
        parameter: paramMatch?.[1],
        technique: "eval-based",
        rawOutput: trimmed
      });
    }
  }
  return findings;
}
async function runCommixScan(config) {
  const startTime = Date.now();
  const timeout = config.timeoutSeconds || 120;
  const command = buildCommixCommand(config);
  let result;
  try {
    result = await executeTool({
      tool: "commix",
      command,
      timeout,
      engagementId: config.engagementId
    });
  } catch (err) {
    return {
      targetUrl: config.targetUrl,
      findings: [],
      stats: { durationSeconds: (Date.now() - startTime) / 1e3, parametersTestedCount: 0, injectionsFound: 0, wafDetected: false },
      rawOutput: `Error: ${err.message}`,
      exitCode: -1,
      timedOut: false
    };
  }
  const output = result.stdout + "\n" + result.stderr;
  const findings = parseCommixOutput(output, config.targetUrl);
  const wafDetected = /waf|firewall|blocked|403.*forbidden/i.test(output);
  return {
    targetUrl: config.targetUrl,
    findings,
    stats: {
      durationSeconds: (Date.now() - startTime) / 1e3,
      parametersTestedCount: 1,
      injectionsFound: findings.filter((f) => f.type === "cmdi" || f.type === "blind_cmdi").length,
      wafDetected
    },
    rawOutput: output.slice(0, 1e4),
    exitCode: result.exitCode ?? 0,
    timedOut: result.timedOut || false
  };
}
async function batchCommixScan(urls, config) {
  const results = [];
  const targetUrls = urls.slice(0, 10);
  for (const target of targetUrls) {
    try {
      const result = await runCommixScan({
        targetUrl: target.url,
        engagementId: config.engagementId,
        cookie: config.cookie,
        timeoutSeconds: config.timeoutSeconds || 90,
        level: config.level || 2,
        targetOs: config.targetOs,
        batch: true
      });
      results.push(result);
      if (result.stats.injectionsFound > 0) {
        console.log(`[Commix] CONFIRMED: ${result.stats.injectionsFound} command injection(s) on ${target.url}`);
      }
    } catch (err) {
      console.warn(`[Commix] Error scanning ${target.url}: ${err.message}`);
      results.push({
        targetUrl: target.url,
        findings: [],
        stats: { durationSeconds: 0, parametersTestedCount: 0, injectionsFound: 0, wafDetected: false },
        rawOutput: `Error: ${err.message}`,
        exitCode: -1,
        timedOut: false
      });
    }
  }
  return results;
}
async function ingestCommixToWebAppFindings(results, engagementId, hostname) {
  const db = await getDb();
  if (!db) return { findingsIngested: 0 };
  let ingested = 0;
  for (const result of results) {
    for (const finding of result.findings) {
      if (finding.type !== "cmdi" && finding.type !== "blind_cmdi") continue;
      try {
        const mitre = mapToMitre("Command Injection", finding.title);
        await db.insert(webAppFindings).values({
          engagementId,
          hostname,
          findingType: "command_injection",
          severity: finding.severity,
          title: finding.title,
          description: `Command injection vulnerability found via Commix.
Parameter: ${finding.parameter || "unknown"}
Technique: ${finding.technique || "unknown"}
URL: ${finding.url}`,
          url: finding.url,
          parameter: finding.parameter || null,
          evidence: finding.rawOutput?.slice(0, 4e3) || null,
          payload: finding.payload || null,
          remediation: "Sanitize all user input before passing to OS commands. Use parameterized APIs (e.g., subprocess with list args) instead of shell execution. Implement allowlists for expected input values.",
          tool: "commix",
          confidence: finding.type === "cmdi" ? "confirmed" : "firm",
          mitreAttackId: mitre?.attackId || "T1059",
          mitreAttackName: mitre?.attackName || "Command and Scripting Interpreter",
          cweId: "CWE-78",
          cweName: "OS Command Injection",
          falsePositive: false
        });
        ingested++;
      } catch (err) {
        console.warn(`[Commix] Failed to ingest finding: ${err.message}`);
      }
    }
  }
  return { findingsIngested: ingested };
}
var init_commix_scanner = __esm({
  "server/lib/scanners/commix-scanner.ts"() {
    init_scan_server_executor();
    init_db();
    init_schema();
    init_zap_scanner();
  }
});
init_commix_scanner();
export {
  batchCommixScan,
  ingestCommixToWebAppFindings,
  runCommixScan
};
