import {
  applyPlaybookToZap,
  init_zap_attack_playbooks,
  selectPlaybook,
  zap_attack_playbooks_exports
} from "./chunk-UK4O2S6Y.js";
import {
  GROUND_TRUTH_LIBRARY,
  buildLearningContext,
  init_llm_self_learning
} from "./chunk-IU7QQ35X.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-5EG6U75L.js";
import {
  TECH_SCAN_POLICIES,
  getTechScanPolicyContext,
  getZAPAlertCatalogContext,
  getZAPAuthContext,
  init_zap_pentesting_knowledge
} from "./chunk-E7WGGYZE.js";
import {
  getDb,
  init_db
} from "./chunk-TY7YEWON.js";
import {
  init_schema,
  webAppFindings,
  webAppScans
} from "./chunk-2DDCINQV.js";
import {
  __esm,
  __toCommonJS
} from "./chunk-KFQGP6VL.js";

// server/lib/zap-scanner.ts
import { eq, desc, and, sql } from "drizzle-orm";
import { HttpProxyAgent } from "http-proxy-agent";
import http from "http";
function detectTargetPreset(targetUrl) {
  const urlLower = targetUrl.toLowerCase();
  for (const { preset, patterns } of TARGET_PRESET_PATTERNS) {
    for (const pattern of patterns) {
      if (pattern.test(urlLower)) return preset;
    }
  }
  for (const preset of Object.keys(GROUND_TRUTH_LIBRARY)) {
    if (urlLower.includes(preset.replace(/-/g, ""))) return preset;
  }
  return void 0;
}
async function zapRequest(endpoint, params = {}, config = DEFAULT_ZAP_CONFIG) {
  const apiUrl = new URL(`http://zap${endpoint}`);
  apiUrl.searchParams.set("apikey", config.apiKey);
  for (const [k, v] of Object.entries(params)) {
    apiUrl.searchParams.set(k, v);
  }
  const agent = new HttpProxyAgent(config.baseUrl);
  const response = await new Promise((resolve, reject) => {
    const reqUrl = apiUrl.toString();
    const req = http.get(reqUrl, { agent, timeout: 6e4 }, (res) => {
      let data = "";
      res.on("data", (chunk) => data += chunk);
      res.on("end", () => {
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          statusText: res.statusMessage || "",
          json: () => JSON.parse(data)
        });
      });
    });
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("ZAP request timeout"));
    });
  });
  if (!response.ok) {
    let responseBody = "";
    try {
      responseBody = JSON.stringify(response.json()).substring(0, 200);
    } catch {
    }
    console.error(`[ZAP API] ${response.status} ${response.statusText} at ${endpoint} | params: ${JSON.stringify(params).substring(0, 200)} | body: ${responseBody}`);
    throw new Error(`ZAP API error: ${response.status} ${response.statusText} at ${endpoint}`);
  }
  return response.json();
}
function mapZapRisk(risk) {
  const riskLower = (risk || "").toLowerCase();
  if (riskLower === "high") return "high";
  if (riskLower === "medium") return "medium";
  if (riskLower === "low") return "low";
  if (riskLower === "informational" || riskLower === "info") return "info";
  return "medium";
}
function mapZapConfidence(confidence) {
  const c = (confidence || "").toLowerCase();
  if (c === "high" || c === "confirmed") return 0.9;
  if (c === "medium") return 0.7;
  if (c === "low") return 0.4;
  if (c === "false positive") return 0.1;
  return 0.5;
}
function mapToMitre(cweId, alertName) {
  if (cweId && CWE_TO_MITRE[cweId]) return CWE_TO_MITRE[cweId];
  for (const [pattern, mapping] of Object.entries(ALERT_NAME_TO_MITRE)) {
    if (alertName.toLowerCase().includes(pattern.toLowerCase())) return mapping;
  }
  return null;
}
function findMsfModules(cweId) {
  if (!cweId) return [];
  return CWE_TO_MSF_MODULES[cweId] || [];
}
async function generateLLMScanConfig(params) {
  const techKnowledge = params.techStackHints?.length ? getTechScanPolicyContext(params.techStackHints[0]) : "";
  const authKnowledge = params.authHints ? getZAPAuthContext(params.authHints.type) : "";
  const alertKnowledge = params.scanMode === "active" ? getZAPAlertCatalogContext("high") : "";
  const dynamicKnowledge = [techKnowledge, authKnowledge, alertKnowledge].filter(Boolean).join("\n\n");
  let learningFeedback = "";
  if (params.targetPreset) {
    try {
      const learningCtx = await buildLearningContext(params.targetPreset);
      if (learningCtx) {
        learningFeedback = `

## SELF-LEARNING FEEDBACK FROM PREVIOUS SCANS
${learningCtx}

Based on the above feedback:
- If vulnerabilities were MISSED: ensure the corresponding ZAP scan rules are ENABLED at HIGH strength and INSANE threshold
- If injection vulns were missed: enable ALL injection rules (40018-40027 for SQLi, 90019 for code injection, 90020 for OS command injection)
- If XSS was missed: enable 40012, 40014, 40016 at INSANE threshold AND set useAjaxSpider=true for DOM XSS
- If CSRF was missed: set handleAntiCSRFTokens=true
- If auth bypass was missed: enable forced browsing rules and set postForm=true in spider
- If file inclusion was missed: enable rules 6 (Path Traversal) and 7 (Remote File Inclusion) at HIGH/INSANE
- If SSRF was missed: enable rule 40046 at HIGH/INSANE
- ALWAYS use AJAX spider if DOM-based XSS or client-side vulns were previously missed
`;
      }
    } catch (e) {
      console.warn(`[ZAP LLM Config] Failed to build learning context: ${e.message}`);
    }
  }
  const userPrompt = `Analyze this target and generate optimal ZAP scan configuration:

**Target URL**: ${params.targetUrl}
**Scan Mode**: ${params.scanMode} (${params.scanMode === "passive" ? "spider + passive scan only, NO active attacks" : "full active DAST with vulnerability exploitation"})
${params.techStackHints?.length ? `**Known Technologies**: ${params.techStackHints.join(", ")}` : "**Known Technologies**: Unknown \u2014 detect from response headers and content"}
${params.authHints ? `**Authentication**: Type=${params.authHints.type}, Login URL=${params.authHints.loginUrl || "unknown"}` : "**Authentication**: None configured"}
${params.scopeConstraints?.length ? `**Scope Constraints**: ${params.scopeConstraints.join(", ")}` : ""}

${params.scanMode === "passive" ? "Configure for maximum URL discovery and passive vulnerability detection WITHOUT any active attacks. Focus on spider depth, technology fingerprinting, and passive scan rules." : "Configure for thorough active vulnerability testing. Enable all relevant attack categories. Optimize for the detected technology stack."}
${dynamicKnowledge ? "\n\n## ZAP Knowledge Base Reference\n" + dynamicKnowledge : ""}
${learningFeedback}`;
  try {
    const response = await throttledLLMCall({
      messages: [
        { role: "system", content: ZAP_ORCHESTRATOR_SYSTEM_PROMPT },
        { role: "user", content: userPrompt }
      ],
      _caller: "zap-scanner.generateLLMScanConfig",
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "zap_scan_config",
          strict: true,
          schema: {
            type: "object",
            properties: {
              scanPolicy: { type: "string" },
              useAjaxSpider: { type: "boolean" },
              spiderConfig: {
                type: "object",
                properties: {
                  maxDepth: { type: "number" },
                  maxChildren: { type: "number" },
                  threadCount: { type: "number" },
                  parseComments: { type: "boolean" },
                  parseGit: { type: "boolean" },
                  parseSitemapXml: { type: "boolean" },
                  postForm: { type: "boolean" }
                },
                required: ["maxDepth", "maxChildren", "threadCount", "parseComments", "parseGit", "parseSitemapXml", "postForm"],
                additionalProperties: false
              },
              ajaxSpiderConfig: {
                type: "object",
                properties: {
                  maxCrawlDepth: { type: "number" },
                  maxCrawlStates: { type: "number" },
                  maxDuration: { type: "number" },
                  numberOfBrowsers: { type: "number" },
                  clickDefaultElems: { type: "boolean" }
                },
                required: ["maxCrawlDepth", "maxCrawlStates", "maxDuration", "numberOfBrowsers", "clickDefaultElems"],
                additionalProperties: false
              },
              activeScanConfig: {
                type: "object",
                properties: {
                  threadPerHost: { type: "number" },
                  delayInMs: { type: "number" },
                  handleAntiCSRFTokens: { type: "boolean" },
                  scanHeadersAllRequests: { type: "boolean" },
                  maxRuleDurationInMins: { type: "number" }
                },
                required: ["threadPerHost", "delayInMs", "handleAntiCSRFTokens", "scanHeadersAllRequests", "maxRuleDurationInMins"],
                additionalProperties: false
              },
              technologies: { type: "array", items: { type: "string" } },
              authStrategy: { type: "string" },
              authConfig: { type: "object", additionalProperties: true },
              contextIncludes: { type: "array", items: { type: "string" } },
              contextExcludes: { type: "array", items: { type: "string" } },
              importSpec: {
                anyOf: [
                  { type: "null" },
                  {
                    type: "object",
                    properties: {
                      type: { type: "string" },
                      url: { type: "string" }
                    },
                    required: ["type", "url"],
                    additionalProperties: false
                  }
                ]
              },
              customRules: { type: "array", items: { type: "string" } },
              rationale: { type: "string" }
            },
            required: ["scanPolicy", "useAjaxSpider", "spiderConfig", "ajaxSpiderConfig", "activeScanConfig", "technologies", "authStrategy", "authConfig", "contextIncludes", "contextExcludes", "importSpec", "customRules", "rationale"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (typeof content === "string") {
      return JSON.parse(content);
    }
    throw new Error("LLM returned non-string content");
  } catch (err) {
    console.error(`[ZAP LLM Orchestrator] Failed to generate config after retries: ${err.message}`);
    console.log(`[ZAP LLM Orchestrator] Using knowledge-driven fallback for tech hints: [${params.techStackHints?.join(", ") || "none"}], target: ${params.targetUrl}`);
    return getDefaultScanConfig(params.scanMode, params.techStackHints, void 0, params.targetUrl);
  }
}
function getDefaultScanConfig(mode, techStackHints, wafVendor, targetUrl) {
  let matchedPolicy;
  const allHints = [...techStackHints || []];
  if (targetUrl) {
    if (targetUrl.includes(".php") || targetUrl.includes("php")) allHints.push("PHP");
    if (targetUrl.includes(".asp") || targetUrl.includes(".aspx")) allHints.push("ASP.NET");
    if (targetUrl.includes(".jsp") || targetUrl.includes(".do") || targetUrl.includes(".action")) allHints.push("Java");
    if (targetUrl.includes("wp-") || targetUrl.includes("wordpress")) allHints.push("WordPress");
    if (targetUrl.includes("/api/") || targetUrl.includes("/graphql")) allHints.push("API");
  }
  const serverPatterns = {
    "apache": "PHP",
    // Apache commonly serves PHP
    "nginx": "PHP",
    // nginx commonly serves PHP
    "iis": "ASP.NET",
    "tomcat": "Java/Spring",
    "jetty": "Java/Spring",
    "express": "Node.js/Express",
    "kestrel": "ASP.NET",
    "gunicorn": "Python/Django/Flask",
    "uwsgi": "Python/Django/Flask",
    "werkzeug": "Python/Django/Flask",
    "wordpress": "WordPress",
    "wp-": "WordPress",
    "php": "PHP"
  };
  for (const hint of allHints) {
    const lowerHint = hint.toLowerCase();
    matchedPolicy = TECH_SCAN_POLICIES.find(
      (p) => p.technology.toLowerCase().includes(lowerHint) || p.fingerprints.some((f) => f.toLowerCase().includes(lowerHint)) || lowerHint.includes(p.technology.split("/")[0].toLowerCase())
    );
    if (matchedPolicy) break;
    for (const [pattern, tech] of Object.entries(serverPatterns)) {
      if (lowerHint.includes(pattern)) {
        matchedPolicy = TECH_SCAN_POLICIES.find((p) => p.technology === tech);
        if (matchedPolicy) break;
      }
    }
    if (matchedPolicy) break;
  }
  console.log(`[ZAP Smart Fallback] Hints: [${allHints.join(", ")}], Matched: ${matchedPolicy?.technology || "none (using generic defaults)"}`);
  const baseConfig = {
    scanPolicy: matchedPolicy ? `Knowledge-${matchedPolicy.technology}` : "Default Policy",
    useAjaxSpider: matchedPolicy?.useAjaxSpider ?? false,
    spiderConfig: {
      maxDepth: mode === "passive" ? 5 : 8,
      maxChildren: mode === "passive" ? 20 : 50,
      threadCount: 5,
      parseComments: matchedPolicy?.spiderConfig?.parseComments ?? true,
      parseGit: matchedPolicy?.spiderConfig?.parseGit ?? true,
      parseSitemapXml: true,
      postForm: matchedPolicy?.spiderConfig?.postForm ?? mode === "active"
    },
    ajaxSpiderConfig: {
      maxCrawlDepth: 5,
      maxCrawlStates: 1e4,
      maxDuration: 10,
      numberOfBrowsers: 2,
      clickDefaultElems: true
    },
    activeScanConfig: {
      threadPerHost: 5,
      delayInMs: 20,
      handleAntiCSRFTokens: true,
      scanHeadersAllRequests: true,
      maxRuleDurationInMins: 10
    },
    technologies: matchedPolicy ? [matchedPolicy.technology] : [],
    authStrategy: "none",
    authConfig: {},
    contextIncludes: [],
    contextExcludes: matchedPolicy?.contextExcludes || [".*\\.(js|css|png|jpg|gif|svg|ico|woff|woff2|ttf|eot)$"],
    importSpec: null,
    customRules: matchedPolicy ? matchedPolicy.criticalRules.map((r) => `Rule ${r.id}: ${r.strength}/${r.threshold} \u2014 ${r.reason}`) : [],
    rationale: matchedPolicy ? `Knowledge-driven config: ${matchedPolicy.technology} policy applied (${matchedPolicy.criticalRules.length} critical rules). Tech-specific scan profile selected automatically.` : "Balanced scan configuration applied. Technology-specific tuning will be applied when LLM analysis completes."
  };
  if (wafVendor) {
    return applyWafEvasionConfig(baseConfig, wafVendor);
  }
  return baseConfig;
}
function getWafEvasionProfile(wafVendor) {
  if (WAF_EVASION_PROFILES[wafVendor]) return WAF_EVASION_PROFILES[wafVendor];
  const key = Object.keys(WAF_EVASION_PROFILES).find(
    (k) => k.toLowerCase().includes(wafVendor.toLowerCase()) || wafVendor.toLowerCase().includes(k.toLowerCase())
  );
  if (key) return WAF_EVASION_PROFILES[key];
  return {
    name: `Generic WAF Evasion (${wafVendor})`,
    maxReqPerSec: 2,
    delayInMs: 500,
    threadPerHost: 1,
    spiderThreads: 2,
    maxRuleDurationInMins: 20,
    useAjaxSpider: false,
    rotateUserAgents: true,
    encodePayloads: true,
    techniques: [
      "Use slower scan rate to avoid rate-based blocking",
      "Rotate User-Agent headers between browser variants",
      "Use encoded payloads for injection tests",
      "Avoid common attack signatures in URLs"
    ]
  };
}
function applyWafEvasionConfig(config, wafVendor) {
  const profile = getWafEvasionProfile(wafVendor);
  console.log(`[ZAP WAF Evasion] Applying ${profile.name}: ${profile.delayInMs}ms delay, ${profile.threadPerHost} threads, ${profile.techniques.length} techniques`);
  return {
    ...config,
    useAjaxSpider: profile.useAjaxSpider || config.useAjaxSpider,
    spiderConfig: {
      ...config.spiderConfig,
      threadCount: Math.min(config.spiderConfig.threadCount, profile.spiderThreads)
    },
    activeScanConfig: {
      ...config.activeScanConfig,
      threadPerHost: profile.threadPerHost,
      delayInMs: profile.delayInMs,
      maxRuleDurationInMins: profile.maxRuleDurationInMins
    },
    customRules: [
      ...config.customRules,
      `WAF_EVASION: ${profile.name}`,
      ...profile.techniques
    ],
    rationale: `${config.rationale} | WAF Evasion: ${profile.name} applied \u2014 ${profile.delayInMs}ms delay, ${profile.threadPerHost} thread(s), ${profile.techniques.length} bypass techniques.`
  };
}
async function triageFinding(finding) {
  try {
    const response = await throttledLLMCall({
      messages: [
        {
          role: "system",
          content: `You are a web application security expert performing triage on OWASP ZAP scan findings. Assess each finding for false positive likelihood based on the evidence, URL context, parameter name, and technology stack. Consider common ZAP false positive patterns:
- Generic XSS alerts on static content or JSON responses
- SQL injection alerts on non-database parameters (search terms, pagination)
- CSRF alerts on GET requests or public endpoints
- Missing header alerts that may be handled by CDN/proxy
- Path traversal alerts that return 404 or generic error pages

Return JSON with: verdict (true_positive|likely_positive|needs_review|likely_false_positive|false_positive), reason (brief explanation), falsePositiveScore (0.0=definitely real, 1.0=definitely FP).`
        },
        {
          role: "user",
          content: `Triage this finding:
Alert: ${finding.alertName}
Severity: ${finding.severity}
URL: ${finding.url}
Parameter: ${finding.param || "N/A"}
Evidence: ${(finding.evidence || "").substring(0, 500)}
CWE: ${finding.cweId || "N/A"}
Tech Stack: ${finding.targetTechStack?.join(", ") || "Unknown"}`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "triage_result",
          strict: true,
          schema: {
            type: "object",
            properties: {
              verdict: { type: "string", enum: ["true_positive", "likely_positive", "needs_review", "likely_false_positive", "false_positive"] },
              reason: { type: "string" },
              falsePositiveScore: { type: "number" }
            },
            required: ["verdict", "reason", "falsePositiveScore"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (typeof content === "string") {
      return JSON.parse(content);
    }
    throw new Error("LLM returned non-string content");
  } catch (err) {
    return {
      verdict: "needs_review",
      reason: `AI triage unavailable: ${err.message}`,
      falsePositiveScore: 0.5
    };
  }
}
async function restartZapDocker() {
  const now = Date.now();
  if (now - lastZapRestart < ZAP_RESTART_COOLDOWN_MS) {
    console.warn(`[ZAP Recovery] Restart cooldown active (${Math.round((ZAP_RESTART_COOLDOWN_MS - (now - lastZapRestart)) / 1e3)}s remaining). Skipping restart.`);
    return false;
  }
  try {
    const { executeViaChildProcessSSH } = await import("./scan-server-executor-YX4MKSRW.js");
    console.log(`[ZAP Recovery] Restarting ZAP Docker container via SSH...`);
    const result = await executeViaChildProcessSSH("docker restart zap", 60);
    if (result.exitCode === 0) {
      lastZapRestart = Date.now();
      console.log(`[ZAP Recovery] ZAP container restarted successfully. Waiting for startup...`);
      await new Promise((r) => setTimeout(r, 6e4));
      return true;
    } else {
      console.error(`[ZAP Recovery] Docker restart failed: exit=${result.exitCode} ${result.stderr}`);
      return false;
    }
  } catch (err) {
    console.error(`[ZAP Recovery] Failed to restart ZAP: ${err.message}`);
    return false;
  }
}
async function checkZapHealth(config) {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...config };
  try {
    const result = await zapRequest("/JSON/core/view/version/", {}, cfg);
    return { available: true, version: result.version };
  } catch (err) {
    console.warn(`[ZAP Health] ZAP unreachable at ${cfg.baseUrl}: ${err.message}. Attempting auto-restart...`);
    const restarted = await restartZapDocker();
    if (restarted) {
      try {
        const result = await zapRequest("/JSON/core/view/version/", {}, cfg);
        return { available: true, version: result.version, restarted: true };
      } catch (retryErr) {
        return { available: false, error: `ZAP still unreachable after restart: ${retryErr.message}`, restarted: true };
      }
    }
    return { available: false, error: err.message };
  }
}
async function importOpenApiSpec(params) {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...params.config };
  const errors = [];
  try {
    const reqParams = {};
    if (params.specUrl) {
      reqParams.url = params.specUrl;
    } else if (params.specContent) {
      reqParams.file = params.specContent;
    } else {
      return { success: false, endpointsImported: 0, errors: ["Either specUrl or specContent is required"] };
    }
    if (params.targetUrl) {
      reqParams.hostOverride = params.targetUrl;
    }
    if (params.contextId) {
      reqParams.contextId = params.contextId;
    }
    const result = await zapRequest("/JSON/openapi/action/importUrl/", reqParams, cfg);
    const sitesResult = await zapRequest("/JSON/core/view/urls/", {}, cfg).catch(() => ({ urls: [] }));
    const endpointsImported = (sitesResult.urls || []).length;
    return { success: true, endpointsImported, errors };
  } catch (err) {
    errors.push(`OpenAPI import failed: ${err.message}`);
    return { success: false, endpointsImported: 0, errors };
  }
}
async function importGraphQLSpec(params) {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...params.config };
  const errors = [];
  try {
    const reqParams = {};
    if (params.endpointUrl) {
      reqParams.endurl = params.endpointUrl;
    }
    if (params.schemaUrl) {
      reqParams.schemaUrl = params.schemaUrl;
    } else if (params.schemaContent) {
      reqParams.schemaFile = params.schemaContent;
    }
    if (params.targetUrl) {
      reqParams.url = params.targetUrl;
    }
    if (params.maxQueryDepth) {
      await zapRequest("/JSON/graphql/action/setOptionMaxQueryDepth/", {
        Integer: String(params.maxQueryDepth)
      }, cfg).catch(() => {
      });
    }
    await zapRequest("/JSON/graphql/action/setOptionOptionalArgsEnabled/", {
      Boolean: "true"
    }, cfg).catch(() => {
    });
    const result = await zapRequest("/JSON/graphql/action/importUrl/", reqParams, cfg);
    const sitesResult = await zapRequest("/JSON/core/view/urls/", {}, cfg).catch(() => ({ urls: [] }));
    const graphqlUrls = (sitesResult.urls || []).filter((u) => u.includes("graphql"));
    return {
      success: true,
      queriesImported: Math.max(graphqlUrls.length, 1),
      mutationsImported: 0,
      errors
    };
  } catch (err) {
    errors.push(`GraphQL import failed: ${err.message}`);
    return { success: false, queriesImported: 0, mutationsImported: 0, errors };
  }
}
async function importSoapSpec(params) {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...params.config };
  const errors = [];
  try {
    const reqParams = {};
    if (params.wsdlUrl) {
      reqParams.url = params.wsdlUrl;
    } else if (params.wsdlContent) {
      reqParams.file = params.wsdlContent;
    } else {
      return { success: false, operationsImported: 0, errors: ["Either wsdlUrl or wsdlContent is required"] };
    }
    const result = await zapRequest("/JSON/soap/action/importUrl/", reqParams, cfg);
    return { success: true, operationsImported: 1, errors };
  } catch (err) {
    errors.push(`SOAP import failed: ${err.message}`);
    return { success: false, operationsImported: 0, errors };
  }
}
async function cleanupStaleScansForTarget(targetUrl, cfg = DEFAULT_ZAP_CONFIG) {
  const errors = [];
  let stoppedSpiders = 0;
  let stoppedAscans = 0;
  try {
    const targetHost = new URL(targetUrl).hostname;
    try {
      const spiderScans = await zapRequest("/JSON/spider/view/scans/", {}, cfg);
      const scans = spiderScans.scans || [];
      for (const scan of scans) {
        const state = (scan.state || "").toUpperCase();
        if (state === "RUNNING" || state === "NOT_STARTED") {
          try {
            await zapRequest("/JSON/spider/action/stop/", { scanId: String(scan.id) }, cfg);
            stoppedSpiders++;
            console.log(`[ZAP Cleanup] Stopped stale spider #${scan.id} (state=${state})`);
          } catch (e) {
            errors.push(`Failed to stop spider #${scan.id}: ${e.message}`);
          }
        }
      }
    } catch (e) {
      errors.push(`Failed to list spiders: ${e.message}`);
    }
    try {
      const ascanScans = await zapRequest("/JSON/ascan/view/scans/", {}, cfg);
      const scans = ascanScans.scans || [];
      for (const scan of scans) {
        const state = (scan.state || "").toUpperCase();
        if (state === "RUNNING" || state === "PAUSED") {
          try {
            await zapRequest("/JSON/ascan/action/stop/", { scanId: String(scan.id) }, cfg);
            stoppedAscans++;
            console.log(`[ZAP Cleanup] Stopped stale active scan #${scan.id} (state=${state})`);
          } catch (e) {
            errors.push(`Failed to stop ascan #${scan.id}: ${e.message}`);
          }
        }
      }
    } catch (e) {
      errors.push(`Failed to list active scans: ${e.message}`);
    }
    if (stoppedSpiders > 0 || stoppedAscans > 0) {
      try {
        await zapRequest("/JSON/spider/action/removeAllScans/", {}, cfg);
        console.log(`[ZAP Cleanup] Removed all spider scan records from ZAP memory`);
      } catch (e) {
        errors.push(`Failed to remove spider records: ${e.message}`);
      }
      try {
        await zapRequest("/JSON/ascan/action/removeAllScans/", {}, cfg);
        console.log(`[ZAP Cleanup] Removed all active scan records from ZAP memory`);
      } catch (e) {
        errors.push(`Failed to remove ascan records: ${e.message}`);
      }
    }
    console.log(`[ZAP Cleanup] Target: ${targetUrl} \u2014 stopped ${stoppedSpiders} spiders, ${stoppedAscans} active scans, ${errors.length} errors`);
  } catch (e) {
    errors.push(`Cleanup failed: ${e.message}`);
    console.error(`[ZAP Cleanup] Fatal error: ${e.message}`);
  }
  return { stoppedSpiders, stoppedAscans, errors };
}
async function startScan(params) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...params.config };
  const health = await checkZapHealth(params.config);
  if (!health.available) {
    throw new Error(`ZAP is not available: ${health.error}. Please check the ZAP Docker container on the scan server.`);
  }
  if (health.restarted) {
    console.log(`[ZAP startScan] ZAP was auto-restarted before scan. Version: ${health.version}`);
  }
  let parsedUrl;
  try {
    parsedUrl = new URL(params.targetUrl);
  } catch {
    throw new Error(`Invalid target URL: ${params.targetUrl}`);
  }
  try {
    const cleanup = await cleanupStaleScansForTarget(params.targetUrl, cfg);
    if (cleanup.stoppedSpiders > 0 || cleanup.stoppedAscans > 0) {
      console.log(`[ZAP startScan] Pre-scan cleanup: stopped ${cleanup.stoppedSpiders} spiders + ${cleanup.stoppedAscans} active scans for ${parsedUrl.hostname}`);
      await new Promise((r) => setTimeout(r, 2e3));
    }
  } catch (cleanupErr) {
    console.warn(`[ZAP startScan] Pre-scan cleanup failed (non-fatal): ${cleanupErr.message}`);
  }
  const effectiveScanName = params.scanName || `${params.scanMode === "passive" ? "[RECON]" : "[DAST]"} ${parsedUrl.hostname}`;
  const [existingScan] = await db.select({ id: webAppScans.id, status: webAppScans.status }).from(webAppScans).where(and(
    eq(webAppScans.scanName, effectiveScanName),
    eq(webAppScans.targetUrl, params.targetUrl)
  )).limit(1);
  if (existingScan && existingScan.status !== "error") {
    console.log(`[ZAP Dedup] Scan already exists: ${effectiveScanName} \u2192 id=${existingScan.id} (status=${existingScan.status}). Returning existing.`);
    return { scanId: existingScan.id, status: existingScan.status, llmConfig: params.llmConfig, deduplicated: true };
  }
  if (existingScan && existingScan.status === "error") {
    console.log(`[ZAP Dedup] Previous scan errored: ${effectiveScanName} \u2192 id=${existingScan.id}. Allowing retry with new scan.`);
  }
  const targetPreset = params.targetPreset || detectTargetPreset(params.targetUrl);
  const llmConfig = params.llmConfig || await generateLLMScanConfig({
    targetUrl: params.targetUrl,
    scanMode: params.scanMode,
    techStackHints: params.discoveredTechnologies,
    targetPreset
  });
  if (targetPreset) {
    console.log(`[ZAP Self-Learning] Target preset detected: ${targetPreset} \u2014 learning feedback injected into scan config`);
  }
  const technologies = params.discoveredTechnologies || llmConfig.technologies || [];
  const playbookPhase = params.playbookPhase || (params.scanMode === "active" ? "full" : "crawling");
  const playbook = selectPlaybook(playbookPhase, technologies, {
    useAjaxSpider: llmConfig.useAjaxSpider,
    apiSpec: params.openApiSpecUrl ? { type: "openapi", url: params.openApiSpecUrl } : params.graphqlEndpointUrl ? { type: "graphql", url: params.graphqlEndpointUrl } : params.soapWsdlUrl ? { type: "soap", url: params.soapWsdlUrl } : void 0
  });
  let effectivePlaybook = playbook;
  if (params.trainingLabMode) {
    const { buildTrainingLabPlaybook } = await import("./zap-attack-playbooks-WEEXKOAB.js");
    effectivePlaybook = buildTrainingLabPlaybook();
    console.log(`[ZAP Training Lab] Using focused fast playbook: ${effectivePlaybook.enabledRules.length} rules (was ${playbook.enabledRules.length}), threads=${effectivePlaybook.activeScanOverrides?.threadPerHost}, maxRuleDuration=${effectivePlaybook.activeScanOverrides?.maxRuleDurationInMins}min`);
  }
  console.log(`[ZAP Playbook] Selected: ${effectivePlaybook.name} with ${effectivePlaybook.enabledRules.length} rules for tech: [${technologies.join(", ")}]`);
  const effectiveScanType = params.scanMode === "passive" ? "spider_only" : params.scanType;
  const [result] = await db.insert(webAppScans).values({
    targetUrl: params.targetUrl,
    scanName: params.scanName || `${params.scanMode === "passive" ? "[RECON]" : "[DAST]"} ${parsedUrl.hostname}`,
    scanType: effectiveScanType,
    scanMode: params.scanMode,
    status: "starting",
    startedBy: params.userId,
    startedAt: /* @__PURE__ */ new Date(),
    spiderProgress: 0,
    activeScanProgress: 0,
    alertCounts: JSON.stringify({ high: 0, medium: 0, low: 0, info: 0 }),
    llmScanConfig: JSON.stringify(llmConfig),
    scanPolicyName: llmConfig.scanPolicy,
    ajaxSpiderUsed: llmConfig.useAjaxSpider,
    detectedTechStack: JSON.stringify(llmConfig.technologies),
    attackChainId: params.attackChainId || null,
    calderaOperationId: params.calderaOperationId || null,
    metasploitSessionId: params.metasploitSessionId || null,
    domainIntelScanId: params.domainIntelScanId || null
  });
  const scanId = result.insertId;
  try {
    let specImportResult = null;
    const specToImport = params.openApiSpecUrl ? { type: "openapi", url: params.openApiSpecUrl } : params.graphqlEndpointUrl || params.graphqlSchemaUrl ? { type: "graphql", url: params.graphqlEndpointUrl || params.graphqlSchemaUrl } : params.soapWsdlUrl ? { type: "soap", url: params.soapWsdlUrl } : llmConfig.importSpec;
    if (specToImport) {
      try {
        if (specToImport.type === "openapi") {
          specImportResult = await importOpenApiSpec({
            specUrl: specToImport.url,
            targetUrl: params.targetUrl,
            config: params.config
          });
        } else if (specToImport.type === "graphql") {
          specImportResult = await importGraphQLSpec({
            endpointUrl: specToImport.url,
            targetUrl: params.targetUrl,
            config: params.config
          });
        } else if (specToImport.type === "soap") {
          specImportResult = await importSoapSpec({
            wsdlUrl: specToImport.url,
            config: params.config
          });
        }
      } catch (err) {
        specImportResult = { success: false, errors: [err.message] };
      }
    }
    const zapApiCfg = { baseUrl: cfg.baseUrl, apiKey: cfg.apiKey };
    try {
      const ctxResult = await zapRequest("/JSON/context/action/newContext/", {
        contextName: `scan-${scanId}`
      }, cfg);
      const contextId = ctxResult.contextId;
      const includes = llmConfig.contextIncludes?.length ? llmConfig.contextIncludes : [`${parsedUrl.origin}.*`];
      for (const pattern of includes) {
        await zapRequest("/JSON/context/action/includeInContext/", {
          contextName: `scan-${scanId}`,
          regex: pattern
        }, cfg).catch(() => {
        });
      }
      for (const pattern of llmConfig.contextExcludes || []) {
        await zapRequest("/JSON/context/action/excludeFromContext/", {
          contextName: `scan-${scanId}`,
          regex: pattern
        }, cfg).catch(() => {
        });
      }
      if (technologies.length > 0) {
        await zapRequest("/JSON/context/action/excludeAllContextTechnologies/", {
          contextName: `scan-${scanId}`
        }, cfg).catch(() => {
        });
        for (const tech of technologies) {
          await zapRequest("/JSON/context/action/includeContextTechnologies/", {
            contextName: `scan-${scanId}`,
            technologyName: tech
          }, cfg).catch(() => {
          });
        }
      }
      console.log(`[ZAP Context] Created context scan-${scanId} with ${includes.length} includes, ${technologies.length} technologies`);
    } catch (err) {
      console.warn(`[ZAP Context] Failed to create context: ${err.message} \u2014 continuing with default`);
    }
    if (effectivePlaybook && params.scanMode === "active") {
      console.log(`[ZAP Playbook] Pre-applying ${effectivePlaybook.name} (${effectivePlaybook.enabledRules.length} enabled, ${(effectivePlaybook.disabledRuleIds || []).length} disabled)`);
      const pbResult = await applyPlaybookToZap(effectivePlaybook, zapApiCfg, zapRequest);
      console.log(`[ZAP Playbook] Applied: ${pbResult.applied ? "success" : "partial"}, ${pbResult.errors.length} errors`);
    }
    if (llmConfig.spiderConfig) {
      const sc = llmConfig.spiderConfig;
      await zapRequest("/JSON/spider/action/setOptionMaxDepth/", { Integer: String(sc.maxDepth) }, cfg).catch(() => {
      });
      await zapRequest("/JSON/spider/action/setOptionMaxChildren/", { Integer: String(sc.maxChildren) }, cfg).catch(() => {
      });
      await zapRequest("/JSON/spider/action/setOptionThreadCount/", { Integer: String(sc.threadCount) }, cfg).catch(() => {
      });
      await zapRequest("/JSON/spider/action/setOptionParseComments/", { Boolean: String(sc.parseComments) }, cfg).catch(() => {
      });
      await zapRequest("/JSON/spider/action/setOptionParseSitemapXml/", { Boolean: String(sc.parseSitemapXml) }, cfg).catch(() => {
      });
      await zapRequest("/JSON/spider/action/setOptionPostForm/", { Boolean: String(sc.postForm) }, cfg).catch(() => {
      });
    }
    console.log(`[ZAP startScan] Scan #${scanId}: target=${params.targetUrl}, type=${params.scanType}, mode=${params.scanMode}, trainingLab=${params.trainingLabMode}, seedUrls=${params.seedUrls?.length || 0}`);
    if (params.seedUrls && params.seedUrls.length > 0) {
      console.log(`[ZAP Seed URLs] Pre-loading ${params.seedUrls.length} seed URLs into ZAP site tree (first 3: ${params.seedUrls.slice(0, 3).join(", ")})`);
      const seedResults = await Promise.allSettled(
        params.seedUrls.map(
          (seedUrl) => zapRequest("/JSON/core/action/accessUrl/", { url: seedUrl, followRedirects: "true" }, cfg).catch((err) => console.warn(`[ZAP Seed] Failed to access ${seedUrl}: ${err.message}`))
        )
      );
      const seeded = seedResults.filter((r) => r.status === "fulfilled").length;
      console.log(`[ZAP Seed URLs] Successfully seeded ${seeded}/${params.seedUrls.length} URLs`);
    }
    console.log(`[ZAP Spider] Scan #${scanId}: Starting spider on ${params.targetUrl}`);
    const spiderResult = await zapRequest("/JSON/spider/action/scan/", {
      url: params.targetUrl,
      maxchildren: String(llmConfig.spiderConfig?.maxChildren || cfg.spiderMaxChildren),
      recurse: "true",
      subtreeonly: "true"
    }, cfg);
    const spiderScanId = spiderResult.scan;
    await db.update(webAppScans).set({
      status: "spidering",
      zapSpiderScanId: String(spiderScanId)
    }).where(eq(webAppScans.id, scanId));
    return {
      scanId,
      spiderScanId: String(spiderScanId),
      status: "spidering",
      llmConfig,
      specImportResult,
      playbookApplied: effectivePlaybook?.name
    };
  } catch (err) {
    await db.update(webAppScans).set({
      status: "error",
      errorMessage: `ZAP connection failed: ${err.message}`,
      completedAt: /* @__PURE__ */ new Date()
    }).where(eq(webAppScans.id, scanId));
    return { scanId, status: "error", llmConfig };
  }
}
async function pollScanProgress(scanId, config) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...config };
  const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, scanId));
  if (!scan) throw new Error(`Scan ${scanId} not found`);
  if (scan.status === "completed" || scan.status === "error") {
    return {
      status: scan.status,
      spiderProgress: 100,
      activeScanProgress: scan.status === "completed" ? 100 : 0,
      urlsFound: scan.urlsDiscovered || 0,
      alertCounts: JSON.parse(scan.alertCounts || '{"high":0,"medium":0,"low":0,"info":0}')
    };
  }
  try {
    let spiderProgress = scan.spiderProgress || 0;
    let urlsFound = scan.urlsDiscovered || 0;
    if (scan.status === "spidering" && scan.zapSpiderScanId) {
      const dbSpiderDone = (scan.spiderProgress || 0) >= 100;
      if (!dbSpiderDone) {
        const spiderStatus = await zapRequest("/JSON/spider/view/status/", {
          scanId: scan.zapSpiderScanId
        }, cfg);
        spiderProgress = parseInt(spiderStatus.status || "0", 10);
        const spiderResults = await zapRequest("/JSON/spider/view/results/", {
          scanId: scan.zapSpiderScanId
        }, cfg);
        urlsFound = (spiderResults.results || []).length;
        await db.update(webAppScans).set({
          spiderProgress,
          urlsDiscovered: urlsFound
        }).where(eq(webAppScans.id, scanId));
      } else {
        spiderProgress = scan.spiderProgress || 100;
        urlsFound = scan.urlsDiscovered || 0;
        console.log(`[ZAP pollScanProgress] Scan #${scanId}: DB shows spider complete (${spiderProgress}%), skipping stale ZAP spider check`);
      }
      if (spiderProgress >= 100) {
        const llmConfig = scan.llmScanConfig ? JSON.parse(scan.llmScanConfig) : null;
        if (llmConfig?.useAjaxSpider && !scan.zapAjaxSpiderScanId) {
          const ajaxConfig = llmConfig.ajaxSpiderConfig;
          if (ajaxConfig) {
            const ajaxDuration = Math.min(ajaxConfig.maxDuration || 5, 5);
            await zapRequest("/JSON/ajaxSpider/action/setOptionMaxDuration/", { Integer: String(ajaxDuration) }, cfg).catch(() => {
            });
            await zapRequest("/JSON/ajaxSpider/action/setOptionMaxCrawlDepth/", { Integer: String(ajaxConfig.maxCrawlDepth || 5) }, cfg).catch(() => {
            });
            await zapRequest("/JSON/ajaxSpider/action/setOptionNumberOfBrowsers/", { Integer: String(ajaxConfig.numberOfBrowsers || 2) }, cfg).catch(() => {
            });
            await zapRequest("/JSON/ajaxSpider/action/setOptionClickDefaultElems/", { Boolean: String(ajaxConfig.clickDefaultElems ?? true) }, cfg).catch(() => {
            });
            console.log(`[ZAP AJAX Spider] Scan #${scanId}: Set maxDuration=${ajaxDuration}min, maxCrawlDepth=${ajaxConfig.maxCrawlDepth}, browsers=${ajaxConfig.numberOfBrowsers}`);
          } else {
            await zapRequest("/JSON/ajaxSpider/action/setOptionMaxDuration/", { Integer: "5" }, cfg).catch(() => {
            });
            console.log(`[ZAP AJAX Spider] Scan #${scanId}: Set default maxDuration=5min (no LLM config)`);
          }
          const ajaxResult = await zapRequest("/JSON/ajaxSpider/action/scan/", {
            url: scan.targetUrl,
            subtreeonly: "true"
          }, cfg);
          await db.update(webAppScans).set({
            status: "ajax_spidering",
            zapAjaxSpiderScanId: "running",
            spiderProgress: 100
          }).where(eq(webAppScans.id, scanId));
          return {
            status: "ajax_spidering",
            spiderProgress: 100,
            activeScanProgress: 0,
            urlsFound,
            alertCounts: await getAlertCounts(scanId)
          };
        }
        if (scan.scanMode === "passive" || scan.scanType === "spider_only") {
          await collectAlerts(scanId, cfg);
          await db.update(webAppScans).set({
            status: "completed",
            completedAt: /* @__PURE__ */ new Date(),
            spiderProgress: 100
          }).where(eq(webAppScans.id, scanId));
          return {
            status: "completed",
            spiderProgress: 100,
            activeScanProgress: 0,
            urlsFound,
            alertCounts: await getAlertCounts(scanId)
          };
        }
        const storedPlaybook = scan.llmScanConfig ? (() => {
          try {
            const storedConfig = JSON.parse(scan.llmScanConfig);
            const techs = storedConfig.technologies || [];
            const isTrainingLab = scan.scanName?.includes("EngOps-") && (scan.targetUrl?.includes("juice-shop") || scan.targetUrl?.includes("dvwa") || scan.targetUrl?.includes("lab.aceofcloud") || scan.targetUrl?.includes("testfire") || scan.targetUrl?.includes("vulnweb") || scan.targetUrl?.includes("hackazon"));
            if (isTrainingLab) {
              const { buildTrainingLabPlaybook, boostPlaybookForTrainingLab } = (init_zap_attack_playbooks(), __toCommonJS(zap_attack_playbooks_exports));
              return buildTrainingLabPlaybook();
            }
            return selectPlaybook("full", techs);
          } catch {
            return null;
          }
        })() : null;
        if (storedPlaybook) {
          console.log(`[ZAP Playbook] Applying ${storedPlaybook.name} (${storedPlaybook.enabledRules.length} rules, overrides: ${JSON.stringify(storedPlaybook.activeScanOverrides || {})}) before active scan`);
          const zapApiCfg = { baseUrl: cfg.baseUrl, apiKey: cfg.apiKey };
          const pbResult = await applyPlaybookToZap(storedPlaybook, zapApiCfg, zapRequest);
          if (pbResult.errors.length > 0) {
            console.warn(`[ZAP Playbook] ${pbResult.errors.length} errors applying playbook:`, pbResult.errors);
          }
        }
        try {
          const [siteTreeResult, paramsResult, techResult] = await Promise.allSettled([
            zapRequest("/JSON/core/view/urls/", { baseurl: scan.targetUrl }, cfg),
            zapRequest("/JSON/params/view/params/", { site: new URL(scan.targetUrl).origin }, cfg),
            zapRequest("/JSON/wappalyzer/view/listAll/", {}, cfg).catch(() => null)
          ]);
          const discoveredUrls = siteTreeResult.status === "fulfilled" ? siteTreeResult.value?.urls || [] : [];
          const discoveredParams = paramsResult.status === "fulfilled" ? paramsResult.value?.Parameters || [] : [];
          const detectedTech = techResult.status === "fulfilled" && techResult.value ? techResult.value : null;
          console.log(`[ZAP AttackSurface] Scan #${scanId}: ${discoveredUrls.length} URLs, ${discoveredParams.length} params, tech: ${detectedTech ? "detected" : "N/A"}`);
          await db.update(webAppScans).set({
            urlsDiscovered: discoveredUrls.length || urlsFound,
            detectedTechStack: detectedTech ? JSON.stringify(detectedTech).substring(0, 4e3) : void 0
          }).where(eq(webAppScans.id, scanId));
        } catch (asErr) {
          console.warn(`[ZAP AttackSurface] Scan #${scanId}: Failed to enumerate attack surface: ${asErr.message}`);
        }
        let oastEnabled = false;
        try {
          await zapRequest("/JSON/oast/action/setActiveScanService/", {
            name: "Interactsh"
          }, cfg);
          await zapRequest("/JSON/oast/action/setInteractshOptions/", {
            server: "https://oast.fun",
            pollInSecs: "10",
            authToken: ""
          }, cfg).catch(() => {
            return zapRequest("/JSON/oast/action/setInteractshOptions/", {
              server: "https://interact.sh",
              pollInSecs: "10",
              authToken: ""
            }, cfg);
          });
          await zapRequest("/JSON/oast/action/setDaysToKeepRecords/", {
            days: "7"
          }, cfg).catch(() => {
          });
          oastEnabled = true;
          console.log(`[ZAP OAST] Scan #${scanId}: Interactsh OAST service enabled for blind vulnerability detection`);
        } catch (oastErr) {
          console.warn(`[ZAP OAST] Scan #${scanId}: Failed to enable OAST (non-fatal): ${oastErr.message}`);
        }
        try {
          const activeScanResult = await zapRequest("/JSON/ascan/action/scan/", {
            url: scan.targetUrl,
            recurse: "true"
          }, cfg);
          await db.update(webAppScans).set({
            status: "active_scanning",
            zapActiveScanId: String(activeScanResult.scan),
            spiderProgress: 100
          }).where(eq(webAppScans.id, scanId));
          return {
            status: "active_scanning",
            spiderProgress: 100,
            activeScanProgress: 0,
            urlsFound,
            alertCounts: await getAlertCounts(scanId)
          };
        } catch (activeScanErr) {
          if (activeScanErr.message?.includes("400")) {
            console.log(`[ZAP pollScanProgress] Scan #${scanId}: Active scan 400 \u2014 retrying with accessUrl seed`);
            try {
              await zapRequest("/JSON/core/action/accessUrl/", { url: scan.targetUrl, followRedirects: "true" }, cfg);
              const commonPaths = ["/", "/api", "/rest", "/login", "/search", "/#"];
              await Promise.allSettled(
                commonPaths.map(
                  (p) => zapRequest("/JSON/core/action/accessUrl/", {
                    url: `${scan.targetUrl}${p}`,
                    followRedirects: "true"
                  }, cfg).catch(() => {
                  })
                )
              );
              await new Promise((r) => setTimeout(r, 3e3));
              const retryResult = await zapRequest("/JSON/ascan/action/scan/", {
                url: scan.targetUrl,
                recurse: "true"
              }, cfg);
              console.log(`[ZAP pollScanProgress] Scan #${scanId}: Active scan retry succeeded after accessUrl seed`);
              await db.update(webAppScans).set({
                status: "active_scanning",
                zapActiveScanId: String(retryResult.scan),
                spiderProgress: 100
              }).where(eq(webAppScans.id, scanId));
              return {
                status: "active_scanning",
                spiderProgress: 100,
                activeScanProgress: 0,
                urlsFound,
                alertCounts: await getAlertCounts(scanId)
              };
            } catch (retryErr) {
              console.error(`[ZAP pollScanProgress] Scan #${scanId}: Active scan retry also failed: ${retryErr.message}`);
            }
          }
          console.error(`[ZAP pollScanProgress] Scan #${scanId}: Failed to start active scan: ${activeScanErr.message}`);
          await db.update(webAppScans).set({
            status: "error",
            errorMessage: `Failed to start ZAP active scan: ${activeScanErr.message}`,
            completedAt: /* @__PURE__ */ new Date()
          }).where(eq(webAppScans.id, scanId));
          return {
            status: "error",
            spiderProgress: 100,
            activeScanProgress: 0,
            urlsFound,
            alertCounts: await getAlertCounts(scanId)
          };
        }
      }
    }
    if (scan.status === "ajax_spidering") {
      const ajaxStatus = await zapRequest("/JSON/ajaxSpider/view/status/", {}, cfg);
      if (ajaxStatus.status === "stopped" || ajaxStatus.status === "complete") {
        const ajaxResults = await zapRequest("/JSON/ajaxSpider/view/numberOfResults/", {}, cfg);
        urlsFound = (scan.urlsDiscovered || 0) + parseInt(ajaxResults.numberOfResults || "0", 10);
        if (scan.scanMode === "passive" || scan.scanType === "spider_only") {
          await collectAlerts(scanId, cfg);
          await db.update(webAppScans).set({
            status: "completed",
            completedAt: /* @__PURE__ */ new Date(),
            urlsDiscovered: urlsFound
          }).where(eq(webAppScans.id, scanId));
          return {
            status: "completed",
            spiderProgress: 100,
            activeScanProgress: 0,
            urlsFound,
            alertCounts: await getAlertCounts(scanId)
          };
        }
        const storedPlaybook2 = scan.llmScanConfig ? (() => {
          try {
            const storedConfig = JSON.parse(scan.llmScanConfig);
            const techs = storedConfig.technologies || [];
            const isTrainingLab = scan.scanName?.includes("EngOps-") && (scan.targetUrl?.includes("juice-shop") || scan.targetUrl?.includes("dvwa") || scan.targetUrl?.includes("lab.aceofcloud") || scan.targetUrl?.includes("testfire") || scan.targetUrl?.includes("vulnweb") || scan.targetUrl?.includes("hackazon"));
            if (isTrainingLab) {
              const { buildTrainingLabPlaybook } = (init_zap_attack_playbooks(), __toCommonJS(zap_attack_playbooks_exports));
              return buildTrainingLabPlaybook();
            }
            return selectPlaybook("full", techs);
          } catch {
            return null;
          }
        })() : null;
        if (storedPlaybook2) {
          console.log(`[ZAP Playbook] Applying ${storedPlaybook2.name} (${storedPlaybook2.enabledRules.length} rules, overrides: ${JSON.stringify(storedPlaybook2.activeScanOverrides || {})}) before active scan (post-AJAX)`);
          const zapApiCfg2 = { baseUrl: cfg.baseUrl, apiKey: cfg.apiKey };
          const pbResult2 = await applyPlaybookToZap(storedPlaybook2, zapApiCfg2, zapRequest);
          if (pbResult2.errors.length > 0) {
            console.warn(`[ZAP Playbook] ${pbResult2.errors.length} errors applying playbook:`, pbResult2.errors);
          }
        }
        try {
          const [siteTreeResult2, paramsResult2] = await Promise.allSettled([
            zapRequest("/JSON/core/view/urls/", { baseurl: scan.targetUrl }, cfg),
            zapRequest("/JSON/params/view/params/", { site: new URL(scan.targetUrl).origin }, cfg)
          ]);
          const discoveredUrls2 = siteTreeResult2.status === "fulfilled" ? siteTreeResult2.value?.urls || [] : [];
          const discoveredParams2 = paramsResult2.status === "fulfilled" ? paramsResult2.value?.Parameters || [] : [];
          console.log(`[ZAP AttackSurface] Scan #${scanId} (post-AJAX): ${discoveredUrls2.length} URLs, ${discoveredParams2.length} params`);
          await db.update(webAppScans).set({
            urlsDiscovered: discoveredUrls2.length || urlsFound
          }).where(eq(webAppScans.id, scanId));
        } catch (asErr2) {
          console.warn(`[ZAP AttackSurface] Scan #${scanId}: Failed to enumerate post-AJAX attack surface: ${asErr2.message}`);
        }
        try {
          await zapRequest("/JSON/oast/action/setActiveScanService/", { name: "Interactsh" }, cfg);
          await zapRequest("/JSON/oast/action/setInteractshOptions/", {
            server: "https://oast.fun",
            pollInSecs: "10",
            authToken: ""
          }, cfg).catch(
            () => zapRequest("/JSON/oast/action/setInteractshOptions/", {
              server: "https://interact.sh",
              pollInSecs: "10",
              authToken: ""
            }, cfg)
          );
          console.log(`[ZAP OAST] Scan #${scanId}: Interactsh enabled (post-AJAX spider path)`);
        } catch (oastErr) {
          console.warn(`[ZAP OAST] Scan #${scanId}: OAST setup failed (non-fatal, post-AJAX): ${oastErr.message}`);
        }
        try {
          const activeScanResult = await zapRequest("/JSON/ascan/action/scan/", {
            url: scan.targetUrl,
            recurse: "true"
          }, cfg);
          await db.update(webAppScans).set({
            status: "active_scanning",
            zapActiveScanId: String(activeScanResult.scan),
            urlsDiscovered: urlsFound
          }).where(eq(webAppScans.id, scanId));
          return {
            status: "active_scanning",
            spiderProgress: 100,
            activeScanProgress: 0,
            urlsFound,
            alertCounts: await getAlertCounts(scanId)
          };
        } catch (activeScanErr) {
          if (activeScanErr.message?.includes("400")) {
            console.log(`[ZAP pollScanProgress] Scan #${scanId}: Active scan 400 after AJAX spider on ${scan.targetUrl} \u2014 retrying with accessUrl seed`);
            try {
              await zapRequest("/JSON/core/action/accessUrl/", { url: scan.targetUrl, followRedirects: "true" }, cfg);
              const commonPaths = ["/", "/api", "/rest", "/login", "/search", "/#"];
              await Promise.allSettled(
                commonPaths.map(
                  (p) => zapRequest("/JSON/core/action/accessUrl/", {
                    url: `${scan.targetUrl}${p}`,
                    followRedirects: "true"
                  }, cfg).catch(() => {
                  })
                )
              );
              await new Promise((r) => setTimeout(r, 3e3));
              const retryResult = await zapRequest("/JSON/ascan/action/scan/", {
                url: scan.targetUrl,
                recurse: "true"
              }, cfg);
              console.log(`[ZAP pollScanProgress] Scan #${scanId}: Active scan retry succeeded after AJAX spider + accessUrl seed`);
              await db.update(webAppScans).set({
                status: "active_scanning",
                zapActiveScanId: String(retryResult.scan),
                urlsDiscovered: urlsFound
              }).where(eq(webAppScans.id, scanId));
              return {
                status: "active_scanning",
                spiderProgress: 100,
                activeScanProgress: 0,
                urlsFound,
                alertCounts: await getAlertCounts(scanId)
              };
            } catch (retryErr) {
              console.error(`[ZAP pollScanProgress] Scan #${scanId}: Active scan retry also failed after AJAX spider on ${scan.targetUrl}: ${retryErr.message}`);
            }
          }
          console.error(`[ZAP pollScanProgress] Scan #${scanId}: Failed to start active scan after AJAX spider on ${scan.targetUrl}: ${activeScanErr.message}. URLs discovered: ${urlsFound}`);
          await db.update(webAppScans).set({
            status: "error",
            errorMessage: `Failed to start ZAP active scan after AJAX spider: ${activeScanErr.message}`,
            completedAt: /* @__PURE__ */ new Date()
          }).where(eq(webAppScans.id, scanId));
          return {
            status: "error",
            spiderProgress: 100,
            activeScanProgress: 0,
            urlsFound,
            alertCounts: await getAlertCounts(scanId)
          };
        }
      }
      return {
        status: "ajax_spidering",
        spiderProgress: 100,
        activeScanProgress: 0,
        urlsFound: scan.urlsDiscovered || 0,
        alertCounts: await getAlertCounts(scanId)
      };
    }
    let activeScanProgress = scan.activeScanProgress || 0;
    if (scan.status === "active_scanning" && scan.zapActiveScanId) {
      const ascanStatus = await zapRequest("/JSON/ascan/view/status/", {
        scanId: scan.zapActiveScanId
      }, cfg);
      activeScanProgress = parseInt(ascanStatus.status || "0", 10);
      await db.update(webAppScans).set({
        activeScanProgress
      }).where(eq(webAppScans.id, scanId));
      if (activeScanProgress >= 100) {
        try {
          const oastServices = await zapRequest("/JSON/oast/view/getActiveScanService/", {}, cfg).catch(() => null);
          if (oastServices) {
            const OAST_WAIT_INTERVAL = 15e3;
            const OAST_MAX_WAIT = 6e4;
            const oastWaitStart = Date.now();
            let oastAlertsBefore = 0;
            try {
              const preAlerts = await zapRequest("/JSON/core/view/numberOfAlerts/", { baseurl: scan.targetUrl }, cfg);
              oastAlertsBefore = parseInt(preAlerts?.numberOfAlerts || "0");
            } catch {
            }
            console.log(`[ZAP OAST] Scan #${scanId}: Active scan complete. Waiting up to 60s for OAST blind callbacks (${oastAlertsBefore} alerts before wait)...`);
            while (Date.now() - oastWaitStart < OAST_MAX_WAIT) {
              await new Promise((r) => setTimeout(r, OAST_WAIT_INTERVAL));
              try {
                const postAlerts = await zapRequest("/JSON/core/view/numberOfAlerts/", { baseurl: scan.targetUrl }, cfg);
                const currentAlerts = parseInt(postAlerts?.numberOfAlerts || "0");
                if (currentAlerts > oastAlertsBefore) {
                  console.log(`[ZAP OAST] Scan #${scanId}: ${currentAlerts - oastAlertsBefore} new OAST-triggered alerts detected during wait`);
                  oastAlertsBefore = currentAlerts;
                  await new Promise((r) => setTimeout(r, OAST_WAIT_INTERVAL));
                  break;
                }
              } catch {
              }
            }
            console.log(`[ZAP OAST] Scan #${scanId}: OAST callback wait complete (${Math.round((Date.now() - oastWaitStart) / 1e3)}s). Collecting all alerts including OAST findings.`);
          }
        } catch (oastPollErr) {
          console.warn(`[ZAP OAST] Scan #${scanId}: OAST callback collection warning (non-fatal): ${oastPollErr.message}`);
        }
        await collectAlerts(scanId, cfg);
        await db.update(webAppScans).set({
          status: "completed",
          completedAt: /* @__PURE__ */ new Date(),
          activeScanProgress: 100
        }).where(eq(webAppScans.id, scanId));
        return {
          status: "completed",
          spiderProgress: 100,
          activeScanProgress: 100,
          urlsFound,
          alertCounts: await getAlertCounts(scanId)
        };
      }
    }
    pollFailureCounters.delete(scanId);
    return {
      status: scan.status,
      spiderProgress,
      activeScanProgress,
      urlsFound,
      alertCounts: await getAlertCounts(scanId)
    };
  } catch (err) {
    console.error(`[ZAP pollScanProgress] Scan #${scanId} (status=${scan.status}) error: ${err.message}`);
    if (!pollFailureCounters.has(scanId)) pollFailureCounters.set(scanId, 0);
    const failures = (pollFailureCounters.get(scanId) || 0) + 1;
    pollFailureCounters.set(scanId, failures);
    if (failures === 3) {
      console.warn(`[ZAP pollScanProgress] Scan #${scanId}: 3 consecutive failures. Attempting ZAP auto-restart...`);
      const restarted = await restartZapDocker();
      if (restarted) {
        console.log(`[ZAP pollScanProgress] Scan #${scanId}: ZAP restarted. Resetting failure counter.`);
        pollFailureCounters.set(scanId, 0);
        return {
          status: scan.status,
          spiderProgress: scan.spiderProgress || 0,
          activeScanProgress: scan.activeScanProgress || 0,
          urlsFound: scan.urlsDiscovered || 0,
          alertCounts: JSON.parse(scan.alertCounts || '{"high":0,"medium":0,"low":0,"info":0}')
        };
      }
    }
    const MAX_POLL_FAILURES = 8;
    if (failures >= MAX_POLL_FAILURES) {
      console.error(`[ZAP pollScanProgress] Scan #${scanId}: ${failures} consecutive failures (including restart attempt). Marking as error.`);
      try {
        const db2 = await getDb();
        if (db2) {
          await db2.update(webAppScans).set({
            status: "error",
            errorMessage: `ZAP scan stalled after ${failures} consecutive poll failures: ${err.message}`,
            completedAt: /* @__PURE__ */ new Date()
          }).where(eq(webAppScans.id, scanId));
        }
      } catch (dbErr) {
        console.error(`[ZAP pollScanProgress] Failed to mark scan #${scanId} as error: ${dbErr.message}`);
      }
      pollFailureCounters.delete(scanId);
      return {
        status: "error",
        spiderProgress: scan.spiderProgress || 0,
        activeScanProgress: scan.activeScanProgress || 0,
        urlsFound: scan.urlsDiscovered || 0,
        alertCounts: JSON.parse(scan.alertCounts || '{"high":0,"medium":0,"low":0,"info":0}')
      };
    }
    return {
      status: scan.status,
      spiderProgress: scan.spiderProgress || 0,
      activeScanProgress: scan.activeScanProgress || 0,
      urlsFound: scan.urlsDiscovered || 0,
      alertCounts: JSON.parse(scan.alertCounts || '{"high":0,"medium":0,"low":0,"info":0}')
    };
  }
}
async function collectAlerts(scanId, config) {
  const db = await getDb();
  if (!db) return;
  const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, scanId));
  if (!scan) return;
  try {
    const alertsResult = await zapRequest("/JSON/alert/view/alerts/", {
      baseurl: scan.targetUrl,
      start: "0",
      count: String(config.maxAlertsPerScan)
    }, config);
    const alerts = alertsResult.alerts || [];
    const counts = { high: 0, medium: 0, low: 0, info: 0 };
    const seen = /* @__PURE__ */ new Set();
    const uniqueAlerts = [];
    for (const alert of alerts) {
      const key = `${alert.pluginId}|${alert.url}|${alert.param}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueAlerts.push(alert);
      }
    }
    for (const alert of uniqueAlerts) {
      const severity = mapZapRisk(alert.risk);
      const confidence = mapZapConfidence(alert.confidence);
      const cweId = alert.cweid ? parseInt(alert.cweid, 10) : null;
      if (severity === "high") counts.high++;
      else if (severity === "medium") counts.medium++;
      else if (severity === "low") counts.low++;
      else counts.info++;
      const mitre = mapToMitre(cweId, alert.name || alert.alert);
      const msfModules = findMsfModules(cweId);
      let enrichedEvidence = (alert.evidence || "").substring(0, 2e3);
      if ((severity === "high" || severity === "medium") && alert.messageId) {
        try {
          const msg = await zapRequest("/JSON/core/view/message/", {
            id: alert.messageId
          }, config);
          if (msg?.message) {
            const reqHeaders = (msg.message.requestHeader || "").substring(0, 1e3);
            const reqBody = (msg.message.requestBody || "").substring(0, 500);
            const resHeaders = (msg.message.responseHeader || "").substring(0, 500);
            const resBody = (msg.message.responseBody || "").substring(0, 500);
            const httpEvidence = [
              enrichedEvidence,
              "\n--- HTTP Request ---",
              reqHeaders,
              reqBody ? `
[Body] ${reqBody}` : "",
              "\n--- HTTP Response ---",
              resHeaders,
              resBody ? `
[Body] ${resBody}` : ""
            ].filter(Boolean).join("\n");
            enrichedEvidence = httpEvidence.substring(0, 4e3);
          }
        } catch (msgErr) {
        }
      }
      await db.insert(webAppFindings).values({
        scanId,
        alertName: alert.name || alert.alert,
        severity,
        confidence,
        description: (alert.description || "").substring(0, 4e3),
        solution: (alert.solution || "").substring(0, 4e3),
        reference: (alert.reference || "").substring(0, 2e3),
        cweId,
        wascId: alert.wascid ? parseInt(alert.wascid, 10) : null,
        url: alert.url,
        method: alert.method,
        param: alert.param || null,
        attack: (alert.attack || "").substring(0, 2e3),
        evidence: enrichedEvidence,
        zapPluginId: alert.pluginId,
        zapAlertRef: alert.id,
        // MITRE ATT&CK
        mitreAttackId: mitre?.techniqueId || null,
        mitreAttackName: mitre?.techniqueName || null,
        mitreTactic: mitre?.tactic || null,
        // Exploit correlation
        exploitAvailable: msfModules.length > 0,
        exploitModulePath: msfModules.length > 0 ? msfModules[0] : null
      });
    }
    await db.update(webAppScans).set({
      alertCounts: JSON.stringify(counts),
      totalAlerts: uniqueAlerts.length
    }).where(eq(webAppScans.id, scanId));
  } catch (err) {
    console.error(`[ZAP] Failed to collect alerts for scan ${scanId}: ${err.message}`);
  }
}
async function getAlertCounts(scanId) {
  const db = await getDb();
  if (!db) return { high: 0, medium: 0, low: 0, info: 0 };
  const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, scanId));
  if (!scan?.alertCounts) return { high: 0, medium: 0, low: 0, info: 0 };
  try {
    return JSON.parse(scan.alertCounts);
  } catch {
    return { high: 0, medium: 0, low: 0, info: 0 };
  }
}
async function stopScan(scanId, config) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...config };
  const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, scanId));
  if (!scan) throw new Error(`Scan ${scanId} not found`);
  try {
    if (scan.zapSpiderScanId) {
      await zapRequest("/JSON/spider/action/stop/", { scanId: scan.zapSpiderScanId }, cfg);
    }
    if (scan.zapActiveScanId) {
      await zapRequest("/JSON/ascan/action/stop/", { scanId: scan.zapActiveScanId }, cfg);
    }
    if (scan.zapAjaxSpiderScanId) {
      await zapRequest("/JSON/ajaxSpider/action/stop/", {}, cfg);
    }
  } catch (err) {
  }
  await collectAlerts(scanId, cfg);
  await db.update(webAppScans).set({
    status: "completed",
    completedAt: /* @__PURE__ */ new Date()
  }).where(eq(webAppScans.id, scanId));
  return { success: true };
}
async function listScans(filters) {
  const db = await getDb();
  if (!db) return [];
  const conditions = [];
  if (filters?.status) conditions.push(eq(webAppScans.status, filters.status));
  if (filters?.scanMode) conditions.push(eq(webAppScans.scanMode, filters.scanMode));
  let query;
  if (conditions.length > 0) {
    query = db.select().from(webAppScans).where(and(...conditions)).orderBy(desc(webAppScans.startedAt));
  } else {
    query = db.select().from(webAppScans).orderBy(desc(webAppScans.startedAt));
  }
  return query.limit(filters?.limit || 50);
}
async function getScanFindings(scanId, filters) {
  const db = await getDb();
  if (!db) return [];
  const conditions = [eq(webAppFindings.scanId, scanId)];
  if (filters?.severity) {
    conditions.push(eq(webAppFindings.severity, filters.severity));
  }
  return db.select().from(webAppFindings).where(and(...conditions)).orderBy(desc(webAppFindings.severity)).limit(filters?.limit || 200);
}
async function getScanStats() {
  const db = await getDb();
  if (!db) return {
    totalScans: 0,
    completedScans: 0,
    totalFindings: 0,
    findingsBySeverity: { high: 0, medium: 0, low: 0, info: 0 },
    topVulnerabilities: [],
    avgScanDuration: 0,
    scansByMode: { passive: 0, active: 0 },
    mitreAttackCoverage: [],
    exploitableFindings: 0
  };
  const allScans = await db.select().from(webAppScans);
  const allFindings = await db.select().from(webAppFindings);
  const completedScans = allScans.filter((s) => s.status === "completed");
  const findingsBySeverity = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of allFindings) {
    const sev = f.severity;
    if (sev in findingsBySeverity) findingsBySeverity[sev]++;
  }
  const vulnCounts = /* @__PURE__ */ new Map();
  for (const f of allFindings) {
    const key = f.alertName || "Unknown";
    const existing = vulnCounts.get(key);
    if (existing) existing.count++;
    else vulnCounts.set(key, { count: 1, severity: f.severity || "info" });
  }
  const topVulnerabilities = Array.from(vulnCounts.entries()).map(([name, { count, severity }]) => ({ name, count, severity })).sort((a, b) => b.count - a.count).slice(0, 10);
  const durations = completedScans.filter((s) => s.startedAt && s.completedAt).map((s) => new Date(s.completedAt).getTime() - new Date(s.startedAt).getTime());
  const avgScanDuration = durations.length > 0 ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length / 6e4) : 0;
  const scansByMode = { passive: 0, active: 0 };
  for (const s of allScans) {
    if (s.scanMode === "passive") scansByMode.passive++;
    else scansByMode.active++;
  }
  const mitreCounts = /* @__PURE__ */ new Map();
  for (const f of allFindings) {
    if (f.mitreAttackId) {
      const existing = mitreCounts.get(f.mitreAttackId);
      if (existing) existing.count++;
      else mitreCounts.set(f.mitreAttackId, {
        techniqueName: f.mitreAttackName || "",
        tactic: f.mitreTactic || "",
        count: 1
      });
    }
  }
  const mitreAttackCoverage = Array.from(mitreCounts.entries()).map(([techniqueId, data]) => ({ techniqueId, ...data })).sort((a, b) => b.count - a.count);
  const exploitableFindings = allFindings.filter((f) => f.exploitAvailable).length;
  return {
    totalScans: allScans.length,
    completedScans: completedScans.length,
    totalFindings: allFindings.length,
    findingsBySeverity,
    topVulnerabilities,
    avgScanDuration,
    scansByMode,
    mitreAttackCoverage,
    exploitableFindings
  };
}
async function retryScan(scanId, userId) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, scanId)).limit(1);
  if (!scan) throw new Error(`Scan #${scanId} not found`);
  if (scan.status !== "error") throw new Error(`Scan #${scanId} is in status '${scan.status}' \u2014 only error scans can be retried`);
  await db.delete(webAppFindings).where(eq(webAppFindings.scanId, scanId));
  await db.update(webAppScans).set({
    status: "starting",
    spiderProgress: 0,
    activeScanProgress: 0,
    urlsDiscovered: 0,
    totalAlerts: 0,
    alertCounts: null,
    errorMessage: null,
    zapSpiderScanId: null,
    zapActiveScanId: null,
    zapAjaxSpiderScanId: null,
    startedAt: (/* @__PURE__ */ new Date()).toISOString(),
    completedAt: null,
    startedBy: userId
  }).where(eq(webAppScans.id, scanId));
  let llmConfig;
  if (scan.llmScanConfig) {
    try {
      llmConfig = JSON.parse(scan.llmScanConfig);
    } catch {
    }
  }
  let discoveredTechnologies;
  if (scan.detectedTechStack) {
    try {
      discoveredTechnologies = JSON.parse(scan.detectedTechStack);
    } catch {
    }
  }
  try {
    const result = await startScan({
      targetUrl: scan.targetUrl,
      scanType: scan.scanType || "full",
      scanMode: scan.scanMode || "passive",
      userId,
      scanName: `[RETRY] ${scan.scanName || scan.targetUrl}`,
      llmConfig,
      attackChainId: scan.attackChainId || void 0,
      calderaOperationId: scan.calderaOperationId || void 0,
      metasploitSessionId: scan.metasploitSessionId || void 0,
      domainIntelScanId: scan.domainIntelScanId || void 0,
      discoveredTechnologies
    });
    await db.update(webAppScans).set({
      status: "error",
      errorMessage: `Superseded by retry scan #${result.scanId}`
    }).where(eq(webAppScans.id, scanId));
    return {
      scanId: result.scanId,
      spiderScanId: result.spiderScanId,
      status: result.status,
      message: `Retry started as scan #${result.scanId}`
    };
  } catch (err) {
    await db.update(webAppScans).set({
      status: "error",
      errorMessage: `Retry failed: ${err.message}`,
      completedAt: (/* @__PURE__ */ new Date()).toISOString()
    }).where(eq(webAppScans.id, scanId));
    throw new Error(`Retry failed for scan #${scanId}: ${err.message}`);
  }
}
async function deleteScan(scanId) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.delete(webAppFindings).where(eq(webAppFindings.scanId, scanId));
  await db.delete(webAppScans).where(eq(webAppScans.id, scanId));
  return { success: true };
}
async function seedDemoData() {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const [passiveScan] = await db.insert(webAppScans).values({
    targetUrl: "https://demo-target.example.com",
    scanName: "[DEMO] Passive Recon \u2014 demo-target.example.com",
    scanType: "spider_only",
    scanMode: "passive",
    status: "completed",
    startedBy: "demo",
    startedAt: new Date(Date.now() - 36e5),
    completedAt: new Date(Date.now() - 3e6),
    spiderProgress: 100,
    activeScanProgress: 0,
    urlsDiscovered: 147,
    totalAlerts: 8,
    alertCounts: JSON.stringify({ high: 0, medium: 3, low: 3, info: 2 }),
    detectedTechStack: JSON.stringify(["React", "Node.js", "Express", "nginx"]),
    llmScanConfig: JSON.stringify(getDefaultScanConfig("passive")),
    scanPolicyName: "Default Policy",
    ajaxSpiderUsed: true
  });
  const [activeScan] = await db.insert(webAppScans).values({
    targetUrl: "https://demo-webapp.example.com",
    scanName: "[DEMO] Active DAST \u2014 demo-webapp.example.com",
    scanType: "full",
    scanMode: "active",
    status: "completed",
    startedBy: "demo",
    startedAt: new Date(Date.now() - 72e5),
    completedAt: new Date(Date.now() - 54e5),
    spiderProgress: 100,
    activeScanProgress: 100,
    urlsDiscovered: 312,
    totalAlerts: 15,
    alertCounts: JSON.stringify({ high: 4, medium: 5, low: 3, info: 3 }),
    detectedTechStack: JSON.stringify(["PHP", "Apache", "MySQL", "WordPress"]),
    llmScanConfig: JSON.stringify(getDefaultScanConfig("active")),
    scanPolicyName: "Default Policy",
    authConfigured: true,
    attackChainId: "chain-demo-001"
  });
  const passiveScanId = passiveScan.insertId;
  const activeScanId = activeScan.insertId;
  const passiveFindings = [
    { alertName: "[DEMO] Missing Content-Security-Policy Header", severity: "medium", confidence: 0.9, cweId: 693, url: "https://demo-target.example.com/", description: "Content Security Policy header not set. This allows the browser to load resources from any origin.", solution: "Add Content-Security-Policy header with appropriate directives.", mitreAttackId: "T1189", mitreAttackName: "Drive-by Compromise", mitreTactic: "Initial Access" },
    { alertName: "[DEMO] X-Frame-Options Header Not Set", severity: "medium", confidence: 0.9, cweId: 1021, url: "https://demo-target.example.com/login", description: "X-Frame-Options header is not included in the HTTP response to protect against clickjacking.", solution: "Set X-Frame-Options to DENY or SAMEORIGIN.", mitreAttackId: "T1185", mitreAttackName: "Browser Session Hijacking", mitreTactic: "Collection" },
    { alertName: "[DEMO] Cookie Without SameSite Attribute", severity: "medium", confidence: 0.7, cweId: 1275, url: "https://demo-target.example.com/api/auth", description: "Session cookie does not have SameSite attribute set.", solution: "Set SameSite=Strict or SameSite=Lax on session cookies.", mitreAttackId: "T1539", mitreAttackName: "Steal Web Session Cookie", mitreTactic: "Credential Access" },
    { alertName: "[DEMO] Server Leaks Version Information", severity: "low", confidence: 0.9, cweId: 200, url: "https://demo-target.example.com/", description: "Server response header reveals version: nginx/1.21.3", solution: "Remove or obfuscate server version headers.", mitreAttackId: "T1552", mitreAttackName: "Unsecured Credentials", mitreTactic: "Credential Access" },
    { alertName: "[DEMO] Strict-Transport-Security Header Not Set", severity: "low", confidence: 0.9, cweId: 319, url: "https://demo-target.example.com/", description: "HSTS header not set. Browser may allow HTTP downgrade.", solution: "Add Strict-Transport-Security header with max-age.", mitreAttackId: "T1557", mitreAttackName: "Adversary-in-the-Middle", mitreTactic: "Collection" },
    { alertName: "[DEMO] Information Disclosure - Debug Error Messages", severity: "low", confidence: 0.4, cweId: 209, url: "https://demo-target.example.com/api/users?id=999", description: "Application returns detailed error stack traces.", solution: "Implement custom error pages that do not reveal internal details.", mitreAttackId: "T1552", mitreAttackName: "Unsecured Credentials", mitreTactic: "Credential Access" },
    { alertName: "[DEMO] Modern Web Application Detected", severity: "info", confidence: 0.9, cweId: null, url: "https://demo-target.example.com/", description: "React SPA detected with client-side routing.", solution: "Informational \u2014 no action required." },
    { alertName: "[DEMO] Timestamp Disclosure - Unix", severity: "info", confidence: 0.4, cweId: 200, url: "https://demo-target.example.com/api/status", description: "Unix timestamp found in response body.", solution: "Informational \u2014 review if timestamps reveal sensitive timing." }
  ];
  for (const f of passiveFindings) {
    await db.insert(webAppFindings).values({
      scanId: passiveScanId,
      alertName: f.alertName,
      severity: f.severity,
      confidence: f.confidence,
      cweId: f.cweId,
      url: f.url,
      description: f.description,
      solution: f.solution,
      mitreAttackId: f.mitreAttackId || null,
      mitreAttackName: f.mitreAttackName || null,
      mitreTactic: f.mitreTactic || null
    });
  }
  const activeFindings = [
    { alertName: "[DEMO] SQL Injection", severity: "high", confidence: 0.9, cweId: 89, url: "https://demo-webapp.example.com/search?q=test", param: "q", attack: "' OR '1'='1", evidence: "SQL error in response", description: "SQL injection vulnerability in search parameter.", solution: "Use parameterized queries.", mitreAttackId: "T1190", mitreAttackName: "Exploit Public-Facing Application", mitreTactic: "Initial Access", exploitAvailable: true, exploitModulePath: "exploit/multi/http/sqli_generic" },
    { alertName: "[DEMO] Cross Site Scripting (Reflected)", severity: "high", confidence: 0.9, cweId: 79, url: "https://demo-webapp.example.com/search?q=<script>alert(1)</script>", param: "q", attack: "<script>alert(1)</script>", evidence: "Script tag reflected in response", description: "Reflected XSS in search parameter.", solution: "Encode output and validate input.", mitreAttackId: "T1189", mitreAttackName: "Drive-by Compromise", mitreTactic: "Initial Access" },
    { alertName: "[DEMO] Path Traversal", severity: "high", confidence: 0.7, cweId: 22, url: "https://demo-webapp.example.com/download?file=../../../etc/passwd", param: "file", attack: "../../../etc/passwd", evidence: "root:x:0:0", description: "Path traversal allows reading arbitrary files.", solution: "Validate and sanitize file paths.", mitreAttackId: "T1005", mitreAttackName: "Data from Local System", mitreTactic: "Collection", exploitAvailable: true, exploitModulePath: "exploit/multi/http/lfi_generic" },
    { alertName: "[DEMO] Remote OS Command Injection", severity: "high", confidence: 0.7, cweId: 78, url: "https://demo-webapp.example.com/admin/ping?host=127.0.0.1;id", param: "host", attack: "127.0.0.1;id", evidence: "uid=33(www-data)", description: "OS command injection in admin ping utility.", solution: "Use safe APIs instead of shell commands.", mitreAttackId: "T1059", mitreAttackName: "Command and Scripting Interpreter", mitreTactic: "Execution", exploitAvailable: true, exploitModulePath: "exploit/multi/http/oscommand_generic" },
    { alertName: "[DEMO] CSRF Token Missing", severity: "medium", confidence: 0.9, cweId: 352, url: "https://demo-webapp.example.com/admin/settings", description: "Anti-CSRF token not found in form.", solution: "Implement CSRF tokens for state-changing requests.", mitreAttackId: "T1185", mitreAttackName: "Browser Session Hijacking", mitreTactic: "Collection" },
    { alertName: "[DEMO] Session Fixation", severity: "medium", confidence: 0.7, cweId: 384, url: "https://demo-webapp.example.com/login", description: "Session ID not regenerated after login.", solution: "Regenerate session ID after authentication.", mitreAttackId: "T1078", mitreAttackName: "Valid Accounts", mitreTactic: "Defense Evasion" },
    { alertName: "[DEMO] CORS Misconfiguration", severity: "medium", confidence: 0.9, cweId: 942, url: "https://demo-webapp.example.com/api/user/profile", description: "Access-Control-Allow-Origin: * allows any origin.", solution: "Restrict CORS to trusted origins.", mitreAttackId: "T1557", mitreAttackName: "Adversary-in-the-Middle", mitreTactic: "Collection" },
    { alertName: "[DEMO] Insecure HTTP Method (PUT)", severity: "medium", confidence: 0.7, cweId: 200, url: "https://demo-webapp.example.com/uploads/", method: "PUT", description: "PUT method enabled on upload directory.", solution: "Disable unnecessary HTTP methods.", mitreAttackId: "T1190", mitreAttackName: "Exploit Public-Facing Application", mitreTactic: "Initial Access" },
    { alertName: "[DEMO] WordPress Version Disclosure", severity: "medium", confidence: 0.9, cweId: 200, url: "https://demo-webapp.example.com/readme.html", description: "WordPress 5.8.1 version disclosed in readme.", solution: "Remove readme.html and version meta tags." },
    { alertName: "[DEMO] Directory Browsing Enabled", severity: "low", confidence: 0.9, cweId: 548, url: "https://demo-webapp.example.com/wp-content/uploads/", description: "Directory listing enabled on uploads folder.", solution: "Disable directory browsing in web server config.", mitreAttackId: "T1083", mitreAttackName: "File and Directory Discovery", mitreTactic: "Discovery" },
    { alertName: "[DEMO] Cookie Without HttpOnly Flag", severity: "low", confidence: 0.9, cweId: 1004, url: "https://demo-webapp.example.com/", description: "Session cookie missing HttpOnly flag.", solution: "Set HttpOnly flag on session cookies.", mitreAttackId: "T1539", mitreAttackName: "Steal Web Session Cookie", mitreTactic: "Credential Access" },
    { alertName: "[DEMO] X-Content-Type-Options Header Missing", severity: "low", confidence: 0.9, cweId: 693, url: "https://demo-webapp.example.com/", description: "X-Content-Type-Options header not set.", solution: "Add X-Content-Type-Options: nosniff header." },
    { alertName: "[DEMO] Application Error Disclosure", severity: "info", confidence: 0.7, cweId: 209, url: "https://demo-webapp.example.com/wp-admin/", description: "WordPress admin login page accessible.", solution: "Restrict access to admin pages." },
    { alertName: "[DEMO] Retrieved from Cache", severity: "info", confidence: 0.4, cweId: null, url: "https://demo-webapp.example.com/", description: "Response served from cache.", solution: "Informational \u2014 no action required." },
    { alertName: "[DEMO] User Agent Fuzzer", severity: "info", confidence: 0.4, cweId: null, url: "https://demo-webapp.example.com/", description: "Different responses for different user agents detected.", solution: "Informational \u2014 review user agent handling." }
  ];
  for (const f of activeFindings) {
    await db.insert(webAppFindings).values({
      scanId: activeScanId,
      alertName: f.alertName,
      severity: f.severity,
      confidence: f.confidence,
      cweId: f.cweId,
      url: f.url,
      method: f.method || "GET",
      param: f.param || null,
      attack: f.attack || null,
      evidence: f.evidence || null,
      description: f.description,
      solution: f.solution,
      mitreAttackId: f.mitreAttackId || null,
      mitreAttackName: f.mitreAttackName || null,
      mitreTactic: f.mitreTactic || null,
      exploitAvailable: f.exploitAvailable || false,
      exploitModulePath: f.exploitModulePath || null
    });
  }
  return { scanId: activeScanId, findingsCount: passiveFindings.length + activeFindings.length };
}
async function clearDemoData() {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const demoScans = await db.select().from(webAppScans).where(sql`${webAppScans.scanName} LIKE '%[DEMO]%'`);
  let deletedFindings = 0;
  for (const scan of demoScans) {
    const findings = await db.delete(webAppFindings).where(eq(webAppFindings.scanId, scan.id));
    deletedFindings += findings.rowsAffected || 0;
  }
  const result = await db.delete(webAppScans).where(sql`${webAppScans.scanName} LIKE '%[DEMO]%'`);
  return { deletedScans: demoScans.length, deletedFindings };
}
async function preAuthenticateAndInjectSession(targetUrl, loginUrl, credentials, formFields, contextId, cfg) {
  try {
    const loginPage = await fetch(loginUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
      signal: AbortSignal.timeout(1e4),
      redirect: "follow"
    });
    const html = await loginPage.text();
    const setCookies = loginPage.headers.getSetCookie?.() || [];
    const cookieJar = {};
    for (const sc of setCookies) {
      const match = sc.match(/^([^=]+)=([^;]+)/);
      if (match) cookieJar[match[1]] = match[2];
    }
    let csrfValue = "";
    if (formFields.csrfField) {
      const csrfRegex = new RegExp(`name=["']${formFields.csrfField}["'][^>]*value=["']([^"']+)["']`, "i");
      const csrfMatch = html.match(csrfRegex);
      if (!csrfMatch) {
        const csrfRegex2 = new RegExp(`value=["']([^"']+)["'][^>]*name=["']${formFields.csrfField}["']`, "i");
        const csrfMatch2 = html.match(csrfRegex2);
        csrfValue = csrfMatch2?.[1] || "";
      } else {
        csrfValue = csrfMatch[1];
      }
      if (!csrfValue) {
        console.log(`[ZAP Pre-Auth] Warning: Could not extract CSRF token for field '${formFields.csrfField}'`);
      }
    }
    const formData = new URLSearchParams();
    formData.set(formFields.usernameField, credentials.username);
    formData.set(formFields.passwordField, credentials.password);
    if (formFields.csrfField && csrfValue) {
      formData.set(formFields.csrfField, csrfValue);
    }
    if (formFields.extraFields) {
      for (const [k, v] of Object.entries(formFields.extraFields)) {
        formData.set(k, v);
      }
    }
    const cookieHeader = Object.entries(cookieJar).map(([k, v]) => `${k}=${v}`).join("; ");
    const loginResp = await fetch(loginUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Cookie": cookieHeader
      },
      body: formData.toString(),
      signal: AbortSignal.timeout(1e4),
      redirect: "manual"
      // Don't follow redirect, capture the Set-Cookie
    });
    const loginSetCookies = loginResp.headers.getSetCookie?.() || [];
    for (const sc of loginSetCookies) {
      const match = sc.match(/^([^=]+)=([^;]+)/);
      if (match) cookieJar[match[1]] = match[2];
    }
    const allCookies = Object.entries(cookieJar).map(([k, v]) => `${k}=${v}`).join("; ");
    const parsedTarget = new URL(targetUrl);
    const verifyUrl = loginResp.headers.get("location") ? new URL(loginResp.headers.get("location"), loginUrl).toString() : `${parsedTarget.origin}${parsedTarget.pathname}`;
    const verifyResp = await fetch(verifyUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0",
        "Cookie": allCookies
      },
      signal: AbortSignal.timeout(1e4),
      redirect: "follow"
    });
    const verifyHtml = await verifyResp.text();
    const isAuthenticated = /logout|sign.out|dashboard|welcome|my.account|profile/i.test(verifyHtml) && !/login\.php|sign.in/i.test(verifyHtml.substring(0, 500));
    if (!isAuthenticated) {
      console.log(`[ZAP Pre-Auth] Login may have failed - no logout indicator found in response`);
    } else {
      console.log(`[ZAP Pre-Auth] Successfully authenticated as ${credentials.username}`);
    }
    const scopeRegex = `${parsedTarget.origin}${parsedTarget.pathname}.*`;
    try {
      await zapRequest("/JSON/replacer/action/addRule/", {
        description: `Auth-Cookie-${contextId}`,
        enabled: "true",
        matchType: "REQ_HEADER",
        matchRegex: "false",
        matchString: "Cookie",
        replacement: allCookies,
        initiators: "",
        url: scopeRegex
      }, cfg);
      console.log(`[ZAP Pre-Auth] Injected session cookie via Replacer for scope: ${scopeRegex}`);
    } catch (e) {
      return { success: false, error: `Failed to add Replacer rule: ${e.message}` };
    }
    try {
      await zapRequest("/JSON/authentication/action/setAuthenticationMethod/", {
        contextId,
        authMethodName: "manualAuthentication",
        authMethodConfigParams: ""
      }, cfg);
    } catch {
    }
    return { success: true, sessionCookie: allCookies };
  } catch (e) {
    return { success: false, error: `Pre-auth failed: ${e.message}` };
  }
}
async function configureZapAuthentication(contextName, targetUrl, credentials, config) {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...config };
  const errors = [];
  const parsedUrl = new URL(targetUrl);
  const webCreds = credentials.filter(
    (c) => ["http", "https", "web_admin", "http-form", "http-get", "http-post"].includes(c.service) || c.protocol === "http" || c.protocol === "https"
  );
  const bestCred = webCreds[0] || credentials[0];
  if (!bestCred) {
    return { configured: false, method: "none", username: "", errors: ["No credentials provided"] };
  }
  console.log(`[ZAP Auth] Configuring authentication for ${targetUrl} using ${bestCred.source} credentials (${bestCred.username}:***)`);
  try {
    let contextId;
    try {
      const ctxResult = await zapRequest("/JSON/context/view/context/", {
        contextName
      }, cfg);
      contextId = ctxResult.context?.id || ctxResult.id;
    } catch {
      try {
        const newCtx = await zapRequest("/JSON/context/action/newContext/", {
          contextName
        }, cfg);
        contextId = newCtx.contextId;
      } catch (e) {
        errors.push(`Failed to create context: ${e.message}`);
      }
    }
    if (!contextId) {
      return { configured: false, method: "none", username: bestCred.username, errors: ["Could not get or create ZAP context"] };
    }
    const basePaths = ["/login", "/admin/login", "/user/login", "/wp-login.php", "/login.php", "/"];
    const techSpecificPaths = [];
    const techHints = config?.techHints || [];
    const techStr = techHints.join(" ").toLowerCase();
    if (techStr.includes("wordpress") || techStr.includes("wp-")) {
      techSpecificPaths.push("/wp-login.php", "/wp-admin/", "/xmlrpc.php");
    }
    if (techStr.includes("django") || techStr.includes("python") || techStr.includes("csrftoken")) {
      techSpecificPaths.push("/admin/login/", "/accounts/login/", "/auth/login/");
    }
    if (techStr.includes("laravel") || techStr.includes("laravel_session")) {
      techSpecificPaths.push("/login", "/admin", "/auth/login", "/nova/login");
    }
    if (techStr.includes("php") || techStr.includes("phpsessid")) {
      techSpecificPaths.push("/login.php", "/admin.php", "/index.php?action=login", "/administrator/");
    }
    if (techStr.includes("java") || techStr.includes("jsessionid") || techStr.includes("spring") || techStr.includes("tomcat")) {
      techSpecificPaths.push("/login", "/j_spring_security_check", "/admin/login", "/cas/login");
    }
    if (techStr.includes("asp.net") || techStr.includes("aspnet")) {
      techSpecificPaths.push("/Account/Login", "/Login.aspx", "/admin/login", "/Identity/Account/Login");
    }
    if (techStr.includes("node") || techStr.includes("express") || techStr.includes("connect.sid")) {
      techSpecificPaths.push("/login", "/auth/login", "/api/auth/login", "/users/login");
    }
    if (techStr.includes("rails") || techStr.includes("ruby")) {
      techSpecificPaths.push("/users/sign_in", "/login", "/admin/login", "/session/new");
    }
    const loginPaths = [.../* @__PURE__ */ new Set([...techSpecificPaths, ...basePaths])];
    if (techSpecificPaths.length > 0) {
      console.log(`[ZAP Auth] Tech-specific login paths added: ${techSpecificPaths.join(", ")} (from: ${techStr.substring(0, 100)})`);
    }
    let detectedLoginUrl;
    let detectedMethod = "form";
    const TRAINING_LAB_AUTH_PRESETS = {
      "juice-shop": { method: "json", loginPath: "/rest/user/login", usernameField: "email", passwordField: "password" },
      "dvwa": { method: "form", loginPath: "/login.php", usernameField: "username", passwordField: "password" },
      "hackazon": { method: "form", loginPath: "/user/login", usernameField: "username", passwordField: "password" },
      "webgoat": { method: "form", loginPath: "/WebGoat/login", usernameField: "username", passwordField: "password" },
      "mutillidae": { method: "form", loginPath: "/index.php?page=login.php", usernameField: "username", passwordField: "password" }
    };
    const targetPreset = detectTargetPreset(targetUrl);
    if (targetPreset && TRAINING_LAB_AUTH_PRESETS[targetPreset]) {
      const preset = TRAINING_LAB_AUTH_PRESETS[targetPreset];
      detectedMethod = preset.method;
      detectedLoginUrl = `${parsedUrl.origin}${preset.loginPath}`;
      console.log(`[ZAP Auth] Training lab preset detected: ${targetPreset} \u2014 using ${preset.method} auth at ${detectedLoginUrl} (skipping fetch-based detection)`);
    } else {
      for (const path of loginPaths) {
        try {
          const testUrl = `${parsedUrl.origin}${path}`;
          const resp = await fetch(testUrl, {
            method: "GET",
            headers: { "User-Agent": "Mozilla/5.0 (compatible; CalderaZapAuth/1.0)" },
            signal: AbortSignal.timeout(5e3),
            redirect: "follow"
          });
          if (resp.status === 401 && resp.headers.get("www-authenticate")?.toLowerCase().includes("basic")) {
            detectedMethod = "basic";
            detectedLoginUrl = testUrl;
            break;
          }
          if (resp.ok) {
            const body = await resp.text();
            if (/type=["']password["']/i.test(body) && /<form/i.test(body)) {
              detectedLoginUrl = testUrl;
              if (/application\/json|fetch\s*\(|axios|XMLHttpRequest/i.test(body) && !/action=["'][^"']*["']/i.test(body)) {
                detectedMethod = "json";
              } else {
                detectedMethod = "form";
              }
              break;
            }
          }
        } catch {
        }
      }
    }
    if (detectedMethod === "basic") {
      try {
        await zapRequest("/JSON/authentication/action/setAuthenticationMethod/", {
          contextId,
          authMethodName: "httpAuthentication",
          authMethodConfigParams: `hostname=${parsedUrl.hostname}&realm=`
        }, cfg);
        console.log(`[ZAP Auth] Configured HTTP Basic Auth for context ${contextName}`);
      } catch (e) {
        errors.push(`Failed to set HTTP Basic auth: ${e.message}`);
      }
    } else if (detectedMethod === "form") {
      const loginUrl = detectedLoginUrl || `${parsedUrl.origin}/login`;
      const authPreset2 = targetPreset ? TRAINING_LAB_AUTH_PRESETS[targetPreset] : void 0;
      let usernameField = authPreset2?.usernameField || "username";
      let passwordField = authPreset2?.passwordField || "password";
      let csrfField;
      let extraFields = {};
      if (authPreset2) {
        console.log(`[ZAP Auth] Using preset field names for ${targetPreset}: ${usernameField}/${passwordField}`);
        const presetLoginRequestData = `${usernameField}={%username%}&${passwordField}={%password%}`;
        try {
          await zapRequest("/JSON/authentication/action/setAuthenticationMethod/", {
            contextId,
            authMethodName: "formBasedAuthentication",
            authMethodConfigParams: `loginUrl=${encodeURIComponent(loginUrl)}&loginRequestData=${encodeURIComponent(presetLoginRequestData)}`
          }, cfg);
          console.log(`[ZAP Auth] Configured form-based auth with preset fields: ${loginUrl} (${usernameField}/${passwordField})`);
        } catch (e) {
          errors.push(`Failed to configure preset form auth: ${e.message}`);
          try {
            await new Promise((r) => setTimeout(r, 3e3));
            await zapRequest("/JSON/authentication/action/setAuthenticationMethod/", {
              contextId,
              authMethodName: "formBasedAuthentication",
              authMethodConfigParams: `loginUrl=${encodeURIComponent(loginUrl)}&loginRequestData=${encodeURIComponent(presetLoginRequestData)}`
            }, cfg);
            console.log(`[ZAP Auth] Configured form-based auth with preset fields (retry succeeded)`);
          } catch (e2) {
            errors.push(`Retry preset form auth also failed: ${e2.message}`);
          }
        }
      } else {
        try {
          const loginPage = await fetch(loginUrl, {
            headers: { "User-Agent": "Mozilla/5.0" },
            signal: AbortSignal.timeout(5e3)
          });
          const html = await loginPage.text();
          const userFieldMatch = html.match(/name=["'](user(?:name)?|login|log|email|usr|uname|user_login)["']/i);
          if (userFieldMatch) usernameField = userFieldMatch[1];
          const passFieldMatch = html.match(/name=["'](pass(?:word)?|pwd|passwd|user_password|pass_login)["']/i);
          if (passFieldMatch) passwordField = passFieldMatch[1];
          const csrfMatch = html.match(/name=["'](csrf[_-]?token|_?token|user_token|csrfmiddlewaretoken|_csrf|authenticity_token|__RequestVerificationToken)["']/i);
          if (csrfMatch) {
            csrfField = csrfMatch[1];
            console.log(`[ZAP Auth] Detected CSRF token field: ${csrfField}`);
          }
          const submitMatch = html.match(/type=["']submit["'][^>]*name=["']([^"']+)["'][^>]*value=["']([^"']+)["']/i);
          if (submitMatch) {
            extraFields[submitMatch[1]] = submitMatch[2];
          }
          if (csrfField) {
            console.log(`[ZAP Auth] CSRF detected \u2014 using pre-auth + replacer approach for reliable authentication`);
            const preAuthResult = await preAuthenticateAndInjectSession(
              targetUrl,
              loginUrl,
              { username: bestCred.username, password: bestCred.password },
              { usernameField, passwordField, csrfField, extraFields },
              contextId,
              cfg
            );
            if (preAuthResult.success) {
              console.log(`[ZAP Auth] Pre-auth succeeded \u2014 session cookie injected via Replacer`);
              try {
                const db = await getDb();
                if (db) {
                  const scanIdMatch = contextName.match(/scan-(\d+)/);
                  if (scanIdMatch) {
                    await db.update(webAppScans).set({
                      authConfigured: 1,
                      authCredentialSource: bestCred.source,
                      authUsername: bestCred.username,
                      authMethod: "form-preauth"
                    }).where(eq(webAppScans.id, parseInt(scanIdMatch[1], 10)));
                  }
                }
              } catch {
              }
              return {
                configured: true,
                method: "form-preauth",
                username: bestCred.username,
                contextId,
                userId: void 0,
                errors: []
              };
            } else {
              console.log(`[ZAP Auth] Pre-auth failed: ${preAuthResult.error} \u2014 falling back to ZAP form-based auth`);
              errors.push(`Pre-auth failed: ${preAuthResult.error}`);
            }
          }
          const formActionMatch = html.match(/<form[^>]*action=["']([^"']+)["']/i);
          const formAction = formActionMatch ? new URL(formActionMatch[1], loginUrl).toString() : loginUrl;
          let loginRequestData = `${usernameField}={%username%}&${passwordField}={%password%}`;
          if (csrfField) {
            loginRequestData += `&${csrfField}=`;
          }
          await zapRequest("/JSON/authentication/action/setAuthenticationMethod/", {
            contextId,
            authMethodName: "formBasedAuthentication",
            authMethodConfigParams: `loginUrl=${encodeURIComponent(formAction)}&loginRequestData=${encodeURIComponent(loginRequestData)}`
          }, cfg);
          console.log(`[ZAP Auth] Configured form-based auth: ${formAction} (fields: ${usernameField}/${passwordField})`);
        } catch (e) {
          errors.push(`Failed to configure form auth: ${e.message}`);
          try {
            await zapRequest("/JSON/authentication/action/setAuthenticationMethod/", {
              contextId,
              authMethodName: "formBasedAuthentication",
              authMethodConfigParams: `loginUrl=${encodeURIComponent(loginUrl)}&loginRequestData=${encodeURIComponent(`username={%username%}&password={%password%}`)}`
            }, cfg);
            console.log(`[ZAP Auth] Configured form-based auth with generic fields (fallback)`);
          } catch (e2) {
            errors.push(`Fallback form auth also failed: ${e2.message}`);
          }
        }
      }
    } else if (detectedMethod === "json") {
      const loginUrl = detectedLoginUrl || `${parsedUrl.origin}/api/login`;
      const jsonUserField = authPreset?.usernameField || "username";
      const jsonPassField = authPreset?.passwordField || "password";
      console.log(`[ZAP Auth] JSON auth fields: ${jsonUserField}/${jsonPassField} for ${loginUrl}`);
      try {
        await zapRequest("/JSON/authentication/action/setAuthenticationMethod/", {
          contextId,
          authMethodName: "jsonBasedAuthentication",
          authMethodConfigParams: `loginUrl=${encodeURIComponent(loginUrl)}&loginRequestData=${encodeURIComponent(`{"${jsonUserField}":"{%username%}","${jsonPassField}":"{%password%}"}`)}`
        }, cfg);
        console.log(`[ZAP Auth] Configured JSON-based auth: ${loginUrl}`);
      } catch (e) {
        errors.push(`Failed to set JSON auth: ${e.message}`);
      }
    }
    try {
      const { ZAP_AUTH_STRATEGIES } = await import("./zap-pentesting-knowledge-BMF2XM4O.js");
      const matchedStrategy = ZAP_AUTH_STRATEGIES.find((s) => s.type === detectedMethod);
      const loggedInRegex = matchedStrategy?.loggedInIndicator || "\\Qlogout\\E|\\Qsign.out\\E|\\Qdashboard\\E|\\Qwelcome\\E|\\Qmy.account\\E|\\Qprofile\\E";
      const loggedOutRegex = matchedStrategy?.loggedOutIndicator || "\\Qlogin\\E|\\Qsign.in\\E|\\Qauthentication.required\\E|\\Qaccess.denied\\E|\\Q401\\E";
      await zapRequest("/JSON/authentication/action/setLoggedInIndicator/", {
        contextId,
        loggedInIndicatorRegex: loggedInRegex
      }, cfg).catch(() => {
      });
      await zapRequest("/JSON/authentication/action/setLoggedOutIndicator/", {
        contextId,
        loggedOutIndicatorRegex: loggedOutRegex
      }, cfg).catch(() => {
      });
      console.log(`[ZAP Auth] Set logged-in/logged-out indicators`);
    } catch (e) {
      errors.push(`Failed to set session indicators: ${e.message}`);
    }
    let userId;
    try {
      const userResult = await zapRequest("/JSON/users/action/newUser/", {
        contextId,
        name: `${bestCred.source}-${bestCred.username}`
      }, cfg);
      userId = userResult.userId;
      if (userId) {
        await zapRequest("/JSON/users/action/setAuthenticationCredentials/", {
          contextId,
          userId,
          authCredentialsConfigParams: `username=${encodeURIComponent(bestCred.username)}&password=${encodeURIComponent(bestCred.password)}`
        }, cfg);
        await zapRequest("/JSON/users/action/setUserEnabled/", {
          contextId,
          userId,
          enabled: "true"
        }, cfg);
        await zapRequest("/JSON/forcedUser/action/setForcedUser/", {
          contextId,
          userId
        }, cfg);
        await zapRequest("/JSON/forcedUser/action/setForcedUserModeEnabled/", {
          enabled: "true"
        }, cfg);
        console.log(`[ZAP Auth] Created and enabled forced user: ${bestCred.username} (source: ${bestCred.source})`);
      }
    } catch (e) {
      errors.push(`Failed to create ZAP user: ${e.message}`);
    }
    try {
      const db = await getDb();
      if (db) {
        const scanIdMatch = contextName.match(/scan-(\d+)/);
        if (scanIdMatch) {
          await db.update(webAppScans).set({
            authConfigured: 1,
            authCredentialSource: bestCred.source,
            authUsername: bestCred.username,
            authMethod: detectedMethod
          }).where(eq(webAppScans.id, parseInt(scanIdMatch[1], 10)));
        }
      }
    } catch {
    }
    return {
      configured: errors.length === 0,
      method: detectedMethod,
      username: bestCred.username,
      contextId,
      userId,
      errors
    };
  } catch (e) {
    return {
      configured: false,
      method: "none",
      username: bestCred.username,
      errors: [`Unexpected error: ${e.message}`]
    };
  }
}
var DEFAULT_ZAP_CONFIG, TARGET_PRESET_PATTERNS, CWE_TO_MITRE, ALERT_NAME_TO_MITRE, CWE_TO_MSF_MODULES, ZAP_ORCHESTRATOR_SYSTEM_PROMPT, WAF_EVASION_PROFILES, pollFailureCounters, lastZapRestart, ZAP_RESTART_COOLDOWN_MS;
var init_zap_scanner = __esm({
  "server/lib/zap-scanner.ts"() {
    init_db();
    init_schema();
    init_llm_throttle();
    init_zap_attack_playbooks();
    init_zap_pentesting_knowledge();
    init_llm_self_learning();
    DEFAULT_ZAP_CONFIG = {
      baseUrl: process.env.ZAP_BASE_URL || `http://${process.env.SCAN_SERVER_HOST || "137.184.211.238"}:8092`,
      apiKey: process.env.ZAP_API_KEY || "",
      spiderMaxDepth: 5,
      spiderMaxChildren: 20,
      activeScanPolicy: "Default Policy",
      requestDelayMs: 20,
      maxAlertsPerScan: 1e3
    };
    TARGET_PRESET_PATTERNS = [
      { preset: "juice-shop", patterns: [/juice.?shop/i, /owasp.*juice/i] },
      { preset: "dvwa", patterns: [/dvwa/i, /damn.*vulnerable.*web/i] },
      { preset: "mutillidae", patterns: [/mutillidae/i, /nowasp/i] },
      { preset: "zero-bank", patterns: [/zero\.webappsecurity/i, /zero-bank/i] },
      { preset: "altoro-mutual", patterns: [/altoromutual/i, /altoro.*mutual/i] },
      { preset: "hackazon", patterns: [/hackazon/i] },
      { preset: "webscantest", patterns: [/webscantest/i] },
      { preset: "crapi", patterns: [/crapi/i, /completely.*ridiculous.*api/i] },
      { preset: "webgoat", patterns: [/webgoat/i] },
      { preset: "vulnweb-rest", patterns: [/rest\.vulnweb/i] },
      { preset: "vulnweb-aspnet", patterns: [/aspnet\.vulnweb/i, /testasp\.vulnweb/i] },
      { preset: "testsparker-angular", patterns: [/angular\.testsparker/i, /rest\.testsparker/i] },
      { preset: "bodgeit", patterns: [/bodgeit/i] }
    ];
    CWE_TO_MITRE = {
      // SQL Injection family
      89: { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
      564: { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
      // XSS family
      79: { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
      80: { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
      // Command Injection
      78: { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
      77: { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
      // Path Traversal / LFI
      22: { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "Collection" },
      98: { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "Collection" },
      // SSRF
      918: { techniqueId: "T1090", techniqueName: "Proxy", tactic: "Command and Control" },
      // XXE
      611: { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
      // Authentication issues
      287: { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
      384: { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
      613: { techniqueId: "T1539", techniqueName: "Steal Web Session Cookie", tactic: "Credential Access" },
      // Information Disclosure
      200: { techniqueId: "T1552", techniqueName: "Unsecured Credentials", tactic: "Credential Access" },
      209: { techniqueId: "T1552", techniqueName: "Unsecured Credentials", tactic: "Credential Access" },
      // CORS / Headers
      942: { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Collection" },
      // CSRF
      352: { techniqueId: "T1185", techniqueName: "Browser Session Hijacking", tactic: "Collection" },
      // Deserialization
      502: { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
      // File Upload
      434: { techniqueId: "T1105", techniqueName: "Ingress Tool Transfer", tactic: "Command and Control" },
      // LDAP Injection
      90: { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
      // SSTI
      1336: { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
      // Weak Crypto
      327: { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Collection" },
      328: { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Collection" },
      // Open Redirect
      601: { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
      // IDOR
      639: { techniqueId: "T1530", techniqueName: "Data from Cloud Storage Object", tactic: "Collection" }
    };
    ALERT_NAME_TO_MITRE = {
      "SQL Injection": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
      "Cross Site Scripting": { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
      "Remote Code Execution": { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
      "Remote OS Command Injection": { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "Execution" },
      "Path Traversal": { techniqueId: "T1005", techniqueName: "Data from Local System", tactic: "Collection" },
      "Server Side Request Forgery": { techniqueId: "T1090", techniqueName: "Proxy", tactic: "Command and Control" },
      "XML External Entity": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
      "LDAP Injection": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
      "Session Fixation": { techniqueId: "T1078", techniqueName: "Valid Accounts", tactic: "Defense Evasion" },
      "CORS Misconfiguration": { techniqueId: "T1557", techniqueName: "Adversary-in-the-Middle", tactic: "Collection" },
      "Missing Anti-CSRF Tokens": { techniqueId: "T1185", techniqueName: "Browser Session Hijacking", tactic: "Collection" },
      "Insecure HTTP Method": { techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", tactic: "Initial Access" },
      "Directory Browsing": { techniqueId: "T1083", techniqueName: "File and Directory Discovery", tactic: "Discovery" },
      "Source Code Disclosure": { techniqueId: "T1552", techniqueName: "Unsecured Credentials", tactic: "Credential Access" },
      "Cookie Without Secure Flag": { techniqueId: "T1539", techniqueName: "Steal Web Session Cookie", tactic: "Credential Access" },
      "Content Security Policy": { techniqueId: "T1189", techniqueName: "Drive-by Compromise", tactic: "Initial Access" },
      "X-Frame-Options Header Not Set": { techniqueId: "T1185", techniqueName: "Browser Session Hijacking", tactic: "Collection" }
    };
    CWE_TO_MSF_MODULES = {
      89: ["exploit/multi/http/sqli_generic", "auxiliary/sqli/oracle/dbms_xmlquery_getxml"],
      78: ["exploit/multi/http/oscommand_generic", "exploit/unix/webapp/php_eval"],
      22: ["exploit/multi/http/lfi_generic", "auxiliary/scanner/http/dir_traversal"],
      98: ["exploit/multi/http/rfi_generic", "exploit/unix/webapp/php_include"],
      611: ["exploit/multi/http/xxe_generic", "auxiliary/scanner/http/xxe"],
      434: ["exploit/multi/http/upload_exec", "exploit/multi/http/webshell_upload"],
      502: ["exploit/multi/http/deserialization", "exploit/multi/misc/java_rmi_server"],
      918: ["auxiliary/scanner/http/ssrf_detector"],
      90: ["auxiliary/gather/ldap_query"]
    };
    ZAP_ORCHESTRATOR_SYSTEM_PROMPT = `You are an expert OWASP ZAP scan orchestrator for the AC3 offensive security platform. You configure optimal scans based on the target's discovered technology stack. Your goal is to gain a foothold on the server by finding exploitable vulnerabilities, leaked secrets, exposed backend storage, and API credentials.

## ZAP API Categories You Can Configure:
1. **spider** \u2014 Traditional crawler: maxDepth (1-10), maxChildren (0-100), threadCount (1-20), handleParameters, parseComments, parseGit, parseSVNEntries, parseRobotsTxt, parseSitemapXml, postForm, processForm, acceptCookies, sendRefererHeader
2. **ajaxSpider** \u2014 JavaScript-heavy app crawler: browserType (firefox/chrome/htmlunit), maxCrawlDepth (0-10), maxCrawlStates (0-1000000), maxDuration (0-60 min), numberOfBrowsers (1-4), clickDefaultElems, clickElemsOnce, eventWait (ms), randomInputs
3. **ascan** (Active Scanner) \u2014 Vulnerability testing: scanPolicy, threadPerHost (1-20), delayInMs (0-5000), handleAntiCSRFTokens, injectPluginIdInHeader, scanHeadersAllRequests, maxRuleDurationInMins, maxScanDurationInMins
4. **pscan** (Passive Scanner) \u2014 Non-intrusive analysis: enableAllScanners, maxAlertsPerRule, scanOnlyInScope
5. **authentication** \u2014 Login handling: formBased, jsonBased, httpAuth, scriptBased
6. **context** \u2014 Scope management: includeInContext, excludeFromContext, technologyList
7. **script** \u2014 Custom attack scripts
8. **forcedUser** \u2014 Authenticated scanning
9. **openapi/graphql/soap** \u2014 Import API specs

## CRITICAL: ZAP Scan Rule IDs by Technology
You MUST reference these exact rule IDs in your customRules array to enable/disable specific checks.

### Universal Foothold Rules (ALWAYS enable for active scans):
- 40012: XSS Reflected | 40014: XSS Persistent | 40016: XSS Persistent (Prime)
- 40018: SQL Injection | 40019: SQL Injection (MySQL) | 40020: SQL Injection (Hypersonic) | 40021: SQL Injection (Oracle) | 40022: SQL Injection (PostgreSQL) | 40024: SQL Injection (SQLite) | 40027: SQL Injection (MsSQL)
- 90019: Server Side Code Injection (eval/exec) | 90020: Remote OS Command Injection
- 40003: CRLF Injection | 6: Path Traversal | 7: Remote File Inclusion
- 40032: .htaccess Info Leak | 40034: .env Info Leak | 40035: Hidden File Finder
- 10095: Backup File Disclosure | 10048: Spring Actuator Info Leak
- 90034: Cloud Metadata Potentially Exposed (AWS/GCP/Azure IMDS)
- 40042: Spring4Shell (CVE-2022-22965) | 40043: Log4Shell (CVE-2021-44228)
- 40045: Spring Actuator Test | 90021: XPath Injection | 90023: XML External Entity Attack
- 40009: Server Side Include | 40008: Parameter Tampering | 40013: Session ID in URL Rewrite

### Secrets & Backend Storage Discovery Rules:
- 40034: .env Information Leak (DB creds, API keys, S3 secrets)
- 40032: .htaccess Information Leak (rewrite rules, auth configs)
- 40035: Hidden File Finder (backup files, config dumps, .git)
- 10095: Backup File Disclosure (*.bak, *.old, *.orig, *.save)
- 90034: Cloud Metadata (AWS IMDS \u2192 IAM creds \u2192 S3 bucket access)
- 10048: Spring Actuator (env endpoint \u2192 DB/S3/API credentials)
- 10045: Source Code Disclosure (WEB-INF/web.xml, .svn, .git)
- 41: Source Code Disclosure (SVN) | 42: Source Code Disclosure (Git) | 43: Source Code Disclosure (File Inclusion)
- 0: Directory Browsing (find exposed /uploads, /backups, /storage)

### Technology-Specific Rules:
**PHP**: 90019 (Code Injection via eval), 7 (Remote File Include), 6 (Path Traversal/LFI), 40034 (.env), 30001 (Buffer Overflow), 40003 (CRLF)
**Java/Spring**: 40042 (Spring4Shell), 40043 (Log4Shell), 40045 (Spring Actuator), 10048 (Actuator Info), 90019 (EL Injection), 90023 (XXE), 40029 (TRACE)
**Python/Django/Flask**: 90019 (SSTI Jinja2), 40018 (SQLi), 90020 (Command Injection), 40034 (.env), 6 (Path Traversal)
**Node.js/Express**: 40018 (NoSQL Injection via SQLi scanner), 90019 (Prototype Pollution via code injection), 40034 (.env), 40028 (ELMAH Info Leak)
**ASP.NET**: 40029 (TRACE), 40032 (.htaccess/web.config), 10095 (Backup), 90019 (ViewState deserialization), 40034 (.env)
**WordPress**: 40034 (.env), 40035 (Hidden Files: wp-config.php.bak), 10095 (Backup), 0 (Directory Browsing /wp-content/uploads)
**Ruby/Rails**: 90019 (SSTI ERB), 40018 (SQLi), 90020 (Command Injection), 40034 (.env), 10095 (Backup database.yml)
**API (REST/GraphQL)**: 40018 (Injection), 40003 (CRLF), 40008 (Parameter Tampering), 90020 (Command Injection), 40013 (Session in URL)

### Injection Testing for Foothold (prioritize HIGH strength):
- SQL Injection: 40018, 40019, 40020, 40021, 40022, 40024, 40027 \u2192 leads to DB dump, credential theft, or OS command via xp_cmdshell/INTO OUTFILE
- Command Injection: 90020 \u2192 direct RCE
- Code Injection: 90019 \u2192 eval/exec \u2192 RCE
- SSTI: 90019 \u2192 template engine RCE (Jinja2, Twig, Freemarker, ERB)
- File Include: 7 (RFI \u2192 webshell), 6 (LFI \u2192 /etc/passwd, source code)
- XXE: 90023 \u2192 file read, SSRF, potential RCE
- File Upload: test via parameter tampering (40008) + hidden file discovery (40035)

## Scan Policies:
- **Default Policy**: All rules enabled at default thresholds
- **Heavy/Thorough**: Maximum coverage \u2014 set all injection rules to HIGH strength/INSANE threshold
- **API-Focused**: No UI-related checks \u2014 for REST/GraphQL APIs

## Authentication Strategies:
- **Form login**: formBased auth with logged-in/logged-out indicators
- **JWT/Bearer token**: script-based auth to inject Authorization header
- **OAuth2**: browser-based or script to complete OAuth flow
- **API key**: replacer rule to inject API key header

## Output Format:
Return a JSON object with these fields:
{
  "scanPolicy": "Default Policy" | "Heavy" | "API",
  "useAjaxSpider": boolean,
  "spiderConfig": { maxDepth, maxChildren, threadCount, parseComments, parseGit, parseSitemapXml, postForm },
  "ajaxSpiderConfig": { maxCrawlDepth, maxCrawlStates, maxDuration, numberOfBrowsers, clickDefaultElems },
  "activeScanConfig": { threadPerHost, delayInMs, handleAntiCSRFTokens, scanHeadersAllRequests, maxRuleDurationInMins },
  "technologies": ["Java", "Spring", ...],
  "authStrategy": "none" | "form" | "json" | "bearer" | "apikey" | "oauth2",
  "authConfig": { ... },
  "contextIncludes": ["regex patterns"],
  "contextExcludes": ["regex patterns for logout, static assets"],
  "importSpec": null | { type: "openapi" | "graphql" | "soap", url: "spec URL" },
  "customRules": ["enable:40018:HIGH:INSANE", "enable:90019:HIGH:INSANE", "enable:40034:MEDIUM:DEFAULT", ...],
  "rationale": "Brief explanation including which foothold vectors are prioritized and why"
}

## IMPORTANT:
- customRules format: "enable:<ruleId>:<strength>:<threshold>" or "disable:<ruleId>"
- Strength: OFF, DEFAULT, LOW, MEDIUM, HIGH, INSANE
- Threshold: OFF, DEFAULT, LOW, MEDIUM, HIGH
- For foothold acquisition: set all injection rules to HIGH strength, INSANE threshold
- For secrets discovery: enable 40034, 40032, 40035, 10095, 90034, 10048 at MEDIUM strength
- For JavaScript/source code analysis: enable 10025 (Suspicious Comments), 10094 (Base64 Disclosure), 100034 (Google API Key), 10099 (Source Code Disclosure PHP), 42 (Git Disclosure), 41 (SVN Disclosure), 10045 (WEB-INF Disclosure)
- For browser storage secrets: enable 120000, 120001, 120002 (requires Ajax Spider with browser-based crawling)
- ALWAYS set parseComments=true and parseGit=true in spider config to discover source maps and hidden files
- ALWAYS use Ajax Spider for JavaScript-heavy apps to trigger client-side storage and DOM-based vulnerabilities
- ALWAYS include technology-specific rules based on detected stack
- ALWAYS include secrets/storage discovery rules regardless of technology
- ALWAYS include source code disclosure rules (41, 42, 43, 10045, 10099) regardless of technology`;
    WAF_EVASION_PROFILES = {
      "Cloudflare": {
        name: "Cloudflare Evasion",
        maxReqPerSec: 2,
        delayInMs: 500,
        threadPerHost: 1,
        spiderThreads: 2,
        maxRuleDurationInMins: 20,
        useAjaxSpider: false,
        rotateUserAgents: true,
        encodePayloads: true,
        techniques: [
          "Rate limit to 2 req/sec to avoid Cloudflare rate-based rules",
          "Rotate User-Agent between Chrome, Firefox, Safari, Edge variants",
          "Use double URL encoding for injection payloads",
          "Avoid common scanner signatures in spider requests",
          "Set Referer header to target domain on all requests",
          "Add Accept-Language and Accept-Encoding headers for browser mimicry"
        ]
      },
      "AWS WAF": {
        name: "AWS WAF Evasion",
        maxReqPerSec: 5,
        delayInMs: 200,
        threadPerHost: 2,
        spiderThreads: 3,
        maxRuleDurationInMins: 15,
        useAjaxSpider: false,
        rotateUserAgents: true,
        encodePayloads: true,
        techniques: [
          "Vary HTTP methods (GET/POST/PUT) to avoid method-based rules",
          "Use Unicode normalization for injection payloads",
          "Test with different Content-Type headers (form, json, xml)",
          "Fragment payloads across multiple parameters"
        ]
      },
      "Akamai": {
        name: "Akamai Evasion",
        maxReqPerSec: 1,
        delayInMs: 1e3,
        threadPerHost: 1,
        spiderThreads: 1,
        maxRuleDurationInMins: 25,
        useAjaxSpider: false,
        rotateUserAgents: true,
        encodePayloads: true,
        techniques: [
          "Very slow scan rate (1 req/sec) \u2014 Akamai has aggressive behavioral detection",
          "Use custom User-Agent strings (not common scanner signatures)",
          "Fragment payloads across multiple parameters",
          "Avoid automated scanner fingerprints in headers"
        ]
      },
      "Imperva/Incapsula": {
        name: "Imperva Evasion",
        maxReqPerSec: 3,
        delayInMs: 350,
        threadPerHost: 1,
        spiderThreads: 2,
        maxRuleDurationInMins: 20,
        useAjaxSpider: true,
        rotateUserAgents: true,
        encodePayloads: true,
        techniques: [
          "Handle Incapsula JavaScript challenges (use AJAX spider)",
          "Implement cookie handling for challenge responses",
          "Use browser-like request patterns with full header sets",
          "Solve JavaScript challenges before active scanning"
        ]
      },
      "ModSecurity": {
        name: "ModSecurity Evasion",
        maxReqPerSec: 5,
        delayInMs: 200,
        threadPerHost: 2,
        spiderThreads: 3,
        maxRuleDurationInMins: 15,
        useAjaxSpider: false,
        rotateUserAgents: false,
        encodePayloads: true,
        techniques: [
          "Identify CRS paranoia level via incremental payload testing",
          "Use Unicode normalization bypasses for SQL keywords",
          "Test with different character encodings (UTF-8, UTF-16, ISO-8859-1)",
          "Check for rule exclusion via specific paths or parameters",
          "Use case variation in SQL/XSS keywords"
        ]
      },
      "F5 BIG-IP ASM": {
        name: "F5 BIG-IP Evasion",
        maxReqPerSec: 3,
        delayInMs: 350,
        threadPerHost: 2,
        spiderThreads: 2,
        maxRuleDurationInMins: 15,
        useAjaxSpider: false,
        rotateUserAgents: true,
        encodePayloads: true,
        techniques: [
          "Test HTTP parameter pollution techniques",
          "Use HTTP method override headers (X-HTTP-Method-Override)",
          "Try alternative encoding schemes (hex, octal, base64)",
          "Check for bypass via HTTP/2 protocol"
        ]
      }
    };
    pollFailureCounters = /* @__PURE__ */ new Map();
    lastZapRestart = 0;
    ZAP_RESTART_COOLDOWN_MS = 5 * 60 * 1e3;
  }
});

export {
  DEFAULT_ZAP_CONFIG,
  mapToMitre,
  findMsfModules,
  generateLLMScanConfig,
  getWafEvasionProfile,
  applyWafEvasionConfig,
  triageFinding,
  checkZapHealth,
  importOpenApiSpec,
  importGraphQLSpec,
  importSoapSpec,
  cleanupStaleScansForTarget,
  startScan,
  pollScanProgress,
  stopScan,
  listScans,
  getScanFindings,
  getScanStats,
  retryScan,
  deleteScan,
  seedDemoData,
  clearDemoData,
  configureZapAuthentication,
  init_zap_scanner
};
