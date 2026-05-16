import {
  buildFPSuppressionContext,
  init_fp_suppression_rules
} from "./chunk-2NMZEWLR.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-GTXFXXF6.js";
import {
  buildMissedVulnContext,
  init_missed_vuln_training_knowledge
} from "./chunk-5DEWV7VV.js";
import {
  init_api_resilience,
  isRetryableError,
  retryWithBackoff
} from "./chunk-YWKNEYVH.js";
import {
  executeTool,
  init_scan_server_executor
} from "./chunk-KW2CWOOD.js";
import "./chunk-Y2UB65JM.js";
import {
  buildPhaseToolContext,
  buildVulnTestingContext,
  init_bugbounty_methodology_knowledge
} from "./chunk-WP62CKNZ.js";
import {
  getFalsePositiveTriageContext,
  init_zap_pentesting_knowledge
} from "./chunk-E7WGGYZE.js";
import "./chunk-PIYDKQBM.js";
import "./chunk-JPJQZXKW.js";
import "./chunk-SD56WPOS.js";
import "./chunk-TCEHBLTC.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-L4JENJ4Z.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/llm-scan-feedback.ts
function buildAnalysisPrompt(toolInventory) {
  const toolDescriptions = toolInventory.map(
    (t) => `- **${t.name}** [${t.category}]: ${t.description}
  Examples: ${t.exampleArgs.map((a) => `\`${t.name} ${a}\``).join(", ")}`
  ).join("\n");
  return `You are an expert penetration tester and security analyst integrated into an automated engagement pipeline.

Your role is to analyze scan findings and decide whether additional targeted scans are needed to:
1. Confirm potential vulnerabilities that lack sufficient evidence
2. Enumerate services/endpoints that were discovered but not fully explored
3. Check for cloud misconfigurations on newly discovered cloud assets
4. Gather version/banner information needed to identify specific CVEs
5. Probe for common weaknesses in identified technologies

## Available Tools

${toolDescriptions}

## Rules
- Only request scans that will provide NEW information not already in the findings
- Each scan request must include a clear rationale explaining what gap it fills
- Prioritize scans by potential impact (critical findings first)
- Use passive tools when possible; only use active tools when passive data is insufficient
- For cloud assets, always check storage permissions and exposed credentials
- Respect the scan budget \u2014 don't waste scans on low-value targets
- Set appropriate depth: "quick" for simple checks, "standard" for thorough scans, "deep" for comprehensive analysis
- NEVER scan targets outside the engagement scope
- If you have enough data to form a complete attack plan, set satisfied=true

## Convergence Guidelines (IMPORTANT)
- You should set satisfied=true when you have SUFFICIENT data to plan attacks \u2014 you do NOT need PERFECT coverage
- If you already have 5+ findings across multiple severity levels, that is usually sufficient
- If previous re-scans returned similar data to what you already have, set satisfied=true (diminishing returns)
- Do NOT request the same scan (same tool + same target + same args) that was already executed in previous iterations
- If the scan budget is 3 or fewer, strongly prefer satisfied=true unless there is a critical gap
- A "critical gap" means a HIGH/CRITICAL severity finding that needs confirmation, not minor enumeration
- When in doubt, set satisfied=true \u2014 the engagement pipeline has other phases that will catch remaining issues

## Evasion & Bypass Knowledge
When requesting scans against targets with firewalls or WAFs, consider these techniques:
- Use rate limiting (masscan --rate 100) and timing evasion (naabu -rate 50) for firewall bypass
- For file upload testing, use extension splitting payloads: null byte (%00), newline (%0a), semicolon (%3B), Unicode overlong encoding
- For WAF bypass: identify vendor first (wafw00f), then use encoding tricks, chunked transfer, or parameter pollution
- Prefer passive/stealthy tools when the target has active defenses

## Bug Bounty Attack Methodology
When analyzing findings, use this attack methodology knowledge to identify gaps:
${buildVulnTestingContext("sql_injection")}

## Phase-Specific Tool Recommendations
${buildPhaseToolContext("exploitation")}

## Commonly Missed Vulnerability Patterns
${buildMissedVulnContext()}

## False Positive Triage
When analyzing ZAP scan findings, use this knowledge to classify findings:
${getFalsePositiveTriageContext()}

${buildFPSuppressionContext()}

**Apply FP triage before requesting re-scans:**
- If a finding matches 2+ FP indicators, classify as likely FP and do NOT request re-scans for it
- If a finding matches TP indicators, prioritize confirmation scans
- For very_high/high FP rate alerts, require strong TP indicators before requesting follow-up

## Response Format
You MUST respond with valid JSON matching this schema:
{
  "satisfied": boolean,        // true if you have enough data, false if you need more scans
  "analysis": string,          // Your analysis of current findings and what's missing
  "scanRequests": [            // Empty array if satisfied=true
    {
      "tool": string,          // Tool name from the inventory
      "args": string,          // Command-line arguments (DO NOT include the tool name)
      "target": string,        // Target host/IP/URL
      "rationale": string,     // Why this scan is needed
      "depth": "quick"|"standard"|"deep",
      "priority": number       // 1=highest priority
    }
  ]
}`;
}
async function analyzeFindingsAndRequestScans(findings, previousScans, scope, budgetRemaining) {
  const systemPrompt = buildAnalysisPrompt(TOOL_INVENTORY);
  const findingsSummary = findings.map((f) => ({
    type: f.type || f.severity || "unknown",
    title: f.title || f.name || "Untitled",
    target: f.target || f.host || f.asset || "unknown",
    port: f.port,
    service: f.service,
    details: typeof f.details === "string" ? f.details.slice(0, 500) : JSON.stringify(f.details || {}).slice(0, 500),
    severity: f.severity,
    confidence: f.confidence
  }));
  const previousScansSummary = previousScans.map((s) => ({
    tool: s.request.tool,
    args: s.request.args,
    target: s.request.target,
    rationale: s.request.rationale,
    exitCode: s.result.exitCode,
    outputPreview: s.result.stdout.slice(0, 1e3),
    errorPreview: s.result.stderr.slice(0, 500)
  }));
  const severityCounts = {};
  for (const f of findings) {
    const sev = (f.severity || "info").toLowerCase();
    severityCounts[sev] = (severityCounts[sev] || 0) + 1;
  }
  const severityLine = Object.entries(severityCounts).map(([k, v]) => `${k}: ${v}`).join(", ");
  const userMessage = `## Engagement Scope
Targets: ${scope.targets.join(", ")}
${scope.engagementName ? `Engagement: ${scope.engagementName}` : ""}
Scan budget remaining: ${budgetRemaining} scans

## Current Findings (${findings.length} total)
Severity distribution: ${severityLine || "none"}
${JSON.stringify(findingsSummary, null, 2)}

${previousScans.length > 0 ? `## Previous Re-Scans (${previousScans.length} executed)
${JSON.stringify(previousScansSummary, null, 2)}

Note: If previous re-scans did not reveal significant new attack surface, you should set satisfied=true.` : "## No previous re-scans executed yet."}

Analyze these findings. Are there gaps that require additional scanning? If so, specify exactly which tools to run and why. If you have sufficient data to plan attacks, set satisfied=true.`;
  const response = await throttledLLMCall({
    _priority: "bulk",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage }
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "scan_feedback",
        strict: true,
        schema: {
          type: "object",
          properties: {
            satisfied: { type: "boolean", description: "Whether enough data is available" },
            analysis: { type: "string", description: "Analysis of findings and gaps" },
            scanRequests: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  tool: { type: "string" },
                  args: { type: "string" },
                  target: { type: "string" },
                  rationale: { type: "string" },
                  depth: { type: "string", enum: ["quick", "standard", "deep"] },
                  priority: { type: "integer" }
                },
                required: ["tool", "args", "target", "rationale", "depth", "priority"],
                additionalProperties: false
              }
            }
          },
          required: ["satisfied", "analysis", "scanRequests"],
          additionalProperties: false
        }
      }
    }
  });
  const rawContent = response.choices?.[0]?.message?.content;
  if (!rawContent) throw new Error("Empty LLM response");
  const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch (jsonErr) {
    const jsonMatch = content.match(/```(?:json)?\s*([\s\S]*?)```/) || content.match(/(\{[\s\S]*\})/);
    if (jsonMatch) {
      try {
        parsed = JSON.parse(jsonMatch[1].trim());
      } catch {
        console.error(`[ScanFeedback] LLM returned unparseable response: ${content.slice(0, 500)}`);
        return {
          satisfied: true,
          analysis: `LLM response could not be parsed. Treating as satisfied. Raw: ${content.slice(0, 200)}`,
          scanRequests: []
        };
      }
    } else {
      console.error(`[ScanFeedback] LLM returned non-JSON response: ${content.slice(0, 500)}`);
      return {
        satisfied: true,
        analysis: `LLM response was not valid JSON. Treating as satisfied. Raw: ${content.slice(0, 200)}`,
        scanRequests: []
      };
    }
  }
  if (typeof parsed.satisfied !== "boolean") {
    console.warn(`[ScanFeedback] LLM response missing 'satisfied' field, defaulting to true`);
    parsed.satisfied = true;
  }
  if (typeof parsed.analysis !== "string") {
    parsed.analysis = "No analysis provided by LLM.";
  }
  if (!Array.isArray(parsed.scanRequests)) {
    parsed.scanRequests = [];
  }
  const validatedRequests = [];
  const toolNames = new Set(TOOL_INVENTORY.map((t) => t.name));
  for (const req of parsed.scanRequests || []) {
    if (!toolNames.has(req.tool)) {
      console.warn(`[ScanFeedback] LLM requested unknown tool: ${req.tool}, skipping`);
      continue;
    }
    const targetInScope = scope.targets.some(
      (t) => req.target.includes(t) || t.includes(req.target)
    );
    if (!targetInScope) {
      console.warn(`[ScanFeedback] Target ${req.target} not in scope, skipping`);
      continue;
    }
    validatedRequests.push({
      tool: req.tool,
      args: req.args,
      target: req.target,
      rationale: req.rationale,
      depth: req.depth || "standard",
      priority: req.priority || 5
    });
  }
  validatedRequests.sort((a, b) => a.priority - b.priority);
  return {
    satisfied: parsed.satisfied,
    analysis: parsed.analysis,
    scanRequests: validatedRequests
  };
}
async function executeScanRequests(requests, engagementId) {
  const results = [];
  for (const req of requests) {
    const tool = TOOL_INVENTORY.find((t) => t.name === req.tool);
    const baseTimeout = tool?.defaultTimeout || 120;
    const multiplier = DEPTH_TIMEOUT_MULTIPLIER[req.depth] || 1;
    const timeoutSeconds = Math.ceil(baseTimeout * multiplier);
    console.log(
      `[ScanFeedback] Executing: ${req.tool} ${req.args} (depth=${req.depth}, timeout=${timeoutSeconds}s)`
    );
    console.log(`[ScanFeedback] Rationale: ${req.rationale}`);
    const result = await executeTool({
      tool: req.tool,
      args: req.args,
      target: req.target,
      timeoutSeconds,
      engagementId,
      sudo: tool?.requiresSudo || false
    });
    results.push({
      request: req,
      result,
      executedAt: Date.now()
    });
    await new Promise((r) => setTimeout(r, 1e3));
  }
  return results;
}
async function runFeedbackLoop(initialFindings, scope, config = {}) {
  const {
    maxIterations = 5,
    maxTotalScans = 12,
    maxScansPerIteration = 4,
    minIterations = 0,
    staleThreshold = 2,
    engagementId,
    onProgress
  } = config;
  const state = {
    iteration: 0,
    totalScansExecuted: 0,
    budgetRemaining: maxTotalScans,
    history: [],
    satisfied: false
  };
  let allFindings = [...initialFindings];
  let previousFindingsCount = allFindings.length;
  let staleIterations = 0;
  const STALE_THRESHOLD = staleThreshold;
  for (let i = 0; i < maxIterations; i++) {
    state.iteration = i;
    state.budgetRemaining = maxTotalScans - state.totalScansExecuted;
    console.log(
      `
[ScanFeedback] === Iteration ${i + 1}/${maxIterations} === Budget: ${state.budgetRemaining} scans remaining`
    );
    if (staleIterations >= STALE_THRESHOLD && i >= minIterations) {
      console.log(`[ScanFeedback] Convergence detected: no new findings for ${staleIterations} iterations, forcing satisfaction`);
      state.satisfied = true;
      state.finalAnalysis = `Feedback loop converged after ${i} iterations \u2014 no new findings discovered in last ${staleIterations} iterations. ${state.totalScansExecuted} total scans executed.`;
      onProgress?.(state);
      break;
    }
    let analysis;
    try {
      analysis = await retryWithBackoff(
        () => analyzeFindingsAndRequestScans(allFindings, state.history, scope, state.budgetRemaining),
        { maxRetries: 3, baseDelayMs: 2e3, retryableCheck: isRetryableError }
      );
    } catch (err) {
      console.error(`[ScanFeedback] LLM analysis failed after retries: ${err.message}`);
      state.finalAnalysis = `Feedback loop stopped: LLM analysis unavailable (${err.message}). Proceeding with ${allFindings.length} findings from ${state.totalScansExecuted} scans.`;
      onProgress?.(state);
      break;
    }
    console.log(`[ScanFeedback] LLM satisfied: ${analysis.satisfied}`);
    console.log(`[ScanFeedback] Analysis: ${analysis.analysis.slice(0, 200)}...`);
    console.log(`[ScanFeedback] Requested ${analysis.scanRequests.length} scans`);
    if (analysis.satisfied || analysis.scanRequests.length === 0) {
      state.satisfied = true;
      state.finalAnalysis = analysis.analysis;
      onProgress?.(state);
      break;
    }
    const allowedScans = analysis.scanRequests.slice(
      0,
      Math.min(maxScansPerIteration, state.budgetRemaining)
    );
    if (allowedScans.length === 0) {
      console.log("[ScanFeedback] Budget exhausted, stopping loop");
      state.finalAnalysis = analysis.analysis;
      onProgress?.(state);
      break;
    }
    const deduped = allowedScans.filter((scan) => {
      const isDuplicate = state.history.some(
        (h) => h.request.tool === scan.tool && h.request.target === scan.target && h.request.args === scan.args
      );
      if (isDuplicate) {
        console.log(`[ScanFeedback] Skipping duplicate scan: ${scan.tool} ${scan.args} on ${scan.target}`);
      }
      return !isDuplicate;
    });
    if (deduped.length === 0) {
      console.log("[ScanFeedback] All requested scans are duplicates, forcing satisfaction");
      state.satisfied = true;
      state.finalAnalysis = `LLM requested only previously-executed scans \u2014 treating as converged. ${analysis.analysis}`;
      onProgress?.(state);
      break;
    }
    const scanResults = await executeScanRequests(deduped, engagementId);
    state.history.push(...scanResults);
    state.totalScansExecuted += scanResults.length;
    let newFindingsThisIteration = 0;
    for (const sr of scanResults) {
      if (sr.result.exitCode === 0 && sr.result.stdout.length > 0) {
        allFindings.push({
          type: "rescan_result",
          title: `Re-scan: ${sr.request.tool} on ${sr.request.target}`,
          target: sr.request.target,
          tool: sr.request.tool,
          details: sr.result.stdout.slice(0, 5e3),
          rationale: sr.request.rationale,
          severity: "info",
          confidence: "high"
        });
        newFindingsThisIteration++;
      }
    }
    if (allFindings.length <= previousFindingsCount || newFindingsThisIteration === 0) {
      staleIterations++;
      console.log(`[ScanFeedback] Stale iteration ${staleIterations}/${STALE_THRESHOLD} \u2014 no new findings`);
    } else {
      staleIterations = 0;
      console.log(`[ScanFeedback] ${newFindingsThisIteration} new findings this iteration`);
    }
    previousFindingsCount = allFindings.length;
    onProgress?.(state);
  }
  if (!state.satisfied && !state.finalAnalysis) {
    state.finalAnalysis = `Feedback loop completed after ${state.iteration + 1} iterations with ${state.totalScansExecuted} total scans. Budget: ${state.budgetRemaining} remaining.`;
  }
  return state;
}
function getFeedbackLoopSummary(state) {
  const lines = [
    `## Scan Feedback Loop Summary`,
    `- Iterations: ${state.iteration + 1}`,
    `- Total scans executed: ${state.totalScansExecuted}`,
    `- Budget remaining: ${state.budgetRemaining}`,
    `- LLM satisfied: ${state.satisfied}`,
    ""
  ];
  if (state.history.length > 0) {
    lines.push("### Re-Scans Executed");
    for (const h of state.history) {
      const status = h.result.exitCode === 0 ? "OK" : `FAIL(${h.result.exitCode})`;
      lines.push(
        `- **${h.request.tool}** \u2192 ${h.request.target} [${status}, ${h.result.durationMs}ms]`
      );
      lines.push(`  Rationale: ${h.request.rationale}`);
    }
    lines.push("");
  }
  if (state.finalAnalysis) {
    lines.push("### Final Analysis");
    lines.push(state.finalAnalysis);
  }
  return lines.join("\n");
}
var TOOL_INVENTORY, DEPTH_TIMEOUT_MULTIPLIER;
var init_llm_scan_feedback = __esm({
  "server/lib/llm-scan-feedback.ts"() {
    init_llm_throttle();
    init_scan_server_executor();
    init_api_resilience();
    init_zap_pentesting_knowledge();
    init_bugbounty_methodology_knowledge();
    init_missed_vuln_training_knowledge();
    init_fp_suppression_rules();
    TOOL_INVENTORY = [
      // Passive reconnaissance
      {
        name: "curl",
        description: "HTTP client for banner grabbing, header analysis, and API probing. Use -I for headers only, -k for insecure SSL, -s for silent mode.",
        category: "passive",
        exampleArgs: ["-sI https://target.com", "-sk https://target.com/.well-known/security.txt", "-s https://target.com/robots.txt"],
        defaultTimeout: 30,
        requiresSudo: false
      },
      {
        name: "sslscan",
        description: "SSL/TLS configuration scanner. Checks cipher suites, certificate details, protocol versions, and vulnerabilities like Heartbleed.",
        category: "passive",
        exampleArgs: ["target.com:443", "--no-colour target.com:443"],
        defaultTimeout: 60,
        requiresSudo: false
      },
      {
        name: "testssl",
        description: "Comprehensive TLS/SSL testing tool. Checks protocols, ciphers, vulnerabilities (POODLE, BEAST, CRIME, DROWN, Heartbleed), certificate chain, HSTS.",
        category: "passive",
        exampleArgs: ["--quiet target.com:443", "--severity HIGH --quiet target.com:443", "-p target.com:443"],
        defaultTimeout: 120,
        requiresSudo: false
      },
      {
        name: "whatweb",
        description: "Web technology fingerprinting. Identifies CMS, frameworks, server software, JavaScript libraries, and plugins.",
        category: "passive",
        exampleArgs: ["-a 3 https://target.com", "--color=never -a 3 https://target.com"],
        defaultTimeout: 60,
        requiresSudo: false
      },
      {
        name: "dig",
        description: "DNS lookup utility. Query A, AAAA, MX, NS, TXT, CNAME, SOA records. Check for zone transfers with AXFR.",
        category: "passive",
        exampleArgs: ["target.com ANY", "target.com AXFR @ns1.target.com", "+short target.com MX"],
        defaultTimeout: 30,
        requiresSudo: false
      },
      {
        name: "whois",
        description: "Domain/IP registration lookup. Shows registrar, creation date, nameservers, and organization details.",
        category: "passive",
        exampleArgs: ["target.com", "192.168.1.1"],
        defaultTimeout: 30,
        requiresSudo: false
      },
      // Active scanning
      {
        name: "scanforge-discovery",
        description: "Network scanner for port discovery, service detection, OS fingerprinting, and vulnerability scanning via Nuclei templates. Use -sV for service versions, -sC for default scripts, --script for specific Nuclei templates.",
        category: "active",
        exampleArgs: [
          "-sV -sC -p 80,443 target.com",
          "-sV --script=http-enum,http-headers target.com",
          "--script=vuln -p 443 target.com",
          "-sV --script=ssl-enum-ciphers -p 443 target.com",
          "-sU -sV --top-ports 20 target.com"
        ],
        defaultTimeout: 180,
        requiresSudo: false
      },
      {
        name: "nuclei",
        description: "Fast vulnerability scanner using community templates. Supports CVE detection, misconfigurations, exposed panels, default credentials, and technology detection.",
        category: "active",
        exampleArgs: [
          "-u https://target.com -severity critical,high",
          "-u https://target.com -tags cve,misconfig",
          "-u https://target.com -tags cloud,aws,s3",
          "-u https://target.com -tags exposed-panels",
          "-u https://target.com -t /root/nuclei-templates/http/misconfiguration/"
        ],
        defaultTimeout: 300,
        requiresSudo: false
      },
      {
        name: "nikto",
        description: "Web server scanner for dangerous files, outdated software, and server misconfigurations. Checks for 6700+ potentially dangerous files/programs.",
        category: "active",
        exampleArgs: ["-h https://target.com", "-h https://target.com -Tuning 1234567890abc"],
        defaultTimeout: 300,
        requiresSudo: false
      },
      {
        name: "gobuster",
        description: "Directory/file brute-forcer and DNS subdomain enumerator. Use 'dir' mode for web paths, 'dns' for subdomains, 'vhost' for virtual hosts.",
        category: "active",
        exampleArgs: [
          "dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -q",
          "dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html,js,txt -q",
          "dns -d target.com -w /usr/share/wordlists/dirb/common.txt -q"
        ],
        defaultTimeout: 180,
        requiresSudo: false
      },
      {
        name: "ffuf",
        description: "Fast web fuzzer for directory discovery, parameter fuzzing, and virtual host enumeration. Extremely fast with filtering options.",
        category: "active",
        exampleArgs: [
          "-u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403",
          "-u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 404 -o /tmp/ffuf_out.json -of json"
        ],
        defaultTimeout: 180,
        requiresSudo: false
      },
      {
        name: "httpx",
        description: "HTTP toolkit for probing, technology detection, and status code checking. Supports bulk URL probing with detailed output.",
        category: "active",
        exampleArgs: [
          "-u https://target.com -status-code -title -tech-detect -follow-redirects",
          "-u https://target.com -status-code -content-length -web-server -ip"
        ],
        defaultTimeout: 60,
        requiresSudo: false
      },
      // Cloud-specific
      {
        name: "cloud_enum",
        description: "Multi-cloud storage enumeration. Discovers open S3 buckets, Azure blobs, and GCP storage for a given keyword/company name.",
        category: "cloud",
        exampleArgs: ["-k companyname", "-k companyname -t 10"],
        defaultTimeout: 300,
        requiresSudo: false
      },
      {
        name: "s3scanner",
        description: "S3 bucket permission scanner. Checks if buckets are publicly listable, writable, or have ACL misconfigurations.",
        category: "cloud",
        exampleArgs: ["scan --bucket bucketname", "scan --bucket company-assets"],
        defaultTimeout: 60,
        requiresSudo: false
      },
      {
        name: "trufflehog",
        description: "Secret scanner for exposed credentials. Scans git repos, S3 buckets, and filesystems for API keys, passwords, and tokens.",
        category: "cloud",
        exampleArgs: [
          "s3 --bucket bucketname --only-verified",
          "git https://github.com/org/repo --only-verified"
        ],
        defaultTimeout: 180,
        requiresSudo: false
      },
      {
        name: "aws",
        description: "AWS CLI for cloud resource enumeration. Check S3 bucket policies, list objects, check IAM, and probe cloud services. Use --no-sign-request for unauthenticated access.",
        category: "cloud",
        exampleArgs: [
          "s3 ls s3://bucketname --no-sign-request",
          "s3api get-bucket-acl --bucket bucketname --no-sign-request",
          "s3api get-bucket-policy --bucket bucketname --no-sign-request"
        ],
        defaultTimeout: 60,
        requiresSudo: false
      }
    ];
    DEPTH_TIMEOUT_MULTIPLIER = {
      quick: 0.25,
      standard: 1,
      deep: 2.5
    };
  }
});
init_llm_scan_feedback();
export {
  TOOL_INVENTORY,
  analyzeFindingsAndRequestScans,
  executeScanRequests,
  getFeedbackLoopSummary,
  runFeedbackLoop
};
