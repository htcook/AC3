// @ts-nocheck
/**
 * Evasion-Aware Validation Testing
 * 
 * Wraps active probes, verification suites, and takeover PoC validation with
 * the adaptive evasion orchestrator. When a validation test is blocked by
 * WAF/CDN/EDR/NGFW, the system automatically escalates through evasion
 * techniques until it gets through, then records the successful bypass
 * technique as part of the findings.
 * 
 * Integration points:
 * 1. Active Probes (active-probes.ts) — HTTP-based vulnerability probes
 * 2. Verification Suite (active-verification.ts) — Full verification probe suites
 * 3. Takeover PoC (domain-intel-advanced.ts) — Subdomain takeover validation
 */

import {
  runEvasionLoop,
  detectBlockSignal,
  storeFinding,
  type EvasionDomain,
  type EvasionFinding,
  type EscalationContext,
} from "./evasion-orchestrator";

// ─── Types ─────────────────────────────────────────────────────────

export interface EvasionValidationConfig {
  /** Max evasion escalation attempts per probe (default: 5) */
  maxAttempts?: number;
  /** Initial delay between attempts in ms (default: 1000) */
  initialDelayMs?: number;
  /** Whether to store findings in the orchestrator (default: true) */
  storeFindings?: boolean;
  /** Evasion domain to use (default: "scanning") */
  domain?: EvasionDomain;
}

export interface EvasionProbeResult {
  /** Original probe result */
  originalResult: any;
  /** Whether evasion was needed */
  evasionNeeded: boolean;
  /** Whether evasion succeeded in bypassing the block */
  evasionSucceeded: boolean;
  /** Number of evasion attempts made */
  evasionAttempts: number;
  /** The technique that succeeded (null if no evasion needed or all failed) */
  successfulTechnique: string | null;
  /** Defenses detected during probing */
  defensesDetected: string[];
  /** Full evasion finding (if evasion was triggered) */
  evasionFinding: EvasionFinding | null;
  /** The final result after evasion (may differ from original) */
  finalResult: any;
}

export interface EvasionValidationSummary {
  totalProbes: number;
  probesBlocked: number;
  probesBypassed: number;
  probesFailedBypass: number;
  probesClean: number;
  defensesEncountered: string[];
  techniquesUsed: string[];
  bypassRate: number;
  results: EvasionProbeResult[];
}

// ─── WAF/CDN/EDR Block Detection ───────────────────────────────────

/** Signatures that indicate a WAF/CDN/EDR/NGFW is blocking the request */
const BLOCK_SIGNATURES = {
  waf: [
    "403 forbidden",
    "access denied",
    "request blocked",
    "web application firewall",
    "mod_security",
    "cloudflare",
    "akamai",
    "imperva",
    "incapsula",
    "sucuri",
    "barracuda",
    "f5 big-ip",
    "fortiweb",
    "aws waf",
    "azure front door",
  ],
  cdn: [
    "cdn-cgi",
    "cf-ray",
    "x-cdn",
    "x-cache",
    "via: cloudfront",
    "x-amz-cf-id",
    "x-akamai",
    "x-fastly",
  ],
  edr: [
    "connection reset",
    "connection refused",
    "econnreset",
    "econnrefused",
    "socket hang up",
    "network unreachable",
  ],
  ngfw: [
    "406 not acceptable",
    "429 too many requests",
    "503 service unavailable",
    "connection timed out",
    "request timeout",
    "gateway timeout",
  ],
};

/**
 * Detect if a probe result indicates a block by WAF/CDN/EDR/NGFW.
 * Returns the type of defense detected and confidence level.
 */
export function detectValidationBlock(result: {
  statusCode?: number | null;
  body?: string | null;
  error?: string | null;
  headers?: Record<string, string>;
  responseSnippet?: string | null;
}): {
  isBlocked: boolean;
  defenseType: "waf" | "cdn" | "edr" | "ngfw" | "none";
  defenseName: string;
  confidence: number;
  signals: string[];
} {
  const signals: string[] = [];
  const body = (result.body || result.responseSnippet || "").toLowerCase();
  const error = (result.error || "").toLowerCase();
  const statusCode = result.statusCode;
  const headers = result.headers || {};
  const headerStr = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n").toLowerCase();

  // Check WAF signatures
  for (const sig of BLOCK_SIGNATURES.waf) {
    if (body.includes(sig) || headerStr.includes(sig)) {
      signals.push(`WAF signature: "${sig}"`);
    }
  }
  if (signals.length > 0) {
    const defenseName = identifyWafProduct(body, headerStr);
    return { isBlocked: true, defenseType: "waf", defenseName, confidence: 0.85 + (signals.length * 0.03), signals };
  }

  // Check CDN blocking (403 + CDN headers)
  if (statusCode === 403) {
    for (const sig of BLOCK_SIGNATURES.cdn) {
      if (headerStr.includes(sig)) {
        signals.push(`CDN block: 403 + "${sig}"`);
      }
    }
    if (signals.length > 0) {
      return { isBlocked: true, defenseType: "cdn", defenseName: identifyCdnProduct(headerStr), confidence: 0.8, signals };
    }
  }

  // Check EDR/network-level blocks
  for (const sig of BLOCK_SIGNATURES.edr) {
    if (error.includes(sig)) {
      signals.push(`EDR/network block: "${sig}"`);
    }
  }
  if (signals.length > 0) {
    return { isBlocked: true, defenseType: "edr", defenseName: "Network-level defense", confidence: 0.7, signals };
  }

  // Check NGFW signatures
  if (statusCode && [406, 429, 503].includes(statusCode)) {
    for (const sig of BLOCK_SIGNATURES.ngfw) {
      if (body.includes(sig) || error.includes(sig)) {
        signals.push(`NGFW block: "${sig}"`);
      }
    }
    // Even without body match, these status codes with empty/generic bodies suggest NGFW
    if (statusCode === 429 || (statusCode === 503 && body.length < 200)) {
      signals.push(`NGFW block: HTTP ${statusCode} with minimal response`);
    }
    if (signals.length > 0) {
      return { isBlocked: true, defenseType: "ngfw", defenseName: "Next-Gen Firewall", confidence: 0.65, signals };
    }
  }

  return { isBlocked: false, defenseType: "none", defenseName: "none", confidence: 0, signals: [] };
}

function identifyWafProduct(body: string, headers: string): string {
  if (body.includes("cloudflare") || headers.includes("cf-ray")) return "Cloudflare WAF";
  if (body.includes("akamai") || headers.includes("x-akamai")) return "Akamai WAF";
  if (body.includes("imperva") || body.includes("incapsula")) return "Imperva/Incapsula WAF";
  if (body.includes("sucuri")) return "Sucuri WAF";
  if (body.includes("mod_security")) return "ModSecurity";
  if (body.includes("barracuda")) return "Barracuda WAF";
  if (body.includes("f5 big-ip") || headers.includes("bigipserver")) return "F5 BIG-IP ASM";
  if (body.includes("fortiweb")) return "FortiWeb WAF";
  if (body.includes("aws waf") || headers.includes("x-amzn-waf")) return "AWS WAF";
  if (headers.includes("x-azure-ref")) return "Azure Front Door WAF";
  return "Unknown WAF";
}

function identifyCdnProduct(headers: string): string {
  if (headers.includes("cf-ray")) return "Cloudflare CDN";
  if (headers.includes("x-amz-cf-id") || headers.includes("cloudfront")) return "AWS CloudFront";
  if (headers.includes("x-akamai")) return "Akamai CDN";
  if (headers.includes("x-fastly")) return "Fastly CDN";
  if (headers.includes("x-cdn")) return "Generic CDN";
  return "Unknown CDN";
}

// ─── Evasion-Aware HTTP Fetch ──────────────────────────────────────

/** Build modified fetch options based on evasion context */
function buildEvasionFetchOptions(ctx: EscalationContext): {
  headers: Record<string, string>;
  delay: number;
} {
  const headers: Record<string, string> = {};
  const metadata = ctx.metadata || {};

  // User-Agent rotation
  const userAgents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
  ];

  // Apply evasion techniques based on escalation level
  const level = metadata.escalationLevel || 0;

  if (level >= 1) {
    // Level 1: Rotate User-Agent
    headers["User-Agent"] = userAgents[level % userAgents.length];
  }
  if (level >= 2) {
    // Level 2: Add legitimate-looking headers
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
    headers["Accept-Language"] = "en-US,en;q=0.9";
    headers["Accept-Encoding"] = "gzip, deflate, br";
    headers["Cache-Control"] = "no-cache";
    headers["Pragma"] = "no-cache";
  }
  if (level >= 3) {
    // Level 3: Add referer and origin spoofing
    const target = metadata.target || "example.com";
    headers["Referer"] = `https://www.google.com/search?q=${encodeURIComponent(target)}`;
    headers["Origin"] = `https://${target}`;
    headers["DNT"] = "1";
    headers["Sec-Fetch-Dest"] = "document";
    headers["Sec-Fetch-Mode"] = "navigate";
    headers["Sec-Fetch-Site"] = "cross-site";
  }
  if (level >= 4) {
    // Level 4: Use search engine bot UA to bypass WAF rules that whitelist crawlers
    headers["User-Agent"] = userAgents[5]; // Googlebot
    headers["X-Forwarded-For"] = `66.249.${64 + (level % 16)}.${Math.floor(Math.random() * 255)}`;
  }
  if (level >= 5) {
    // Level 5: Aggressive — try different encoding and minimal headers
    headers["User-Agent"] = userAgents[6]; // Bingbot
    headers["X-Forwarded-For"] = `40.77.167.${Math.floor(Math.random() * 255)}`;
    headers["X-Real-IP"] = `40.77.167.${Math.floor(Math.random() * 255)}`;
    delete headers["Referer"];
    delete headers["Origin"];
  }

  // Delay increases with escalation level
  const delay = level * 500 + Math.floor(Math.random() * 300);

  return { headers, delay };
}

// ─── Evasion-Wrapped Active Probes ─────────────────────────────────

/**
 * Run a single active probe with evasion bypass.
 * If the initial probe is blocked, escalates through evasion techniques.
 */
export async function runEvasionAwareProbe(
  probeTemplate: any,
  target: string,
  port?: number,
  config: EvasionValidationConfig = {},
): Promise<EvasionProbeResult> {
  const { executeProbe } = await import("./active-probes");
  
  // First attempt: run the probe normally
  const initialResult = await executeProbe(probeTemplate, target, port);
  
  // Check if the result indicates a block
  const blockCheck = detectValidationBlock({
    statusCode: initialResult.result === "error" ? 0 : undefined,
    body: initialResult.responseSnippet,
    error: initialResult.error,
  });

  if (!(blockCheck as any).isBlocked) {
    return {
      originalResult: initialResult,
      evasionNeeded: false,
      evasionSucceeded: false,
      evasionAttempts: 0,
      successfulTechnique: null,
      defensesDetected: [],
      evasionFinding: null,
      finalResult: initialResult,
    };
  }

  // Block detected — run evasion loop
  const domain = config.domain || "scanning";
  const initialContext: EscalationContext = {
    target,
    operation: `probe:${probeTemplate.id}`,
    metadata: {
      target,
      probeId: probeTemplate.id,
      probeName: probeTemplate.name,
      port,
      defenseType: (blockCheck as any).defenseType,
      defenseName: (blockCheck as any).defenseName,
      escalationLevel: 0,
    },
  };

  const finding = await runEvasionLoop(
    domain,
    target,
    `validation-probe:${probeTemplate.id}`,
    initialContext,
    async (ctx) => {
      const evasionOpts = buildEvasionFetchOptions(ctx);
      
      // Apply delay for rate-limit evasion
      if (evasionOpts.delay > 0) {
        await new Promise(r => setTimeout(r, evasionOpts.delay));
      }

      // Re-run the probe with modified headers
      // We override the template headers with evasion headers
      const modifiedTemplate = {
        ...probeTemplate,
        httpHeaders: { ...(probeTemplate.httpHeaders || {}), ...evasionOpts.headers },
      };
      const result = await executeProbe(modifiedTemplate, target, port);
      
      // Determine if this attempt was blocked
      const recheck = detectValidationBlock({
        statusCode: result.result === "error" ? 0 : undefined,
        body: result.responseSnippet,
        error: result.error,
      });

      return {
        success: !recheck.isBlocked,
        statusCode: result.result === "vulnerable" ? 200 : result.result === "error" ? 0 : 200,
        body: result.responseSnippet || "",
        error: result.error,
        data: result,
      };
    },
    { maxAttempts: config.maxAttempts || 5, initialDelayMs: config.initialDelayMs || 500 },
  );

  if (config.storeFindings !== false) {
    storeFinding(finding);
  }

  const evasionSucceeded = finding.finalResult === "bypassed";
  return {
    originalResult: initialResult,
    evasionNeeded: true,
    evasionSucceeded,
    evasionAttempts: finding.attempts.length,
    successfulTechnique: (finding as any).successfulTechnique?.name || null,
    defensesDetected: finding.defensesDetected,
    evasionFinding: finding,
    finalResult: evasionSucceeded && finding.attempts.length > 0
      ? finding.attempts[finding.attempts.length - 1].responseData
      : initialResult,
  };
}

/**
 * Run a full probe scan with evasion bypass on blocked probes.
 */
export async function runEvasionAwareProbeScan(
  target: string,
  options?: {
    port?: number;
    cveIds?: string[];
    probeIds?: string[];
    timeoutMs?: number;
    evasionConfig?: EvasionValidationConfig;
  },
): Promise<EvasionValidationSummary> {
  const { runProbeScan, getProbesForCves, PROBE_TEMPLATES } = await import("./active-probes");
  
  let templates = [...PROBE_TEMPLATES];
  if (options?.probeIds && options.probeIds.length > 0) {
    templates = templates.filter(p => options.probeIds!.includes(p.id));
  } else if (options?.cveIds && options.cveIds.length > 0) {
    templates = getProbesForCves(options.cveIds);
  }

  const results: EvasionProbeResult[] = [];
  const defensesEncountered = new Set<string>();
  const techniquesUsed = new Set<string>();

  for (const template of templates) {
    const result = await runEvasionAwareProbe(
      template,
      target,
      options?.port,
      options?.evasionConfig,
    );
    results.push(result);

    if (result.evasionNeeded) {
      result.defensesDetected.forEach(d => defensesEncountered.add(d));
      if (result.successfulTechnique) techniquesUsed.add(result.successfulTechnique);
    }
  }

  const probesBlocked = results.filter(r => r.evasionNeeded).length;
  const probesBypassed = results.filter(r => r.evasionNeeded && r.evasionSucceeded).length;
  const probesFailedBypass = results.filter(r => r.evasionNeeded && !r.evasionSucceeded).length;
  const probesClean = results.filter(r => !r.evasionNeeded).length;

  return {
    totalProbes: results.length,
    probesBlocked,
    probesBypassed,
    probesFailedBypass,
    probesClean,
    defensesEncountered: Array.from(defensesEncountered),
    techniquesUsed: Array.from(techniquesUsed),
    bypassRate: probesBlocked > 0 ? probesBypassed / probesBlocked : 1,
    results,
  };
}

// ─── Evasion-Wrapped Verification Suite ────────────────────────────

/**
 * Run a verification suite with evasion bypass on blocked probes.
 */
export async function runEvasionAwareVerificationSuite(
  targetHost: string,
  targetPort: number = 443,
  protocol: "http" | "https" = "https",
  probeFilter?: { cveIds?: string[]; tags?: string[] },
  evasionConfig?: EvasionValidationConfig,
): Promise<{
  report: any;
  evasionSummary: EvasionValidationSummary;
}> {
  const { BUILTIN_PROBES, runProbe } = await import("./active-verification");

  // Filter probes
  let probes = [...BUILTIN_PROBES];
  if (probeFilter?.cveIds && probeFilter.cveIds.length > 0) {
    probes = probes.filter(p => p.cveIds.some((c: string) => probeFilter.cveIds!.includes(c)));
  }
  if (probeFilter?.tags && probeFilter.tags.length > 0) {
    probes = probes.filter(p => p.tags.some((t: string) => probeFilter.tags!.includes(t)));
  }
  if (probes.length === 0) {
    probes = BUILTIN_PROBES.filter((p: any) => p.safeForProduction);
  }

  const evasionResults: EvasionProbeResult[] = [];
  const verificationResults: any[] = [];
  const defensesEncountered = new Set<string>();
  const techniquesUsed = new Set<string>();

  for (const probe of probes) {
    // Run the probe normally first
    const initialResult = await runProbe(probe, targetHost, targetPort, protocol);
    
    // Check if blocked
    const blockCheck = detectValidationBlock({
      statusCode: initialResult.status === "error" ? 0 : (initialResult.responseData?.statusCode || null),
      body: initialResult.responseData?.bodySnippet || null,
      error: initialResult.evidence,
    });

    if (!(blockCheck as any).isBlocked) {
      verificationResults.push(initialResult);
      evasionResults.push({
        originalResult: initialResult,
        evasionNeeded: false,
        evasionSucceeded: false,
        evasionAttempts: 0,
        successfulTechnique: null,
        defensesDetected: [],
        evasionFinding: null,
        finalResult: initialResult,
      });
      continue;
    }

    // Block detected — run evasion loop for this probe
    (blockCheck as any).signals.forEach(() => defensesEncountered.add((blockCheck as any).defenseName));

    const finding = await runEvasionLoop(
      evasionConfig?.domain || "scanning",
      targetHost,
      `verification:${probe.id}`,
      {
        target: targetHost,
        operation: `verify:${probe.id}`,
        metadata: {
          target: targetHost,
          probeId: probe.id,
          port: targetPort,
          protocol,
          defenseType: (blockCheck as any).defenseType,
          defenseName: (blockCheck as any).defenseName,
          escalationLevel: 0,
        },
      },
      async (ctx) => {
        const evasionOpts = buildEvasionFetchOptions(ctx);
        if (evasionOpts.delay > 0) {
          await new Promise(r => setTimeout(r, evasionOpts.delay));
        }
        // Re-run probe (the probe itself uses fetch internally, so we can't easily
        // inject headers. Instead, we modify the probe's request config)
        const modifiedProbe = {
          ...probe,
          headers: { ...(probe as any).headers, ...evasionOpts.headers },
        };
        const result = await runProbe(modifiedProbe, targetHost, targetPort, protocol);
        const recheck = detectValidationBlock({
          statusCode: result.responseData?.statusCode || null,
          body: result.responseData?.bodySnippet || null,
          error: result.evidence,
        });
        return {
          success: !recheck.isBlocked,
          statusCode: result.responseData?.statusCode || 0,
          body: result.responseData?.bodySnippet || "",
          error: result.status === "error" ? result.evidence : undefined,
          data: result,
        };
      },
      { maxAttempts: evasionConfig?.maxAttempts || 5 },
    );

    if (evasionConfig?.storeFindings !== false) {
      storeFinding(finding);
    }

    const evasionSucceeded = finding.finalResult === "bypassed";
    const finalResult = evasionSucceeded && finding.attempts.length > 0
      ? finding.attempts[finding.attempts.length - 1].responseData
      : initialResult;

    verificationResults.push(finalResult);
    if ((finding as any).successfulTechnique) techniquesUsed.add((finding as any).successfulTechnique.name);

    evasionResults.push({
      originalResult: initialResult,
      evasionNeeded: true,
      evasionSucceeded,
      evasionAttempts: finding.attempts.length,
      successfulTechnique: (finding as any).successfulTechnique?.name || null,
      defensesDetected: finding.defensesDetected,
      evasionFinding: finding,
      finalResult,
    });
  }

  // Build verification report from final results
  const vulnerableCount = verificationResults.filter((r: any) => r.status === "vulnerable").length;
  const hasCritical = verificationResults.some((r: any) =>
    r.status === "vulnerable" && probes.find((p: any) => p.id === r.probeId)?.severity === "critical"
  );
  const hasHigh = verificationResults.some((r: any) =>
    r.status === "vulnerable" && probes.find((p: any) => p.id === r.probeId)?.severity === "high"
  );

  let overallRisk: string;
  if (hasCritical) overallRisk = "critical";
  else if (hasHigh) overallRisk = "high";
  else if (vulnerableCount > 0) overallRisk = "medium";
  else if (verificationResults.some((r: any) => r.status === "inconclusive")) overallRisk = "low";
  else overallRisk = "none";

  const probesBlocked = evasionResults.filter(r => r.evasionNeeded).length;
  const probesBypassed = evasionResults.filter(r => r.evasionNeeded && r.evasionSucceeded).length;

  return {
    report: {
      targetHost,
      totalProbes: verificationResults.length,
      vulnerableCount,
      notVulnerableCount: verificationResults.filter((r: any) => r.status === "not_vulnerable").length,
      inconclusiveCount: verificationResults.filter((r: any) => r.status === "inconclusive").length,
      errorCount: verificationResults.filter((r: any) => r.status === "error" || r.status === "timeout").length,
      results: verificationResults,
      overallRisk,
      generatedAt: Date.now(),
    },
    evasionSummary: {
      totalProbes: evasionResults.length,
      probesBlocked,
      probesBypassed,
      probesFailedBypass: evasionResults.filter(r => r.evasionNeeded && !r.evasionSucceeded).length,
      probesClean: evasionResults.filter(r => !r.evasionNeeded).length,
      defensesEncountered: Array.from(defensesEncountered),
      techniquesUsed: Array.from(techniquesUsed),
      bypassRate: probesBlocked > 0 ? probesBypassed / probesBlocked : 1,
      results: evasionResults,
    },
  };
}

// ─── Evasion-Wrapped Takeover PoC Validation ───────────────────────

/**
 * Run takeover PoC validation with evasion bypass.
 * When HTTP probes to subdomain targets are blocked by WAF/CDN,
 * escalates through evasion techniques to get the real response.
 */
export async function runEvasionAwareTakeoverValidation(
  candidates: Array<{ subdomain: string; cnameTarget: string; service: string }>,
  evasionConfig?: EvasionValidationConfig,
): Promise<{
  validationResult: any;
  evasionSummary: {
    totalCandidates: number;
    candidatesBlocked: number;
    candidatesBypassed: number;
    defensesEncountered: string[];
    techniquesUsed: string[];
  };
}> {
  const { validateTakeoverCandidates } = await import("./domain-intel-advanced");
  const http = await import("http");
  const https = await import("https");

  // First, run normal validation
  const normalResult = await validateTakeoverCandidates(candidates);

  // Check each result for blocks and re-validate with evasion if needed
  const defensesEncountered = new Set<string>();
  const techniquesUsed = new Set<string>();
  let candidatesBlocked = 0;
  let candidatesBypassed = 0;

  for (let i = 0; i < normalResult.results.length; i++) {
    const pocResult = normalResult.results[i];
    const candidate = candidates[i];

    // Check if the HTTP probe was blocked (error or suspicious response)
    const blockCheck = detectValidationBlock({
      statusCode: pocResult.httpStatusCode,
      body: pocResult.responseSnippet,
      error: pocResult.validationStatus === "error" ? pocResult.exploitabilityNote : null,
    });

    if (!(blockCheck as any).isBlocked) continue;

    candidatesBlocked++;
    defensesEncountered.add((blockCheck as any).defenseName);

    // Run evasion loop for this candidate's HTTP probe
    const finding = await runEvasionLoop(
      evasionConfig?.domain || "scanning",
      (candidate as any).subdomain,
      `takeover-poc:${(candidate as any).subdomain}`,
      {
        target: (candidate as any).subdomain,
        operation: `takeover-validate:${(candidate as any).service}`,
        metadata: {
          target: (candidate as any).subdomain,
          cnameTarget: (candidate as any).cnameTarget,
          service: (candidate as any).service,
          defenseType: (blockCheck as any).defenseType,
          defenseName: (blockCheck as any).defenseName,
          escalationLevel: 0,
        },
      },
      async (ctx) => {
        const evasionOpts = buildEvasionFetchOptions(ctx);
        if (evasionOpts.delay > 0) {
          await new Promise(r => setTimeout(r, evasionOpts.delay));
        }

        // Re-probe the subdomain with evasion headers
        try {
          const response = await fetch(`https://${(candidate as any).subdomain}`, {
            headers: {
              ...evasionOpts.headers,
              "Accept": "text/html,application/xhtml+xml,*/*",
            },
            signal: AbortSignal.timeout(8000),
            redirect: "follow",
          });
          const body = await response.text().catch(() => "");
          const recheck = detectValidationBlock({
            statusCode: response.status,
            body,
            headers: Object.fromEntries(response.headers.entries()),
          });
          return {
            success: !recheck.isBlocked,
            statusCode: response.status,
            body: body.substring(0, 2000),
            data: { statusCode: response.status, body: body.substring(0, 2000) },
          };
        } catch (err: any) {
          // Try HTTP fallback
          try {
            const response = await fetch(`http://${(candidate as any).subdomain}`, {
              headers: evasionOpts.headers,
              signal: AbortSignal.timeout(8000),
              redirect: "follow",
            });
            const body = await response.text().catch(() => "");
            return {
              success: true,
              statusCode: response.status,
              body: body.substring(0, 2000),
              data: { statusCode: response.status, body: body.substring(0, 2000) },
            };
          } catch (err2: any) {
            return {
              success: false,
              error: err2.message,
              data: null,
            };
          }
        }
      },
      { maxAttempts: evasionConfig?.maxAttempts || 4 },
    );

    if (evasionConfig?.storeFindings !== false) {
      storeFinding(finding);
    }

    // If evasion succeeded, re-evaluate the takeover candidate with the new response
    if (finding.finalResult === "bypassed" && finding.attempts.length > 0) {
      candidatesBypassed++;
      const lastAttempt = finding.attempts[finding.attempts.length - 1];
      if ((finding as any).successfulTechnique) techniquesUsed.add((finding as any).successfulTechnique.name);

      const newBody = lastAttempt.responseData?.body || "";
      const newStatus = lastAttempt.responseData?.statusCode || 0;

      // Re-evaluate with the evasion-obtained response
      pocResult.httpStatusCode = newStatus;
      pocResult.responseSnippet = newBody.substring(0, 500);

      // Re-check fingerprints against the new response
      const domIntelMod = await import("./domain-intel-advanced") as any;
      const TAKEOVER_FINGERPRINTS = domIntelMod.TAKEOVER_FINGERPRINTS;
      const fingerprint = (await import("./domain-intel-advanced") as any).TAKEOVER_FINGERPRINTS.find((f: any) => f.service === (candidate as any).service);
      if (fingerprint && newBody) {
        for (const fp of fingerprint.httpFingerprints) {
          if (newBody.includes(fp)) {
            pocResult.responseContainsFingerprint = true;
            pocResult.fingerprintMatched = fp;
            break;
          }
        }
      }

      // Reclassify based on new evidence
      if (pocResult.responseContainsFingerprint && !pocResult.dnsResolves) {
        pocResult.validationStatus = "confirmed";
        pocResult.confidence = 95;
        pocResult.exploitabilityNote = `CONFIRMED (via evasion bypass of ${(blockCheck as any).defenseName}): CNAME target does not resolve and HTTP response contains "${pocResult.fingerprintMatched}" — subdomain can be claimed.`;
      } else if (pocResult.responseContainsFingerprint) {
        pocResult.validationStatus = "likely";
        pocResult.confidence = 80;
        pocResult.exploitabilityNote = `LIKELY (via evasion bypass of ${(blockCheck as any).defenseName}): HTTP response contains "${pocResult.fingerprintMatched}" indicating unclaimed ${(candidate as any).service} resource.`;
      }

      // Add evasion context to the result
      (pocResult as any).evasionUsed = true;
      (pocResult as any).evasionTechnique = (finding as any).successfulTechnique?.name;
      (pocResult as any).defenseBypassed = (blockCheck as any).defenseName;
    }
  }

  // Recalculate summary counts
  const updatedResults = normalResult.results;
  normalResult.confirmedCount = updatedResults.filter((r: any) => r.validationStatus === "confirmed").length;
  normalResult.likelyCount = updatedResults.filter((r: any) => r.validationStatus === "likely").length;
  normalResult.possibleCount = updatedResults.filter((r: any) => r.validationStatus === "possible").length;
  normalResult.unlikelyCount = updatedResults.filter((r: any) => r.validationStatus === "unlikely").length;
  normalResult.errorCount = updatedResults.filter((r: any) => r.validationStatus === "error").length;

  return {
    validationResult: normalResult,
    evasionSummary: {
      totalCandidates: candidates.length,
      candidatesBlocked,
      candidatesBypassed,
      defensesEncountered: Array.from(defensesEncountered),
      techniquesUsed: Array.from(techniquesUsed),
    },
  };
}

// ─── Evasion-Wrapped KEV Exploit Validation ────────────────────────

/**
 * Validate KEV-matched exploits against a target with evasion bypass.
 * Takes KEV posture findings that have linked exploits and attempts to
 * verify exploitability, escalating through evasion if blocked.
 */
export async function runEvasionAwareExploitValidation(
  target: string,
  kevFindings: Array<{
    id: string;
    cveIds: string[];
    title: string;
    linkedExploits?: Array<{
      cveId: string;
      bestExploit: any;
      isRemoteAccess: boolean;
    }>;
  }>,
  evasionConfig?: EvasionValidationConfig,
): Promise<{
  totalValidated: number;
  exploitable: number;
  blocked: number;
  bypassed: number;
  results: Array<{
    findingId: string;
    cveId: string;
    exploitName: string;
    validationResult: "exploitable" | "not_exploitable" | "blocked" | "bypassed" | "error";
    evasionUsed: boolean;
    evasionTechnique: string | null;
    defenseBypassed: string | null;
    evidence: string;
  }>;
}> {
  const { getProbesForCves } = await import("./active-probes");
  
  const results: Array<{
    findingId: string;
    cveId: string;
    exploitName: string;
    validationResult: "exploitable" | "not_exploitable" | "blocked" | "bypassed" | "error";
    evasionUsed: boolean;
    evasionTechnique: string | null;
    defenseBypassed: string | null;
    evidence: string;
  }> = [];

  let exploitable = 0;
  let blocked = 0;
  let bypassed = 0;

  for (const finding of kevFindings) {
    if (!finding.linkedExploits || finding.linkedExploits.length === 0) continue;

    for (const exploit of finding.linkedExploits) {
      // Try to find matching probes for this CVE
      const probes = getProbesForCves([exploit.cveId]);
      
      if (probes.length === 0) {
        // No specific probe — run a generic HTTP check with the exploit's context
        results.push({
          findingId: finding.id,
          cveId: exploit.cveId,
          exploitName: exploit.bestExploit?.name || exploit.cveId,
          validationResult: "not_exploitable",
          evasionUsed: false,
          evasionTechnique: null,
          defenseBypassed: null,
          evidence: `No validation probe available for ${exploit.cveId}. Exploit exists (${exploit.bestExploit?.source || "unknown"}) but cannot be automatically verified.`,
        });
        continue;
      }

      // Run each matching probe with evasion
      for (const probe of probes) {
        const evasionResult = await runEvasionAwareProbe(
          probe,
          target,
          undefined,
          evasionConfig,
        );

        const finalResult = evasionResult.finalResult;
        const isExploitable = finalResult?.result === "vulnerable";
        const wasBlocked = evasionResult.evasionNeeded && !evasionResult.evasionSucceeded;

        if (isExploitable) exploitable++;
        if (wasBlocked) blocked++;
        if (evasionResult.evasionSucceeded) bypassed++;

        results.push({
          findingId: finding.id,
          cveId: exploit.cveId,
          exploitName: exploit.bestExploit?.name || exploit.cveId,
          validationResult: isExploitable
            ? "exploitable"
            : wasBlocked
              ? "blocked"
              : evasionResult.evasionSucceeded
                ? "bypassed"
                : "not_exploitable",
          evasionUsed: evasionResult.evasionNeeded,
          evasionTechnique: evasionResult.successfulTechnique,
          defenseBypassed: evasionResult.defensesDetected[0] || null,
          evidence: isExploitable
            ? `EXPLOITABLE: Probe "${probe.name}" confirmed vulnerability for ${exploit.cveId}${evasionResult.evasionSucceeded ? ` (bypassed ${evasionResult.defensesDetected.join(", ")} using ${evasionResult.successfulTechnique})` : ""}`
            : wasBlocked
              ? `BLOCKED: Defense (${evasionResult.defensesDetected.join(", ")}) prevented validation of ${exploit.cveId} after ${evasionResult.evasionAttempts} evasion attempts`
              : `NOT EXPLOITABLE: Probe "${probe.name}" did not confirm vulnerability for ${exploit.cveId}`,
        });
      }
    }
  }

  return {
    totalValidated: results.length,
    exploitable,
    blocked,
    bypassed,
    results,
  };
}
