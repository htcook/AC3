/**
 * Evasion Integrations
 * ════════════════════
 * Wires the Adaptive Evasion Orchestrator into the three operational domains:
 *   1. Web App Scanning (ZAP) — WAF bypass loop
 *   2. C2 Task Execution (Sliver) — EDR bypass loop
 *   3. Exploit Automation (Attack Vectors) — payload obfuscation escalation
 *
 * Each integration wraps the existing operation with the orchestrator's
 * progressive escalation loop and records bypass findings.
 */

import {
  evasionScan,
  evasionC2Task,
  evasionExploit,
  storeFinding,
  detectBlockSignal,
  type EvasionFinding,
  type OrchestratorConfig,
  type EvasionDomain,
  type BlockSignal,
} from "./evasion-orchestrator";

import {
  buildPipeline,
  type EvasionProfile,
  type TransformPipeline,
} from "./payload-transform-pipeline";

import {
  generateMutations,
  type MutationVariant,
} from "./siem-mutation-engine";

// ═══════════════════════════════════════════════════════════════════════
// §1 — SCANNING INTEGRATION (WAF Bypass)
// ═══════════════════════════════════════════════════════════════════════

export interface EvasionScanRequest {
  targetUrl: string;
  scanType: "spider_only" | "active" | "full";
  scanMode: "passive" | "active";
  scanName?: string;
  userId: string;
  /** Enable evasion orchestrator for this scan */
  evasionEnabled: boolean;
  /** Max evasion attempts before giving up */
  maxEvasionAttempts?: number;
}

export interface EvasionScanResult {
  scanId?: number;
  scanStatus: string;
  evasionFinding?: EvasionFinding;
  wafDetected?: string[];
  bypassAchieved: boolean;
  bypassTechnique?: string;
  originalBlocked: boolean;
}

/**
 * Run a web app scan with evasion orchestrator wrapping.
 * If the initial scan request is blocked by a WAF, the orchestrator
 * escalates through header manipulation, encoding, and rate throttling
 * until the scan can proceed.
 */
export async function runEvasionAwareScan(
  request: EvasionScanRequest,
): Promise<EvasionScanResult> {
  if (!request.evasionEnabled) {
    // No evasion — just return a placeholder for the normal scan flow
    return {
      scanStatus: "started_without_evasion",
      bypassAchieved: true,
      originalBlocked: false,
    };
  }

  // First, probe the target to detect WAF presence
  const finding = await evasionScan(
    request.targetUrl,
    `DAST Scan: ${request.scanName || request.targetUrl}`,
    async (url, headers, options) => {
      // Perform an HTTP probe to the target
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15000);
        const response = await fetch(url, {
          method: options.method || "GET",
          headers: {
            ...headers,
            "User-Agent": headers["User-Agent"] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
          },
          signal: controller.signal,
          redirect: "follow",
        });
        clearTimeout(timeout);

        const body = await response.text().catch(() => "");
        const respHeaders: Record<string, string> = {};
        response.headers.forEach((v, k) => { respHeaders[k] = v; });

        return {
          statusCode: response.status,
          body: body.substring(0, 5000),
          headers: respHeaders,
        };
      } catch (err: any) {
        throw err;
      }
    },
    {
      maxAttempts: request.maxEvasionAttempts || 10,
      delayBetweenAttempts: 1000,
      jitterRange: 500,
      abortOnFirstSuccess: true,
    },
  );

  // Store the finding
  storeFinding(finding);

  return {
    scanStatus: finding.finalResult === "bypassed" ? "scan_can_proceed" : "scan_blocked_by_waf",
    evasionFinding: finding,
    wafDetected: finding.defensesDetected,
    bypassAchieved: finding.finalResult === "bypassed",
    bypassTechnique: finding.successfulTechnique?.name,
    originalBlocked: finding.attempts[0]?.result === "blocked",
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — C2 TASK INTEGRATION (EDR Bypass)
// ═══════════════════════════════════════════════════════════════════════

export interface EvasionC2Request {
  sessionId: number;
  sessionTarget: string; // hostname or IP
  taskType: string;
  command: string;
  /** Enable evasion orchestrator for this C2 task */
  evasionEnabled: boolean;
  /** Max evasion attempts */
  maxEvasionAttempts?: number;
  /** Current transport protocol */
  transport?: string;
}

export interface EvasionC2Result {
  taskId?: string;
  taskStatus: string;
  evasionFinding?: EvasionFinding;
  edrDetected?: string[];
  bypassAchieved: boolean;
  bypassTechnique?: string;
  originalBlocked: boolean;
  /** The mutated command that succeeded (if different from original) */
  effectiveCommand?: string;
  /** The pipeline profile used for the successful attempt */
  effectivePipeline?: EvasionProfile;
  /** The transport protocol used for the successful attempt */
  effectiveTransport?: string;
}

/**
 * Execute a C2 task with evasion orchestrator wrapping.
 * If the task is blocked by EDR (process killed, AMSI block, signature match),
 * the orchestrator escalates through command mutation, sleep jitter,
 * protocol rotation, and payload transformation.
 */
export async function runEvasionAwareC2Task(
  request: EvasionC2Request,
  /** The actual C2 task execution function from the Sliver router */
  executeTaskFn: (command: string, options: {
    sessionId: number;
    taskType: string;
    transport?: string;
    pipelineProfile?: EvasionProfile;
  }) => Promise<{ taskId: string; status: string; output?: string; error?: string }>,
): Promise<EvasionC2Result> {
  if (!request.evasionEnabled) {
    const result = await executeTaskFn(request.command, {
      sessionId: request.sessionId,
      taskType: request.taskType,
      transport: request.transport,
    });
    return {
      taskId: result.taskId,
      taskStatus: result.status,
      bypassAchieved: result.status !== "blocked",
      originalBlocked: false,
    };
  }

  const finding = await evasionC2Task(
    request.sessionTarget,
    request.command,
    async (command, options) => {
      try {
        const result = await executeTaskFn(command, {
          sessionId: request.sessionId,
          taskType: request.taskType,
          transport: options.transport,
          pipelineProfile: options.pipelineProfile,
        });

        // Determine if the task was blocked
        const blocked = result.status === "blocked" ||
          result.status === "killed" ||
          result.status === "quarantined" ||
          (result.error && /blocked|killed|quarantine|denied|amsi/i.test(result.error));

        return {
          success: !blocked,
          body: result.output,
          error: result.error,
        };
      } catch (err: any) {
        return { success: false, error: err.message };
      }
    },
    {
      maxAttempts: request.maxEvasionAttempts || 10,
      delayBetweenAttempts: 2000,
      jitterRange: 1000,
      abortOnFirstSuccess: true,
    },
  );

  storeFinding(finding);

  // Extract the effective command/transport from the successful attempt
  const successAttempt = finding.attempts.find(a => a.result === "bypassed");

  return {
    taskStatus: finding.finalResult === "bypassed" ? "executed" : "blocked_by_edr",
    evasionFinding: finding,
    edrDetected: finding.defensesDetected,
    bypassAchieved: finding.finalResult === "bypassed",
    bypassTechnique: finding.successfulTechnique?.name,
    originalBlocked: finding.attempts[0]?.result === "blocked",
    effectiveCommand: successAttempt?.mutationApplied ? finding.attempts[finding.attempts.length - 1]?.mutationApplied : request.command,
    effectivePipeline: successAttempt?.pipelineProfile,
    effectiveTransport: finding.attempts.find(a => a.result === "bypassed")?.techniqueId === "protocol_rotation"
      ? "rotated" : request.transport,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — EXPLOIT AUTOMATION INTEGRATION (Payload Obfuscation)
// ═══════════════════════════════════════════════════════════════════════

export interface EvasionExploitRequest {
  target: string; // URL or IP
  exploitId: string;
  exploitName: string;
  payload: string;
  /** Enable evasion orchestrator for this exploit */
  evasionEnabled: boolean;
  /** Max evasion attempts */
  maxEvasionAttempts?: number;
  /** Attack vector ID for linking results */
  attackVectorId?: string;
  /** Playbook execution ID for linking results */
  executionId?: string;
}

export interface EvasionExploitResult {
  exploitStatus: string;
  evasionFinding?: EvasionFinding;
  defensesDetected?: string[];
  bypassAchieved: boolean;
  bypassTechnique?: string;
  originalBlocked: boolean;
  /** The effective payload that succeeded */
  effectivePayload?: string;
  /** The pipeline profile used */
  effectivePipeline?: EvasionProfile;
  /** The obfuscation level that worked */
  effectiveObfuscationLevel?: number;
  /** Whether staged delivery was used */
  stagedDelivery: boolean;
}

/**
 * Execute an exploit with evasion orchestrator wrapping.
 * If the exploit is blocked by WAF or EDR, the orchestrator escalates
 * through UA rotation, encoding, payload transformation, and staged delivery.
 */
export async function runEvasionAwareExploit(
  request: EvasionExploitRequest,
  /** The actual exploit execution function */
  exploitFn: (payload: string, options: {
    headers?: Record<string, string>;
    encoding?: string;
    pipelineProfile?: EvasionProfile;
    obfuscationLevel?: number;
    stager?: string;
  }) => Promise<{ success: boolean; statusCode?: number; body?: string; error?: string }>,
): Promise<EvasionExploitResult> {
  if (!request.evasionEnabled) {
    const result = await exploitFn(request.payload, {});
    return {
      exploitStatus: result.success ? "success" : "failed",
      bypassAchieved: result.success,
      originalBlocked: !result.success,
      stagedDelivery: false,
    };
  }

  const finding = await evasionExploit(
    request.target,
    request.exploitName,
    request.payload,
    exploitFn,
    {
      maxAttempts: request.maxEvasionAttempts || 12,
      delayBetweenAttempts: 1500,
      jitterRange: 800,
      abortOnFirstSuccess: true,
    },
  );

  storeFinding(finding);

  const successAttempt = finding.attempts.find(a => a.result === "bypassed");

  return {
    exploitStatus: finding.finalResult === "bypassed" ? "exploit_succeeded" : "exploit_blocked",
    evasionFinding: finding,
    defensesDetected: finding.defensesDetected,
    bypassAchieved: finding.finalResult === "bypassed",
    bypassTechnique: finding.successfulTechnique?.name,
    originalBlocked: finding.attempts[0]?.result === "blocked",
    effectivePipeline: successAttempt?.pipelineProfile,
    effectiveObfuscationLevel: successAttempt?.pipelineProfile === "high" ? 3 : successAttempt?.pipelineProfile === "medium" ? 2 : successAttempt?.pipelineProfile === "low" ? 1 : 0,
    stagedDelivery: finding.attempts.some(a => a.techniqueId === "staged_delivery" && a.result === "bypassed"),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — QUICK EVASION PROBE (Lightweight WAF/EDR detection)
// ═══════════════════════════════════════════════════════════════════════

export interface ProbeResult {
  target: string;
  accessible: boolean;
  wafDetected: boolean;
  wafProducts: string[];
  edrIndicators: string[];
  responseCode?: number;
  serverHeader?: string;
  securityHeaders: Record<string, string>;
  recommendations: string[];
}

/**
 * Quick probe to detect WAF/EDR presence without running a full evasion loop.
 * Useful for pre-scan reconnaissance.
 */
export async function probeDefenses(targetUrl: string): Promise<ProbeResult> {
  const securityHeaders: Record<string, string> = {};
  const wafProducts: string[] = [];
  const edrIndicators: string[] = [];
  const recommendations: string[] = [];
  let accessible = false;
  let responseCode: number | undefined;
  let serverHeader: string | undefined;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const response = await fetch(targetUrl, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      signal: controller.signal,
      redirect: "follow",
    });
    clearTimeout(timeout);

    responseCode = response.status;
    accessible = response.status >= 200 && response.status < 400;
    serverHeader = response.headers.get("server") || undefined;

    // Collect security headers
    const secHeaders = [
      "x-frame-options", "x-content-type-options", "x-xss-protection",
      "content-security-policy", "strict-transport-security",
      "x-waf-status", "x-sucuri-id", "x-cdn-provider",
      "cf-ray", "x-amz-cf-id", "x-akamai-transformed",
    ];
    for (const h of secHeaders) {
      const val = response.headers.get(h);
      if (val) securityHeaders[h] = val;
    }

    // Detect WAF from headers
    if (response.headers.get("cf-ray")) wafProducts.push("Cloudflare");
    if (response.headers.get("x-sucuri-id")) wafProducts.push("Sucuri");
    if (response.headers.get("x-akamai-transformed")) wafProducts.push("Akamai");
    if (response.headers.get("x-amz-cf-id")) wafProducts.push("AWS CloudFront");
    if (serverHeader) {
      if (/cloudflare/i.test(serverHeader)) wafProducts.push("Cloudflare");
      if (/akamai/i.test(serverHeader)) wafProducts.push("Akamai");
      if (/imperva|incapsula/i.test(serverHeader)) wafProducts.push("Imperva");
      if (/bigip|f5/i.test(serverHeader)) wafProducts.push("F5 BIG-IP");
      if (/barracuda/i.test(serverHeader)) wafProducts.push("Barracuda");
    }

    // Check body for WAF indicators
    const body = await response.text().catch(() => "");
    if (/captcha|challenge|verify.*human|access.*denied/i.test(body)) {
      wafProducts.push("Challenge Page Detected");
    }

    // Probe with a suspicious payload to trigger WAF
    try {
      const probeUrl = new URL(targetUrl);
      probeUrl.searchParams.set("test", "<script>alert(1)</script>");
      const probeController = new AbortController();
      const probeTimeout = setTimeout(() => probeController.abort(), 10000);
      const probeResponse = await fetch(probeUrl.toString(), {
        method: "GET",
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        signal: probeController.signal,
        redirect: "follow",
      });
      clearTimeout(probeTimeout);

      if (probeResponse.status === 403 || probeResponse.status === 406) {
        wafProducts.push("Active WAF (blocks XSS probes)");
      }
    } catch {
      // Probe blocked — likely WAF
      wafProducts.push("Active WAF (connection blocked on probe)");
    }

  } catch (err: any) {
    if (/ECONNRESET|ECONNREFUSED/i.test(err.message)) {
      recommendations.push("Target actively refuses connections — may have IP-based blocking.");
    }
    if (/timeout/i.test(err.message)) {
      recommendations.push("Target timed out — may have rate limiting or geo-blocking.");
    }
  }

  // Deduplicate WAF products
  const uniqueWaf = [...new Set(wafProducts)];

  // Generate recommendations
  if (uniqueWaf.length > 0) {
    recommendations.push(`WAF detected: ${uniqueWaf.join(", ")}. Enable evasion orchestrator for scanning and exploits.`);
    recommendations.push("Start with Level 1-2 evasion (UA rotation, header normalization) before escalating.");
  } else {
    recommendations.push("No WAF detected on initial probe. Standard scanning should work without evasion.");
  }

  if (Object.keys(securityHeaders).length < 3) {
    recommendations.push("Target has minimal security headers — may be vulnerable to header-based attacks.");
  }

  return {
    target: targetUrl,
    accessible,
    wafDetected: uniqueWaf.length > 0,
    wafProducts: uniqueWaf,
    edrIndicators,
    responseCode,
    serverHeader,
    securityHeaders,
    recommendations,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — PIPELINE GENERATION HELPERS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate a payload transformation pipeline based on detected defenses.
 * Uses the evasion finding to select the optimal pipeline profile.
 */
export function selectPipelineForDefenses(
  defensesDetected: string[],
  targetOS: "windows" | "linux" | "macos" = "windows",
): { profile: EvasionProfile; pipeline: TransformPipeline; reasoning: string } {
  const hasEDR = defensesDetected.some(d =>
    /crowdstrike|sentinelone|carbon.*black|defender|cylance|sophos|kaspersky|bitdefender|eset/i.test(d)
  );
  const hasWAF = defensesDetected.some(d =>
    /cloudflare|akamai|imperva|aws.*waf|modsecurity|sucuri|barracuda|f5|fortinet|palo.*alto/i.test(d)
  );
  const hasAMSI = defensesDetected.some(d => /amsi|antimalware/i.test(d));

  let profile: EvasionProfile = "none";
  let reasoning = "";

  if (hasEDR && hasAMSI) {
    profile = "high";
    reasoning = `EDR (${defensesDetected.filter(d => /crowdstrike|sentinelone|carbon|defender|cylance|sophos/i.test(d)).join(", ")}) and AMSI detected — using full evasion pipeline with NTDLL unhook, ETW patch, AMSI bypass, and process hollowing.`;
  } else if (hasEDR) {
    profile = "medium";
    reasoning = `EDR detected (${defensesDetected.filter(d => /crowdstrike|sentinelone|carbon|defender|cylance|sophos/i.test(d)).join(", ")}) — using medium profile with direct syscalls and process injection.`;
  } else if (hasWAF) {
    profile = "low";
    reasoning = `WAF detected (${defensesDetected.filter(d => /cloudflare|akamai|imperva|aws|modsecurity|sucuri/i.test(d)).join(", ")}) — using low profile with shellcode conversion and string encryption.`;
  } else {
    profile = "none";
    reasoning = "No significant defenses detected — raw payload should work.";
  }

  const pipeline = buildPipeline(profile, { targetOS });

  return { profile, pipeline, reasoning };
}

/**
 * Generate command mutations optimized for detected SIEM/EDR products.
 */
export function generateOptimizedMutations(
  command: string,
  defensesDetected: string[],
): { mutations: MutationVariant[]; reasoning: string } {
  const hasEDR = defensesDetected.some(d =>
    /crowdstrike|sentinelone|carbon.*black|defender/i.test(d)
  );

  // Select mutation categories based on detected defenses
  const categories: string[] = [];
  let reasoning = "";

  if (hasEDR) {
    // EDR typically monitors process creation and command lines
    categories.push(
      "case_mutation", "path_mutation", "env_var_substitution",
      "encoding_mutation", "argument_mutation", "string_concat",
    );
    reasoning = "EDR detected — applying comprehensive command mutations including case, path, env var, encoding, argument, and string concatenation mutations.";
  } else {
    // Basic SIEM rules — lighter mutations
    categories.push("case_mutation", "whitespace_mutation", "separator_mutation");
    reasoning = "Basic defenses — applying lightweight mutations (case, whitespace, separator).";
  }

  const mutations = generateMutations(command, {
    categories: categories as any[],
    maxPerCategory: 3,
  });

  return { mutations, reasoning };
}
