import {
  runEvasionLoop,
  storeFinding
} from "./chunk-SP7DWOM3.js";
import "./chunk-JGUFAE3I.js";
import "./chunk-KFQGP6VL.js";

// server/lib/evasion-validation.ts
var BLOCK_SIGNATURES = {
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
    "azure front door"
  ],
  cdn: [
    "cdn-cgi",
    "cf-ray",
    "x-cdn",
    "x-cache",
    "via: cloudfront",
    "x-amz-cf-id",
    "x-akamai",
    "x-fastly"
  ],
  edr: [
    "connection reset",
    "connection refused",
    "econnreset",
    "econnrefused",
    "socket hang up",
    "network unreachable"
  ],
  ngfw: [
    "406 not acceptable",
    "429 too many requests",
    "503 service unavailable",
    "connection timed out",
    "request timeout",
    "gateway timeout"
  ]
};
function detectValidationBlock(result) {
  const signals = [];
  const body = (result.body || result.responseSnippet || "").toLowerCase();
  const error = (result.error || "").toLowerCase();
  const statusCode = result.statusCode;
  const headers = result.headers || {};
  const headerStr = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n").toLowerCase();
  for (const sig of BLOCK_SIGNATURES.waf) {
    if (body.includes(sig) || headerStr.includes(sig)) {
      signals.push(`WAF signature: "${sig}"`);
    }
  }
  if (signals.length > 0) {
    const defenseName = identifyWafProduct(body, headerStr);
    return { isBlocked: true, defenseType: "waf", defenseName, confidence: 0.85 + signals.length * 0.03, signals };
  }
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
  for (const sig of BLOCK_SIGNATURES.edr) {
    if (error.includes(sig)) {
      signals.push(`EDR/network block: "${sig}"`);
    }
  }
  if (signals.length > 0) {
    return { isBlocked: true, defenseType: "edr", defenseName: "Network-level defense", confidence: 0.7, signals };
  }
  if (statusCode && [406, 429, 503].includes(statusCode)) {
    for (const sig of BLOCK_SIGNATURES.ngfw) {
      if (body.includes(sig) || error.includes(sig)) {
        signals.push(`NGFW block: "${sig}"`);
      }
    }
    if (statusCode === 429 || statusCode === 503 && body.length < 200) {
      signals.push(`NGFW block: HTTP ${statusCode} with minimal response`);
    }
    if (signals.length > 0) {
      return { isBlocked: true, defenseType: "ngfw", defenseName: "Next-Gen Firewall", confidence: 0.65, signals };
    }
  }
  return { isBlocked: false, defenseType: "none", defenseName: "none", confidence: 0, signals: [] };
}
function identifyWafProduct(body, headers) {
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
function identifyCdnProduct(headers) {
  if (headers.includes("cf-ray")) return "Cloudflare CDN";
  if (headers.includes("x-amz-cf-id") || headers.includes("cloudfront")) return "AWS CloudFront";
  if (headers.includes("x-akamai")) return "Akamai CDN";
  if (headers.includes("x-fastly")) return "Fastly CDN";
  if (headers.includes("x-cdn")) return "Generic CDN";
  return "Unknown CDN";
}
function buildEvasionFetchOptions(ctx) {
  const headers = {};
  const metadata = ctx.metadata || {};
  const userAgents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
  ];
  const level = metadata.escalationLevel || 0;
  if (level >= 1) {
    headers["User-Agent"] = userAgents[level % userAgents.length];
  }
  if (level >= 2) {
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
    headers["Accept-Language"] = "en-US,en;q=0.9";
    headers["Accept-Encoding"] = "gzip, deflate, br";
    headers["Cache-Control"] = "no-cache";
    headers["Pragma"] = "no-cache";
  }
  if (level >= 3) {
    const target = metadata.target || "example.com";
    headers["Referer"] = `https://www.google.com/search?q=${encodeURIComponent(target)}`;
    headers["Origin"] = `https://${target}`;
    headers["DNT"] = "1";
    headers["Sec-Fetch-Dest"] = "document";
    headers["Sec-Fetch-Mode"] = "navigate";
    headers["Sec-Fetch-Site"] = "cross-site";
  }
  if (level >= 4) {
    headers["User-Agent"] = userAgents[5];
    headers["X-Forwarded-For"] = `66.249.${64 + level % 16}.${Math.floor(Math.random() * 255)}`;
  }
  if (level >= 5) {
    headers["User-Agent"] = userAgents[6];
    headers["X-Forwarded-For"] = `40.77.167.${Math.floor(Math.random() * 255)}`;
    headers["X-Real-IP"] = `40.77.167.${Math.floor(Math.random() * 255)}`;
    delete headers["Referer"];
    delete headers["Origin"];
  }
  const delay = level * 500 + Math.floor(Math.random() * 300);
  return { headers, delay };
}
async function runEvasionAwareProbe(probeTemplate, target, port, config = {}) {
  const { executeProbe } = await import("./active-probes-4TT6TATU.js");
  const initialResult = await executeProbe(probeTemplate, target, port);
  const blockCheck = detectValidationBlock({
    statusCode: initialResult.result === "error" ? 0 : void 0,
    body: initialResult.responseSnippet,
    error: initialResult.error
  });
  if (!blockCheck.isBlocked) {
    return {
      originalResult: initialResult,
      evasionNeeded: false,
      evasionSucceeded: false,
      evasionAttempts: 0,
      successfulTechnique: null,
      defensesDetected: [],
      evasionFinding: null,
      finalResult: initialResult
    };
  }
  const domain = config.domain || "scanning";
  const initialContext = {
    target,
    operation: `probe:${probeTemplate.id}`,
    metadata: {
      target,
      probeId: probeTemplate.id,
      probeName: probeTemplate.name,
      port,
      defenseType: blockCheck.defenseType,
      defenseName: blockCheck.defenseName,
      escalationLevel: 0
    }
  };
  const finding = await runEvasionLoop(
    domain,
    target,
    `validation-probe:${probeTemplate.id}`,
    initialContext,
    async (ctx) => {
      const evasionOpts = buildEvasionFetchOptions(ctx);
      if (evasionOpts.delay > 0) {
        await new Promise((r) => setTimeout(r, evasionOpts.delay));
      }
      const modifiedTemplate = {
        ...probeTemplate,
        httpHeaders: { ...probeTemplate.httpHeaders || {}, ...evasionOpts.headers }
      };
      const result = await executeProbe(modifiedTemplate, target, port);
      const recheck = detectValidationBlock({
        statusCode: result.result === "error" ? 0 : void 0,
        body: result.responseSnippet,
        error: result.error
      });
      return {
        success: !recheck.isBlocked,
        statusCode: result.result === "vulnerable" ? 200 : result.result === "error" ? 0 : 200,
        body: result.responseSnippet || "",
        error: result.error,
        data: result
      };
    },
    { maxAttempts: config.maxAttempts || 5, initialDelayMs: config.initialDelayMs || 500 }
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
    successfulTechnique: finding.successfulTechnique?.name || null,
    defensesDetected: finding.defensesDetected,
    evasionFinding: finding,
    finalResult: evasionSucceeded && finding.attempts.length > 0 ? finding.attempts[finding.attempts.length - 1].responseData : initialResult
  };
}
async function runEvasionAwareProbeScan(target, options) {
  const { runProbeScan, getProbesForCves, PROBE_TEMPLATES } = await import("./active-probes-4TT6TATU.js");
  let templates = [...PROBE_TEMPLATES];
  if (options?.probeIds && options.probeIds.length > 0) {
    templates = templates.filter((p) => options.probeIds.includes(p.id));
  } else if (options?.cveIds && options.cveIds.length > 0) {
    templates = getProbesForCves(options.cveIds);
  }
  const results = [];
  const defensesEncountered = /* @__PURE__ */ new Set();
  const techniquesUsed = /* @__PURE__ */ new Set();
  for (const template of templates) {
    const result = await runEvasionAwareProbe(
      template,
      target,
      options?.port,
      options?.evasionConfig
    );
    results.push(result);
    if (result.evasionNeeded) {
      result.defensesDetected.forEach((d) => defensesEncountered.add(d));
      if (result.successfulTechnique) techniquesUsed.add(result.successfulTechnique);
    }
  }
  const probesBlocked = results.filter((r) => r.evasionNeeded).length;
  const probesBypassed = results.filter((r) => r.evasionNeeded && r.evasionSucceeded).length;
  const probesFailedBypass = results.filter((r) => r.evasionNeeded && !r.evasionSucceeded).length;
  const probesClean = results.filter((r) => !r.evasionNeeded).length;
  return {
    totalProbes: results.length,
    probesBlocked,
    probesBypassed,
    probesFailedBypass,
    probesClean,
    defensesEncountered: Array.from(defensesEncountered),
    techniquesUsed: Array.from(techniquesUsed),
    bypassRate: probesBlocked > 0 ? probesBypassed / probesBlocked : 1,
    results
  };
}
async function runEvasionAwareVerificationSuite(targetHost, targetPort = 443, protocol = "https", probeFilter, evasionConfig) {
  const { BUILTIN_PROBES, runProbe } = await import("./active-verification-Q67CHWGV.js");
  let probes = [...BUILTIN_PROBES];
  if (probeFilter?.cveIds && probeFilter.cveIds.length > 0) {
    probes = probes.filter((p) => p.cveIds.some((c) => probeFilter.cveIds.includes(c)));
  }
  if (probeFilter?.tags && probeFilter.tags.length > 0) {
    probes = probes.filter((p) => p.tags.some((t) => probeFilter.tags.includes(t)));
  }
  if (probes.length === 0) {
    probes = BUILTIN_PROBES.filter((p) => p.safeForProduction);
  }
  const evasionResults = [];
  const verificationResults = [];
  const defensesEncountered = /* @__PURE__ */ new Set();
  const techniquesUsed = /* @__PURE__ */ new Set();
  for (const probe of probes) {
    const initialResult = await runProbe(probe, targetHost, targetPort, protocol);
    const blockCheck = detectValidationBlock({
      statusCode: initialResult.status === "error" ? 0 : initialResult.responseData?.statusCode || null,
      body: initialResult.responseData?.bodySnippet || null,
      error: initialResult.evidence
    });
    if (!blockCheck.isBlocked) {
      verificationResults.push(initialResult);
      evasionResults.push({
        originalResult: initialResult,
        evasionNeeded: false,
        evasionSucceeded: false,
        evasionAttempts: 0,
        successfulTechnique: null,
        defensesDetected: [],
        evasionFinding: null,
        finalResult: initialResult
      });
      continue;
    }
    blockCheck.signals.forEach(() => defensesEncountered.add(blockCheck.defenseName));
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
          defenseType: blockCheck.defenseType,
          defenseName: blockCheck.defenseName,
          escalationLevel: 0
        }
      },
      async (ctx) => {
        const evasionOpts = buildEvasionFetchOptions(ctx);
        if (evasionOpts.delay > 0) {
          await new Promise((r) => setTimeout(r, evasionOpts.delay));
        }
        const modifiedProbe = {
          ...probe,
          headers: { ...probe.headers, ...evasionOpts.headers }
        };
        const result = await runProbe(modifiedProbe, targetHost, targetPort, protocol);
        const recheck = detectValidationBlock({
          statusCode: result.responseData?.statusCode || null,
          body: result.responseData?.bodySnippet || null,
          error: result.evidence
        });
        return {
          success: !recheck.isBlocked,
          statusCode: result.responseData?.statusCode || 0,
          body: result.responseData?.bodySnippet || "",
          error: result.status === "error" ? result.evidence : void 0,
          data: result
        };
      },
      { maxAttempts: evasionConfig?.maxAttempts || 5 }
    );
    if (evasionConfig?.storeFindings !== false) {
      storeFinding(finding);
    }
    const evasionSucceeded = finding.finalResult === "bypassed";
    const finalResult = evasionSucceeded && finding.attempts.length > 0 ? finding.attempts[finding.attempts.length - 1].responseData : initialResult;
    verificationResults.push(finalResult);
    if (finding.successfulTechnique) techniquesUsed.add(finding.successfulTechnique.name);
    evasionResults.push({
      originalResult: initialResult,
      evasionNeeded: true,
      evasionSucceeded,
      evasionAttempts: finding.attempts.length,
      successfulTechnique: finding.successfulTechnique?.name || null,
      defensesDetected: finding.defensesDetected,
      evasionFinding: finding,
      finalResult
    });
  }
  const vulnerableCount = verificationResults.filter((r) => r.status === "vulnerable").length;
  const hasCritical = verificationResults.some(
    (r) => r.status === "vulnerable" && probes.find((p) => p.id === r.probeId)?.severity === "critical"
  );
  const hasHigh = verificationResults.some(
    (r) => r.status === "vulnerable" && probes.find((p) => p.id === r.probeId)?.severity === "high"
  );
  let overallRisk;
  if (hasCritical) overallRisk = "critical";
  else if (hasHigh) overallRisk = "high";
  else if (vulnerableCount > 0) overallRisk = "medium";
  else if (verificationResults.some((r) => r.status === "inconclusive")) overallRisk = "low";
  else overallRisk = "none";
  const probesBlocked = evasionResults.filter((r) => r.evasionNeeded).length;
  const probesBypassed = evasionResults.filter((r) => r.evasionNeeded && r.evasionSucceeded).length;
  return {
    report: {
      targetHost,
      totalProbes: verificationResults.length,
      vulnerableCount,
      notVulnerableCount: verificationResults.filter((r) => r.status === "not_vulnerable").length,
      inconclusiveCount: verificationResults.filter((r) => r.status === "inconclusive").length,
      errorCount: verificationResults.filter((r) => r.status === "error" || r.status === "timeout").length,
      results: verificationResults,
      overallRisk,
      generatedAt: Date.now()
    },
    evasionSummary: {
      totalProbes: evasionResults.length,
      probesBlocked,
      probesBypassed,
      probesFailedBypass: evasionResults.filter((r) => r.evasionNeeded && !r.evasionSucceeded).length,
      probesClean: evasionResults.filter((r) => !r.evasionNeeded).length,
      defensesEncountered: Array.from(defensesEncountered),
      techniquesUsed: Array.from(techniquesUsed),
      bypassRate: probesBlocked > 0 ? probesBypassed / probesBlocked : 1,
      results: evasionResults
    }
  };
}
async function runEvasionAwareTakeoverValidation(candidates, evasionConfig) {
  const { validateTakeoverCandidates } = await import("./domain-intel-advanced-AHE4BPFB.js");
  const http = await import("http");
  const https = await import("https");
  const normalResult = await validateTakeoverCandidates(candidates);
  const defensesEncountered = /* @__PURE__ */ new Set();
  const techniquesUsed = /* @__PURE__ */ new Set();
  let candidatesBlocked = 0;
  let candidatesBypassed = 0;
  for (let i = 0; i < normalResult.results.length; i++) {
    const pocResult = normalResult.results[i];
    const candidate = candidates[i];
    const blockCheck = detectValidationBlock({
      statusCode: pocResult.httpStatusCode,
      body: pocResult.responseSnippet,
      error: pocResult.validationStatus === "error" ? pocResult.exploitabilityNote : null
    });
    if (!blockCheck.isBlocked) continue;
    candidatesBlocked++;
    defensesEncountered.add(blockCheck.defenseName);
    const finding = await runEvasionLoop(
      evasionConfig?.domain || "scanning",
      candidate.subdomain,
      `takeover-poc:${candidate.subdomain}`,
      {
        target: candidate.subdomain,
        operation: `takeover-validate:${candidate.service}`,
        metadata: {
          target: candidate.subdomain,
          cnameTarget: candidate.cnameTarget,
          service: candidate.service,
          defenseType: blockCheck.defenseType,
          defenseName: blockCheck.defenseName,
          escalationLevel: 0
        }
      },
      async (ctx) => {
        const evasionOpts = buildEvasionFetchOptions(ctx);
        if (evasionOpts.delay > 0) {
          await new Promise((r) => setTimeout(r, evasionOpts.delay));
        }
        try {
          const response = await fetch(`https://${candidate.subdomain}`, {
            headers: {
              ...evasionOpts.headers,
              "Accept": "text/html,application/xhtml+xml,*/*"
            },
            signal: AbortSignal.timeout(8e3),
            redirect: "follow"
          });
          const body = await response.text().catch(() => "");
          const recheck = detectValidationBlock({
            statusCode: response.status,
            body,
            headers: Object.fromEntries(response.headers.entries())
          });
          return {
            success: !recheck.isBlocked,
            statusCode: response.status,
            body: body.substring(0, 2e3),
            data: { statusCode: response.status, body: body.substring(0, 2e3) }
          };
        } catch (err) {
          try {
            const response = await fetch(`http://${candidate.subdomain}`, {
              headers: evasionOpts.headers,
              signal: AbortSignal.timeout(8e3),
              redirect: "follow"
            });
            const body = await response.text().catch(() => "");
            return {
              success: true,
              statusCode: response.status,
              body: body.substring(0, 2e3),
              data: { statusCode: response.status, body: body.substring(0, 2e3) }
            };
          } catch (err2) {
            return {
              success: false,
              error: err2.message,
              data: null
            };
          }
        }
      },
      { maxAttempts: evasionConfig?.maxAttempts || 4 }
    );
    if (evasionConfig?.storeFindings !== false) {
      storeFinding(finding);
    }
    if (finding.finalResult === "bypassed" && finding.attempts.length > 0) {
      candidatesBypassed++;
      const lastAttempt = finding.attempts[finding.attempts.length - 1];
      if (finding.successfulTechnique) techniquesUsed.add(finding.successfulTechnique.name);
      const newBody = lastAttempt.responseData?.body || "";
      const newStatus = lastAttempt.responseData?.statusCode || 0;
      pocResult.httpStatusCode = newStatus;
      pocResult.responseSnippet = newBody.substring(0, 500);
      const domIntelMod = await import("./domain-intel-advanced-AHE4BPFB.js");
      const TAKEOVER_FINGERPRINTS = domIntelMod.TAKEOVER_FINGERPRINTS;
      const fingerprint = (await import("./domain-intel-advanced-AHE4BPFB.js")).TAKEOVER_FINGERPRINTS.find((f) => f.service === candidate.service);
      if (fingerprint && newBody) {
        for (const fp of fingerprint.httpFingerprints) {
          if (newBody.includes(fp)) {
            pocResult.responseContainsFingerprint = true;
            pocResult.fingerprintMatched = fp;
            break;
          }
        }
      }
      if (pocResult.responseContainsFingerprint && !pocResult.dnsResolves) {
        pocResult.validationStatus = "confirmed";
        pocResult.confidence = 95;
        pocResult.exploitabilityNote = `CONFIRMED (via evasion bypass of ${blockCheck.defenseName}): CNAME target does not resolve and HTTP response contains "${pocResult.fingerprintMatched}" \u2014 subdomain can be claimed.`;
      } else if (pocResult.responseContainsFingerprint) {
        pocResult.validationStatus = "likely";
        pocResult.confidence = 80;
        pocResult.exploitabilityNote = `LIKELY (via evasion bypass of ${blockCheck.defenseName}): HTTP response contains "${pocResult.fingerprintMatched}" indicating unclaimed ${candidate.service} resource.`;
      }
      pocResult.evasionUsed = true;
      pocResult.evasionTechnique = finding.successfulTechnique?.name;
      pocResult.defenseBypassed = blockCheck.defenseName;
    }
  }
  const updatedResults = normalResult.results;
  normalResult.confirmedCount = updatedResults.filter((r) => r.validationStatus === "confirmed").length;
  normalResult.likelyCount = updatedResults.filter((r) => r.validationStatus === "likely").length;
  normalResult.possibleCount = updatedResults.filter((r) => r.validationStatus === "possible").length;
  normalResult.unlikelyCount = updatedResults.filter((r) => r.validationStatus === "unlikely").length;
  normalResult.errorCount = updatedResults.filter((r) => r.validationStatus === "error").length;
  return {
    validationResult: normalResult,
    evasionSummary: {
      totalCandidates: candidates.length,
      candidatesBlocked,
      candidatesBypassed,
      defensesEncountered: Array.from(defensesEncountered),
      techniquesUsed: Array.from(techniquesUsed)
    }
  };
}
async function runEvasionAwareExploitValidation(target, kevFindings, evasionConfig) {
  const { getProbesForCves } = await import("./active-probes-4TT6TATU.js");
  const results = [];
  let exploitable = 0;
  let blocked = 0;
  let bypassed = 0;
  for (const finding of kevFindings) {
    if (!finding.linkedExploits || finding.linkedExploits.length === 0) continue;
    for (const exploit of finding.linkedExploits) {
      const probes = getProbesForCves([exploit.cveId]);
      if (probes.length === 0) {
        results.push({
          findingId: finding.id,
          cveId: exploit.cveId,
          exploitName: exploit.bestExploit?.name || exploit.cveId,
          validationResult: "not_exploitable",
          evasionUsed: false,
          evasionTechnique: null,
          defenseBypassed: null,
          evidence: `No validation probe available for ${exploit.cveId}. Exploit exists (${exploit.bestExploit?.source || "unknown"}) but cannot be automatically verified.`
        });
        continue;
      }
      for (const probe of probes) {
        const evasionResult = await runEvasionAwareProbe(
          probe,
          target,
          void 0,
          evasionConfig
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
          validationResult: isExploitable ? "exploitable" : wasBlocked ? "blocked" : evasionResult.evasionSucceeded ? "bypassed" : "not_exploitable",
          evasionUsed: evasionResult.evasionNeeded,
          evasionTechnique: evasionResult.successfulTechnique,
          defenseBypassed: evasionResult.defensesDetected[0] || null,
          evidence: isExploitable ? `EXPLOITABLE: Probe "${probe.name}" confirmed vulnerability for ${exploit.cveId}${evasionResult.evasionSucceeded ? ` (bypassed ${evasionResult.defensesDetected.join(", ")} using ${evasionResult.successfulTechnique})` : ""}` : wasBlocked ? `BLOCKED: Defense (${evasionResult.defensesDetected.join(", ")}) prevented validation of ${exploit.cveId} after ${evasionResult.evasionAttempts} evasion attempts` : `NOT EXPLOITABLE: Probe "${probe.name}" did not confirm vulnerability for ${exploit.cveId}`
        });
      }
    }
  }
  return {
    totalValidated: results.length,
    exploitable,
    blocked,
    bypassed,
    results
  };
}
export {
  detectValidationBlock,
  runEvasionAwareExploitValidation,
  runEvasionAwareProbe,
  runEvasionAwareProbeScan,
  runEvasionAwareTakeoverValidation,
  runEvasionAwareVerificationSuite
};
