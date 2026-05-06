import "./chunk-KFQGP6VL.js";

// server/lib/compensating-controls.ts
var DEFAULT_CONTROL_CONFIG = {
  enableWafDetection: true,
  enableHeaderAnalysis: true,
  enableCdnDetection: true,
  enableSecurityHeaderScoring: true,
  minimumConfidence: "low"
};
var WAF_SIGNATURES = [
  {
    name: "Cloudflare",
    category: "waf",
    headerPatterns: [
      { header: "server", pattern: /cloudflare/i },
      { header: "cf-ray", pattern: /.+/ },
      { header: "cf-cache-status", pattern: /.+/ }
    ],
    mitigationFactor: 0.35,
    affectedVectors: ["T1190", "T1189", "T1059", "T1203"]
  },
  {
    name: "Akamai",
    category: "waf",
    headerPatterns: [
      { header: "server", pattern: /akamai/i },
      { header: "x-akamai-transformed", pattern: /.+/ },
      { header: "x-akamai-request-id", pattern: /.+/ }
    ],
    mitigationFactor: 0.35,
    affectedVectors: ["T1190", "T1189", "T1059"]
  },
  {
    name: "AWS WAF / CloudFront",
    category: "waf",
    headerPatterns: [
      { header: "x-amz-cf-id", pattern: /.+/ },
      { header: "x-amzn-waf-action", pattern: /.+/ },
      { header: "server", pattern: /cloudfront/i }
    ],
    mitigationFactor: 0.3,
    affectedVectors: ["T1190", "T1189"]
  },
  {
    name: "Imperva / Incapsula",
    category: "waf",
    headerPatterns: [
      { header: "x-iinfo", pattern: /.+/ },
      { header: "x-cdn", pattern: /incapsula/i }
    ],
    mitigationFactor: 0.35,
    affectedVectors: ["T1190", "T1189", "T1059"]
  },
  {
    name: "F5 BIG-IP ASM",
    category: "waf",
    headerPatterns: [
      { header: "server", pattern: /big-?ip/i },
      { header: "x-wa-info", pattern: /.+/ }
    ],
    mitigationFactor: 0.3,
    affectedVectors: ["T1190", "T1059"]
  },
  {
    name: "Sucuri",
    category: "waf",
    headerPatterns: [
      { header: "server", pattern: /sucuri/i },
      { header: "x-sucuri-id", pattern: /.+/ }
    ],
    mitigationFactor: 0.25,
    affectedVectors: ["T1190"]
  },
  {
    name: "Fastly",
    category: "cdn",
    headerPatterns: [
      { header: "server", pattern: /fastly/i },
      { header: "x-served-by", pattern: /cache-/i },
      { header: "via", pattern: /varnish/i }
    ],
    mitigationFactor: 0.15,
    affectedVectors: ["T1499"]
  },
  {
    name: "ModSecurity",
    category: "waf",
    headerPatterns: [
      { header: "server", pattern: /mod_security/i }
    ],
    mitigationFactor: 0.2,
    affectedVectors: ["T1190", "T1059"]
  }
];
var SECURITY_HEADER_CHECKS = [
  {
    header: "strict-transport-security",
    category: "hsts",
    name: "HSTS",
    validator: (v) => v.includes("max-age=") && parseInt(v.match(/max-age=(\d+)/)?.[1] || "0") >= 31536e3,
    mitigationFactor: 0.1,
    affectedVectors: ["T1557"]
  },
  {
    header: "content-security-policy",
    category: "csp",
    name: "Content Security Policy",
    validator: (v) => !v.includes("unsafe-inline") || v.includes("nonce-"),
    mitigationFactor: 0.15,
    affectedVectors: ["T1189", "T1059.007"]
  },
  {
    header: "x-frame-options",
    category: "csp",
    name: "X-Frame-Options",
    validator: (v) => v.toLowerCase() === "deny" || v.toLowerCase() === "sameorigin",
    mitigationFactor: 0.05,
    affectedVectors: ["T1189"]
  },
  {
    header: "x-content-type-options",
    category: "csp",
    name: "X-Content-Type-Options",
    validator: (v) => v.toLowerCase() === "nosniff",
    mitigationFactor: 0.05,
    affectedVectors: ["T1189"]
  },
  {
    header: "x-xss-protection",
    category: "csp",
    name: "XSS Protection",
    validator: (v) => v.startsWith("1"),
    mitigationFactor: 0.05,
    affectedVectors: ["T1189"]
  }
];
function detectControlsFromHeaders(headers, config = DEFAULT_CONTROL_CONFIG) {
  const controls = [];
  const normalizedHeaders = {};
  for (const [key, value] of Object.entries(headers)) {
    normalizedHeaders[key.toLowerCase()] = value;
  }
  if (config.enableWafDetection) {
    for (const sig of WAF_SIGNATURES) {
      let matchCount = 0;
      let evidence = "";
      for (const { header, pattern } of sig.headerPatterns) {
        const value = normalizedHeaders[header.toLowerCase()];
        if (value && pattern.test(value)) {
          matchCount++;
          evidence += `${header}: ${value}; `;
        }
      }
      if (matchCount > 0) {
        const confidence = matchCount >= 2 ? "high" : matchCount === 1 ? "medium" : "low";
        controls.push({
          category: sig.category,
          name: sig.name,
          confidence,
          evidence: evidence.trim(),
          mitigationFactor: sig.mitigationFactor,
          affectedAttackVectors: sig.affectedVectors
        });
      }
    }
  }
  if (config.enableHeaderAnalysis) {
    for (const check of SECURITY_HEADER_CHECKS) {
      const value = normalizedHeaders[check.header.toLowerCase()];
      if (value && check.validator(value)) {
        controls.push({
          category: check.category,
          name: check.name,
          confidence: "high",
          evidence: `${check.header}: ${value}`,
          mitigationFactor: check.mitigationFactor,
          affectedAttackVectors: check.affectedVectors
        });
      }
    }
  }
  return controls;
}
function detectControlsFromObservations(observations) {
  const controls = [];
  const seen = /* @__PURE__ */ new Set();
  for (const obs of observations) {
    const valueLower = (obs.value || "").toLowerCase();
    const metaStr = JSON.stringify(obs.metadata || {}).toLowerCase();
    const combined = `${valueLower} ${metaStr}`;
    if (obs.assetType === "technology" || obs.assetType === "dns_record") {
      if (combined.includes("cloudflare") && !seen.has("cloudflare")) {
        seen.add("cloudflare");
        controls.push({
          category: "waf",
          name: "Cloudflare WAF",
          confidence: "high",
          evidence: `Detected via ${obs.source}: ${obs.value}`,
          mitigationFactor: 0.35,
          affectedAttackVectors: ["T1190", "T1189", "T1059", "T1499"]
        });
      }
      if (combined.includes("akamai") && !seen.has("akamai")) {
        seen.add("akamai");
        controls.push({
          category: "waf",
          name: "Akamai WAF",
          confidence: "high",
          evidence: `Detected via ${obs.source}: ${obs.value}`,
          mitigationFactor: 0.35,
          affectedAttackVectors: ["T1190", "T1189"]
        });
      }
      if ((combined.includes("crowdstrike") || combined.includes("falcon")) && !seen.has("edr")) {
        seen.add("edr");
        controls.push({
          category: "edr",
          name: "CrowdStrike Falcon EDR",
          confidence: "medium",
          evidence: `Detected via ${obs.source}: ${obs.value}`,
          mitigationFactor: 0.25,
          affectedAttackVectors: ["T1059", "T1203", "T1068", "T1105"]
        });
      }
      if (combined.includes("sentinelone") && !seen.has("edr")) {
        seen.add("edr");
        controls.push({
          category: "edr",
          name: "SentinelOne EDR",
          confidence: "medium",
          evidence: `Detected via ${obs.source}: ${obs.value}`,
          mitigationFactor: 0.25,
          affectedAttackVectors: ["T1059", "T1203", "T1068"]
        });
      }
    }
    if (obs.assetType === "technology") {
      if ((combined.includes("okta") || combined.includes("duo") || combined.includes("auth0")) && !seen.has("mfa")) {
        seen.add("mfa");
        controls.push({
          category: "mfa",
          name: combined.includes("okta") ? "Okta MFA" : combined.includes("duo") ? "Cisco Duo MFA" : "Auth0 MFA",
          confidence: "medium",
          evidence: `Detected via ${obs.source}: ${obs.value}`,
          mitigationFactor: 0.3,
          affectedAttackVectors: ["T1078", "T1110", "T1133"]
        });
      }
    }
    if (combined.includes("recaptcha") || combined.includes("hcaptcha") || combined.includes("turnstile")) {
      if (!seen.has("bot_protection")) {
        seen.add("bot_protection");
        controls.push({
          category: "bot_protection",
          name: combined.includes("recaptcha") ? "Google reCAPTCHA" : combined.includes("hcaptcha") ? "hCaptcha" : "Cloudflare Turnstile",
          confidence: "high",
          evidence: `Detected via ${obs.source}: ${obs.value}`,
          mitigationFactor: 0.1,
          affectedAttackVectors: ["T1110", "T1499"]
        });
      }
    }
  }
  return controls;
}
function assessControls(controls, findingSeverity, findingAttackVector) {
  if (controls.length === 0) {
    return {
      controls: [],
      overallMitigationScore: 0,
      severityAdjustment: 0,
      adjustedSeverityLabel: findingSeverity,
      rationale: "No compensating controls detected. Finding severity unchanged.",
      controlCategories: []
    };
  }
  let cumulativeMitigation = 0;
  const sortedControls = [...controls].sort((a, b) => b.mitigationFactor - a.mitigationFactor);
  for (const control of sortedControls) {
    if (findingAttackVector && !control.affectedAttackVectors.includes(findingAttackVector)) {
      continue;
    }
    const effectiveFactor = (1 - cumulativeMitigation) * control.mitigationFactor;
    cumulativeMitigation += effectiveFactor;
  }
  const overallMitigationScore = Math.round(cumulativeMitigation * 100);
  const severityLevels = ["low", "medium", "high", "critical"];
  const currentLevel = severityLevels.indexOf(findingSeverity);
  let levelReduction = 0;
  if (overallMitigationScore >= 60) levelReduction = 2;
  else if (overallMitigationScore >= 35) levelReduction = 1;
  const adjustedLevel = Math.max(0, currentLevel - levelReduction);
  const adjustedSeverityLabel = severityLevels[adjustedLevel];
  const controlNames = controls.map((c) => c.name).join(", ");
  const categories = Array.from(new Set(controls.map((c) => c.category)));
  let rationale;
  if (levelReduction > 0) {
    rationale = `${controls.length} compensating control(s) detected (${controlNames}). Overall mitigation score: ${overallMitigationScore}%. Severity adjusted from ${findingSeverity} to ${adjustedSeverityLabel} (${levelReduction} level${levelReduction > 1 ? "s" : ""} reduced). Note: controls reduce exploitability but do not eliminate the underlying vulnerability.`;
  } else {
    rationale = `${controls.length} compensating control(s) detected (${controlNames}). Overall mitigation score: ${overallMitigationScore}%. Insufficient to warrant severity reduction. Finding remains ${findingSeverity}.`;
  }
  return {
    controls,
    overallMitigationScore,
    severityAdjustment: -levelReduction,
    adjustedSeverityLabel,
    rationale,
    controlCategories: categories
  };
}
function batchAssessControls(controls, findings) {
  const results = /* @__PURE__ */ new Map();
  for (const finding of findings) {
    results.set(finding.id, assessControls(controls, finding.severity, finding.attackVector));
  }
  return results;
}
async function evaluateCompensatingControls(params) {
  const controls = [];
  for (const controlName of params.existingControls) {
    const lower = controlName.toLowerCase();
    let category = "waf";
    let mitigationFactor = 0.15;
    const affectedVectors = [];
    if (lower.includes("waf")) {
      category = "waf";
      mitigationFactor = 0.35;
      affectedVectors.push("T1190", "T1189");
    } else if (lower.includes("edr")) {
      category = "edr";
      mitigationFactor = 0.25;
      affectedVectors.push("T1059", "T1203");
    } else if (lower.includes("ips")) {
      category = "ips";
      mitigationFactor = 0.2;
      affectedVectors.push("T1190");
    } else if (lower.includes("mfa")) {
      category = "mfa";
      mitigationFactor = 0.3;
      affectedVectors.push("T1078", "T1110");
    } else if (lower.includes("hsts")) {
      category = "hsts";
      mitigationFactor = 0.1;
      affectedVectors.push("T1557");
    } else if (lower.includes("csp")) {
      category = "csp";
      mitigationFactor = 0.15;
      affectedVectors.push("T1189");
    } else if (lower.includes("segment")) {
      category = "network_segmentation";
      mitigationFactor = 0.25;
      affectedVectors.push("T1021");
    } else if (lower.includes("cdn")) {
      category = "cdn";
      mitigationFactor = 0.15;
      affectedVectors.push("T1499");
    } else if (lower.includes("rate")) {
      category = "rate_limiting";
      mitigationFactor = 0.1;
      affectedVectors.push("T1110", "T1499");
    }
    controls.push({
      category,
      name: controlName,
      confidence: "medium",
      evidence: `User-declared control: ${controlName}`,
      mitigationFactor,
      affectedAttackVectors: affectedVectors
    });
  }
  const assessment = assessControls(controls, "high", params.techniqueId);
  const recommendations = [];
  if (!controls.some((c) => c.category === "waf")) recommendations.push("Consider deploying a WAF to protect web-facing assets.");
  if (!controls.some((c) => c.category === "edr")) recommendations.push("Consider deploying EDR for endpoint protection.");
  if (!controls.some((c) => c.category === "mfa")) recommendations.push("Enable MFA for all privileged accounts.");
  if (!controls.some((c) => c.category === "hsts")) recommendations.push("Enable HSTS to prevent protocol downgrade attacks.");
  return { controls, assessment, recommendations };
}
function getControlCatalog() {
  return [
    { category: "waf", name: "Web Application Firewall", description: "Filters malicious HTTP traffic (SQL injection, XSS, etc.)", typicalMitigationFactor: 0.35, affectedAttackVectors: ["T1190", "T1189", "T1059"] },
    { category: "cdn", name: "CDN with DDoS Protection", description: "Content delivery with DDoS mitigation", typicalMitigationFactor: 0.15, affectedAttackVectors: ["T1499"] },
    { category: "ips", name: "Intrusion Prevention System", description: "Network-based attack detection and prevention", typicalMitigationFactor: 0.2, affectedAttackVectors: ["T1190", "T1059"] },
    { category: "edr", name: "Endpoint Detection & Response", description: "Endpoint monitoring, detection, and response", typicalMitigationFactor: 0.25, affectedAttackVectors: ["T1059", "T1203", "T1068", "T1105"] },
    { category: "network_segmentation", name: "Network Segmentation", description: "Isolates critical assets from general network", typicalMitigationFactor: 0.25, affectedAttackVectors: ["T1021", "T1570"] },
    { category: "mfa", name: "Multi-Factor Authentication", description: "Requires multiple authentication factors", typicalMitigationFactor: 0.3, affectedAttackVectors: ["T1078", "T1110", "T1133"] },
    { category: "rate_limiting", name: "Rate Limiting", description: "Limits request frequency to prevent brute force", typicalMitigationFactor: 0.1, affectedAttackVectors: ["T1110", "T1499"] },
    { category: "hsts", name: "HTTP Strict Transport Security", description: "Enforces HTTPS connections", typicalMitigationFactor: 0.1, affectedAttackVectors: ["T1557"] },
    { category: "csp", name: "Content Security Policy", description: "Restricts content sources to prevent XSS", typicalMitigationFactor: 0.15, affectedAttackVectors: ["T1189", "T1059.007"] },
    { category: "cors_strict", name: "Strict CORS Policy", description: "Restricts cross-origin requests", typicalMitigationFactor: 0.1, affectedAttackVectors: ["T1189"] },
    { category: "api_gateway", name: "API Gateway", description: "Centralized API management with auth and rate limiting", typicalMitigationFactor: 0.2, affectedAttackVectors: ["T1190", "T1110"] },
    { category: "bot_protection", name: "Bot Protection", description: "CAPTCHA and bot detection mechanisms", typicalMitigationFactor: 0.1, affectedAttackVectors: ["T1110", "T1499"] },
    { category: "geo_blocking", name: "Geographic IP Blocking", description: "Blocks traffic from specific regions", typicalMitigationFactor: 0.1, affectedAttackVectors: ["T1190"] },
    { category: "vpn_required", name: "VPN / Zero Trust Access", description: "Requires VPN or zero-trust network access", typicalMitigationFactor: 0.35, affectedAttackVectors: ["T1190", "T1133", "T1078"] }
  ];
}
function calculateRiskAdjustment(baseRiskScore, activeControlIds) {
  const catalog = getControlCatalog();
  let cumulativeMitigation = 0;
  for (const controlId of activeControlIds) {
    const control = catalog.find((c) => c.category === controlId || c.name.toLowerCase().includes(controlId.toLowerCase()));
    if (control) {
      const effectiveFactor = (1 - cumulativeMitigation) * control.typicalMitigationFactor;
      cumulativeMitigation += effectiveFactor;
    }
  }
  const reduction = baseRiskScore * cumulativeMitigation;
  const adjustedRiskScore = Math.max(0, Math.round((baseRiskScore - reduction) * 10) / 10);
  return {
    baseRiskScore,
    adjustedRiskScore,
    reduction: Math.round(reduction * 10) / 10,
    reductionPercent: Math.round(cumulativeMitigation * 100),
    activeControls: activeControlIds,
    rationale: `${activeControlIds.length} control(s) applied. Cumulative mitigation: ${Math.round(cumulativeMitigation * 100)}%. Risk reduced from ${baseRiskScore} to ${adjustedRiskScore}.`
  };
}
export {
  DEFAULT_CONTROL_CONFIG,
  assessControls,
  batchAssessControls,
  calculateRiskAdjustment,
  detectControlsFromHeaders,
  detectControlsFromObservations,
  evaluateCompensatingControls,
  getControlCatalog
};
