import "./chunk-KFQGP6VL.js";

// server/lib/training-roe-guard.ts
var scanCountMap = /* @__PURE__ */ new Map();
function getScanCountToday(targetId) {
  const now = Date.now();
  const entry = scanCountMap.get(targetId);
  if (!entry || now > entry.resetAt) {
    return 0;
  }
  return entry.count;
}
function incrementScanCount(targetId) {
  const now = Date.now();
  const entry = scanCountMap.get(targetId);
  const midnight = /* @__PURE__ */ new Date();
  midnight.setHours(23, 59, 59, 999);
  const resetAt = midnight.getTime();
  if (!entry || now > entry.resetAt) {
    scanCountMap.set(targetId, { count: 1, resetAt });
  } else {
    entry.count++;
  }
}
function enforceTrainingRoE(target, request) {
  const roe = target.roe;
  const violations = [];
  const warnings = [];
  const enforcedRules = [];
  if (roe.noBruteForce) {
    enforcedRules.push("No brute-force attacks");
    if (request.enableBruteForce || request.enableCredentialStuffing) {
      violations.push({
        rule: "noBruteForce",
        severity: "block",
        message: `${target.name} (${roe.provider}) explicitly prohibits brute-force and credential attacks. Disable brute-force/credential stuffing before scanning.`
      });
    }
    if (request.customNucleiTemplates?.some(
      (t) => t.includes("brute") || t.includes("credential") || t.includes("password")
    )) {
      violations.push({
        rule: "noBruteForce",
        severity: "block",
        message: `Nuclei templates containing brute-force/credential attacks are prohibited for ${target.name}.`
      });
    }
  }
  if (roe.noDoS) {
    enforcedRules.push("No DoS/DDoS attacks");
    if (request.enableDoS) {
      violations.push({
        rule: "noDoS",
        severity: "block",
        message: `${target.name} (${roe.provider}) prohibits denial-of-service attacks. Disable DoS testing before scanning.`
      });
    }
    if (request.scanProfile === "deep" && request.customScanForgeFlags?.includes("-T5")) {
      warnings.push({
        rule: "noDoS",
        severity: "warn",
        message: `Deep scan with aggressive timing (-T5) may overwhelm ${target.name}. Consider using -T3 or -T4 to respect their infrastructure.`
      });
    }
  }
  if (roe.noExfiltration) {
    enforcedRules.push("No data exfiltration");
    if (request.enableExfiltration) {
      violations.push({
        rule: "noExfiltration",
        severity: "block",
        message: `${target.name} (${roe.provider}) prohibits data exfiltration. Disable exfiltration testing before scanning.`
      });
    }
  }
  if (roe.maxScansPerDay !== null) {
    enforcedRules.push(`Max ${roe.maxScansPerDay} scans/day`);
    const todayCount = getScanCountToday(target.id);
    if (todayCount >= roe.maxScansPerDay) {
      violations.push({
        rule: "maxScansPerDay",
        severity: "block",
        message: `Rate limit exceeded for ${target.name}: ${todayCount}/${roe.maxScansPerDay} scans today. ${roe.rateLimit || "Try again tomorrow."}`
      });
    } else if (todayCount >= roe.maxScansPerDay - 2) {
      warnings.push({
        rule: "maxScansPerDay",
        severity: "warn",
        message: `Approaching rate limit for ${target.name}: ${todayCount}/${roe.maxScansPerDay} scans today.`
      });
    }
  }
  if (roe.requiresOwnInstance) {
    enforcedRules.push("Requires own sandboxed instance");
    warnings.push({
      rule: "requiresOwnInstance",
      severity: "warn",
      message: `${target.name} requires you to use your own sandboxed instance. ${roe.notes || "Ensure you are scanning your own instance, not the shared/main domain."}`
    });
  }
  if (target.id === "custom") {
    warnings.push({
      rule: "customTarget",
      severity: "warn",
      message: "Custom target: YOU must ensure you have written authorization (ROE) before scanning. Scanning without authorization is illegal."
    });
  }
  if (roe.noBruteForce && request.customScanForgeFlags) {
    const dangerousFlags = ["--script=brute", "--script brute", "ssh-brute", "http-brute", "ftp-brute"];
    for (const flag of dangerousFlags) {
      if (request.customScanForgeFlags.includes(flag)) {
        violations.push({
          rule: "noBruteForce",
          severity: "block",
          message: `ScanForge brute-force script "${flag}" is prohibited for ${target.name}.`
        });
      }
    }
  }
  const allowed = violations.length === 0;
  return {
    allowed,
    violations,
    warnings,
    enforcedRules,
    targetName: target.name,
    provider: roe.provider
  };
}
function recordScanLaunch(targetId) {
  incrementScanCount(targetId);
}
function sanitizeScanForgeFlags(flags, roe) {
  let sanitized = flags;
  if (roe.noBruteForce) {
    sanitized = sanitized.replace(/--script[= ]?[^\s]*brute[^\s]*/gi, "");
    sanitized = sanitized.replace(/--script[= ]?[^\s]*password[^\s]*/gi, "");
    sanitized = sanitized.replace(/--script[= ]?[^\s]*credential[^\s]*/gi, "");
  }
  if (roe.noDoS) {
    sanitized = sanitized.replace(/-T5/g, "-T3");
  }
  return sanitized.replace(/\s+/g, " ").trim();
}
function filterNucleiTemplates(templates, roe) {
  const allowed = [];
  const blocked = [];
  for (const template of templates) {
    const lower = template.toLowerCase();
    let isBlocked = false;
    if (roe.noBruteForce && (lower.includes("brute") || lower.includes("credential") || lower.includes("password-spray"))) {
      isBlocked = true;
    }
    if (roe.noDoS && (lower.includes("dos") || lower.includes("flood") || lower.includes("slowloris"))) {
      isBlocked = true;
    }
    if (isBlocked) {
      blocked.push(template);
    } else {
      allowed.push(template);
    }
  }
  return { allowed, blocked };
}
function formatRoESummary(target) {
  const roe = target.roe;
  const lines = [];
  lines.push(`Provider: ${roe.provider}`);
  lines.push(`Summary: ${roe.summary}`);
  if (roe.allowed.length > 0) {
    lines.push(`Allowed: ${roe.allowed.join(", ")}`);
  }
  if (roe.prohibited.length > 0) {
    lines.push(`Prohibited: ${roe.prohibited.join(", ")}`);
  }
  if (roe.rateLimit) {
    lines.push(`Rate Limit: ${roe.rateLimit}`);
  }
  if (roe.maxScansPerDay !== null) {
    lines.push(`Max Scans/Day: ${roe.maxScansPerDay}`);
  }
  if (roe.requiresOwnInstance) {
    lines.push(`\u26A0 Requires Own Instance: Yes`);
  }
  if (roe.notes) {
    lines.push(`Notes: ${roe.notes}`);
  }
  if (roe.termsUrl) {
    lines.push(`Terms URL: ${roe.termsUrl}`);
  }
  return lines.join("\n");
}
export {
  enforceTrainingRoE,
  filterNucleiTemplates,
  formatRoESummary,
  recordScanLaunch,
  sanitizeScanForgeFlags
};
