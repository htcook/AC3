/**
 * Training Lab RoE (Rules of Engagement) Enforcement Guard
 * 
 * Enforces boundaries defined in each training target's RoE before
 * and during scan execution. Prevents the platform from violating
 * any target's terms of use.
 * 
 * Author: Harrison Cook / AceofCloud
 */

import type { TrainingTarget, TrainingTargetRoE } from "../routers/training-lab";

// ─── Types ───────────────────────────────────────────────────────────

export interface RoEViolation {
  rule: string;
  severity: "block" | "warn";
  message: string;
}

export interface RoECheckResult {
  allowed: boolean;
  violations: RoEViolation[];
  warnings: RoEViolation[];
  enforcedRules: string[];
  targetName: string;
  provider: string;
}

export interface ScanRequest {
  targetId: string;
  scanProfile: "quick" | "standard" | "deep";
  enableBruteForce?: boolean;
  enableCredentialStuffing?: boolean;
  enableDoS?: boolean;
  enableExfiltration?: boolean;
  customNmapFlags?: string;
  customNucleiTemplates?: string[];
}

// ─── Rate Limit Tracker ──────────────────────────────────────────────

const scanCountMap = new Map<string, { count: number; resetAt: number }>();

function getScanCountToday(targetId: string): number {
  const now = Date.now();
  const entry = scanCountMap.get(targetId);
  if (!entry || now > entry.resetAt) {
    return 0;
  }
  return entry.count;
}

function incrementScanCount(targetId: string): void {
  const now = Date.now();
  const entry = scanCountMap.get(targetId);
  const midnight = new Date();
  midnight.setHours(23, 59, 59, 999);
  const resetAt = midnight.getTime();

  if (!entry || now > entry.resetAt) {
    scanCountMap.set(targetId, { count: 1, resetAt });
  } else {
    entry.count++;
  }
}

// ─── Enforcement Functions ───────────────────────────────────────────

/**
 * Pre-scan RoE check. Validates that the requested scan does not
 * violate any of the target's rules of engagement.
 * Returns { allowed: true } if the scan can proceed, or
 * { allowed: false, violations: [...] } if it must be blocked.
 */
export function enforceTrainingRoE(
  target: TrainingTarget,
  request: ScanRequest
): RoECheckResult {
  const roe = target.roe;
  const violations: RoEViolation[] = [];
  const warnings: RoEViolation[] = [];
  const enforcedRules: string[] = [];

  // ── Rule 1: Brute-force prohibition ──
  if (roe.noBruteForce) {
    enforcedRules.push("No brute-force attacks");
    if (request.enableBruteForce || request.enableCredentialStuffing) {
      violations.push({
        rule: "noBruteForce",
        severity: "block",
        message: `${target.name} (${roe.provider}) explicitly prohibits brute-force and credential attacks. Disable brute-force/credential stuffing before scanning.`,
      });
    }
    // Also check for brute-force nuclei templates
    if (request.customNucleiTemplates?.some(t =>
      t.includes("brute") || t.includes("credential") || t.includes("password")
    )) {
      violations.push({
        rule: "noBruteForce",
        severity: "block",
        message: `Nuclei templates containing brute-force/credential attacks are prohibited for ${target.name}.`,
      });
    }
  }

  // ── Rule 2: DoS prohibition ──
  if (roe.noDoS) {
    enforcedRules.push("No DoS/DDoS attacks");
    if (request.enableDoS) {
      violations.push({
        rule: "noDoS",
        severity: "block",
        message: `${target.name} (${roe.provider}) prohibits denial-of-service attacks. Disable DoS testing before scanning.`,
      });
    }
    // Deep scans with aggressive timing can be DoS-like
    if (request.scanProfile === "deep" && request.customNmapFlags?.includes("-T5")) {
      warnings.push({
        rule: "noDoS",
        severity: "warn",
        message: `Deep scan with aggressive timing (-T5) may overwhelm ${target.name}. Consider using -T3 or -T4 to respect their infrastructure.`,
      });
    }
  }

  // ── Rule 3: Exfiltration prohibition ──
  if (roe.noExfiltration) {
    enforcedRules.push("No data exfiltration");
    if (request.enableExfiltration) {
      violations.push({
        rule: "noExfiltration",
        severity: "block",
        message: `${target.name} (${roe.provider}) prohibits data exfiltration. Disable exfiltration testing before scanning.`,
      });
    }
  }

  // ── Rule 4: Rate limit enforcement ──
  if (roe.maxScansPerDay !== null) {
    enforcedRules.push(`Max ${roe.maxScansPerDay} scans/day`);
    const todayCount = getScanCountToday(target.id);
    if (todayCount >= roe.maxScansPerDay) {
      violations.push({
        rule: "maxScansPerDay",
        severity: "block",
        message: `Rate limit exceeded for ${target.name}: ${todayCount}/${roe.maxScansPerDay} scans today. ${roe.rateLimit || "Try again tomorrow."}`,
      });
    } else if (todayCount >= roe.maxScansPerDay - 2) {
      warnings.push({
        rule: "maxScansPerDay",
        severity: "warn",
        message: `Approaching rate limit for ${target.name}: ${todayCount}/${roe.maxScansPerDay} scans today.`,
      });
    }
  }

  // ── Rule 5: Requires own instance ──
  if (roe.requiresOwnInstance) {
    enforcedRules.push("Requires own sandboxed instance");
    warnings.push({
      rule: "requiresOwnInstance",
      severity: "warn",
      message: `${target.name} requires you to use your own sandboxed instance. ${roe.notes || "Ensure you are scanning your own instance, not the shared/main domain."}`,
    });
  }

  // ── Rule 6: Custom target warning ──
  if (target.id === "custom") {
    warnings.push({
      rule: "customTarget",
      severity: "warn",
      message: "Custom target: YOU must ensure you have written authorization (ROE) before scanning. Scanning without authorization is illegal.",
    });
  }

  // ── Rule 7: Nmap flags sanitization for restricted targets ──
  if (roe.noBruteForce && request.customNmapFlags) {
    const dangerousFlags = ["--script=brute", "--script brute", "ssh-brute", "http-brute", "ftp-brute"];
    for (const flag of dangerousFlags) {
      if (request.customNmapFlags.includes(flag)) {
        violations.push({
          rule: "noBruteForce",
          severity: "block",
          message: `Nmap brute-force script "${flag}" is prohibited for ${target.name}.`,
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
    provider: roe.provider,
  };
}

/**
 * Records a scan launch for rate-limiting purposes.
 * Call this AFTER the RoE check passes and the scan is about to start.
 */
export function recordScanLaunch(targetId: string): void {
  incrementScanCount(targetId);
}

/**
 * Sanitizes nmap flags based on target RoE.
 * Removes prohibited flags and returns the cleaned version.
 */
export function sanitizeNmapFlags(flags: string, roe: TrainingTargetRoE): string {
  let sanitized = flags;

  if (roe.noBruteForce) {
    // Remove brute-force scripts
    sanitized = sanitized.replace(/--script[= ]?[^\s]*brute[^\s]*/gi, "");
    sanitized = sanitized.replace(/--script[= ]?[^\s]*password[^\s]*/gi, "");
    sanitized = sanitized.replace(/--script[= ]?[^\s]*credential[^\s]*/gi, "");
  }

  if (roe.noDoS) {
    // Downgrade aggressive timing
    sanitized = sanitized.replace(/-T5/g, "-T3");
  }

  return sanitized.replace(/\s+/g, " ").trim();
}

/**
 * Filters nuclei templates based on target RoE.
 * Removes templates that would violate the target's rules.
 */
export function filterNucleiTemplates(
  templates: string[],
  roe: TrainingTargetRoE
): { allowed: string[]; blocked: string[] } {
  const allowed: string[] = [];
  const blocked: string[] = [];

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

/**
 * Returns a human-readable summary of the RoE for display in the UI.
 */
export function formatRoESummary(target: TrainingTarget): string {
  const roe = target.roe;
  const lines: string[] = [];

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
    lines.push(`⚠ Requires Own Instance: Yes`);
  }
  if (roe.notes) {
    lines.push(`Notes: ${roe.notes}`);
  }
  if (roe.termsUrl) {
    lines.push(`Terms URL: ${roe.termsUrl}`);
  }

  return lines.join("\n");
}
