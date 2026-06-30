/**
 * LLM Resilience Layer
 * ────────────────────
 * Production hardening for all LLM-powered analysis:
 * - Retry logic with exponential backoff
 * - Timeout enforcement via AbortController
 * - Response schema validation
 * - Partial success handling (merge valid fields with defaults)
 * - Structured fallback generation when LLM is completely unavailable
 * - Token budget estimation to prevent oversized prompts
 * - Call auditing for debugging and cost tracking
 */

// ─── Configuration ───────────────────────────────────────────────────

export interface LLMCallConfig {
  /** Maximum number of retry attempts (default: 3) */
  maxRetries?: number;
  /** Base delay between retries in ms (default: 1000, doubles each retry) */
  retryBaseDelayMs?: number;
  /** Maximum timeout for a single LLM call in ms (default: 60000) */
  timeoutMs?: number;
  /** Name of the calling module for audit trail */
  callerModule?: string;
  /** Whether to use structured fallback on failure (default: true) */
  useFallback?: boolean;
}

const DEFAULT_CONFIG: Required<LLMCallConfig> = {
  maxRetries: 3,
  retryBaseDelayMs: 1000,
  timeoutMs: 60000,
  callerModule: "unknown",
  useFallback: true,
};

// ─── Audit Trail ─────────────────────────────────────────────────────

export interface LLMCallAudit {
  callerModule: string;
  startedAt: number;
  completedAt: number;
  durationMs: number;
  attempts: number;
  success: boolean;
  usedFallback: boolean;
  errors: string[];
  promptTokenEstimate: number;
  responseTokenEstimate: number;
}

const recentAudits: LLMCallAudit[] = [];
const MAX_AUDIT_HISTORY = 100;

export function getRecentLLMAudits(): LLMCallAudit[] {
  return [...recentAudits];
}

export function getLLMHealthSummary(): {
  totalCalls: number;
  successRate: number;
  fallbackRate: number;
  avgDurationMs: number;
  recentErrors: string[];
} {
  if (recentAudits.length === 0) {
    return { totalCalls: 0, successRate: 1, fallbackRate: 0, avgDurationMs: 0, recentErrors: [] };
  }
  const total = recentAudits.length;
  const successes = recentAudits.filter(a => a.success).length;
  const fallbacks = recentAudits.filter(a => a.usedFallback).length;
  const avgDuration = recentAudits.reduce((s, a) => s + a.durationMs, 0) / total;
  const recentErrors = recentAudits
    .filter(a => !a.success)
    .flatMap(a => a.errors)
    .slice(-10);

  return {
    totalCalls: total,
    successRate: successes / total,
    fallbackRate: fallbacks / total,
    avgDurationMs: Math.round(avgDuration),
    recentErrors,
  };
}

// ─── Token Estimation ────────────────────────────────────────────────

/** Rough token count estimation (4 chars ≈ 1 token for English text) */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/** Check if a prompt is within safe token limits */
export function isPromptWithinBudget(prompt: string, maxTokens: number = 12000): boolean {
  return estimateTokens(prompt) <= maxTokens;
}

/** Truncate prompt to fit within token budget while preserving structure */
export function truncatePromptToBudget(prompt: string, maxTokens: number = 12000): string {
  const currentTokens = estimateTokens(prompt);
  if (currentTokens <= maxTokens) return prompt;

  const targetChars = maxTokens * 4;
  // Try to truncate at a section boundary
  const truncated = prompt.substring(0, targetChars);
  const lastNewline = truncated.lastIndexOf("\n\n");
  if (lastNewline > targetChars * 0.7) {
    return truncated.substring(0, lastNewline) + "\n\n[Content truncated to fit token budget]";
  }
  return truncated + "\n\n[Content truncated to fit token budget]";
}

// ─── Retry with Exponential Backoff ──────────────────────────────────

/**
 * Execute an LLM call with retry logic and timeout enforcement.
 * Returns the parsed response or throws after all retries are exhausted.
 */
export async function resilientLLMCall<T>(
  callFn: () => Promise<T>,
  config?: LLMCallConfig,
): Promise<{ result: T; audit: LLMCallAudit }> {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const startedAt = Date.now();
  const errors: string[] = [];
  let attempts = 0;

  for (let attempt = 0; attempt <= cfg.maxRetries; attempt++) {
    attempts = attempt + 1;

    try {
      // Timeout enforcement
      const result = await Promise.race([
        callFn(),
        new Promise<never>((_, reject) => {
          setTimeout(() => reject(new Error(`LLM call timed out after ${cfg.timeoutMs}ms`)), cfg.timeoutMs);
        }),
      ]);

      const completedAt = Date.now();
      const audit: LLMCallAudit = {
        callerModule: cfg.callerModule,
        startedAt,
        completedAt,
        durationMs: completedAt - startedAt,
        attempts,
        success: true,
        usedFallback: false,
        errors,
        promptTokenEstimate: 0,
        responseTokenEstimate: 0,
      };

      recordAudit(audit);
      return { result, audit };
    } catch (err: any) {
      const errorMsg = err?.message || String(err);
      errors.push(`Attempt ${attempt + 1}: ${errorMsg}`);
      console.warn(`[LLMResilience] ${cfg.callerModule} attempt ${attempt + 1}/${cfg.maxRetries + 1} failed: ${errorMsg}`);

      // Don't retry on certain errors
      if (isNonRetryableError(errorMsg)) {
        console.error(`[LLMResilience] Non-retryable error, stopping retries: ${errorMsg}`);
        break;
      }

      // Exponential backoff before retry
      if (attempt < cfg.maxRetries) {
        const delay = cfg.retryBaseDelayMs * Math.pow(2, attempt);
        const jitter = Math.random() * delay * 0.3;
        await sleep(delay + jitter);
      }
    }
  }

  // All retries exhausted
  const completedAt = Date.now();
  const audit: LLMCallAudit = {
    callerModule: cfg.callerModule,
    startedAt,
    completedAt,
    durationMs: completedAt - startedAt,
    attempts,
    success: false,
    usedFallback: true,
    errors,
    promptTokenEstimate: 0,
    responseTokenEstimate: 0,
  };

  recordAudit(audit);
  throw new LLMExhaustedError(
    `LLM call failed after ${attempts} attempts: ${errors.join("; ")}`,
    audit,
  );
}

function isNonRetryableError(msg: string): boolean {
  const nonRetryable = [
    "invalid_api_key",
    "authentication_error",
    "insufficient_quota",
    "model_not_found",
    "invalid_request",
    "content_policy_violation",
  ];
  const lower = msg.toLowerCase();
  return nonRetryable.some(e => lower.includes(e));
}

function recordAudit(audit: LLMCallAudit): void {
  recentAudits.push(audit);
  if (recentAudits.length > MAX_AUDIT_HISTORY) {
    recentAudits.shift();
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export class LLMExhaustedError extends Error {
  audit: LLMCallAudit;
  constructor(message: string, audit: LLMCallAudit) {
    super(message);
    this.name = "LLMExhaustedError";
    this.audit = audit;
  }
}

// ─── Response Validation ─────────────────────────────────────────────

/**
 * Validate and repair an LLM JSON response against expected fields.
 * Returns the validated object with missing fields filled from defaults.
 */
export function validateAndRepairResponse<T extends Record<string, any>>(
  raw: any,
  defaults: T,
  fieldValidators?: Partial<Record<keyof T, (val: any) => boolean>>,
): { result: T; repaired: string[] } {
  const repaired: string[] = [];

  if (!raw || typeof raw !== "object") {
    repaired.push("Entire response was invalid, using defaults");
    return { result: { ...defaults }, repaired };
  }

  const result = { ...defaults } as any;

  for (const [key, defaultVal] of Object.entries(defaults)) {
    if (key in raw && raw[key] !== undefined && raw[key] !== null) {
      // Check type match
      if (typeof raw[key] === typeof defaultVal || (Array.isArray(defaultVal) && Array.isArray(raw[key]))) {
        // Run custom validator if provided
        if (fieldValidators?.[key as keyof T]) {
          if (fieldValidators[key as keyof T]!(raw[key])) {
            result[key] = raw[key];
          } else {
            repaired.push(`${key}: failed validation, using default`);
          }
        } else {
          result[key] = raw[key];
        }
      } else {
        repaired.push(`${key}: type mismatch (expected ${typeof defaultVal}, got ${typeof raw[key]})`);
      }
    } else {
      repaired.push(`${key}: missing, using default`);
    }
  }

  return { result: result as T, repaired };
}

// ─── Structured Fallback Generators ──────────────────────────────────

/**
 * Generate a deterministic post-enrichment analysis fallback
 * when the LLM is completely unavailable.
 */
export function generateDeterministicAnalysisFallback(context: {
  totalAssets: number;
  confirmedFindings: number;
  probableFindings: number;
  criticalAssets: number;
  highRiskAssets: number;
  technologies: string[];
  hasBreachData: boolean;
}): {
  attackPaths: any[];
  blindSpots: any[];
  prioritizedRecommendations: any[];
  crossFindingCorrelations: any[];
  threatActorMapping: any[];
  overallAssessment: string;
  confidenceStatement: string;
} {
  const blindSpots: any[] = [];
  const recommendations: any[] = [];
  let rank = 1;

  // Generate blind spots based on what we know is missing
  blindSpots.push({
    area: "Internal Network Assessment",
    description: "External-only scan cannot assess internal network segmentation, lateral movement paths, or internal service exposure.",
    suggestedAction: "Conduct internal penetration test or deploy network sensors for internal visibility.",
    severity: "high",
  });

  if (!context.hasBreachData) {
    blindSpots.push({
      area: "Credential Exposure",
      description: "No breach data sources were available to check for exposed credentials.",
      suggestedAction: "Check Have I Been Pwned, DeHashed, or similar services for credential exposure.",
      severity: "medium",
    });
  }

  blindSpots.push({
    area: "Social Engineering Surface",
    description: "Technical scanning cannot assess susceptibility to phishing, vishing, or pretexting attacks.",
    suggestedAction: "Conduct social engineering assessment with GoPhish or similar tools.",
    severity: "medium",
  });

  // Generate recommendations based on findings
  if (context.confirmedFindings > 0) {
    recommendations.push({
      rank: rank++,
      title: "Remediate Confirmed Vulnerabilities",
      description: `${context.confirmedFindings} confirmed vulnerabilities were identified. Prioritize those on critical assets.`,
      affectedAssets: [],
      effort: context.confirmedFindings > 20 ? "medium_term" : "short_term",
      impact: "critical",
      category: "Vulnerability Management",
    });
  }

  if (context.highRiskAssets > 0) {
    recommendations.push({
      rank: rank++,
      title: "Harden High-Risk Assets",
      description: `${context.highRiskAssets} assets scored as high or critical risk. Review their exposure and apply defense-in-depth.`,
      affectedAssets: [],
      effort: "short_term",
      impact: "high",
      category: "Asset Hardening",
    });
  }

  // Technology-based recommendations
  const techLower = context.technologies.map(t => t.toLowerCase());
  if (techLower.some(t => t.includes("wordpress") || t.includes("drupal") || t.includes("joomla"))) {
    recommendations.push({
      rank: rank++,
      title: "CMS Security Audit",
      description: "Content management systems detected. Ensure plugins are updated, admin panels are protected, and WAF rules are in place.",
      affectedAssets: [],
      effort: "quick_win",
      impact: "medium",
      category: "Application Security",
    });
  }

  if (techLower.some(t => t.includes("apache") || t.includes("nginx") || t.includes("iis"))) {
    recommendations.push({
      rank: rank++,
      title: "Web Server Hardening",
      description: "Review web server configurations for security headers, TLS settings, and directory listing exposure.",
      affectedAssets: [],
      effort: "quick_win",
      impact: "medium",
      category: "Infrastructure Hardening",
    });
  }

  // Always recommend monitoring
  recommendations.push({
    rank: rank++,
    title: "Continuous Monitoring",
    description: "Set up OSINT monitoring for the domain to detect infrastructure changes, new subdomains, and certificate transparency logs.",
    affectedAssets: [],
    effort: "short_term",
    impact: "medium",
    category: "Continuous Security",
  });

  const riskLevel = context.highRiskAssets > 5 ? "elevated" :
    context.confirmedFindings > 10 ? "moderate" : "baseline";

  return {
    attackPaths: [],
    blindSpots,
    prioritizedRecommendations: recommendations,
    crossFindingCorrelations: [],
    threatActorMapping: [],
    overallAssessment: `Deterministic analysis of ${context.totalAssets} assets: ${context.confirmedFindings} confirmed findings, ${context.probableFindings} probable findings, ${context.highRiskAssets} high-risk assets. Overall risk posture: ${riskLevel}. LLM-powered analysis was unavailable — this is a rule-based fallback. For attack path analysis and threat actor mapping, retry when LLM service is available.`,
    confidenceStatement: `Low confidence — deterministic fallback analysis. ${context.confirmedFindings} findings are verified through multi-source corroboration. Attack path analysis and threat actor mapping require LLM capability.`,
  };
}
