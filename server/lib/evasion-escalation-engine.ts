/**
 * Evasion Escalation Engine
 * 
 * Detects when scanning tools are blocked (WAF, rate limit, IP ban, CAPTCHA)
 * and progressively escalates evasion profiles to maintain scan coverage.
 * 
 * Escalation levels:
 *   1. Normal     — default rate, no evasion
 *   2. Cautious   — reduced rate, randomized timing
 *   3. Moderate   — WAF-aware encoding, header manipulation
 *   4. Aggressive — chunked transfer, HTTP/2, payload encoding
 *   5. Stealth    — maximum evasion, minimum rate, Tor/proxy rotation
 * 
 * Each escalation includes a cooldown period before the next level can trigger.
 */

import type { EvasionProfile, TargetProfile } from "./context-aware-scanner";

// ─── Types ──────────────────────────────────────────────────────────────────

export type BlockReason = "waf_block" | "rate_limit" | "connection_reset" | "captcha" | "ip_ban" | "manual";

export interface EvasionEscalation {
  currentLevel: number;
  maxLevel: number;
  reason: BlockReason;
  action: string;
  escalatedAt: number;
  cooldownUntil: number;
  history: EscalationEvent[];
  adaptations: EvasionAdaptation[];
}

export interface EscalationEvent {
  level: number;
  reason: BlockReason;
  timestamp: number;
  statusCode?: number;
  toolOutput?: string;
  action: string;
}

export interface EvasionAdaptation {
  type: "rate_reduction" | "encoding_change" | "header_manipulation" | "payload_rotation" | "proxy_switch" | "protocol_change" | "timing_jitter" | "cooldown";
  description: string;
  applied: boolean;
  appliedAt?: number;
}

export interface EscalationResult {
  escalation: EvasionEscalation;
  newEvasionProfile: EvasionProfile | null;
  shouldPause: boolean;
  pauseDurationMs: number;
  recommendations: string[];
}

// ─── Escalation Level Configs ───────────────────────────────────────────────

const ESCALATION_CONFIGS: Record<number, {
  name: string;
  rateLimit: number;
  delayMs: number;
  cooldownMs: number;
  adaptations: EvasionAdaptation[];
  evasionOverrides: Partial<EvasionProfile>;
}> = {
  1: {
    name: "Normal",
    rateLimit: 50,
    delayMs: 100,
    cooldownMs: 0,
    adaptations: [],
    evasionOverrides: {
      randomizeOrder: false,
      userAgentStrategy: "bot",
      chunkedTransfer: false,
      useHttp2: false,
      ipRotation: "none",
    },
  },
  2: {
    name: "Cautious",
    rateLimit: 20,
    delayMs: 500,
    cooldownMs: 30_000,
    adaptations: [
      { type: "rate_reduction", description: "Reduced request rate to 20 req/s", applied: false },
      { type: "timing_jitter", description: "Added random delay jitter (200-800ms)", applied: false },
    ],
    evasionOverrides: {
      randomizeOrder: true,
      userAgentStrategy: "browser_mimic",
      chunkedTransfer: false,
      useHttp2: false,
      ipRotation: "none",
    },
  },
  3: {
    name: "Moderate",
    rateLimit: 8,
    delayMs: 1500,
    cooldownMs: 60_000,
    adaptations: [
      { type: "rate_reduction", description: "Reduced request rate to 8 req/s", applied: false },
      { type: "encoding_change", description: "Enabled URL double-encoding and Unicode normalization", applied: false },
      { type: "header_manipulation", description: "Rotating X-Forwarded-For, X-Real-IP, X-Originating-IP headers", applied: false },
    ],
    evasionOverrides: {
      randomizeOrder: true,
      userAgentStrategy: "browser_mimic",
      encodingTricks: ["double_url_encode", "unicode_normalization", "mixed_case", "null_byte_insertion"],
      headerManipulation: {
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Custom-IP-Authorization": "127.0.0.1",
      },
      chunkedTransfer: false,
      useHttp2: true,
      ipRotation: "none",
    },
  },
  4: {
    name: "Aggressive",
    rateLimit: 3,
    delayMs: 3000,
    cooldownMs: 120_000,
    adaptations: [
      { type: "rate_reduction", description: "Reduced request rate to 3 req/s", applied: false },
      { type: "payload_rotation", description: "Rotating WAF bypass payloads (chunked, encoding, case variation)", applied: false },
      { type: "protocol_change", description: "Switched to HTTP/2 with chunked transfer encoding", applied: false },
      { type: "header_manipulation", description: "Full header rotation with browser fingerprint mimicry", applied: false },
    ],
    evasionOverrides: {
      randomizeOrder: true,
      userAgentStrategy: "browser_mimic",
      encodingTricks: ["double_url_encode", "unicode_normalization", "mixed_case", "null_byte_insertion", "hex_encoding", "overlong_utf8"],
      headerManipulation: {
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Custom-IP-Authorization": "127.0.0.1",
        "Content-Type": "application/x-www-form-urlencoded; charset=ibm037",
        "Transfer-Encoding": "chunked",
      },
      chunkedTransfer: true,
      useHttp2: true,
      ipRotation: "proxy_chain",
    },
  },
  5: {
    name: "Stealth",
    rateLimit: 1,
    delayMs: 8000,
    cooldownMs: 300_000,
    adaptations: [
      { type: "rate_reduction", description: "Minimum rate: 1 req/s with 5-10s jitter", applied: false },
      { type: "proxy_switch", description: "Switched to Tor/proxy chain for IP rotation", applied: false },
      { type: "payload_rotation", description: "Using WAF-specific bypass payloads with full encoding rotation", applied: false },
      { type: "protocol_change", description: "HTTP/2 + chunked + connection keep-alive manipulation", applied: false },
      { type: "cooldown", description: "5-minute cooldown between scan batches", applied: false },
    ],
    evasionOverrides: {
      randomizeOrder: true,
      userAgentStrategy: "browser_mimic",
      encodingTricks: ["double_url_encode", "unicode_normalization", "mixed_case", "null_byte_insertion", "hex_encoding", "overlong_utf8", "json_unicode_escape", "html_entity_encoding"],
      headerManipulation: {
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "X-Originating-IP": "127.0.0.1",
        "X-Custom-IP-Authorization": "127.0.0.1",
        "Content-Type": "application/x-www-form-urlencoded; charset=ibm037",
        "Transfer-Encoding": "chunked",
        "Connection": "keep-alive",
      },
      chunkedTransfer: true,
      useHttp2: true,
      ipRotation: "tor",
    },
  },
};

// ─── Block Detection Heuristics ─────────────────────────────────────────────

const WAF_BLOCK_PATTERNS = [
  /access denied/i,
  /forbidden/i,
  /blocked by/i,
  /web application firewall/i,
  /cloudflare/i,
  /attention required/i,
  /request blocked/i,
  /security violation/i,
  /waf.*block/i,
  /rate.*limit.*exceeded/i,
  /too many requests/i,
  /captcha/i,
  /challenge.*required/i,
  /bot.*detected/i,
  /automated.*request/i,
  /suspicious.*activity/i,
];

export function detectBlockReason(statusCode: number, responseBody?: string): BlockReason | null {
  if (statusCode === 429) return "rate_limit";
  if (statusCode === 403) {
    if (responseBody) {
      if (/captcha|challenge.*required|hcaptcha|recaptcha/i.test(responseBody)) return "captcha";
      if (WAF_BLOCK_PATTERNS.some(p => p.test(responseBody))) return "waf_block";
    }
    return "waf_block";
  }
  if (statusCode === 503 && responseBody && /cloudflare|ddos.*protection/i.test(responseBody)) return "waf_block";
  if (statusCode === 0 || statusCode === -1) return "connection_reset";
  return null;
}

// ─── Escalation Engine ──────────────────────────────────────────────────────

export function escalateEvasionProfile(
  targetProfile: TargetProfile,
  reason: BlockReason,
  context?: { statusCode?: number; toolOutput?: string }
): EscalationResult {
  const existing = (targetProfile as any).evasionEscalation as EvasionEscalation | undefined;
  const currentLevel = existing?.currentLevel || 1;
  const history = existing?.history || [];

  // Check cooldown
  if (existing?.cooldownUntil && Date.now() < existing.cooldownUntil) {
    return {
      escalation: existing,
      newEvasionProfile: null,
      shouldPause: true,
      pauseDurationMs: existing.cooldownUntil - Date.now(),
      recommendations: [`Cooldown active until ${new Date(existing.cooldownUntil).toISOString()} — wait before retrying`],
    };
  }

  // Calculate next level
  const nextLevel = Math.min(currentLevel + 1, 5);
  const config = ESCALATION_CONFIGS[nextLevel];

  // Build escalation event
  const event: EscalationEvent = {
    level: nextLevel,
    reason,
    timestamp: Date.now(),
    statusCode: context?.statusCode,
    toolOutput: context?.toolOutput?.substring(0, 500),
    action: `Escalated to Level ${nextLevel} (${config.name}): ${getActionDescription(reason, nextLevel)}`,
  };

  // Mark adaptations as applied
  const adaptations = config.adaptations.map(a => ({
    ...a,
    applied: true,
    appliedAt: Date.now(),
  }));

  // Build new evasion profile
  const baseProfile = targetProfile.recommendedStrategy?.evasionProfile;
  const newProfile: EvasionProfile = {
    name: `escalated_${config.name.toLowerCase()}`,
    rateLimit: config.rateLimit,
    delayMs: config.delayMs,
    randomizeOrder: config.evasionOverrides.randomizeOrder ?? baseProfile?.randomizeOrder ?? true,
    userAgentStrategy: config.evasionOverrides.userAgentStrategy ?? baseProfile?.userAgentStrategy ?? "browser_mimic",
    httpMethodPreferences: baseProfile?.httpMethodPreferences || ["GET", "POST"],
    encodingTricks: config.evasionOverrides.encodingTricks ?? baseProfile?.encodingTricks ?? [],
    headerManipulation: config.evasionOverrides.headerManipulation ?? baseProfile?.headerManipulation ?? {},
    chunkedTransfer: config.evasionOverrides.chunkedTransfer ?? baseProfile?.chunkedTransfer ?? false,
    useHttp2: config.evasionOverrides.useHttp2 ?? baseProfile?.useHttp2 ?? false,
    ipRotation: config.evasionOverrides.ipRotation ?? baseProfile?.ipRotation ?? "none",
    wafBypassPayloads: baseProfile?.wafBypassPayloads || [],
  };

  // Build recommendations
  const recommendations = getRecommendations(reason, nextLevel, targetProfile);

  const escalation: EvasionEscalation = {
    currentLevel: nextLevel,
    maxLevel: 5,
    reason,
    action: event.action,
    escalatedAt: Date.now(),
    cooldownUntil: Date.now() + config.cooldownMs,
    history: [...history, event],
    adaptations,
  };

  return {
    escalation,
    newEvasionProfile: newProfile,
    shouldPause: nextLevel >= 4,
    pauseDurationMs: nextLevel >= 4 ? config.cooldownMs : 0,
    recommendations,
  };
}

// ─── Auto-detect and escalate from tool output ──────────────────────────────

export function analyzeToolOutputForBlocking(
  toolOutput: string,
  exitCode: number
): { isBlocked: boolean; reason: BlockReason | null; confidence: number; indicators: string[] } {
  const indicators: string[] = [];
  let confidence = 0;

  // Check for WAF block patterns
  for (const pattern of WAF_BLOCK_PATTERNS) {
    if (pattern.test(toolOutput)) {
      indicators.push(`Matched WAF pattern: ${pattern.source}`);
      confidence += 25;
    }
  }

  // Check for rate limiting indicators
  if (/429|too many|rate.?limit/i.test(toolOutput)) {
    indicators.push("Rate limiting detected (429/too many requests)");
    confidence += 40;
  }

  // Check for connection issues
  if (/connection.*reset|ECONNRESET|ETIMEDOUT|connection.*refused/i.test(toolOutput)) {
    indicators.push("Connection reset/timeout detected");
    confidence += 30;
  }

  // Check for CAPTCHA
  if (/captcha|hcaptcha|recaptcha|challenge/i.test(toolOutput)) {
    indicators.push("CAPTCHA/challenge detected");
    confidence += 50;
  }

  // Check exit code
  if (exitCode !== 0 && confidence > 0) {
    indicators.push(`Non-zero exit code: ${exitCode}`);
    confidence += 10;
  }

  // Check for high error ratios in output
  const errorLines = toolOutput.split("\n").filter(l => /error|fail|block|denied|timeout/i.test(l)).length;
  const totalLines = toolOutput.split("\n").length;
  if (totalLines > 5 && errorLines / totalLines > 0.5) {
    indicators.push(`High error ratio: ${errorLines}/${totalLines} lines`);
    confidence += 20;
  }

  confidence = Math.min(confidence, 100);
  const isBlocked = confidence >= 40;

  let reason: BlockReason | null = null;
  if (isBlocked) {
    if (/captcha|hcaptcha|recaptcha/i.test(toolOutput)) reason = "captcha";
    else if (/429|rate.?limit|too many/i.test(toolOutput)) reason = "rate_limit";
    else if (/connection.*reset|ECONNRESET/i.test(toolOutput)) reason = "connection_reset";
    else if (/ip.*ban|blacklist|blocklist/i.test(toolOutput)) reason = "ip_ban";
    else reason = "waf_block";
  }

  return { isBlocked, reason, confidence, indicators };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function getActionDescription(reason: BlockReason, level: number): string {
  const actions: Record<BlockReason, Record<number, string>> = {
    waf_block: {
      2: "Reduced rate and added browser-like User-Agent",
      3: "Enabled URL encoding tricks and header spoofing",
      4: "Activated chunked transfer and payload rotation",
      5: "Maximum stealth: Tor routing, minimum rate, full encoding rotation",
    },
    rate_limit: {
      2: "Reduced rate to 20 req/s with timing jitter",
      3: "Reduced rate to 8 req/s with randomized delays",
      4: "Reduced rate to 3 req/s with proxy rotation",
      5: "Minimum rate (1 req/s) with 5-minute cooldown batches",
    },
    connection_reset: {
      2: "Added connection retry with backoff",
      3: "Switched to HTTP/2 with keep-alive",
      4: "Enabled proxy chain for connection diversity",
      5: "Tor routing with maximum connection resilience",
    },
    captcha: {
      2: "Reduced rate to appear more human-like",
      3: "Browser mimicry with realistic timing patterns",
      4: "Proxy rotation to avoid IP-based CAPTCHA triggers",
      5: "Maximum stealth with Tor and extended cooldowns",
    },
    ip_ban: {
      2: "Reduced rate to avoid further bans",
      3: "Enabled proxy chain for IP rotation",
      4: "Switched to proxy chain with header spoofing",
      5: "Tor routing with full identity rotation",
    },
    manual: {
      2: "Manual escalation to cautious mode",
      3: "Manual escalation to moderate evasion",
      4: "Manual escalation to aggressive evasion",
      5: "Manual escalation to maximum stealth",
    },
  };
  return actions[reason]?.[level] || `Escalated evasion to level ${level}`;
}

function getRecommendations(reason: BlockReason, level: number, profile: TargetProfile): string[] {
  const recs: string[] = [];

  if (level >= 3 && profile.waf.detected) {
    recs.push(`WAF vendor "${profile.waf.vendor}" detected — consider using vendor-specific bypass payloads`);
    if (profile.waf.bypassTechniques.length > 0) {
      recs.push(`Available bypass techniques: ${profile.waf.bypassTechniques.slice(0, 3).join(", ")}`);
    }
  }

  if (level >= 4) {
    recs.push("Consider pausing automated scanning and switching to manual testing");
    recs.push("Review scope authorization — aggressive evasion may trigger incident response");
  }

  if (level >= 5) {
    recs.push("Maximum evasion reached — further scanning may be counterproductive");
    recs.push("Consider requesting expanded scope or alternative testing approach from client");
  }

  if (reason === "captcha") {
    recs.push("CAPTCHA detected — automated scanning may not be effective for this target");
    recs.push("Consider manual browser-based testing for CAPTCHA-protected endpoints");
  }

  if (reason === "ip_ban") {
    recs.push("IP ban detected — wait before retrying or use a different source IP");
  }

  if (profile.cdn.detected) {
    recs.push(`CDN "${profile.cdn.provider}" detected — consider testing origin IP directly if authorized`);
  }

  return recs;
}
