/**
 * SSIL Scan Policy Engine
 * 
 * Centralised policy enforcement for all scanner execution. Loads YAML-defined
 * scan mode profiles (strict_passive, balanced, aggressive_internal) and
 * escalation rules. Every scanner must call canExecute() before probing a target.
 *
 * Implements SSIL controls SP-01 through SP-05 from strict-passive-profile.yaml.
 *
 * Author: Harrison Cook — AceofCloud
 */

import * as crypto from "crypto";

// ─── Types ──────────────────────────────────────────────────────────────────

export type ScanMode = "passive" | "active-low" | "active-standard" | "active-aggressive";

export type ScannerName =
  | "nuclei"
  | "zgrab2"
  | "zap"
  | "discovery_orchestrated"
  | "custom_dns"
  | "custom_tls"
  | "custom_http_headers"
  | "vuln_scanner"
  | "domain_intel"
  | "protocol_scanner"
  | "web_crawler";

export interface RateLimits {
  perHostRps: number;
  perDomainConcurrent: number;
  globalConcurrent: number;
  jitterMsRange?: [number, number];
}

export interface LoggingPolicy {
  logLevel: "DEBUG" | "INFO" | "WARN" | "ERROR";
  retainDays: number;
  includeRequestHashes: boolean;
  includeResponseHashes: boolean;
  storeRawResponses: boolean;
}

export interface ScanProfile {
  id: string;
  description: string;
  allowedScanners: ScannerName[];
  allowedModes: ScanMode[];
  disallowed: string[];
  rateLimits: RateLimits;
  logging: LoggingPolicy;
  controls: PassiveControl[];
}

export interface PassiveControl {
  id: string;
  requirement: string;
  enforcement: Record<string, unknown>;
}

export interface EscalationRule {
  id: string;
  name: string;
  conditions: EscalationCondition[];
  requestMode: ScanMode;
  allowScanners: ScannerName[];
  templateTagsAllowlist?: string[];
  templateTagsBlocklist?: string[];
  actions?: string[];
}

export interface EscalationCondition {
  field: string;
  operator: "==" | "!=" | ">=" | "<=" | ">" | "<" | "in";
  value: string | number | string[];
}

export interface ScanAsset {
  host: string;
  port: number;
  protocol?: string;
  tags?: string[];
}

export interface ScanRequest {
  scanner: ScannerName;
  mode: ScanMode;
  asset: ScanAsset;
  templateTags?: string[];
  httpMethod?: string;
  hasBody?: boolean;
}

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
  effectiveMode: ScanMode;
  rateLimits: RateLimits;
  controlViolations: string[];
  escalationApplied?: string;
}

export interface SignalContext {
  category: string;
  signalType: string;
  confidence: number;
}

export interface ObservationContext {
  observationType: string;
  severity: string;
  confidence: number;
}

// ─── Default Profiles (from SSIL YAML specs) ───────────────────────────────

const STRICT_PASSIVE_CONTROLS: PassiveControl[] = [
  {
    id: "SP-01",
    requirement: "No payload injection (no fuzzing, no attack strings, no form submissions).",
    enforcement: {
      blockHttpMethods: ["POST", "PUT", "PATCH", "DELETE"],
      blockBodyBytes: true,
      allowOnlySafeHeaders: true,
    },
  },
  {
    id: "SP-02",
    requirement: "No authentication guessing/bruteforce.",
    enforcement: {
      disableCredentialStuffing: true,
      disableLoginWorkflows: true,
    },
  },
  {
    id: "SP-03",
    requirement: "No exploit modules.",
    enforcement: {
      disableExploitation: true,
      nucleiTemplateTagsBlocklist: [
        "rce", "sqli", "ssrf", "cmdi", "deserialization", "bruteforce", "takeover-exploit",
      ],
    },
  },
  {
    id: "SP-04",
    requirement: "Rate limiting to avoid service impact.",
    enforcement: {
      perHostRps: 0.5,
      perDomainConcurrent: 2,
      globalConcurrent: 50,
      jitterMsRange: [50, 250],
    },
  },
  {
    id: "SP-05",
    requirement: "Privacy-preserving evidence collection.",
    enforcement: {
      storeRawResponses: false,
      storeHtmlBodies: false,
      storeOnlyHashes: true,
      redactHeaders: ["Authorization", "Cookie", "Set-Cookie"],
    },
  },
];

// ─── Federal Auth Testing Controls ──────────────────────────────────────────

const FEDERAL_STRICT_AUTH_CONTROLS: PassiveControl[] = [
  {
    id: "FA-01",
    requirement: "Maximum 0.1 RPS against auth endpoints. No credential guessing.",
    enforcement: {
      perHostRps: 0.1,
      disableCredentialStuffing: true,
      disableLoginWorkflows: true,
      maxAttemptsPerAccount: 1,
    },
  },
  {
    id: "FA-02",
    requirement: "Stop immediately on lockout signal (429/403).",
    enforcement: {
      stopOnLockoutSignal: true,
      lockoutSignalCodes: [429, 403],
      lockoutBackoffMs: 60000,
    },
  },
  {
    id: "FA-03",
    requirement: "Mandatory evidence capture for all auth interactions.",
    enforcement: {
      requireEvidenceCapture: true,
      captureRequestResponse: true,
      captureTimings: true,
      redactCredentials: true,
    },
  },
  {
    id: "FA-04",
    requirement: "Scope allowlist required — only test authorized auth endpoints.",
    enforcement: {
      requireScopeAllowlist: true,
      requireChangeWindow: true,
    },
  },
  {
    id: "FA-05",
    requirement: "Human-in-the-loop approval required for credential testing tools.",
    enforcement: {
      humanApprovalTools: ["hydra", "medusa", "netexec"],
      humanApprovalForActiveScanning: true,
    },
  },
];

const FEDERAL_STANDARD_AUTH_CONTROLS: PassiveControl[] = [
  {
    id: "FA-S01",
    requirement: "Maximum 0.5 RPS against auth endpoints. Credential testing with authorization.",
    enforcement: {
      perHostRps: 0.5,
      maxAttemptsPerAccount: 3,
    },
  },
  {
    id: "FA-S02",
    requirement: "Stop on lockout signal.",
    enforcement: {
      stopOnLockoutSignal: true,
      lockoutSignalCodes: [429, 403],
    },
  },
  {
    id: "FA-S03",
    requirement: "Evidence capture recommended but not mandatory.",
    enforcement: {
      requireEvidenceCapture: false,
      captureRequestResponse: true,
    },
  },
];

const DEFAULT_PROFILES: Record<string, ScanProfile> = {
  strict_passive: {
    id: "strict_passive",
    description:
      "Passive-only posture. No active probing, no fuzzing, no auth brute forcing. " +
      "Allowed: DNS lookups, TLS handshake metadata, HTTP HEAD/GET with safe headers, banner grabs.",
    allowedScanners: ["zgrab2", "custom_dns", "custom_tls", "custom_http_headers"],
    allowedModes: ["passive"],
    disallowed: ["active_scan", "exploitation", "brute_force", "auth_guessing", "payload_injection"],
    rateLimits: {
      perHostRps: 0.5,
      perDomainConcurrent: 2,
      globalConcurrent: 50,
      jitterMsRange: [50, 250],
    },
    logging: {
      logLevel: "INFO",
      retainDays: 90,
      includeRequestHashes: true,
      includeResponseHashes: true,
      storeRawResponses: false,
    },
    controls: STRICT_PASSIVE_CONTROLS,
  },

  balanced: {
    id: "balanced",
    description:
      "Passive-first with low-impact active checks allowed only after gating rules trigger.",
    allowedScanners: ["zgrab2", "nuclei", "custom_dns", "custom_tls", "custom_http_headers"],
    allowedModes: ["passive", "active-low"],
    disallowed: ["exploitation", "brute_force", "auth_guessing"],
    rateLimits: {
      perHostRps: 1,
      perDomainConcurrent: 4,
      globalConcurrent: 100,
    },
    logging: {
      logLevel: "INFO",
      retainDays: 90,
      includeRequestHashes: true,
      includeResponseHashes: true,
      storeRawResponses: false,
    },
    controls: [STRICT_PASSIVE_CONTROLS[1], STRICT_PASSIVE_CONTROLS[2], STRICT_PASSIVE_CONTROLS[4]],
  },

  aggressive_internal: {
    id: "aggressive_internal",
    description: "For explicitly authorized internal environments only.",
    allowedScanners: ["zgrab2", "nuclei", "discovery_orchestrated", "zap", "vuln_scanner", "web_crawler", "protocol_scanner"],
    allowedModes: ["passive", "active-low", "active-standard", "active-aggressive"],
    disallowed: [],
    rateLimits: {
      perHostRps: 5,
      perDomainConcurrent: 10,
      globalConcurrent: 250,
    },
    logging: {
      logLevel: "DEBUG",
      retainDays: 30,
      includeRequestHashes: true,
      includeResponseHashes: true,
      storeRawResponses: false,
    },
    controls: [],
  },
  // ── Federal Auth Testing Profiles (from Auth Pack v1.2) ─────────────────────

  federal_auth_strict: {
    id: "federal_auth_strict",
    description:
      "Federal strict auth testing mode. 0.1 RPS, no credential guessing, mandatory evidence capture, " +
      "human-in-the-loop gates for all active testing. For high-assurance federal environments.",  allowedScanners: ["zap", "custom_http_headers", "custom_tls", "custom_dns"],
    allowedModes: ["passive", "active-low"],
    disallowed: ["brute_force", "auth_guessing", "credential_stuffing", "payload_injection"],
    rateLimits: {
      perHostRps: 0.1,
      perDomainConcurrent: 1,
      globalConcurrent: 5,
      jitterMsRange: [200, 1000],
    },
    logging: {
      logLevel: "INFO",
      retainDays: 365,
      includeRequestHashes: true,
      includeResponseHashes: true,
      storeRawResponses: false,
    },
    controls: FEDERAL_STRICT_AUTH_CONTROLS,
  },

  federal_auth_standard: {
    id: "federal_auth_standard",
    description:
      "Federal standard auth testing mode. 0.5 RPS, controlled credential testing with authorization, " +
      "active scanning allowed. For authorized penetration testing of federal environments.",
    allowedScanners: ["zap", "nuclei", "discovery_orchestrated", "custom_http_headers", "custom_tls", "custom_dns"],
    allowedModes: ["passive", "active-low", "active-standard"],
    disallowed: ["exploitation", "payload_injection"],
    rateLimits: {
      perHostRps: 0.5,
      perDomainConcurrent: 2,
      globalConcurrent: 20,
      jitterMsRange: [100, 500],
    },
    logging: {
      logLevel: "INFO",
      retainDays: 180,
      includeRequestHashes: true,
      includeResponseHashes: true,
      storeRawResponses: false,
    },
    controls: FEDERAL_STANDARD_AUTH_CONTROLS,
  },
};

// ─── Default Escalation Rules (from SSIL YAML specs) ────────────────────────

const DEFAULT_ESCALATION_RULES: EscalationRule[] = [
  {
    id: "esc-001",
    name: "Admin surface discovered → allow active-low (nuclei safe templates)",
    conditions: [
      { field: "signal.category", operator: "==", value: "auth_surface" },
      { field: "signal.signalType", operator: "==", value: "exposure" },
      { field: "signal.confidence", operator: ">=", value: 0.85 },
    ],
    requestMode: "active-low",
    allowScanners: ["nuclei"],
    templateTagsAllowlist: ["misconfig", "headers", "tls", "exposures"],
    templateTagsBlocklist: ["rce", "ssrf", "sqli", "cmdi", "deserialization", "bruteforce"],
  },
  {
    id: "esc-002",
    name: "Dangling CNAME indicators → enrich with DNS takeover templates",
    conditions: [
      { field: "signal.category", operator: "==", value: "dns_takeover" },
      { field: "signal.signalType", operator: "in", value: ["weak_signal", "exposure"] },
      { field: "signal.confidence", operator: ">=", value: 0.70 },
    ],
    requestMode: "passive",
    allowScanners: ["custom_dns"],
    actions: ["resolve_target", "check_known_dangling_patterns"],
  },
  {
    id: "esc-003",
    name: "Exposed management port → active-low fingerprint only",
    conditions: [
      { field: "observation.observationType", operator: "==", value: "service_banner" },
      { field: "observation.severity", operator: "in", value: ["medium", "high", "critical"] },
      { field: "observation.confidence", operator: ">=", value: 0.80 },
    ],
    requestMode: "active-low",
    allowScanners: ["zgrab2"],
    actions: ["protocol_probe_metadata_only"],
  },
];

// ─── Rate Limiter ───────────────────────────────────────────────────────────

interface RateBucket {
  tokens: number;
  lastRefill: number;
  maxTokens: number;
  refillRate: number; // tokens per second
}

class TokenBucketRateLimiter {
  private hostBuckets = new Map<string, RateBucket>();
  private domainConcurrent = new Map<string, number>();
  private globalConcurrent = 0;

  private getBucket(key: string, rps: number): RateBucket {
    let bucket = this.hostBuckets.get(key);
    if (!bucket) {
      bucket = { tokens: rps * 2, lastRefill: Date.now(), maxTokens: rps * 2, refillRate: rps };
      this.hostBuckets.set(key, bucket);
    }
    // Refill tokens
    const now = Date.now();
    const elapsed = (now - bucket.lastRefill) / 1000;
    bucket.tokens = Math.min(bucket.maxTokens, bucket.tokens + elapsed * bucket.refillRate);
    bucket.lastRefill = now;
    return bucket;
  }

  canProceed(host: string, domain: string, limits: RateLimits): { allowed: boolean; reason?: string } {
    // Check global concurrent
    if (this.globalConcurrent >= limits.globalConcurrent) {
      return { allowed: false, reason: `Global concurrent limit reached (${limits.globalConcurrent})` };
    }

    // Check domain concurrent
    const domainCount = this.domainConcurrent.get(domain) || 0;
    if (domainCount >= limits.perDomainConcurrent) {
      return { allowed: false, reason: `Domain concurrent limit reached for ${domain} (${limits.perDomainConcurrent})` };
    }

    // Check host rate
    const bucket = this.getBucket(host, limits.perHostRps);
    if (bucket.tokens < 1) {
      return { allowed: false, reason: `Host rate limit reached for ${host} (${limits.perHostRps} rps)` };
    }

    return { allowed: true };
  }

  acquire(host: string, domain: string, limits: RateLimits): void {
    const bucket = this.getBucket(host, limits.perHostRps);
    bucket.tokens -= 1;
    this.domainConcurrent.set(domain, (this.domainConcurrent.get(domain) || 0) + 1);
    this.globalConcurrent += 1;
  }

  release(domain: string): void {
    const count = this.domainConcurrent.get(domain) || 0;
    if (count > 0) this.domainConcurrent.set(domain, count - 1);
    if (this.globalConcurrent > 0) this.globalConcurrent -= 1;
  }

  getJitter(limits: RateLimits): number {
    if (!limits.jitterMsRange) return 0;
    const [min, max] = limits.jitterMsRange;
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  getStats(): { globalConcurrent: number; hostBuckets: number; domainBuckets: number } {
    return {
      globalConcurrent: this.globalConcurrent,
      hostBuckets: this.hostBuckets.size,
      domainBuckets: this.domainConcurrent.size,
    };
  }
}

// ─── Policy Violation Log ───────────────────────────────────────────────────

export interface PolicyViolation {
  id: string;
  timestamp: number;
  scanner: ScannerName;
  asset: ScanAsset;
  requestedMode: ScanMode;
  profileId: string;
  controlId?: string;
  reason: string;
}

// ─── Scan Policy Engine ─────────────────────────────────────────────────────

export class ScanPolicyEngine {
  private profiles: Map<string, ScanProfile>;
  private escalationRules: EscalationRule[];
  private activeProfileId: string;
  private rateLimiter: TokenBucketRateLimiter;
  private violations: PolicyViolation[] = [];
  private maxViolationLog = 1000;

  constructor(activeProfileId: string = "strict_passive") {
    this.profiles = new Map(Object.entries(DEFAULT_PROFILES));
    this.escalationRules = [...DEFAULT_ESCALATION_RULES];
    this.activeProfileId = activeProfileId;
    this.rateLimiter = new TokenBucketRateLimiter();
  }

  // ── Profile Management ──────────────────────────────────────────────────

  getActiveProfile(): ScanProfile {
    return this.profiles.get(this.activeProfileId) || DEFAULT_PROFILES.strict_passive;
  }

  getActiveProfileId(): string {
    return this.activeProfileId;
  }

  setActiveProfile(profileId: string): void {
    if (!this.profiles.has(profileId)) {
      throw new Error(`Unknown scan profile: ${profileId}`);
    }
    this.activeProfileId = profileId;
  }

  getProfile(profileId: string): ScanProfile | undefined {
    return this.profiles.get(profileId);
  }

  listProfiles(): ScanProfile[] {
    return Array.from(this.profiles.values());
  }

  addProfile(profile: ScanProfile): void {
    this.profiles.set(profile.id, profile);
  }

  // ── Escalation Rules ───────────────────────────────────────────────────

  getEscalationRules(): EscalationRule[] {
    return [...this.escalationRules];
  }

  addEscalationRule(rule: EscalationRule): void {
    this.escalationRules.push(rule);
  }

  removeEscalationRule(ruleId: string): void {
    this.escalationRules = this.escalationRules.filter((r) => r.id !== ruleId);
  }

  // ── Core Policy Decision ──────────────────────────────────────────────

  canExecute(request: ScanRequest): PolicyDecision {
    const profile = this.getActiveProfile();
    const violations: string[] = [];
    let effectiveMode = request.mode;

    // 1. Check if scanner is allowed
    if (!profile.allowedScanners.includes(request.scanner)) {
      violations.push(`Scanner '${request.scanner}' not allowed in profile '${profile.id}'`);
    }

    // 2. Check if mode is allowed
    if (!profile.allowedModes.includes(request.mode)) {
      violations.push(`Mode '${request.mode}' not allowed in profile '${profile.id}'`);
    }

    // 3. Check disallowed actions
    if (request.mode !== "passive" && profile.disallowed.includes("active_scan")) {
      violations.push("Active scanning is disallowed in current profile");
    }

    // 4. Enforce SP-01: No payload injection
    if (profile.id === "strict_passive" || profile.controls.some((c) => c.id === "SP-01")) {
      const blockedMethods = ["POST", "PUT", "PATCH", "DELETE"];
      if (request.httpMethod && blockedMethods.includes(request.httpMethod.toUpperCase())) {
        violations.push(`SP-01: HTTP method '${request.httpMethod}' blocked in passive mode`);
      }
      if (request.hasBody) {
        violations.push("SP-01: Request body not allowed in passive mode");
      }
    }

    // 5. Enforce SP-02: No auth guessing
    if (profile.disallowed.includes("brute_force") || profile.disallowed.includes("auth_guessing")) {
      if (request.templateTags?.some((t) => ["bruteforce", "default-login"].includes(t))) {
        violations.push("SP-02: Authentication guessing/bruteforce templates blocked");
      }
    }

    // 6. Enforce SP-03: No exploit modules
    if (profile.controls.some((c) => c.id === "SP-03")) {
      const blocklist = ["rce", "sqli", "ssrf", "cmdi", "deserialization", "bruteforce", "takeover-exploit"];
      const blocked = request.templateTags?.filter((t) => blocklist.includes(t)) || [];
      if (blocked.length > 0) {
        violations.push(`SP-03: Exploit template tags blocked: ${blocked.join(", ")}`);
      }
    }

    // 7. Check rate limits
    const domain = extractDomain(request.asset.host);
    const rateCheck = this.rateLimiter.canProceed(request.asset.host, domain, profile.rateLimits);
    if (!rateCheck.allowed) {
      violations.push(`SP-04: ${rateCheck.reason}`);
    }

    const allowed = violations.length === 0;

    // Log violations
    if (!allowed) {
      this.logViolation(request, profile, violations);
    }

    return {
      allowed,
      reason: allowed ? "Request permitted by policy" : violations.join("; "),
      effectiveMode,
      rateLimits: profile.rateLimits,
      controlViolations: violations,
    };
  }

  // ── Escalation Evaluation ─────────────────────────────────────────────

  evaluateEscalation(
    signal?: SignalContext,
    observation?: ObservationContext
  ): { escalated: boolean; rule?: EscalationRule; newMode?: ScanMode } {
    const profile = this.getActiveProfile();

    // Strict passive never escalates
    if (profile.id === "strict_passive") {
      return { escalated: false };
    }

    for (const rule of this.escalationRules) {
      if (this.matchesConditions(rule.conditions, signal, observation)) {
        // Only escalate if the profile allows the target mode
        if (profile.allowedModes.includes(rule.requestMode)) {
          return { escalated: true, rule, newMode: rule.requestMode };
        }
      }
    }

    return { escalated: false };
  }

  private matchesConditions(
    conditions: EscalationCondition[],
    signal?: SignalContext,
    observation?: ObservationContext
  ): boolean {
    for (const cond of conditions) {
      const value = this.resolveField(cond.field, signal, observation);
      if (value === undefined) return false;

      switch (cond.operator) {
        case "==":
          if (value !== cond.value) return false;
          break;
        case "!=":
          if (value === cond.value) return false;
          break;
        case ">=":
          if (typeof value !== "number" || value < (cond.value as number)) return false;
          break;
        case "<=":
          if (typeof value !== "number" || value > (cond.value as number)) return false;
          break;
        case ">":
          if (typeof value !== "number" || value <= (cond.value as number)) return false;
          break;
        case "<":
          if (typeof value !== "number" || value >= (cond.value as number)) return false;
          break;
        case "in":
          if (!Array.isArray(cond.value) || !cond.value.includes(value as string)) return false;
          break;
      }
    }
    return true;
  }

  private resolveField(
    field: string,
    signal?: SignalContext,
    observation?: ObservationContext
  ): string | number | undefined {
    const parts = field.split(".");
    if (parts[0] === "signal" && signal) {
      return (signal as unknown as Record<string, unknown>)[parts[1]] as string | number | undefined;
    }
    if (parts[0] === "observation" && observation) {
      return (observation as unknown as Record<string, unknown>)[parts[1]] as string | number | undefined;
    }
    return undefined;
  }

  // ── Rate Limiter Interaction ──────────────────────────────────────────

  acquireRateSlot(asset: ScanAsset): void {
    const profile = this.getActiveProfile();
    const domain = extractDomain(asset.host);
    this.rateLimiter.acquire(asset.host, domain, profile.rateLimits);
  }

  releaseRateSlot(asset: ScanAsset): void {
    const domain = extractDomain(asset.host);
    this.rateLimiter.release(domain);
  }

  getJitterMs(): number {
    return this.rateLimiter.getJitter(this.getActiveProfile().rateLimits);
  }

  getRateLimiterStats() {
    return this.rateLimiter.getStats();
  }

  // ── Evidence Fingerprinting (SP-05) ───────────────────────────────────

  shouldStoreRawResponses(): boolean {
    const profile = this.getActiveProfile();
    return profile.logging.storeRawResponses;
  }

  getRedactedHeaders(): string[] {
    const profile = this.getActiveProfile();
    const sp05 = profile.controls.find((c) => c.id === "SP-05");
    if (sp05) {
      return (sp05.enforcement.redactHeaders as string[]) || [];
    }
    return ["Authorization", "Cookie", "Set-Cookie"];
  }

  fingerprintEvidence(data: string | Buffer): string {
    return crypto.createHash("sha256").update(data).digest("hex");
  }

  redactHeaders(headers: Record<string, string>): Record<string, string> {
    const redactList = this.getRedactedHeaders();
    const result: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      if (redactList.some((r) => r.toLowerCase() === key.toLowerCase())) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = value;
      }
    }
    return result;
  }

  // ── Violation Log ─────────────────────────────────────────────────────

  private logViolation(request: ScanRequest, profile: ScanProfile, violations: string[]): void {
    const violation: PolicyViolation = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      scanner: request.scanner,
      asset: request.asset,
      requestedMode: request.mode,
      profileId: profile.id,
      reason: violations.join("; "),
    };
    this.violations.push(violation);
    if (this.violations.length > this.maxViolationLog) {
      this.violations = this.violations.slice(-this.maxViolationLog);
    }
  }

  getViolations(limit: number = 50): PolicyViolation[] {
    return this.violations.slice(-limit);
  }

  getViolationCount(): number {
    return this.violations.length;
  }

  clearViolations(): void {
    this.violations = [];
  }

  // ── Attestation ───────────────────────────────────────────────────────

  getAttestation(): string {
    const profile = this.getActiveProfile();
    if (profile.id === "strict_passive") {
      return (
        "When Strict Passive Mode is enabled, the system enforces technical controls that " +
        "prevent active exploitation, payload injection, and authentication attacks. Evidence " +
        "retention is limited to metadata and hashes to reduce data sensitivity."
      );
    }
    if (profile.id === "federal_auth_strict") {
      return (
        "Federal Auth Strict Mode is active. Rate limited to 0.1 RPS. No credential guessing. " +
        "Mandatory evidence capture. Human-in-the-loop approval required for all active testing. " +
        "Controls FA-01 through FA-05 enforced. Suitable for high-assurance federal environments."
      );
    }
    if (profile.id === "federal_auth_standard") {
      return (
        "Federal Auth Standard Mode is active. Rate limited to 0.5 RPS. Controlled credential " +
        "testing with authorization. Active scanning allowed with scope restrictions. " +
        "Controls FA-S01 through FA-S03 enforced."
      );
    }
    return `Scan policy profile '${profile.id}' is active. ${profile.description}`;
  }

  /**
   * Check if the current profile is a federal auth testing profile.
   * CROSS-MODULE: Other engines can use this to adjust their behavior.
   */
  isFederalAuthMode(): boolean {
    return this.activeProfileId.startsWith("federal_auth_");
  }

  /**
   * Get the federal auth mode level (strict/standard/none).
   */
  getFederalAuthLevel(): "strict" | "standard" | "none" {
    if (this.activeProfileId === "federal_auth_strict") return "strict";
    if (this.activeProfileId === "federal_auth_standard") return "standard";
    return "none";
  }

  // ── Serialisation ─────────────────────────────────────────────────────

  toJSON() {
    return {
      activeProfileId: this.activeProfileId,
      profiles: Array.from(this.profiles.values()),
      escalationRules: this.escalationRules,
      rateLimiterStats: this.rateLimiter.getStats(),
      violationCount: this.violations.length,
    };
  }
}

// ─── Tool-to-Tier Classification (Claude’s Passive/Active Taxonomy) ───────────────
//
// Maps external scanning/recon tools to their correct scan mode tier.
// Classification follows Claude’s analysis (Apr 2026):
//   - passive:           No packets to target. Queries third-party databases only.
//   - active-low:        Sends packets but no aggressive probing. Standard web/DNS client behavior.
//   - active-standard:   Service fingerprinting, content discovery, deeper probing. No exploitation.
//   - active-aggressive:  Vulnerability probing, exploit-like payloads, high-volume scanning.
//
// IMPORTANT: "passive" in OSINT literature = "no packets sent to target."
// Operations that send packets but don’t probe aggressively (httpx, dnsx) are classified
// as active-low, NOT passive, to keep ROE conversations honest with customers.

export interface ToolClassification {
  name: string;
  tier: ScanMode;
  description: string;
  targetContact: boolean;  // Does this tool send packets to the target?
  stateChange: boolean;    // Can this tool cause state changes on the target?
  detectionRisk: "none" | "minimal" | "low" | "medium" | "high";
  roeRequired: boolean;    // Does ROE need to explicitly authorize this tool?
  notes?: string;
}

export const TOOL_TIER_CLASSIFICATION: ToolClassification[] = [
  // ── Fully Passive (no packets to target) ──────────────────────────────
  // Subdomain & DNS discovery (third-party databases)
  { name: "crt.sh", tier: "passive", description: "Certificate Transparency log search", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "certspotter", tier: "passive", description: "SSLMate CT log monitoring", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "subfinder", tier: "passive", description: "Passive subdomain discovery (~30 third-party sources)", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false, notes: "Passive mode is default. Never use active mode in DI pipeline." },
  { name: "chaos-client", tier: "passive", description: "ProjectDiscovery managed corpus", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "amass-passive", tier: "passive", description: "Amass enum -passive (touchless mode)", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false, notes: "MUST use -passive flag. Without it, amass does active DNS brute-forcing." },
  { name: "assetfinder", tier: "passive", description: "Passive subdomain discovery", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "findomain", tier: "passive", description: "Passive subdomain discovery", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  // Archive & historical data
  { name: "gau", tier: "passive", description: "GetAllURLs — Wayback Machine + archive sources", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false, notes: "Passive by default. Live-fetching flags push to active-low." },
  { name: "waybackurls", tier: "passive", description: "Wayback Machine URL extraction", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "commoncrawl", tier: "passive", description: "Common Crawl historical web data", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  // Infrastructure intelligence (pre-scanned databases)
  { name: "shodan", tier: "passive", description: "Shodan pre-scanned database", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "shodan-internetdb", tier: "passive", description: "Shodan InternetDB free endpoint", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "censys", tier: "passive", description: "Censys internet-wide scan database", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "fofa", tier: "passive", description: "FOFA internet-wide scan database", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "zoomeye", tier: "passive", description: "ZoomEye internet-wide scan database", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "netlas", tier: "passive", description: "Netlas.io internet-wide host scanning", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "team-cymru", tier: "passive", description: "IP-to-ASN mapping via DNS (queries Cymru, not target)", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "ripestat", tier: "passive", description: "RIPE Stat routing and RIR data", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "bgpview", tier: "passive", description: "BGPView ASN/BGP routing data", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  // WHOIS & registration
  { name: "rdap", tier: "passive", description: "RDAP/WHOIS registry data", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "whoisxmlapi", tier: "passive", description: "WhoisXML API registration data", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "whoisfreaks", tier: "passive", description: "WhoisFreaks WHOIS data", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "securitytrails", tier: "passive", description: "SecurityTrails historical DNS/WHOIS", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  // Reputation & threat intel
  { name: "urlhaus", tier: "passive", description: "abuse.ch malicious URL database", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "threatfox", tier: "passive", description: "abuse.ch IOC database", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "malwarebazaar", tier: "passive", description: "abuse.ch malware sample database", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "feodo-tracker", tier: "passive", description: "abuse.ch botnet C2 tracking", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "sslbl", tier: "passive", description: "abuse.ch SSL certificate blacklist", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "alienvault-otx", tier: "passive", description: "AlienVault OTX threat indicators", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "greynoise", tier: "passive", description: "GreyNoise internet background noise", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "hibp", tier: "passive", description: "Have I Been Pwned breach database", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "phishtank", tier: "passive", description: "PhishTank phishing URL database", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "openphish", tier: "passive", description: "OpenPhish phishing reputation", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  // Vulnerability correlation
  { name: "nvd", tier: "passive", description: "NVD CVE database", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "cisa-kev", tier: "passive", description: "CISA Known Exploited Vulnerabilities", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "epss", tier: "passive", description: "EPSS exploit prediction scoring", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "osv-dev", tier: "passive", description: "OSV.dev open source vulnerability DB", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "github-advisories", tier: "passive", description: "GitHub Security Advisories (GHSA)", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  // Email & org attribution
  { name: "theharvester-passive", tier: "passive", description: "theHarvester (passive sources only)", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false, notes: "Must audit --source flag. Some sources are active." },
  { name: "sec-edgar", tier: "passive", description: "SEC EDGAR corporate filings", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "companies-house", tier: "passive", description: "UK Companies House registry", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },
  { name: "opencorporates", tier: "passive", description: "Global corporate registry (140M+ companies)", targetContact: false, stateChange: false, detectionRisk: "none", roeRequired: false },

  // ── Boundary Cases (passive-by-default, can become active) ────────────
  // These are classified as active-low because they DO send packets to target.
  // ROE must authorize probing even though impact is minimal.
  { name: "httpx", tier: "active-low", description: "HTTP probing — single GET per host, standard web client behavior", targetContact: true, stateChange: false, detectionRisk: "minimal", roeRequired: true, notes: "Lightest possible active probing. Indistinguishable from normal user visit. Classify as active-low, not passive, to keep ROE honest." },
  { name: "dnsx", tier: "active-low", description: "DNS resolution against authoritative nameservers", targetContact: true, stateChange: false, detectionRisk: "minimal", roeRequired: true, notes: "DNS queries are indistinguishable from normal internet traffic. Almost universally classified as passive in practice, but technically sends packets." },

  // ── Active — Low Impact ────────────────────────────────────────────────
  // Send packets, no aggressive probing, no exploitation, no state change.
  { name: "naabu", tier: "active-low", description: "TCP connect port discovery", targetContact: true, stateChange: false, detectionRisk: "low", roeRequired: true, notes: "Standard TCP connections. No state change, low noise." },
  { name: "rustscan", tier: "active-low", description: "Fast port discovery (similar to naabu)", targetContact: true, stateChange: false, detectionRisk: "low", roeRequired: true },
  { name: "gowitness", tier: "active-low", description: "Web screenshot tool — full HTTP connections + page rendering", targetContact: true, stateChange: false, detectionRisk: "low", roeRequired: true, notes: "Active, but no probing beyond normal browser behavior." },
  { name: "aquatone", tier: "active-low", description: "Web screenshot and HTTP probing", targetContact: true, stateChange: false, detectionRisk: "low", roeRequired: true },
  { name: "eyewitness", tier: "active-low", description: "Web screenshot tool", targetContact: true, stateChange: false, detectionRisk: "low", roeRequired: true },

  // ── Active — Standard Impact ───────────────────────────────────────────
  // Service fingerprinting, content discovery, deeper probing. No exploitation.
  { name: "nmap-sv", tier: "active-standard", description: "Nmap service/OS fingerprinting (-sS/-sT/-sV/-O, --script safe)", targetContact: true, stateChange: false, detectionRisk: "medium", roeRequired: true, notes: "NSE scripts in 'safe' category stay in this tier." },
  { name: "naabu-svc", tier: "active-standard", description: "Port scanning with service detection", targetContact: true, stateChange: false, detectionRisk: "medium", roeRequired: true },
  { name: "whatweb", tier: "active-standard", description: "HTTP fingerprinting with depth", targetContact: true, stateChange: false, detectionRisk: "medium", roeRequired: true },
  { name: "webanalyze", tier: "active-standard", description: "Technology fingerprinting", targetContact: true, stateChange: false, detectionRisk: "medium", roeRequired: true },
  { name: "ffuf", tier: "active-standard", description: "Content discovery via fuzzing", targetContact: true, stateChange: false, detectionRisk: "medium", roeRequired: true, notes: "Generates 10,000+ 404s in target logs. OPSEC risk engine should score higher than fingerprinting. Requires explicit ROE for content discovery." },
  { name: "gobuster", tier: "active-standard", description: "Content discovery via wordlist brute-force", targetContact: true, stateChange: false, detectionRisk: "medium", roeRequired: true, notes: "Same OPSEC concern as ffuf — high log volume on target." },
  { name: "feroxbuster", tier: "active-standard", description: "Recursive content discovery", targetContact: true, stateChange: false, detectionRisk: "medium", roeRequired: true },
  { name: "katana", tier: "active-standard", description: "Web crawler", targetContact: true, stateChange: false, detectionRisk: "medium", roeRequired: true, notes: "Configuration-dependent. At aggressive concurrency pushes toward active-aggressive." },
  { name: "nikto", tier: "active-standard", description: "Web vulnerability scanner (mostly fingerprinting)", targetContact: true, stateChange: false, detectionRisk: "medium", roeRequired: true, notes: "Some checks border on active-aggressive (default credential probing)." },
  { name: "retire-js", tier: "active-standard", description: "JavaScript vulnerability detection", targetContact: true, stateChange: false, detectionRisk: "low", roeRequired: true, notes: "Active if fetching JS from target, but non-invasive." },

  // ── Active — Aggressive ────────────────────────────────────────────────
  // Vulnerability probing, exploit-like payloads, high-volume scanning.
  { name: "nmap-vuln", tier: "active-aggressive", description: "Nmap with NSE vuln scripts (--script vuln)", targetContact: true, stateChange: false, detectionRisk: "high", roeRequired: true, notes: "Some NSE vuln scripts send exploit-like payloads." },
  { name: "nuclei", tier: "active-aggressive", description: "Template-based vulnerability checking", targetContact: true, stateChange: false, detectionRisk: "high", roeRequired: true, notes: "Severity depends on template tags. Templates tagged dos/intrusive/fuzz need particular care. Info/tech templates are closer to active-standard." },
  { name: "masscan", tier: "active-aggressive", description: "High-rate port scanning", targetContact: true, stateChange: false, detectionRisk: "high", roeRequired: true, notes: "At any meaningful rate, masscan is aggressive due to volume alone." },
  { name: "wapiti", tier: "active-aggressive", description: "Web vulnerability scanner with active probing", targetContact: true, stateChange: false, detectionRisk: "high", roeRequired: true },
  { name: "s3scanner", tier: "active-aggressive", description: "Cloud bucket enumeration (triggers defender alerts)", targetContact: true, stateChange: false, detectionRisk: "high", roeRequired: true },
];

/**
 * Get all tools classified at a specific tier.
 */
export function getToolsByTier(tier: ScanMode): ToolClassification[] {
  return TOOL_TIER_CLASSIFICATION.filter(t => t.tier === tier);
}

/**
 * Get the classification for a specific tool.
 */
export function getToolClassification(toolName: string): ToolClassification | undefined {
  return TOOL_TIER_CLASSIFICATION.find(t => t.name === toolName);
}

/**
 * Check if a tool is allowed under a given scan mode.
 * A tool is allowed if its tier is equal to or less aggressive than the requested mode.
 */
export function isToolAllowedInMode(toolName: string, mode: ScanMode): boolean {
  const tool = getToolClassification(toolName);
  if (!tool) return false;
  const tierOrder: ScanMode[] = ["passive", "active-low", "active-standard", "active-aggressive"];
  const toolIdx = tierOrder.indexOf(tool.tier);
  const modeIdx = tierOrder.indexOf(mode);
  return toolIdx <= modeIdx;
}

// ─── Helpers ────────────────────────────────────────────────────────────────────────────────

function extractDomain(host: string): string {
  // Strip port if present, extract registrable domain
  const h = host.replace(/:\d+$/, "");
  const parts = h.split(".");
  if (parts.length <= 2) return h;
  return parts.slice(-2).join(".");
}

// ─── Singleton ──────────────────────────────────────────────────────────────

let _engine: ScanPolicyEngine | null = null;

export function getScanPolicyEngine(): ScanPolicyEngine {
  if (!_engine) {
    _engine = new ScanPolicyEngine("strict_passive");
  }
  return _engine;
}

export function resetScanPolicyEngine(): void {
  _engine = null;
}
