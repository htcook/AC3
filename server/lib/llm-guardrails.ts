/**
 * SSIL LLM Guardrails Service
 *
 * Wraps the platform's invokeLLM function with SSIL-defined safety guardrails
 * to prevent exploit generation, payload creation, and offensive instruction output.
 *
 * Implements the guardrails from docs/ssil/llm/prompts/guardrails.md and
 * system.md, injecting them as system-level constraints on every LLM call.
 *
 * Author: Harrison Cook — AceofCloud
 */

import * as crypto from "crypto";
import type { InvokeParams, InvokeResult, Message } from "../_core/llm";

// ─── Types ──────────────────────────────────────────────────────────────────

export type GuardrailContext =
  | "analyst"        // Scan reasoning / observation analysis
  | "risk_card"      // Risk card generation
  | "caldera_hooks"  // Safe Caldera planning hooks
  | "detection"      // Detection rule generation (Sigma/YARA/Suricata)
  | "phishing"       // Red team phishing content (authorized)
  | "report"         // Report generation
  | "general";       // Default context

export interface GuardrailConfig {
  enabled: boolean;
  context: GuardrailContext;
  strictPassiveMode: boolean;
  logViolations: boolean;
  maxSystemPromptTokenEstimate: number;
}

export interface GuardrailViolation {
  id: string;
  timestamp: number;
  context: GuardrailContext;
  triggerPattern: string;
  originalPrompt: string;
  action: "blocked" | "sanitized" | "warned";
  reason: string;
}

export interface GuardrailStats {
  totalCalls: number;
  blockedCalls: number;
  sanitizedCalls: number;
  warnedCalls: number;
  violations: GuardrailViolation[];
}

// ─── SSIL System Prompts (from docs/ssil/llm/prompts/) ─────────────────────

const SSIL_SYSTEM_PROMPT = `You are the SSIL Scan Reasoning Assistant embedded in a defensive security platform.
You will be given normalized scan_observation and signal objects that conform to the SSIL schemas.
Your job is to:
1) Summarize what is known with evidence and confidence.
2) Identify likely risk themes without speculating beyond evidence.
3) Recommend defensive next steps (verification steps, remediation, monitoring).
4) Produce structured outputs exactly as requested.

Constraints:
- Use only the input data. Do NOT assume additional vulnerabilities.
- Do NOT provide exploit steps, payloads, or instructions to attack systems.
- Prefer metadata-only reasoning and safe verification steps (configuration checks, patch validation, logging).
- If the confidence is low (<0.6), say so and recommend additional passive evidence collection.`;

const SSIL_GUARDRAILS_PROMPT = `Safety Guardrails:
- Never produce exploit payloads, attack strings, or instructions to compromise systems.
- Focus on remediation, validation, monitoring, configuration hardening.
- If a user asks for offensive instructions, refuse and offer defensive alternatives.
- Respect Strict Passive Mode: recommend only passive verification unless explicitly authorized.

Compliance:
- Do not store or repeat sensitive data (tokens, cookies, credentials).
- Use hashes/fingerprints if referencing evidence.`;

const CONTEXT_PROMPTS: Record<GuardrailContext, string> = {
  analyst: `You are analyzing normalized scan observations and signals. Produce findings summaries, top risks (ranked with confidence), recommended defensive next steps, and data gaps with suggested passive checks. Output structured YAML or JSON as requested.`,

  risk_card: `Create risk_card objects per asset using the SSIL risk card schema. Components must include cvss (0-10), carver (0-10), bia (0-10), and confidence_weight (0-1). Evidence should reference observation_id and/or signal_id. Recommendations must be defensive and actionable. Return JSON.`,

  caldera_hooks: `Generate safe, high-level Caldera planning hooks based on signals. Return suggested_objectives (e.g., validate auth hardening, validate patch level), suggested_abilities (high-level names only like "Enumerate exposed endpoints", "Check TLS config"), and safety_notes (must include "No exploit payloads; authorized testing only"). Do NOT include commands, payloads, or step-by-step intrusion instructions.`,

  detection: `You are a detection engineering expert. Generate production-ready detection rules (Sigma, YARA, Suricata, Splunk SPL, or KQL) for the given techniques. Focus on behavioral detection patterns, not exploit signatures. Rules should detect adversary behavior, not specific tools.`,

  phishing: `You are a red team phishing campaign designer for authorized security testing. Generate realistic but clearly marked test content. All generated content must include clear "THIS IS A SECURITY TEST" markers in metadata. Do not generate content that could be used for actual social engineering attacks outside authorized engagements.`,

  report: `You are a cybersecurity report writer. Generate professional assessment reports with executive summaries, technical findings, risk ratings, and remediation recommendations. Focus on actionable defensive guidance. Do not include exploit code or attack instructions in reports.`,

  general: `You are a cybersecurity assistant. Provide helpful, defensive-focused guidance. Do not generate exploit code, attack payloads, or instructions for compromising systems. Focus on security hardening, detection, and remediation.`,
};

// ─── Blocked Patterns ───────────────────────────────────────────────────────

/**
 * Patterns that indicate the LLM is being asked to generate exploit content.
 * These are checked against user messages before they reach the LLM.
 */
const BLOCKED_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /generate\s+(a\s+)?working\s+exploit/i,
    reason: "Request to generate working exploit code",
  },
  {
    pattern: /write\s+(a\s+)?(shell|reverse)\s*shell/i,
    reason: "Request to generate shell/reverse shell code",
  },
  {
    pattern: /create\s+(a\s+)?payload\s+for\s+(remote|code)\s+execution/i,
    reason: "Request to create RCE payload",
  },
  {
    pattern: /bypass\s+(authentication|authorization|firewall|waf|ids|ips)/i,
    reason: "Request to bypass security controls",
  },
  {
    pattern: /sql\s+injection\s+(payload|string|attack)/i,
    reason: "Request for SQL injection attack strings",
  },
  {
    pattern: /xss\s+(payload|vector|attack\s+string)/i,
    reason: "Request for XSS attack vectors",
  },
  {
    pattern: /privilege\s+escalation\s+(exploit|script|payload)/i,
    reason: "Request for privilege escalation exploit",
  },
  {
    pattern: /brute\s*force\s+(password|credential|login)/i,
    reason: "Request for brute force attack tooling",
  },
];

/**
 * Patterns that trigger a warning but don't block — the guardrail system
 * prompt is still injected to constrain the LLM's response.
 */
const WARN_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /how\s+to\s+(hack|exploit|attack|compromise)/i,
    reason: "Question about offensive techniques — guardrails applied",
  },
  {
    pattern: /vulnerability\s+(exploitation|weaponization)/i,
    reason: "Discussion of vulnerability exploitation — guardrails applied",
  },
  {
    pattern: /attack\s+(chain|path|surface|vector)/i,
    reason: "Attack surface discussion — guardrails applied",
  },
];

// ─── Guardrails Service ─────────────────────────────────────────────────────

export class LLMGuardrails {
  private config: GuardrailConfig;
  private stats: GuardrailStats;

  constructor(config?: Partial<GuardrailConfig>) {
    this.config = {
      enabled: true,
      context: "general",
      strictPassiveMode: true,
      logViolations: true,
      maxSystemPromptTokenEstimate: 500,
      ...config,
    };
    this.stats = {
      totalCalls: 0,
      blockedCalls: 0,
      sanitizedCalls: 0,
      warnedCalls: 0,
      violations: [],
    };
  }

  // ── Configuration ─────────────────────────────────────────────────────

  setContext(context: GuardrailContext): void {
    this.config.context = context;
  }

  setEnabled(enabled: boolean): void {
    this.config.enabled = enabled;
  }

  setStrictPassiveMode(enabled: boolean): void {
    this.config.strictPassiveMode = enabled;
  }

  getConfig(): GuardrailConfig {
    return { ...this.config };
  }

  // ── Core Guardrail Application ────────────────────────────────────────

  /**
   * Wraps invokeLLM parameters with SSIL guardrails.
   * Returns modified params with safety system prompts injected,
   * or null if the request should be blocked entirely.
   */
  applyGuardrails(
    params: InvokeParams,
    context?: GuardrailContext
  ): { params: InvokeParams; blocked: boolean; warnings: string[] } {
    this.stats.totalCalls++;
    const ctx = context || this.config.context;
    const warnings: string[] = [];

    if (!this.config.enabled) {
      return { params, blocked: false, warnings: [] };
    }

    // 1. Check user messages for blocked patterns
    const userMessages = params.messages.filter((m) => m.role === "user");
    for (const msg of userMessages) {
      const content = typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content);
      for (const { pattern, reason } of BLOCKED_PATTERNS) {
        if (pattern.test(content)) {
          this.stats.blockedCalls++;
          this.logViolation(ctx, pattern.source, content.substring(0, 200), "blocked", reason);
          return { params, blocked: true, warnings: [reason] };
        }
      }

      // Check warn patterns
      for (const { pattern, reason } of WARN_PATTERNS) {
        if (pattern.test(content)) {
          this.stats.warnedCalls++;
          warnings.push(reason);
          this.logViolation(ctx, pattern.source, content.substring(0, 200), "warned", reason);
        }
      }
    }

    // 2. Inject SSIL guardrails system prompt
    const guardrailedMessages = this.injectGuardrailPrompts(params.messages, ctx);

    // 3. Sanitize any existing system prompts that might override guardrails
    const sanitizedMessages = this.sanitizeSystemPrompts(guardrailedMessages);

    this.stats.sanitizedCalls++;

    return {
      params: { ...params, messages: sanitizedMessages },
      blocked: false,
      warnings,
    };
  }

  /**
   * Convenience wrapper that calls invokeLLM with guardrails applied.
   */
  async invokeWithGuardrails(
    invokeLLM: (params: InvokeParams) => Promise<InvokeResult>,
    params: InvokeParams,
    context?: GuardrailContext
  ): Promise<InvokeResult> {
    const result = this.applyGuardrails(params, context);

    if (result.blocked) {
      // Return a synthetic "blocked" response
      return {
        id: `guardrail-blocked-${crypto.randomUUID()}`,
        created: Math.floor(Date.now() / 1000),
        model: "guardrail",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content:
                "I cannot fulfill this request. The SSIL guardrails system has determined that " +
                "this request seeks to generate exploit code, attack payloads, or offensive instructions. " +
                "I can help with defensive alternatives: vulnerability remediation, detection rule creation, " +
                "security hardening recommendations, or compliance guidance. How can I help defensively?",
            },
            finish_reason: "stop",
          },
        ],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      };
    }

    return invokeLLM(result.params);
  }

  // ── Prompt Injection ──────────────────────────────────────────────────

  private injectGuardrailPrompts(messages: Message[], context: GuardrailContext): Message[] {
    const result: Message[] = [];
    let hasSystemPrompt = false;

    // Check if there's already a system message
    for (const msg of messages) {
      if (msg.role === "system") {
        hasSystemPrompt = true;
        // Append guardrails to existing system prompt
        const existingContent = typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content);
        const enhancedContent = `${existingContent}\n\n${SSIL_GUARDRAILS_PROMPT}`;
        result.push({ ...msg, content: enhancedContent });
      } else {
        result.push(msg);
      }
    }

    // If no system prompt exists, prepend the full SSIL system prompt
    if (!hasSystemPrompt) {
      const contextPrompt = CONTEXT_PROMPTS[context] || CONTEXT_PROMPTS.general;
      result.unshift({
        role: "system",
        content: `${SSIL_SYSTEM_PROMPT}\n\n${contextPrompt}\n\n${SSIL_GUARDRAILS_PROMPT}`,
      });
    }

    // Add strict passive mode constraint if enabled
    if (this.config.strictPassiveMode) {
      const passiveNote: Message = {
        role: "system",
        content:
          "STRICT PASSIVE MODE ACTIVE: All recommendations must be limited to passive verification, " +
          "configuration review, and monitoring. Do not suggest active scanning, exploitation, or " +
          "any actions that could alter target system state.",
      };
      // Insert after the first system message
      const firstSystemIdx = result.findIndex((m) => m.role === "system");
      if (firstSystemIdx >= 0) {
        result.splice(firstSystemIdx + 1, 0, passiveNote);
      } else {
        result.unshift(passiveNote);
      }
    }

    return result;
  }

  // ── System Prompt Sanitization ────────────────────────────────────────

  /**
   * Ensures no system prompt contains instructions that would override
   * the guardrails (e.g., "ignore previous instructions").
   */
  private sanitizeSystemPrompts(messages: Message[]): Message[] {
    const overridePatterns = [
      /ignore\s+(all\s+)?previous\s+instructions/i,
      /disregard\s+(all\s+)?safety/i,
      /you\s+are\s+now\s+(an?\s+)?unrestricted/i,
      /jailbreak/i,
      /DAN\s+mode/i,
    ];

    return messages.map((msg) => {
      if (msg.role !== "system" && msg.role !== "user") return msg;
      const content = typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content);

      for (const pattern of overridePatterns) {
        if (pattern.test(content)) {
          this.logViolation(
            this.config.context,
            pattern.source,
            content.substring(0, 200),
            "sanitized",
            "Prompt injection attempt detected and neutralized"
          );
          // Replace the override attempt with a safe version
          const sanitized = content.replace(pattern, "[REDACTED: guardrail override attempt]");
          return { ...msg, content: sanitized };
        }
      }

      return msg;
    });
  }

  // ── Post-Response Validation ──────────────────────────────────────────

  /**
   * Validates LLM response content for guardrail compliance.
   * Returns warnings if the response contains potentially dangerous content.
   */
  validateResponse(response: InvokeResult): { valid: boolean; warnings: string[] } {
    const warnings: string[] = [];
    const content = response.choices?.[0]?.message?.content;
    if (!content || typeof content !== "string") return { valid: true, warnings };

    // Check for exploit-like patterns in response
    const dangerousPatterns: Array<{ pattern: RegExp; warning: string }> = [
      { pattern: /\bexec\s*\(\s*['"].*['"].*\)/i, warning: "Response may contain executable code injection" },
      { pattern: /\bsystem\s*\(\s*['"].*['"].*\)/i, warning: "Response may contain system command execution" },
      { pattern: /\b(nc|ncat|netcat)\s+-[elp]/i, warning: "Response may contain netcat reverse shell" },
      { pattern: /\bbash\s+-i\s+>&\s+\/dev\/tcp/i, warning: "Response may contain bash reverse shell" },
      { pattern: /\bpowershell\s+-enc/i, warning: "Response may contain encoded PowerShell payload" },
      { pattern: /\bmsfvenom\b/i, warning: "Response references Metasploit payload generation" },
    ];

    for (const { pattern, warning } of dangerousPatterns) {
      if (pattern.test(content)) {
        warnings.push(warning);
      }
    }

    return { valid: warnings.length === 0, warnings };
  }

  // ── Violation Logging ─────────────────────────────────────────────────

  private logViolation(
    context: GuardrailContext,
    triggerPattern: string,
    originalPrompt: string,
    action: "blocked" | "sanitized" | "warned",
    reason: string
  ): void {
    if (!this.config.logViolations) return;

    const violation: GuardrailViolation = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      context,
      triggerPattern,
      originalPrompt: originalPrompt.substring(0, 500), // Truncate for storage
      action,
      reason,
    };

    this.stats.violations.push(violation);
    // Keep only last 500 violations in memory
    if (this.stats.violations.length > 500) {
      this.stats.violations = this.stats.violations.slice(-500);
    }
  }

  // ── Statistics ────────────────────────────────────────────────────────

  getStats(): GuardrailStats {
    return { ...this.stats };
  }

  getViolations(limit: number = 50): GuardrailViolation[] {
    return this.stats.violations.slice(-limit);
  }

  resetStats(): void {
    this.stats = {
      totalCalls: 0,
      blockedCalls: 0,
      sanitizedCalls: 0,
      warnedCalls: 0,
      violations: [],
    };
  }

  // ── Serialisation ─────────────────────────────────────────────────────

  toJSON() {
    return {
      config: this.config,
      stats: {
        totalCalls: this.stats.totalCalls,
        blockedCalls: this.stats.blockedCalls,
        sanitizedCalls: this.stats.sanitizedCalls,
        warnedCalls: this.stats.warnedCalls,
        violationCount: this.stats.violations.length,
      },
    };
  }
}

// ─── Singleton ──────────────────────────────────────────────────────────────

let _guardrails: LLMGuardrails | null = null;

export function getLLMGuardrails(): LLMGuardrails {
  if (!_guardrails) {
    _guardrails = new LLMGuardrails();
  }
  return _guardrails;
}

export function resetLLMGuardrails(): void {
  _guardrails = null;
}

// ─── Helper: Create guarded invokeLLM wrapper ───────────────────────────────

/**
 * Creates a wrapped version of invokeLLM that automatically applies
 * SSIL guardrails. Use this in routers instead of raw invokeLLM.
 *
 * @example
 * const guardedLLM = createGuardedInvokeLLM(invokeLLM, "detection");
 * const response = await guardedLLM({ messages: [...] });
 */
export function createGuardedInvokeLLM(
  invokeLLM: (params: InvokeParams) => Promise<InvokeResult>,
  context: GuardrailContext = "general"
): (params: InvokeParams) => Promise<InvokeResult> {
  const guardrails = getLLMGuardrails();
  return async (params: InvokeParams) => {
    return guardrails.invokeWithGuardrails(invokeLLM, params, context);
  };
}
