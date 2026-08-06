/**
 * Centralized LLM JSON Parsing Utility
 *
 * Provides a single, battle-tested JSON parsing pipeline for all LLM specialist
 * responses. Consolidates the various ad-hoc parsing patterns scattered across
 * the codebase into one utility with:
 *
 * 1. Markdown code fence stripping
 * 2. Leading/trailing garbage removal
 * 3. Common LLM JSON malformation repairs (trailing commas, single quotes, etc.)
 * 4. Structured error reporting with raw content excerpt
 * 5. Type-safe fallback values
 *
 * Usage:
 *   import { parseLLMJson } from "../../shared/llm-json-parser";
 *   const result = parseLLMJson<MyType>(llmContent, { fallback: { items: [] } });
 *   if (result.ok) { use(result.data); } else { handle(result.error); }
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ParseSuccess<T> {
  ok: true;
  data: T;
  repaired: boolean;  // True if JSON required repair before parsing
}

export interface ParseFailure {
  ok: false;
  error: string;
  rawExcerpt: string; // First 500 chars of raw content for debugging
}

export type ParseResult<T> = ParseSuccess<T> | ParseFailure;

export interface ParseOptions<T> {
  /** Fallback value returned when parsing fails. If not provided, returns ParseFailure. */
  fallback?: T;
  /** Optional label for error logging (e.g., specialist name) */
  label?: string;
  /** If true, suppresses console.error on failure */
  silent?: boolean;
}

// ─── Core Sanitization ────────────────────────────────────────────────────────

/**
 * Strip markdown code fences and find the JSON payload in LLM output.
 */
export function sanitizeLLMJson(raw: string): string {
  let s = raw.trim();

  // Strip markdown code fences (```json ... ``` or ``` ... ```)
  if (s.startsWith('```')) {
    s = s.replace(/^```(?:json|JSON|js|typescript)?\s*\n?/, '').replace(/\n?```\s*$/, '');
  }

  s = s.trim();

  // If it doesn't start with { or [, try to find the first JSON structure
  if (!s.startsWith('{') && !s.startsWith('[')) {
    const objIdx = s.indexOf('{');
    const arrIdx = s.indexOf('[');
    if (objIdx >= 0 && (arrIdx < 0 || objIdx < arrIdx)) {
      s = s.substring(objIdx);
    } else if (arrIdx >= 0) {
      s = s.substring(arrIdx);
    }
  }

  // Trim trailing garbage after the last } or ]
  const lastBrace = s.lastIndexOf('}');
  const lastBracket = s.lastIndexOf(']');
  const lastClose = Math.max(lastBrace, lastBracket);
  if (lastClose > 0 && lastClose < s.length - 1) {
    s = s.substring(0, lastClose + 1);
  }

  return s;
}

/**
 * Attempt common JSON repairs for LLM output malformations.
 * Returns { repaired: string, wasRepaired: boolean }
 */
export function repairLLMJson(sanitized: string): { repaired: string; wasRepaired: boolean } {
  let s = sanitized;
  let wasRepaired = false;

  // Fix 1: Trailing commas before } or ]
  const trailingCommaRegex = /,\s*([}\]])/g;
  if (trailingCommaRegex.test(s)) {
    s = s.replace(trailingCommaRegex, '$1');
    wasRepaired = true;
  }

  // Fix 2: Single quotes used as string delimiters (only if no double quotes present in values)
  // This is risky so we only do it if the string doesn't parse as-is
  // and contains patterns like {'key': 'value'}
  if (/'\w+':\s*'/.test(s) && !/"/.test(s)) {
    s = s.replace(/'/g, '"');
    wasRepaired = true;
  }

  // Fix 3: Unquoted keys (JavaScript object literal style)
  // Match patterns like { key: "value" } and convert to { "key": "value" }
  const unquotedKeyRegex = /([{,]\s*)([a-zA-Z_$][a-zA-Z0-9_$]*)(\s*:)/g;
  if (unquotedKeyRegex.test(s)) {
    s = s.replace(unquotedKeyRegex, '$1"$2"$3');
    wasRepaired = true;
  }

  // Fix 4: NaN and Infinity (not valid JSON)
  if (/\bNaN\b/.test(s)) {
    s = s.replace(/\bNaN\b/g, 'null');
    wasRepaired = true;
  }
  if (/\bInfinity\b/.test(s)) {
    s = s.replace(/\bInfinity\b/g, '999999');
    wasRepaired = true;
  }
  if (/\b-Infinity\b/.test(s)) {
    s = s.replace(/\b-Infinity\b/g, '-999999');
    wasRepaired = true;
  }

  // Fix 5: Comments (// and /* */)
  if (/\/\/.*$/m.test(s) || /\/\*[\s\S]*?\*\//.test(s)) {
    s = s.replace(/\/\/.*$/gm, '');
    s = s.replace(/\/\*[\s\S]*?\*\//g, '');
    wasRepaired = true;
  }

  return { repaired: s, wasRepaired };
}

// ─── Main Parser ──────────────────────────────────────────────────────────────

/**
 * Parse LLM response content as JSON with sanitization, repair, and fallback.
 *
 * @param content - Raw LLM response content (string or unknown)
 * @param options - Parse options including fallback, label, and silent mode
 * @returns ParseResult<T> with either parsed data or error info
 *
 * @example
 * // With fallback (never throws, always returns data)
 * const { data } = parseLLMJson<MyType>(content, { fallback: { items: [] } });
 *
 * @example
 * // Without fallback (returns ok/error discriminated union)
 * const result = parseLLMJson<MyType>(content, { label: 'OpsDecider' });
 * if (!result.ok) { console.error(result.error); return; }
 * use(result.data);
 */
export function parseLLMJson<T = any>(
  content: unknown,
  options: ParseOptions<T> & { fallback: T }
): ParseSuccess<T>;
export function parseLLMJson<T = any>(
  content: unknown,
  options?: ParseOptions<T>
): ParseResult<T>;
export function parseLLMJson<T = any>(
  content: unknown,
  options: ParseOptions<T> = {}
): ParseResult<T> {
  const raw = String(content || '{}');
  const label = options.label || 'LLM';

  // Step 1: Sanitize
  const sanitized = sanitizeLLMJson(raw);

  // Step 2: Try direct parse
  try {
    const data = JSON.parse(sanitized) as T;
    return { ok: true, data, repaired: false };
  } catch {
    // Continue to repair
  }

  // Step 3: Try with repairs
  const { repaired, wasRepaired } = repairLLMJson(sanitized);
  if (wasRepaired) {
    try {
      const data = JSON.parse(repaired) as T;
      return { ok: true, data, repaired: true };
    } catch {
      // Fall through to failure
    }
  }

  // Step 4: Failure
  const rawExcerpt = raw.substring(0, 500);
  const error = `[${label}] JSON parse failed after sanitization and repair`;

  if (!options.silent) {
    console.error(`${error}. Raw excerpt: ${rawExcerpt}`);
  }

  if (options.fallback !== undefined) {
    return { ok: true, data: options.fallback, repaired: false };
  }

  return { ok: false, error, rawExcerpt };
}

// ─── Legacy Compatibility ─────────────────────────────────────────────────────

/**
 * Drop-in replacement for the old safeParseLLMJson pattern.
 * Always returns a value (either parsed or fallback).
 */
export function safeParseLLMJson<T = any>(content: unknown, fallback: T): T {
  const result = parseLLMJson<T>(content, { fallback });
  return result.data;
}

/**
 * Drop-in replacement for the old sanitizeJsonResponse pattern.
 */
export function sanitizeJsonResponse(raw: string): string {
  return sanitizeLLMJson(raw);
}
