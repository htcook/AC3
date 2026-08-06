/**
 * Safe string utilities for rendering dynamic data from the database.
 * Prevents crashes when fields are unexpectedly null, undefined, or non-string types.
 */

/** Safely convert any value to uppercase string. Returns fallback if value is nullish. */
export function safeUpper(val: unknown, fallback = "UNKNOWN"): string {
  if (val == null) return fallback;
  return String(val).toUpperCase();
}

/** Safely convert any value to a display string with optional replace. */
export function safeDisplay(val: unknown, fallback = "—"): string {
  if (val == null || val === "") return fallback;
  return String(val);
}

/** Safely format a confidence value (int 0-100) to a display string. */
export function safeConfidence(val: unknown): string {
  if (val == null) return "N/A";
  const n = Number(val);
  if (isNaN(n)) return String(val);
  return `${n}%`;
}
