/**
 * Error Sanitizer — strips internal details from error messages
 * before displaying them to users. Prevents leaking:
 * - Internal URLs, IPs, and hostnames
 * - File paths and directory structures
 * - API keys, tokens, and credentials
 * - Database connection strings
 * - Stack traces and code references
 * - Third-party tool names and versions
 */

// Patterns that indicate internal details
const INTERNAL_PATTERNS: Array<{ pattern: RegExp; replacement: string }> = [
  // URLs with internal hostnames/IPs
  { pattern: /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[:\d]*/gi, replacement: '[internal-service]' },
  // Full URLs with paths (external services)
  { pattern: /https?:\/\/[^\s"'`,)}\]]+/gi, replacement: '[service-endpoint]' },
  // File paths
  { pattern: /(?:\/[\w.-]+){2,}/g, replacement: '[internal-path]' },
  // Windows paths
  { pattern: /[A-Z]:\\(?:[\w.-]+\\){1,}/gi, replacement: '[internal-path]' },
  // API keys and tokens (common patterns)
  { pattern: /(?:key|token|secret|password|api[_-]?key|bearer)\s*[:=]\s*['"]?[\w\-./+=]{8,}['"]?/gi, replacement: '[redacted-credential]' },
  // Database connection strings
  { pattern: /(?:mysql|postgres|mongodb|redis|tidb):\/\/[^\s"']+/gi, replacement: '[database-connection]' },
  // Stack trace lines
  { pattern: /\s+at\s+[\w.$]+\s*\([^)]*\)/g, replacement: '' },
  // Node module paths
  { pattern: /node_modules\/[\w@/.-]+/g, replacement: '[module]' },
  // IP addresses
  { pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b/g, replacement: '[network-address]' },
  // HTTP status with body details
  { pattern: /HTTP\s+\d{3}:\s*\{[^}]*\}/gi, replacement: 'Service unavailable' },
  // JSON error bodies
  { pattern: /\{[^}]*"(?:error|message|detail)"[^}]*\}/gi, replacement: '' },
];

// Map of technical error messages to user-friendly versions
const ERROR_FRIENDLY_MAP: Array<{ match: RegExp; friendly: string }> = [
  { match: /ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|fetch failed/i, friendly: 'Service temporarily unavailable. Please try again later.' },
  { match: /UNAUTHORIZED|401|403|FORBIDDEN/i, friendly: 'Authentication required. Please check your session.' },
  { match: /NOT_FOUND|404/i, friendly: 'The requested resource was not found.' },
  { match: /INTERNAL_SERVER_ERROR|500/i, friendly: 'An internal error occurred. Please try again.' },
  { match: /timeout|timed?\s*out|aborted/i, friendly: 'The request timed out. Please try again.' },
  { match: /rate\s*limit|too\s*many\s*requests|429/i, friendly: 'Too many requests. Please wait a moment and try again.' },
  { match: /CONFLICT|409/i, friendly: 'A conflict occurred. The resource may have been modified.' },
  { match: /BAD_REQUEST|400|validation|invalid input/i, friendly: 'Invalid request. Please check your input and try again.' },
  { match: /network\s*error|failed\s*to\s*fetch|ERR_NETWORK/i, friendly: 'Network error. Please check your connection.' },
  { match: /JSON\.parse|Unexpected token|SyntaxError/i, friendly: 'Received an unexpected response. Please try again.' },
];

/**
 * Sanitize an error message to remove internal details
 */
export function sanitizeError(error: unknown): string {
  let message = '';

  if (error instanceof Error) {
    message = error.message;
  } else if (typeof error === 'string') {
    message = error;
  } else if (error && typeof error === 'object' && 'message' in error) {
    message = String((error as any).message);
  } else {
    return 'An unexpected error occurred. Please try again.';
  }

  // Check for friendly error mapping first
  for (const { match, friendly } of ERROR_FRIENDLY_MAP) {
    if (match.test(message)) {
      return friendly;
    }
  }

  // Strip internal patterns
  let sanitized = message;
  for (const { pattern, replacement } of INTERNAL_PATTERNS) {
    sanitized = sanitized.replace(pattern, replacement);
  }

  // Clean up any double spaces or empty results
  sanitized = sanitized.replace(/\s{2,}/g, ' ').trim();

  // If the sanitized message is empty or too short, return generic
  if (!sanitized || sanitized.length < 5) {
    return 'An unexpected error occurred. Please try again.';
  }

  // Truncate overly long messages
  if (sanitized.length > 200) {
    sanitized = sanitized.substring(0, 200) + '...';
  }

  return sanitized;
}

/**
 * Sanitize error for toast notifications (shorter)
 */
export function sanitizeErrorForToast(error: unknown): string {
  const sanitized = sanitizeError(error);
  // Toast messages should be concise
  if (sanitized.length > 100) {
    return sanitized.substring(0, 100) + '...';
  }
  return sanitized;
}

/**
 * Create a safe error handler for tRPC mutation onError callbacks
 */
export function safeErrorHandler(prefix: string) {
  return (err: { message: string }) => {
    const sanitized = sanitizeErrorForToast(err);
    return `${prefix}: ${sanitized}`;
  };
}
