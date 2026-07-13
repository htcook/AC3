/**
 * Shell / filesystem input-safety helpers.
 *
 * Many scan and cloud integrations build shell command STRINGS that are then
 * executed on a remote scan/exploit host (see scan-server-executor.ts →
 * executeViaChildProcessSSH, which passes the string to `ssh` as the remote
 * command). Any unescaped interpolation of user/engagement-controlled input
 * into those strings is remote command injection.
 *
 * The executor takes a single command string (not an argv array), so we cannot
 * rely on argv separation. Instead:
 *   - shq()          — POSIX single-quote escape a value so it is exactly one
 *                      shell word with no metacharacter interpretation.
 *   - assertSafe*()  — reject values that must match a strict format (defense
 *                      in depth for tokens that are used unquoted, or that
 *                      should never contain exotic characters).
 *   - assertWithinDir() — path-traversal containment for filesystem reads.
 */

/**
 * POSIX-safe single-quote escaping. The returned string is safe to splice into
 * a shell command as a single argument: it is wrapped in single quotes and any
 * embedded single quote is closed/escaped/reopened ('\'').
 */
export function shq(value: string | number): string {
  const s = String(value);
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/**
 * Reject a value that contains shell metacharacters. Use for tokens that are
 * interpolated UNQUOTED (e.g. joined flag lists) where shq() is not applied.
 * Returns the value unchanged when safe; throws otherwise.
 */
export function assertNoShellMeta(value: string, label = "value"): string {
  // Disallow anything that could break out of, or extend, a shell word.
  if (/[;&|`$(){}<>\n\r\t\\'"\s*?~!#]/.test(value)) {
    throw new Error(`Unsafe characters in ${label}`);
  }
  return value;
}

/**
 * Validate a scan target (hostname, IP, or IP:port). Allows letters, digits,
 * dot, colon, hyphen, and brackets (IPv6). Rejects everything else, so it can
 * never contain shell metacharacters or whitespace.
 */
export function assertSafeHostname(value: string, label = "target"): string {
  if (!value || value.length > 253 || !/^[A-Za-z0-9._:\-\[\]]+$/.test(value)) {
    throw new Error(`Invalid ${label}: contains disallowed characters`);
  }
  return value;
}

/**
 * Validate a container image reference (registry/name:tag@digest). Allows the
 * standard OCI reference character set only.
 */
export function assertSafeImageRef(value: string, label = "image"): string {
  if (!value || value.length > 512 || !/^[A-Za-z0-9._:@\/\-]+$/.test(value)) {
    throw new Error(`Invalid ${label}: contains disallowed characters`);
  }
  return value;
}

/**
 * Validate a cloud identifier such as an AWS role ARN / external id, a GCP
 * project id, or an Azure subscription id. These are used as command flags and
 * must never contain shell metacharacters.
 */
export function assertSafeCloudId(value: string, label = "identifier"): string {
  if (!value || value.length > 2048 || !/^[A-Za-z0-9._:@\/\-]+$/.test(value)) {
    throw new Error(`Invalid ${label}: contains disallowed characters`);
  }
  return value;
}

/**
 * Validate a value against an explicit allowlist (case-sensitive). Throws when
 * the value is not a member.
 */
export function assertAllowed<T extends string>(
  value: string,
  allowed: readonly T[],
  label = "value"
): T {
  if (!(allowed as readonly string[]).includes(value)) {
    throw new Error(`Invalid ${label}: not an allowed value`);
  }
  return value as T;
}

/**
 * Path-traversal containment. Resolves `candidate` (which may be relative to
 * `baseDir`) and throws unless the result stays inside `baseDir`. Returns the
 * resolved absolute path when safe.
 */
export async function assertWithinDir(baseDir: string, candidate: string): Promise<string> {
  const path = await import("path");
  const base = path.resolve(baseDir);
  const resolved = path.resolve(base, candidate);
  if (resolved !== base && !resolved.startsWith(base + path.sep)) {
    throw new Error("Path escapes the permitted directory");
  }
  return resolved;
}
