/**
 * SSRF guard for user-supplied fetch targets (webhook URLs, live-probe URLs,
 * tech-detection targets, etc.).
 *
 * The platform is a scanner and legitimately makes outbound HTTP requests, but
 * user-controlled URLs must not be pointable at internal infrastructure or the
 * cloud metadata endpoint (169.254.169.254). This validates the scheme and
 * blocks literal internal IPs, then resolves the hostname and blocks it if any
 * resolved address is loopback/private/link-local/reserved.
 */

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata",
]);

/** True if an IPv4/IPv6 literal is loopback, private, link-local, or reserved. */
export function isPrivateOrReservedIp(ip: string): boolean {
  const addr = ip.replace(/^\[|\]$/g, "").toLowerCase();

  // IPv6
  if (addr.includes(":")) {
    if (addr === "::1" || addr === "::") return true;
    if (addr.startsWith("fe80")) return true;          // link-local
    if (addr.startsWith("fc") || addr.startsWith("fd")) return true; // unique-local
    // IPv4-mapped IPv6 (::ffff:a.b.c.d)
    const mapped = addr.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateOrReservedIp(mapped[1]);
    return false;
  }

  // IPv4
  const parts = addr.split(".").map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return false; // not an IPv4 literal
  }
  const [a, b] = parts;
  if (a === 127) return true;                          // loopback
  if (a === 10) return true;                           // private
  if (a === 0) return true;                            // "this" network
  if (a === 169 && b === 254) return true;             // link-local + metadata
  if (a === 172 && b >= 16 && b <= 31) return true;    // private
  if (a === 192 && b === 168) return true;             // private
  if (a === 100 && b >= 64 && b <= 127) return true;   // carrier-grade NAT
  if (a >= 224) return true;                           // multicast / reserved
  return false;
}

/**
 * Validate a user-supplied URL for outbound fetch. Throws when the URL is not
 * http(s), targets a blocked hostname, or resolves to an internal address.
 * Returns the parsed URL when safe.
 */
export async function assertSafeFetchUrl(rawUrl: string): Promise<URL> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http(s) URLs are allowed");
  }

  const host = url.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.has(host)) {
    throw new Error("URL targets a blocked host");
  }

  // Literal IP in the URL — check directly.
  if (isPrivateOrReservedIp(host)) {
    throw new Error("URL targets an internal or reserved IP address");
  }

  // Resolve the hostname and block if ANY resolved address is internal.
  // This defends against names that point at internal ranges. (It does not
  // fully prevent DNS-rebinding, which would require pinning the resolved IP
  // through to the socket; it raises the bar substantially.)
  try {
    const dns = await import("dns");
    const { lookup } = dns.promises;
    const results = await lookup(host, { all: true });
    for (const { address } of results) {
      if (isPrivateOrReservedIp(address)) {
        throw new Error("URL resolves to an internal or reserved IP address");
      }
    }
  } catch (err: any) {
    // Re-throw our own block errors; tolerate genuine resolution failures
    // (the fetch will fail naturally) so we don't break offline/dev use.
    if (err?.message?.includes("internal or reserved")) throw err;
  }

  return url;
}
