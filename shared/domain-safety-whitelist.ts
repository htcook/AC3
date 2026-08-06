/**
 * Domain Safety Whitelist — Guardrail for Active Scanning & Exploitation
 *
 * Maintains a whitelist of approved domains/IPs that are safe for full-stack
 * pipeline execution (active scanning, exploitation, C2, etc.).
 *
 * Any engagement targeting domains NOT on this whitelist will be restricted
 * to passive-only operations unless an admin explicitly overrides.
 *
 * The whitelist includes:
 *   1. AC3-owned test lab infrastructure (scan.aceofcloud.io, 159.223.152.190)
 *   2. Public intentionally-vulnerable applications (OWASP, Acunetix, etc.)
 *   3. Nmap's official scan-me host
 */

// ─── Approved Test Lab Domains ──────────────────────────────────────────────
// These domains are AC3-owned or publicly authorized for security testing.
// Subdomains of whitelisted domains are automatically included.

export const WHITELISTED_DOMAINS: readonly string[] = [
  // AC3-owned test lab infrastructure
  "scan.aceofcloud.io",
  "aceofcloud.io",
  "aceofcloud.com",

  // Public intentionally-vulnerable web applications
  "testphp.vulnweb.com",       // Acunetix PHP test site
  "testasp.vulnweb.com",       // Acunetix ASP test site
  "testaspnet.vulnweb.com",    // Acunetix ASP.NET test site
  "testhtml5.vulnweb.com",     // Acunetix HTML5 test site
  "rest.vulnweb.com",          // Acunetix REST API test site
  "hackazon.webscantest.com",  // Rapid7 Hackazon
  "www.webscantest.com",       // Rapid7 WebScanTest
  "demo.testfire.net",         // IBM Altoro Mutual
  "brokencrystals.com",        // Broken Crystals
  "ginandjuice.shop",          // PortSwigger Gin & Juice Shop
  "public-firing-range.appspot.com", // Google Firing Range
  "google-gruyere.appspot.com",     // Google Gruyere
  "hack-yourself-first.com",        // Troy Hunt's test site
  "pentest-ground.com",             // Pentest Ground
  "angular.testsparker.com",        // Netsparker Angular
  "aspnet.testsparker.com",         // Netsparker ASP.NET
  "php.testsparker.com",            // Netsparker PHP
  "zero.webappsecurity.com",        // HP Zero Bank

  // Nmap official scan target
  "scanme.nmap.org",

  // Source code hosting platforms (for bug bounty source code audits)
  "github.com",
  "gitlab.com",
  "bitbucket.org",
  "codeberg.org",
  "sr.ht",
] as const;

// ─── Source Code Hosting Platforms ─────────────────────────────────────────
// Domains that host source code repositories. When these appear as targets,
// the asset should be treated as a source code audit (download & build)
// rather than a live web application scan.

export const SOURCE_CODE_HOSTS: readonly string[] = [
  "github.com",
  "gitlab.com",
  "bitbucket.org",
  "codeberg.org",
  "sr.ht",
] as const;

/**
 * Check if a target URL/domain is a source code repository.
 * Returns the repo URL if it is, null otherwise.
 */
export function isSourceCodeTarget(target: string): { isSourceCode: boolean; repoUrl?: string; host?: string } {
  const hostname = extractHostname(target);
  const isSourceCode = SOURCE_CODE_HOSTS.some(h => hostname === h || hostname.endsWith(`.${h}`));
  if (isSourceCode) {
    // Normalize to full URL
    const repoUrl = target.includes('://') ? target : `https://${target}`;
    return { isSourceCode: true, repoUrl, host: hostname };
  }
  return { isSourceCode: false };
}

// ─── Approved Test Lab IPs ──────────────────────────────────────────────────
// IP addresses of AC3-owned test infrastructure.

export const WHITELISTED_IPS: readonly string[] = [
  "159.223.152.190",  // AC3 DigitalOcean test lab droplet
  "159.223.154.80",   // ac3-lab-linux-target (Sprint 11B)
  "104.248.62.133",   // ac3-lab-windows-target (Sprint 11B)
  "157.230.13.143",   // ac3-lab-dmz-target (Sprint 11B)
  "157.245.241.183",  // ac3-lab-internal-target (Sprint 11B)
  "45.33.32.156",     // scanme.nmap.org
] as const;

// ─── Localhost / Private Ranges (always safe) ───────────────────────────────

const SAFE_PRIVATE_PATTERNS = [
  /^127\.\d+\.\d+\.\d+$/,       // Loopback
  /^10\.\d+\.\d+\.\d+$/,        // Class A private
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/, // Class B private
  /^192\.168\.\d+\.\d+$/,       // Class C private
  /^localhost$/i,
  /^::1$/,
];

// ─── Validation Functions ───────────────────────────────────────────────────

/**
 * Extract the hostname from a URL or domain string.
 * Handles: "https://scan.aceofcloud.io/lab/dvwa/", "scan.aceofcloud.io", "http://159.223.152.190:3001"
 */
export function extractHostname(target: string): string {
  let cleaned = target.trim();
  // Strip protocol
  if (cleaned.includes("://")) {
    try {
      const url = new URL(cleaned);
      cleaned = url.hostname;
    } catch {
      cleaned = cleaned.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
    }
  } else {
    // Remove path and port
    cleaned = cleaned.split("/")[0].split(":")[0];
  }
  return cleaned.toLowerCase();
}

/**
 * Check if a single domain/IP is on the safety whitelist.
 * Returns true if the target is approved for active scanning.
 */
export function isDomainWhitelisted(target: string): boolean {
  const hostname = extractHostname(target);
  if (!hostname) return false;

  // Check private/localhost ranges (always safe)
  if (SAFE_PRIVATE_PATTERNS.some(p => p.test(hostname))) return true;

  // Check exact IP match
  if (WHITELISTED_IPS.includes(hostname)) return true;

  // Check domain match (including subdomains)
  for (const whitelisted of WHITELISTED_DOMAINS) {
    if (hostname === whitelisted || hostname.endsWith(`.${whitelisted}`)) {
      return true;
    }
  }

  return false;
}

/**
 * Parse a comma/semicolon/space-separated target string into individual targets.
 */
export function parseTargets(targetString: string): string[] {
  if (!targetString) return [];
  return targetString
    .split(/[,;\s]+/)
    .map(t => t.trim())
    .filter(Boolean);
}

/**
 * Validate all targets in an engagement's targetDomain and targetIpRange fields.
 * Returns a detailed result with per-target status.
 */
export interface DomainValidationResult {
  allWhitelisted: boolean;
  totalTargets: number;
  whitelistedCount: number;
  nonWhitelistedCount: number;
  targets: Array<{
    original: string;
    hostname: string;
    whitelisted: boolean;
  }>;
  nonWhitelistedTargets: string[];
}

export function validateEngagementTargets(
  targetDomain?: string | null,
  targetIpRange?: string | null,
): DomainValidationResult {
  const allTargets: Array<{ original: string; hostname: string; whitelisted: boolean }> = [];

  // Parse domains
  for (const t of parseTargets(targetDomain || "")) {
    const hostname = extractHostname(t);
    allTargets.push({ original: t, hostname, whitelisted: isDomainWhitelisted(t) });
  }

  // Parse IPs
  for (const t of parseTargets(targetIpRange || "")) {
    const hostname = extractHostname(t);
    allTargets.push({ original: t, hostname, whitelisted: isDomainWhitelisted(t) });
  }

  const whitelisted = allTargets.filter(t => t.whitelisted);
  const nonWhitelisted = allTargets.filter(t => !t.whitelisted);

  return {
    allWhitelisted: nonWhitelisted.length === 0 && allTargets.length > 0,
    totalTargets: allTargets.length,
    whitelistedCount: whitelisted.length,
    nonWhitelistedCount: nonWhitelisted.length,
    targets: allTargets,
    nonWhitelistedTargets: nonWhitelisted.map(t => t.hostname),
  };
}

/**
 * Get a human-readable safety warning message for non-whitelisted targets.
 */
export function getSafetyWarning(validation: DomainValidationResult): string | null {
  if (validation.allWhitelisted) return null;
  if (validation.totalTargets === 0) return null;

  const nonWL = validation.nonWhitelistedTargets;
  return (
    `⚠️ SAFETY GUARDRAIL: ${nonWL.length} target(s) are NOT on the approved test lab whitelist: ` +
    `${nonWL.join(", ")}. ` +
    `Active scanning, exploitation, and C2 operations are BLOCKED for non-whitelisted domains. ` +
    `Only passive reconnaissance (OSINT, DNS, certificate transparency) is permitted. ` +
    `An admin can override this restriction if a signed RoE authorizes active testing on these targets.`
  );
}
