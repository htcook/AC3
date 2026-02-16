/**
 * Passive Policy Guard — Scan Mode Enforcement
 * 
 * Enforces scan mode policies to ensure the pipeline stays within
 * the user's chosen aggressiveness level:
 * 
 * - strict_passive: Only query third-party databases (crt.sh, Shodan, Wayback, etc.)
 *   NO DNS resolution, NO direct connections to target infrastructure
 * 
 * - standard: Third-party databases + DNS resolution + well-known endpoint checks
 *   (e.g., /.well-known/security.txt, robots.txt)
 * 
 * - active: All of the above + banner grabbing, port probing, direct HTTP requests
 *   (Note: active mode uses the existing pipeline's DNS/banner verification)
 */

import type { ScanMode, PassivePolicyConfig, PassiveConnector } from "./types";

// Connectors that only query third-party databases (never touch target infra)
const STRICT_PASSIVE_CONNECTORS = new Set([
  "crtsh",
  "shodan",
  "censys",
  "wayback",
  "urlscan",
  "securitytrails",
]);

// Connectors that perform DNS resolution (touch DNS infrastructure)
const DNS_RESOLUTION_CONNECTORS = new Set([
  "ripestat",  // Resolves domain to IP before querying RIPEstat
]);

// Connectors that query registration databases (touch RDAP/WHOIS servers)
const REGISTRATION_CONNECTORS = new Set([
  "rdap",
]);

/**
 * Get the default policy for a scan mode
 */
export function getDefaultPolicy(scanMode: ScanMode): PassivePolicyConfig {
  switch (scanMode) {
    case "strict_passive":
      return {
        scanMode,
        allowDnsResolution: false,
        allowWellKnownFetch: false,
        allowedNetlocs: new Set([
          "crt.sh",
          "api.shodan.io",
          "search.censys.io",
          "web.archive.org",
          "urlscan.io",
          "api.securitytrails.com",
        ]),
      };
    case "standard":
      return {
        scanMode,
        allowDnsResolution: true,
        allowWellKnownFetch: true,
        allowedNetlocs: new Set([
          "crt.sh",
          "api.shodan.io",
          "search.censys.io",
          "web.archive.org",
          "urlscan.io",
          "api.securitytrails.com",
          "rdap.org",
          "stat.ripe.net",
        ]),
      };
    case "active":
      return {
        scanMode,
        allowDnsResolution: true,
        allowWellKnownFetch: true,
        allowedNetlocs: new Set(), // Empty = allow all
      };
  }
}

/**
 * Filter connectors based on scan mode policy
 */
export function filterConnectors(
  connectors: PassiveConnector[],
  scanMode: ScanMode
): { allowed: PassiveConnector[]; blocked: { name: string; reason: string }[] } {
  const allowed: PassiveConnector[] = [];
  const blocked: { name: string; reason: string }[] = [];

  for (const connector of connectors) {
    switch (scanMode) {
      case "strict_passive":
        if (STRICT_PASSIVE_CONNECTORS.has(connector.name)) {
          allowed.push(connector);
        } else if (DNS_RESOLUTION_CONNECTORS.has(connector.name)) {
          blocked.push({ name: connector.name, reason: "Requires DNS resolution (not allowed in strict passive mode)" });
        } else if (REGISTRATION_CONNECTORS.has(connector.name)) {
          blocked.push({ name: connector.name, reason: "Queries registration databases directly (not allowed in strict passive mode)" });
        } else {
          blocked.push({ name: connector.name, reason: "Not classified as strict passive connector" });
        }
        break;

      case "standard":
        // Standard mode allows all passive connectors
        allowed.push(connector);
        break;

      case "active":
        // Active mode allows everything
        allowed.push(connector);
        break;
    }
  }

  return { allowed, blocked };
}

/**
 * Get human-readable description of what each scan mode does
 */
export function getScanModeDescription(scanMode: ScanMode): {
  label: string;
  description: string;
  techniques: string[];
  restrictions: string[];
} {
  switch (scanMode) {
    case "strict_passive":
      return {
        label: "Strict Passive",
        description: "Only queries third-party databases. Never touches target infrastructure directly. Zero risk of detection.",
        techniques: [
          "Certificate Transparency log search (crt.sh)",
          "Shodan pre-scanned database lookup",
          "Censys internet-wide scan database query",
          "Wayback Machine historical URL archive search",
          "urlscan.io community scan database search",
          "SecurityTrails DNS intelligence API",
        ],
        restrictions: [
          "No DNS resolution against target nameservers",
          "No direct HTTP/HTTPS connections to target",
          "No RDAP/WHOIS queries for target domain",
          "No banner grabbing or port probing",
        ],
      };
    case "standard":
      return {
        label: "Standard",
        description: "Queries third-party databases plus DNS resolution and registration lookups. Minimal footprint on target infrastructure.",
        techniques: [
          "All strict passive techniques",
          "DNS A/AAAA/MX/NS/TXT record resolution",
          "RDAP domain registration lookup",
          "RIPEstat ASN and prefix analysis",
          "Well-known endpoint checks (security.txt, robots.txt)",
        ],
        restrictions: [
          "No active port scanning",
          "No banner grabbing beyond well-known endpoints",
          "No vulnerability probing",
        ],
      };
    case "active":
      return {
        label: "Active",
        description: "Full reconnaissance including direct connections to target infrastructure. Includes banner grabbing and service identification.",
        techniques: [
          "All standard techniques",
          "Direct HTTP/HTTPS banner grabbing",
          "Service version identification",
          "TLS certificate inspection",
          "LLM-powered asset discovery",
        ],
        restrictions: [
          "No destructive actions",
          "No exploitation attempts",
          "No brute-force attacks",
        ],
      };
  }
}
