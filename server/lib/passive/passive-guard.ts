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
  // Original core connectors (query pre-scanned databases only)
  "crtsh",               // Certificate Transparency logs
  "shodan",              // Shodan pre-scanned database
  "shodan_internetdb",   // Free fast-path — queries pre-scanned database only
  "censys",              // Censys pre-scanned database
  "wayback",             // Wayback Machine historical archive
  "urlscan",             // URLScan.io community scan database
  "securitytrails",      // SecurityTrails DNS intelligence API
  "dehashed",            // DeHashed breach database
  "coalition_control",   // Coalition Control ASM — replaces BinaryEdge (shut down March 2025)
  // Third-party API connectors (never touch target infrastructure)
  "virustotal",          // VirusTotal — file/URL/domain reputation database
  "hibp",                // Have I Been Pwned — breach exposure database
  "whoisxml",            // WhoisXML API — WHOIS records + subdomain enum (queries WhoisXML, not target WHOIS)
  "leakix",              // LeakIX — exposed services & data leaks (pre-scanned database)
  "fullhunt",            // FullHunt — attack surface discovery (pre-scanned database)
  "netlas",              // Netlas.io — internet-wide host scanning (pre-scanned database)
  "hunter",              // Hunter.io — email discovery (queries Hunter's database)
  "social-media",        // Social media — GitHub org/user presence (queries GitHub API)
  "abuseipdb",           // AbuseIPDB — IP abuse reputation (queries AbuseIPDB database)
  "passivetotal",        // PassiveTotal — passive DNS, SSL history (queries RiskIQ database)
  "github_leaks",        // GitHub code leak scanner (queries GitHub search API)
  "github_recon",        // GitHub org/repo/CI-CD exposure (queries GitHub API)
  "cloud_assets",        // Cloud storage enumeration (queries cloud provider APIs, not target)
  // NOTE: binaryedge removed — API shut down March 31, 2025
  // --- OSINT Pipeline Expansion (Gap Analysis v2) ---
  "intelx_search",       // Intelligence X — queries IntelX database (never touches target)
  "hudson_rock",         // Hudson Rock — queries stealer log database (never touches target)
  "leakcheck",           // LeakCheck — queries credential leak database (never touches target)
  "company_intel",       // Company Intelligence — web scraping + LLM (queries public web, not target infra)
  "threatminer",         // ThreatMiner — queries ThreatMiner database (passive)
  "ip_api",              // ip-api.com — queries IP geolocation database (passive)
  "bgpview",             // BGPView — queries ASN/BGP database (passive)
  "ransomware_live",     // Ransomware.live — queries ransomware victim database (passive)
  "threatfox",           // ThreatFox — queries IOC database (passive)
  "builtwith",           // BuiltWith — queries tech stack database (passive)
  "circl_pdns",          // CIRCL Passive DNS — queries historical DNS database (passive)
  "commoncrawl",         // CommonCrawl — queries historical web crawl database (passive)
  "reverse_whois",       // Reverse WHOIS — queries crt.sh for related domains (passive)
]);

// Connectors that perform DNS resolution (touch DNS infrastructure)
// These are allowed in 'standard' mode but blocked in 'strict_passive'
const DNS_RESOLUTION_CONNECTORS = new Set([
  "ripestat",          // Resolves domain to IP before querying RIPEstat
  "greynoise",         // Resolves domain to IP before querying GreyNoise
  "email_security",    // DNS resolution for SPF/DKIM/DMARC records
  "dns_deep",          // Comprehensive DNS record resolution (A/AAAA/MX/NS/TXT/SOA/CAA)
  "typosquat",         // Typosquat Generator — performs DNS resolution to check domain availability
]);

// Connectors that query registration databases or make direct contact
// These are allowed in 'standard' mode but blocked in 'strict_passive'
const REGISTRATION_CONNECTORS = new Set([
  "rdap",              // Queries RDAP/WHOIS servers directly
]);

// Connectors that make direct HTTP contact with target infrastructure
// These are only allowed in 'active' mode
const ACTIVE_CONTACT_CONNECTORS = new Set([
  "http_security",       // Direct HTTPS to target (security headers, WAF detection)
  "container-discovery", // Direct HTTP probes to target ports (Docker/K8s/registries)
  "cloud_bucket_recon",  // Direct HTTP probes to cloud provider bucket URLs
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
          "api.dehashed.com",
          "internetdb.shodan.io",
          "api.binaryedge.io",
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
          "api.dehashed.com",
          "rdap.org",
          "stat.ripe.net",
          "internetdb.shodan.io",
          "api.binaryedge.io",
          "api.greynoise.io",
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
        } else if (ACTIVE_CONTACT_CONNECTORS.has(connector.name)) {
          blocked.push({ name: connector.name, reason: "Makes direct HTTP contact with target infrastructure (not allowed in strict passive mode)" });
        } else {
          blocked.push({ name: connector.name, reason: "Not classified as strict passive connector" });
        }
        break;

      case "standard":
        // Standard mode allows passive + DNS resolution + registration, but blocks active contact
        if (ACTIVE_CONTACT_CONNECTORS.has(connector.name)) {
          blocked.push({ name: connector.name, reason: "Makes direct HTTP contact with target infrastructure (not allowed in standard mode)" });
        } else {
          allowed.push(connector);
        }
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
        description: "Only queries third-party databases and pre-scanned indexes. Never touches target infrastructure directly. Zero risk of detection.",
        techniques: [
          "Certificate Transparency log search (crt.sh)",
          "Shodan pre-scanned database lookup + InternetDB fast-path CVE/port enrichment",
          "Censys internet-wide scan database query",
          "Wayback Machine historical URL archive search",
          "urlscan.io community scan database search",
          "SecurityTrails DNS intelligence API",
          "DeHashed breach intelligence & domain mapping",
          "Coalition Control ASM (replaces BinaryEdge)",
          "VirusTotal domain/URL reputation & malware analysis",
          "Have I Been Pwned breach exposure & credential leaks",
          "WhoisXML WHOIS records & subdomain enumeration",
          "LeakIX exposed services & data leaks",
          "FullHunt attack surface discovery",
          "Netlas.io internet-wide host scanning & DNS history",
          "Hunter.io email discovery & org intelligence",
          "Social media (GitHub org/user presence & code exposure)",
          "AbuseIPDB IP abuse reputation scoring",
          "PassiveTotal passive DNS, SSL history, host attributes",
          "GitHub code leak scanner (secrets, env files, API keys)",
          "GitHub org/repo/CI-CD exposure recon",
          "Cloud storage enumeration (S3/Azure/GCP bucket discovery)",
        ],
        restrictions: [
          "No DNS resolution against target nameservers",
          "No direct HTTP/HTTPS connections to target",
          "No RDAP/WHOIS queries for target domain",
          "No banner grabbing or port probing",
          "No cloud bucket permission probing",
        ],
      };
    case "standard":
      return {
        label: "Standard",
        description: "All passive techniques plus DNS resolution, registration lookups, and email security checks. Minimal footprint on target infrastructure.",
        techniques: [
          "All strict passive techniques (23 connectors)",
          "DNS A/AAAA/MX/NS/TXT/SOA/CAA record resolution (deep DNS analysis)",
          "Email security posture (SPF/DKIM/DMARC validation)",
          "RDAP domain registration lookup",
          "RIPEstat ASN and prefix analysis",
          "GreyNoise threat pressure analysis (IP classification & active attack detection)",
        ],
        restrictions: [
          "No direct HTTP/HTTPS connections to target",
          "No active port scanning",
          "No banner grabbing or service probing",
          "No cloud bucket permission probing",
        ],
      };
    case "active":
      return {
        label: "Active",
        description: "Full reconnaissance including direct connections to target infrastructure. Includes banner grabbing, service identification, and cloud bucket probing.",
        techniques: [
          "All standard techniques (27 connectors)",
          "HTTP security header analysis & WAF detection",
          "Container infrastructure discovery (Docker/K8s/registries)",
          "Cloud bucket permission probing (S3/Azure/GCP depth scan)",
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
