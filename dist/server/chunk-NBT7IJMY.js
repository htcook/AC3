import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/passive/passive-guard.ts
function getDefaultPolicy(scanMode) {
  switch (scanMode) {
    case "strict_passive":
      return {
        scanMode,
        allowDnsResolution: false,
        allowWellKnownFetch: false,
        allowedNetlocs: /* @__PURE__ */ new Set([
          "crt.sh",
          "api.shodan.io",
          "search.censys.io",
          "web.archive.org",
          "urlscan.io",
          "api.securitytrails.com",
          "api.dehashed.com",
          "internetdb.shodan.io",
          "api.binaryedge.io"
        ])
      };
    case "standard":
      return {
        scanMode,
        allowDnsResolution: true,
        allowWellKnownFetch: true,
        allowedNetlocs: /* @__PURE__ */ new Set([
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
          "api.greynoise.io"
        ])
      };
    case "active":
      return {
        scanMode,
        allowDnsResolution: true,
        allowWellKnownFetch: true,
        allowedNetlocs: /* @__PURE__ */ new Set()
        // Empty = allow all
      };
  }
}
function filterConnectors(connectors, scanMode) {
  const allowed = [];
  const blocked = [];
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
        if (ACTIVE_CONTACT_CONNECTORS.has(connector.name)) {
          blocked.push({ name: connector.name, reason: "Makes direct HTTP contact with target infrastructure (not allowed in standard mode)" });
        } else {
          allowed.push(connector);
        }
        break;
      case "active":
        allowed.push(connector);
        break;
    }
  }
  return { allowed, blocked };
}
function getScanModeDescription(scanMode) {
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
          "Free subdomain enumeration (Anubis, HackerTarget, RapidDNS, DNSRepo, Sitedossier)",
          "Wayback Diff historical content analysis",
          "abuse.ch family (URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker, SSLBL)",
          "CISA Advisories (KEV catalog + ICS advisories)",
          "OSV.dev open source vulnerability database",
          "GitHub Security Advisories (GHSA)",
          "Certspotter CT log monitoring",
          "Business intelligence (SEC EDGAR, Companies House, OpenCorporates)",
          "HC3 healthcare sector threat intelligence"
        ],
        restrictions: [
          "No DNS resolution against target nameservers",
          "No direct HTTP/HTTPS connections to target",
          "No RDAP/WHOIS queries for target domain",
          "No banner grabbing or port probing",
          "No cloud bucket permission probing",
          "No TLS fingerprinting (JARM) or zone transfer attempts"
        ]
      };
    case "standard":
      return {
        label: "Standard",
        description: "All passive techniques plus DNS resolution, registration lookups, and email security checks. Minimal footprint on target infrastructure.",
        techniques: [
          "All strict passive techniques (50+ connectors)",
          "DNS A/AAAA/MX/NS/TXT/SOA/CAA record resolution (deep DNS analysis)",
          "Email security posture (SPF/DKIM/DMARC validation)",
          "RDAP domain registration lookup",
          "RIPEstat ASN and prefix analysis",
          "GreyNoise threat pressure analysis (IP classification & active attack detection)"
        ],
        restrictions: [
          "No direct HTTP/HTTPS connections to target",
          "No active port scanning",
          "No banner grabbing or service probing",
          "No cloud bucket permission probing"
        ]
      };
    case "active":
      return {
        label: "Active",
        description: "Full reconnaissance including direct connections to target infrastructure. Includes banner grabbing, service identification, and cloud bucket probing.",
        techniques: [
          "All standard techniques (55+ connectors)",
          "HTTP security header analysis & WAF detection",
          "Container infrastructure discovery (Docker/K8s/registries)",
          "Cloud bucket permission probing (S3/Azure/GCP depth scan)",
          "Direct HTTP/HTTPS banner grabbing",
          "Service version identification",
          "TLS certificate inspection",
          "JARM TLS fingerprinting (10 probe packets per host)",
          "Favicon hash infrastructure discovery",
          "DNS zone transfer (AXFR) attempts",
          "LLM-powered asset discovery"
        ],
        restrictions: [
          "No destructive actions",
          "No exploitation attempts",
          "No brute-force attacks"
        ]
      };
  }
}
var STRICT_PASSIVE_CONNECTORS, DNS_RESOLUTION_CONNECTORS, REGISTRATION_CONNECTORS, ACTIVE_CONTACT_CONNECTORS;
var init_passive_guard = __esm({
  "server/lib/passive/passive-guard.ts"() {
    STRICT_PASSIVE_CONNECTORS = /* @__PURE__ */ new Set([
      // Original core connectors (query pre-scanned databases only)
      "crtsh",
      // Certificate Transparency logs
      "shodan",
      // Shodan pre-scanned database
      "shodan_internetdb",
      // Free fast-path — queries pre-scanned database only
      "censys",
      // Censys pre-scanned database
      "wayback",
      // Wayback Machine historical archive
      "urlscan",
      // URLScan.io community scan database
      "securitytrails",
      // SecurityTrails DNS intelligence API
      "dehashed",
      // DeHashed breach database
      "coalition_control",
      // Coalition Control ASM — replaces BinaryEdge (shut down March 2025)
      // Third-party API connectors (never touch target infrastructure)
      "virustotal",
      // VirusTotal — file/URL/domain reputation database
      "hibp",
      // Have I Been Pwned — breach exposure database
      "whoisxml",
      // WhoisXML API — WHOIS records + subdomain enum (queries WhoisXML, not target WHOIS)
      "leakix",
      // LeakIX — exposed services & data leaks (pre-scanned database)
      "fullhunt",
      // FullHunt — attack surface discovery (pre-scanned database)
      "netlas",
      // Netlas.io — internet-wide host scanning (pre-scanned database)
      "hunter",
      // Hunter.io — email discovery (queries Hunter's database)
      "social-media",
      // Social media — GitHub org/user presence (queries GitHub API)
      "abuseipdb",
      // AbuseIPDB — IP abuse reputation (queries AbuseIPDB database)
      "passivetotal",
      // PassiveTotal — passive DNS, SSL history (queries RiskIQ database)
      "github_leaks",
      // GitHub code leak scanner (queries GitHub search API)
      "github_recon",
      // GitHub org/repo/CI-CD exposure (queries GitHub API)
      "cloud_assets",
      // Cloud storage enumeration (queries cloud provider APIs, not target)
      // NOTE: binaryedge removed — API shut down March 31, 2025
      // --- OSINT Pipeline Expansion (Gap Analysis v2) ---
      "intelx_search",
      // Intelligence X — queries IntelX database (never touches target)
      "hudson_rock",
      // Hudson Rock — queries stealer log database (never touches target)
      "leakcheck",
      // LeakCheck — queries credential leak database (never touches target)
      "company_intel",
      // Company Intelligence — web scraping + LLM (queries public web, not target infra)
      "threatminer",
      // ThreatMiner — queries ThreatMiner database (passive)
      "ip_api",
      // ip-api.com — queries IP geolocation database (passive)
      "bgpview",
      // BGPView — queries ASN/BGP database (passive)
      "ransomware_live",
      // Ransomware.live — queries ransomware victim database (passive)
      "threatfox",
      // ThreatFox — queries IOC database (passive)
      "builtwith",
      // BuiltWith — queries tech stack database (passive)
      "circl_pdns",
      // CIRCL Passive DNS — queries historical DNS database (passive)
      "commoncrawl",
      // CommonCrawl — queries historical web crawl database (passive)
      "reverse_whois",
      // Reverse WHOIS — queries crt.sh for related domains (passive)
      // --- Threat Intel Expansion (Gap Analysis P0) ---
      "alienvault_otx",
      // AlienVault OTX — queries OTX pulse database (passive)
      "google_safebrowsing",
      // Google SafeBrowsing — queries SafeBrowsing database (passive)
      "phishtank",
      // PhishTank — queries phishing URL database (passive)
      "darkweb_crossref",
      // Dark Web Cross-Reference — queries local underground intel DB only (passive)
      "dehashed_whois",
      // Dehashed WHOIS — queries Dehashed API for WHOIS, reverse WHOIS, subdomain scan (passive)
      // --- Tier 1 OSINT Gap Connectors (Gap Analysis Apr 2026) ---
      "urlhaus",
      // URLhaus (abuse.ch) — queries malicious URL database (passive)
      "malwarebazaar",
      // MalwareBazaar (abuse.ch) — queries malware sample database (passive)
      "sec_edgar",
      // SEC EDGAR — queries SEC filing database (passive)
      "osv_dev",
      // OSV.dev — queries open source vulnerability database (passive)
      "cisa_advisories",
      // CISA Advisories — queries KEV catalog (passive)
      // --- Tier 2 OSINT Gap Connectors (Gap Analysis Apr 2026) ---
      "sslbl",
      // SSLBL (abuse.ch) — queries SSL blacklist database (passive)
      "github_advisories",
      // GitHub Security Advisories — queries GHSA database (passive)
      "certspotter",
      // Certspotter (SSLMate) — queries CT log database (passive)
      "companies_house",
      // Companies House (UK) — queries corporate registry API (passive)
      "opencorporates",
      // OpenCorporates — queries global corporate registry API (passive)
      "hc3",
      // HC3 (HHS) — queries healthcare sector threat intel (passive)
      // --- Free Subdomain Enumeration Sources (Audit R2) ---
      "anubis",
      // Anubis — queries jldc.me aggregated CT+DNS database (passive)
      "hackertarget",
      // HackerTarget — queries HackerTarget host search API (passive)
      "rapiddns",
      // RapidDNS — queries DNS zone file database (passive)
      "dnsrepo",
      // DNSRepo — queries DNS zone file database (passive)
      "sitedossier",
      // Sitedossier — queries web crawl database (passive)
      // --- Historical Analysis ---
      "wayback_diff"
      // Wayback Diff — queries Wayback Machine CDX API for historical analysis (passive)
    ]);
    DNS_RESOLUTION_CONNECTORS = /* @__PURE__ */ new Set([
      "ripestat",
      // Resolves domain to IP before querying RIPEstat
      "greynoise",
      // Resolves domain to IP before querying GreyNoise
      "email_security",
      // DNS resolution for SPF/DKIM/DMARC records
      "dns_deep",
      // Comprehensive DNS record resolution (A/AAAA/MX/NS/TXT/SOA/CAA)
      "typosquat",
      // Typosquat Generator — performs DNS resolution to check domain availability
      "team_cymru",
      // Team Cymru — resolves domain to IP, then queries DNS for ASN mapping
      "feodo_tracker",
      // Feodo Tracker — resolves domain to IP, then checks C2 blocklist
      "domain_health"
      // Domain Health — DNS resolution + SMTP connect + DNSBL lookups
    ]);
    REGISTRATION_CONNECTORS = /* @__PURE__ */ new Set([
      "rdap"
      // Queries RDAP/WHOIS servers directly
    ]);
    ACTIVE_CONTACT_CONNECTORS = /* @__PURE__ */ new Set([
      "http_security",
      // Direct HTTPS to target (security headers, WAF detection)
      "container-discovery",
      // Direct HTTP probes to target ports (Docker/K8s/registries)
      "cloud_bucket_recon",
      // Direct HTTP probes to cloud provider bucket URLs
      "favicon_hash",
      // Favicon Hash — fetches favicon from target via HTTP (active contact)
      "jarm_fingerprint",
      // JARM — sends 10 TLS Client Hello probes to target (active contact)
      "dns_zone_transfer"
      // DNS Zone Transfer — AXFR attempt against target nameservers (active contact)
    ]);
  }
});

export {
  getDefaultPolicy,
  filterConnectors,
  getScanModeDescription,
  init_passive_guard
};
