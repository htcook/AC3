/**
 * Evidence Multiplier Mapping — Connector Confidence Tiers
 * 
 * Assigns each connector a confidence tier that modifies the weight
 * of its observations during corroboration and signal classification.
 * 
 * Tiers:
 *   - confirmed (1.0x):    Direct evidence from authoritative sources
 *   - corroborated (0.8x): Strong indirect evidence, cross-referenced
 *   - unverified (0.5x):   Single-source, unconfirmed, or scraped data
 * 
 * The multiplier is applied to:
 *   1. Risk signal severity scoring
 *   2. Corroboration engine weighting
 *   3. Report narrative confidence language
 */

export type EvidenceTier = "confirmed" | "corroborated" | "unverified";

export interface ConnectorEvidenceConfig {
  /** The connector name (matches PassiveConnector.name) */
  connector: string;
  /** Evidence confidence tier */
  tier: EvidenceTier;
  /** Numeric multiplier applied to severity/confidence scores */
  multiplier: number;
  /** Whether this source is considered authoritative for its data type */
  authoritative: boolean;
  /** Data types this connector is authoritative for */
  authoritativeFor?: string[];
  /** Brief rationale for the tier assignment */
  rationale: string;
}

/**
 * Default evidence multiplier mapping for all connectors.
 * 
 * Tier assignment criteria:
 * - confirmed: Authoritative database, direct scan data, or official source
 * - corroborated: Well-known aggregator, cross-referenced data, or API with verification
 * - unverified: Community-sourced, scraped, or single-source data
 */
export const EVIDENCE_MULTIPLIER_MAP: Record<string, ConnectorEvidenceConfig> = {
  // === CONFIRMED TIER (1.0x) — Authoritative sources ===
  shodan: {
    connector: "shodan", tier: "confirmed", multiplier: 1.0, authoritative: true,
    authoritativeFor: ["ports", "banners", "cves", "services"],
    rationale: "Direct internet-wide scanning with banner verification",
  },
  shodan_internetdb: {
    connector: "shodan_internetdb", tier: "confirmed", multiplier: 1.0, authoritative: true,
    authoritativeFor: ["ports", "cves"],
    rationale: "Pre-scanned Shodan database — same authority as full Shodan",
  },
  censys: {
    connector: "censys", tier: "confirmed", multiplier: 1.0, authoritative: true,
    authoritativeFor: ["certificates", "services", "ports"],
    rationale: "Internet-wide scanning with certificate and service verification",
  },
  crtsh: {
    connector: "crtsh", tier: "confirmed", multiplier: 1.0, authoritative: true,
    authoritativeFor: ["certificates", "subdomains"],
    rationale: "Certificate Transparency logs — cryptographically verified issuance",
  },
  rdap: {
    connector: "rdap", tier: "confirmed", multiplier: 1.0, authoritative: true,
    authoritativeFor: ["whois", "registration"],
    rationale: "Official RDAP/WHOIS registration data from registries",
  },
  cisa_advisories: {
    connector: "cisa_advisories", tier: "confirmed", multiplier: 1.0, authoritative: true,
    authoritativeFor: ["kev", "exploitation_status", "remediation_deadlines"],
    rationale: "US government authoritative source for known exploited vulnerabilities",
  },
  team_cymru: {
    connector: "team_cymru", tier: "confirmed", multiplier: 1.0, authoritative: true,
    authoritativeFor: ["asn", "bgp_origin", "ip_attribution"],
    rationale: "Gold standard for IP-to-ASN mapping via BGP routing data",
  },
  sec_edgar: {
    connector: "sec_edgar", tier: "confirmed", multiplier: 1.0, authoritative: true,
    authoritativeFor: ["financial_filings", "company_profile", "bia_context"],
    rationale: "Official SEC filing database — legally mandated disclosures",
  },
  dehashed: {
    connector: "dehashed", tier: "confirmed", multiplier: 1.0, authoritative: true,
    authoritativeFor: ["breach_credentials", "credential_exposure"],
    rationale: "Aggregated breach database with verified credential data",
  },
  hibp: {
    connector: "hibp", tier: "confirmed", multiplier: 1.0, authoritative: true,
    authoritativeFor: ["breach_exposure", "data_classes"],
    rationale: "Troy Hunt's authoritative breach notification service",
  },

  // === CORROBORATED TIER (0.8x) — Strong indirect evidence ===
  virustotal: {
    connector: "virustotal", tier: "corroborated", multiplier: 0.8, authoritative: false,
    authoritativeFor: ["malware_detection", "url_reputation"],
    rationale: "Multi-engine aggregator — high confidence when multiple engines agree",
  },
  securitytrails: {
    connector: "securitytrails", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "Historical DNS intelligence — well-maintained commercial database",
  },
  urlscan: {
    connector: "urlscan", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "Community scan database — scans are real but may be outdated",
  },
  abuseipdb: {
    connector: "abuseipdb", tier: "corroborated", multiplier: 0.8, authoritative: false,
    authoritativeFor: ["ip_abuse_reputation"],
    rationale: "Community-reported abuse data with ISP verification",
  },
  greynoise: {
    connector: "greynoise", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "Internet-wide noise classification — good for threat pressure context",
  },
  passivetotal: {
    connector: "passivetotal", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "RiskIQ passive DNS and SSL history — commercial intelligence",
  },
  ripestat: {
    connector: "ripestat", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "RIPE NCC statistics — authoritative for European IP space",
  },
  coalition_control: {
    connector: "coalition_control", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "Coalition's ASM platform — commercial scanning with good coverage",
  },
  urlhaus: {
    connector: "urlhaus", tier: "corroborated", multiplier: 0.8, authoritative: false,
    authoritativeFor: ["malicious_urls", "malware_distribution"],
    rationale: "abuse.ch community project — well-curated malicious URL database",
  },
  malwarebazaar: {
    connector: "malwarebazaar", tier: "corroborated", multiplier: 0.8, authoritative: false,
    authoritativeFor: ["malware_samples", "malware_families"],
    rationale: "abuse.ch community project — verified malware sample repository",
  },
  threatfox: {
    connector: "threatfox", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "abuse.ch IOC database — community-reported with confidence scoring",
  },
  osv_dev: {
    connector: "osv_dev", tier: "corroborated", multiplier: 0.8, authoritative: false,
    authoritativeFor: ["supply_chain_vulns", "ecosystem_advisories"],
    rationale: "Google-backed OSS vuln database — aggregates ecosystem advisories",
  },
  alienvault_otx: {
    connector: "alienvault_otx", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "AlienVault OTX community threat intel — pulse-based with peer review",
  },
  google_safebrowsing: {
    connector: "google_safebrowsing", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "Google's SafeBrowsing — high-confidence malware/phishing detection",
  },
  ransomware_live: {
    connector: "ransomware_live", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "Ransomware victim tracking — cross-referenced with leak sites",
  },
  darkweb_crossref: {
    connector: "darkweb_crossref", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "Local underground intel DB — cross-referenced across multiple sources",
  },
  email_security: {
    connector: "email_security", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "Direct DNS queries for SPF/DKIM/DMARC — verifiable but point-in-time",
  },
  http_security: {
    connector: "http_security", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "Direct HTTP header inspection — verifiable but point-in-time",
  },
  dns_deep: {
    connector: "dns_deep", tier: "corroborated", multiplier: 0.8, authoritative: false,
    rationale: "Comprehensive DNS record analysis — direct queries, verifiable",
  },

  // === UNVERIFIED TIER (0.5x) — Single-source or scraped ===
  wayback: {
    connector: "wayback", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Historical archive — data may be stale or no longer applicable",
  },
  wayback_diff: {
    connector: "wayback_diff", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Historical diff analysis — speculative, requires manual verification",
  },
  github_leaks: {
    connector: "github_leaks", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "GitHub code search — may produce false positives from forks/examples",
  },
  github_recon: {
    connector: "github_recon", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "GitHub org/repo enumeration — presence doesn't imply vulnerability",
  },
  social_media: {
    connector: "social-media", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Social media presence — informational only, no security implications",
  },
  company_intel: {
    connector: "company_intel", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Web scraping + LLM — may hallucinate or extract outdated data",
  },
  commoncrawl: {
    connector: "commoncrawl", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Historical web crawl data — may be stale",
  },
  phishtank: {
    connector: "phishtank", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Community-reported phishing — some false positives possible",
  },
  leakix: {
    connector: "leakix", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Exposed service scanner — findings need version/config verification",
  },
  intelx_search: {
    connector: "intelx_search", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Intelligence X search — aggregated darkweb/paste data, context needed",
  },
  hudson_rock: {
    connector: "hudson_rock", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Stealer log database — credentials may be stale or already rotated",
  },
  leakcheck: {
    connector: "leakcheck", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Credential leak search — single source, needs cross-reference",
  },
  builtwith: {
    connector: "builtwith", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Tech stack detection — may be outdated or detect removed technologies",
  },
  threatminer: {
    connector: "threatminer", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Free threat intel aggregator — data freshness varies",
  },
  ip_api: {
    connector: "ip_api", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "Free IP geolocation — accuracy varies by region",
  },
  bgpview: {
    connector: "bgpview", tier: "unverified", multiplier: 0.5, authoritative: false,
    rationale: "BGP routing data — informational, not authoritative like Team Cymru",
  },
  // Subdomain enumeration connectors (unverified — need DNS confirmation)
  anubis: { connector: "anubis", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "CT + DNS aggregation — needs DNS confirmation" },
  hackertarget: { connector: "hackertarget", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Free host search — limited daily queries" },
  rapiddns: { connector: "rapiddns", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "DNS zone file database — may include stale entries" },
  dnsrepo: { connector: "dnsrepo", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "DNS zone file database — may include stale entries" },
  sitedossier: { connector: "sitedossier", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Web crawl database — may include stale entries" },
  // Infrastructure discovery (unverified — needs confirmation)
  favicon_hash: { connector: "favicon_hash", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Hash-based infrastructure discovery — may match unrelated servers" },
  jarm_fingerprint: { connector: "jarm_fingerprint", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "TLS fingerprinting — shared configs can cause false matches" },
  dns_zone_transfer: { connector: "dns_zone_transfer", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "AXFR attempt — finding is confirmed if successful, but rare" },
  // Other connectors
  cloud_assets: { connector: "cloud_assets", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Cloud enumeration — bucket existence doesn't imply ownership" },
  cloud_bucket_recon: { connector: "cloud_bucket_recon", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Cloud bucket probing — needs ownership confirmation" },
  container_discovery: { connector: "container-discovery", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Container probing — needs version/config verification" },
  fullhunt: { connector: "fullhunt", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Attack surface discovery — pre-scanned but needs verification" },
  netlas: { connector: "netlas", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Internet-wide scanning — smaller coverage than Shodan/Censys" },
  hunter: { connector: "hunter", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Email discovery — may include outdated addresses" },
  whoisxml: { connector: "whoisxml", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "WHOIS aggregator — data may lag behind RDAP" },
  circl_pdns: { connector: "circl_pdns", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Passive DNS — historical, may include stale records" },
  reverse_whois: { connector: "reverse_whois", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Reverse WHOIS via crt.sh — indirect ownership inference" },
  typosquat: { connector: "typosquat", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Generated lookalike domains — existence doesn't imply malice" },
  domain_health: { connector: "domain_health", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "DNSBL/SMTP checks — blacklist status can be transient" },
  dehashed_whois: { connector: "dehashed_whois", tier: "unverified", multiplier: 0.5, authoritative: false, rationale: "Dehashed WHOIS — aggregated, may lag behind RDAP" },
  // --- Tier 2 OSINT Gap Connectors ---
  feodo_tracker: { connector: "feodo_tracker", tier: "confirmed", multiplier: 1.0, authoritative: true, rationale: "abuse.ch Feodo Tracker — authoritative botnet C2 blocklist, law enforcement collaboration", authoritativeFor: ["botnet_c2", "malware_infrastructure"] },
  sslbl: { connector: "sslbl", tier: "confirmed", multiplier: 1.0, authoritative: true, rationale: "abuse.ch SSLBL — authoritative SSL certificate blacklist for C2/malware", authoritativeFor: ["malicious_ssl", "c2_certificates"] },
  github_advisories: { connector: "github_advisories", tier: "confirmed", multiplier: 1.0, authoritative: true, rationale: "GitHub Security Advisories — peer-reviewed, CVE-assigned vulnerability database", authoritativeFor: ["supply_chain_vuln", "open_source_vuln"] },
  certspotter: { connector: "certspotter", tier: "confirmed", multiplier: 0.9, authoritative: true, rationale: "SSLMate Certspotter — authoritative CT log monitor, real-time certificate issuance", authoritativeFor: ["certificate_transparency", "subdomain_discovery"] },
  companies_house: { connector: "companies_house", tier: "confirmed", multiplier: 1.0, authoritative: true, rationale: "UK Companies House — official government corporate registry", authoritativeFor: ["uk_corporate_data", "company_officers"] },
  opencorporates: { connector: "opencorporates", tier: "corroborated", multiplier: 0.7, authoritative: false, rationale: "OpenCorporates — aggregated global corporate data, good coverage but secondary source" },
  hc3: { connector: "hc3", tier: "confirmed", multiplier: 0.9, authoritative: true, rationale: "HHS HC3 — official US government healthcare sector threat intelligence", authoritativeFor: ["healthcare_threats", "sector_advisories"] },
};

/**
 * Get the evidence multiplier for a connector
 */
export function getEvidenceMultiplier(connectorName: string): number {
  return EVIDENCE_MULTIPLIER_MAP[connectorName]?.multiplier ?? 0.5;
}

/**
 * Get the evidence tier for a connector
 */
export function getEvidenceTier(connectorName: string): EvidenceTier {
  return EVIDENCE_MULTIPLIER_MAP[connectorName]?.tier ?? "unverified";
}

/**
 * Check if a connector is authoritative for a given data type
 */
export function isAuthoritativeFor(connectorName: string, dataType: string): boolean {
  const config = EVIDENCE_MULTIPLIER_MAP[connectorName];
  if (!config?.authoritative) return false;
  return config.authoritativeFor?.includes(dataType) ?? false;
}

/**
 * Apply evidence multiplier to a severity score
 */
export function applyEvidenceMultiplier(connectorName: string, severity: number): number {
  const multiplier = getEvidenceMultiplier(connectorName);
  return Math.round(severity * multiplier * 10) / 10;
}

/**
 * Get confidence language for report narratives based on tier
 */
export function getConfidenceLanguage(connectorName: string): { prefix: string; qualifier: string } {
  const tier = getEvidenceTier(connectorName);
  switch (tier) {
    case "confirmed":
      return { prefix: "Confirmed", qualifier: "verified by authoritative source" };
    case "corroborated":
      return { prefix: "Likely", qualifier: "supported by multiple indicators" };
    case "unverified":
      return { prefix: "Possible", qualifier: "requires further verification" };
  }
}

/**
 * Get a summary of all connector tiers for reporting
 */
export function getEvidenceTierSummary(): { confirmed: string[]; corroborated: string[]; unverified: string[] } {
  const summary = { confirmed: [] as string[], corroborated: [] as string[], unverified: [] as string[] };
  for (const [name, config] of Object.entries(EVIDENCE_MULTIPLIER_MAP)) {
    summary[config.tier].push(name);
  }
  return summary;
}
