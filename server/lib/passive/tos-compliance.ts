/**
 * Terms of Service Compliance Registry
 * 
 * Documents the legal and usage constraints for each OSINT connector.
 * Ensures the platform operates within the terms of service of all
 * data sources, and provides compliance metadata for audit trails.
 * 
 * This registry is checked before connector execution and can be
 * used to generate compliance reports for clients.
 */

export type UsageRestriction = 
  | "none"                    // No restrictions
  | "attribution_required"    // Must credit the source
  | "non_commercial"          // Free tier is non-commercial only
  | "api_key_required"        // Requires API key / account
  | "rate_limited"            // Has documented rate limits
  | "no_redistribution"       // Cannot redistribute raw data
  | "no_bulk_download"        // Cannot bulk download
  | "gdpr_restricted"         // May contain PII, GDPR applies
  | "us_persons_restricted"   // US persons data restrictions
  | "government_data"         // Government data with usage terms
  | "research_only"           // Academic/research use only
  | "commercial_license";     // Requires commercial license for production

export type DataClassification =
  | "public"                  // Publicly available data
  | "semi_public"             // Requires account but free
  | "commercial"              // Requires paid subscription
  | "government"              // Government-published data
  | "community"               // Community-contributed data
  | "breach_data";            // Breach/leak data (special handling)

export interface TosEntry {
  /** Connector name */
  connector: string;
  /** Human-readable source name */
  sourceName: string;
  /** URL to the terms of service */
  tosUrl: string;
  /** URL to the privacy policy (if separate) */
  privacyUrl?: string;
  /** URL to the acceptable use policy (if separate) */
  aupUrl?: string;
  /** Data classification */
  dataClassification: DataClassification;
  /** Active usage restrictions */
  restrictions: UsageRestriction[];
  /** Whether attribution is required in reports */
  attributionRequired: boolean;
  /** Required attribution text (if attributionRequired) */
  attributionText?: string;
  /** Whether data can be stored/cached */
  cachingAllowed: boolean;
  /** Maximum cache duration in seconds (0 = no caching) */
  maxCacheDurationSec: number;
  /** Whether data can be included in client reports */
  reportInclusionAllowed: boolean;
  /** Whether data can be shared with third parties */
  thirdPartyShareAllowed: boolean;
  /** GDPR considerations */
  gdprConsiderations?: string;
  /** Date the ToS was last reviewed */
  lastReviewDate: string;
  /** Notes on compliance */
  complianceNotes?: string;
}

/**
 * ToS Compliance Registry — all OSINT connectors
 */
export const TOS_REGISTRY: Record<string, TosEntry> = {
  // === abuse.ch Family ===
  urlhaus: {
    connector: "urlhaus",
    sourceName: "URLhaus (abuse.ch)",
    tosUrl: "https://urlhaus.abuse.ch/api/",
    dataClassification: "community",
    restrictions: ["attribution_required"],
    attributionRequired: true,
    attributionText: "Data provided by URLhaus (https://urlhaus.abuse.ch/)",
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
    complianceNotes: "CC0 license for data. Attribution appreciated but not legally required.",
  },
  malwarebazaar: {
    connector: "malwarebazaar",
    sourceName: "MalwareBazaar (abuse.ch)",
    tosUrl: "https://bazaar.abuse.ch/api/",
    dataClassification: "community",
    restrictions: ["attribution_required"],
    attributionRequired: true,
    attributionText: "Data provided by MalwareBazaar (https://bazaar.abuse.ch/)",
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
    complianceNotes: "CC0 license. Do not download actual malware samples without proper sandboxing.",
  },
  threatfox: {
    connector: "threatfox",
    sourceName: "ThreatFox (abuse.ch)",
    tosUrl: "https://threatfox.abuse.ch/api/",
    dataClassification: "community",
    restrictions: ["attribution_required"],
    attributionRequired: true,
    attributionText: "Data provided by ThreatFox (https://threatfox.abuse.ch/)",
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
  },

  // === Government Sources ===
  cisa_advisories: {
    connector: "cisa_advisories",
    sourceName: "CISA Known Exploited Vulnerabilities Catalog",
    tosUrl: "https://www.cisa.gov/terms",
    dataClassification: "government",
    restrictions: ["government_data", "attribution_required"],
    attributionRequired: true,
    attributionText: "Source: CISA Known Exploited Vulnerabilities Catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
    cachingAllowed: true,
    maxCacheDurationSec: 86400,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
    complianceNotes: "Public domain US government data. Cache the catalog to reduce load on CISA servers.",
  },
  sec_edgar: {
    connector: "sec_edgar",
    sourceName: "SEC EDGAR",
    tosUrl: "https://www.sec.gov/privacy#security",
    dataClassification: "government",
    restrictions: ["government_data", "rate_limited", "no_bulk_download"],
    attributionRequired: true,
    attributionText: "Source: SEC EDGAR (https://www.sec.gov/cgi-bin/browse-edgar)",
    cachingAllowed: true,
    maxCacheDurationSec: 86400,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
    complianceNotes: "Public domain. Must include User-Agent with contact email. Max 10 req/sec. Do not use for automated trading.",
  },

  // === Free/Open APIs ===
  osv_dev: {
    connector: "osv_dev",
    sourceName: "OSV.dev (Google)",
    tosUrl: "https://osv.dev/docs/",
    dataClassification: "public",
    restrictions: ["attribution_required"],
    attributionRequired: true,
    attributionText: "Vulnerability data from OSV.dev (https://osv.dev/)",
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
    complianceNotes: "CC-BY 4.0 license. Attribution required.",
  },
  team_cymru: {
    connector: "team_cymru",
    sourceName: "Team Cymru IP-to-ASN Mapping",
    tosUrl: "https://www.team-cymru.com/ip-asn-mapping",
    dataClassification: "public",
    restrictions: ["rate_limited", "no_bulk_download"],
    attributionRequired: true,
    attributionText: "IP-to-ASN data from Team Cymru (https://www.team-cymru.com/)",
    cachingAllowed: true,
    maxCacheDurationSec: 86400,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
    complianceNotes: "Free for non-bulk queries. For bulk lookups, use the whois.cymru.com service. Do not exceed 100k queries/day.",
  },

  // === Commercial APIs ===
  shodan: {
    connector: "shodan",
    sourceName: "Shodan",
    tosUrl: "https://www.shodan.io/terms",
    dataClassification: "commercial",
    restrictions: ["api_key_required", "rate_limited", "no_redistribution"],
    attributionRequired: false,
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: false,
    lastReviewDate: "2026-04-24",
    complianceNotes: "Cannot redistribute raw Shodan data. Can include findings in reports. Rate limits vary by plan.",
  },
  censys: {
    connector: "censys",
    sourceName: "Censys",
    tosUrl: "https://censys.io/terms-of-service",
    dataClassification: "commercial",
    restrictions: ["api_key_required", "rate_limited", "no_redistribution"],
    attributionRequired: false,
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: false,
    lastReviewDate: "2026-04-24",
  },
  virustotal: {
    connector: "virustotal",
    sourceName: "VirusTotal",
    tosUrl: "https://support.virustotal.com/hc/en-us/articles/115002145529",
    dataClassification: "commercial",
    restrictions: ["api_key_required", "rate_limited", "no_redistribution", "attribution_required"],
    attributionRequired: true,
    attributionText: "Scanned by VirusTotal (https://www.virustotal.com/)",
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: false,
    lastReviewDate: "2026-04-24",
    complianceNotes: "Free API: 4 req/min, 500 req/day. Must not redistribute raw scan results.",
  },
  securitytrails: {
    connector: "securitytrails",
    sourceName: "SecurityTrails",
    tosUrl: "https://securitytrails.com/terms-of-service",
    dataClassification: "commercial",
    restrictions: ["api_key_required", "rate_limited"],
    attributionRequired: false,
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: false,
    lastReviewDate: "2026-04-24",
  },

  // === Breach Data (Special Handling) ===
  dehashed: {
    connector: "dehashed",
    sourceName: "Dehashed",
    tosUrl: "https://www.dehashed.com/legal",
    dataClassification: "breach_data",
    restrictions: ["api_key_required", "gdpr_restricted", "no_redistribution"],
    attributionRequired: false,
    cachingAllowed: false,
    maxCacheDurationSec: 0,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: false,
    gdprConsiderations: "Contains PII from breaches. Redact personal data in reports. Only use for authorized security assessments.",
    lastReviewDate: "2026-04-24",
    complianceNotes: "Breach data must be handled per engagement authorization. Redact in reports unless client explicitly requests full data.",
  },
  hibp: {
    connector: "hibp",
    sourceName: "Have I Been Pwned",
    tosUrl: "https://haveibeenpwned.com/API/v3#AcceptableUse",
    dataClassification: "breach_data",
    restrictions: ["api_key_required", "rate_limited", "gdpr_restricted"],
    attributionRequired: true,
    attributionText: "Breach data from Have I Been Pwned (https://haveibeenpwned.com/)",
    cachingAllowed: false,
    maxCacheDurationSec: 0,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: false,
    gdprConsiderations: "Contains PII. Only query for domains/emails you are authorized to assess.",
    lastReviewDate: "2026-04-24",
    complianceNotes: "Must not use for credential stuffing or unauthorized access. Rate limit: 10/min.",
  },
  hudson_rock: {
    connector: "hudson_rock",
    sourceName: "Hudson Rock Cavalier",
    tosUrl: "https://cavalier.hudsonrock.com/docs",
    dataClassification: "breach_data",
    restrictions: ["gdpr_restricted", "no_redistribution"],
    attributionRequired: false,
    cachingAllowed: false,
    maxCacheDurationSec: 0,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: false,
    gdprConsiderations: "Stealer log data contains PII. Handle per engagement authorization.",
    lastReviewDate: "2026-04-24",
  },
  leakcheck: {
    connector: "leakcheck",
    sourceName: "LeakCheck",
    tosUrl: "https://leakcheck.io/terms",
    dataClassification: "breach_data",
    restrictions: ["api_key_required", "gdpr_restricted", "no_redistribution"],
    attributionRequired: false,
    cachingAllowed: false,
    maxCacheDurationSec: 0,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: false,
    gdprConsiderations: "Contains PII from breaches. Only use for authorized assessments.",
    lastReviewDate: "2026-04-24",
  },
  darkweb_crossref: {
    connector: "darkweb_crossref",
    sourceName: "Dark Web Cross-Reference (Internal)",
    tosUrl: "internal",
    dataClassification: "breach_data",
    restrictions: ["gdpr_restricted"],
    attributionRequired: false,
    cachingAllowed: true,
    maxCacheDurationSec: 86400,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: false,
    gdprConsiderations: "Contains PII from underground sources. Handle per engagement authorization.",
    lastReviewDate: "2026-04-24",
    complianceNotes: "Internal database. Ensure data provenance is documented.",
  },

  // === Community/Free Sources ===
  crtsh: {
    connector: "crtsh",
    sourceName: "crt.sh (Sectigo)",
    tosUrl: "https://crt.sh/",
    dataClassification: "public",
    restrictions: ["rate_limited"],
    attributionRequired: false,
    cachingAllowed: true,
    maxCacheDurationSec: 86400,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
    complianceNotes: "Certificate Transparency data is public. Be gentle with queries.",
  },
  alienvault_otx: {
    connector: "alienvault_otx",
    sourceName: "AlienVault OTX",
    tosUrl: "https://otx.alienvault.com/terms-of-service",
    dataClassification: "community",
    restrictions: ["api_key_required", "attribution_required"],
    attributionRequired: true,
    attributionText: "Threat intelligence from AlienVault OTX (https://otx.alienvault.com/)",
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
  },
  abuseipdb: {
    connector: "abuseipdb",
    sourceName: "AbuseIPDB",
    tosUrl: "https://www.abuseipdb.com/legal",
    dataClassification: "community",
    restrictions: ["api_key_required", "rate_limited", "attribution_required"],
    attributionRequired: true,
    attributionText: "IP reputation data from AbuseIPDB (https://www.abuseipdb.com/)",
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: false,
    lastReviewDate: "2026-04-24",
  },
  phishtank: {
    connector: "phishtank",
    sourceName: "PhishTank (OpenDNS)",
    tosUrl: "https://phishtank.org/developer_info.php",
    dataClassification: "community",
    restrictions: ["attribution_required"],
    attributionRequired: true,
    attributionText: "Phishing data from PhishTank (https://phishtank.org/)",
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
  },
  ransomware_live: {
    connector: "ransomware_live",
    sourceName: "ransomware.live",
    tosUrl: "https://www.ransomware.live/",
    dataClassification: "community",
    restrictions: ["attribution_required"],
    attributionRequired: true,
    attributionText: "Ransomware tracking data from ransomware.live",
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
  },
  // --- Tier 2 OSINT Gap Connectors ---
  feodo_tracker: {
    connector: "feodo_tracker",
    sourceName: "Feodo Tracker",
    tosUrl: "https://feodotracker.abuse.ch/",
    dataClassification: "community",
    restrictions: ["attribution_required"],
    attributionRequired: true,
    attributionText: "Botnet C2 data from Feodo Tracker by abuse.ch",
    cachingAllowed: true,
    maxCacheDurationSec: 300,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
  },
  sslbl: {
    connector: "sslbl",
    sourceName: "SSLBL",
    tosUrl: "https://sslbl.abuse.ch/",
    dataClassification: "community",
    restrictions: ["attribution_required"],
    attributionRequired: true,
    attributionText: "SSL blacklist data from SSLBL by abuse.ch",
    cachingAllowed: true,
    maxCacheDurationSec: 300,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
  },
  github_advisories: {
    connector: "github_advisories",
    sourceName: "GitHub Security Advisories",
    tosUrl: "https://docs.github.com/en/site-policy/github-terms/github-terms-of-service",
    dataClassification: "open_source",
    restrictions: [],
    attributionRequired: false,
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
  },
  certspotter: {
    connector: "certspotter",
    sourceName: "Certspotter",
    tosUrl: "https://sslmate.com/certspotter/",
    dataClassification: "open_source",
    restrictions: ["rate_limited"],
    attributionRequired: false,
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
  },
  companies_house: {
    connector: "companies_house",
    sourceName: "Companies House",
    tosUrl: "https://developer.company-information.service.gov.uk/developer/terms-of-use",
    dataClassification: "government",
    restrictions: ["attribution_required"],
    attributionRequired: true,
    attributionText: "Contains public sector information licensed under the Open Government Licence v3.0 (Companies House)",
    cachingAllowed: true,
    maxCacheDurationSec: 86400,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
  },
  opencorporates: {
    connector: "opencorporates",
    sourceName: "OpenCorporates",
    tosUrl: "https://opencorporates.com/info/licence",
    dataClassification: "open_source",
    restrictions: ["attribution_required"],
    attributionRequired: true,
    attributionText: "Corporate data from OpenCorporates (https://opencorporates.com)",
    cachingAllowed: true,
    maxCacheDurationSec: 86400,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
  },
  hc3: {
    connector: "hc3",
    sourceName: "HC3 (HHS)",
    tosUrl: "https://www.hhs.gov/disclaimer.html",
    dataClassification: "government",
    restrictions: [],
    attributionRequired: false,
    cachingAllowed: true,
    maxCacheDurationSec: 3600,
    reportInclusionAllowed: true,
    thirdPartyShareAllowed: true,
    lastReviewDate: "2026-04-24",
  },
};

/**
 * Get the ToS entry for a connector
 */
export function getTosEntry(connector: string): TosEntry | null {
  return TOS_REGISTRY[connector] ?? null;
}

/**
 * Check if a connector requires attribution in reports
 */
export function requiresAttribution(connector: string): boolean {
  return TOS_REGISTRY[connector]?.attributionRequired ?? false;
}

/**
 * Get the attribution text for a connector
 */
export function getAttributionText(connector: string): string | null {
  return TOS_REGISTRY[connector]?.attributionText ?? null;
}

/**
 * Check if data from a connector can be cached
 */
export function isCachingAllowed(connector: string): boolean {
  return TOS_REGISTRY[connector]?.cachingAllowed ?? true;
}

/**
 * Check if a connector's data can be included in client reports
 */
export function isReportInclusionAllowed(connector: string): boolean {
  return TOS_REGISTRY[connector]?.reportInclusionAllowed ?? true;
}

/**
 * Get all connectors with GDPR considerations
 */
export function getGdprRestrictedConnectors(): { connector: string; considerations: string }[] {
  return Object.values(TOS_REGISTRY)
    .filter(entry => entry.restrictions.includes("gdpr_restricted"))
    .map(entry => ({
      connector: entry.connector,
      considerations: entry.gdprConsiderations || "Contains PII — handle per engagement authorization",
    }));
}

/**
 * Get all connectors that require attribution
 */
export function getAttributionRequiredConnectors(): { connector: string; text: string }[] {
  return Object.values(TOS_REGISTRY)
    .filter(entry => entry.attributionRequired && entry.attributionText)
    .map(entry => ({
      connector: entry.connector,
      text: entry.attributionText!,
    }));
}

/**
 * Generate a compliance summary for an engagement report
 */
export function generateComplianceSummary(usedConnectors: string[]): {
  attributions: string[];
  gdprWarnings: string[];
  restrictions: string[];
  lastReviewDates: { connector: string; date: string }[];
} {
  const attributions: string[] = [];
  const gdprWarnings: string[] = [];
  const restrictions: string[] = [];
  const lastReviewDates: { connector: string; date: string }[] = [];

  for (const connector of usedConnectors) {
    const entry = TOS_REGISTRY[connector];
    if (!entry) continue;

    if (entry.attributionRequired && entry.attributionText) {
      attributions.push(entry.attributionText);
    }

    if (entry.restrictions.includes("gdpr_restricted")) {
      gdprWarnings.push(`${entry.sourceName}: ${entry.gdprConsiderations || "Contains PII"}`);
    }

    if (entry.restrictions.includes("no_redistribution")) {
      restrictions.push(`${entry.sourceName}: Raw data must not be redistributed`);
    }

    lastReviewDates.push({ connector: entry.connector, date: entry.lastReviewDate });
  }

  return { attributions, gdprWarnings, restrictions, lastReviewDates };
}
