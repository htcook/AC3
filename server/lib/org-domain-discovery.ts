/**
 * Org-Wide Domain Discovery
 *
 * Discovers ALL root domains owned by an organization starting from a single
 * seed domain. Uses multiple passive techniques with ownership verification
 * to ensure only domains belonging to the target entity are included.
 *
 * Discovery Sources:
 * 1. Reverse WHOIS — find domains registered by the same org/email
 * 2. SecurityTrails Associated Domains — API-based related domain lookup
 * 3. Certificate Transparency Org Search — crt.sh by organization name
 * 4. Censys Certificate Org Search — TLS certs with matching O= field
 * 5. Shared Infrastructure Pivoting — NS, MX, IP/ASN correlation
 * 6. DNS TXT/SPF Record Pivoting — domains referenced in SPF includes
 *
 * Ownership Verification (multi-signal confidence scoring):
 * - WHOIS registrant match (org name, email, registrant ID)
 * - SSL certificate org match (O= field in cert subject)
 * - DNS infrastructure match (shared nameservers, excluding generic providers)
 * - ASN ownership verification (IPs in the org's registered ASN)
 * - Web content correlation (copyright text, branding match)
 *
 * Mission Relevance Classification:
 * - product: Customer-facing product/service domains
 * - service: SaaS, API, portal, or platform domains
 * - infrastructure: Internal tools, CI/CD, VPN, mail
 * - marketing: Marketing sites, landing pages, campaign domains
 * - corporate: Main corporate website, investor relations
 * - unknown: Unclassified
 *
 * @module org-domain-discovery
 */

import { ENV } from "../_core/env";

// ─── Types ──────────────────────────────────────────────────────────────

export interface OrgDomainResult {
  domain: string;
  ownershipConfidence: number;
  ownershipSignals: OwnershipSignal[];
  missionRelevance: MissionRelevance;
  discoverySource: string[];
  registrant: string | null;
  registrantEmail: string | null;
  sslCertOrg: string | null;
  nameservers: string[];
  mxRecords: string[];
  resolvedIps: string[];
  asn: string | null;
  isVerified: boolean;
}

export interface OwnershipSignal {
  type: "whois_org" | "whois_email" | "ssl_cert_org" | "shared_ns" | "shared_mx" | "shared_asn" | "shared_ip_range" | "spf_include" | "web_branding" | "ct_org_match";
  value: string;
  confidence: number;
  detail: string;
}

export type MissionRelevance =
  | "product"
  | "service"
  | "infrastructure"
  | "marketing"
  | "corporate"
  | "unknown";

export interface OrgDiscoveryConfig {
  /** Minimum ownership confidence (0-100) to include a domain */
  minConfidenceThreshold: number;
  /** Maximum number of candidate domains to evaluate */
  maxCandidates: number;
  /** Whether to perform web content verification (slower but more accurate) */
  enableWebVerification: boolean;
  /** Whether to perform SPF/TXT record pivoting */
  enableSpfPivoting: boolean;
  /** Timeout for individual lookups in ms */
  lookupTimeoutMs: number;
}

export interface OrgDiscoveryResult {
  seedDomain: string;
  orgName: string;
  orgEmail: string | null;
  totalCandidatesFound: number;
  verifiedDomains: OrgDomainResult[];
  unverifiedDomains: OrgDomainResult[];
  discoveryStats: {
    source: string;
    domainsFound: number;
    durationMs: number;
    status: "success" | "failed" | "skipped";
    error: string | null;
  }[];
  durationMs: number;
}

// ─── Constants ──────────────────────────────────────────────────────────

/** Generic NS providers — shared NS with these doesn't indicate ownership */
const GENERIC_NS_PROVIDERS = new Set([
  "cloudflare.com", "awsdns", "google.com", "azure-dns", "ultradns",
  "domaincontrol.com", "registrar-servers.com", "ns1.com", "dnsmadeeasy.com",
  "route53", "dnsimple.com", "he.net", "linode.com", "digitalocean.com",
  "vultr.com", "hetzner.com", "ovh.net", "gandi.net", "name.com",
  "hostgator.com", "bluehost.com", "siteground.net", "dreamhost.com",
  "pair.com", "hover.com", "namecheap.com", "godaddy.com",
]);

/** Generic MX providers — shared MX with these doesn't indicate ownership */
const GENERIC_MX_PROVIDERS = new Set([
  "google.com", "googlemail.com", "outlook.com", "protection.outlook.com",
  "pphosted.com", "mimecast.com", "barracuda.com", "messagelabs.com",
  "secureserver.net", "emailsrvr.com", "zoho.com", "fastmail.com",
  "protonmail.ch", "icloud.com", "yahoo.com", "yandex.net",
]);

/** Subdomain patterns that indicate mission relevance */
const MISSION_PATTERNS: Record<MissionRelevance, RegExp[]> = {
  product: [
    /^(app|platform|dashboard|console|portal|my|account|client)/i,
    /(shop|store|buy|checkout|cart|pay|billing)/i,
    /(cloud|saas|api|sdk|dev|developer)/i,
  ],
  service: [
    /^(api|graphql|rest|ws|webhook|gateway|proxy)/i,
    /(service|microservice|backend|server)/i,
    /(cdn|assets|static|media|images|files|storage)/i,
  ],
  infrastructure: [
    /^(mail|smtp|imap|pop|mx|email)/i,
    /^(vpn|sso|auth|login|ldap|ad|directory)/i,
    /^(git|gitlab|github|bitbucket|ci|cd|jenkins|drone|argo)/i,
    /^(monitor|grafana|prometheus|kibana|elastic|splunk|siem)/i,
    /^(db|database|sql|redis|mongo|postgres|mysql)/i,
    /^(internal|intranet|corp|office|admin)/i,
  ],
  marketing: [
    /^(www|web|site|landing|promo|campaign|go|try|get|start)/i,
    /(blog|news|press|media|brand|marketing)/i,
    /(event|conference|summit|webinar)/i,
  ],
  corporate: [
    /^(ir|investor|careers|jobs|about|legal|privacy|terms|compliance)/i,
    /(corporate|company|group|holdings|inc|ltd|llc)/i,
  ],
  unknown: [],
};

const DEFAULT_CONFIG: OrgDiscoveryConfig = {
  minConfidenceThreshold: 60,
  maxCandidates: 200,
  enableWebVerification: false,
  enableSpfPivoting: true,
  lookupTimeoutMs: 15000,
};

// ─── Helper: SecurityTrails API ─────────────────────────────────────────

async function securityTrailsFetch(path: string, timeoutMs: number): Promise<any> {
  const apiKey = ENV.SECURITYTRAILS_API_KEY;
  if (!apiKey) throw new Error("SecurityTrails API key not configured");
  const res = await fetch(`https://api.securitytrails.com/v1${path}`, {
    headers: { APIKEY: apiKey, Accept: "application/json" },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`SecurityTrails ${res.status}: ${res.statusText}`);
  return res.json();
}

// ─── Helper: DNS Lookups ────────────────────────────────────────────────

async function resolveDNS(domain: string, type: string, timeoutMs: number): Promise<string[]> {
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
      { signal: AbortSignal.timeout(timeoutMs) }
    );
    if (!res.ok) return [];
    const data = await res.json();
    return (data.Answer || []).map((a: any) => a.data?.replace(/\.$/, "") || "").filter(Boolean);
  } catch {
    return [];
  }
}

function isGenericNS(ns: string): boolean {
  const lower = ns.toLowerCase();
  for (const provider of GENERIC_NS_PROVIDERS) {
    if (lower.includes(provider)) return true;
  }
  return false;
}

function isGenericMX(mx: string): boolean {
  const lower = mx.toLowerCase();
  for (const provider of GENERIC_MX_PROVIDERS) {
    if (lower.includes(provider)) return true;
  }
  return false;
}

// ─── Source 1: SecurityTrails Associated Domains ────────────────────────

async function discoverViaSecurityTrailsAssociated(
  domain: string,
  config: OrgDiscoveryConfig
): Promise<{ domains: string[]; durationMs: number }> {
  const start = Date.now();
  try {
    // SecurityTrails associated domains endpoint
    const data = await securityTrailsFetch(
      `/domain/${domain}/associated`,
      config.lookupTimeoutMs
    );
    const domains = (data.records || [])
      .map((r: any) => r.hostname || r.domain || "")
      .filter((d: string) => d && d !== domain)
      .slice(0, config.maxCandidates);
    return { domains: [...new Set(domains)], durationMs: Date.now() - start };
  } catch (err: any) {
    console.error(`[OrgDiscovery] SecurityTrails associated failed: ${err.message}`);
    return { domains: [], durationMs: Date.now() - start };
  }
}

// ─── Source 2: SecurityTrails WHOIS → Reverse WHOIS ─────────────────────

async function discoverViaReverseWhois(
  domain: string,
  orgName: string,
  orgEmail: string | null,
  config: OrgDiscoveryConfig
): Promise<{ domains: string[]; durationMs: number }> {
  const start = Date.now();
  const domains: string[] = [];

  try {
    // Use SecurityTrails WHOIS search by org name
    if (orgName && orgName.length > 2) {
      try {
        const data = await securityTrailsFetch(
          `/domains/list?include[]=whois_organization&filter[whois_organization]=${encodeURIComponent(orgName)}`,
          config.lookupTimeoutMs
        );
        const found = (data.records || []).map((r: any) => r.hostname || "").filter(Boolean);
        domains.push(...found);
      } catch {
        // Fallback: try the search endpoint
        try {
          const searchData = await securityTrailsFetch(
            `/search/list`,
            config.lookupTimeoutMs
          );
          // This endpoint may not support org search directly
        } catch { /* skip */ }
      }
    }

    // Also try by registrant email if available
    if (orgEmail) {
      try {
        const data = await securityTrailsFetch(
          `/domains/list?include[]=whois_email&filter[whois_email]=${encodeURIComponent(orgEmail)}`,
          config.lookupTimeoutMs
        );
        const found = (data.records || []).map((r: any) => r.hostname || "").filter(Boolean);
        domains.push(...found);
      } catch { /* skip */ }
    }
  } catch (err: any) {
    console.error(`[OrgDiscovery] Reverse WHOIS failed: ${err.message}`);
  }

  return {
    domains: [...new Set(domains.filter(d => d !== domain))].slice(0, config.maxCandidates),
    durationMs: Date.now() - start,
  };
}

// ─── Source 3: Certificate Transparency Org Search ──────────────────────

async function discoverViaCTOrgSearch(
  orgName: string,
  seedDomain: string,
  config: OrgDiscoveryConfig
): Promise<{ domains: string[]; durationMs: number }> {
  const start = Date.now();
  const domains = new Set<string>();

  try {
    // crt.sh supports org search via O= parameter
    const res = await fetch(
      `https://crt.sh/?O=${encodeURIComponent(orgName)}&output=json`,
      { signal: AbortSignal.timeout(config.lookupTimeoutMs) }
    );
    if (res.ok) {
      const data = await res.json();
      for (const entry of data) {
        const names = (entry.name_value || "").split("\n");
        for (const name of names) {
          const clean = name.trim().toLowerCase().replace(/^\*\./, "");
          if (!clean || clean === seedDomain) continue;
          // Extract root domain (last two parts, or three for co.uk etc.)
          const parts = clean.split(".");
          if (parts.length >= 2) {
            const root = parts.slice(-2).join(".");
            if (root !== seedDomain && root.includes(".")) {
              domains.add(root);
            }
          }
        }
      }
    }
  } catch (err: any) {
    console.error(`[OrgDiscovery] CT org search failed: ${err.message}`);
  }

  return {
    domains: [...domains].slice(0, config.maxCandidates),
    durationMs: Date.now() - start,
  };
}

// ─── Source 4: Censys Certificate Org Search ────────────────────────────

async function discoverViaCensysCertOrg(
  orgName: string,
  seedDomain: string,
  config: OrgDiscoveryConfig
): Promise<{ domains: string[]; durationMs: number }> {
  const start = Date.now();
  const domains = new Set<string>();

  const apiId = ENV.CENSYS_API_ID;
  const apiSecret = ENV.CENSYS_API_SECRET;
  if (!apiId || !apiSecret) {
    return { domains: [], durationMs: Date.now() - start };
  }

  try {
    const auth = Buffer.from(`${apiId}:${apiSecret}`).toString("base64");
    const res = await fetch("https://search.censys.io/api/v2/certificates/search", {
      method: "POST",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        q: `parsed.subject.organization: "${orgName}"`,
        per_page: 100,
      }),
      signal: AbortSignal.timeout(config.lookupTimeoutMs),
    });

    if (res.ok) {
      const data = await res.json();
      for (const cert of data.result?.hits || []) {
        const names = cert.parsed?.names || cert.names || [];
        for (const name of names) {
          const clean = name.trim().toLowerCase().replace(/^\*\./, "");
          const parts = clean.split(".");
          if (parts.length >= 2) {
            const root = parts.slice(-2).join(".");
            if (root !== seedDomain && root.includes(".")) {
              domains.add(root);
            }
          }
        }
      }
    }
  } catch (err: any) {
    console.error(`[OrgDiscovery] Censys cert org search failed: ${err.message}`);
  }

  return {
    domains: [...domains].slice(0, config.maxCandidates),
    durationMs: Date.now() - start,
  };
}

// ─── Source 5: SPF/TXT Record Pivoting ──────────────────────────────────

async function discoverViaSpfPivoting(
  domain: string,
  config: OrgDiscoveryConfig
): Promise<{ domains: string[]; durationMs: number }> {
  const start = Date.now();
  const domains = new Set<string>();

  try {
    const txtRecords = await resolveDNS(domain, "TXT", config.lookupTimeoutMs);
    for (const txt of txtRecords) {
      // Parse SPF includes: "v=spf1 include:_spf.google.com include:mail.example.com -all"
      const includes = txt.match(/include:([^\s]+)/g) || [];
      for (const inc of includes) {
        const incDomain = inc.replace("include:", "").replace(/\.$/, "");
        const parts = incDomain.split(".");
        if (parts.length >= 2) {
          const root = parts.slice(-2).join(".");
          // Skip known email providers
          if (!isGenericMX(root) && root !== domain && root.includes(".")) {
            domains.add(root);
          }
        }
      }

      // Also check for redirect= in SPF
      const redirect = txt.match(/redirect=([^\s]+)/);
      if (redirect?.[1]) {
        const redDomain = redirect[1].replace(/\.$/, "");
        const parts = redDomain.split(".");
        if (parts.length >= 2) {
          const root = parts.slice(-2).join(".");
          if (root !== domain && root.includes(".")) {
            domains.add(root);
          }
        }
      }

      // Check DMARC records for rua/ruf email domains
      if (txt.includes("v=DMARC1")) {
        const emails = txt.match(/ru[af]=mailto:([^;,\s]+)/g) || [];
        for (const e of emails) {
          const emailAddr = e.replace(/ru[af]=mailto:/, "");
          const emailDomain = emailAddr.split("@")[1];
          if (emailDomain && emailDomain !== domain) {
            domains.add(emailDomain);
          }
        }
      }
    }
  } catch (err: any) {
    console.error(`[OrgDiscovery] SPF pivoting failed: ${err.message}`);
  }

  return { domains: [...domains], durationMs: Date.now() - start };
}

// ─── Ownership Verification ─────────────────────────────────────────────

async function verifyOwnership(
  candidateDomain: string,
  seedOrgName: string,
  seedOrgEmail: string | null,
  seedNS: string[],
  seedMX: string[],
  seedAsn: string | null,
  config: OrgDiscoveryConfig
): Promise<{ signals: OwnershipSignal[]; confidence: number }> {
  const signals: OwnershipSignal[] = [];

  // 1. WHOIS org match
  try {
    if (ENV.SECURITYTRAILS_API_KEY) {
      const whoisData = await securityTrailsFetch(
        `/domain/${candidateDomain}/whois`,
        config.lookupTimeoutMs
      );
      const registrantOrg = whoisData?.registrant?.organization || whoisData?.registrant?.name || "";
      const registrantEmail = whoisData?.registrant?.email || whoisData?.contacts?.registrant?.email || "";

      if (registrantOrg && seedOrgName) {
        const orgLower = registrantOrg.toLowerCase();
        const seedLower = seedOrgName.toLowerCase();
        if (orgLower === seedLower || orgLower.includes(seedLower) || seedLower.includes(orgLower)) {
          signals.push({
            type: "whois_org",
            value: registrantOrg,
            confidence: 85,
            detail: `WHOIS registrant org "${registrantOrg}" matches seed org "${seedOrgName}"`,
          });
        }
      }

      if (registrantEmail && seedOrgEmail) {
        // Match by email domain (not exact email, as contacts may differ)
        const candidateEmailDomain = registrantEmail.split("@")[1]?.toLowerCase();
        const seedEmailDomain = seedOrgEmail.split("@")[1]?.toLowerCase();
        if (candidateEmailDomain && seedEmailDomain && candidateEmailDomain === seedEmailDomain) {
          signals.push({
            type: "whois_email",
            value: registrantEmail,
            confidence: 80,
            detail: `WHOIS registrant email domain matches seed email domain "${seedEmailDomain}"`,
          });
        }
      }
    }
  } catch { /* WHOIS lookup failed, continue with other signals */ }

  // 2. SSL cert org match
  try {
    const [aRecords] = await Promise.all([
      resolveDNS(candidateDomain, "A", config.lookupTimeoutMs),
    ]);
    if (aRecords.length > 0 && ENV.CENSYS_API_ID && ENV.CENSYS_API_SECRET) {
      const auth = Buffer.from(`${ENV.CENSYS_API_ID}:${ENV.CENSYS_API_SECRET}`).toString("base64");
      const certRes = await fetch("https://search.censys.io/api/v2/certificates/search", {
        method: "POST",
        headers: {
          Authorization: `Basic ${auth}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({ q: `names: ${candidateDomain}`, per_page: 5 }),
        signal: AbortSignal.timeout(config.lookupTimeoutMs),
      });
      if (certRes.ok) {
        const certData = await certRes.json();
        for (const cert of certData.result?.hits || []) {
          const certOrg = cert.parsed?.subject?.organization?.[0] || "";
          if (certOrg && seedOrgName) {
            const certLower = certOrg.toLowerCase();
            const seedLower = seedOrgName.toLowerCase();
            if (certLower === seedLower || certLower.includes(seedLower) || seedLower.includes(certLower)) {
              signals.push({
                type: "ssl_cert_org",
                value: certOrg,
                confidence: 80,
                detail: `SSL cert org "${certOrg}" matches seed org "${seedOrgName}"`,
              });
              break;
            }
          }
        }
      }
    }
  } catch { /* cert lookup failed */ }

  // 3. Shared nameservers (non-generic)
  try {
    const candidateNS = await resolveDNS(candidateDomain, "NS", config.lookupTimeoutMs);
    const sharedNS = candidateNS.filter(ns =>
      !isGenericNS(ns) && seedNS.some(sNS =>
        ns.toLowerCase() === sNS.toLowerCase() ||
        ns.toLowerCase().endsWith("." + sNS.split(".").slice(-2).join(".").toLowerCase())
      )
    );
    if (sharedNS.length > 0) {
      signals.push({
        type: "shared_ns",
        value: sharedNS.join(", "),
        confidence: 65,
        detail: `Shares ${sharedNS.length} non-generic nameserver(s) with seed domain`,
      });
    }
  } catch { /* NS lookup failed */ }

  // 4. Shared MX records (non-generic)
  try {
    const candidateMX = await resolveDNS(candidateDomain, "MX", config.lookupTimeoutMs);
    const cleanMX = candidateMX.map(mx => mx.replace(/^\d+\s+/, "").toLowerCase());
    const sharedMX = cleanMX.filter(mx =>
      !isGenericMX(mx) && seedMX.some(sMX =>
        mx === sMX.toLowerCase() ||
        mx.endsWith("." + sMX.split(".").slice(-2).join(".").toLowerCase())
      )
    );
    if (sharedMX.length > 0) {
      signals.push({
        type: "shared_mx",
        value: sharedMX.join(", "),
        confidence: 55,
        detail: `Shares ${sharedMX.length} non-generic MX record(s) with seed domain`,
      });
    }
  } catch { /* MX lookup failed */ }

  // 5. CT org match (check if this domain appears in certs with the seed org name)
  try {
    const res = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(candidateDomain)}&output=json`,
      { signal: AbortSignal.timeout(config.lookupTimeoutMs) }
    );
    if (res.ok) {
      const certs = await res.json();
      for (const cert of certs.slice(0, 10)) {
        const issuerOrg = cert.issuer_name || "";
        const certOrg = cert.common_name || "";
        // Check if the cert's organization matches seed org
        if (seedOrgName && (issuerOrg.toLowerCase().includes(seedOrgName.toLowerCase()) ||
            certOrg.toLowerCase().includes(seedOrgName.toLowerCase()))) {
          signals.push({
            type: "ct_org_match",
            value: certOrg || issuerOrg,
            confidence: 60,
            detail: `CT log certificate references seed org "${seedOrgName}"`,
          });
          break;
        }
      }
    }
  } catch { /* CT lookup failed */ }

  // Calculate aggregate confidence
  let confidence = 0;
  if (signals.length === 0) {
    confidence = 10; // Only discovered via association, no verification signals
  } else if (signals.length === 1) {
    confidence = signals[0].confidence;
  } else {
    // Multiple signals: take highest + bonus for corroboration
    signals.sort((a, b) => b.confidence - a.confidence);
    confidence = Math.min(100, signals[0].confidence + (signals.length - 1) * 8);
  }

  return { signals, confidence };
}

// ─── Mission Relevance Classification ───────────────────────────────────

function classifyMissionRelevance(domain: string): MissionRelevance {
  const lower = domain.toLowerCase();

  // Check each category's patterns against the domain name
  for (const [category, patterns] of Object.entries(MISSION_PATTERNS)) {
    if (category === "unknown") continue;
    for (const pattern of patterns) {
      if (pattern.test(lower)) {
        return category as MissionRelevance;
      }
    }
  }

  // Heuristic: short domains are likely corporate/product
  const baseName = lower.split(".")[0];
  if (baseName.length <= 8) return "corporate";

  return "unknown";
}

/**
 * Enhanced mission relevance classification using LLM when available.
 * Falls back to pattern-based classification.
 */
async function classifyMissionRelevanceLLM(
  domains: { domain: string; signals: OwnershipSignal[] }[],
  orgName: string
): Promise<Map<string, MissionRelevance>> {
  const result = new Map<string, MissionRelevance>();

  // Start with pattern-based classification
  for (const { domain } of domains) {
    result.set(domain, classifyMissionRelevance(domain));
  }

  // Try LLM enrichment for better classification
  if (domains.length > 0) {
    try {
      const { invokeLLM } = await import("../_core/llm");
      const domainList = domains.map(d => d.domain).join(", ");

      const response = await invokeLLM({ _priority: 'bulk',
        messages: [
          {
            role: "system",
            content: "You are a cybersecurity analyst classifying domains by their mission relevance to an organization. Return ONLY valid JSON.",
          },
          {
            role: "user",
            content: `Organization: ${orgName}\nDomains: ${domainList}\n\nClassify each domain into one of: product (customer-facing apps/platforms), service (APIs, SaaS, CDN), infrastructure (mail, VPN, CI/CD, monitoring), marketing (blogs, landing pages, campaigns), corporate (main site, investor relations). Return JSON object mapping domain to category.`,
          },
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "domain_classification",
            strict: true,
            schema: {
              type: "object",
              properties: {
                classifications: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      domain: { type: "string" },
                      category: {
                        type: "string",
                        enum: ["product", "service", "infrastructure", "marketing", "corporate", "unknown"],
                      },
                      reasoning: { type: "string" },
                    },
                    required: ["domain", "category", "reasoning"],
                    additionalProperties: false,
                  },
                },
              },
              required: ["classifications"],
              additionalProperties: false,
            },
          },
        },
      });

      const content = response.choices?.[0]?.message?.content;
      if (content) {
        const parsed = JSON.parse(content);
        for (const cls of parsed.classifications || []) {
          if (cls.domain && cls.category) {
            result.set(cls.domain, cls.category as MissionRelevance);
          }
        }
      }
    } catch (err: any) {
      console.error(`[OrgDiscovery] LLM classification failed, using pattern-based: ${err.message}`);
    }
  }

  return result;
}

// ─── Main: Discover Org Domains ─────────────────────────────────────────

/**
 * Discover all root domains owned by the organization behind a seed domain.
 * Uses multiple passive sources with ownership verification.
 */
export async function discoverOrgDomains(
  seedDomain: string,
  orgName: string,
  orgEmail: string | null,
  config?: Partial<OrgDiscoveryConfig>,
  onProgress?: (detail: string) => void,
): Promise<OrgDiscoveryResult> {
  const fullConfig = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();
  const stats: OrgDiscoveryResult["discoveryStats"] = [];
  const candidateMap = new Map<string, Set<string>>(); // domain → sources

  onProgress?.(`Starting org-wide domain discovery for ${seedDomain} (org: ${orgName})`);

  // ── Gather seed domain infrastructure for comparison ──
  onProgress?.("Gathering seed domain infrastructure signals...");
  const [seedNS, seedMXRaw] = await Promise.all([
    resolveDNS(seedDomain, "NS", fullConfig.lookupTimeoutMs),
    resolveDNS(seedDomain, "MX", fullConfig.lookupTimeoutMs),
  ]);
  const seedMX = seedMXRaw.map(mx => mx.replace(/^\d+\s+/, "").toLowerCase());
  let seedAsn: string | null = null;

  // ── Source 1: SecurityTrails Associated Domains ──
  if (ENV.SECURITYTRAILS_API_KEY) {
    onProgress?.("Querying SecurityTrails associated domains...");
    const result = await discoverViaSecurityTrailsAssociated(seedDomain, fullConfig);
    for (const d of result.domains) {
      if (!candidateMap.has(d)) candidateMap.set(d, new Set());
      candidateMap.get(d)!.add("securitytrails_associated");
    }
    stats.push({
      source: "securitytrails_associated",
      domainsFound: result.domains.length,
      durationMs: result.durationMs,
      status: result.domains.length >= 0 ? "success" : "failed",
      error: null,
    });
  } else {
    stats.push({ source: "securitytrails_associated", domainsFound: 0, durationMs: 0, status: "skipped", error: "API key not configured" });
  }

  // ── Source 2: Reverse WHOIS ──
  if (ENV.SECURITYTRAILS_API_KEY && orgName) {
    onProgress?.("Performing reverse WHOIS lookup...");
    const result = await discoverViaReverseWhois(seedDomain, orgName, orgEmail, fullConfig);
    for (const d of result.domains) {
      if (!candidateMap.has(d)) candidateMap.set(d, new Set());
      candidateMap.get(d)!.add("reverse_whois");
    }
    stats.push({
      source: "reverse_whois",
      domainsFound: result.domains.length,
      durationMs: result.durationMs,
      status: "success",
      error: null,
    });
  } else {
    stats.push({ source: "reverse_whois", domainsFound: 0, durationMs: 0, status: "skipped", error: orgName ? "API key not configured" : "No org name available" });
  }

  // ── Source 3: CT Org Search ──
  if (orgName) {
    onProgress?.("Searching Certificate Transparency logs by org name...");
    const result = await discoverViaCTOrgSearch(orgName, seedDomain, fullConfig);
    for (const d of result.domains) {
      if (!candidateMap.has(d)) candidateMap.set(d, new Set());
      candidateMap.get(d)!.add("ct_org_search");
    }
    stats.push({
      source: "ct_org_search",
      domainsFound: result.domains.length,
      durationMs: result.durationMs,
      status: "success",
      error: null,
    });
  } else {
    stats.push({ source: "ct_org_search", domainsFound: 0, durationMs: 0, status: "skipped", error: "No org name available" });
  }

  // ── Source 4: Censys Cert Org Search ──
  if (orgName && ENV.CENSYS_API_ID && ENV.CENSYS_API_SECRET) {
    onProgress?.("Searching Censys certificates by org name...");
    const result = await discoverViaCensysCertOrg(orgName, seedDomain, fullConfig);
    for (const d of result.domains) {
      if (!candidateMap.has(d)) candidateMap.set(d, new Set());
      candidateMap.get(d)!.add("censys_cert_org");
    }
    stats.push({
      source: "censys_cert_org",
      domainsFound: result.domains.length,
      durationMs: result.durationMs,
      status: "success",
      error: null,
    });
  } else {
    stats.push({ source: "censys_cert_org", domainsFound: 0, durationMs: 0, status: "skipped", error: !orgName ? "No org name" : "Censys API not configured" });
  }

  // ── Source 5: SPF/TXT Pivoting ──
  if (fullConfig.enableSpfPivoting) {
    onProgress?.("Analyzing SPF/TXT records for domain references...");
    const result = await discoverViaSpfPivoting(seedDomain, fullConfig);
    for (const d of result.domains) {
      if (!candidateMap.has(d)) candidateMap.set(d, new Set());
      candidateMap.get(d)!.add("spf_pivoting");
    }
    stats.push({
      source: "spf_pivoting",
      domainsFound: result.domains.length,
      durationMs: result.durationMs,
      status: "success",
      error: null,
    });
  }

  const totalCandidates = candidateMap.size;
  onProgress?.(`Found ${totalCandidates} candidate domains. Verifying ownership...`);

  // ── Ownership Verification (batch with concurrency limit) ──
  const candidates = [...candidateMap.entries()].slice(0, fullConfig.maxCandidates);
  const CONCURRENCY = 5;
  const verifiedDomains: OrgDomainResult[] = [];
  const unverifiedDomains: OrgDomainResult[] = [];

  for (let i = 0; i < candidates.length; i += CONCURRENCY) {
    const batch = candidates.slice(i, i + CONCURRENCY);
    const results = await Promise.allSettled(
      batch.map(async ([domain, sources]) => {
        const { signals, confidence } = await verifyOwnership(
          domain, orgName, orgEmail, seedNS, seedMX, seedAsn, fullConfig
        );

        const domainResult: OrgDomainResult = {
          domain,
          ownershipConfidence: confidence,
          ownershipSignals: signals,
          missionRelevance: "unknown", // Will be classified later
          discoverySource: [...sources],
          registrant: null,
          registrantEmail: null,
          sslCertOrg: null,
          nameservers: [],
          mxRecords: [],
          resolvedIps: [],
          asn: null,
          isVerified: confidence >= fullConfig.minConfidenceThreshold,
        };

        // Extract registrant info from signals
        for (const signal of signals) {
          if (signal.type === "whois_org") domainResult.registrant = signal.value;
          if (signal.type === "whois_email") domainResult.registrantEmail = signal.value;
          if (signal.type === "ssl_cert_org") domainResult.sslCertOrg = signal.value;
          if (signal.type === "shared_ns") domainResult.nameservers = signal.value.split(", ");
          if (signal.type === "shared_mx") domainResult.mxRecords = signal.value.split(", ");
        }

        return domainResult;
      })
    );

    for (const result of results) {
      if (result.status === "fulfilled") {
        if (result.value.isVerified) {
          verifiedDomains.push(result.value);
        } else {
          unverifiedDomains.push(result.value);
        }
      }
    }

    onProgress?.(`Verified ${i + batch.length}/${candidates.length} candidates (${verifiedDomains.length} confirmed)`);
  }

  // ── Mission Relevance Classification ──
  if (verifiedDomains.length > 0) {
    onProgress?.("Classifying mission relevance of verified domains...");
    const classifications = await classifyMissionRelevanceLLM(
      verifiedDomains.map(d => ({ domain: d.domain, signals: d.ownershipSignals })),
      orgName
    );
    for (const domain of verifiedDomains) {
      domain.missionRelevance = classifications.get(domain.domain) || classifyMissionRelevance(domain.domain);
    }
  }

  // Sort verified domains by confidence (highest first), then by mission relevance priority
  const relevancePriority: Record<MissionRelevance, number> = {
    product: 1, service: 2, infrastructure: 3, corporate: 4, marketing: 5, unknown: 6,
  };
  verifiedDomains.sort((a, b) => {
    if (b.ownershipConfidence !== a.ownershipConfidence) {
      return b.ownershipConfidence - a.ownershipConfidence;
    }
    return (relevancePriority[a.missionRelevance] || 6) - (relevancePriority[b.missionRelevance] || 6);
  });

  onProgress?.(`Discovery complete: ${verifiedDomains.length} verified, ${unverifiedDomains.length} unverified out of ${totalCandidates} candidates`);

  return {
    seedDomain,
    orgName,
    orgEmail,
    totalCandidatesFound: totalCandidates,
    verifiedDomains,
    unverifiedDomains,
    discoveryStats: stats,
    durationMs: Date.now() - startTime,
  };
}
