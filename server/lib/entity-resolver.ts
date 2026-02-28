/**
 * Entity Resolver — Multi-Signal Business Identification
 *
 * Identifies the actual business/organization behind a domain by cross-referencing
 * multiple signals. Critically, it filters out hosting providers, CDNs, registrars,
 * and other third-party infrastructure to find the real site owner.
 *
 * Signals used (in priority order):
 * 1. Web crawl branding — page title, copyright text, meta description, logo alt text
 * 2. SSL/TLS certificate — Organization (O) and Organizational Unit (OU) fields
 * 3. WHOIS registrant — Org name (filtered against known hosting/registrar companies)
 * 4. Social media links — LinkedIn, Twitter/X company profiles from crawled pages
 * 5. DNS/infrastructure — MX records (Google Workspace, M365), CNAME chains
 *
 * After entity identification, enriches with financial data (revenue, valuation,
 * employee count) using LLM-assisted OSINT for BIA financial impact scoring.
 */

// ─── Known Infrastructure Providers (NOT the site owner) ────────────────
const HOSTING_PROVIDERS = new Set([
  // Cloud / IaaS
  "amazon.com", "amazon technologies", "amazon web services", "aws", "amazon",
  "google llc", "google cloud", "google inc", "alphabet",
  "microsoft corporation", "microsoft", "azure",
  "digitalocean", "digital ocean", "linode", "akamai technologies", "akamai",
  "oracle corporation", "oracle", "ibm", "rackspace",
  "ovh", "ovhcloud", "hetzner", "vultr", "upcloud",
  // CDN
  "cloudflare", "cloudflare inc", "fastly", "stackpath", "keycdn",
  "bunny.net", "bunnycdn", "cdn77", "limelight networks", "edgecast",
  "imperva", "incapsula", "sucuri",
  // Hosting
  "godaddy", "go daddy", "godaddy.com", "namecheap", "name cheap",
  "bluehost", "hostgator", "siteground", "dreamhost", "a2 hosting",
  "ionos", "1and1", "1&1", "hostinger", "inmotion hosting",
  "wpengine", "wp engine", "kinsta", "flywheel", "pantheon",
  "netlify", "vercel", "heroku", "render", "railway",
  // Registrars
  "enom", "tucows", "network solutions", "register.com", "gandi",
  "hover", "porkbun", "dynadot", "epik", "markmonitor",
  // DNS providers
  "dnsimple", "dnsmadeeasy", "ns1", "route53", "ultradns",
  // Security / WAF
  "comodo", "sectigo", "digicert", "let's encrypt", "letsencrypt",
  "globalsign", "entrust", "thawte", "geotrust", "rapid ssl",
  // Telecom / ISP
  "comcast", "verizon", "at&t", "centurylink", "lumen technologies",
  "cogent", "level 3", "telia", "ntt", "zayo",
  // Privacy / proxy
  "whoisguard", "privacy protect", "domains by proxy", "contact privacy",
  "withheld for privacy", "redacted for privacy", "data protected",
  "identity protection", "perfect privacy", "whois privacy",
]);

// ─── Types ──────────────────────────────────────────────────────────────

export interface EntityProfile {
  /** Resolved organization name */
  orgName: string;
  /** Confidence in the identification (0-100) */
  confidence: number;
  /** How the org was identified */
  identificationMethod: string;
  /** Evidence trail */
  evidence: EntityEvidence[];
  /** Industry / sector classification */
  industry: string | null;
  /** Sub-sector */
  subSector: string | null;
  /** Estimated company size */
  companySize: "startup" | "small" | "medium" | "large" | "enterprise" | "unknown";
  /** Estimated annual revenue (USD) */
  estimatedRevenue: number | null;
  /** Revenue confidence */
  revenueConfidence: "verified" | "estimated" | "unknown";
  /** Revenue source description */
  revenueSource: string | null;
  /** Estimated company valuation (USD) */
  estimatedValuation: number | null;
  /** Valuation confidence */
  valuationConfidence: "verified" | "estimated" | "unknown";
  /** Valuation source description */
  valuationSource: string | null;
  /** Employee count estimate */
  estimatedEmployees: number | null;
  /** Whether the company is publicly traded */
  isPublicCompany: boolean;
  /** Stock ticker if public */
  stockTicker: string | null;
  /** Headquarters location */
  headquarters: string | null;
  /** Founded year */
  foundedYear: number | null;
  /** Key products/services */
  keyProducts: string[];
  /** Social media profiles found */
  socialProfiles: { platform: string; url: string }[];
  /** Domain WHOIS org (raw, before filtering) */
  whoisOrg: string | null;
  /** SSL cert org */
  sslCertOrg: string | null;
  /** Whether the WHOIS org was filtered as a hosting provider */
  whoisIsHostingProvider: boolean;
}

export interface EntityEvidence {
  source: string;
  signal: string;
  value: string;
  confidence: number;
}

export interface FinancialEnrichment {
  estimatedRevenue: number | null;
  revenueConfidence: "verified" | "estimated" | "unknown";
  revenueSource: string | null;
  estimatedValuation: number | null;
  valuationConfidence: "verified" | "estimated" | "unknown";
  valuationSource: string | null;
  estimatedEmployees: number | null;
  isPublicCompany: boolean;
  stockTicker: string | null;
  headquarters: string | null;
  foundedYear: number | null;
  industry: string | null;
  subSector: string | null;
  keyProducts: string[];
  companySize: "startup" | "small" | "medium" | "large" | "enterprise" | "unknown";
}

// ─── Helper: Check if an org name is a known hosting/infrastructure provider ─

function isHostingProvider(orgName: string): boolean {
  if (!orgName) return false;
  const lower = orgName.toLowerCase().trim();
  for (const provider of HOSTING_PROVIDERS) {
    if (lower === provider || lower.includes(provider) || provider.includes(lower)) {
      return true;
    }
  }
  // Also check for generic patterns
  if (/\b(hosting|registrar|registry|datacenter|data center|colocation|colo)\b/i.test(orgName)) {
    return true;
  }
  return false;
}

// ─── Helper: Extract copyright holder from HTML ─────────────────────────

function extractCopyrightHolder(html: string): string | null {
  if (!html) return null;
  // Match patterns like "© 2024 Company Name" or "Copyright 2024 Company Name"
  const patterns = [
    /(?:©|&copy;|copyright)\s*(?:\d{4}[-–]\d{4}|\d{4})?\s*([A-Z][A-Za-z0-9\s&.,'-]{2,60}?)(?:\.|,|\s*All\s*rights|\s*<|\s*$)/gi,
    /(?:©|&copy;|copyright)\s*(?:\d{4}[-–]\d{4}|\d{4})?\s*by\s+([A-Z][A-Za-z0-9\s&.,'-]{2,60}?)(?:\.|,|\s*All\s*rights|\s*<|\s*$)/gi,
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(html);
    if (match?.[1]) {
      const name = match[1].trim().replace(/[.,]+$/, "").trim();
      if (name.length > 2 && !isHostingProvider(name)) {
        return name;
      }
    }
  }
  return null;
}

// ─── Helper: Extract company name from page title ───────────────────────

function extractFromTitle(title: string): string | null {
  if (!title) return null;
  // Common patterns: "Company Name - Tagline", "Company Name | Product"
  const separators = [" - ", " | ", " — ", " – ", " :: ", " : "];
  for (const sep of separators) {
    if (title.includes(sep)) {
      const parts = title.split(sep);
      const candidate = parts[0].trim();
      if (candidate.length > 2 && candidate.length < 80 && !isHostingProvider(candidate)) {
        return candidate;
      }
    }
  }
  // If no separator, use the full title if it's short enough
  if (title.length > 2 && title.length < 60 && !isHostingProvider(title)) {
    return title;
  }
  return null;
}

// ─── Helper: Extract social profiles from external links ────────────────

function extractSocialProfiles(externalLinks: string[]): { platform: string; url: string }[] {
  const profiles: { platform: string; url: string }[] = [];
  const seen = new Set<string>();
  for (const link of externalLinks) {
    try {
      const url = new URL(link);
      const host = url.hostname.toLowerCase();
      let platform: string | null = null;
      if (host.includes("linkedin.com") && url.pathname.includes("/company/")) platform = "LinkedIn";
      else if (host.includes("twitter.com") || host.includes("x.com")) platform = "X/Twitter";
      else if (host.includes("facebook.com") && !url.pathname.includes("/sharer")) platform = "Facebook";
      else if (host.includes("github.com")) platform = "GitHub";
      else if (host.includes("instagram.com")) platform = "Instagram";
      else if (host.includes("youtube.com") && (url.pathname.includes("/c/") || url.pathname.includes("/channel/") || url.pathname.includes("/@"))) platform = "YouTube";
      if (platform && !seen.has(platform)) {
        seen.add(platform);
        profiles.push({ platform, url: link });
      }
    } catch {
      // Invalid URL, skip
    }
  }
  return profiles;
}

// ─── Main: Resolve Entity from Crawl Data ───────────────────────────────

/**
 * Resolve the actual business entity behind a domain using multiple signals
 * from web crawl results, WHOIS data, and SSL certificate info.
 */
export function resolveEntity(params: {
  domain: string;
  pageTitle?: string | null;
  metaDescription?: string | null;
  html?: string | null;
  externalLinks?: string[] | null;
  tlsInfo?: { issuer?: string; subject?: string; subjectAltNames?: string[] } | null;
  whoisOrg?: string | null;
  technologies?: string[] | null;
  rawHeaders?: Record<string, string> | null;
}): Omit<EntityProfile, "estimatedRevenue" | "revenueConfidence" | "revenueSource" | "estimatedValuation" | "valuationConfidence" | "valuationSource" | "estimatedEmployees" | "isPublicCompany" | "stockTicker" | "headquarters" | "foundedYear" | "keyProducts" | "industry" | "subSector" | "companySize"> {
  const evidence: EntityEvidence[] = [];
  const candidates: { name: string; confidence: number; source: string }[] = [];

  // ── Signal 1: Copyright text from HTML (highest priority — site owner declares themselves)
  if (params.html) {
    const copyrightHolder = extractCopyrightHolder(params.html);
    if (copyrightHolder) {
      evidence.push({ source: "html_copyright", signal: "Copyright text", value: copyrightHolder, confidence: 90 });
      candidates.push({ name: copyrightHolder, confidence: 90, source: "copyright" });
    }
  }

  // ── Signal 2: Page title
  if (params.pageTitle) {
    const titleName = extractFromTitle(params.pageTitle);
    if (titleName) {
      evidence.push({ source: "page_title", signal: "Page title", value: titleName, confidence: 75 });
      candidates.push({ name: titleName, confidence: 75, source: "title" });
    }
  }

  // ── Signal 3: Meta description
  if (params.metaDescription) {
    const desc = params.metaDescription;
    // Look for "Company Name is..." or "About Company Name" patterns
    const aboutMatch = desc.match(/^([A-Z][A-Za-z0-9\s&.,'-]{2,40}?)\s+(?:is|provides|offers|delivers|helps|enables|builds|creates|specializes)/);
    if (aboutMatch?.[1] && !isHostingProvider(aboutMatch[1])) {
      evidence.push({ source: "meta_description", signal: "Meta description", value: aboutMatch[1], confidence: 65 });
      candidates.push({ name: aboutMatch[1], confidence: 65, source: "meta" });
    }
  }

  // ── Signal 4: SSL/TLS certificate Organization field
  if (params.tlsInfo?.subject) {
    // Parse "O=Company Name" from subject string
    const orgMatch = params.tlsInfo.subject.match(/O=([^,/]+)/);
    if (orgMatch?.[1]) {
      const sslOrg = orgMatch[1].trim();
      if (!isHostingProvider(sslOrg)) {
        evidence.push({ source: "ssl_certificate", signal: "SSL cert Organization", value: sslOrg, confidence: 80 });
        candidates.push({ name: sslOrg, confidence: 80, source: "ssl" });
      } else {
        evidence.push({ source: "ssl_certificate", signal: "SSL cert Organization (hosting provider)", value: sslOrg, confidence: 0 });
      }
    }
  }

  // ── Signal 5: WHOIS registrant org
  if (params.whoisOrg) {
    const whoisFiltered = isHostingProvider(params.whoisOrg);
    if (!whoisFiltered) {
      evidence.push({ source: "whois", signal: "WHOIS registrant org", value: params.whoisOrg, confidence: 70 });
      candidates.push({ name: params.whoisOrg, confidence: 70, source: "whois" });
    } else {
      evidence.push({ source: "whois", signal: "WHOIS registrant org (hosting provider filtered)", value: params.whoisOrg, confidence: 0 });
    }
  }

  // ── Signal 6: Social media profiles
  const socialProfiles = extractSocialProfiles(params.externalLinks || []);
  for (const profile of socialProfiles) {
    if (profile.platform === "LinkedIn") {
      // Extract company name from LinkedIn URL: /company/company-name/
      const match = profile.url.match(/\/company\/([^/?]+)/);
      if (match?.[1]) {
        const linkedInName = match[1].replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase());
        evidence.push({ source: "social_linkedin", signal: "LinkedIn company page", value: linkedInName, confidence: 60 });
        candidates.push({ name: linkedInName, confidence: 60, source: "linkedin" });
      }
    }
  }

  // ── Resolve: Pick the best candidate ──
  // Sort by confidence, then prefer copyright > ssl > title > whois > meta > linkedin
  candidates.sort((a, b) => b.confidence - a.confidence);

  let orgName = params.domain.replace(/^www\./, "");
  let bestConfidence = 0;
  let identificationMethod = "domain_fallback";

  if (candidates.length > 0) {
    orgName = candidates[0].name;
    bestConfidence = candidates[0].confidence;
    identificationMethod = candidates[0].source;

    // Boost confidence if multiple signals agree
    if (candidates.length >= 2) {
      const topName = candidates[0].name.toLowerCase();
      const agreeing = candidates.filter(c =>
        c.name.toLowerCase() === topName ||
        c.name.toLowerCase().includes(topName) ||
        topName.includes(c.name.toLowerCase())
      );
      if (agreeing.length >= 2) {
        bestConfidence = Math.min(100, bestConfidence + 10 * (agreeing.length - 1));
        identificationMethod = `multi_signal (${agreeing.map(a => a.source).join(", ")})`;
      }
    }
  }

  return {
    orgName,
    confidence: bestConfidence,
    identificationMethod,
    evidence,
    socialProfiles,
    whoisOrg: params.whoisOrg || null,
    sslCertOrg: params.tlsInfo?.subject?.match(/O=([^,/]+)/)?.[1]?.trim() || null,
    whoisIsHostingProvider: params.whoisOrg ? isHostingProvider(params.whoisOrg) : false,
  };
}

// ─── Financial Enrichment via LLM ───────────────────────────────────────

/**
 * Enrich an entity profile with financial data using LLM-assisted OSINT.
 * Uses the LLM to estimate revenue, valuation, and other financial metrics
 * based on publicly available information about the company.
 */
export async function enrichEntityFinancials(params: {
  orgName: string;
  domain: string;
  industry?: string | null;
  technologies?: string[] | null;
  employeeSignals?: string[];
}): Promise<FinancialEnrichment> {
  try {
    const { invokeLLM } = await import("../_core/llm");

    const prompt = `You are a business intelligence analyst. Given the following company information, provide your best estimate of their financial profile based on publicly available information, industry benchmarks, and observable signals.

Company: ${params.orgName}
Domain: ${params.domain}
${params.industry ? `Industry: ${params.industry}` : ""}
${params.technologies?.length ? `Technologies detected: ${params.technologies.slice(0, 20).join(", ")}` : ""}
${params.employeeSignals?.length ? `Employee signals: ${params.employeeSignals.join("; ")}` : ""}

Analyze this company and provide:
1. Whether they are publicly traded (check if they have a known stock ticker)
2. Estimated annual revenue in USD (use public filings if available, otherwise estimate from industry, size signals, and technology stack)
3. Estimated company valuation in USD
4. Estimated employee count
5. Industry and sub-sector classification
6. Company size category
7. Headquarters location
8. Founded year (if known)
9. Key products or services (up to 5)

IMPORTANT: 
- For public companies, use actual reported revenue and market cap
- For private companies, estimate based on industry benchmarks, employee count signals, and technology sophistication
- Revenue and valuation should be in USD (whole numbers, no decimals)
- If you cannot determine a value with any confidence, use null
- Be conservative in estimates — underestimate rather than overestimate`;

    const response = await invokeLLM({
      messages: [
        { role: "system", content: "You are a business intelligence analyst. Return ONLY valid JSON matching the requested schema. No markdown, no explanation." },
        { role: "user", content: prompt },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "financial_enrichment",
          strict: true,
          schema: {
            type: "object",
            properties: {
              isPublicCompany: { type: "boolean", description: "Whether the company is publicly traded" },
              stockTicker: { type: ["string", "null"], description: "Stock ticker symbol if public, null otherwise" },
              estimatedRevenue: { type: ["number", "null"], description: "Estimated annual revenue in USD" },
              revenueConfidence: { type: "string", enum: ["verified", "estimated", "unknown"], description: "Confidence level for revenue estimate" },
              revenueSource: { type: ["string", "null"], description: "Source of revenue data" },
              estimatedValuation: { type: ["number", "null"], description: "Estimated company valuation in USD" },
              valuationConfidence: { type: "string", enum: ["verified", "estimated", "unknown"], description: "Confidence level for valuation" },
              valuationSource: { type: ["string", "null"], description: "Source of valuation data" },
              estimatedEmployees: { type: ["number", "null"], description: "Estimated employee count" },
              industry: { type: ["string", "null"], description: "Primary industry classification" },
              subSector: { type: ["string", "null"], description: "Sub-sector within the industry" },
              companySize: { type: "string", enum: ["startup", "small", "medium", "large", "enterprise", "unknown"] },
              headquarters: { type: ["string", "null"], description: "HQ city and country" },
              foundedYear: { type: ["number", "null"], description: "Year founded" },
              keyProducts: { type: "array", items: { type: "string" }, description: "Key products or services (up to 5)" },
            },
            required: [
              "isPublicCompany", "stockTicker", "estimatedRevenue", "revenueConfidence",
              "revenueSource", "estimatedValuation", "valuationConfidence", "valuationSource",
              "estimatedEmployees", "industry", "subSector", "companySize", "headquarters",
              "foundedYear", "keyProducts"
            ],
            additionalProperties: false,
          },
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");

    const parsed = JSON.parse(content) as FinancialEnrichment;
    return parsed;
  } catch (err: any) {
    console.error(`[EntityResolver] Financial enrichment failed for ${params.orgName}: ${err.message}`);
    return {
      estimatedRevenue: null,
      revenueConfidence: "unknown",
      revenueSource: null,
      estimatedValuation: null,
      valuationConfidence: "unknown",
      valuationSource: null,
      estimatedEmployees: null,
      isPublicCompany: false,
      stockTicker: null,
      headquarters: null,
      foundedYear: null,
      industry: null,
      subSector: null,
      keyProducts: [],
      companySize: "unknown",
    };
  }
}

// ─── Full Entity Resolution Pipeline ────────────────────────────────────

/**
 * Complete entity resolution: identify the business, then enrich with financials.
 * Designed to be called after auto-crawl completes for a domain scan.
 */
export async function resolveAndEnrichEntity(params: {
  domain: string;
  pageTitle?: string | null;
  metaDescription?: string | null;
  html?: string | null;
  externalLinks?: string[] | null;
  tlsInfo?: { issuer?: string; subject?: string; subjectAltNames?: string[] } | null;
  whoisOrg?: string | null;
  technologies?: string[] | null;
  rawHeaders?: Record<string, string> | null;
}): Promise<EntityProfile> {
  // Step 1: Resolve the entity identity
  const baseEntity = resolveEntity(params);

  // Step 2: Enrich with financial data
  const financials = await enrichEntityFinancials({
    orgName: baseEntity.orgName,
    domain: params.domain,
    industry: null, // Will be determined by LLM
    technologies: params.technologies,
  });

  // Step 3: Combine into full profile
  const fullProfile: EntityProfile = {
    ...baseEntity,
    industry: financials.industry,
    subSector: financials.subSector,
    companySize: financials.companySize,
    estimatedRevenue: financials.estimatedRevenue,
    revenueConfidence: financials.revenueConfidence,
    revenueSource: financials.revenueSource,
    estimatedValuation: financials.estimatedValuation,
    valuationConfidence: financials.valuationConfidence,
    valuationSource: financials.valuationSource,
    estimatedEmployees: financials.estimatedEmployees,
    isPublicCompany: financials.isPublicCompany,
    stockTicker: financials.stockTicker,
    headquarters: financials.headquarters,
    foundedYear: financials.foundedYear,
    keyProducts: financials.keyProducts,
  };

  return fullProfile;
}

// ─── BIA Financial Impact Enhancement ───────────────────────────────────

/**
 * Calculate enhanced financial impact ratings using entity financial data.
 * Maps revenue/valuation to concrete dollar-value impact estimates for BIA.
 */
export function calculateFinancialImpact(entity: EntityProfile): {
  maxSingleIncidentLoss: number;
  estimatedDailyRevenueLoss: number;
  regulatoryFineExposure: number;
  reputationalDamageEstimate: number;
  totalMaxExposure: number;
  impactTier: "catastrophic" | "severe" | "significant" | "moderate" | "minimal";
  rationale: string;
} {
  const revenue = entity.estimatedRevenue || 0;
  const valuation = entity.estimatedValuation || 0;
  const employees = entity.estimatedEmployees || 0;

  // Daily revenue (assuming 365 operating days)
  const dailyRevenue = revenue > 0 ? Math.round(revenue / 365) : 0;

  // Estimate max single incident loss as % of annual revenue
  // Based on Ponemon/IBM Cost of Data Breach studies
  let incidentLossRate = 0.03; // Default 3% of revenue
  if (entity.industry?.toLowerCase().includes("healthcare")) incidentLossRate = 0.05;
  else if (entity.industry?.toLowerCase().includes("financial")) incidentLossRate = 0.04;
  else if (entity.industry?.toLowerCase().includes("technology")) incidentLossRate = 0.035;
  else if (entity.industry?.toLowerCase().includes("government")) incidentLossRate = 0.02;

  const maxSingleIncidentLoss = Math.round(revenue * incidentLossRate);

  // Regulatory fine exposure (GDPR up to 4% of global revenue, HIPAA up to $1.5M per violation)
  const regulatoryFineExposure = Math.round(revenue * 0.04);

  // Reputational damage estimate (typically 1-5% of market cap / valuation)
  const reputationalDamageEstimate = Math.round((valuation || revenue * 3) * 0.02);

  // Total max exposure
  const totalMaxExposure = maxSingleIncidentLoss + regulatoryFineExposure + reputationalDamageEstimate + (dailyRevenue * 7); // 7 days downtime

  // Determine impact tier
  let impactTier: "catastrophic" | "severe" | "significant" | "moderate" | "minimal";
  if (totalMaxExposure > 100_000_000) impactTier = "catastrophic";
  else if (totalMaxExposure > 10_000_000) impactTier = "severe";
  else if (totalMaxExposure > 1_000_000) impactTier = "significant";
  else if (totalMaxExposure > 100_000) impactTier = "moderate";
  else impactTier = "minimal";

  const rationale = [
    revenue > 0 ? `Annual revenue: $${(revenue / 1_000_000).toFixed(1)}M` : "Revenue: unknown",
    valuation > 0 ? `Valuation: $${(valuation / 1_000_000).toFixed(1)}M` : null,
    employees > 0 ? `Employees: ~${employees.toLocaleString()}` : null,
    entity.industry ? `Industry: ${entity.industry}` : null,
    entity.isPublicCompany ? `Publicly traded (${entity.stockTicker})` : "Private company",
    `Incident loss rate: ${(incidentLossRate * 100).toFixed(1)}% (industry-adjusted)`,
  ].filter(Boolean).join(". ");

  return {
    maxSingleIncidentLoss,
    estimatedDailyRevenueLoss: dailyRevenue,
    regulatoryFineExposure,
    reputationalDamageEstimate,
    totalMaxExposure,
    impactTier,
    rationale,
  };
}
