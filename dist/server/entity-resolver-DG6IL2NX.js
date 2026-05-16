import "./chunk-KFQGP6VL.js";

// server/lib/entity-resolver.ts
var HOSTING_PROVIDERS = /* @__PURE__ */ new Set([
  // Cloud / IaaS
  "amazon.com",
  "amazon technologies",
  "amazon web services",
  "aws",
  "amazon",
  "google llc",
  "google cloud",
  "google inc",
  "alphabet",
  "microsoft corporation",
  "microsoft",
  "azure",
  "digitalocean",
  "digital ocean",
  "linode",
  "akamai technologies",
  "akamai",
  "oracle corporation",
  "oracle",
  "ibm",
  "rackspace",
  "ovh",
  "ovhcloud",
  "hetzner",
  "vultr",
  "upcloud",
  // CDN
  "cloudflare",
  "cloudflare inc",
  "fastly",
  "stackpath",
  "keycdn",
  "bunny.net",
  "bunnycdn",
  "cdn77",
  "limelight networks",
  "edgecast",
  "imperva",
  "incapsula",
  "sucuri",
  // Hosting
  "godaddy",
  "go daddy",
  "godaddy.com",
  "namecheap",
  "name cheap",
  "bluehost",
  "hostgator",
  "siteground",
  "dreamhost",
  "a2 hosting",
  "ionos",
  "1and1",
  "1&1",
  "hostinger",
  "inmotion hosting",
  "wpengine",
  "wp engine",
  "kinsta",
  "flywheel",
  "pantheon",
  "netlify",
  "vercel",
  "heroku",
  "render",
  "railway",
  // Registrars
  "enom",
  "tucows",
  "network solutions",
  "register.com",
  "gandi",
  "hover",
  "porkbun",
  "dynadot",
  "epik",
  "markmonitor",
  // DNS providers
  "dnsimple",
  "dnsmadeeasy",
  "ns1",
  "route53",
  "ultradns",
  // Security / WAF
  "comodo",
  "sectigo",
  "digicert",
  "let's encrypt",
  "letsencrypt",
  "globalsign",
  "entrust",
  "thawte",
  "geotrust",
  "rapid ssl",
  // Telecom / ISP
  "comcast",
  "verizon",
  "at&t",
  "centurylink",
  "lumen technologies",
  "cogent",
  "level 3",
  "telia",
  "ntt",
  "zayo",
  // Privacy / proxy
  "whoisguard",
  "privacy protect",
  "domains by proxy",
  "contact privacy",
  "withheld for privacy",
  "redacted for privacy",
  "data protected",
  "identity protection",
  "perfect privacy",
  "whois privacy"
]);
function isHostingProvider(orgName) {
  if (!orgName) return false;
  const lower = orgName.toLowerCase().trim();
  for (const provider of HOSTING_PROVIDERS) {
    if (lower === provider || lower.includes(provider) || provider.includes(lower)) {
      return true;
    }
  }
  if (/\b(hosting|registrar|registry|datacenter|data center|colocation|colo)\b/i.test(orgName)) {
    return true;
  }
  return false;
}
function extractCopyrightHolder(html) {
  if (!html) return null;
  const patterns = [
    /(?:©|&copy;|copyright)\s*(?:\d{4}[-–]\d{4}|\d{4})?\s*([A-Z][A-Za-z0-9\s&.,'-]{2,60}?)(?:\.|,|\s*All\s*rights|\s*<|\s*$)/gi,
    /(?:©|&copy;|copyright)\s*(?:\d{4}[-–]\d{4}|\d{4})?\s*by\s+([A-Z][A-Za-z0-9\s&.,'-]{2,60}?)(?:\.|,|\s*All\s*rights|\s*<|\s*$)/gi
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
function extractFromTitle(title) {
  if (!title) return null;
  const separators = [" - ", " | ", " \u2014 ", " \u2013 ", " :: ", " : "];
  for (const sep of separators) {
    if (title.includes(sep)) {
      const parts = title.split(sep);
      const candidate = parts[0].trim();
      if (candidate.length > 2 && candidate.length < 80 && !isHostingProvider(candidate)) {
        return candidate;
      }
    }
  }
  if (title.length > 2 && title.length < 60 && !isHostingProvider(title)) {
    return title;
  }
  return null;
}
function extractSocialProfiles(externalLinks) {
  const profiles = [];
  const seen = /* @__PURE__ */ new Set();
  for (const link of externalLinks) {
    try {
      const url = new URL(link);
      const host = url.hostname.toLowerCase();
      let platform = null;
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
    }
  }
  return profiles;
}
function resolveEntity(params) {
  const evidence = [];
  const candidates = [];
  if (params.html) {
    const copyrightHolder = extractCopyrightHolder(params.html);
    if (copyrightHolder) {
      evidence.push({ source: "html_copyright", signal: "Copyright text", value: copyrightHolder, confidence: 90 });
      candidates.push({ name: copyrightHolder, confidence: 90, source: "copyright" });
    }
  }
  if (params.pageTitle) {
    const titleName = extractFromTitle(params.pageTitle);
    if (titleName) {
      evidence.push({ source: "page_title", signal: "Page title", value: titleName, confidence: 75 });
      candidates.push({ name: titleName, confidence: 75, source: "title" });
    }
  }
  if (params.metaDescription) {
    const desc = params.metaDescription;
    const aboutMatch = desc.match(/^([A-Z][A-Za-z0-9\s&.,'-]{2,40}?)\s+(?:is|provides|offers|delivers|helps|enables|builds|creates|specializes)/);
    if (aboutMatch?.[1] && !isHostingProvider(aboutMatch[1])) {
      evidence.push({ source: "meta_description", signal: "Meta description", value: aboutMatch[1], confidence: 65 });
      candidates.push({ name: aboutMatch[1], confidence: 65, source: "meta" });
    }
  }
  if (params.tlsInfo?.subject) {
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
  if (params.whoisOrg) {
    const whoisFiltered = isHostingProvider(params.whoisOrg);
    if (!whoisFiltered) {
      evidence.push({ source: "whois", signal: "WHOIS registrant org", value: params.whoisOrg, confidence: 70 });
      candidates.push({ name: params.whoisOrg, confidence: 70, source: "whois" });
    } else {
      evidence.push({ source: "whois", signal: "WHOIS registrant org (hosting provider filtered)", value: params.whoisOrg, confidence: 0 });
    }
  }
  const socialProfiles = extractSocialProfiles(params.externalLinks || []);
  for (const profile of socialProfiles) {
    if (profile.platform === "LinkedIn") {
      const match = profile.url.match(/\/company\/([^/?]+)/);
      if (match?.[1]) {
        const linkedInName = match[1].replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
        evidence.push({ source: "social_linkedin", signal: "LinkedIn company page", value: linkedInName, confidence: 60 });
        candidates.push({ name: linkedInName, confidence: 60, source: "linkedin" });
      }
    }
  }
  const domainBase = params.domain.replace(/^www\./, "").split(".")[0];
  if (domainBase && domainBase.length > 1) {
    const domainName = domainBase.includes("-") ? domainBase.split("-").map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ") : domainBase.toUpperCase();
    evidence.push({ source: "domain_name", signal: "Domain-derived name", value: domainName, confidence: 40 });
    candidates.push({ name: domainName, confidence: 40, source: "domain_name" });
  }
  const thirdPartyNames = ["outlook", "sign in", "login", "microsoft", "google", "yahoo", "office 365", "webmail", "roundcube", "cpanel", "plesk", "wordpress", "godaddy", "namecheap", "cloudflare", "squarespace", "wix", "shopify", "github", "gitlab", "bitbucket", "jira", "confluence", "atlassian", "salesforce", "zendesk", "freshdesk", "hubspot", "mailchimp", "sendgrid", "twilio", "slack", "zoom", "teams", "dropbox", "box.com", "docusign", "adobe", "okta", "auth0", "onelogin", "duo security", "lastpass", "aws", "amazon web services", "azure", "oracle cloud", "heroku", "netlify", "vercel", "firebase", "supabase", "akamai", "fastly", "imperva", "sucuri", "proofpoint", "mimecast", "barracuda", "sophos", "fortinet", "palo alto", "crowdstrike", "sentinelone", "carbon black", "cyberark", "servicenow", "workday", "bamboohr", "paylocity", "adp", "welcome to", "home page", "default page", "coming soon", "under construction", "parked domain", "domain for sale"];
  const filteredCandidates = candidates.filter((c) => !thirdPartyNames.some((tp) => c.name.toLowerCase().includes(tp)));
  const finalCandidates = filteredCandidates.length > 0 ? filteredCandidates : candidates;
  finalCandidates.sort((a, b) => b.confidence - a.confidence);
  let orgName = params.domain.replace(/^www\./, "");
  let bestConfidence = 0;
  let identificationMethod = "domain_fallback";
  if (finalCandidates.length > 0) {
    orgName = finalCandidates[0].name;
    bestConfidence = finalCandidates[0].confidence;
    identificationMethod = finalCandidates[0].source;
    if (finalCandidates.length >= 2) {
      const topName = finalCandidates[0].name.toLowerCase();
      const agreeing = finalCandidates.filter(
        (c) => c.name.toLowerCase() === topName || c.name.toLowerCase().includes(topName) || topName.includes(c.name.toLowerCase())
      );
      if (agreeing.length >= 2) {
        bestConfidence = Math.min(100, bestConfidence + 10 * (agreeing.length - 1));
        identificationMethod = `multi_signal (${agreeing.map((a) => a.source).join(", ")})`;
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
    whoisIsHostingProvider: params.whoisOrg ? isHostingProvider(params.whoisOrg) : false
  };
}
async function enrichEntityFinancials(params) {
  try {
    const { invokeLLM } = await import("./llm-4Y4Y4JIZ.js");
    const prompt = `You are a business intelligence analyst. Given the following company information, provide your best estimate of their financial profile based on publicly available information, industry benchmarks, and observable signals.

Company: ${params.orgName}
Domain: ${params.domain}
${params.industry ? `Industry: ${params.industry}` : ""}
${params.technologies?.length ? `Technologies detected: ${params.technologies.slice(0, 20).join(", ")}` : ""}
${params.employeeSignals?.length ? `Employee signals: ${params.employeeSignals.join("; ")}` : ""}

CRITICAL: You MUST identify the company that OWNS AND OPERATES the domain "${params.domain}". 
Do NOT confuse this with other companies that may have a similar name but operate different domains.
If you are not confident that your answer describes the actual operator of ${params.domain}, set all values to null and companySize to "unknown".

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
- Be conservative in estimates \u2014 underestimate rather than overestimate
- IMPORTANT: If there are multiple companies with similar names, you MUST identify the one that operates the domain "${params.domain}". If unsure, return null for all financial fields.`;
    const response = await invokeLLM({
      _caller: "entity-resolver.enrichEntityFinancials",
      _priority: "bulk",
      messages: [
        { role: "system", content: "You are a business intelligence analyst. Return ONLY valid JSON matching the requested schema. No markdown, no explanation." },
        { role: "user", content: prompt }
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
              keyProducts: { type: "array", items: { type: "string" }, description: "Key products or services (up to 5)" }
            },
            required: [
              "isPublicCompany",
              "stockTicker",
              "estimatedRevenue",
              "revenueConfidence",
              "revenueSource",
              "estimatedValuation",
              "valuationConfidence",
              "valuationSource",
              "estimatedEmployees",
              "industry",
              "subSector",
              "companySize",
              "headquarters",
              "foundedYear",
              "keyProducts"
            ],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    const parsed = JSON.parse(content);
    return parsed;
  } catch (err) {
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
      companySize: "unknown"
    };
  }
}
async function resolveAndEnrichEntity(params) {
  const baseEntity = resolveEntity(params);
  const financials = await enrichEntityFinancials({
    orgName: baseEntity.orgName,
    domain: params.domain,
    industry: null,
    // Will be determined by LLM
    technologies: params.technologies
  });
  const fullProfile = {
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
    keyProducts: financials.keyProducts
  };
  return fullProfile;
}
function calculateFinancialImpact(entity) {
  const revenue = entity.estimatedRevenue || 0;
  const valuation = entity.estimatedValuation || 0;
  const employees = entity.estimatedEmployees || 0;
  const dailyRevenue = revenue > 0 ? Math.round(revenue / 365) : 0;
  let incidentLossRate = 0.03;
  if (entity.industry?.toLowerCase().includes("healthcare")) incidentLossRate = 0.05;
  else if (entity.industry?.toLowerCase().includes("financial")) incidentLossRate = 0.04;
  else if (entity.industry?.toLowerCase().includes("technology")) incidentLossRate = 0.035;
  else if (entity.industry?.toLowerCase().includes("government")) incidentLossRate = 0.02;
  const maxSingleIncidentLoss = Math.round(revenue * incidentLossRate);
  const regulatoryFineExposure = Math.round(revenue * 0.04);
  const reputationalDamageEstimate = Math.round((valuation || revenue * 3) * 0.02);
  const totalMaxExposure = maxSingleIncidentLoss + regulatoryFineExposure + reputationalDamageEstimate + dailyRevenue * 7;
  let impactTier;
  if (totalMaxExposure > 1e8) impactTier = "catastrophic";
  else if (totalMaxExposure > 1e7) impactTier = "severe";
  else if (totalMaxExposure > 1e6) impactTier = "significant";
  else if (totalMaxExposure > 1e5) impactTier = "moderate";
  else impactTier = "minimal";
  const rationale = [
    revenue > 0 ? `Annual revenue: $${(revenue / 1e6).toFixed(1)}M` : "Revenue: unknown",
    valuation > 0 ? `Valuation: $${(valuation / 1e6).toFixed(1)}M` : null,
    employees > 0 ? `Employees: ~${employees.toLocaleString()}` : null,
    entity.industry ? `Industry: ${entity.industry}` : null,
    entity.isPublicCompany ? `Publicly traded (${entity.stockTicker})` : "Private company",
    `Incident loss rate: ${(incidentLossRate * 100).toFixed(1)}% (industry-adjusted)`
  ].filter(Boolean).join(". ");
  return {
    maxSingleIncidentLoss,
    estimatedDailyRevenueLoss: dailyRevenue,
    regulatoryFineExposure,
    reputationalDamageEstimate,
    totalMaxExposure,
    impactTier,
    rationale
  };
}
export {
  calculateFinancialImpact,
  enrichEntityFinancials,
  resolveAndEnrichEntity,
  resolveEntity
};
