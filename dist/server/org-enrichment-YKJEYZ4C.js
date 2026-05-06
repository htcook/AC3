import "./chunk-KFQGP6VL.js";

// server/lib/org-enrichment.ts
function extractTechFromHeaders(headers) {
  const techs = [];
  const headerStr = JSON.stringify(headers).toLowerCase();
  const techSignatures = [
    { pattern: /cloudflare/i, name: "Cloudflare", category: "cdn" },
    { pattern: /akamai/i, name: "Akamai", category: "cdn" },
    { pattern: /fastly/i, name: "Fastly", category: "cdn" },
    { pattern: /nginx/i, name: "Nginx", category: "infrastructure" },
    { pattern: /apache/i, name: "Apache", category: "infrastructure" },
    { pattern: /aws/i, name: "AWS", category: "hosting" },
    { pattern: /gws/i, name: "Google Web Server", category: "hosting" },
    { pattern: /microsoft/i, name: "Microsoft IIS", category: "infrastructure" },
    { pattern: /wordpress/i, name: "WordPress", category: "cms" },
    { pattern: /drupal/i, name: "Drupal", category: "cms" },
    { pattern: /shopify/i, name: "Shopify", category: "frontend" },
    { pattern: /x-powered-by.*express/i, name: "Express.js", category: "backend" },
    { pattern: /x-powered-by.*php/i, name: "PHP", category: "backend" },
    { pattern: /x-powered-by.*asp/i, name: "ASP.NET", category: "backend" }
  ];
  for (const sig of techSignatures) {
    if (sig.pattern.test(headerStr)) {
      techs.push({ name: sig.name, category: sig.category, confidence: 80 });
    }
  }
  return techs;
}
function extractTechFromHtml(html) {
  const techs = [];
  const htmlLower = html.toLowerCase();
  const htmlSignatures = [
    { pattern: /react/i, name: "React", category: "frontend" },
    { pattern: /vue\.js|vuejs/i, name: "Vue.js", category: "frontend" },
    { pattern: /angular/i, name: "Angular", category: "frontend" },
    { pattern: /next\.js|nextjs|__next/i, name: "Next.js", category: "frontend" },
    { pattern: /gatsby/i, name: "Gatsby", category: "frontend" },
    { pattern: /tailwindcss|tailwind/i, name: "Tailwind CSS", category: "frontend" },
    { pattern: /bootstrap/i, name: "Bootstrap", category: "frontend" },
    { pattern: /jquery/i, name: "jQuery", category: "frontend" },
    { pattern: /google-analytics|gtag|ga\.js/i, name: "Google Analytics", category: "analytics" },
    { pattern: /hotjar/i, name: "Hotjar", category: "analytics" },
    { pattern: /segment\.com|analytics\.js/i, name: "Segment", category: "analytics" },
    { pattern: /hubspot/i, name: "HubSpot", category: "analytics" },
    { pattern: /salesforce/i, name: "Salesforce", category: "other" },
    { pattern: /stripe/i, name: "Stripe", category: "other" },
    { pattern: /intercom/i, name: "Intercom", category: "other" },
    { pattern: /zendesk/i, name: "Zendesk", category: "other" },
    { pattern: /cloudflare/i, name: "Cloudflare", category: "cdn" },
    { pattern: /recaptcha/i, name: "reCAPTCHA", category: "security" },
    { pattern: /hcaptcha/i, name: "hCaptcha", category: "security" },
    { pattern: /wp-content|wordpress/i, name: "WordPress", category: "cms" },
    { pattern: /drupal/i, name: "Drupal", category: "cms" },
    { pattern: /joomla/i, name: "Joomla", category: "cms" },
    { pattern: /wix\.com/i, name: "Wix", category: "cms" },
    { pattern: /squarespace/i, name: "Squarespace", category: "cms" },
    { pattern: /webflow/i, name: "Webflow", category: "cms" }
  ];
  for (const sig of htmlSignatures) {
    if (sig.pattern.test(htmlLower)) {
      techs.push({ name: sig.name, category: sig.category, confidence: 70 });
    }
  }
  return techs;
}
function parseHtmlBasic(html) {
  const data = {
    title: "",
    metaDescription: "",
    metaKeywords: [],
    headings: [],
    paragraphs: [],
    links: [],
    socialLinks: {},
    contactEmails: [],
    phoneNumbers: [],
    techIndicators: [],
    legalPages: {},
    structuredData: []
  };
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (titleMatch) data.title = titleMatch[1].trim().replace(/\s+/g, " ");
  const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([\s\S]*?)["']/i);
  if (descMatch) data.metaDescription = descMatch[1].trim();
  const kwMatch = html.match(/<meta[^>]*name=["']keywords["'][^>]*content=["']([\s\S]*?)["']/i);
  if (kwMatch) data.metaKeywords = kwMatch[1].split(",").map((k) => k.trim()).filter(Boolean);
  const headingRegex = /<h[1-3][^>]*>([\s\S]*?)<\/h[1-3]>/gi;
  let hMatch;
  while ((hMatch = headingRegex.exec(html)) !== null) {
    const text = hMatch[1].replace(/<[^>]+>/g, "").trim().replace(/\s+/g, " ");
    if (text.length > 2 && text.length < 200) data.headings.push(text);
  }
  const pRegex = /<p[^>]*>([\s\S]*?)<\/p>/gi;
  let pMatch;
  let pCount = 0;
  while ((pMatch = pRegex.exec(html)) !== null && pCount < 30) {
    const text = pMatch[1].replace(/<[^>]+>/g, "").trim().replace(/\s+/g, " ");
    if (text.length > 20) {
      data.paragraphs.push(text);
      pCount++;
    }
  }
  const linkRegex = /<a[^>]*href=["'](https?:\/\/[^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let lMatch;
  while ((lMatch = linkRegex.exec(html)) !== null) {
    const text = lMatch[2].replace(/<[^>]+>/g, "").trim();
    data.links.push({ text, href: lMatch[1] });
  }
  const socialPatterns = [
    { key: "linkedin", pattern: /https?:\/\/(www\.)?linkedin\.com\/company\/[^\s"']+/i },
    { key: "twitter", pattern: /https?:\/\/(www\.)?(twitter|x)\.com\/[^\s"']+/i },
    { key: "github", pattern: /https?:\/\/(www\.)?github\.com\/[^\s"']+/i },
    { key: "facebook", pattern: /https?:\/\/(www\.)?facebook\.com\/[^\s"']+/i },
    { key: "crunchbase", pattern: /https?:\/\/(www\.)?crunchbase\.com\/organization\/[^\s"']+/i }
  ];
  for (const sp of socialPatterns) {
    const m = html.match(sp.pattern);
    if (m) data.socialLinks[sp.key] = m[0];
  }
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = html.match(emailRegex) || [];
  data.contactEmails = [...new Set(emails)].filter(
    (e) => !e.includes("example.com") && !e.includes("sentry") && !e.includes("webpack")
  ).slice(0, 10);
  const phoneRegex = /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;
  const phones = html.match(phoneRegex) || [];
  data.phoneNumbers = [...new Set(phones)].slice(0, 5);
  const privacyMatch = html.match(/href=["']([^"']*(?:privacy|data-protection)[^"']*)["']/i);
  if (privacyMatch) data.legalPages.privacy = privacyMatch[1];
  const termsMatch = html.match(/href=["']([^"']*(?:terms|tos|terms-of-service)[^"']*)["']/i);
  if (termsMatch) data.legalPages.terms = termsMatch[1];
  const securityMatch = html.match(/href=["']([^"']*(?:security|trust)[^"']*)["']/i);
  if (securityMatch) data.legalPages.security = securityMatch[1];
  data.techIndicators = extractTechFromHtml(html);
  const jsonLdRegex = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let jMatch;
  while ((jMatch = jsonLdRegex.exec(html)) !== null) {
    try {
      data.structuredData.push(JSON.parse(jMatch[1]));
    } catch {
    }
  }
  return data;
}
async function scrapeWebsite(domain) {
  const url = domain.startsWith("http") ? domain : `https://${domain}`;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15e3);
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
      },
      redirect: "follow"
    });
    clearTimeout(timeout);
    const html = await response.text();
    const headers = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
    const scraped = parseHtmlBasic(html);
    const headerTechs = extractTechFromHeaders(headers);
    return { ...scraped, headerTechs };
  } catch (error) {
    return {
      title: "",
      metaDescription: "",
      metaKeywords: [],
      headings: [],
      paragraphs: [],
      links: [],
      socialLinks: {},
      contactEmails: [],
      phoneNumbers: [],
      techIndicators: [],
      legalPages: {},
      structuredData: [],
      headerTechs: []
    };
  }
}
async function enrichFromDNS(domain) {
  const result = {
    aRecords: [],
    mxRecords: [],
    nsRecords: [],
    txtRecords: [],
    caaRecords: []
  };
  try {
    const dnsTypes = ["A", "MX", "NS", "TXT", "CAA"];
    for (const type of dnsTypes) {
      try {
        const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`, {
          headers: { "Accept": "application/dns-json" }
        });
        const data = await resp.json();
        if (data.Answer) {
          for (const answer of data.Answer) {
            const val = answer.data.replace(/^"|"$/g, "");
            switch (type) {
              case "A":
                result.aRecords.push(val);
                break;
              case "MX":
                result.mxRecords.push(val);
                break;
              case "NS":
                result.nsRecords.push(val);
                break;
              case "TXT": {
                result.txtRecords.push(val);
                if (val.startsWith("v=spf1")) result.spfRecord = val;
                break;
              }
              case "CAA":
                result.caaRecords.push(val);
                break;
            }
          }
        }
      } catch {
      }
    }
    try {
      const dmarcResp = await fetch(`https://cloudflare-dns.com/dns-query?name=_dmarc.${domain}&type=TXT`, {
        headers: { "Accept": "application/dns-json" }
      });
      const dmarcData = await dmarcResp.json();
      if (dmarcData.Answer) {
        for (const a of dmarcData.Answer) {
          const val = a.data.replace(/^"|"$/g, "");
          if (val.startsWith("v=DMARC1")) result.dmarcRecord = val;
        }
      }
    } catch {
    }
  } catch {
  }
  return result;
}
async function enrichFromShodan(domain, apiKey) {
  if (!apiKey) return null;
  try {
    const dnsResp = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
      headers: { "Accept": "application/dns-json" }
    });
    const dnsData = await dnsResp.json();
    const ip = dnsData.Answer?.[0]?.data;
    if (!ip) return null;
    const resp = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);
    if (!resp.ok) return null;
    const data = await resp.json();
    return {
      openPorts: data.ports || [],
      services: (data.data || []).map((s) => ({
        port: s.port,
        protocol: s.transport,
        product: s.product,
        version: s.version
      })),
      vulns: data.vulns || [],
      os: data.os || void 0,
      hostnames: data.hostnames || [],
      isp: data.isp,
      org: data.org,
      asn: data.asn,
      country: data.country_name,
      city: data.city
    };
  } catch {
    return null;
  }
}
async function enrichFromSecurityTrails(domain, apiKey) {
  if (!apiKey) return null;
  try {
    const headers = { "APIKEY": apiKey, "Accept": "application/json" };
    const subResp = await fetch(`https://api.securitytrails.com/v1/domain/${domain}/subdomains`, { headers });
    const subData = await subResp.json();
    const whoisResp = await fetch(`https://api.securitytrails.com/v1/domain/${domain}/whois`, { headers });
    const whoisData = await whoisResp.json();
    return {
      subdomainCount: subData.subdomain_count || 0,
      subdomains: (subData.subdomains || []).slice(0, 50).map((s) => `${s}.${domain}`),
      historicalDns: [],
      associatedDomains: [],
      whois: {
        registrar: whoisData.result?.registrar_name,
        createdDate: whoisData.result?.created_date,
        expiresDate: whoisData.result?.expires_date,
        nameServers: whoisData.result?.name_servers || [],
        registrantOrg: whoisData.result?.contacts?.registrant?.[0]?.organization,
        registrantCountry: whoisData.result?.contacts?.registrant?.[0]?.country
      }
    };
  } catch {
    return null;
  }
}
async function enrichFromCensys(domain, apiId, apiSecret) {
  if (!apiId || !apiSecret) return null;
  try {
    const auth = Buffer.from(`${apiId}:${apiSecret}`).toString("base64");
    const resp = await fetch(`https://search.censys.io/api/v2/hosts/search?q=${domain}&per_page=5`, {
      headers: {
        "Authorization": `Basic ${auth}`,
        "Accept": "application/json"
      }
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    const firstHit = data.result?.hits?.[0];
    if (!firstHit) return null;
    return {
      services: (firstHit.services || []).map((s) => ({
        port: s.port,
        serviceName: s.service_name,
        transportProtocol: s.transport_protocol
      })),
      operatingSystem: firstHit.operating_system?.product,
      lastUpdated: firstHit.last_updated_at,
      autonomousSystem: firstHit.autonomous_system ? {
        asn: firstHit.autonomous_system.asn,
        name: firstHit.autonomous_system.name,
        bgpPrefix: firstHit.autonomous_system.bgp_prefix
      } : void 0,
      location: firstHit.location ? {
        country: firstHit.location.country,
        city: firstHit.location.city,
        province: firstHit.location.province
      } : void 0
    };
  } catch {
    return null;
  }
}
function buildLLMPromptForOrgProfile(scrapedData, domain) {
  const context = [
    `Domain: ${domain}`,
    `Website Title: ${scrapedData.title}`,
    `Meta Description: ${scrapedData.metaDescription}`,
    `Keywords: ${scrapedData.metaKeywords.join(", ")}`,
    `Headings: ${scrapedData.headings.slice(0, 20).join(" | ")}`,
    `Content Excerpts: ${scrapedData.paragraphs.slice(0, 15).join(" ")}`,
    `Contact Emails: ${scrapedData.contactEmails.join(", ")}`,
    `Structured Data: ${JSON.stringify(scrapedData.structuredData).slice(0, 2e3)}`
  ].join("\n");
  return `Analyze the following website data and extract a comprehensive organizational profile. Return a JSON object with these fields:

{
  "companyName": "Official company name",
  "industry": "Primary industry (e.g., Technology, Healthcare, Finance, Government, Defense)",
  "sector": "Specific sector (e.g., Cloud Computing, Cybersecurity, SaaS)",
  "description": "2-3 sentence company description",
  "products": [{"name": "...", "description": "...", "category": "...", "criticality": "critical|high|medium|low", "revenueImpact": "primary|secondary|supporting"}],
  "services": [{"name": "...", "description": "...", "category": "...", "criticality": "critical|high|medium|low", "revenueImpact": "primary|secondary|supporting"}],
  "employeeEstimate": {"range": "e.g., 50-200", "approximate": 100},
  "locations": [{"type": "headquarters|office", "city": "...", "state": "...", "country": "..."}],
  "financials": {"estimatedRevenue": "...", "fundingStage": "...", "publiclyTraded": false},
  "regulatoryContext": {
    "frameworks": ["FedRAMP", "SOC2", etc.],
    "certifications": [],
    "dataTypes": ["PII", "PHI", etc.],
    "complianceIndicators": ["mentions of compliance on website"]
  }
}

Website Data:
${context}

Return ONLY the JSON object, no markdown or explanation.`;
}
function buildLLMPromptForBIA(orgProfile, shodanData, dnsData, darkwebContext, companyIntelContext, detectedRegulations) {
  const context = [
    `Company: ${orgProfile.companyName}`,
    `Industry: ${orgProfile.industry} / ${orgProfile.sector}`,
    `Description: ${orgProfile.description}`,
    `Products: ${orgProfile.products.map((p) => p.name).join(", ")}`,
    `Services: ${orgProfile.services.map((s) => s.name).join(", ")}`,
    `Technologies: ${orgProfile.technologies.map((t) => t.name).join(", ")}`,
    `Employee Count: ~${orgProfile.employees.approximate}`,
    `Regulatory Frameworks: ${orgProfile.regulatoryContext.frameworks.join(", ")}`,
    `Data Types: ${orgProfile.regulatoryContext.dataTypes.join(", ")}`,
    `Open Ports: ${shodanData?.openPorts?.join(", ") || "Unknown"}`,
    `Services Exposed: ${shodanData?.services?.map((s) => `${s.port}/${s.product || s.protocol}`).join(", ") || "Unknown"}`,
    `Known Vulns: ${shodanData?.vulns?.join(", ") || "None detected"}`,
    `MX Records: ${dnsData.mxRecords.join(", ")}`,
    `SPF: ${dnsData.spfRecord || "Not configured"}`,
    `DMARC: ${dnsData.dmarcRecord || "Not configured"}`
  ];
  if (darkwebContext) {
    context.push("");
    context.push("=== DARKWEB & BREACH INTELLIGENCE ===");
    context.push(`Total Breached Credentials: ${darkwebContext.totalBreachedCredentials}`);
    if (darkwebContext.breachSources.length > 0) {
      context.push(`Breach Sources: ${darkwebContext.breachSources.map((s) => `${s.source} (${s.count} creds${s.latestDate ? `, latest: ${s.latestDate}` : ""})`).join("; ")}`);
    }
    context.push(`Stealer Log Exposures: ${darkwebContext.stealerLogExposures}`);
    if (darkwebContext.ransomwareVictim) {
      context.push(`RANSOMWARE VICTIM: Yes \u2014 Group: ${darkwebContext.ransomwareGroup || "Unknown"}, Date: ${darkwebContext.ransomwareDate || "Unknown"}`);
    }
    context.push(`Dark Web Mentions: ${darkwebContext.darkwebMentions}`);
    context.push(`Paste Site Mentions: ${darkwebContext.pasteSiteMentions}`);
    if (darkwebContext.threatActorReferences.length > 0) {
      context.push(`Referenced Threat Actors: ${darkwebContext.threatActorReferences.join(", ")}`);
    }
    context.push(`Associated IOCs: ${darkwebContext.iocCount}`);
    context.push(`Typosquat Domains Found: ${darkwebContext.typosquatDomainsFound}`);
  }
  if (companyIntelContext) {
    context.push("");
    context.push("=== COMPANY INTELLIGENCE ===");
    if (companyIntelContext.techStack.length > 0) {
      context.push(`Detected Tech Stack: ${companyIntelContext.techStack.map((t) => `${t.name} (${t.category})`).join(", ")}`);
    }
    if (companyIntelContext.asnInfo.length > 0) {
      context.push(`ASN Ownership: ${companyIntelContext.asnInfo.map((a) => `AS${a.asn} ${a.name} (${a.prefixCount} prefixes)`).join("; ")}`);
    }
    if (companyIntelContext.relatedDomains.length > 0) {
      context.push(`Related Domains Owned: ${companyIntelContext.relatedDomains.slice(0, 20).join(", ")}${companyIntelContext.relatedDomains.length > 20 ? ` (+${companyIntelContext.relatedDomains.length - 20} more)` : ""}`);
    }
    context.push(`Historical DNS Changes: ${companyIntelContext.historicalDnsChanges}`);
    context.push(`Passive DNS Records: ${companyIntelContext.passiveDnsRecords}`);
  }
  if (detectedRegulations && detectedRegulations.length > 0) {
    context.push("");
    context.push("=== REGULATORY COMPLIANCE OBLIGATIONS ===");
    context.push(`Detected Frameworks: ${detectedRegulations.join(", ")}`);
    context.push("Note: These frameworks impose specific breach notification timelines, data handling requirements, and audit obligations that affect impact severity.");
  }
  return `Based on the following organizational profile, technical intelligence, darkweb exposure data, and regulatory context, generate a comprehensive Business Impact Analysis (BIA) and Hybrid Risk scoring.

IMPORTANT: Factor in the darkweb/breach data when scoring. Organizations with active credential leaks, stealer log exposure, or ransomware history should receive elevated CARVER scores for vulnerability and accessibility. Regulatory obligations amplify legal and financial impact categories. Typosquat domains indicate active phishing risk.

Return a JSON object:

Organization Data:
${context.join("\n")}

Return ONLY the JSON object, no markdown or explanation.

{
  "missionCriticalSystems": [
    {"name": "...", "description": "...", "type": "application|infrastructure|data_store|network|identity", "criticality": "critical|high|medium|low", "dependencies": [], "exposureLevel": "internet_facing|internal|hybrid"}
  ],
  "impactCategories": [
    {"category": "operational|financial|reputational|legal|safety", "severity": "catastrophic|severe|moderate|minor|negligible", "description": "...", "mtpd": "e.g., 4 hours"}
  ],
  "rtoRpoEstimates": [
    {"system": "...", "rto": "e.g., 1 hour", "rpo": "e.g., 15 minutes", "justification": "..."}
  ],
  "overallCriticality": "critical|high|medium|low",
  "carverScores": {
    "criticality": 1-10,
    "accessibility": 1-10,
    "recuperability": 1-10,
    "vulnerability": 1-10,
    "effect": 1-10,
    "recognizability": 1-10,
    "shockIndex": 1-10
  },
  "recommendations": ["actionable recommendation 1", "..."]
}

Return ONLY the JSON object, no markdown or explanation.`;
}
async function runEnrichmentPipeline(domain, config) {
  const cleanDomain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();
  const [scrapedRaw, dnsData, shodanData, securityTrailsData, censysData] = await Promise.all([
    scrapeWebsite(cleanDomain),
    enrichFromDNS(cleanDomain),
    enrichFromShodan(cleanDomain, config.shodanApiKey),
    enrichFromSecurityTrails(cleanDomain, config.securityTrailsApiKey),
    enrichFromCensys(cleanDomain, config.censysApiId, config.censysApiSecret)
  ]);
  const { headerTechs, ...scrapedData } = scrapedRaw;
  const allTechs = [...scrapedData.techIndicators, ...headerTechs];
  const uniqueTechs = Array.from(
    allTechs.reduce((map, t) => {
      const key = t.name.toLowerCase();
      if (!map.has(key) || map.get(key).confidence < t.confidence) {
        map.set(key, t);
      }
      return map;
    }, /* @__PURE__ */ new Map()).values()
  );
  const enrichmentSources = [
    {
      name: "Website Scrape",
      type: "website_scrape",
      dataPoints: scrapedData.headings.length + scrapedData.paragraphs.length + scrapedData.contactEmails.length,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    },
    {
      name: "DNS Records",
      type: "dns",
      dataPoints: dnsData.aRecords.length + dnsData.mxRecords.length + dnsData.txtRecords.length + dnsData.nsRecords.length,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    }
  ];
  if (shodanData) {
    enrichmentSources.push({
      name: "Shodan",
      type: "shodan",
      dataPoints: shodanData.openPorts.length + shodanData.services.length + shodanData.vulns.length,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  }
  if (securityTrailsData) {
    enrichmentSources.push({
      name: "SecurityTrails",
      type: "securitytrails",
      dataPoints: securityTrailsData.subdomainCount + (securityTrailsData.whois.registrar ? 5 : 0),
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  }
  if (censysData) {
    enrichmentSources.push({
      name: "Censys",
      type: "censys",
      dataPoints: censysData.services.length + (censysData.autonomousSystem ? 3 : 0),
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  }
  const orgProfile = {
    domain: cleanDomain,
    companyName: scrapedData.title.split(/[|\-–—]/).map((s) => s.trim())[0] || cleanDomain,
    industry: "Unknown",
    sector: "Unknown",
    description: scrapedData.metaDescription || "",
    products: [],
    services: [],
    technologies: uniqueTechs,
    employees: {
      range: "Unknown",
      approximate: 0,
      source: "Not yet enriched"
    },
    locations: shodanData?.country ? [{
      type: "unknown",
      country: shodanData.country,
      city: shodanData.city
    }] : [],
    socialMedia: scrapedData.socialLinks,
    contactInfo: {
      emails: scrapedData.contactEmails,
      phones: scrapedData.phoneNumbers,
      supportUrl: void 0,
      privacyPolicyUrl: scrapedData.legalPages.privacy,
      termsUrl: scrapedData.legalPages.terms
    },
    financials: {
      publiclyTraded: false
    },
    regulatoryContext: {
      frameworks: [],
      certifications: [],
      dataTypes: [],
      complianceIndicators: []
    },
    enrichmentSources,
    confidence: calculateConfidence(scrapedData, dnsData, shodanData, securityTrailsData, censysData),
    lastUpdated: (/* @__PURE__ */ new Date()).toISOString()
  };
  const llmOrgPrompt = buildLLMPromptForOrgProfile(scrapedData, cleanDomain);
  const llmBiaPrompt = buildLLMPromptForBIA(
    orgProfile,
    shodanData,
    dnsData,
    config.darkwebContext,
    config.companyIntelContext,
    config.detectedRegulations
  );
  return {
    orgProfile,
    dnsData,
    shodanData,
    securityTrailsData,
    censysData,
    scrapedData,
    llmOrgPrompt,
    llmBiaPrompt
  };
}
function calculateConfidence(scraped, dns, shodan, st, censys) {
  let score = 10;
  if (scraped.title) score += 10;
  if (scraped.metaDescription) score += 5;
  if (scraped.headings.length > 3) score += 10;
  if (scraped.paragraphs.length > 5) score += 10;
  if (scraped.contactEmails.length > 0) score += 5;
  if (scraped.structuredData.length > 0) score += 10;
  if (dns.aRecords.length > 0) score += 5;
  if (dns.mxRecords.length > 0) score += 5;
  if (dns.spfRecord) score += 3;
  if (dns.dmarcRecord) score += 3;
  if (shodan) score += 10;
  if (st) score += 10;
  if (censys) score += 5;
  return Math.min(score, 100);
}
function mergeLLMOrgData(profile, llmData) {
  const updated = { ...profile };
  if (typeof llmData.companyName === "string" && llmData.companyName) updated.companyName = llmData.companyName;
  if (typeof llmData.industry === "string" && llmData.industry) updated.industry = llmData.industry;
  if (typeof llmData.sector === "string" && llmData.sector) updated.sector = llmData.sector;
  if (typeof llmData.description === "string" && llmData.description) updated.description = llmData.description;
  if (Array.isArray(llmData.products)) {
    updated.products = llmData.products.map((p) => ({
      name: String(p.name || ""),
      description: String(p.description || ""),
      category: String(p.category || ""),
      criticality: ["critical", "high", "medium", "low"].includes(String(p.criticality)) ? String(p.criticality) : "medium",
      revenueImpact: ["primary", "secondary", "supporting"].includes(String(p.revenueImpact)) ? String(p.revenueImpact) : "supporting"
    }));
  }
  if (Array.isArray(llmData.services)) {
    updated.services = llmData.services.map((s) => ({
      name: String(s.name || ""),
      description: String(s.description || ""),
      category: String(s.category || ""),
      criticality: ["critical", "high", "medium", "low"].includes(String(s.criticality)) ? String(s.criticality) : "medium",
      revenueImpact: ["primary", "secondary", "supporting"].includes(String(s.revenueImpact)) ? String(s.revenueImpact) : "supporting"
    }));
  }
  const empEst = llmData.employeeEstimate;
  if (empEst) {
    updated.employees = {
      range: String(empEst.range || updated.employees.range),
      approximate: Number(empEst.approximate) || updated.employees.approximate,
      source: "LLM Analysis"
    };
  }
  if (Array.isArray(llmData.locations)) {
    updated.locations = llmData.locations.map((l) => ({
      type: ["headquarters", "office", "datacenter"].includes(String(l.type)) ? String(l.type) : "unknown",
      city: String(l.city || ""),
      state: String(l.state || ""),
      country: String(l.country || "")
    }));
  }
  const fin = llmData.financials;
  if (fin) {
    updated.financials = {
      estimatedRevenue: String(fin.estimatedRevenue || ""),
      fundingStage: String(fin.fundingStage || ""),
      publiclyTraded: Boolean(fin.publiclyTraded),
      ticker: fin.ticker ? String(fin.ticker) : void 0
    };
  }
  const reg = llmData.regulatoryContext;
  if (reg) {
    updated.regulatoryContext = {
      frameworks: Array.isArray(reg.frameworks) ? reg.frameworks.map(String) : updated.regulatoryContext.frameworks,
      certifications: Array.isArray(reg.certifications) ? reg.certifications.map(String) : updated.regulatoryContext.certifications,
      dataTypes: Array.isArray(reg.dataTypes) ? reg.dataTypes.map(String) : updated.regulatoryContext.dataTypes,
      complianceIndicators: Array.isArray(reg.complianceIndicators) ? reg.complianceIndicators.map(String) : updated.regulatoryContext.complianceIndicators
    };
  }
  updated.confidence = Math.min(updated.confidence + 15, 100);
  updated.enrichmentSources = [
    ...updated.enrichmentSources,
    {
      name: "LLM Analysis",
      type: "llm_analysis",
      dataPoints: Object.keys(llmData).length,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    }
  ];
  return updated;
}
function buildBIAFromLLMData(domain, orgProfile, llmData) {
  const carverRaw = llmData.carverScores;
  const carverScores = {
    criticality: Math.min(10, Math.max(1, carverRaw?.criticality || 5)),
    accessibility: Math.min(10, Math.max(1, carverRaw?.accessibility || 5)),
    recuperability: Math.min(10, Math.max(1, carverRaw?.recuperability || 5)),
    vulnerability: Math.min(10, Math.max(1, carverRaw?.vulnerability || 5)),
    effect: Math.min(10, Math.max(1, carverRaw?.effect || 5)),
    recognizability: Math.min(10, Math.max(1, carverRaw?.recognizability || 5)),
    shockIndex: Math.min(10, Math.max(1, carverRaw?.shockIndex || 5)),
    total: 0,
    normalized: 0
  };
  carverScores.total = carverScores.criticality + carverScores.accessibility + carverScores.recuperability + carverScores.vulnerability + carverScores.effect + carverScores.recognizability + carverScores.shockIndex;
  carverScores.normalized = Math.round(carverScores.total / 70 * 100);
  return {
    domain,
    orgProfile,
    missionCriticalSystems: Array.isArray(llmData.missionCriticalSystems) ? llmData.missionCriticalSystems.map((s) => ({
      name: String(s.name || ""),
      description: String(s.description || ""),
      type: String(s.type || "application"),
      criticality: String(s.criticality || "medium"),
      dependencies: Array.isArray(s.dependencies) ? s.dependencies.map(String) : [],
      exposureLevel: String(s.exposureLevel || "hybrid")
    })) : [],
    impactCategories: Array.isArray(llmData.impactCategories) ? llmData.impactCategories.map((c) => ({
      category: String(c.category || "operational"),
      severity: String(c.severity || "moderate"),
      description: String(c.description || ""),
      mtpd: String(c.mtpd || "Unknown")
    })) : [],
    rtoRpoEstimates: Array.isArray(llmData.rtoRpoEstimates) ? llmData.rtoRpoEstimates.map((r) => ({
      system: String(r.system || ""),
      rto: String(r.rto || "Unknown"),
      rpo: String(r.rpo || "Unknown"),
      justification: String(r.justification || "")
    })) : [],
    overallCriticality: ["critical", "high", "medium", "low"].includes(String(llmData.overallCriticality)) ? String(llmData.overallCriticality) : "medium",
    carverScores,
    hybridScore: carverScores.normalized,
    recommendations: Array.isArray(llmData.recommendations) ? llmData.recommendations.map(String) : [],
    generatedAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}
export {
  buildBIAFromLLMData,
  buildLLMPromptForBIA,
  buildLLMPromptForOrgProfile,
  enrichFromCensys,
  enrichFromDNS,
  enrichFromSecurityTrails,
  enrichFromShodan,
  mergeLLMOrgData,
  runEnrichmentPipeline,
  scrapeWebsite
};
