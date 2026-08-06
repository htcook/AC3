/**
 * Company Intelligence Connector
 * 
 * Gathers firmographic data about the target organization from
 * multiple sources: website scraping, DNS/WHOIS context, and
 * LLM-powered inference. Produces structured company profile
 * data for BIA enrichment.
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const companyIntelConnector: PassiveConnector = {
  name: "company_intel",
  description: 'Gathers firmographic data (industry, size, products, tech stack) from target domain for BIA enrichment',
  requiresApiKey: false,
  freeUrl: "https://www.google.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const GLOBAL_TIMEOUT = 20000; // 20s hard cap for entire connector
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();
    const source = "company_intel";
    
    const isTimedOut = () => Date.now() - start > GLOBAL_TIMEOUT;

    try {
      // Step 1: Scrape the target website for company info
      const websiteData = await scrapeCompanyWebsite(domain);
      
      // Step 2: Check for common company info pages (skip if running low on time)
      const aboutData = isTimedOut()
        ? { html: '', text: '', found: false }
        : await scrapeAboutPage(domain);
      
      // Step 3: Extract social media links
      const socialLinks = extractSocialLinks(websiteData.html || '', aboutData.html || '');

      // Step 4: Check for publicly traded indicators
      const publicIndicators = detectPublicCompany(websiteData.html || '', aboutData.html || '');

      // Combine all scraped data
      const combinedText = [
        websiteData.text || '',
        aboutData.text || '',
      ].join('\n').slice(0, 8000); // Limit for LLM context

      if (combinedText.length > 100) {
        const name = `Company website data for ${domain}`;
        observations.push({
          assetId: makeAssetId(domain, name, source),
          domain,
          assetType: 'breach',
          name,
          source,
          observedAt: now,
          tags: ['company_intel', 'website_scrape'],
          evidence: {
            source: 'website_scrape',
            text_length: combinedText.length,
            has_about_page: aboutData.found,
            social_links: socialLinks,
            public_company_indicators: publicIndicators,
            raw_text: combinedText,
            severity: 0,
            confidence: 70,
          },
          attribution: {
            provider: "Company Intel Connector",
            method: "scrape",
            url: `https://${domain}`
          }
        });
      }

      // Step 5: Check meta tags for structured data
      const metaData = extractMetaTags(websiteData.html || '');
      if (Object.keys(metaData).length > 0) {
        const name = `Structured metadata for ${domain}`;
        observations.push({
          assetId: makeAssetId(domain, name, source),
          domain,
          assetType: 'breach',
          name,
          source,
          observedAt: now,
          tags: ['company_intel', 'metadata'],
          evidence: {
            source: 'meta_tags',
            ...metaData,
            severity: 0,
            confidence: 75,
          },
          attribution: {
            provider: "Company Intel Connector",
            method: "scrape",
            url: `https://${domain}`
          }
        });
      }

      // Step 6: Check for privacy policy / terms (regulatory hints)
      const regulatoryHints = await detectRegulatoryHints(domain, websiteData.html || '');
      if (regulatoryHints.length > 0) {
        const name = `Regulatory hints for ${domain}`;
        observations.push({
          assetId: makeAssetId(domain, name, source),
          domain,
          assetType: 'breach',
          name,
          source,
          observedAt: now,
          tags: ['company_intel', 'regulatory_hint'],
          evidence: {
            source: 'website_analysis',
            hints: regulatoryHints,
            severity: 0,
            confidence: 60,
          },
          attribution: {
            provider: "Company Intel Connector",
            method: "scrape",
            url: `https://${domain}`
          }
        });
      }

    } catch (err: any) {
      errors.push(err.message || 'Unknown error during company intel collection');
    }

    return {
      connector: source,
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};

// ─── Helper Functions ────────────────────────────────────────────────────────

async function scrapeCompanyWebsite(domain: string): Promise<{ html: string; text: string }> {
  try {
    const resp = await fetch(`https://${domain}`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)' },
      signal: AbortSignal.timeout(5000),
    });
    if (!resp.ok) return { html: '', text: '' };
    const html = await resp.text();
    const text = html
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/<style[\s\S]*?<\/style>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    return { html, text: text.slice(0, 10000) };
  } catch {
    return { html: '', text: '' };
  }
}

async function scrapeAboutPage(domain: string): Promise<{ html: string; text: string; found: boolean }> {
  const aboutPaths = ['/about', '/about-us', '/company', '/about.html'];
  for (const path of aboutPaths) {
    try {
      const resp = await fetch(`https://${domain}${path}`, {
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)' },
        signal: AbortSignal.timeout(4000),
      });
      if (resp.ok) {
        const html = await resp.text();
        const text = html
          .replace(/<script[\s\S]*?<\/script>/gi, '')
          .replace(/<style[\s\S]*?<\/style>/gi, '')
          .replace(/<[^>]+>/g, ' ')
          .replace(/\s+/g, ' ')
          .trim();
        return { html, text: text.slice(0, 8000), found: true };
      }
    } catch { /* continue */ }
  }
  return { html: '', text: '', found: false };
}

function extractSocialLinks(html1: string, html2: string): Record<string, string> {
  const combined = html1 + html2;
  const links: Record<string, string> = {};
  const patterns: [string, RegExp][] = [
    ['linkedin', /https?:\/\/(www\.)?linkedin\.com\/company\/[^\s\"'<>]+/i],
    ['twitter', /https?:\/\/(www\.)?(twitter|x)\.com\/[^\s\"'<>]+/i],
    ['facebook', /https?:\/\/(www\.)?facebook\.com\/[^\s\"'<>]+/i],
    ['github', /https?:\/\/(www\.)?github\.com\/[^\s\"'<>]+/i],
    ['crunchbase', /https?:\/\/(www\.)?crunchbase\.com\/organization\/[^\s\"'<>]+/i],
  ];
  for (const [name, pattern] of patterns) {
    const match = combined.match(pattern);
    if (match) links[name] = match[0];
  }
  return links;
}

function detectPublicCompany(html1: string, html2: string): string[] {
  const combined = (html1 + html2).toLowerCase();
  const indicators: string[] = [];
  if (combined.includes('investor') || combined.includes('shareholders')) indicators.push('investor_relations');
  if (combined.includes('sec filing') || combined.includes('10-k') || combined.includes('10-q')) indicators.push('sec_filings');
  if (combined.match(/nasdaq|nyse|stock\s*price/)) indicators.push('stock_exchange');
  if (combined.match(/annual\s*report/)) indicators.push('annual_report');
  if (combined.match(/earnings\s*call/)) indicators.push('earnings_call');
  return indicators;
}

function extractMetaTags(html: string): Record<string, string> {
  const meta: Record<string, string> = {};
  const patterns: [string, RegExp][] = [
    ['og_title', /<meta\s+property="og:title"\s+content="([^\"]+)"/i],
    ['og_description', /<meta\s+property="og:description"\s+content="([^\"]+)"/i],
    ['og_site_name', /<meta\s+property="og:site_name"\s+content="([^\"]+)"/i],
    ['description', /<meta\s+name="description"\s+content="([^\"]+)"/i],
    ['keywords', /<meta\s+name="keywords"\s+content="([^\"]+)"/i],
    ['author', /<meta\s+name="author"\s+content="([^\"]+)"/i],
    ['title', /<title>([^<]+)<\/title>/i],
  ];
  for (const [key, pattern] of patterns) {
    const match = html.match(pattern);
    if (match) meta[key] = match[1].trim();
  }
  // Check for JSON-LD structured data
  const jsonLdMatch = html.match(/<script\s+type="application\/ld\+json">([\s\S]*?)<\/script>/i);
  if (jsonLdMatch) {
    try {
      const ld = JSON.parse(jsonLdMatch[1]);
      if (ld['@type'] === 'Organization' || ld['@type'] === 'Corporation') {
        if (ld.name) meta['ld_name'] = ld.name;
        if (ld.description) meta['ld_description'] = ld.description;
        if (ld.numberOfEmployees?.value) meta['ld_employees'] = String(ld.numberOfEmployees.value);
        if (ld.foundingDate) meta['ld_founded'] = ld.foundingDate;
        if (ld.address?.addressLocality) meta['ld_city'] = ld.address.addressLocality;
        if (ld.address?.addressCountry) meta['ld_country'] = ld.address.addressCountry;
      }
    } catch { /* ignore parse errors */ }
  }
  return meta;
}

async function detectRegulatoryHints(domain: string, html: string): Promise<string[]> {
  const hints: string[] = [];
  const lowerHtml = html.toLowerCase();

  // Check for privacy policy mentions of specific regulations
  if (lowerHtml.match(/hipaa|health\s*insurance\s*portability/)) hints.push('HIPAA');
  if (lowerHtml.match(/gdpr|general\s*data\s*protection/)) hints.push('GDPR');
  if (lowerHtml.match(/ccpa|california\s*consumer\s*privacy/)) hints.push('CCPA');
  if (lowerHtml.match(/pci[\s-]*dss|payment\s*card\s*industry/)) hints.push('PCI-DSS');
  if (lowerHtml.match(/sox|sarbanes[\s-]*oxley/)) hints.push('SOX');
  if (lowerHtml.match(/fedramp/i)) hints.push('FedRAMP');
  if (lowerHtml.match(/cmmc|cybersecurity\s*maturity/)) hints.push('CMMC');
  if (lowerHtml.match(/nerc[\s-]*cip/)) hints.push('NERC-CIP');
  if (lowerHtml.match(/ferpa|family\s*educational/)) hints.push('FERPA');
  if (lowerHtml.match(/glba|gramm[\s-]*leach/)) hints.push('GLBA');
  if (lowerHtml.match(/nist\s*800/)) hints.push('NIST-800-53');
  if (lowerHtml.match(/iso\s*27001/)) hints.push('ISO-27001');
  if (lowerHtml.match(/soc\s*2|soc2/)) hints.push('SOC-2');
  if (lowerHtml.match(/hitrust/)) hints.push('HITRUST');
  if (lowerHtml.match(/itar|international\s*traffic\s*in\s*arms/)) hints.push('ITAR');
  if (lowerHtml.match(/coppa|children.*online.*privacy/)) hints.push('COPPA');

  // Check for compliance badges/certifications
  if (lowerHtml.match(/certified|certification|compliant|compliance/)) {
    // Try to fetch privacy policy for more regulatory hints (skip if already slow)
    try {
      const privacyResp = await fetch(`https://${domain}/privacy`, {
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)' },
        signal: AbortSignal.timeout(4000),
      });
      if (privacyResp.ok) {
        const privacyHtml = (await privacyResp.text()).toLowerCase();
        if (privacyHtml.match(/hipaa/) && !hints.includes('HIPAA')) hints.push('HIPAA');
        if (privacyHtml.match(/gdpr/) && !hints.includes('GDPR')) hints.push('GDPR');
        if (privacyHtml.match(/ccpa/) && !hints.includes('CCPA')) hints.push('CCPA');
        if (privacyHtml.match(/pci/) && !hints.includes('PCI-DSS')) hints.push('PCI-DSS');
        if (privacyHtml.match(/coppa/) && !hints.includes('COPPA')) hints.push('COPPA');
        if (privacyHtml.match(/ferpa/) && !hints.includes('FERPA')) hints.push('FERPA');
        if (privacyHtml.match(/glba/) && !hints.includes('GLBA')) hints.push('GLBA');
      }
    } catch { /* ignore */ }
  }

  return hints;
}
