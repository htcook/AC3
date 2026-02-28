/**
 * Organization Enrichment Service
 * 
 * Scrapes a target domain's website for company/product/service information,
 * then enriches that data using online intelligence feeds to build a comprehensive
 * organizational profile for BIA and hybrid Hybrid Risk/CVSS scoring.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface OrgProfile {
  domain: string;
  companyName: string;
  industry: string;
  sector: string;
  description: string;
  products: ProductService[];
  services: ProductService[];
  technologies: TechStackItem[];
  employees: EmployeeEstimate;
  locations: LocationInfo[];
  socialMedia: SocialMediaLinks;
  contactInfo: ContactInfo;
  financials: FinancialIndicators;
  regulatoryContext: RegulatoryContext;
  enrichmentSources: EnrichmentSource[];
  confidence: number; // 0-100
  lastUpdated: string;
}

export interface ProductService {
  name: string;
  description: string;
  category: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  revenueImpact: 'primary' | 'secondary' | 'supporting';
}

export interface TechStackItem {
  name: string;
  category: 'frontend' | 'backend' | 'infrastructure' | 'security' | 'analytics' | 'cdn' | 'cms' | 'database' | 'hosting' | 'other';
  version?: string;
  confidence: number;
}

export interface EmployeeEstimate {
  range: string;
  approximate: number;
  source: string;
}

export interface LocationInfo {
  type: 'headquarters' | 'office' | 'datacenter' | 'unknown';
  address?: string;
  city?: string;
  state?: string;
  country?: string;
}

export interface SocialMediaLinks {
  linkedin?: string;
  twitter?: string;
  github?: string;
  facebook?: string;
  crunchbase?: string;
}

export interface ContactInfo {
  emails: string[];
  phones: string[];
  supportUrl?: string;
  privacyPolicyUrl?: string;
  termsUrl?: string;
}

export interface FinancialIndicators {
  estimatedRevenue?: string;
  fundingStage?: string;
  publiclyTraded: boolean;
  ticker?: string;
}

export interface RegulatoryContext {
  frameworks: string[];         // e.g., ['FedRAMP', 'SOC2', 'HIPAA', 'PCI-DSS']
  certifications: string[];
  dataTypes: string[];           // e.g., ['PII', 'PHI', 'financial', 'government']
  complianceIndicators: string[];
}

export interface EnrichmentSource {
  name: string;
  type: 'website_scrape' | 'dns' | 'whois' | 'shodan' | 'securitytrails' | 'censys' | 'osint' | 'llm_analysis';
  dataPoints: number;
  timestamp: string;
}

export interface BIAProfile {
  domain: string;
  orgProfile: OrgProfile;
  missionCriticalSystems: MissionCriticalSystem[];
  impactCategories: ImpactCategory[];
  rtoRpoEstimates: RTORPOEstimate[];
  overallCriticality: 'critical' | 'high' | 'medium' | 'low';
  carverScores: CARVERScores;
  hybridScore: number; // 0-100
  recommendations: string[];
  generatedAt: string;
}

export interface MissionCriticalSystem {
  name: string;
  description: string;
  type: 'application' | 'infrastructure' | 'data_store' | 'network' | 'identity';
  criticality: 'critical' | 'high' | 'medium' | 'low';
  dependencies: string[];
  exposureLevel: 'internet_facing' | 'internal' | 'hybrid';
}

export interface ImpactCategory {
  category: 'operational' | 'financial' | 'reputational' | 'legal' | 'safety';
  severity: 'catastrophic' | 'severe' | 'moderate' | 'minor' | 'negligible';
  description: string;
  mtpd: string; // Maximum Tolerable Period of Disruption
}

export interface RTORPOEstimate {
  system: string;
  rto: string;
  rpo: string;
  justification: string;
}

export interface CARVERScores {
  criticality: number;    // 1-10
  accessibility: number;  // 1-10
  recuperability: number; // 1-10
  vulnerability: number;  // 1-10
  effect: number;         // 1-10
  recognizability: number;// 1-10
  shockIndex: number;     // 1-10
  total: number;          // sum
  normalized: number;     // 0-100
}

// ─── Website Scraping ────────────────────────────────────────────────────────

interface ScrapedWebData {
  title: string;
  metaDescription: string;
  metaKeywords: string[];
  headings: string[];
  paragraphs: string[];
  links: { text: string; href: string }[];
  socialLinks: SocialMediaLinks;
  contactEmails: string[];
  phoneNumbers: string[];
  techIndicators: TechStackItem[];
  legalPages: { privacy?: string; terms?: string; security?: string };
  structuredData: Record<string, unknown>[];
}

function extractTechFromHeaders(headers: Record<string, string>): TechStackItem[] {
  const techs: TechStackItem[] = [];
  const headerStr = JSON.stringify(headers).toLowerCase();

  const techSignatures: { pattern: RegExp; name: string; category: TechStackItem['category'] }[] = [
    { pattern: /cloudflare/i, name: 'Cloudflare', category: 'cdn' },
    { pattern: /akamai/i, name: 'Akamai', category: 'cdn' },
    { pattern: /fastly/i, name: 'Fastly', category: 'cdn' },
    { pattern: /nginx/i, name: 'Nginx', category: 'infrastructure' },
    { pattern: /apache/i, name: 'Apache', category: 'infrastructure' },
    { pattern: /aws/i, name: 'AWS', category: 'hosting' },
    { pattern: /gws/i, name: 'Google Web Server', category: 'hosting' },
    { pattern: /microsoft/i, name: 'Microsoft IIS', category: 'infrastructure' },
    { pattern: /wordpress/i, name: 'WordPress', category: 'cms' },
    { pattern: /drupal/i, name: 'Drupal', category: 'cms' },
    { pattern: /shopify/i, name: 'Shopify', category: 'frontend' },
    { pattern: /x-powered-by.*express/i, name: 'Express.js', category: 'backend' },
    { pattern: /x-powered-by.*php/i, name: 'PHP', category: 'backend' },
    { pattern: /x-powered-by.*asp/i, name: 'ASP.NET', category: 'backend' },
  ];

  for (const sig of techSignatures) {
    if (sig.pattern.test(headerStr)) {
      techs.push({ name: sig.name, category: sig.category, confidence: 80 });
    }
  }

  return techs;
}

function extractTechFromHtml(html: string): TechStackItem[] {
  const techs: TechStackItem[] = [];
  const htmlLower = html.toLowerCase();

  const htmlSignatures: { pattern: RegExp; name: string; category: TechStackItem['category'] }[] = [
    { pattern: /react/i, name: 'React', category: 'frontend' },
    { pattern: /vue\.js|vuejs/i, name: 'Vue.js', category: 'frontend' },
    { pattern: /angular/i, name: 'Angular', category: 'frontend' },
    { pattern: /next\.js|nextjs|__next/i, name: 'Next.js', category: 'frontend' },
    { pattern: /gatsby/i, name: 'Gatsby', category: 'frontend' },
    { pattern: /tailwindcss|tailwind/i, name: 'Tailwind CSS', category: 'frontend' },
    { pattern: /bootstrap/i, name: 'Bootstrap', category: 'frontend' },
    { pattern: /jquery/i, name: 'jQuery', category: 'frontend' },
    { pattern: /google-analytics|gtag|ga\.js/i, name: 'Google Analytics', category: 'analytics' },
    { pattern: /hotjar/i, name: 'Hotjar', category: 'analytics' },
    { pattern: /segment\.com|analytics\.js/i, name: 'Segment', category: 'analytics' },
    { pattern: /hubspot/i, name: 'HubSpot', category: 'analytics' },
    { pattern: /salesforce/i, name: 'Salesforce', category: 'other' },
    { pattern: /stripe/i, name: 'Stripe', category: 'other' },
    { pattern: /intercom/i, name: 'Intercom', category: 'other' },
    { pattern: /zendesk/i, name: 'Zendesk', category: 'other' },
    { pattern: /cloudflare/i, name: 'Cloudflare', category: 'cdn' },
    { pattern: /recaptcha/i, name: 'reCAPTCHA', category: 'security' },
    { pattern: /hcaptcha/i, name: 'hCaptcha', category: 'security' },
    { pattern: /wp-content|wordpress/i, name: 'WordPress', category: 'cms' },
    { pattern: /drupal/i, name: 'Drupal', category: 'cms' },
    { pattern: /joomla/i, name: 'Joomla', category: 'cms' },
    { pattern: /wix\.com/i, name: 'Wix', category: 'cms' },
    { pattern: /squarespace/i, name: 'Squarespace', category: 'cms' },
    { pattern: /webflow/i, name: 'Webflow', category: 'cms' },
  ];

  for (const sig of htmlSignatures) {
    if (sig.pattern.test(htmlLower)) {
      techs.push({ name: sig.name, category: sig.category, confidence: 70 });
    }
  }

  return techs;
}

function parseHtmlBasic(html: string): ScrapedWebData {
  const data: ScrapedWebData = {
    title: '',
    metaDescription: '',
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
  };

  // Title
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (titleMatch) data.title = titleMatch[1].trim().replace(/\s+/g, ' ');

  // Meta description
  const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([\s\S]*?)["']/i);
  if (descMatch) data.metaDescription = descMatch[1].trim();

  // Meta keywords
  const kwMatch = html.match(/<meta[^>]*name=["']keywords["'][^>]*content=["']([\s\S]*?)["']/i);
  if (kwMatch) data.metaKeywords = kwMatch[1].split(',').map(k => k.trim()).filter(Boolean);

  // Headings (h1-h3)
  const headingRegex = /<h[1-3][^>]*>([\s\S]*?)<\/h[1-3]>/gi;
  let hMatch;
  while ((hMatch = headingRegex.exec(html)) !== null) {
    const text = hMatch[1].replace(/<[^>]+>/g, '').trim().replace(/\s+/g, ' ');
    if (text.length > 2 && text.length < 200) data.headings.push(text);
  }

  // Paragraphs (first 30 for context)
  const pRegex = /<p[^>]*>([\s\S]*?)<\/p>/gi;
  let pMatch;
  let pCount = 0;
  while ((pMatch = pRegex.exec(html)) !== null && pCount < 30) {
    const text = pMatch[1].replace(/<[^>]+>/g, '').trim().replace(/\s+/g, ' ');
    if (text.length > 20) {
      data.paragraphs.push(text);
      pCount++;
    }
  }

  // Links
  const linkRegex = /<a[^>]*href=["'](https?:\/\/[^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let lMatch;
  while ((lMatch = linkRegex.exec(html)) !== null) {
    const text = lMatch[2].replace(/<[^>]+>/g, '').trim();
    data.links.push({ text, href: lMatch[1] });
  }

  // Social media links
  const socialPatterns: { key: keyof SocialMediaLinks; pattern: RegExp }[] = [
    { key: 'linkedin', pattern: /https?:\/\/(www\.)?linkedin\.com\/company\/[^\s"']+/i },
    { key: 'twitter', pattern: /https?:\/\/(www\.)?(twitter|x)\.com\/[^\s"']+/i },
    { key: 'github', pattern: /https?:\/\/(www\.)?github\.com\/[^\s"']+/i },
    { key: 'facebook', pattern: /https?:\/\/(www\.)?facebook\.com\/[^\s"']+/i },
    { key: 'crunchbase', pattern: /https?:\/\/(www\.)?crunchbase\.com\/organization\/[^\s"']+/i },
  ];
  for (const sp of socialPatterns) {
    const m = html.match(sp.pattern);
    if (m) data.socialLinks[sp.key] = m[0];
  }

  // Emails
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = html.match(emailRegex) || [];
  data.contactEmails = [...new Set(emails)].filter(e =>
    !e.includes('example.com') && !e.includes('sentry') && !e.includes('webpack')
  ).slice(0, 10);

  // Phone numbers
  const phoneRegex = /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;
  const phones = html.match(phoneRegex) || [];
  data.phoneNumbers = [...new Set(phones)].slice(0, 5);

  // Legal pages
  const privacyMatch = html.match(/href=["']([^"']*(?:privacy|data-protection)[^"']*)["']/i);
  if (privacyMatch) data.legalPages.privacy = privacyMatch[1];
  const termsMatch = html.match(/href=["']([^"']*(?:terms|tos|terms-of-service)[^"']*)["']/i);
  if (termsMatch) data.legalPages.terms = termsMatch[1];
  const securityMatch = html.match(/href=["']([^"']*(?:security|trust)[^"']*)["']/i);
  if (securityMatch) data.legalPages.security = securityMatch[1];

  // Tech stack from HTML
  data.techIndicators = extractTechFromHtml(html);

  // JSON-LD structured data
  const jsonLdRegex = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let jMatch;
  while ((jMatch = jsonLdRegex.exec(html)) !== null) {
    try {
      data.structuredData.push(JSON.parse(jMatch[1]));
    } catch { /* ignore malformed JSON-LD */ }
  }

  return data;
}

export async function scrapeWebsite(domain: string): Promise<ScrapedWebData & { headerTechs: TechStackItem[] }> {
  const url = domain.startsWith('http') ? domain : `https://${domain}`;
  
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
      },
      redirect: 'follow',
    });
    
    clearTimeout(timeout);
    
    const html = await response.text();
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => { headers[key] = value; });
    
    const scraped = parseHtmlBasic(html);
    const headerTechs = extractTechFromHeaders(headers);
    
    return { ...scraped, headerTechs };
  } catch (error) {
    // Return empty data if scrape fails
    return {
      title: '',
      metaDescription: '',
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
      headerTechs: [],
    };
  }
}

// ─── DNS & WHOIS Enrichment ──────────────────────────────────────────────────

export interface DNSEnrichment {
  aRecords: string[];
  mxRecords: string[];
  nsRecords: string[];
  txtRecords: string[];
  spfRecord?: string;
  dmarcRecord?: string;
  dkimSelector?: string;
  caaRecords: string[];
}

export async function enrichFromDNS(domain: string): Promise<DNSEnrichment> {
  const result: DNSEnrichment = {
    aRecords: [],
    mxRecords: [],
    nsRecords: [],
    txtRecords: [],
    caaRecords: [],
  };

  try {
    // Use DNS over HTTPS (Cloudflare)
    const dnsTypes = ['A', 'MX', 'NS', 'TXT', 'CAA'];
    
    for (const type of dnsTypes) {
      try {
        const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=${type}`, {
          headers: { 'Accept': 'application/dns-json' },
        });
        const data = await resp.json() as { Answer?: { type: number; data: string }[] };
        
        if (data.Answer) {
          for (const answer of data.Answer) {
            const val = answer.data.replace(/^"|"$/g, '');
            switch (type) {
              case 'A': result.aRecords.push(val); break;
              case 'MX': result.mxRecords.push(val); break;
              case 'NS': result.nsRecords.push(val); break;
              case 'TXT': {
                result.txtRecords.push(val);
                if (val.startsWith('v=spf1')) result.spfRecord = val;
                break;
              }
              case 'CAA': result.caaRecords.push(val); break;
            }
          }
        }
      } catch { /* individual DNS query failed */ }
    }

    // Check DMARC
    try {
      const dmarcResp = await fetch(`https://cloudflare-dns.com/dns-query?name=_dmarc.${domain}&type=TXT`, {
        headers: { 'Accept': 'application/dns-json' },
      });
      const dmarcData = await dmarcResp.json() as { Answer?: { data: string }[] };
      if (dmarcData.Answer) {
        for (const a of dmarcData.Answer) {
          const val = a.data.replace(/^"|"$/g, '');
          if (val.startsWith('v=DMARC1')) result.dmarcRecord = val;
        }
      }
    } catch { /* DMARC lookup failed */ }

  } catch { /* DNS enrichment failed */ }

  return result;
}

// ─── Shodan Enrichment ───────────────────────────────────────────────────────

export interface ShodanEnrichment {
  openPorts: number[];
  services: { port: number; protocol: string; product?: string; version?: string }[];
  vulns: string[];
  os?: string;
  hostnames: string[];
  isp?: string;
  org?: string;
  asn?: string;
  country?: string;
  city?: string;
}

export async function enrichFromShodan(domain: string, apiKey?: string): Promise<ShodanEnrichment | null> {
  if (!apiKey) return null;
  
  try {
    // First resolve domain to IP
    const dnsResp = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
      headers: { 'Accept': 'application/dns-json' },
    });
    const dnsData = await dnsResp.json() as { Answer?: { data: string }[] };
    const ip = dnsData.Answer?.[0]?.data;
    if (!ip) return null;

    const resp = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);
    if (!resp.ok) return null;
    
    const data = await resp.json() as {
      ports?: number[];
      data?: { port: number; transport: string; product?: string; version?: string }[];
      vulns?: string[];
      os?: string;
      hostnames?: string[];
      isp?: string;
      org?: string;
      asn?: string;
      country_name?: string;
      city?: string;
    };

    return {
      openPorts: data.ports || [],
      services: (data.data || []).map(s => ({
        port: s.port,
        protocol: s.transport,
        product: s.product,
        version: s.version,
      })),
      vulns: data.vulns || [],
      os: data.os || undefined,
      hostnames: data.hostnames || [],
      isp: data.isp,
      org: data.org,
      asn: data.asn,
      country: data.country_name,
      city: data.city,
    };
  } catch {
    return null;
  }
}

// ─── SecurityTrails Enrichment ───────────────────────────────────────────────

export interface SecurityTrailsEnrichment {
  subdomainCount: number;
  subdomains: string[];
  historicalDns: { firstSeen: string; lastSeen: string; type: string; value: string }[];
  associatedDomains: string[];
  whois: {
    registrar?: string;
    createdDate?: string;
    expiresDate?: string;
    nameServers: string[];
    registrantOrg?: string;
    registrantCountry?: string;
  };
}

export async function enrichFromSecurityTrails(domain: string, apiKey?: string): Promise<SecurityTrailsEnrichment | null> {
  if (!apiKey) return null;
  
  try {
    const headers = { 'APIKEY': apiKey, 'Accept': 'application/json' };
    
    // Subdomains
    const subResp = await fetch(`https://api.securitytrails.com/v1/domain/${domain}/subdomains`, { headers });
    const subData = await subResp.json() as { subdomains?: string[]; subdomain_count?: number };
    
    // WHOIS
    const whoisResp = await fetch(`https://api.securitytrails.com/v1/domain/${domain}/whois`, { headers });
    const whoisData = await whoisResp.json() as {
      result?: {
        registrar_name?: string;
        created_date?: string;
        expires_date?: string;
        name_servers?: string[];
        contacts?: { registrant?: { organization?: string; country?: string }[] };
      };
    };

    return {
      subdomainCount: subData.subdomain_count || 0,
      subdomains: (subData.subdomains || []).slice(0, 50).map(s => `${s}.${domain}`),
      historicalDns: [],
      associatedDomains: [],
      whois: {
        registrar: whoisData.result?.registrar_name,
        createdDate: whoisData.result?.created_date,
        expiresDate: whoisData.result?.expires_date,
        nameServers: whoisData.result?.name_servers || [],
        registrantOrg: whoisData.result?.contacts?.registrant?.[0]?.organization,
        registrantCountry: whoisData.result?.contacts?.registrant?.[0]?.country,
      },
    };
  } catch {
    return null;
  }
}

// ─── Censys Enrichment ───────────────────────────────────────────────────────

export interface CensysEnrichment {
  services: { port: number; serviceName: string; transportProtocol: string }[];
  operatingSystem?: string;
  lastUpdated?: string;
  autonomousSystem?: { asn: number; name: string; bgpPrefix: string };
  location?: { country: string; city: string; province: string };
}

export async function enrichFromCensys(domain: string, apiId?: string, apiSecret?: string): Promise<CensysEnrichment | null> {
  if (!apiId || !apiSecret) return null;
  
  try {
    const auth = Buffer.from(`${apiId}:${apiSecret}`).toString('base64');
    const resp = await fetch(`https://search.censys.io/api/v2/hosts/search?q=${domain}&per_page=5`, {
      headers: {
        'Authorization': `Basic ${auth}`,
        'Accept': 'application/json',
      },
    });
    
    if (!resp.ok) return null;
    
    const data = await resp.json() as {
      result?: {
        hits?: {
          services?: { port: number; service_name: string; transport_protocol: string }[];
          operating_system?: { product: string };
          last_updated_at?: string;
          autonomous_system?: { asn: number; name: string; bgp_prefix: string };
          location?: { country: string; city: string; province: string };
        }[];
      };
    };

    const firstHit = data.result?.hits?.[0];
    if (!firstHit) return null;

    return {
      services: (firstHit.services || []).map(s => ({
        port: s.port,
        serviceName: s.service_name,
        transportProtocol: s.transport_protocol,
      })),
      operatingSystem: firstHit.operating_system?.product,
      lastUpdated: firstHit.last_updated_at,
      autonomousSystem: firstHit.autonomous_system ? {
        asn: firstHit.autonomous_system.asn,
        name: firstHit.autonomous_system.name,
        bgpPrefix: firstHit.autonomous_system.bgp_prefix,
      } : undefined,
      location: firstHit.location ? {
        country: firstHit.location.country,
        city: firstHit.location.city,
        province: firstHit.location.province,
      } : undefined,
    };
  } catch {
    return null;
  }
}

// ─── LLM-Based Analysis ─────────────────────────────────────────────────────

export function buildLLMPromptForOrgProfile(scrapedData: ScrapedWebData, domain: string): string {
  const context = [
    `Domain: ${domain}`,
    `Website Title: ${scrapedData.title}`,
    `Meta Description: ${scrapedData.metaDescription}`,
    `Keywords: ${scrapedData.metaKeywords.join(', ')}`,
    `Headings: ${scrapedData.headings.slice(0, 20).join(' | ')}`,
    `Content Excerpts: ${scrapedData.paragraphs.slice(0, 15).join(' ')}`,
    `Contact Emails: ${scrapedData.contactEmails.join(', ')}`,
    `Structured Data: ${JSON.stringify(scrapedData.structuredData).slice(0, 2000)}`,
  ].join('\n');

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

export function buildLLMPromptForBIA(orgProfile: OrgProfile, shodanData: ShodanEnrichment | null, dnsData: DNSEnrichment): string {
  const context = [
    `Company: ${orgProfile.companyName}`,
    `Industry: ${orgProfile.industry} / ${orgProfile.sector}`,
    `Description: ${orgProfile.description}`,
    `Products: ${orgProfile.products.map(p => p.name).join(', ')}`,
    `Services: ${orgProfile.services.map(s => s.name).join(', ')}`,
    `Technologies: ${orgProfile.technologies.map(t => t.name).join(', ')}`,
    `Employee Count: ~${orgProfile.employees.approximate}`,
    `Regulatory Frameworks: ${orgProfile.regulatoryContext.frameworks.join(', ')}`,
    `Data Types: ${orgProfile.regulatoryContext.dataTypes.join(', ')}`,
    `Open Ports: ${shodanData?.openPorts?.join(', ') || 'Unknown'}`,
    `Services Exposed: ${shodanData?.services?.map(s => `${s.port}/${s.product || s.protocol}`).join(', ') || 'Unknown'}`,
    `Known Vulns: ${shodanData?.vulns?.join(', ') || 'None detected'}`,
    `MX Records: ${dnsData.mxRecords.join(', ')}`,
    `SPF: ${dnsData.spfRecord || 'Not configured'}`,
    `DMARC: ${dnsData.dmarcRecord || 'Not configured'}`,
  ].join('\n');

  return `Based on the following organizational profile and technical intelligence, generate a Business Impact Analysis (BIA) and Hybrid Risk scoring. Return a JSON object:

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

Organization Data:
${context}

Return ONLY the JSON object, no markdown or explanation.`;
}

// ─── Main Enrichment Pipeline ────────────────────────────────────────────────

export interface EnrichmentConfig {
  shodanApiKey?: string;
  securityTrailsApiKey?: string;
  censysApiId?: string;
  censysApiSecret?: string;
}

export interface EnrichmentResult {
  orgProfile: OrgProfile;
  dnsData: DNSEnrichment;
  shodanData: ShodanEnrichment | null;
  securityTrailsData: SecurityTrailsEnrichment | null;
  censysData: CensysEnrichment | null;
  scrapedData: ScrapedWebData;
  llmOrgPrompt: string;
  llmBiaPrompt: string;
}

export async function runEnrichmentPipeline(
  domain: string,
  config: EnrichmentConfig
): Promise<EnrichmentResult> {
  // Normalize domain
  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
  
  // Run all enrichment sources in parallel
  const [scrapedRaw, dnsData, shodanData, securityTrailsData, censysData] = await Promise.all([
    scrapeWebsite(cleanDomain),
    enrichFromDNS(cleanDomain),
    enrichFromShodan(cleanDomain, config.shodanApiKey),
    enrichFromSecurityTrails(cleanDomain, config.securityTrailsApiKey),
    enrichFromCensys(cleanDomain, config.censysApiId, config.censysApiSecret),
  ]);

  const { headerTechs, ...scrapedData } = scrapedRaw;

  // Merge tech stacks from all sources
  const allTechs = [...scrapedData.techIndicators, ...headerTechs];
  const uniqueTechs = Array.from(
    allTechs.reduce((map, t) => {
      const key = t.name.toLowerCase();
      if (!map.has(key) || (map.get(key)!.confidence < t.confidence)) {
        map.set(key, t);
      }
      return map;
    }, new Map<string, TechStackItem>()).values()
  );

  // Count enrichment data points
  const enrichmentSources: EnrichmentSource[] = [
    {
      name: 'Website Scrape',
      type: 'website_scrape' as const,
      dataPoints: scrapedData.headings.length + scrapedData.paragraphs.length + scrapedData.contactEmails.length,
      timestamp: new Date().toISOString(),
    },
    {
      name: 'DNS Records',
      type: 'dns' as const,
      dataPoints: dnsData.aRecords.length + dnsData.mxRecords.length + dnsData.txtRecords.length + dnsData.nsRecords.length,
      timestamp: new Date().toISOString(),
    },
  ];

  if (shodanData) {
    enrichmentSources.push({
      name: 'Shodan',
      type: 'shodan' as const,
      dataPoints: shodanData.openPorts.length + shodanData.services.length + shodanData.vulns.length,
      timestamp: new Date().toISOString(),
    });
  }

  if (securityTrailsData) {
    enrichmentSources.push({
      name: 'SecurityTrails',
      type: 'securitytrails' as const,
      dataPoints: securityTrailsData.subdomainCount + (securityTrailsData.whois.registrar ? 5 : 0),
      timestamp: new Date().toISOString(),
    });
  }

  if (censysData) {
    enrichmentSources.push({
      name: 'Censys',
      type: 'censys' as const,
      dataPoints: censysData.services.length + (censysData.autonomousSystem ? 3 : 0),
      timestamp: new Date().toISOString(),
    });
  }

  // Build initial org profile from scraped data (will be enriched by LLM)
  const orgProfile: OrgProfile = {
    domain: cleanDomain,
    companyName: scrapedData.title.split(/[|\-–—]/).map(s => s.trim())[0] || cleanDomain,
    industry: 'Unknown',
    sector: 'Unknown',
    description: scrapedData.metaDescription || '',
    products: [],
    services: [],
    technologies: uniqueTechs,
    employees: {
      range: 'Unknown',
      approximate: 0,
      source: 'Not yet enriched',
    },
    locations: shodanData?.country ? [{
      type: 'unknown',
      country: shodanData.country,
      city: shodanData.city,
    }] : [],
    socialMedia: scrapedData.socialLinks,
    contactInfo: {
      emails: scrapedData.contactEmails,
      phones: scrapedData.phoneNumbers,
      supportUrl: undefined,
      privacyPolicyUrl: scrapedData.legalPages.privacy,
      termsUrl: scrapedData.legalPages.terms,
    },
    financials: {
      publiclyTraded: false,
    },
    regulatoryContext: {
      frameworks: [],
      certifications: [],
      dataTypes: [],
      complianceIndicators: [],
    },
    enrichmentSources,
    confidence: calculateConfidence(scrapedData, dnsData, shodanData, securityTrailsData, censysData),
    lastUpdated: new Date().toISOString(),
  };

  // Build LLM prompts for further enrichment
  const llmOrgPrompt = buildLLMPromptForOrgProfile(scrapedData, cleanDomain);
  const llmBiaPrompt = buildLLMPromptForBIA(orgProfile, shodanData, dnsData);

  return {
    orgProfile,
    dnsData,
    shodanData,
    securityTrailsData,
    censysData,
    scrapedData,
    llmOrgPrompt,
    llmBiaPrompt,
  };
}

function calculateConfidence(
  scraped: ScrapedWebData,
  dns: DNSEnrichment,
  shodan: ShodanEnrichment | null,
  st: SecurityTrailsEnrichment | null,
  censys: CensysEnrichment | null,
): number {
  let score = 10; // base

  // Website data quality
  if (scraped.title) score += 10;
  if (scraped.metaDescription) score += 5;
  if (scraped.headings.length > 3) score += 10;
  if (scraped.paragraphs.length > 5) score += 10;
  if (scraped.contactEmails.length > 0) score += 5;
  if (scraped.structuredData.length > 0) score += 10;

  // DNS completeness
  if (dns.aRecords.length > 0) score += 5;
  if (dns.mxRecords.length > 0) score += 5;
  if (dns.spfRecord) score += 3;
  if (dns.dmarcRecord) score += 3;

  // External intelligence
  if (shodan) score += 10;
  if (st) score += 10;
  if (censys) score += 5;

  return Math.min(score, 100);
}

// ─── Utility: Merge LLM results into OrgProfile ─────────────────────────────

export function mergeLLMOrgData(profile: OrgProfile, llmData: Record<string, unknown>): OrgProfile {
  const updated = { ...profile };

  if (typeof llmData.companyName === 'string' && llmData.companyName) updated.companyName = llmData.companyName;
  if (typeof llmData.industry === 'string' && llmData.industry) updated.industry = llmData.industry;
  if (typeof llmData.sector === 'string' && llmData.sector) updated.sector = llmData.sector;
  if (typeof llmData.description === 'string' && llmData.description) updated.description = llmData.description;

  if (Array.isArray(llmData.products)) {
    updated.products = llmData.products.map((p: Record<string, unknown>) => ({
      name: String(p.name || ''),
      description: String(p.description || ''),
      category: String(p.category || ''),
      criticality: (['critical', 'high', 'medium', 'low'].includes(String(p.criticality)) ? String(p.criticality) : 'medium') as ProductService['criticality'],
      revenueImpact: (['primary', 'secondary', 'supporting'].includes(String(p.revenueImpact)) ? String(p.revenueImpact) : 'supporting') as ProductService['revenueImpact'],
    }));
  }

  if (Array.isArray(llmData.services)) {
    updated.services = llmData.services.map((s: Record<string, unknown>) => ({
      name: String(s.name || ''),
      description: String(s.description || ''),
      category: String(s.category || ''),
      criticality: (['critical', 'high', 'medium', 'low'].includes(String(s.criticality)) ? String(s.criticality) : 'medium') as ProductService['criticality'],
      revenueImpact: (['primary', 'secondary', 'supporting'].includes(String(s.revenueImpact)) ? String(s.revenueImpact) : 'supporting') as ProductService['revenueImpact'],
    }));
  }

  const empEst = llmData.employeeEstimate as Record<string, unknown> | undefined;
  if (empEst) {
    updated.employees = {
      range: String(empEst.range || updated.employees.range),
      approximate: Number(empEst.approximate) || updated.employees.approximate,
      source: 'LLM Analysis',
    };
  }

  if (Array.isArray(llmData.locations)) {
    updated.locations = llmData.locations.map((l: Record<string, unknown>) => ({
      type: (['headquarters', 'office', 'datacenter'].includes(String(l.type)) ? String(l.type) : 'unknown') as LocationInfo['type'],
      city: String(l.city || ''),
      state: String(l.state || ''),
      country: String(l.country || ''),
    }));
  }

  const fin = llmData.financials as Record<string, unknown> | undefined;
  if (fin) {
    updated.financials = {
      estimatedRevenue: String(fin.estimatedRevenue || ''),
      fundingStage: String(fin.fundingStage || ''),
      publiclyTraded: Boolean(fin.publiclyTraded),
      ticker: fin.ticker ? String(fin.ticker) : undefined,
    };
  }

  const reg = llmData.regulatoryContext as Record<string, unknown> | undefined;
  if (reg) {
    updated.regulatoryContext = {
      frameworks: Array.isArray(reg.frameworks) ? reg.frameworks.map(String) : updated.regulatoryContext.frameworks,
      certifications: Array.isArray(reg.certifications) ? reg.certifications.map(String) : updated.regulatoryContext.certifications,
      dataTypes: Array.isArray(reg.dataTypes) ? reg.dataTypes.map(String) : updated.regulatoryContext.dataTypes,
      complianceIndicators: Array.isArray(reg.complianceIndicators) ? reg.complianceIndicators.map(String) : updated.regulatoryContext.complianceIndicators,
    };
  }

  // Boost confidence after LLM enrichment
  updated.confidence = Math.min(updated.confidence + 15, 100);
  updated.enrichmentSources = [
    ...updated.enrichmentSources,
    {
      name: 'LLM Analysis',
      type: 'llm_analysis',
      dataPoints: Object.keys(llmData).length,
      timestamp: new Date().toISOString(),
    },
  ];

  return updated;
}

export function buildBIAFromLLMData(domain: string, orgProfile: OrgProfile, llmData: Record<string, unknown>): BIAProfile {
  const carverRaw = llmData.carverScores as Record<string, number> | undefined;
  const carverScores: CARVERScores = {
    criticality: Math.min(10, Math.max(1, carverRaw?.criticality || 5)),
    accessibility: Math.min(10, Math.max(1, carverRaw?.accessibility || 5)),
    recuperability: Math.min(10, Math.max(1, carverRaw?.recuperability || 5)),
    vulnerability: Math.min(10, Math.max(1, carverRaw?.vulnerability || 5)),
    effect: Math.min(10, Math.max(1, carverRaw?.effect || 5)),
    recognizability: Math.min(10, Math.max(1, carverRaw?.recognizability || 5)),
    shockIndex: Math.min(10, Math.max(1, carverRaw?.shockIndex || 5)),
    total: 0,
    normalized: 0,
  };
  carverScores.total = carverScores.criticality + carverScores.accessibility + carverScores.recuperability +
    carverScores.vulnerability + carverScores.effect + carverScores.recognizability + carverScores.shockIndex;
  carverScores.normalized = Math.round((carverScores.total / 70) * 100);

  return {
    domain,
    orgProfile,
    missionCriticalSystems: Array.isArray(llmData.missionCriticalSystems)
      ? llmData.missionCriticalSystems.map((s: Record<string, unknown>) => ({
          name: String(s.name || ''),
          description: String(s.description || ''),
          type: String(s.type || 'application') as MissionCriticalSystem['type'],
          criticality: String(s.criticality || 'medium') as MissionCriticalSystem['criticality'],
          dependencies: Array.isArray(s.dependencies) ? s.dependencies.map(String) : [],
          exposureLevel: String(s.exposureLevel || 'hybrid') as MissionCriticalSystem['exposureLevel'],
        }))
      : [],
    impactCategories: Array.isArray(llmData.impactCategories)
      ? llmData.impactCategories.map((c: Record<string, unknown>) => ({
          category: String(c.category || 'operational') as ImpactCategory['category'],
          severity: String(c.severity || 'moderate') as ImpactCategory['severity'],
          description: String(c.description || ''),
          mtpd: String(c.mtpd || 'Unknown'),
        }))
      : [],
    rtoRpoEstimates: Array.isArray(llmData.rtoRpoEstimates)
      ? llmData.rtoRpoEstimates.map((r: Record<string, unknown>) => ({
          system: String(r.system || ''),
          rto: String(r.rto || 'Unknown'),
          rpo: String(r.rpo || 'Unknown'),
          justification: String(r.justification || ''),
        }))
      : [],
    overallCriticality: (['critical', 'high', 'medium', 'low'].includes(String(llmData.overallCriticality))
      ? String(llmData.overallCriticality) : 'medium') as BIAProfile['overallCriticality'],
    carverScores,
    hybridScore: carverScores.normalized,
    recommendations: Array.isArray(llmData.recommendations) ? llmData.recommendations.map(String) : [],
    generatedAt: new Date().toISOString(),
  };
}
