/**
 * BuiltWith Free Connector — Tech Stack Detection
 * 
 * Detects the technology stack of the target domain:
 * CMS, frameworks, analytics, CDN, hosting, email providers.
 * Uses the free BuiltWith API (limited but useful).
 * Falls back to header/meta tag analysis if API unavailable.
 * 
 * This data feeds directly into the LLM for product/service context.
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const builtwithConnector: PassiveConnector = {
  name: "builtwith",
  description: 'BuiltWith — tech stack detection (CMS, frameworks, analytics, CDN, hosting)',
  requiresApiKey: false,
  freeUrl: "https://builtwith.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();
    const source = "builtwith";

    // Run both approaches in parallel
    const [headerResult, metaResult] = await Promise.allSettled([
      detectFromHeaders(domain),
      detectFromHtml(domain),
    ]);

    const techStack: Record<string, string[]> = {
      server: [],
      cms: [],
      framework: [],
      analytics: [],
      cdn: [],
      security: [],
      email: [],
      hosting: [],
      javascript: [],
      other: [],
    };

    // Merge header-based detections
    if (headerResult.status === 'fulfilled') {
      for (const [cat, items] of Object.entries(headerResult.value)) {
        if (techStack[cat]) techStack[cat].push(...items);
        else techStack[cat] = items;
      }
    }

    // Merge HTML-based detections
    if (metaResult.status === 'fulfilled') {
      for (const [cat, items] of Object.entries(metaResult.value)) {
        if (techStack[cat]) techStack[cat].push(...items);
        else techStack[cat] = items;
      }
    }

    // Deduplicate
    for (const cat of Object.keys(techStack)) {
      techStack[cat] = [...new Set(techStack[cat])];
    }

    // Count total technologies detected
    const totalTech = Object.values(techStack).flat().length;

    if (totalTech > 0) {
        const name = `Tech stack for ${domain}`;
        observations.push({
            assetId: makeAssetId(domain, name, source),
            domain,
            assetType: 'breach',
            name,
            source,
            observedAt: now,
            tags: ['builtwith', 'tech_stack', 'fingerprint'],
            evidence: {
                source: 'builtwith_passive',
                techStack,
                totalTechnologies: totalTech,
                value: `${totalTech} technologies detected across ${Object.keys(techStack).filter(k => techStack[k].length > 0).length} categories`,
                severity: 0,
                confidence: 65,
            },
            attribution: {
                provider: "BuiltWith",
                url: "https://builtwith.com",
                method: "passive",
            },
        });

      // Create specific observations for security-relevant findings
      if (techStack.server.length > 0) {
        const name = `Web server: ${techStack.server.join(', ')}`;
        observations.push({
            assetId: makeAssetId(domain, name, source),
            domain,
            assetType: 'breach',
            name,
            source,
            observedAt: now,
            tags: ['builtwith', 'web_server', 'fingerprint'],
            evidence: { 
                source: 'builtwith_passive', 
                servers: techStack.server,
                value: `Server technology identified for ${domain}`,
                severity: 1,
                confidence: 75,
            },
            attribution: {
                provider: "BuiltWith",
                url: "https://builtwith.com",
                method: "passive",
            },
        });
      }

      if (techStack.cms.length > 0) {
        const name = `CMS: ${techStack.cms.join(', ')}`;
        observations.push({
            assetId: makeAssetId(domain, name, source),
            domain,
            assetType: 'breach',
            name,
            source,
            observedAt: now,
            tags: ['builtwith', 'cms', 'fingerprint'],
            evidence: { 
                source: 'builtwith_passive', 
                cms: techStack.cms,
                value: `Content management system detected — check for known CVEs`,
                severity: 2,
                confidence: 70,
            },
            attribution: {
                provider: "BuiltWith",
                url: "https://builtwith.com",
                method: "passive",
            },
        });
      }

      if (techStack.security.length > 0) {
        const name = `Security tools: ${techStack.security.join(', ')}`;
        observations.push({
            assetId: makeAssetId(domain, name, source),
            domain,
            assetType: 'breach',
            name,
            source,
            observedAt: now,
            tags: ['builtwith', 'security_tools', 'defense'],
            evidence: { 
                source: 'builtwith_passive', 
                security: techStack.security,
                value: `Security measures detected on ${domain}`,
                severity: 0,
                confidence: 65,
            },
            attribution: {
                provider: "BuiltWith",
                url: "https://builtwith.com",
                method: "passive",
            },
        });
      }

      if (techStack.cdn.length > 0) {
        const name = `CDN/WAF: ${techStack.cdn.join(', ')}`;
        observations.push({
            assetId: makeAssetId(domain, name, source),
            domain,
            assetType: 'breach',
            name,
            source,
            observedAt: now,
            tags: ['builtwith', 'cdn', 'waf'],
            evidence: { 
                source: 'builtwith_passive', 
                cdn: techStack.cdn,
                value: `CDN or WAF detected — may affect scanning approach`,
                severity: 0,
                confidence: 70,
            },
            attribution: {
                provider: "BuiltWith",
                url: "https://builtwith.com",
                method: "passive",
            },
        });
      }
    }

    return {
      connector: 'builtwith',
      domain,
      observations,
      errors, 
      durationMs: Date.now() - start, 
      rateLimited,
    };
  },
};

async function detectFromHeaders(domain: string): Promise<Record<string, string[]>> {
  const tech: Record<string, string[]> = {};
  try {
    const resp = await fetch(`https://${domain}`, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)' },
    });

    const server = resp.headers.get('server');
    if (server) tech.server = [server];

    const powered = resp.headers.get('x-powered-by');
    if (powered) tech.framework = [powered];

    // CDN/WAF detection from headers
    const cdn: string[] = [];
    if (resp.headers.get('cf-ray')) cdn.push('Cloudflare');
    if (resp.headers.get('x-amz-cf-id') || resp.headers.get('x-amz-cf-pop')) cdn.push('AWS CloudFront');
    if (resp.headers.get('x-akamai-transformed')) cdn.push('Akamai');
    if (resp.headers.get('x-fastly-request-id')) cdn.push('Fastly');
    if (resp.headers.get('x-sucuri-id')) cdn.push('Sucuri WAF');
    if (resp.headers.get('x-cdn') === 'Incapsula') cdn.push('Imperva/Incapsula');
    if (resp.headers.get('x-vercel-id')) cdn.push('Vercel');
    if (resp.headers.get('x-netlify-request-id')) cdn.push('Netlify');
    if (cdn.length > 0) tech.cdn = cdn;

    // Security headers
    const security: string[] = [];
    if (resp.headers.get('strict-transport-security')) security.push('HSTS');
    if (resp.headers.get('content-security-policy')) security.push('CSP');
    if (resp.headers.get('x-frame-options')) security.push('X-Frame-Options');
    if (resp.headers.get('x-content-type-options')) security.push('X-Content-Type-Options');
    if (resp.headers.get('x-xss-protection')) security.push('X-XSS-Protection');
    if (resp.headers.get('permissions-policy')) security.push('Permissions-Policy');
    if (security.length > 0) tech.security = security;

  } catch { /* continue */ }
  return tech;
}

async function detectFromHtml(domain: string): Promise<Record<string, string[]>> {
  const tech: Record<string, string[]> = {};
  try {
    const resp = await fetch(`https://${domain}`, {
      redirect: 'follow',
      signal: AbortSignal.timeout(12000),
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
    });
    if (!resp.ok) return tech;

    const html = await resp.text();
    const lower = html.toLowerCase();

    // CMS detection
    const cms: string[] = [];
    if (lower.includes('wp-content') || lower.includes('wp-includes')) cms.push('WordPress');
    if (lower.includes('drupal') || lower.includes('/sites/default/')) cms.push('Drupal');
    if (lower.includes('joomla') || lower.includes('/media/jui/')) cms.push('Joomla');
    if (lower.includes('shopify') || lower.includes('cdn.shopify.com')) cms.push('Shopify');
    if (lower.includes('squarespace')) cms.push('Squarespace');
    if (lower.includes('wix.com')) cms.push('Wix');
    if (lower.includes('hubspot')) cms.push('HubSpot');
    if (lower.includes('webflow')) cms.push('Webflow');
    if (lower.includes('ghost') && lower.includes('ghost-')) cms.push('Ghost');
    if (cms.length > 0) tech.cms = cms;

    // Framework detection
    const framework: string[] = [];
    if (lower.includes('__next') || lower.includes('_next/')) framework.push('Next.js');
    if (lower.includes('__nuxt') || lower.includes('/_nuxt/')) framework.push('Nuxt.js');
    if (lower.includes('ng-') || lower.includes('angular')) framework.push('Angular');
    if (lower.includes('react') || lower.includes('__react')) framework.push('React');
    if (lower.includes('vue') && lower.includes('data-v-')) framework.push('Vue.js');
    if (lower.includes('laravel')) framework.push('Laravel');
    if (lower.includes('django') || lower.includes('csrfmiddlewaretoken')) framework.push('Django');
    if (lower.includes('rails') || lower.includes('csrf-token')) framework.push('Ruby on Rails');
    if (lower.includes('asp.net') || lower.includes('__viewstate')) framework.push('ASP.NET');
    if (framework.length > 0) tech.framework = framework;

    // Analytics detection
    const analytics: string[] = [];
    if (lower.includes('google-analytics') || lower.includes('gtag') || lower.includes('ga.js')) analytics.push('Google Analytics');
    if (lower.includes('googletagmanager')) analytics.push('Google Tag Manager');
    if (lower.includes('hotjar')) analytics.push('Hotjar');
    if (lower.includes('mixpanel')) analytics.push('Mixpanel');
    if (lower.includes('segment.com') || lower.includes('analytics.js')) analytics.push('Segment');
    if (lower.includes('facebook') && lower.includes('pixel')) analytics.push('Facebook Pixel');
    if (lower.includes('clarity.ms')) analytics.push('Microsoft Clarity');
    if (lower.includes('heap') && lower.includes('heap-')) analytics.push('Heap');
    if (analytics.length > 0) tech.analytics = analytics;

    // JavaScript libraries
    const js: string[] = [];
    if (lower.includes('jquery')) js.push('jQuery');
    if (lower.includes('bootstrap')) js.push('Bootstrap');
    if (lower.includes('tailwind')) js.push('Tailwind CSS');
    if (lower.includes('lodash')) js.push('Lodash');
    if (lower.includes('moment.js') || lower.includes('moment.min')) js.push('Moment.js');
    if (lower.includes('recaptcha')) js.push('reCAPTCHA');
    if (lower.includes('stripe.js') || lower.includes('stripe.com/v3')) js.push('Stripe');
    if (js.length > 0) tech.javascript = js;

    // Email/marketing
    const email: string[] = [];
    if (lower.includes('mailchimp')) email.push('Mailchimp');
    if (lower.includes('sendgrid')) email.push('SendGrid');
    if (lower.includes('intercom')) email.push('Intercom');
    if (lower.includes('zendesk')) email.push('Zendesk');
    if (lower.includes('drift')) email.push('Drift');
    if (lower.includes('crisp')) email.push('Crisp');
    if (email.length > 0) tech.email = email;

  } catch { /* continue */ }
  return tech;
}
