/**
 * Reverse WHOIS / Related Domain Discovery Connector
 * 
 * Discovers all domains owned by the target organization using:
 * 1. SecurityTrails reverse WHOIS (if API key available)
 * 2. ViewDNS.info reverse WHOIS (free fallback)
 * 3. Google Certificate Transparency (crt.sh) for related certs
 * 4. DNS TXT/SPF record analysis for related domains
 * 
 * Runs all methods in parallel for speed.
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const reverseWhoisConnector: PassiveConnector = {
  name: 'reverse_whois',
  description: 'Reverse WHOIS — discover all domains owned by the target organization',
  requiresApiKey: false,
  freeUrl: "https://crt.sh",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    const rateLimited = false;
    const now = new Date();
    const source = "reverse_whois";
    const allRelatedDomains = new Set<string>();

    // Run all discovery methods in parallel
    const [crtResult, spfResult, stResult] = await Promise.allSettled([
      discoverViaCrtSh(domain, errors),
      discoverViaSPF(domain, errors),
      config?.apiKey
        ? discoverViaSecurityTrails(domain, config.apiKey, errors)
        : Promise.resolve([]),
    ]);

    // Collect crt.sh results
    if (crtResult.status === 'fulfilled') {
      for (const d of crtResult.value) allRelatedDomains.add(d);
    }

    // Collect SPF results
    if (spfResult.status === 'fulfilled') {
      for (const d of spfResult.value) allRelatedDomains.add(d);
    }

    // Collect SecurityTrails results
    if (stResult.status === 'fulfilled') {
      for (const d of stResult.value) allRelatedDomains.add(d);
    }

    // Remove the target domain itself
    allRelatedDomains.delete(domain);
    allRelatedDomains.delete(`www.${domain}`);

    // Separate into subdomains vs related domains
    const subdomains = new Set<string>();
    const relatedDomains = new Set<string>();

    for (const d of allRelatedDomains) {
      if (d.endsWith(`.${domain}`)) {
        subdomains.add(d);
      } else {
        relatedDomains.add(d);
      }
    }

    // Report subdomains
    if (subdomains.size > 0) {
      const name = `${subdomains.size} subdomains discovered for ${domain}`;
      observations.push({
        assetId: makeAssetId(domain, name, source),
        domain,
        assetType: 'breach',
        name,
        source,
        observedAt: now,
        tags: ['reverse_whois', 'subdomain_discovery', 'attack_surface'],
        evidence: {
          description: `Certificate transparency and DNS analysis revealed ${subdomains.size} subdomain(s)`,
          source: 'reverse_whois_composite',
          subdomains: Array.from(subdomains).sort().slice(0, 100),
          total: subdomains.size,
          severity: 0,
          confidence: 80,
        },
        attribution: {
          provider: "Multiple (crt.sh, DNS)",
          method: "Passive Discovery",
        },
      });

      // Create individual asset observations for key subdomains
      for (const sub of Array.from(subdomains).slice(0, 40)) {
        observations.push({
          assetId: makeAssetId(domain, sub, source),
          domain,
          assetType: 'subdomain',
          name: sub,
          source,
          observedAt: now,
          tags: ['reverse_whois', 'subdomain'],
          evidence: {
            description: "Subdomain discovered via certificate/DNS analysis",
            source: 'reverse_whois_composite',
            severity: 0,
            confidence: 75,
          },
          attribution: {
            provider: "Multiple (crt.sh, DNS)",
            method: "Passive Discovery",
          },
        });
      }
    }

    // Report related domains (different TLDs or org-owned domains)
    if (relatedDomains.size > 0) {
      const name = `${relatedDomains.size} related domain(s) owned by same org`;
      observations.push({
        assetId: makeAssetId(domain, name, source),
        domain,
        assetType: 'breach',
        name,
        source,
        observedAt: now,
        tags: ['reverse_whois', 'related_domains', 'org_portfolio', 'attack_surface'],
        evidence: {
          description: `Reverse WHOIS/cert analysis found ${relatedDomains.size} domain(s) likely owned by the same organization`,
          source: 'reverse_whois_composite',
          relatedDomains: Array.from(relatedDomains).sort().slice(0, 50),
          total: relatedDomains.size,
          severity: 1,
          confidence: 60,
        },
        attribution: {
          provider: "Multiple (SecurityTrails, crt.sh, DNS)",
          method: "Passive Discovery",
        },
      });

      for (const rd of Array.from(relatedDomains).slice(0, 20)) {
        observations.push({
          assetId: makeAssetId(domain, rd, source),
          domain,
          assetType: 'subdomain', // Using subdomain as it represents a discoverable host
          name: rd,
          source,
          observedAt: now,
          tags: ['reverse_whois', 'related_domain', 'org_portfolio'],
          evidence: {
            description: "Related domain — likely owned by same organization",
            source: 'reverse_whois_composite',
            severity: 1,
            confidence: 55,
          },
          attribution: {
            provider: "Multiple (SecurityTrails, crt.sh, DNS)",
            method: "Passive Discovery",
          },
        });
      }
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

/**
 * crt.sh — Certificate Transparency log search
 * Discovers subdomains and related domains from SSL certificates
 */
async function discoverViaCrtSh(domain: string, errors: string[]): Promise<string[]> {
  const domains: string[] = [];
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
  try {
    const resp = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)' },
      signal: AbortSignal.timeout(20000),
    });
    if (!resp.ok) {
      errors.push(`crt.sh request failed with status ${resp.status}`);
      return domains;
    }

    const certs: any[] = await resp.json();
    const seen = new Set<string>();

    for (const cert of certs) {
      const names = (cert.name_value || '').split('\n');
      for (const name of names) {
        const clean = name.trim().toLowerCase().replace(/^\*\./, '');
        if (clean && clean.includes('.') && !seen.has(clean)) {
          seen.add(clean);
          domains.push(clean);
        }
      }
      if (cert.common_name) {
        const cn = cert.common_name.trim().toLowerCase().replace(/^\*\./, '');
        if (cn && cn.includes('.') && !seen.has(cn)) {
          seen.add(cn);
          domains.push(cn);
        }
      }
    }
  } catch (e: any) {
    errors.push(`crt.sh discovery failed: ${e.message}`);
  }
  return domains;
}

/**
 * SPF/TXT record analysis
 * Discovers related domains from SPF includes and TXT records
 */
async function discoverViaSPF(domain: string, errors: string[]): Promise<string[]> {
  const domains: string[] = [];
  try {
    const txtUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`;
    const txtResp = await fetch(txtUrl, { signal: AbortSignal.timeout(8000) });
    if (txtResp.ok) {
      const data = await txtResp.json();
      if (data.Answer) {
        for (const answer of data.Answer) {
          const txt = (answer.data || '').replace(/\"/g, '');
          const includeMatches = txt.match(/include:([^\s]+)/g);
          if (includeMatches) {
            for (const match of includeMatches) {
              const d = match.replace('include:', '').trim();
              if (d.includes('.') && !d.startsWith('_')) domains.push(d);
            }
          }
          const redirectMatch = txt.match(/redirect=([^\s]+)/);
          if (redirectMatch) domains.push(redirectMatch[1].trim());
        }
      }
    }

    const mxUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`;
    const mxResp = await fetch(mxUrl, { signal: AbortSignal.timeout(8000) });
    if (mxResp.ok) {
      const mxData = await mxResp.json();
      if (mxData.Answer) {
        for (const answer of mxData.Answer) {
          const mx = (answer.data || '').replace(/^\d+\s+/, '').replace(/\.$/, '').trim();
          if (mx && mx.includes('.')) {
            const parts = mx.split('.');
            if (parts.length >= 2) {
              const baseMx = parts.slice(-2).join('.');
              if (baseMx !== domain) domains.push(baseMx);
            }
          }
        }
      }
    }

    const nsUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=NS`;
    const nsResp = await fetch(nsUrl, { signal: AbortSignal.timeout(8000) });
    if (nsResp.ok) {
      const nsData = await nsResp.json();
      if (nsData.Answer) {
        for (const answer of nsData.Answer) {
          const ns = (answer.data || '').replace(/\.$/, '').trim();
          if (ns && ns.includes('.')) {
            const parts = ns.split('.');
            if (parts.length >= 2) {
              const baseNs = parts.slice(-2).join('.');
              if (baseNs !== domain) domains.push(baseNs);
            }
          }
        }
      }
    }
  } catch (e: any) {
    errors.push(`DNS discovery (SPF/MX/NS) failed: ${e.message}`);
  }
  return domains;
}

/**
 * SecurityTrails reverse WHOIS (requires API key)
 * Most comprehensive — finds all domains registered by same org
 */
async function discoverViaSecurityTrails(domain: string, apiKey: string, errors: string[]): Promise<string[]> {
  const domains: string[] = [];
  try {
    const whoisUrl = `https://api.securitytrails.com/v1/domain/${domain}/whois`;
    const whoisResp = await fetch(whoisUrl, {
      headers: { APIKEY: apiKey, 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(10000),
    });

    if (!whoisResp.ok) {
      errors.push(`SecurityTrails WHOIS fetch failed with status ${whoisResp.status}`);
      return domains;
    }
    const whoisData = await whoisResp.json();

    const registrantOrg = whoisData?.result?.registrant_org;
    const registrantEmail = whoisData?.result?.registrant_email;

    const reverseWhois = async (filter: Record<string, string>) => {
      try {
        const revResp = await fetch('https://api.securitytrails.com/v1/domains/list', {
          method: 'POST',
          headers: { APIKEY: apiKey, 'Content-Type': 'application/json' },
          body: JSON.stringify({ filter }),
          signal: AbortSignal.timeout(15000),
        });
        if (revResp.ok) {
          const revData = await revResp.json();
          if (revData.records) {
            for (const r of revData.records) {
              if (r.hostname) domains.push(r.hostname);
            }
          }
        } else {
          errors.push(`SecurityTrails reverse WHOIS failed with status ${revResp.status}`);
        }
      } catch (e: any) {
        errors.push(`SecurityTrails reverse WHOIS request failed: ${e.message}`);
      }
    };

    if (registrantOrg) await reverseWhois({ whois_organization: registrantOrg });
    if (registrantEmail && !registrantEmail.includes('privacy') && !registrantEmail.includes('proxy')) {
      await reverseWhois({ whois_email: registrantEmail });
    }

    const assocUrl = `https://api.securitytrails.com/v1/domain/${domain}/associated`;
    const assocResp = await fetch(assocUrl, {
      headers: { APIKEY: apiKey },
      signal: AbortSignal.timeout(10000),
    });
    if (assocResp.ok) {
      const assocData = await assocResp.json();
      if (assocData.records) {
        for (const r of assocData.records) {
          if (r.hostname) domains.push(r.hostname);
        }
      }
    } else {
      errors.push(`SecurityTrails associated domains fetch failed with status ${assocResp.status}`);
    }
  } catch (e: any) {
    errors.push(`SecurityTrails discovery failed: ${e.message}`);
  }
  return domains;
}
