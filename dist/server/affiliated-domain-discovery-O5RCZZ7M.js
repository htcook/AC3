import {
  init_llm,
  invokeLLM
} from "./chunk-NS7EEW5R.js";
import "./chunk-RUIEEOYK.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/affiliated-domain-discovery.ts
async function discoverViaSecurityTrails(domain) {
  const apiKey = ENV.SECURITYTRAILS_API_KEY;
  if (!apiKey) {
    console.log("[AffiliatedDomains] SecurityTrails API key not configured \u2014 skipping");
    return { domains: [], registrantOrg: null, registrantEmail: null };
  }
  const results = [];
  let registrantOrg = null;
  let registrantEmail = null;
  try {
    const whoisResp = await fetch(`https://api.securitytrails.com/v1/domain/${domain}/whois`, {
      headers: { APIKEY: apiKey, "Content-Type": "application/json" },
      signal: AbortSignal.timeout(12e3)
    });
    if (whoisResp.ok) {
      const whoisData = await whoisResp.json();
      registrantOrg = whoisData?.result?.registrant_org || null;
      registrantEmail = whoisData?.result?.registrant_email || null;
      if (registrantOrg) {
        try {
          const revResp = await fetch("https://api.securitytrails.com/v1/domains/list", {
            method: "POST",
            headers: { APIKEY: apiKey, "Content-Type": "application/json" },
            body: JSON.stringify({ filter: { whois_organization: registrantOrg } }),
            signal: AbortSignal.timeout(15e3)
          });
          if (revResp.ok) {
            const revData = await revResp.json();
            for (const r of revData.records || []) {
              if (r.hostname && r.hostname !== domain) {
                results.push({
                  domain: r.hostname,
                  relationship: "same_registrant",
                  confidence: 90,
                  source: "securitytrails_reverse_whois",
                  evidence: `Registered to same organization: ${registrantOrg}`,
                  registrantOrg
                });
              }
            }
          }
        } catch (e) {
          console.error(`[AffiliatedDomains] SecurityTrails reverse WHOIS (org) failed: ${e.message}`);
        }
      }
      if (registrantEmail && !registrantEmail.includes("privacy") && !registrantEmail.includes("proxy") && !registrantEmail.includes("redacted")) {
        try {
          const revResp = await fetch("https://api.securitytrails.com/v1/domains/list", {
            method: "POST",
            headers: { APIKEY: apiKey, "Content-Type": "application/json" },
            body: JSON.stringify({ filter: { whois_email: registrantEmail } }),
            signal: AbortSignal.timeout(15e3)
          });
          if (revResp.ok) {
            const revData = await revResp.json();
            for (const r of revData.records || []) {
              if (r.hostname && r.hostname !== domain && !results.some((d) => d.domain === r.hostname)) {
                results.push({
                  domain: r.hostname,
                  relationship: "same_registrant",
                  confidence: 95,
                  source: "securitytrails_reverse_whois",
                  evidence: `Registered with same email: ${registrantEmail}`,
                  registrantEmail
                });
              }
            }
          }
        } catch (e) {
          console.error(`[AffiliatedDomains] SecurityTrails reverse WHOIS (email) failed: ${e.message}`);
        }
      }
    }
    try {
      const assocResp = await fetch(`https://api.securitytrails.com/v1/domain/${domain}/associated`, {
        headers: { APIKEY: apiKey },
        signal: AbortSignal.timeout(12e3)
      });
      if (assocResp.ok) {
        const assocData = await assocResp.json();
        for (const r of assocData.records || []) {
          if (r.hostname && r.hostname !== domain && !results.some((d) => d.domain === r.hostname)) {
            results.push({
              domain: r.hostname,
              relationship: "same_org",
              confidence: 80,
              source: "securitytrails_associated",
              evidence: `SecurityTrails associated domain analysis`,
              registrantOrg: registrantOrg || void 0
            });
          }
        }
      }
    } catch (e) {
      console.error(`[AffiliatedDomains] SecurityTrails associated domains failed: ${e.message}`);
    }
  } catch (e) {
    console.error(`[AffiliatedDomains] SecurityTrails discovery failed: ${e.message}`);
  }
  return { domains: results, registrantOrg, registrantEmail };
}
async function discoverViaCrtShOrgName(orgName, targetDomain) {
  if (!orgName) return [];
  const results = [];
  const seenDomains = /* @__PURE__ */ new Set();
  try {
    const url = `https://crt.sh/?O=${encodeURIComponent(orgName)}&output=json`;
    const resp = await fetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)" },
      signal: AbortSignal.timeout(25e3)
    });
    if (!resp.ok) return results;
    const certs = await resp.json();
    for (const cert of certs) {
      const names = (cert.name_value || "").split("\n");
      for (const name of names) {
        const clean = name.trim().toLowerCase().replace(/^\*\./, "");
        if (!clean || !clean.includes(".")) continue;
        const parts = clean.split(".");
        const baseDomain = parts.length >= 2 ? parts.slice(-2).join(".") : clean;
        if (baseDomain === targetDomain || clean.endsWith(`.${targetDomain}`)) continue;
        if (!seenDomains.has(baseDomain)) {
          seenDomains.add(baseDomain);
          results.push({
            domain: baseDomain,
            relationship: "shared_certificate",
            confidence: 70,
            source: "crtsh_org_search",
            evidence: `Certificate issued to organization "${orgName}" also covers ${baseDomain}`
          });
        }
      }
    }
  } catch (e) {
    console.error(`[AffiliatedDomains] crt.sh org search failed: ${e.message}`);
  }
  return results.slice(0, 50);
}
async function discoverViaDNSCorrelation(domain) {
  const results = [];
  try {
    const txtResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`, {
      signal: AbortSignal.timeout(8e3)
    });
    if (txtResp.ok) {
      const data = await txtResp.json();
      if (data.Answer) {
        for (const answer of data.Answer) {
          const txt = (answer.data || "").replace(/"/g, "");
          const includes = txt.match(/include:([^\s]+)/g);
          if (includes) {
            for (const inc of includes) {
              const d = inc.replace("include:", "").trim();
              if (d.includes(".") && !d.startsWith("_")) {
                const parts = d.split(".");
                const baseDomain = parts.length >= 2 ? parts.slice(-2).join(".") : d;
                if (baseDomain !== domain) {
                  results.push({
                    domain: baseDomain,
                    relationship: "spf_include",
                    confidence: 40,
                    source: "dns_spf",
                    evidence: `Referenced in SPF record: include:${d}`
                  });
                }
              }
            }
          }
          const dmarcDomains = txt.match(/ru[af]=mailto:[^@]+@([^\s;]+)/g);
          if (dmarcDomains) {
            for (const match of dmarcDomains) {
              const emailDomain = match.split("@")[1]?.replace(/[;\s].*/, "");
              if (emailDomain && emailDomain !== domain) {
                results.push({
                  domain: emailDomain,
                  relationship: "dns_correlation",
                  confidence: 50,
                  source: "dns_dmarc",
                  evidence: `DMARC reporting destination: ${emailDomain}`
                });
              }
            }
          }
        }
      }
    }
  } catch (e) {
    console.error(`[AffiliatedDomains] DNS correlation failed: ${e.message}`);
  }
  return results;
}
async function discoverViaLLMKnowledge(domain, orgName) {
  const results = [];
  const orgLabel = orgName || domain.split(".").slice(-2, -1)[0];
  try {
    const response = await invokeLLM({
      _caller: "affiliated-domain-discovery:discoverAffiliatedDomains",
      messages: [
        {
          role: "system",
          content: `You are a domain intelligence analyst. Given an organization and its primary domain, identify other domains that are known to be owned or operated by the same organization. Only include domains you are confident about \u2014 do not guess or speculate.

Return JSON matching this schema:
{
  "affiliatedDomains": [
    {
      "domain": "example.com",
      "relationship": "Brief description of the relationship",
      "confidence": "high|medium|low"
    }
  ]
}

Rules:
- Only include domains you are highly confident are owned by the same organization
- Include alternate TLDs (e.g., .org, .com, .net versions)
- Include product/service domains (e.g., mypbs.org for PBS)
- Include subsidiary domains
- Do NOT include third-party service domains (e.g., google.com, cloudflare.com)
- Do NOT include social media profiles
- Maximum 20 domains`
        },
        {
          role: "user",
          content: `Organization: ${orgLabel}
Primary domain: ${domain}

What other domains are known to be owned or operated by this organization?`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "affiliated_domains",
          strict: true,
          schema: {
            type: "object",
            properties: {
              affiliatedDomains: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    domain: { type: "string" },
                    relationship: { type: "string" },
                    confidence: { type: "string", enum: ["high", "medium", "low"] }
                  },
                  required: ["domain", "relationship", "confidence"],
                  additionalProperties: false
                }
              }
            },
            required: ["affiliatedDomains"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (content) {
      const parsed = JSON.parse(content);
      for (const item of parsed.affiliatedDomains || []) {
        if (item.domain && item.domain !== domain) {
          const confMap = { high: 75, medium: 55, low: 35 };
          results.push({
            domain: item.domain.toLowerCase().replace(/^www\./, ""),
            relationship: "llm_knowledge",
            confidence: confMap[item.confidence] || 50,
            source: "llm_knowledge",
            evidence: item.relationship
          });
        }
      }
    }
  } catch (e) {
    console.error(`[AffiliatedDomains] LLM knowledge discovery failed: ${e.message}`);
  }
  return results;
}
async function runAffiliatedDomainDiscovery(domain, orgName) {
  console.log(`[AffiliatedDomains] Starting affiliated domain discovery for ${domain}`);
  const startMs = Date.now();
  const [stResult, crtResult, dnsResult, llmResult] = await Promise.allSettled([
    discoverViaSecurityTrails(domain),
    discoverViaCrtShOrgName(orgName || "", domain),
    discoverViaDNSCorrelation(domain),
    discoverViaLLMKnowledge(domain, orgName || null)
  ]);
  const allDomains = [];
  let registrantOrg = null;
  let registrantEmail = null;
  if (stResult.status === "fulfilled") {
    allDomains.push(...stResult.value.domains);
    registrantOrg = stResult.value.registrantOrg;
    registrantEmail = stResult.value.registrantEmail;
  }
  if (crtResult.status === "fulfilled") allDomains.push(...crtResult.value);
  if (dnsResult.status === "fulfilled") allDomains.push(...dnsResult.value);
  if (llmResult.status === "fulfilled") allDomains.push(...llmResult.value);
  if (registrantOrg && !orgName && crtResult.status === "fulfilled" && crtResult.value.length === 0) {
    try {
      const crtOrgResults = await discoverViaCrtShOrgName(registrantOrg, domain);
      allDomains.push(...crtOrgResults);
    } catch (e) {
    }
  }
  const domainMap = /* @__PURE__ */ new Map();
  for (const d of allDomains) {
    const key = d.domain.toLowerCase();
    if (key === domain.toLowerCase()) continue;
    if (key.endsWith(`.${domain.toLowerCase()}`)) continue;
    if (isCommonServiceDomain(key)) continue;
    const existing = domainMap.get(key);
    if (!existing || d.confidence > existing.confidence) {
      domainMap.set(key, d);
    } else if (existing && d.source !== existing.source) {
      existing.confidence = Math.min(100, existing.confidence + 10);
      existing.evidence += ` | Also found via ${d.source}`;
    }
  }
  const affiliatedDomains = Array.from(domainMap.values()).sort((a, b) => b.confidence - a.confidence);
  const sourceBreakdown = {};
  for (const d of affiliatedDomains) {
    sourceBreakdown[d.source] = (sourceBreakdown[d.source] || 0) + 1;
  }
  const summary = generateSummary(domain, affiliatedDomains, registrantOrg);
  const elapsed = Date.now() - startMs;
  console.log(`[AffiliatedDomains] Complete for ${domain}: ${affiliatedDomains.length} affiliated domains in ${elapsed}ms`);
  return {
    targetDomain: domain,
    searchedAt: Date.now(),
    registrantOrg,
    registrantEmail,
    affiliatedDomains,
    totalDiscovered: affiliatedDomains.length,
    sourceBreakdown,
    summary
  };
}
function isCommonServiceDomain(domain) {
  const servicePatterns = [
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "cloudflare.com",
    "cloudflare-dns.com",
    "cloudfront.net",
    "amazonaws.com",
    "awsdns-",
    "azure.com",
    "azurewebsites.net",
    "microsoft.com",
    "office365.com",
    "outlook.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "instagram.com",
    "github.com",
    "github.io",
    "githubusercontent.com",
    "wordpress.com",
    "wp.com",
    "squarespace.com",
    "wix.com",
    "mailchimp.com",
    "sendgrid.net",
    "mailgun.org",
    "zendesk.com",
    "intercom.io",
    "hubspot.com",
    "stripe.com",
    "paypal.com",
    "akamai.net",
    "akamaiedge.net",
    "fastly.net",
    "spf.protection.outlook.com",
    "amazonses.com"
  ];
  return servicePatterns.some((p) => domain === p || domain.endsWith(`.${p}`));
}
function generateSummary(domain, affiliatedDomains, registrantOrg) {
  if (affiliatedDomains.length === 0) {
    return `No affiliated domains discovered for ${domain}. The organization may use privacy-protected WHOIS registration or operate under a single domain.`;
  }
  const parts = [];
  parts.push(`${affiliatedDomains.length} affiliated domain(s) discovered for ${domain}`);
  if (registrantOrg) {
    parts.push(`registered to ${registrantOrg}`);
  }
  const highConf = affiliatedDomains.filter((d) => d.confidence >= 80);
  const medConf = affiliatedDomains.filter((d) => d.confidence >= 50 && d.confidence < 80);
  const lowConf = affiliatedDomains.filter((d) => d.confidence < 50);
  if (highConf.length > 0) {
    parts.push(`${highConf.length} high-confidence (same registrant/org)`);
  }
  if (medConf.length > 0) {
    parts.push(`${medConf.length} medium-confidence (certificate/LLM correlation)`);
  }
  if (lowConf.length > 0) {
    parts.push(`${lowConf.length} low-confidence (DNS/SPF correlation)`);
  }
  const topDomains = affiliatedDomains.slice(0, 5).map((d) => d.domain);
  if (topDomains.length > 0) {
    parts.push(`Top matches: ${topDomains.join(", ")}`);
  }
  return parts.join(". ") + ".";
}
var init_affiliated_domain_discovery = __esm({
  "server/lib/affiliated-domain-discovery.ts"() {
    init_env();
    init_llm();
  }
});
init_affiliated_domain_discovery();
export {
  runAffiliatedDomainDiscovery
};
