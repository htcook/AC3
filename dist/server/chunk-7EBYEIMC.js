import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/org-domain-discovery.ts
async function securityTrailsFetch(path, timeoutMs) {
  const apiKey = ENV.SECURITYTRAILS_API_KEY;
  if (!apiKey) throw new Error("SecurityTrails API key not configured");
  const res = await fetch(`https://api.securitytrails.com/v1${path}`, {
    headers: { APIKEY: apiKey, Accept: "application/json" },
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (!res.ok) throw new Error(`SecurityTrails ${res.status}: ${res.statusText}`);
  return res.json();
}
async function resolveDNS(domain, type, timeoutMs) {
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
      { signal: AbortSignal.timeout(timeoutMs) }
    );
    if (!res.ok) return [];
    const data = await res.json();
    return (data.Answer || []).map((a) => a.data?.replace(/\.$/, "") || "").filter(Boolean);
  } catch {
    return [];
  }
}
function isGenericNS(ns) {
  const lower = ns.toLowerCase();
  for (const provider of GENERIC_NS_PROVIDERS) {
    if (lower.includes(provider)) return true;
  }
  return false;
}
function isGenericMX(mx) {
  const lower = mx.toLowerCase();
  for (const provider of GENERIC_MX_PROVIDERS) {
    if (lower.includes(provider)) return true;
  }
  return false;
}
async function discoverViaSecurityTrailsAssociated(domain, config) {
  const start = Date.now();
  try {
    const data = await securityTrailsFetch(
      `/domain/${domain}/associated`,
      config.lookupTimeoutMs
    );
    const domains = (data.records || []).map((r) => r.hostname || r.domain || "").filter((d) => d && d !== domain).slice(0, config.maxCandidates);
    return { domains: [...new Set(domains)], durationMs: Date.now() - start };
  } catch (err) {
    console.error(`[OrgDiscovery] SecurityTrails associated failed: ${err.message}`);
    return { domains: [], durationMs: Date.now() - start };
  }
}
async function discoverViaReverseWhois(domain, orgName, orgEmail, config) {
  const start = Date.now();
  const domains = [];
  try {
    if (orgName && orgName.length > 2) {
      try {
        const data = await securityTrailsFetch(
          `/domains/list?include[]=whois_organization&filter[whois_organization]=${encodeURIComponent(orgName)}`,
          config.lookupTimeoutMs
        );
        const found = (data.records || []).map((r) => r.hostname || "").filter(Boolean);
        domains.push(...found);
      } catch {
        try {
          const searchData = await securityTrailsFetch(
            `/search/list`,
            config.lookupTimeoutMs
          );
        } catch {
        }
      }
    }
    if (orgEmail) {
      try {
        const data = await securityTrailsFetch(
          `/domains/list?include[]=whois_email&filter[whois_email]=${encodeURIComponent(orgEmail)}`,
          config.lookupTimeoutMs
        );
        const found = (data.records || []).map((r) => r.hostname || "").filter(Boolean);
        domains.push(...found);
      } catch {
      }
    }
  } catch (err) {
    console.error(`[OrgDiscovery] Reverse WHOIS failed: ${err.message}`);
  }
  return {
    domains: [...new Set(domains.filter((d) => d !== domain))].slice(0, config.maxCandidates),
    durationMs: Date.now() - start
  };
}
async function discoverViaCTOrgSearch(orgName, seedDomain, config) {
  const start = Date.now();
  const domains = /* @__PURE__ */ new Set();
  try {
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
  } catch (err) {
    console.error(`[OrgDiscovery] CT org search failed: ${err.message}`);
  }
  return {
    domains: [...domains].slice(0, config.maxCandidates),
    durationMs: Date.now() - start
  };
}
async function discoverViaCensysCertOrg(orgName, seedDomain, config) {
  const start = Date.now();
  const domains = /* @__PURE__ */ new Set();
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
        Accept: "application/json"
      },
      body: JSON.stringify({
        q: `parsed.subject.organization: "${orgName}"`,
        per_page: 100
      }),
      signal: AbortSignal.timeout(config.lookupTimeoutMs)
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
  } catch (err) {
    console.error(`[OrgDiscovery] Censys cert org search failed: ${err.message}`);
  }
  return {
    domains: [...domains].slice(0, config.maxCandidates),
    durationMs: Date.now() - start
  };
}
async function discoverViaSpfPivoting(domain, config) {
  const start = Date.now();
  const domains = /* @__PURE__ */ new Set();
  try {
    const txtRecords = await resolveDNS(domain, "TXT", config.lookupTimeoutMs);
    for (const txt of txtRecords) {
      const includes = txt.match(/include:([^\s]+)/g) || [];
      for (const inc of includes) {
        const incDomain = inc.replace("include:", "").replace(/\.$/, "");
        const parts = incDomain.split(".");
        if (parts.length >= 2) {
          const root = parts.slice(-2).join(".");
          if (!isGenericMX(root) && root !== domain && root.includes(".")) {
            domains.add(root);
          }
        }
      }
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
  } catch (err) {
    console.error(`[OrgDiscovery] SPF pivoting failed: ${err.message}`);
  }
  return { domains: [...domains], durationMs: Date.now() - start };
}
async function verifyOwnership(candidateDomain, seedOrgName, seedOrgEmail, seedNS, seedMX, seedAsn, config) {
  const signals = [];
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
            detail: `WHOIS registrant org "${registrantOrg}" matches seed org "${seedOrgName}"`
          });
        }
      }
      if (registrantEmail && seedOrgEmail) {
        const candidateEmailDomain = registrantEmail.split("@")[1]?.toLowerCase();
        const seedEmailDomain = seedOrgEmail.split("@")[1]?.toLowerCase();
        if (candidateEmailDomain && seedEmailDomain && candidateEmailDomain === seedEmailDomain) {
          signals.push({
            type: "whois_email",
            value: registrantEmail,
            confidence: 80,
            detail: `WHOIS registrant email domain matches seed email domain "${seedEmailDomain}"`
          });
        }
      }
    }
  } catch {
  }
  try {
    const [aRecords] = await Promise.all([
      resolveDNS(candidateDomain, "A", config.lookupTimeoutMs)
    ]);
    if (aRecords.length > 0 && ENV.CENSYS_API_ID && ENV.CENSYS_API_SECRET) {
      const auth = Buffer.from(`${ENV.CENSYS_API_ID}:${ENV.CENSYS_API_SECRET}`).toString("base64");
      const certRes = await fetch("https://search.censys.io/api/v2/certificates/search", {
        method: "POST",
        headers: {
          Authorization: `Basic ${auth}`,
          "Content-Type": "application/json",
          Accept: "application/json"
        },
        body: JSON.stringify({ q: `names: ${candidateDomain}`, per_page: 5 }),
        signal: AbortSignal.timeout(config.lookupTimeoutMs)
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
                detail: `SSL cert org "${certOrg}" matches seed org "${seedOrgName}"`
              });
              break;
            }
          }
        }
      }
    }
  } catch {
  }
  try {
    const candidateNS = await resolveDNS(candidateDomain, "NS", config.lookupTimeoutMs);
    const sharedNS = candidateNS.filter(
      (ns) => !isGenericNS(ns) && seedNS.some(
        (sNS) => ns.toLowerCase() === sNS.toLowerCase() || ns.toLowerCase().endsWith("." + sNS.split(".").slice(-2).join(".").toLowerCase())
      )
    );
    if (sharedNS.length > 0) {
      signals.push({
        type: "shared_ns",
        value: sharedNS.join(", "),
        confidence: 65,
        detail: `Shares ${sharedNS.length} non-generic nameserver(s) with seed domain`
      });
    }
  } catch {
  }
  try {
    const candidateMX = await resolveDNS(candidateDomain, "MX", config.lookupTimeoutMs);
    const cleanMX = candidateMX.map((mx) => mx.replace(/^\d+\s+/, "").toLowerCase());
    const sharedMX = cleanMX.filter(
      (mx) => !isGenericMX(mx) && seedMX.some(
        (sMX) => mx === sMX.toLowerCase() || mx.endsWith("." + sMX.split(".").slice(-2).join(".").toLowerCase())
      )
    );
    if (sharedMX.length > 0) {
      signals.push({
        type: "shared_mx",
        value: sharedMX.join(", "),
        confidence: 55,
        detail: `Shares ${sharedMX.length} non-generic MX record(s) with seed domain`
      });
    }
  } catch {
  }
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
        if (seedOrgName && (issuerOrg.toLowerCase().includes(seedOrgName.toLowerCase()) || certOrg.toLowerCase().includes(seedOrgName.toLowerCase()))) {
          signals.push({
            type: "ct_org_match",
            value: certOrg || issuerOrg,
            confidence: 60,
            detail: `CT log certificate references seed org "${seedOrgName}"`
          });
          break;
        }
      }
    }
  } catch {
  }
  let confidence = 0;
  if (signals.length === 0) {
    confidence = 10;
  } else if (signals.length === 1) {
    confidence = signals[0].confidence;
  } else {
    signals.sort((a, b) => b.confidence - a.confidence);
    confidence = Math.min(100, signals[0].confidence + (signals.length - 1) * 8);
  }
  return { signals, confidence };
}
function classifyMissionRelevance(domain) {
  const lower = domain.toLowerCase();
  for (const [category, patterns] of Object.entries(MISSION_PATTERNS)) {
    if (category === "unknown") continue;
    for (const pattern of patterns) {
      if (pattern.test(lower)) {
        return category;
      }
    }
  }
  const baseName = lower.split(".")[0];
  if (baseName.length <= 8) return "corporate";
  return "unknown";
}
async function classifyMissionRelevanceLLM(domains, orgName) {
  const result = /* @__PURE__ */ new Map();
  for (const { domain } of domains) {
    result.set(domain, classifyMissionRelevance(domain));
  }
  if (domains.length > 0) {
    try {
      const { invokeLLM } = await import("./llm-IHYY5FA6.js");
      const domainList = domains.map((d) => d.domain).join(", ");
      const response = await invokeLLM({
        _caller: "org-domain-discovery.classifyMissionRelevanceLLM",
        _priority: "bulk",
        messages: [
          {
            role: "system",
            content: "You are a cybersecurity analyst classifying domains by their mission relevance to an organization. Return ONLY valid JSON."
          },
          {
            role: "user",
            content: `Organization: ${orgName}
Domains: ${domainList}

Classify each domain into one of: product (customer-facing apps/platforms), service (APIs, SaaS, CDN), infrastructure (mail, VPN, CI/CD, monitoring), marketing (blogs, landing pages, campaigns), corporate (main site, investor relations). Return JSON object mapping domain to category.`
          }
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
                        enum: ["product", "service", "infrastructure", "marketing", "corporate", "unknown"]
                      },
                      reasoning: { type: "string" }
                    },
                    required: ["domain", "category", "reasoning"],
                    additionalProperties: false
                  }
                }
              },
              required: ["classifications"],
              additionalProperties: false
            }
          }
        }
      });
      const content = response.choices?.[0]?.message?.content;
      if (content) {
        const parsed = JSON.parse(content);
        for (const cls of parsed.classifications || []) {
          if (cls.domain && cls.category) {
            result.set(cls.domain, cls.category);
          }
        }
      }
    } catch (err) {
      console.error(`[OrgDiscovery] LLM classification failed, using pattern-based: ${err.message}`);
    }
  }
  return result;
}
async function discoverOrgDomains(seedDomain, orgName, orgEmail, config, onProgress) {
  const fullConfig = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();
  const stats = [];
  const candidateMap = /* @__PURE__ */ new Map();
  onProgress?.(`Starting org-wide domain discovery for ${seedDomain} (org: ${orgName})`);
  onProgress?.("Gathering seed domain infrastructure signals...");
  const [seedNS, seedMXRaw] = await Promise.all([
    resolveDNS(seedDomain, "NS", fullConfig.lookupTimeoutMs),
    resolveDNS(seedDomain, "MX", fullConfig.lookupTimeoutMs)
  ]);
  const seedMX = seedMXRaw.map((mx) => mx.replace(/^\d+\s+/, "").toLowerCase());
  let seedAsn = null;
  if (ENV.SECURITYTRAILS_API_KEY) {
    onProgress?.("Querying SecurityTrails associated domains...");
    const result = await discoverViaSecurityTrailsAssociated(seedDomain, fullConfig);
    for (const d of result.domains) {
      if (!candidateMap.has(d)) candidateMap.set(d, /* @__PURE__ */ new Set());
      candidateMap.get(d).add("securitytrails_associated");
    }
    stats.push({
      source: "securitytrails_associated",
      domainsFound: result.domains.length,
      durationMs: result.durationMs,
      status: result.domains.length >= 0 ? "success" : "failed",
      error: null
    });
  } else {
    stats.push({ source: "securitytrails_associated", domainsFound: 0, durationMs: 0, status: "skipped", error: "API key not configured" });
  }
  if (ENV.SECURITYTRAILS_API_KEY && orgName) {
    onProgress?.("Performing reverse WHOIS lookup...");
    const result = await discoverViaReverseWhois(seedDomain, orgName, orgEmail, fullConfig);
    for (const d of result.domains) {
      if (!candidateMap.has(d)) candidateMap.set(d, /* @__PURE__ */ new Set());
      candidateMap.get(d).add("reverse_whois");
    }
    stats.push({
      source: "reverse_whois",
      domainsFound: result.domains.length,
      durationMs: result.durationMs,
      status: "success",
      error: null
    });
  } else {
    stats.push({ source: "reverse_whois", domainsFound: 0, durationMs: 0, status: "skipped", error: orgName ? "API key not configured" : "No org name available" });
  }
  if (orgName) {
    onProgress?.("Searching Certificate Transparency logs by org name...");
    const result = await discoverViaCTOrgSearch(orgName, seedDomain, fullConfig);
    for (const d of result.domains) {
      if (!candidateMap.has(d)) candidateMap.set(d, /* @__PURE__ */ new Set());
      candidateMap.get(d).add("ct_org_search");
    }
    stats.push({
      source: "ct_org_search",
      domainsFound: result.domains.length,
      durationMs: result.durationMs,
      status: "success",
      error: null
    });
  } else {
    stats.push({ source: "ct_org_search", domainsFound: 0, durationMs: 0, status: "skipped", error: "No org name available" });
  }
  if (orgName && ENV.CENSYS_API_ID && ENV.CENSYS_API_SECRET) {
    onProgress?.("Searching Censys certificates by org name...");
    const result = await discoverViaCensysCertOrg(orgName, seedDomain, fullConfig);
    for (const d of result.domains) {
      if (!candidateMap.has(d)) candidateMap.set(d, /* @__PURE__ */ new Set());
      candidateMap.get(d).add("censys_cert_org");
    }
    stats.push({
      source: "censys_cert_org",
      domainsFound: result.domains.length,
      durationMs: result.durationMs,
      status: "success",
      error: null
    });
  } else {
    stats.push({ source: "censys_cert_org", domainsFound: 0, durationMs: 0, status: "skipped", error: !orgName ? "No org name" : "Censys API not configured" });
  }
  if (fullConfig.enableSpfPivoting) {
    onProgress?.("Analyzing SPF/TXT records for domain references...");
    const result = await discoverViaSpfPivoting(seedDomain, fullConfig);
    for (const d of result.domains) {
      if (!candidateMap.has(d)) candidateMap.set(d, /* @__PURE__ */ new Set());
      candidateMap.get(d).add("spf_pivoting");
    }
    stats.push({
      source: "spf_pivoting",
      domainsFound: result.domains.length,
      durationMs: result.durationMs,
      status: "success",
      error: null
    });
  }
  const totalCandidates = candidateMap.size;
  onProgress?.(`Found ${totalCandidates} candidate domains. Verifying ownership...`);
  const candidates = [...candidateMap.entries()].slice(0, fullConfig.maxCandidates);
  const CONCURRENCY = 5;
  const verifiedDomains = [];
  const unverifiedDomains = [];
  for (let i = 0; i < candidates.length; i += CONCURRENCY) {
    const batch = candidates.slice(i, i + CONCURRENCY);
    const results = await Promise.allSettled(
      batch.map(async ([domain, sources]) => {
        const { signals, confidence } = await verifyOwnership(
          domain,
          orgName,
          orgEmail,
          seedNS,
          seedMX,
          seedAsn,
          fullConfig
        );
        const domainResult = {
          domain,
          ownershipConfidence: confidence,
          ownershipSignals: signals,
          missionRelevance: "unknown",
          // Will be classified later
          discoverySource: [...sources],
          registrant: null,
          registrantEmail: null,
          sslCertOrg: null,
          nameservers: [],
          mxRecords: [],
          resolvedIps: [],
          asn: null,
          isVerified: confidence >= fullConfig.minConfidenceThreshold
        };
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
  if (verifiedDomains.length > 0) {
    onProgress?.("Classifying mission relevance of verified domains...");
    const classifications = await classifyMissionRelevanceLLM(
      verifiedDomains.map((d) => ({ domain: d.domain, signals: d.ownershipSignals })),
      orgName
    );
    for (const domain of verifiedDomains) {
      domain.missionRelevance = classifications.get(domain.domain) || classifyMissionRelevance(domain.domain);
    }
  }
  const relevancePriority = {
    product: 1,
    service: 2,
    infrastructure: 3,
    corporate: 4,
    marketing: 5,
    unknown: 6
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
    durationMs: Date.now() - startTime
  };
}
var GENERIC_NS_PROVIDERS, GENERIC_MX_PROVIDERS, MISSION_PATTERNS, DEFAULT_CONFIG;
var init_org_domain_discovery = __esm({
  "server/lib/org-domain-discovery.ts"() {
    "use strict";
    init_env();
    GENERIC_NS_PROVIDERS = /* @__PURE__ */ new Set([
      "cloudflare.com",
      "awsdns",
      "google.com",
      "azure-dns",
      "ultradns",
      "domaincontrol.com",
      "registrar-servers.com",
      "ns1.com",
      "dnsmadeeasy.com",
      "route53",
      "dnsimple.com",
      "he.net",
      "linode.com",
      "digitalocean.com",
      "vultr.com",
      "hetzner.com",
      "ovh.net",
      "gandi.net",
      "name.com",
      "hostgator.com",
      "bluehost.com",
      "siteground.net",
      "dreamhost.com",
      "pair.com",
      "hover.com",
      "namecheap.com",
      "godaddy.com"
    ]);
    GENERIC_MX_PROVIDERS = /* @__PURE__ */ new Set([
      "google.com",
      "googlemail.com",
      "outlook.com",
      "protection.outlook.com",
      "pphosted.com",
      "mimecast.com",
      "barracuda.com",
      "messagelabs.com",
      "secureserver.net",
      "emailsrvr.com",
      "zoho.com",
      "fastmail.com",
      "protonmail.ch",
      "icloud.com",
      "yahoo.com",
      "yandex.net"
    ]);
    MISSION_PATTERNS = {
      product: [
        /^(app|platform|dashboard|console|portal|my|account|client)/i,
        /(shop|store|buy|checkout|cart|pay|billing)/i,
        /(cloud|saas|api|sdk|dev|developer)/i
      ],
      service: [
        /^(api|graphql|rest|ws|webhook|gateway|proxy)/i,
        /(service|microservice|backend|server)/i,
        /(cdn|assets|static|media|images|files|storage)/i
      ],
      infrastructure: [
        /^(mail|smtp|imap|pop|mx|email)/i,
        /^(vpn|sso|auth|login|ldap|ad|directory)/i,
        /^(git|gitlab|github|bitbucket|ci|cd|jenkins|drone|argo)/i,
        /^(monitor|grafana|prometheus|kibana|elastic|splunk|siem)/i,
        /^(db|database|sql|redis|mongo|postgres|mysql)/i,
        /^(internal|intranet|corp|office|admin)/i
      ],
      marketing: [
        /^(www|web|site|landing|promo|campaign|go|try|get|start)/i,
        /(blog|news|press|media|brand|marketing)/i,
        /(event|conference|summit|webinar)/i
      ],
      corporate: [
        /^(ir|investor|careers|jobs|about|legal|privacy|terms|compliance)/i,
        /(corporate|company|group|holdings|inc|ltd|llc)/i
      ],
      unknown: []
    };
    DEFAULT_CONFIG = {
      minConfidenceThreshold: 60,
      maxCandidates: 200,
      enableWebVerification: false,
      enableSpfPivoting: true,
      lookupTimeoutMs: 15e3
    };
  }
});

export {
  discoverOrgDomains,
  init_org_domain_discovery
};
