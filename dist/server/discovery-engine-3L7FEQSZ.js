import {
  discoverOrgDomains,
  init_org_domain_discovery
} from "./chunk-7EBYEIMC.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/discovery-engine.ts
async function shodanFetch(path, params = {}) {
  const apiKey = ENV.SHODAN_API_KEY;
  if (!apiKey) throw new Error("Shodan API key not configured");
  const qs = new URLSearchParams({ ...params, key: apiKey }).toString();
  const res = await fetch(`https://api.shodan.io${path}?${qs}`, {
    signal: AbortSignal.timeout(2e4)
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Shodan ${res.status}: ${text}`);
  }
  return res.json();
}
async function shodanHostLookup(ip) {
  try {
    const data = await shodanFetch(`/shodan/host/${ip}`);
    return {
      ip: data.ip_str || ip,
      hostnames: data.hostnames || [],
      ports: (data.data || []).map((svc) => ({
        port: svc.port,
        protocol: svc.transport || "tcp",
        service: svc._shodan?.module || null,
        product: svc.product || null,
        version: svc.version || null,
        banner: (svc.data || "").substring(0, 500),
        cpe: svc.cpe || [],
        vulns: Object.keys(svc.vulns || {}),
        transport: svc.transport || null,
        timestamp: svc.timestamp || null
      })),
      os: data.os || null,
      location: {
        country: data.country_name || null,
        city: data.city || null,
        latitude: data.latitude || null,
        longitude: data.longitude || null
      },
      organization: data.org || null,
      asn: data.asn ? parseInt(String(data.asn).replace("AS", "")) : null,
      isp: data.isp || null,
      lastSeen: data.last_update || (/* @__PURE__ */ new Date()).toISOString(),
      source: "shodan",
      tags: data.tags || [],
      vulns: data.vulns || [],
      confidence: 90
    };
  } catch (err) {
    console.error(`[DiscoveryEngine] Shodan host lookup failed for ${ip}:`, err.message);
    return null;
  }
}
async function shodanDomainSearch(domain) {
  try {
    const data = await shodanFetch("/shodan/host/search", { query: `hostname:${domain}` });
    return (data.matches || []).map((match) => ({
      ip: match.ip_str,
      hostnames: match.hostnames || [],
      ports: [{
        port: match.port,
        protocol: match.transport || "tcp",
        service: match._shodan?.module || null,
        product: match.product || null,
        version: match.version || null,
        banner: (match.data || "").substring(0, 500),
        cpe: match.cpe || [],
        vulns: Object.keys(match.vulns || {}),
        transport: match.transport || null,
        timestamp: match.timestamp || null
      }],
      os: match.os || null,
      location: {
        country: match.location?.country_name || null,
        city: match.location?.city || null,
        latitude: match.location?.latitude || null,
        longitude: match.location?.longitude || null
      },
      organization: match.org || null,
      asn: match.asn ? parseInt(String(match.asn).replace("AS", "")) : null,
      isp: match.isp || null,
      lastSeen: match.timestamp || (/* @__PURE__ */ new Date()).toISOString(),
      source: "shodan",
      tags: [],
      vulns: Object.keys(match.vulns || {}),
      confidence: 85
    }));
  } catch (err) {
    console.error(`[DiscoveryEngine] Shodan domain search failed for ${domain}:`, err.message);
    return [];
  }
}
async function shodanDNSLookup(domain) {
  try {
    const data = await shodanFetch(`/dns/domain/${domain}`);
    const subdomains = [];
    for (const record of data.data || []) {
      if (record.type === "A" || record.type === "AAAA") {
        const fqdn = record.subdomain ? `${record.subdomain}.${domain}` : domain;
        const existing = subdomains.find((s) => s.subdomain === fqdn);
        if (existing) {
          if (!existing.ips.includes(record.value)) existing.ips.push(record.value);
        } else {
          subdomains.push({
            subdomain: fqdn,
            source: "shodan_dns",
            ips: [record.value],
            firstSeen: null,
            isActive: true
          });
        }
      }
    }
    return subdomains;
  } catch (err) {
    console.error(`[DiscoveryEngine] Shodan DNS lookup failed for ${domain}:`, err.message);
    return [];
  }
}
async function censysFetch(path, body) {
  const apiId = ENV.CENSYS_API_ID;
  const apiSecret = ENV.CENSYS_API_SECRET;
  if (!apiId || !apiSecret) throw new Error("Censys API credentials not configured");
  const auth = Buffer.from(`${apiId}:${apiSecret}`).toString("base64");
  const res = await fetch(`https://search.censys.io/api/v2${path}`, {
    method: body ? "POST" : "GET",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    body: body ? JSON.stringify(body) : void 0,
    signal: AbortSignal.timeout(2e4)
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Censys ${res.status}: ${text}`);
  }
  return res.json();
}
async function censysHostSearch(query) {
  try {
    const data = await censysFetch("/hosts/search", { q: query, per_page: 50 });
    return (data.result?.hits || []).map((hit) => ({
      ip: hit.ip,
      hostnames: hit.dns?.names || [],
      ports: (hit.services || []).map((svc) => ({
        port: svc.port,
        protocol: svc.transport_protocol || "tcp",
        service: svc.service_name || null,
        product: svc.software?.[0]?.product || null,
        version: svc.software?.[0]?.version || null,
        banner: svc.banner || null,
        cpe: svc.software?.map((s) => s.uniform_resource_identifier).filter(Boolean) || [],
        vulns: [],
        transport: svc.transport_protocol || null,
        timestamp: svc.observed_at || null
      })),
      os: hit.operating_system?.product || null,
      location: {
        country: hit.location?.country || null,
        city: hit.location?.city || null,
        latitude: hit.location?.coordinates?.latitude || null,
        longitude: hit.location?.coordinates?.longitude || null
      },
      organization: hit.autonomous_system?.name || null,
      asn: hit.autonomous_system?.asn || null,
      isp: null,
      lastSeen: hit.last_updated_at || (/* @__PURE__ */ new Date()).toISOString(),
      source: "censys",
      tags: hit.labels || [],
      vulns: [],
      confidence: 85
    }));
  } catch (err) {
    console.error(`[DiscoveryEngine] Censys host search failed:`, err.message);
    return [];
  }
}
async function censysCertSearch(domain) {
  try {
    const data = await censysFetch("/certificates/search", { q: `names: ${domain}`, per_page: 50 });
    return (data.result?.hits || []).map((cert) => {
      const parsed = cert.parsed || {};
      const notAfter = parsed.validity_period?.not_after || "";
      return {
        subject: parsed.subject_dn || "",
        issuer: parsed.issuer_dn || "",
        validFrom: parsed.validity_period?.not_before || "",
        validTo: notAfter,
        serialNumber: parsed.serial_number || "",
        fingerprint: cert.fingerprint_sha256 || "",
        sans: parsed.names || [],
        isExpired: notAfter ? new Date(notAfter) < /* @__PURE__ */ new Date() : false,
        isWildcard: (parsed.names || []).some((n) => n.startsWith("*."))
      };
    });
  } catch (err) {
    console.error(`[DiscoveryEngine] Censys cert search failed for ${domain}:`, err.message);
    return [];
  }
}
async function securityTrailsFetch(path) {
  const apiKey = ENV.SECURITYTRAILS_API_KEY;
  if (!apiKey) throw new Error("SecurityTrails API key not configured");
  const res = await fetch(`https://api.securitytrails.com/v1${path}`, {
    headers: {
      APIKEY: apiKey,
      Accept: "application/json"
    },
    signal: AbortSignal.timeout(2e4)
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`SecurityTrails ${res.status}: ${text}`);
  }
  return res.json();
}
async function securityTrailsSubdomains(domain) {
  try {
    const data = await securityTrailsFetch(`/domain/${domain}/subdomains`);
    return (data.subdomains || []).map((sub) => ({
      subdomain: `${sub}.${domain}`,
      source: "securitytrails",
      ips: [],
      firstSeen: null,
      isActive: true
    }));
  } catch (err) {
    console.error(`[DiscoveryEngine] SecurityTrails subdomain enum failed for ${domain}:`, err.message);
    return [];
  }
}
async function securityTrailsDNSHistory(domain) {
  try {
    const data = await securityTrailsFetch(`/history/${domain}/dns/a`);
    const records = [];
    for (const record of data.records || []) {
      for (const value of record.values || []) {
        records.push({
          type: "A",
          value: value.ip || value.value || "",
          ttl: null,
          firstSeen: record.first_seen || null,
          lastSeen: record.last_seen || null
        });
      }
    }
    return records;
  } catch (err) {
    console.error(`[DiscoveryEngine] SecurityTrails DNS history failed for ${domain}:`, err.message);
    return [];
  }
}
async function securityTrailsDomainInfo(domain) {
  try {
    return await securityTrailsFetch(`/domain/${domain}`);
  } catch (err) {
    console.error(`[DiscoveryEngine] SecurityTrails domain info failed for ${domain}:`, err.message);
    return {};
  }
}
async function securityTrailsWHOIS(domain) {
  try {
    return await securityTrailsFetch(`/domain/${domain}/whois`);
  } catch (err) {
    console.error(`[DiscoveryEngine] SecurityTrails WHOIS failed for ${domain}:`, err.message);
    return {};
  }
}
function generateDiscoveryId() {
  return `disc_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
}
function defaultConfig(targets) {
  return {
    targets,
    scanDepth: "standard",
    enabledSources: {
      shodan: !!ENV.SHODAN_API_KEY,
      censys: !!(ENV.CENSYS_API_ID && ENV.CENSYS_API_SECRET),
      securityTrails: !!ENV.SECURITYTRAILS_API_KEY,
      nuclei: false,
      // Requires CLI bridge
      crtsh: true,
      wayback: true,
      dnsEnum: true,
      whois: true
    },
    scanMode: "passive",
    enrichmentModules: ["domain_intel", "bug_bounty", "threat_enrichment", "opsec"],
    maxConcurrency: 3,
    timeoutMs: 12e4
  };
}
async function crtshSubdomains(domain) {
  try {
    const res = await fetch(
      `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { signal: AbortSignal.timeout(15e3) }
    );
    if (!res.ok) return [];
    const data = await res.json();
    const seen = /* @__PURE__ */ new Set();
    const results = [];
    for (const entry of data) {
      const names = (entry.name_value || "").split("\n").map((n) => n.trim().toLowerCase());
      for (const name of names) {
        if (name && name.endsWith(`.${domain}`) && !seen.has(name) && !name.startsWith("*.")) {
          seen.add(name);
          results.push({
            subdomain: name,
            source: "crtsh",
            ips: [],
            firstSeen: entry.not_before || null,
            isActive: true
          });
        }
      }
    }
    return results;
  } catch (err) {
    console.error(`[DiscoveryEngine] crt.sh lookup failed for ${domain}:`, err.message);
    return [];
  }
}
function mergeHosts(allHosts) {
  const hostMap = /* @__PURE__ */ new Map();
  for (const host of allHosts) {
    const existing = hostMap.get(host.ip);
    if (!existing) {
      hostMap.set(host.ip, { ...host });
      continue;
    }
    for (const h of host.hostnames) {
      if (!existing.hostnames.includes(h)) existing.hostnames.push(h);
    }
    for (const port of host.ports) {
      const existingPort = existing.ports.find((p) => p.port === port.port && p.protocol === port.protocol);
      if (!existingPort) {
        existing.ports.push(port);
      } else if (port.version && !existingPort.version) {
        existingPort.version = port.version;
        existingPort.product = port.product || existingPort.product;
        existingPort.banner = port.banner || existingPort.banner;
      }
    }
    for (const v of host.vulns) {
      if (!existing.vulns.includes(v)) existing.vulns.push(v);
    }
    for (const t of host.tags) {
      if (!existing.tags.includes(t)) existing.tags.push(t);
    }
    if (!existing.source.includes(host.source)) {
      existing.source += `,${host.source}`;
    }
    existing.confidence = Math.max(existing.confidence, host.confidence);
  }
  return Array.from(hostMap.values());
}
function mergeSubdomains(allSubs) {
  const subMap = /* @__PURE__ */ new Map();
  for (const sub of allSubs) {
    const existing = subMap.get(sub.subdomain);
    if (!existing) {
      subMap.set(sub.subdomain, { ...sub });
      continue;
    }
    for (const ip of sub.ips) {
      if (!existing.ips.includes(ip)) existing.ips.push(ip);
    }
    if (!existing.source.includes(sub.source)) {
      existing.source += `,${sub.source}`;
    }
  }
  return Array.from(subMap.values());
}
function calculateRiskScore(hosts, nucleiFindings) {
  let score = 0;
  const allVulns = hosts.flatMap((h) => h.vulns);
  score += allVulns.length * 5;
  const highRiskPorts = [21, 22, 23, 25, 53, 110, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017];
  for (const host of hosts) {
    for (const port of host.ports) {
      if (highRiskPorts.includes(port.port)) score += 3;
    }
  }
  for (const finding of nucleiFindings) {
    switch (finding.severity) {
      case "critical":
        score += 25;
        break;
      case "high":
        score += 15;
        break;
      case "medium":
        score += 8;
        break;
      case "low":
        score += 3;
        break;
      default:
        score += 1;
    }
  }
  score = Math.min(100, Math.round(score));
  const band = score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : score >= 20 ? "low" : "minimal";
  return { score, band };
}
function buildSummary(hosts, subdomains, certs, nucleiFindings) {
  const allPorts = hosts.flatMap((h) => h.ports);
  const services = /* @__PURE__ */ new Set();
  const products = /* @__PURE__ */ new Set();
  const exposedPorts = /* @__PURE__ */ new Set();
  for (const port of allPorts) {
    if (port.service) services.add(port.service);
    if (port.product) products.add(port.product);
    exposedPorts.add(port.port);
  }
  const { score, band } = calculateRiskScore(hosts, nucleiFindings);
  return {
    totalHosts: hosts.length,
    totalPorts: allPorts.length,
    totalSubdomains: subdomains.length,
    totalVulnerabilities: hosts.reduce((sum, h) => sum + h.vulns.length, 0) + nucleiFindings.length,
    totalCertificates: certs.length,
    criticalFindings: nucleiFindings.filter((f) => f.severity === "critical").length,
    highFindings: nucleiFindings.filter((f) => f.severity === "high").length,
    mediumFindings: nucleiFindings.filter((f) => f.severity === "medium").length,
    lowFindings: nucleiFindings.filter((f) => f.severity === "low").length,
    infoFindings: nucleiFindings.filter((f) => f.severity === "info").length,
    uniqueServices: Array.from(services),
    uniqueProducts: Array.from(products),
    exposedPorts: Array.from(exposedPorts).sort((a, b) => a - b),
    riskScore: score,
    riskBand: band
  };
}
async function enrichFromBugBounty(hosts, domain) {
  try {
    const { enrichDomainIntel } = await import("./bug-bounty-intelligence-THPSB567.js");
    const bbData = await enrichDomainIntel(domain);
    const correlations = [];
    if (bbData.hasBugBountyProgram) {
      correlations.push({
        sourceModule: "bug_bounty",
        targetModule: "discovery_engine",
        correlationType: "extends",
        description: `Active bug bounty program found: ${bbData.programName}. ${bbData.disclosedVulnerabilities.total} disclosed vulnerabilities.`,
        confidence: 90,
        relatedEntities: [domain]
      });
    }
    if (bbData.topCWEs.length > 0) {
      correlations.push({
        sourceModule: "bug_bounty",
        targetModule: "discovery_engine",
        correlationType: "extends",
        description: `Top CWEs from bounty reports: ${bbData.topCWEs.slice(0, 5).map((c) => c.cwe).join(", ")}`,
        confidence: 80,
        relatedEntities: bbData.topCWEs.map((c) => c.cwe)
      });
    }
    return {
      module: "bug_bounty",
      status: "success",
      findingsCount: bbData.disclosedVulnerabilities.total,
      data: bbData,
      correlations
    };
  } catch (err) {
    return { module: "bug_bounty", status: "failed", findingsCount: 0, data: { error: err.message }, correlations: [] };
  }
}
async function enrichFromThreatIntel(hosts) {
  try {
    const { enrichThreatIntelligence } = await import("./bug-bounty-intelligence-THPSB567.js");
    const threatData = await enrichThreatIntelligence(30);
    const correlations = [];
    const discoveredServices = new Set(hosts.flatMap((h) => h.ports.map((p) => p.product).filter(Boolean)));
    for (const trend of threatData.trendingWeaknesses || []) {
      if (trend.trend === "rising") {
        correlations.push({
          sourceModule: "threat_enrichment",
          targetModule: "discovery_engine",
          correlationType: "extends",
          description: `Rising weakness trend: ${trend.cwe} (${trend.recentCount} recent reports)`,
          confidence: 70,
          relatedEntities: [trend.cwe]
        });
      }
    }
    return {
      module: "threat_enrichment",
      status: "success",
      findingsCount: threatData.exploitPatterns?.length || 0,
      data: threatData,
      correlations
    };
  } catch (err) {
    return { module: "threat_enrichment", status: "failed", findingsCount: 0, data: { error: err.message }, correlations: [] };
  }
}
async function enrichFromOpSec(hosts) {
  try {
    const { enrichOpSec } = await import("./bug-bounty-intelligence-THPSB567.js");
    const opsecData = await enrichOpSec();
    const correlations = [];
    const exposedHighRisk = hosts.filter((h) => h.ports.some((p) => [22, 3389, 445, 5900].includes(p.port)));
    if (exposedHighRisk.length > 0) {
      correlations.push({
        sourceModule: "discovery_engine",
        targetModule: "opsec",
        correlationType: "new_finding",
        description: `${exposedHighRisk.length} hosts expose high-risk remote access ports (SSH, RDP, SMB, VNC)`,
        confidence: 95,
        relatedEntities: exposedHighRisk.map((h) => h.ip)
      });
    }
    return {
      module: "opsec",
      status: "success",
      findingsCount: opsecData.weaknessCategories?.length || 0,
      data: opsecData,
      correlations
    };
  } catch (err) {
    return { module: "opsec", status: "failed", findingsCount: 0, data: { error: err.message }, correlations: [] };
  }
}
async function analyzeScanWithLLM(result) {
  try {
    const { invokeLLM } = await import("./llm-IHYY5FA6.js");
    const prompt = `You are a senior red team operator analyzing reconnaissance results. Analyze the following discovery scan data and provide a structured security assessment.

Target: ${result.targets.map((t) => t.domain || t.ip || t.cidr).join(", ")}
Hosts Discovered: ${result.summary.totalHosts}
Open Ports: ${result.summary.totalPorts}
Subdomains: ${result.summary.totalSubdomains}
Vulnerabilities: ${result.summary.totalVulnerabilities}
Risk Score: ${result.summary.riskScore}/100 (${result.summary.riskBand})

Services Found: ${result.summary.uniqueServices.join(", ")}
Products Found: ${result.summary.uniqueProducts.join(", ")}
Exposed Ports: ${result.summary.exposedPorts.join(", ")}

Top Hosts (by port count):
${result.hosts.slice(0, 10).map((h) => `- ${h.ip} (${h.hostnames.join(", ")}): ${h.ports.length} ports, ${h.vulns.length} vulns, OS: ${h.os || "unknown"}`).join("\n")}

Critical/High Findings:
${result.nucleiFindings.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 10).map((f) => `- [${f.severity.toUpperCase()}] ${f.name}: ${f.description}`).join("\n") || "None from Nuclei templates"}

Cross-Module Correlations:
${result.enrichmentResults.flatMap((e) => e.correlations).slice(0, 10).map((c) => `- [${c.correlationType}] ${c.description}`).join("\n") || "None"}

Provide your analysis as JSON with these fields: executiveSummary, keyFindings (array), riskAssessment, attackSurfaceAnalysis, recommendations (array), threatActorRelevance (array), nextSteps (array).`;
    const response = await invokeLLM({
      _caller: "discovery-engine.analyzeScanWithLLM",
      messages: [
        { role: "system", content: "You are a senior penetration tester and red team operator. Provide actionable security analysis. Return valid JSON only." },
        { role: "user", content: prompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "discovery_analysis",
          strict: true,
          schema: {
            type: "object",
            properties: {
              executiveSummary: { type: "string" },
              keyFindings: { type: "array", items: { type: "string" } },
              riskAssessment: { type: "string" },
              attackSurfaceAnalysis: { type: "string" },
              recommendations: { type: "array", items: { type: "string" } },
              threatActorRelevance: { type: "array", items: { type: "string" } },
              nextSteps: { type: "array", items: { type: "string" } }
            },
            required: ["executiveSummary", "keyFindings", "riskAssessment", "attackSurfaceAnalysis", "recommendations", "threatActorRelevance", "nextSteps"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices[0].message.content;
    return JSON.parse(typeof content === "string" ? content : "{}");
  } catch (err) {
    console.error("[DiscoveryEngine] LLM analysis failed:", err.message);
    return {
      executiveSummary: "LLM analysis unavailable \u2014 review raw findings manually.",
      keyFindings: [],
      riskAssessment: "Unable to generate automated risk assessment.",
      attackSurfaceAnalysis: "Manual review required.",
      recommendations: ["Review discovered hosts and ports manually", "Cross-reference with known vulnerability databases"],
      threatActorRelevance: [],
      nextSteps: ["Run deeper scans on high-value targets", "Validate critical findings"]
    };
  }
}
async function runDiscoveryPipeline(targets, config, onProgress) {
  const fullConfig = { ...defaultConfig(targets), ...config };
  const discoveryId = generateDiscoveryId();
  const startedAt = (/* @__PURE__ */ new Date()).toISOString();
  const sourceStats = [];
  let allHosts = [];
  let allSubdomains = [];
  let allDnsRecords = [];
  let allCerts = [];
  const nucleiFindings = [];
  onProgress?.("initializing", `Discovery scan ${discoveryId} starting for ${targets.length} target(s)`);
  let domains = targets.filter((t) => t.domain).map((t) => t.domain);
  const ips = targets.filter((t) => t.ip).map((t) => t.ip);
  let orgDiscoveryResult = null;
  if (domains.length > 0) {
    onProgress?.("org_discovery", "Discovering all domains owned by the target organization");
    try {
      const seedDomain = domains[0];
      let orgName = "";
      let orgEmail = null;
      if (fullConfig.enabledSources.securityTrails) {
        try {
          const whoisData = await securityTrailsWHOIS(seedDomain);
          orgName = whoisData?.registrant?.organization || whoisData?.registrant?.name || whoisData?.contacts?.registrant?.organization || whoisData?.contacts?.registrant?.name || "";
          orgEmail = whoisData?.registrant?.email || whoisData?.contacts?.registrant?.email || null;
          onProgress?.("org_discovery", `Identified org: "${orgName}" (${orgEmail || "no email"}) from WHOIS`);
        } catch (err) {
          onProgress?.("org_discovery", `WHOIS org extraction failed: ${err.message}`);
        }
      }
      if (orgName) {
        orgDiscoveryResult = await discoverOrgDomains(
          seedDomain,
          orgName,
          orgEmail,
          {
            minConfidenceThreshold: 60,
            maxCandidates: 150,
            enableWebVerification: false,
            enableSpfPivoting: true,
            lookupTimeoutMs: 15e3
          },
          (detail) => onProgress?.("org_discovery", detail)
        );
        const newDomains = orgDiscoveryResult.verifiedDomains.filter((d) => !domains.includes(d.domain)).map((d) => d.domain);
        if (newDomains.length > 0) {
          domains = [...domains, ...newDomains];
          onProgress?.("org_discovery", `Added ${newDomains.length} verified org domains to scan scope: ${newDomains.join(", ")}`);
        }
        sourceStats.push({
          source: "org_discovery",
          hostsFound: 0,
          portsFound: 0,
          subdomainsFound: 0,
          vulnsFound: 0,
          responseTimeMs: orgDiscoveryResult.durationMs,
          status: orgDiscoveryResult.verifiedDomains.length > 0 ? "success" : "partial",
          error: null
        });
      } else {
        onProgress?.("org_discovery", "Skipped: could not determine org name from WHOIS");
        sourceStats.push({
          source: "org_discovery",
          hostsFound: 0,
          portsFound: 0,
          subdomainsFound: 0,
          vulnsFound: 0,
          responseTimeMs: 0,
          status: "skipped",
          error: "No org name available from WHOIS"
        });
      }
    } catch (err) {
      onProgress?.("org_discovery", `Org discovery failed (non-fatal): ${err.message}`);
      sourceStats.push({
        source: "org_discovery",
        hostsFound: 0,
        portsFound: 0,
        subdomainsFound: 0,
        vulnsFound: 0,
        responseTimeMs: 0,
        status: "failed",
        error: err.message
      });
    }
  }
  onProgress?.("subdomain_enum", "Enumerating subdomains from multiple sources");
  for (const domain of domains) {
    if (fullConfig.enabledSources.crtsh) {
      const start = Date.now();
      try {
        const subs = await crtshSubdomains(domain);
        allSubdomains.push(...subs);
        sourceStats.push({ source: "crtsh", hostsFound: 0, portsFound: 0, subdomainsFound: subs.length, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "success", error: null });
      } catch (err) {
        sourceStats.push({ source: "crtsh", hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "failed", error: err.message });
      }
    }
    if (fullConfig.enabledSources.securityTrails) {
      const start = Date.now();
      try {
        const subs = await securityTrailsSubdomains(domain);
        allSubdomains.push(...subs);
        const dnsHistory = await securityTrailsDNSHistory(domain);
        allDnsRecords.push(...dnsHistory);
        sourceStats.push({ source: "securitytrails", hostsFound: 0, portsFound: 0, subdomainsFound: subs.length, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "success", error: null });
      } catch (err) {
        sourceStats.push({ source: "securitytrails", hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "failed", error: err.message });
      }
    }
    if (fullConfig.enabledSources.shodan) {
      const start = Date.now();
      try {
        const subs = await shodanDNSLookup(domain);
        allSubdomains.push(...subs);
        sourceStats.push({ source: "shodan_dns", hostsFound: 0, portsFound: 0, subdomainsFound: subs.length, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "success", error: null });
      } catch (err) {
        sourceStats.push({ source: "shodan_dns", hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "failed", error: err.message });
      }
    }
  }
  allSubdomains = mergeSubdomains(allSubdomains);
  onProgress?.("subdomain_enum", `Found ${allSubdomains.length} unique subdomains`);
  onProgress?.("host_discovery", "Discovering hosts and scanning ports");
  for (const domain of domains) {
    if (fullConfig.enabledSources.shodan) {
      const start = Date.now();
      try {
        const hosts = await shodanDomainSearch(domain);
        allHosts.push(...hosts);
        const totalPorts = hosts.reduce((s, h) => s + h.ports.length, 0);
        const totalVulns = hosts.reduce((s, h) => s + h.vulns.length, 0);
        sourceStats.push({ source: "shodan", hostsFound: hosts.length, portsFound: totalPorts, subdomainsFound: 0, vulnsFound: totalVulns, responseTimeMs: Date.now() - start, status: "success", error: null });
      } catch (err) {
        sourceStats.push({ source: "shodan", hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "failed", error: err.message });
      }
    }
    if (fullConfig.enabledSources.censys) {
      const start = Date.now();
      try {
        const hosts = await censysHostSearch(domain);
        allHosts.push(...hosts);
        const certs = await censysCertSearch(domain);
        allCerts.push(...certs);
        sourceStats.push({ source: "censys", hostsFound: hosts.length, portsFound: hosts.reduce((s, h) => s + h.ports.length, 0), subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "success", error: null });
      } catch (err) {
        sourceStats.push({ source: "censys", hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "failed", error: err.message });
      }
    }
  }
  for (const ip of ips) {
    if (fullConfig.enabledSources.shodan) {
      const start = Date.now();
      try {
        const host = await shodanHostLookup(ip);
        if (host) allHosts.push(host);
        sourceStats.push({ source: "shodan_ip", hostsFound: host ? 1 : 0, portsFound: host?.ports.length || 0, subdomainsFound: 0, vulnsFound: host?.vulns.length || 0, responseTimeMs: Date.now() - start, status: "success", error: null });
      } catch (err) {
        sourceStats.push({ source: "shodan_ip", hostsFound: 0, portsFound: 0, subdomainsFound: 0, vulnsFound: 0, responseTimeMs: Date.now() - start, status: "failed", error: err.message });
      }
    }
  }
  allHosts = mergeHosts(allHosts);
  onProgress?.("host_discovery", `Found ${allHosts.length} unique hosts with ${allHosts.reduce((s, h) => s + h.ports.length, 0)} ports`);
  onProgress?.("enrichment", "Running cross-module enrichment");
  const enrichmentResults = [];
  if (fullConfig.enrichmentModules.includes("bug_bounty") && domains.length > 0) {
    const bbResult = await enrichFromBugBounty(allHosts, domains[0]);
    enrichmentResults.push(bbResult);
  }
  if (fullConfig.enrichmentModules.includes("threat_enrichment")) {
    const threatResult = await enrichFromThreatIntel(allHosts);
    enrichmentResults.push(threatResult);
  }
  if (fullConfig.enrichmentModules.includes("opsec")) {
    const opsecResult = await enrichFromOpSec(allHosts);
    enrichmentResults.push(opsecResult);
  }
  onProgress?.("enrichment", `Completed ${enrichmentResults.filter((e) => e.status === "success").length}/${enrichmentResults.length} enrichment modules`);
  const summary = buildSummary(allHosts, allSubdomains, allCerts, nucleiFindings);
  const result = {
    id: discoveryId,
    startedAt,
    completedAt: (/* @__PURE__ */ new Date()).toISOString(),
    status: "completed",
    targets,
    config: fullConfig,
    hosts: allHosts,
    subdomains: allSubdomains,
    dnsRecords: allDnsRecords,
    certificates: allCerts,
    nucleiFindings,
    sourceStats,
    summary,
    enrichmentResults,
    llmAnalysis: null,
    orgDiscovery: orgDiscoveryResult
  };
  if (allHosts.length > 0 || allSubdomains.length > 0) {
    onProgress?.("llm_analysis", "Running LLM-powered analysis");
    result.llmAnalysis = await analyzeScanWithLLM(result);
  }
  try {
    onProgress?.("carver_scoring", "Generating CARVER risk cards for discovered assets");
    const { buildExplainableRiskCard } = await import("./auto-industry-carver-YAORFIXM.js");
    const { createCarverRiskCardsBatch } = await import("./db-FQGKASI3.js");
    const riskCardRecords = [];
    const batchId = `discovery-${discoveryId}`;
    for (const domain of domains) {
      try {
        const domainSubs = allSubdomains.filter((s) => s.subdomain.endsWith(domain));
        const assetSignals = [];
        for (const sub of domainSubs) {
          if (sub.subdomain.includes("mail") || sub.subdomain.includes("mx")) assetSignals.push("MX Record");
          if (sub.subdomain.includes("sso") || sub.subdomain.includes("auth") || sub.subdomain.includes("login")) assetSignals.push("SSO");
          if (sub.subdomain.includes("vpn")) assetSignals.push("VPN Gateway");
          if (sub.subdomain.includes("api")) assetSignals.push("API Gateway");
          if (sub.subdomain.includes("db") || sub.subdomain.includes("sql")) assetSignals.push("Database");
          if (sub.subdomain.includes("git") || sub.subdomain.includes("ci") || sub.subdomain.includes("jenkins")) assetSignals.push("CI/CD");
        }
        const domainHosts = allHosts.filter((h) => h.hostnames?.some((hn) => hn.endsWith(domain)));
        const keywords = [];
        for (const host of domainHosts) {
          for (const port of host.ports || []) {
            if (port.service) keywords.push(port.service);
            if (port.product) keywords.push(port.product);
          }
        }
        const riskCard = buildExplainableRiskCard({
          assetId: domain,
          assetLabel: `${domain} (Discovery Scan)`,
          domain,
          keywords: [...new Set(keywords)],
          assetSignals: [...new Set(assetSignals)]
        });
        riskCardRecords.push({
          domain,
          scanTitle: `${domain} \u2014 Discovery Scan`,
          inferredSector: riskCard.sector,
          sectorConfidence: riskCard.confidence >= 0.78 ? "high" : riskCard.confidence >= 0.55 ? "medium" : riskCard.confidence >= 0.35 ? "low" : "insufficient",
          naicsCode: riskCard.naics || null,
          naicsLabel: null,
          industry: null,
          regulatoryTags: riskCard.regulatoryProfile || [],
          country: "US",
          carverScores: { criticality: riskCard.scores?.carverShock || 0 },
          shockScores: null,
          hybridScore: riskCard.scores?.hybrid || 0,
          priorityTier: riskCard.scores?.priorityTier || "P3",
          confidenceBand: riskCard.confidence >= 0.78 ? "high" : riskCard.confidence >= 0.55 ? "medium" : "low",
          topDrivers: riskCard.topDrivers || [],
          recommendedActions: riskCard.recommendedActions || [],
          calderaOps: riskCard.calderaPriority || null,
          threatLikelihood: riskCard.threatLikelihood || null,
          fullRiskCard: riskCard,
          source: "discovery_engine",
          batchId
        });
      } catch (_) {
      }
    }
    if (riskCardRecords.length > 0) {
      await createCarverRiskCardsBatch(riskCardRecords);
      onProgress?.("carver_scoring", `Generated ${riskCardRecords.length} CARVER risk cards`);
    }
  } catch (carverErr) {
    onProgress?.("carver_scoring", `CARVER scoring skipped: ${carverErr.message}`);
  }
  onProgress?.("completed", `Discovery scan complete: ${summary.totalHosts} hosts, ${summary.totalSubdomains} subdomains, risk=${summary.riskScore}`);
  return result;
}
function getAvailableSources() {
  return [
    { source: "shodan", available: !!ENV.SHODAN_API_KEY, reason: ENV.SHODAN_API_KEY ? "API key configured" : "SHODAN_API_KEY not set" },
    { source: "censys", available: !!(ENV.CENSYS_API_ID && ENV.CENSYS_API_SECRET), reason: ENV.CENSYS_API_ID && ENV.CENSYS_API_SECRET ? "API credentials configured" : "CENSYS_API_ID/SECRET not set" },
    { source: "securityTrails", available: !!ENV.SECURITYTRAILS_API_KEY, reason: ENV.SECURITYTRAILS_API_KEY ? "API key configured" : "SECURITYTRAILS_API_KEY not set" },
    { source: "crtsh", available: true, reason: "Free service, no API key required" },
    { source: "wayback", available: true, reason: "Free service, no API key required" },
    { source: "dnsEnum", available: true, reason: "Built-in DNS enumeration" },
    { source: "whois", available: true, reason: "Built-in WHOIS lookup" },
    { source: "nuclei", available: false, reason: "Requires CLI bridge (not yet configured)" }
  ];
}
var init_discovery_engine = __esm({
  "server/lib/discovery-engine.ts"() {
    init_env();
    init_org_domain_discovery();
  }
});
init_discovery_engine();
export {
  analyzeScanWithLLM,
  censysCertSearch,
  censysHostSearch,
  getAvailableSources,
  runDiscoveryPipeline,
  securityTrailsDNSHistory,
  securityTrailsDomainInfo,
  securityTrailsSubdomains,
  securityTrailsWHOIS,
  shodanDNSLookup,
  shodanDomainSearch,
  shodanHostLookup
};
