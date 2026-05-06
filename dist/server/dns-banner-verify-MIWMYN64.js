import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/dns-banner-verify.ts
import dns from "dns/promises";
function extractTechnologiesFromHeaders(headers) {
  const results = [];
  const seen = /* @__PURE__ */ new Set();
  const headerString = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n");
  const serverHeader = headers["server"] || headers["Server"] || "";
  const poweredBy = headers["x-powered-by"] || headers["X-Powered-By"] || "";
  const generator = headers["x-generator"] || headers["X-Generator"] || "";
  const setCookie = headers["set-cookie"] || headers["Set-Cookie"] || "";
  const allHeaderText = [headerString, serverHeader, poweredBy, generator, setCookie].join("\n");
  for (const tech of TECH_PATTERNS) {
    if (seen.has(tech.name)) continue;
    for (const pattern of tech.patterns) {
      const match = allHeaderText.match(pattern);
      if (match) {
        seen.add(tech.name);
        const version = match[1] || void 0;
        const source = serverHeader && pattern.test(serverHeader) ? "Server header" : poweredBy && pattern.test(poweredBy) ? "X-Powered-By header" : setCookie && pattern.test(setCookie) ? "Set-Cookie header" : "HTTP response headers";
        results.push({ name: tech.name, version, source });
        break;
      }
    }
  }
  return results;
}
async function verifyDns(hostname, timeoutMs = 5e3) {
  const result = { hostname, resolved: false };
  try {
    const resolver = new dns.Resolver();
    resolver.setServers(["8.8.8.8", "1.1.1.1"]);
    const withTimeout = (promise, fallback) => Promise.race([
      promise,
      new Promise((resolve) => setTimeout(() => resolve(fallback), timeoutMs))
    ]);
    try {
      const aRecords = await withTimeout(resolver.resolve4(hostname), []);
      if (aRecords.length > 0) {
        result.resolved = true;
        result.aRecords = aRecords;
      }
    } catch {
    }
    try {
      const aaaaRecords = await withTimeout(resolver.resolve6(hostname), []);
      if (aaaaRecords.length > 0) {
        result.resolved = true;
        result.aaaaRecords = aaaaRecords;
      }
    } catch {
    }
    try {
      const cnameRecords = await withTimeout(resolver.resolveCname(hostname), []);
      if (cnameRecords.length > 0) {
        result.resolved = true;
        result.cnameRecords = cnameRecords;
      }
    } catch {
    }
    try {
      const mxRecords = await withTimeout(resolver.resolveMx(hostname), []);
      if (mxRecords.length > 0) {
        result.resolved = true;
        result.mxRecords = mxRecords;
      }
    } catch {
    }
    try {
      const txtRecords = await withTimeout(resolver.resolveTxt(hostname), []);
      if (txtRecords.length > 0) {
        result.txtRecords = txtRecords.map((r) => r.join(""));
      }
    } catch {
    }
    try {
      const nsRecords = await withTimeout(resolver.resolveNs(hostname), []);
      if (nsRecords.length > 0) {
        result.nsRecords = nsRecords;
      }
    } catch {
    }
  } catch (err) {
    result.error = err.message || "DNS resolution failed";
  }
  return result;
}
async function verifyBanner(hostname, timeoutMs = 8e3) {
  const result = {
    hostname,
    reachable: false,
    detectedTechnologies: []
  };
  const urls = [
    `https://${hostname}`,
    `http://${hostname}`
  ];
  for (const url of urls) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const response = await fetch(url, {
        method: "HEAD",
        signal: controller.signal,
        redirect: "follow",
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; AC3-Scanner/1.0; +https://aceofcloud.com)"
        }
      });
      clearTimeout(timer);
      result.reachable = true;
      result.statusCode = response.status;
      const headers = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      result.allHeaders = headers;
      result.serverHeader = headers["server"] || void 0;
      result.poweredByHeader = headers["x-powered-by"] || void 0;
      result.xGeneratorHeader = headers["x-generator"] || void 0;
      result.contentTypeHeader = headers["content-type"] || void 0;
      result.detectedTechnologies = extractTechnologiesFromHeaders(headers);
      if (response.status === 405) {
        try {
          const getController = new AbortController();
          const getTimer = setTimeout(() => getController.abort(), timeoutMs);
          const getResponse = await fetch(url, {
            method: "GET",
            signal: getController.signal,
            redirect: "follow",
            headers: {
              "User-Agent": "Mozilla/5.0 (compatible; AC3-Scanner/1.0; +https://aceofcloud.com)"
            }
          });
          clearTimeout(getTimer);
          const getHeaders = {};
          getResponse.headers.forEach((value, key) => {
            getHeaders[key.toLowerCase()] = value;
          });
          const additionalTechs = extractTechnologiesFromHeaders(getHeaders);
          for (const tech of additionalTechs) {
            if (!result.detectedTechnologies.some((t) => t.name === tech.name)) {
              result.detectedTechnologies.push(tech);
            }
          }
          await getResponse.text().catch(() => {
          });
        } catch {
        }
      }
      break;
    } catch (err) {
      result.error = err.message || "HTTP request failed";
    }
  }
  return result;
}
async function verifyAsset(asset) {
  const hostname = asset.hostname;
  const dnsResult = await verifyDns(hostname);
  let bannerResult;
  if (dnsResult.resolved) {
    bannerResult = await verifyBanner(hostname);
  }
  const enrichedAsset = { ...asset };
  if (dnsResult.resolved) {
    enrichedAsset.discoveryMethod = bannerResult?.reachable ? "header_detected" : "dns_verified";
    enrichedAsset.dnsRecords = {
      ...enrichedAsset.dnsRecords || {},
      A: dnsResult.aRecords || [],
      AAAA: dnsResult.aaaaRecords || [],
      CNAME: dnsResult.cnameRecords || [],
      MX: dnsResult.mxRecords?.map((r) => `${r.priority} ${r.exchange}`) || [],
      TXT: dnsResult.txtRecords || [],
      NS: dnsResult.nsRecords || []
    };
    enrichedAsset.dnsStatus = "verified";
    const evidenceParts = [];
    if (dnsResult.aRecords?.length) evidenceParts.push(`A records: ${dnsResult.aRecords.join(", ")}`);
    if (dnsResult.cnameRecords?.length) evidenceParts.push(`CNAME: ${dnsResult.cnameRecords.join(", ")}`);
    if (dnsResult.mxRecords?.length) evidenceParts.push(`MX: ${dnsResult.mxRecords.map((r) => r.exchange).join(", ")}`);
    enrichedAsset.discoveryEvidence = `DNS verified: ${evidenceParts.join("; ") || "resolved successfully"}`;
    if (bannerResult?.reachable && bannerResult.detectedTechnologies.length > 0) {
      const existingTechs = new Set((enrichedAsset.technologies || []).map((t) => t.toLowerCase()));
      const existingVersions = { ...enrichedAsset.technologyVersions || {} };
      for (const tech of bannerResult.detectedTechnologies) {
        if (!existingTechs.has(tech.name.toLowerCase())) {
          enrichedAsset.technologies = [...enrichedAsset.technologies || [], tech.name];
          existingTechs.add(tech.name.toLowerCase());
        }
        if (tech.version) {
          const existingKey = Object.keys(existingVersions).find(
            (k) => k.toLowerCase() === tech.name.toLowerCase()
          );
          if (existingKey) {
            existingVersions[existingKey] = tech.version;
          } else {
            existingVersions[tech.name] = tech.version;
          }
        }
      }
      enrichedAsset.technologyVersions = existingVersions;
      enrichedAsset.headers = bannerResult.serverHeader || enrichedAsset.headers;
      const techDetails = bannerResult.detectedTechnologies.map((t) => t.version ? `${t.name}/${t.version} (${t.source})` : `${t.name} (${t.source})`).join(", ");
      enrichedAsset.discoveryEvidence = `DNS verified + HTTP banner: ${techDetails}. ${enrichedAsset.discoveryEvidence}`;
      enrichedAsset.discoveryMethod = "header_detected";
    }
  } else {
    enrichedAsset.dnsStatus = "unresolved";
    enrichedAsset.discoveryEvidence = `DNS unresolved: ${hostname} did not resolve. ${enrichedAsset.discoveryEvidence || "Inferred from OSINT patterns."}`;
  }
  return {
    asset: enrichedAsset,
    verification: { dns: dnsResult, banner: bannerResult }
  };
}
async function verifyAllAssets(assets, concurrency = 5, onProgress) {
  const results = [];
  let dnsVerified = 0;
  let bannerDetected = 0;
  let unresolved = 0;
  let technologiesFound = 0;
  let versionsFound = 0;
  for (let i = 0; i < assets.length; i += concurrency) {
    const batch = assets.slice(i, i + concurrency);
    const batchResults = await Promise.allSettled(
      batch.map((asset) => verifyAsset(asset))
    );
    for (const result of batchResults) {
      if (result.status === "fulfilled") {
        const { asset } = result.value;
        results.push(asset);
        if (asset.discoveryMethod === "header_detected") {
          bannerDetected++;
        } else if (asset.discoveryMethod === "dns_verified") {
          dnsVerified++;
        } else {
          unresolved++;
        }
        const versions = asset.technologyVersions || {};
        const versionCount = Object.values(versions).filter((v) => v && v !== "null").length;
        technologiesFound += (asset.technologies || []).length;
        versionsFound += versionCount;
      } else {
        const originalAsset = batch[batchResults.indexOf(result)];
        if (originalAsset) {
          results.push(originalAsset);
          unresolved++;
        }
      }
    }
    onProgress?.(Math.min(i + concurrency, assets.length), assets.length);
  }
  return {
    assets: results,
    summary: {
      total: assets.length,
      dnsVerified,
      bannerDetected,
      unresolved,
      technologiesFound,
      versionsFound
    }
  };
}
var TECH_PATTERNS;
var init_dns_banner_verify = __esm({
  "server/lib/dns-banner-verify.ts"() {
    TECH_PATTERNS = [
      { name: "nginx", patterns: [/nginx\/([\d.]+)/i, /nginx/i] },
      { name: "Apache", patterns: [/Apache\/([\d.]+)/i, /Apache/i] },
      { name: "IIS", patterns: [/Microsoft-IIS\/([\d.]+)/i, /IIS/i] },
      { name: "OpenSSL", patterns: [/OpenSSL\/([\d.]+[a-z]?)/i] },
      { name: "PHP", patterns: [/PHP\/([\d.]+)/i] },
      { name: "Express", patterns: [/Express/i] },
      { name: "ASP.NET", patterns: [/ASP\.NET/i, /X-AspNet-Version:\s*([\d.]+)/i] },
      { name: "Cloudflare", patterns: [/cloudflare/i] },
      { name: "Amazon S3", patterns: [/AmazonS3/i] },
      { name: "Varnish", patterns: [/Varnish/i, /varnish\/([\d.]+)/i] },
      { name: "LiteSpeed", patterns: [/LiteSpeed/i, /LiteSpeed\/([\d.]+)/i] },
      { name: "Tomcat", patterns: [/Apache-Coyote\/([\d.]+)/i, /Tomcat/i] },
      { name: "Caddy", patterns: [/Caddy/i] },
      { name: "gunicorn", patterns: [/gunicorn\/([\d.]+)/i, /gunicorn/i] },
      { name: "Envoy", patterns: [/envoy/i] },
      { name: "HAProxy", patterns: [/HAProxy/i] },
      { name: "WordPress", patterns: [/WordPress\/([\d.]+)/i, /wp-/i] },
      { name: "Drupal", patterns: [/Drupal/i, /X-Drupal-Cache/i] },
      { name: "Django", patterns: [/WSGIServer/i, /django/i] },
      { name: "Rails", patterns: [/Phusion Passenger/i, /X-Powered-By:\s*Phusion/i] },
      { name: "Next.js", patterns: [/Next\.js/i, /x-nextjs/i] },
      { name: "Vercel", patterns: [/Vercel/i] },
      { name: "Netlify", patterns: [/Netlify/i] },
      { name: "Microsoft Exchange", patterns: [/Microsoft-HTTPAPI\/([\d.]+)/i, /X-OWA-Version:\s*([\d.]+)/i, /X-FEServer/i] },
      { name: "Citrix", patterns: [/Citrix/i, /NetScaler/i] },
      { name: "F5 BIG-IP", patterns: [/BIG-IP/i, /BigIP/i, /Set-Cookie:.*BIGipServer/i, /Server:.*\bF5\b/i] },
      { name: "Palo Alto", patterns: [/PanOS/i, /Palo Alto/i] },
      { name: "Fortinet", patterns: [/FortiGate/i, /Fortinet/i, /FortiOS/i] },
      { name: "SonicWall", patterns: [/SonicWALL/i, /SonicOS/i] }
    ];
  }
});
init_dns_banner_verify();
export {
  extractTechnologiesFromHeaders,
  verifyAllAssets,
  verifyAsset,
  verifyBanner,
  verifyDns
};
