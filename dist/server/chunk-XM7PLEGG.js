import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/shodan-verifier.ts
function isProtocolVersion(product, version) {
  if (!version) return false;
  const ver = version.trim();
  const prod = product.toLowerCase().trim();
  if (PROTOCOL_VERSION_PATTERNS.has(ver)) {
    if (HTTP_PRODUCT_INDICATORS.some((kw) => prod.includes(kw))) return true;
    if (!prod || prod === "unknown" || prod === "n/a") return true;
  }
  if (/^\d+(\.\d+)?$/.test(ver) && parseFloat(ver) <= 3) {
    if (HTTP_PRODUCT_INDICATORS.some((kw) => prod.includes(kw))) return true;
  }
  return false;
}
function matchShodanProductToTech(shodanProduct) {
  const lower = shodanProduct.toLowerCase().trim();
  if (!lower) return null;
  for (const [canonical, aliases] of Object.entries(PRODUCT_ALIASES)) {
    for (const alias of aliases) {
      if (lower === alias || lower.includes(alias) || alias.includes(lower)) {
        return canonical;
      }
    }
  }
  if (lower.length >= 3 && !["unknown", "n/a", "none"].includes(lower)) {
    return shodanProduct;
  }
  return null;
}
function techMatchesShodanProduct(assetTech, shodanProduct) {
  const techLower = assetTech.toLowerCase().trim();
  const prodLower = shodanProduct.toLowerCase().trim();
  if (techLower === prodLower) return true;
  if (techLower.includes(prodLower) || prodLower.includes(techLower)) return true;
  for (const [canonical, aliases] of Object.entries(PRODUCT_ALIASES)) {
    const techIsAlias = aliases.some((a) => techLower.includes(a) || a.includes(techLower)) || techLower.includes(canonical);
    const prodIsAlias = aliases.some((a) => prodLower.includes(a) || a.includes(prodLower)) || prodLower.includes(canonical);
    if (techIsAlias && prodIsAlias) return true;
  }
  return false;
}
function extractShodanVersionEvidence(observations) {
  const evidence = [];
  const seen = /* @__PURE__ */ new Set();
  for (const obs of observations) {
    if (obs.source !== "shodan") continue;
    if (obs.assetType !== "ip") continue;
    const ev = obs.evidence || {};
    const ip = obs.ip || ev.ip || "";
    const port = ev.port || 0;
    const product = ev.product || "";
    const version = ev.version || "";
    const cpe = ev.cpe || [];
    const vulns = ev.vulns || ev.host_vulns || [];
    const banner = ev.banner_snippet || "";
    const hostname = obs.name || ev.hostnames?.[0] || "";
    const os = ev.os || "";
    const transport = ev.transport || "tcp";
    if (!product && !version && cpe.length === 0 && vulns.length === 0) continue;
    const cleanVersion = isProtocolVersion(product, version) ? "" : version;
    const key = `${ip}:${port}:${product}`;
    if (seen.has(key)) continue;
    seen.add(key);
    evidence.push({
      ip,
      port,
      product,
      version: cleanVersion,
      cpe,
      vulns,
      bannerSnippet: banner,
      hostname: hostname || void 0,
      os: os || void 0,
      transport: transport || void 0
    });
  }
  return evidence;
}
function enrichAssetsWithShodanData(assets, shodanObservations) {
  const versionEvidence = extractShodanVersionEvidence(shodanObservations);
  let assetsEnriched = 0;
  let versionsAdded = 0;
  let shodanConfirmedCves = 0;
  for (const asset of assets) {
    const hostname = asset.hostname.toLowerCase();
    const assetIPs = asset.dnsRecords?.A || [];
    const matchingEvidence = versionEvidence.filter((ev) => {
      if (ev.hostname && (ev.hostname.toLowerCase() === hostname || ev.hostname.toLowerCase().endsWith(`.${hostname}`) || hostname.endsWith(`.${ev.hostname.toLowerCase()}`))) return true;
      if (ev.ip && assetIPs.includes(ev.ip)) return true;
      return false;
    });
    if (matchingEvidence.length === 0) continue;
    let enriched = false;
    const existingVersions = { ...asset.technologyVersions || {} };
    const existingTechs = new Set((asset.technologies || []).map((t) => t.toLowerCase()));
    for (const ev of matchingEvidence) {
      if (ev.product && ev.version && !isProtocolVersion(ev.product, ev.version)) {
        const canonicalName = matchShodanProductToTech(ev.product);
        if (canonicalName) {
          const existingKey = Object.keys(existingVersions).find(
            (k) => k.toLowerCase() === canonicalName.toLowerCase() || techMatchesShodanProduct(k, ev.product)
          );
          if (existingKey) {
            if (!existingVersions[existingKey] || existingVersions[existingKey] === "null") {
              existingVersions[existingKey] = ev.version;
              versionsAdded++;
              enriched = true;
            }
          } else {
            existingVersions[canonicalName] = ev.version;
            if (!existingTechs.has(canonicalName.toLowerCase())) {
              asset.technologies = [...asset.technologies || [], canonicalName];
              existingTechs.add(canonicalName.toLowerCase());
            }
            versionsAdded++;
            enriched = true;
          }
        }
      }
      for (const cpeStr of ev.cpe) {
        const parts = cpeStr.split(":");
        if (parts.length >= 6) {
          const cpeProduct = parts[4] || "";
          const cpeVersion = parts[5] || "";
          if (cpeProduct && cpeVersion && cpeVersion !== "*" && cpeVersion !== "-") {
            const canonicalName = matchShodanProductToTech(cpeProduct);
            if (canonicalName) {
              const existingKey = Object.keys(existingVersions).find(
                (k) => k.toLowerCase() === canonicalName.toLowerCase() || techMatchesShodanProduct(k, cpeProduct)
              );
              if (!existingKey || !existingVersions[existingKey] || existingVersions[existingKey] === "null") {
                const key = existingKey || canonicalName;
                existingVersions[key] = cpeVersion;
                if (!existingTechs.has(canonicalName.toLowerCase())) {
                  asset.technologies = [...asset.technologies || [], canonicalName];
                  existingTechs.add(canonicalName.toLowerCase());
                }
                versionsAdded++;
                enriched = true;
              }
            }
          }
        }
      }
      shodanConfirmedCves += ev.vulns.length;
    }
    if (enriched) {
      asset.technologyVersions = existingVersions;
      const shodanProducts = matchingEvidence.filter((e) => e.product).map((e) => `${e.product}${e.version ? "/" + e.version : ""} (${e.ip}:${e.port})`).slice(0, 5).join(", ");
      asset.discoveryEvidence = `${asset.discoveryEvidence || ""} | Shodan banner enrichment: ${shodanProducts}`.trim();
      assetsEnriched++;
    }
  }
  const summary = `Shodan enrichment: ${assetsEnriched} assets enriched, ${versionsAdded} versions added, ${shodanConfirmedCves} Shodan-confirmed CVEs across ${versionEvidence.length} service banners`;
  return {
    assetsEnriched,
    versionsAdded,
    shodanConfirmedCves,
    versionEvidence,
    summary
  };
}
function verifyCvesWithShodanData(analyses, shodanObservations) {
  const versionEvidence = extractShodanVersionEvidence(shodanObservations);
  const verifications = [];
  let upgraded = 0;
  const cveShodanMap = /* @__PURE__ */ new Map();
  for (const ev of versionEvidence) {
    for (const cve of ev.vulns) {
      const existing = cveShodanMap.get(cve) || [];
      existing.push(ev);
      cveShodanMap.set(cve, existing);
    }
  }
  const ipShodanMap = /* @__PURE__ */ new Map();
  for (const ev of versionEvidence) {
    if (ev.ip) {
      const existing = ipShodanMap.get(ev.ip) || [];
      existing.push(ev);
      ipShodanMap.set(ev.ip, existing);
    }
  }
  for (const analysis of analyses) {
    const hostname = analysis.asset.hostname.toLowerCase();
    const assetIPs = analysis.asset.dnsRecords?.A || [];
    const assetShodanEvidence = [];
    for (const ev of versionEvidence) {
      if (ev.hostname && (ev.hostname.toLowerCase() === hostname || ev.hostname.toLowerCase().endsWith(`.${hostname}`) || hostname.endsWith(`.${ev.hostname.toLowerCase()}`))) {
        assetShodanEvidence.push(ev);
        continue;
      }
      if (ev.ip && assetIPs.includes(ev.ip)) {
        assetShodanEvidence.push(ev);
      }
    }
    for (const finding of analysis.postureFindings) {
      if (!finding.cveIds || finding.cveIds.length === 0) continue;
      for (const cveId of finding.cveIds) {
        const shodanCveEvidence = cveShodanMap.get(cveId);
        if (shodanCveEvidence) {
          const matchingCveEvidence = shodanCveEvidence.find((ev) => {
            if (ev.hostname && (ev.hostname.toLowerCase() === hostname || ev.hostname.toLowerCase().endsWith(`.${hostname}`) || hostname.endsWith(`.${ev.hostname.toLowerCase()}`))) return true;
            if (ev.ip && assetIPs.includes(ev.ip)) return true;
            return false;
          });
          if (matchingCveEvidence) {
            verifications.push({
              cveId,
              shodanConfirmed: true,
              detectedOn: `${matchingCveEvidence.ip}:${matchingCveEvidence.port}`,
              product: matchingCveEvidence.product,
              version: matchingCveEvidence.version,
              cpe: matchingCveEvidence.cpe
            });
            if (finding.corroborationTier !== "confirmed") {
              finding.corroborationTier = "confirmed";
              finding.versionMatchConfirmed = true;
              finding.detectedVersion = matchingCveEvidence.version || finding.detectedVersion;
              if (finding.severity < 7 && finding.cvssScore && finding.cvssScore >= 7) {
                finding.severity = Math.round(finding.cvssScore);
              }
              finding.confidence = Math.max(finding.confidence, 0.95);
              finding.evidenceChain = [
                ...finding.evidenceChain || [],
                `SHODAN VERIFICATION: ${cveId} independently detected by Shodan on ${matchingCveEvidence.ip}:${matchingCveEvidence.port} (${matchingCveEvidence.product}${matchingCveEvidence.version ? "/" + matchingCveEvidence.version : ""})`,
                `Corroboration upgraded from probable \u2192 CONFIRMED via Shodan banner analysis`
              ];
              finding.evidenceDetail = `CONFIRMED (Shodan-verified): ${finding.evidenceDetail || ""} Shodan independently detected ${cveId} on ${matchingCveEvidence.ip}:${matchingCveEvidence.port}.`;
              finding.evidenceBasis = "confirmed_cve";
              upgraded++;
            }
            continue;
          }
        }
        if (finding.corroborationTier === "probable" && !finding.versionMatchConfirmed) {
          for (const ev of assetShodanEvidence) {
            if (!ev.product || !ev.version) continue;
            const findingTitle = (finding.title || "").toLowerCase();
            const findingTech = finding.cveIds?.join(" ").toLowerCase() || "";
            if (techMatchesShodanProduct(findingTitle, ev.product) || finding.assetHostname && ev.hostname && ev.hostname.toLowerCase().includes(finding.assetHostname.toLowerCase())) {
              if (!finding.detectedVersion) {
                finding.detectedVersion = ev.version;
                finding.versionMatchConfirmed = true;
                finding.corroborationTier = "confirmed";
                if (finding.severity < 7 && finding.cvssScore && finding.cvssScore >= 7) {
                  finding.severity = Math.round(finding.cvssScore);
                }
                finding.confidence = Math.max(finding.confidence, 0.85);
                finding.evidenceChain = [
                  ...finding.evidenceChain || [],
                  `SHODAN VERSION EVIDENCE: ${ev.product}/${ev.version} detected on ${ev.ip}:${ev.port} via Shodan banner`,
                  `Version evidence allows corroboration upgrade from probable \u2192 CONFIRMED`
                ];
                finding.evidenceDetail = `CONFIRMED (Shodan version): ${finding.evidenceDetail || ""} Shodan detected ${ev.product}/${ev.version} on ${ev.ip}:${ev.port}.`;
                verifications.push({
                  cveId,
                  shodanConfirmed: true,
                  detectedOn: `${ev.ip}:${ev.port}`,
                  product: ev.product,
                  version: ev.version,
                  cpe: ev.cpe
                });
                upgraded++;
                break;
              }
            }
          }
        }
      }
    }
  }
  const summary = `Shodan CVE verification: ${upgraded} findings upgraded to confirmed, ${verifications.filter((v) => v.shodanConfirmed).length} CVEs verified across ${analyses.length} assets`;
  return { upgraded, verified: verifications, summary };
}
function createShodanPostureFindings(analyses, shodanObservations) {
  const versionEvidence = extractShodanVersionEvidence(shodanObservations);
  let findingsAdded = 0;
  for (const analysis of analyses) {
    const hostname = analysis.asset.hostname.toLowerCase();
    const assetIPs = analysis.asset.dnsRecords?.A || [];
    const matchingEvidence = versionEvidence.filter((ev) => {
      if (ev.hostname && (ev.hostname.toLowerCase() === hostname || ev.hostname.toLowerCase().endsWith(`.${hostname}`) || hostname.endsWith(`.${ev.hostname.toLowerCase()}`))) return true;
      if (ev.ip && assetIPs.includes(ev.ip)) return true;
      return false;
    });
    for (const ev of matchingEvidence) {
      if (ev.vulns.length === 0) continue;
      for (const cveId of ev.vulns) {
        if (analysis.postureFindings.some((f) => f.cveIds?.includes(cveId))) continue;
        const finding = {
          id: `shodan-${cveId}-${analysis.asset.assetId}`,
          assetRef: analysis.asset.assetId,
          assetHostname: analysis.asset.hostname,
          category: "Shodan Detected CVE",
          title: `${cveId}: Detected by Shodan on ${ev.product || "service"}${ev.version ? " " + ev.version : ""} (${ev.ip}:${ev.port})`,
          severity: 8,
          // High default — Shodan-detected CVEs are real
          likelihood: 8,
          confidence: 0.95,
          // Very high — Shodan's own detection
          recommendedControls: [
            `Investigate ${cveId} on ${ev.ip}:${ev.port}`,
            `Verify ${ev.product || "service"} version and apply patches`,
            `Check Shodan for additional details: https://www.shodan.io/host/${ev.ip}`
          ],
          cveIds: [cveId],
          kevListed: false,
          // Will be updated by KEV enrichment if applicable
          exploitAvailable: true,
          // Shodan-detected implies exploitability
          affectedAssets: [analysis.asset.hostname],
          evidenceBasis: "confirmed_cve",
          evidenceDetail: `CONFIRMED (Shodan detection): Shodan's internet-wide scan detected ${cveId} on ${ev.ip}:${ev.port} running ${ev.product || "unknown"}${ev.version ? "/" + ev.version : ""}. Banner: "${ev.bannerSnippet.substring(0, 100)}..."`,
          corroborationTier: "confirmed",
          detectedVersion: ev.version || void 0,
          versionMatchConfirmed: true,
          evidenceChain: [
            `Shodan internet-wide scan detected ${ev.product || "service"} on ${ev.ip}:${ev.port}/${ev.transport || "tcp"}`,
            ev.version ? `Version ${ev.version} identified from service banner` : "Version not available in banner",
            ev.cpe.length > 0 ? `CPE: ${ev.cpe.join(", ")}` : "No CPE data",
            `${cveId} flagged by Shodan's vulnerability detection engine`,
            `Corroboration: CONFIRMED \u2014 independent detection by Shodan (not inferred)`
          ]
        };
        analysis.postureFindings.push(finding);
        findingsAdded++;
      }
    }
  }
  const summary = `Shodan posture findings: ${findingsAdded} new confirmed CVE findings added from Shodan's own detection`;
  return { findingsAdded, summary };
}
var PROTOCOL_VERSION_PATTERNS, HTTP_PRODUCT_INDICATORS, PRODUCT_ALIASES;
var init_shodan_verifier = __esm({
  "server/lib/shodan-verifier.ts"() {
    PROTOCOL_VERSION_PATTERNS = /* @__PURE__ */ new Set(["1.0", "1.1", "2", "2.0", "3", "3.0"]);
    HTTP_PRODUCT_INDICATORS = ["http", "www", "web", "cloudflare", "akamai", "fastly", "varnish", "cdn"];
    PRODUCT_ALIASES = {
      "nginx": ["nginx"],
      "apache": ["apache httpd", "apache http server", "apache", "httpd"],
      "iis": ["microsoft-iis", "iis", "microsoft iis"],
      "openssh": ["openssh", "ssh"],
      "openssl": ["openssl"],
      "php": ["php"],
      "mysql": ["mysql", "mariadb"],
      "postgresql": ["postgresql", "postgres"],
      "redis": ["redis"],
      "mongodb": ["mongodb", "mongo"],
      "elasticsearch": ["elasticsearch", "elastic"],
      "tomcat": ["apache-coyote", "tomcat", "apache tomcat"],
      "wordpress": ["wordpress"],
      "drupal": ["drupal"],
      "exchange": ["microsoft exchange", "exchange", "microsoft-httpapi"],
      "citrix": ["citrix", "netscaler"],
      "f5 big-ip": ["big-ip", "bigip"],
      "fortinet": ["fortigate", "fortios", "fortinet"],
      "palo alto": ["panos", "palo alto"],
      "sonicwall": ["sonicwall", "sonicos"],
      "vmware": ["vmware", "vcenter", "esxi"],
      "jenkins": ["jenkins"],
      "gitlab": ["gitlab"],
      "confluence": ["confluence"],
      "jira": ["jira"],
      "varnish": ["varnish"],
      "haproxy": ["haproxy"],
      "lighttpd": ["lighttpd"],
      "caddy": ["caddy"],
      "express": ["express"],
      "gunicorn": ["gunicorn"],
      "envoy": ["envoy"],
      "cloudflare": ["cloudflare"],
      "akamai": ["akamai"],
      "litespeed": ["litespeed"],
      "zimbra": ["zimbra"],
      "roundcube": ["roundcube"],
      "pulse secure": ["pulse secure", "pulse connect secure"],
      "ivanti": ["ivanti", "pulse secure"],
      "solarwinds": ["solarwinds", "orion"],
      "barracuda": ["barracuda"],
      "moveit": ["moveit", "progress moveit"],
      "connectwise": ["connectwise", "screenconnect"]
    };
  }
});

export {
  isProtocolVersion,
  PRODUCT_ALIASES,
  matchShodanProductToTech,
  techMatchesShodanProduct,
  extractShodanVersionEvidence,
  enrichAssetsWithShodanData,
  verifyCvesWithShodanData,
  createShodanPostureFindings,
  init_shodan_verifier
};
