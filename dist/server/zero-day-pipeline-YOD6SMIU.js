import {
  crossReferenceAssets,
  extractAssetsFromObservations
} from "./chunk-7OGJJRL5.js";
import {
  init_db,
  saveZeroDayMatches
} from "./chunk-VL2KRLTM.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-IG2G4XDA.js";
import "./chunk-KFQGP6VL.js";

// server/lib/zero-day-pipeline.ts
init_db();
async function runZeroDayCheck(input) {
  const startMs = Date.now();
  try {
    const assets = extractAssetsFromObservations(
      input.observations,
      input.domain
    );
    if (input.additionalAssets) {
      for (const extra of input.additionalAssets) {
        const existing = assets.find(
          (a) => a.identifier === extra.identifier
        );
        if (existing) {
          if (extra.cves) {
            for (const c of extra.cves) {
              if (!existing.cves.includes(c)) existing.cves.push(c);
            }
          }
          if (extra.vendors) {
            for (const v of extra.vendors) {
              if (!existing.vendors.includes(v)) existing.vendors.push(v);
            }
          }
          if (extra.products) {
            for (const p of extra.products) {
              if (!existing.products.includes(p))
                existing.products.push(p);
            }
          }
        } else {
          assets.push(extra);
        }
      }
    }
    const crossRefResult = await crossReferenceAssets(assets);
    let persisted = false;
    if (crossRefResult.matches.length > 0) {
      try {
        await saveZeroDayMatches(
          crossRefResult.matches.map((m) => ({
            scanId: input.scanId,
            engagementId: input.engagementId,
            domain: input.domain,
            cve: m.zeroDayEntry.cve,
            vendor: m.zeroDayEntry.vendor,
            product: m.zeroDayEntry.product,
            matchType: m.matchType,
            confidence: m.confidence,
            severity: m.severity,
            matchedAsset: m.matchedAsset,
            zeroDayDescription: m.zeroDayEntry.description,
            zeroDayType: m.zeroDayEntry.type,
            advisoryUrl: m.zeroDayEntry.advisoryUrl || void 0
          }))
        );
        persisted = true;
      } catch (err) {
        console.error("[ZeroDayPipeline] Failed to persist matches:", err);
      }
    }
    const durationMs = Date.now() - startMs;
    const criticalMatches = crossRefResult.matches.filter(
      (m) => m.severity === "critical"
    ).length;
    const highMatches = crossRefResult.matches.filter(
      (m) => m.severity === "high"
    ).length;
    const mediumMatches = crossRefResult.matches.filter(
      (m) => m.severity === "medium"
    ).length;
    console.log(
      `[ZeroDayPipeline] ${input.domain} scan=${input.scanId}: ${crossRefResult.matches.length} matches (${criticalMatches} critical, ${highMatches} high, ${mediumMatches} medium) in ${durationMs}ms`
    );
    return {
      totalMatches: crossRefResult.matches.length,
      criticalMatches,
      highMatches,
      mediumMatches,
      cveExactMatches: crossRefResult.matches.filter(
        (m) => m.matchType === "cve_exact"
      ).length,
      vendorProductMatches: crossRefResult.matches.filter(
        (m) => m.matchType === "vendor_product"
      ).length,
      productFuzzyMatches: crossRefResult.matches.filter(
        (m) => m.matchType === "product_fuzzy"
      ).length,
      persisted,
      crossRefResult
    };
  } catch (err) {
    console.error(
      `[ZeroDayPipeline] Failed for ${input.domain}:`,
      err
    );
    return {
      totalMatches: 0,
      criticalMatches: 0,
      highMatches: 0,
      mediumMatches: 0,
      cveExactMatches: 0,
      vendorProductMatches: 0,
      productFuzzyMatches: 0,
      persisted: false,
      crossRefResult: {
        matches: [],
        totalChecked: 0,
        zeroDaysChecked: 0,
        checkedAt: Date.now()
      }
    };
  }
}
function extractAssetsFromEngagementFindings(findings, domain) {
  const assetMap = /* @__PURE__ */ new Map();
  for (const finding of findings) {
    const identifier = finding.targetHost || domain;
    if (!assetMap.has(identifier)) {
      assetMap.set(identifier, {
        identifier,
        cves: [],
        vendors: [],
        products: [],
        versions: []
      });
    }
    const asset = assetMap.get(identifier);
    if (finding.cve) {
      const cves = finding.cve.match(/CVE-\d{4}-\d{4,}/gi);
      if (cves) {
        for (const cve of cves) {
          if (!asset.cves.includes(cve.toUpperCase())) {
            asset.cves.push(cve.toUpperCase());
          }
        }
      }
    }
    const textToScan = [
      finding.description,
      finding.rawOutput,
      finding.title
    ].filter(Boolean).join(" ");
    const cveMatches = textToScan.match(/CVE-\d{4}-\d{4,}/gi);
    if (cveMatches) {
      for (const cve of cveMatches) {
        if (!asset.cves.includes(cve.toUpperCase())) {
          asset.cves.push(cve.toUpperCase());
        }
      }
    }
    if (finding.technology) {
      const techs = finding.technology.split(/[,;\/]/).map((t) => t.trim());
      for (const tech of techs) {
        if (tech && !asset.products.includes(tech)) {
          asset.products.push(tech);
        }
      }
    }
  }
  return Array.from(assetMap.values());
}
export {
  extractAssetsFromEngagementFindings,
  runZeroDayCheck
};
