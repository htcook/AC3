import {
  getDb,
  init_db
} from "./chunk-B7OU3XQL.js";
import "./chunk-NRYVRXXR.js";
import {
  discoveredAssets,
  domainIntelScans,
  init_schema,
  threatActorIocs
} from "./chunk-TYPEU32S.js";
import "./chunk-KFQGP6VL.js";

// server/lib/ioc-overlap-detector.ts
init_db();
init_schema();
import { eq, sql } from "drizzle-orm";
async function computeIocOverlap(scanId) {
  const db = await getDb();
  if (!db) {
    return {
      totalMatches: 0,
      matchesByActor: /* @__PURE__ */ new Map(),
      compromiseIndicators: [],
      assetExposure: { totalAssetsChecked: 0, assetsWithIocHits: 0, uniqueActorsMatched: 0 }
    };
  }
  const assets = await db.select({
    id: discoveredAssets.id,
    hostname: discoveredAssets.hostname,
    url: discoveredAssets.url,
    dnsRecords: discoveredAssets.dnsRecords
  }).from(discoveredAssets).where(eq(discoveredAssets.scanId, scanId));
  const [scan] = await db.select({
    primaryDomain: domainIntelScans.primaryDomain
  }).from(domainIntelScans).where(eq(domainIntelScans.id, scanId)).limit(1);
  const assetDomains = /* @__PURE__ */ new Set();
  const assetIps = /* @__PURE__ */ new Set();
  const assetUrls = /* @__PURE__ */ new Set();
  if (scan?.primaryDomain) {
    assetDomains.add(scan.primaryDomain.toLowerCase());
  }
  for (const asset of assets) {
    if (asset.hostname) {
      assetDomains.add(asset.hostname.toLowerCase());
      const parts = asset.hostname.toLowerCase().split(".");
      if (parts.length > 2) {
        assetDomains.add(parts.slice(-2).join("."));
      }
    }
    if (asset.url) {
      assetUrls.add(asset.url.toLowerCase());
      try {
        const urlObj = new URL(asset.url);
        assetDomains.add(urlObj.hostname.toLowerCase());
      } catch {
      }
    }
    if (asset.dnsRecords) {
      const dns = typeof asset.dnsRecords === "string" ? JSON.parse(asset.dnsRecords) : asset.dnsRecords;
      if (dns?.A && Array.isArray(dns.A)) {
        for (const ip of dns.A) {
          assetIps.add(ip);
        }
      }
      if (dns?.AAAA && Array.isArray(dns.AAAA)) {
        for (const ip of dns.AAAA) {
          assetIps.add(ip);
        }
      }
    }
  }
  const matches = [];
  if (assetDomains.size > 0) {
    const domainArr = [...assetDomains];
    for (let i = 0; i < domainArr.length; i += 200) {
      const batch = domainArr.slice(i, i + 200);
      const domainIocs = await db.select({
        actorId: threatActorIocs.actorId,
        iocType: threatActorIocs.iocType,
        value: threatActorIocs.value,
        confidence: threatActorIocs.iocConfidence
      }).from(threatActorIocs).where(sql`${threatActorIocs.iocType} = 'domain' AND LOWER(${threatActorIocs.value}) IN (${sql.join(batch.map((d) => sql`${d}`), sql`, `)})`);
      for (const ioc of domainIocs) {
        const matchedAsset = domainArr.find((d) => d === ioc.value?.toLowerCase()) || ioc.value;
        matches.push({
          actorId: ioc.actorId,
          iocType: "domain",
          iocValue: ioc.value,
          matchedAsset,
          matchType: "domain",
          confidence: ioc.confidence
        });
      }
    }
    const allDomainIocs = await db.select({
      actorId: threatActorIocs.actorId,
      value: threatActorIocs.value,
      confidence: threatActorIocs.iocConfidence
    }).from(threatActorIocs).where(eq(threatActorIocs.iocType, "domain")).limit(5e3);
    for (const ioc of allDomainIocs) {
      const iocDomain = (ioc.value || "").toLowerCase();
      for (const assetDomain of assetDomains) {
        if (assetDomain !== iocDomain && assetDomain.endsWith("." + iocDomain)) {
          matches.push({
            actorId: ioc.actorId,
            iocType: "domain",
            iocValue: ioc.value,
            matchedAsset: assetDomain,
            matchType: "subdomain",
            confidence: ioc.confidence
          });
        }
      }
    }
  }
  if (assetIps.size > 0) {
    const ipArr = [...assetIps];
    for (let i = 0; i < ipArr.length; i += 200) {
      const batch = ipArr.slice(i, i + 200);
      const ipIocs = await db.select({
        actorId: threatActorIocs.actorId,
        iocType: threatActorIocs.iocType,
        value: threatActorIocs.value,
        confidence: threatActorIocs.iocConfidence
      }).from(threatActorIocs).where(sql`${threatActorIocs.iocType} = 'ip' AND ${threatActorIocs.value} IN (${sql.join(batch.map((ip) => sql`${ip}`), sql`, `)})`);
      for (const ioc of ipIocs) {
        matches.push({
          actorId: ioc.actorId,
          iocType: "ip",
          iocValue: ioc.value,
          matchedAsset: ioc.value,
          matchType: "ip",
          confidence: ioc.confidence
        });
      }
    }
  }
  if (assetUrls.size > 0) {
    const urlArr = [...assetUrls];
    for (let i = 0; i < urlArr.length; i += 200) {
      const batch = urlArr.slice(i, i + 200);
      const urlIocs = await db.select({
        actorId: threatActorIocs.actorId,
        iocType: threatActorIocs.iocType,
        value: threatActorIocs.value,
        confidence: threatActorIocs.iocConfidence
      }).from(threatActorIocs).where(sql`${threatActorIocs.iocType} = 'url' AND LOWER(${threatActorIocs.value}) IN (${sql.join(batch.map((u) => sql`${u}`), sql`, `)})`);
      for (const ioc of urlIocs) {
        matches.push({
          actorId: ioc.actorId,
          iocType: "url",
          iocValue: ioc.value,
          matchedAsset: urlArr.find((u) => u === ioc.value?.toLowerCase()) || ioc.value,
          matchType: "url",
          confidence: ioc.confidence
        });
      }
    }
  }
  const matchesByActor = /* @__PURE__ */ new Map();
  const assetsWithHits = /* @__PURE__ */ new Set();
  for (const m of matches) {
    if (!matchesByActor.has(m.actorId)) {
      matchesByActor.set(m.actorId, []);
    }
    matchesByActor.get(m.actorId).push(m);
    assetsWithHits.add(m.matchedAsset);
  }
  for (const [actorId, actorMatches] of matchesByActor) {
    const seen = /* @__PURE__ */ new Set();
    const deduped = actorMatches.filter((m) => {
      const key = `${m.iocType}:${m.iocValue}:${m.matchedAsset}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    matchesByActor.set(actorId, deduped);
  }
  const allDeduped = [...matchesByActor.values()].flat();
  const confidenceOrder = { high: 3, medium: 2, low: 1 };
  const typeOrder = { ip: 4, domain: 3, url: 2, subdomain: 1 };
  allDeduped.sort((a, b) => {
    const confDiff = (confidenceOrder[b.confidence || "medium"] || 0) - (confidenceOrder[a.confidence || "medium"] || 0);
    if (confDiff !== 0) return confDiff;
    return (typeOrder[b.matchType] || 0) - (typeOrder[a.matchType] || 0);
  });
  return {
    totalMatches: allDeduped.length,
    matchesByActor,
    compromiseIndicators: allDeduped.slice(0, 20),
    assetExposure: {
      totalAssetsChecked: assets.length,
      assetsWithIocHits: assetsWithHits.size,
      uniqueActorsMatched: matchesByActor.size
    }
  };
}
export {
  computeIocOverlap
};
