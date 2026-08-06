/**
 * IOC Overlap Detector — Cross-references discovered assets against threat actor IOCs
 *
 * Matches:
 * - Asset hostnames ↔ IOC domains
 * - Asset DNS A records (IPs) ↔ IOC IPs
 * - Asset URLs ↔ IOC URLs
 * - Scan primaryDomain ↔ IOC domains
 *
 * Returns per-actor overlap counts and specific matched indicators for the briefing.
 */
import { getDb } from "../db";
import { eq, inArray, sql } from "drizzle-orm";
import {
  discoveredAssets,
  domainIntelScans,
  threatActorIocs,
} from "../../drizzle/schema";

export interface IocMatch {
  actorId: string;
  iocType: string;
  iocValue: string;
  matchedAsset: string;       // hostname, IP, or URL that matched
  matchType: "domain" | "ip" | "url" | "subdomain";
  confidence: string | null;
}

export interface IocOverlapResult {
  totalMatches: number;
  matchesByActor: Map<string, IocMatch[]>;
  compromiseIndicators: IocMatch[];   // top matches for display
  assetExposure: {
    totalAssetsChecked: number;
    assetsWithIocHits: number;
    uniqueActorsMatched: number;
  };
}

/**
 * Compute IOC overlap for a given scan's discovered assets.
 */
export async function computeIocOverlap(scanId: number): Promise<IocOverlapResult> {
  const db = await getDb();
  if (!db) {
    return {
      totalMatches: 0,
      matchesByActor: new Map(),
      compromiseIndicators: [],
      assetExposure: { totalAssetsChecked: 0, assetsWithIocHits: 0, uniqueActorsMatched: 0 },
    };
  }

  // ── Step 1: Load all discovered assets for this scan ──
  const assets = await db.select({
    id: discoveredAssets.id,
    hostname: discoveredAssets.hostname,
    url: discoveredAssets.url,
    dnsRecords: discoveredAssets.dnsRecords,
  }).from(discoveredAssets)
    .where(eq(discoveredAssets.scanId, scanId));

  // Also load the scan's primary domain
  const [scan] = await db.select({
    primaryDomain: domainIntelScans.primaryDomain,
  }).from(domainIntelScans)
    .where(eq(domainIntelScans.id, scanId))
    .limit(1);

  // ── Step 2: Extract all domains, IPs, and URLs from assets ──
  const assetDomains = new Set<string>();
  const assetIps = new Set<string>();
  const assetUrls = new Set<string>();

  if (scan?.primaryDomain) {
    assetDomains.add(scan.primaryDomain.toLowerCase());
  }

  for (const asset of assets) {
    // Add hostname as domain
    if (asset.hostname) {
      assetDomains.add(asset.hostname.toLowerCase());
      // Also add the root domain (e.g., "www.example.com" → "example.com")
      const parts = asset.hostname.toLowerCase().split(".");
      if (parts.length > 2) {
        assetDomains.add(parts.slice(-2).join("."));
      }
    }

    // Add URL
    if (asset.url) {
      assetUrls.add(asset.url.toLowerCase());
      // Extract domain from URL
      try {
        const urlObj = new URL(asset.url);
        assetDomains.add(urlObj.hostname.toLowerCase());
      } catch { /* skip invalid URLs */ }
    }

    // Extract IPs from DNS A records
    if (asset.dnsRecords) {
      const dns = typeof asset.dnsRecords === "string"
        ? JSON.parse(asset.dnsRecords)
        : asset.dnsRecords;
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

  // ── Step 3: Query IOCs that match our asset indicators ──
  // We batch-query IOCs by type for efficiency
  const matches: IocMatch[] = [];

  // 3a: Domain IOCs
  if (assetDomains.size > 0) {
    const domainArr = [...assetDomains];
    // Query in batches of 200 to avoid query size limits
    for (let i = 0; i < domainArr.length; i += 200) {
      const batch = domainArr.slice(i, i + 200);
      const domainIocs = await db.select({
        actorId: threatActorIocs.actorId,
        iocType: threatActorIocs.iocType,
        value: threatActorIocs.value,
        confidence: threatActorIocs.iocConfidence,
      }).from(threatActorIocs)
        .where(sql`${threatActorIocs.iocType} = 'domain' AND LOWER(${threatActorIocs.value}) IN (${sql.join(batch.map(d => sql`${d}`), sql`, `)})`);

      for (const ioc of domainIocs) {
        const matchedAsset = domainArr.find(d => d === ioc.value?.toLowerCase()) || ioc.value;
        matches.push({
          actorId: ioc.actorId,
          iocType: "domain",
          iocValue: ioc.value,
          matchedAsset,
          matchType: "domain",
          confidence: ioc.confidence,
        });
      }
    }

    // Also check for subdomain matches (IOC domain is a parent of asset domain)
    const allDomainIocs = await db.select({
      actorId: threatActorIocs.actorId,
      value: threatActorIocs.value,
      confidence: threatActorIocs.iocConfidence,
    }).from(threatActorIocs)
      .where(eq(threatActorIocs.iocType, "domain"))
      .limit(5000);

    for (const ioc of allDomainIocs) {
      const iocDomain = (ioc.value || "").toLowerCase();
      for (const assetDomain of assetDomains) {
        if (assetDomain !== iocDomain && assetDomain.endsWith("." + iocDomain)) {
          // Asset is a subdomain of the IOC domain
          matches.push({
            actorId: ioc.actorId,
            iocType: "domain",
            iocValue: ioc.value,
            matchedAsset: assetDomain,
            matchType: "subdomain",
            confidence: ioc.confidence,
          });
        }
      }
    }
  }

  // 3b: IP IOCs
  if (assetIps.size > 0) {
    const ipArr = [...assetIps];
    for (let i = 0; i < ipArr.length; i += 200) {
      const batch = ipArr.slice(i, i + 200);
      const ipIocs = await db.select({
        actorId: threatActorIocs.actorId,
        iocType: threatActorIocs.iocType,
        value: threatActorIocs.value,
        confidence: threatActorIocs.iocConfidence,
      }).from(threatActorIocs)
        .where(sql`${threatActorIocs.iocType} = 'ip' AND ${threatActorIocs.value} IN (${sql.join(batch.map(ip => sql`${ip}`), sql`, `)})`);

      for (const ioc of ipIocs) {
        matches.push({
          actorId: ioc.actorId,
          iocType: "ip",
          iocValue: ioc.value,
          matchedAsset: ioc.value,
          matchType: "ip",
          confidence: ioc.confidence,
        });
      }
    }
  }

  // 3c: URL IOCs
  if (assetUrls.size > 0) {
    const urlArr = [...assetUrls];
    for (let i = 0; i < urlArr.length; i += 200) {
      const batch = urlArr.slice(i, i + 200);
      const urlIocs = await db.select({
        actorId: threatActorIocs.actorId,
        iocType: threatActorIocs.iocType,
        value: threatActorIocs.value,
        confidence: threatActorIocs.iocConfidence,
      }).from(threatActorIocs)
        .where(sql`${threatActorIocs.iocType} = 'url' AND LOWER(${threatActorIocs.value}) IN (${sql.join(batch.map(u => sql`${u}`), sql`, `)})`);

      for (const ioc of urlIocs) {
        matches.push({
          actorId: ioc.actorId,
          iocType: "url",
          iocValue: ioc.value,
          matchedAsset: urlArr.find(u => u === ioc.value?.toLowerCase()) || ioc.value,
          matchType: "url",
          confidence: ioc.confidence,
        });
      }
    }
  }

  // ── Step 4: Aggregate results ──
  const matchesByActor = new Map<string, IocMatch[]>();
  const assetsWithHits = new Set<string>();

  for (const m of matches) {
    if (!matchesByActor.has(m.actorId)) {
      matchesByActor.set(m.actorId, []);
    }
    matchesByActor.get(m.actorId)!.push(m);
    assetsWithHits.add(m.matchedAsset);
  }

  // Deduplicate matches (same actor + same IOC value)
  for (const [actorId, actorMatches] of matchesByActor) {
    const seen = new Set<string>();
    const deduped = actorMatches.filter(m => {
      const key = `${m.iocType}:${m.iocValue}:${m.matchedAsset}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    matchesByActor.set(actorId, deduped);
  }

  // Top compromise indicators (sorted by confidence, then by match type priority)
  const allDeduped = [...matchesByActor.values()].flat();
  const confidenceOrder: Record<string, number> = { high: 3, medium: 2, low: 1 };
  const typeOrder: Record<string, number> = { ip: 4, domain: 3, url: 2, subdomain: 1 };
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
      uniqueActorsMatched: matchesByActor.size,
    },
  };
}
