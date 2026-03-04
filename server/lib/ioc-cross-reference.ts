/**
 * IOC Cross-Reference Engine
 *
 * Checks threat actor IOCs (domains, IPs, URLs, emails) against
 * engagement assets (discovered domains, hostnames, URLs, technologies)
 * to identify potential exposure to known threat infrastructure.
 *
 * Supports:
 *   - Domain matching (exact + subdomain)
 *   - IP address matching
 *   - URL pattern matching
 *   - Email domain matching
 *   - Technology/tool matching
 */

import { getDb } from "../db";
import {
  threatActorIocs,
  threatActors,
  discoveredAssets,
  domainIntelScans,
  engagements,
} from "../../drizzle/schema";
import { eq, sql, and, desc } from "drizzle-orm";

// ─── Types ───────────────────────────────────────────────────────────

export interface IOCMatch {
  iocId: number;
  iocType: string;
  iocValue: string;
  iocDescription: string;
  actorId: string;
  actorName: string;
  actorThreatLevel: string;
  matchType: "exact" | "subdomain" | "domain_overlap" | "ip_match" | "technology_match";
  matchedAssetId: number;
  matchedAssetHostname: string;
  matchedAssetUrl: string | null;
  matchedField: string;
  matchedValue: string;
  engagementId: number | null;
  engagementName: string | null;
  scanId: number;
  confidence: number;
  riskLevel: "critical" | "high" | "medium" | "low";
  recommendation: string;
}

export interface CrossReferenceResult {
  totalIOCsChecked: number;
  totalAssetsChecked: number;
  matches: IOCMatch[];
  matchesByActor: Record<string, IOCMatch[]>;
  matchesByRiskLevel: Record<string, number>;
  duration: number;
  checkedAt: string;
}

// ─── Matching Logic ──────────────────────────────────────────────────

/**
 * Extract the registrable domain from a hostname (e.g., "sub.example.com" → "example.com").
 */
function extractDomain(hostname: string): string {
  const parts = hostname.replace(/^https?:\/\//, "").split("/")[0].split(".");
  if (parts.length >= 2) {
    return parts.slice(-2).join(".");
  }
  return hostname;
}

/**
 * Check if an IOC domain matches an asset hostname.
 */
function matchDomain(iocValue: string, assetHostname: string): { matched: boolean; matchType: "exact" | "subdomain" | "domain_overlap" } | null {
  const iocDomain = extractDomain(iocValue.replace(/^https?:\/\//, "").split("/")[0]);
  const assetDomain = extractDomain(assetHostname);

  if (iocDomain === assetDomain) {
    if (iocValue === assetHostname) return { matched: true, matchType: "exact" };
    return { matched: true, matchType: "domain_overlap" };
  }

  // Check if asset is a subdomain of IOC domain
  if (assetHostname.endsWith("." + iocDomain)) {
    return { matched: true, matchType: "subdomain" };
  }

  return null;
}

/**
 * Check if an IOC email's domain matches any asset domain.
 */
function matchEmailDomain(iocEmail: string, assetHostname: string): boolean {
  const emailDomain = iocEmail.split("@")[1];
  if (!emailDomain) return false;
  return extractDomain(emailDomain) === extractDomain(assetHostname);
}

/**
 * Determine risk level based on IOC type and actor threat level.
 */
function assessRisk(iocType: string, actorThreatLevel: string, matchType: string): "critical" | "high" | "medium" | "low" {
  if (actorThreatLevel === "critical") return "critical";
  if (iocType === "ip" && matchType === "exact") return "critical";
  if (iocType === "domain" && (matchType === "exact" || matchType === "subdomain")) return "high";
  if (actorThreatLevel === "high") return "high";
  if (iocType === "url") return "high";
  if (matchType === "domain_overlap") return "medium";
  return "medium";
}

/**
 * Generate a recommendation based on the match.
 */
function generateRecommendation(iocType: string, matchType: string, actorName: string): string {
  if (iocType === "domain" && matchType === "exact") {
    return `URGENT: Asset hostname exactly matches known ${actorName} infrastructure. Investigate immediately for compromise indicators.`;
  }
  if (iocType === "domain" && matchType === "subdomain") {
    return `Asset is a subdomain of known ${actorName} infrastructure domain. Verify if this is legitimate or indicates compromise.`;
  }
  if (iocType === "ip" && matchType === "ip_match") {
    return `Asset resolves to an IP address associated with ${actorName}. Check DNS records and hosting provider for potential shared infrastructure.`;
  }
  if (iocType === "email") {
    return `Asset domain matches email domain used by ${actorName}. Review for phishing or social engineering exposure.`;
  }
  if (matchType === "technology_match") {
    return `Asset uses technology/tool associated with ${actorName} TTPs. Ensure patching and hardening are current.`;
  }
  return `Potential overlap with ${actorName} infrastructure detected. Review asset configuration and monitor for anomalous activity.`;
}

// ─── Main Cross-Reference Function ───────────────────────────────────

async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

/**
 * Cross-reference all threat actor IOCs against discovered assets.
 * Optionally filter by specific actor ID or engagement ID.
 */
export async function crossReferenceIOCs(opts?: {
  actorId?: string;
  engagementId?: number;
  scanId?: number;
}): Promise<CrossReferenceResult> {
  const start = Date.now();
  const db = await requireDb();
  const matches: IOCMatch[] = [];

  // 1. Fetch IOCs (optionally filtered by actor)
  let iocQuery = db.select({
    id: threatActorIocs.id,
    actorId: threatActorIocs.actorId,
    type: threatActorIocs.type,
    value: threatActorIocs.value,
    description: threatActorIocs.description,
    confidence: threatActorIocs.confidence,
  }).from(threatActorIocs);

  if (opts?.actorId) {
    iocQuery = iocQuery.where(eq(threatActorIocs.actorId, opts.actorId)) as any;
  }

  const iocs = await iocQuery;

  // 2. Fetch assets (optionally filtered by engagement/scan)
  let assetQuery = db.select({
    id: discoveredAssets.id,
    hostname: discoveredAssets.hostname,
    url: discoveredAssets.url,
    scanId: discoveredAssets.scanId,
    technologies: discoveredAssets.technologies,
    dnsRecords: discoveredAssets.dnsRecords,
    riskBand: discoveredAssets.riskBand,
  }).from(discoveredAssets)
    .where(eq(discoveredAssets.excluded, false));

  if (opts?.scanId) {
    assetQuery = assetQuery.where(and(
      eq(discoveredAssets.excluded, false),
      eq(discoveredAssets.scanId, opts.scanId),
    )) as any;
  }

  const assets = await assetQuery.limit(5000); // Cap for performance

  // 3. Build actor lookup
  const actorIds = [...new Set(iocs.map(i => i.actorId))];
  const actorMap = new Map<string, { name: string; threatLevel: string }>();
  for (const aid of actorIds) {
    const [actor] = await db.select({
      name: threatActors.name,
      threatLevel: threatActors.threatLevel,
    }).from(threatActors).where(eq(threatActors.actorId, aid)).limit(1);
    if (actor) actorMap.set(aid, { name: actor.name, threatLevel: actor.threatLevel ?? "medium" });
  }

  // 4. Build scan → engagement lookup
  const scanIds = [...new Set(assets.map(a => a.scanId))];
  const scanEngMap = new Map<number, { engagementId: number | null; engagementName: string | null }>();
  for (const sid of scanIds) {
    const [scan] = await db.select({
      engagementId: domainIntelScans.engagementId,
    }).from(domainIntelScans).where(eq(domainIntelScans.id, sid)).limit(1);
    if (scan?.engagementId) {
      const [eng] = await db.select({ name: engagements.name }).from(engagements).where(eq(engagements.id, scan.engagementId)).limit(1);
      scanEngMap.set(sid, { engagementId: scan.engagementId, engagementName: eng?.name ?? null });
    } else {
      scanEngMap.set(sid, { engagementId: null, engagementName: null });
    }
  }

  // Filter by engagement if specified
  const filteredAssets = opts?.engagementId
    ? assets.filter(a => scanEngMap.get(a.scanId)?.engagementId === opts.engagementId)
    : assets;

  // 5. Cross-reference
  for (const ioc of iocs) {
    const actor = actorMap.get(ioc.actorId);
    if (!actor) continue;

    for (const asset of filteredAssets) {
      let matched = false;
      let matchType: IOCMatch["matchType"] = "exact";
      let matchedField = "";
      let matchedValue = "";

      if (ioc.type === "domain" || ioc.type === "url") {
        const iocHost = ioc.value.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
        const domainMatch = matchDomain(iocHost, asset.hostname);
        if (domainMatch) {
          matched = true;
          matchType = domainMatch.matchType;
          matchedField = "hostname";
          matchedValue = asset.hostname;
        }
        // Also check asset URL
        if (!matched && asset.url) {
          const urlHost = asset.url.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
          const urlMatch = matchDomain(iocHost, urlHost);
          if (urlMatch) {
            matched = true;
            matchType = urlMatch.matchType;
            matchedField = "url";
            matchedValue = asset.url;
          }
        }
      }

      if (ioc.type === "email") {
        if (matchEmailDomain(ioc.value, asset.hostname)) {
          matched = true;
          matchType = "domain_overlap";
          matchedField = "hostname (email domain)";
          matchedValue = asset.hostname;
        }
      }

      if (ioc.type === "ip") {
        // Check DNS records for IP matches
        const dns = asset.dnsRecords as any;
        if (dns && Array.isArray(dns)) {
          for (const record of dns) {
            if (record?.value === ioc.value || record?.address === ioc.value) {
              matched = true;
              matchType = "ip_match";
              matchedField = "dnsRecords";
              matchedValue = ioc.value;
              break;
            }
          }
        }
      }

      // Check technologies for tool matches
      if (!matched && ioc.type === "tool") {
        const techs = asset.technologies as any;
        if (techs && Array.isArray(techs)) {
          for (const tech of techs) {
            const techName = typeof tech === "string" ? tech : tech?.name;
            if (techName && techName.toLowerCase().includes(ioc.value.toLowerCase())) {
              matched = true;
              matchType = "technology_match";
              matchedField = "technologies";
              matchedValue = techName;
              break;
            }
          }
        }
      }

      if (matched) {
        const engInfo = scanEngMap.get(asset.scanId);
        const riskLevel = assessRisk(ioc.type, actor.threatLevel, matchType);

        matches.push({
          iocId: ioc.id,
          iocType: ioc.type,
          iocValue: ioc.value,
          iocDescription: ioc.description ?? "",
          actorId: ioc.actorId,
          actorName: actor.name,
          actorThreatLevel: actor.threatLevel,
          matchType,
          matchedAssetId: asset.id,
          matchedAssetHostname: asset.hostname,
          matchedAssetUrl: asset.url,
          matchedField,
          matchedValue,
          engagementId: engInfo?.engagementId ?? null,
          engagementName: engInfo?.engagementName ?? null,
          scanId: asset.scanId,
          confidence: ioc.confidence ?? 70,
          riskLevel,
          recommendation: generateRecommendation(ioc.type, matchType, actor.name),
        });
      }
    }
  }

  // 6. Aggregate results
  const matchesByActor: Record<string, IOCMatch[]> = {};
  const matchesByRiskLevel: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const m of matches) {
    if (!matchesByActor[m.actorName]) matchesByActor[m.actorName] = [];
    matchesByActor[m.actorName].push(m);
    matchesByRiskLevel[m.riskLevel]++;
  }

  return {
    totalIOCsChecked: iocs.length,
    totalAssetsChecked: filteredAssets.length,
    matches,
    matchesByActor,
    matchesByRiskLevel,
    duration: Date.now() - start,
    checkedAt: new Date().toISOString(),
  };
}
