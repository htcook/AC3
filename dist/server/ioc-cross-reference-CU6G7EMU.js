import {
  getDb,
  init_db
} from "./chunk-RSFTEATL.js";
import "./chunk-KDOLKO2A.js";
import {
  discoveredAssets,
  domainIntelScans,
  engagements,
  init_schema,
  threatActorIocs,
  threatActors
} from "./chunk-L4JENJ4Z.js";
import "./chunk-KFQGP6VL.js";

// server/lib/ioc-cross-reference.ts
init_db();
init_schema();
import { eq, and } from "drizzle-orm";
function extractDomain(hostname) {
  const parts = hostname.replace(/^https?:\/\//, "").split("/")[0].split(".");
  if (parts.length >= 2) {
    return parts.slice(-2).join(".");
  }
  return hostname;
}
function matchDomain(iocValue, assetHostname) {
  const iocDomain = extractDomain(iocValue.replace(/^https?:\/\//, "").split("/")[0]);
  const assetDomain = extractDomain(assetHostname);
  if (iocDomain === assetDomain) {
    if (iocValue === assetHostname) return { matched: true, matchType: "exact" };
    return { matched: true, matchType: "domain_overlap" };
  }
  if (assetHostname.endsWith("." + iocDomain)) {
    return { matched: true, matchType: "subdomain" };
  }
  return null;
}
function matchEmailDomain(iocEmail, assetHostname) {
  const emailDomain = iocEmail.split("@")[1];
  if (!emailDomain) return false;
  return extractDomain(emailDomain) === extractDomain(assetHostname);
}
function assessRisk(iocType, actorThreatLevel, matchType) {
  if (actorThreatLevel === "critical") return "critical";
  if (iocType === "ip" && matchType === "exact") return "critical";
  if (iocType === "domain" && (matchType === "exact" || matchType === "subdomain")) return "high";
  if (actorThreatLevel === "high") return "high";
  if (iocType === "url") return "high";
  if (matchType === "domain_overlap") return "medium";
  return "medium";
}
function generateRecommendation(iocType, matchType, actorName) {
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
async function requireDb() {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  return db;
}
async function crossReferenceIOCs(opts) {
  const start = Date.now();
  const db = await requireDb();
  const matches = [];
  let iocQuery = db.select({
    id: threatActorIocs.id,
    actorId: threatActorIocs.actorId,
    type: threatActorIocs.iocType,
    value: threatActorIocs.value,
    description: threatActorIocs.description,
    confidence: threatActorIocs.iocConfidence
  }).from(threatActorIocs);
  if (opts?.actorId) {
    iocQuery = iocQuery.where(eq(threatActorIocs.actorId, opts.actorId));
  }
  const iocs = await iocQuery;
  let assetQuery = db.select({
    id: discoveredAssets.id,
    hostname: discoveredAssets.hostname,
    url: discoveredAssets.url,
    scanId: discoveredAssets.scanId,
    technologies: discoveredAssets.technologies,
    dnsRecords: discoveredAssets.dnsRecords,
    riskBand: discoveredAssets.riskBand
  }).from(discoveredAssets).where(eq(discoveredAssets.excluded, false));
  if (opts?.scanId) {
    assetQuery = assetQuery.where(and(
      eq(discoveredAssets.excluded, false),
      eq(discoveredAssets.scanId, opts.scanId)
    ));
  }
  const assets = await assetQuery.limit(5e3);
  const actorIds = [...new Set(iocs.map((i) => i.actorId))];
  const actorMap = /* @__PURE__ */ new Map();
  for (const aid of actorIds) {
    const [actor] = await db.select({
      name: threatActors.name,
      threatLevel: threatActors.threatLevel
    }).from(threatActors).where(eq(threatActors.actorId, aid)).limit(1);
    if (actor) actorMap.set(aid, { name: actor.name, threatLevel: actor.threatLevel ?? "medium" });
  }
  const scanIds = [...new Set(assets.map((a) => a.scanId))];
  const scanEngMap = /* @__PURE__ */ new Map();
  for (const sid of scanIds) {
    const [scan] = await db.select({
      engagementId: domainIntelScans.engagementId
    }).from(domainIntelScans).where(eq(domainIntelScans.id, sid)).limit(1);
    if (scan?.engagementId) {
      const [eng] = await db.select({ name: engagements.name }).from(engagements).where(eq(engagements.id, scan.engagementId)).limit(1);
      scanEngMap.set(sid, { engagementId: scan.engagementId, engagementName: eng?.name ?? null });
    } else {
      scanEngMap.set(sid, { engagementId: null, engagementName: null });
    }
  }
  const filteredAssets = opts?.engagementId ? assets.filter((a) => scanEngMap.get(a.scanId)?.engagementId === opts.engagementId) : assets;
  for (const ioc of iocs) {
    const actor = actorMap.get(ioc.actorId);
    if (!actor) continue;
    for (const asset of filteredAssets) {
      let matched = false;
      let matchType = "exact";
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
        const dns = asset.dnsRecords;
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
      if (!matched && ioc.type === "tool") {
        const techs = asset.technologies;
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
          recommendation: generateRecommendation(ioc.type, matchType, actor.name)
        });
      }
    }
  }
  const matchesByActor = {};
  const matchesByRiskLevel = { critical: 0, high: 0, medium: 0, low: 0 };
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
    checkedAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}
export {
  crossReferenceIOCs
};
