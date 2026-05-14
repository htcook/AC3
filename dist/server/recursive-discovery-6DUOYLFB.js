import "./chunk-KFQGP6VL.js";

// server/lib/passive/recursive-discovery.ts
import { createHash } from "crypto";
var DEFAULT_RECURSIVE_CONFIG = {
  maxDepth: 3,
  maxEntities: 200,
  maxApiCalls: 500,
  scopeRestriction: "related",
  entityTypes: ["domain", "ip", "email", "organization", "url", "certificate"],
  timeout: 3e4
};
function makeEntityId(type, value) {
  return createHash("sha256").update(`${type}|${value}`).digest("hex").slice(0, 16);
}
function extractEntities(observations, parentId, depth, rootDomain, scopeRestriction) {
  const entities = [];
  const seen = /* @__PURE__ */ new Set();
  for (const obs of observations) {
    if (obs.assetType === "subdomain" || obs.assetType === "cname" || obs.assetType === "ns" || obs.assetType === "mx") {
      const hostname = obs.name;
      if (hostname && isInScope(hostname, rootDomain, scopeRestriction)) {
        const id = makeEntityId("domain", hostname);
        if (!seen.has(id)) {
          seen.add(id);
          entities.push({
            id,
            type: "domain",
            value: hostname,
            parentId,
            depth,
            source: obs.source,
            discoveredAt: /* @__PURE__ */ new Date(),
            investigated: false,
            observationCount: 0,
            childEntities: []
          });
        }
      }
    }
    if (obs.ip) {
      const id = makeEntityId("ip", obs.ip);
      if (!seen.has(id)) {
        seen.add(id);
        entities.push({
          id,
          type: "ip",
          value: obs.ip,
          parentId,
          depth,
          source: obs.source,
          discoveredAt: /* @__PURE__ */ new Date(),
          investigated: false,
          observationCount: 0,
          childEntities: []
        });
      }
    }
    const evidence = obs.evidence || {};
    if (evidence.email && typeof evidence.email === "string") {
      const email = evidence.email;
      if (isEmailInScope(email, rootDomain, scopeRestriction)) {
        const id = makeEntityId("email", email);
        if (!seen.has(id)) {
          seen.add(id);
          entities.push({
            id,
            type: "email",
            value: email,
            parentId,
            depth,
            source: obs.source,
            discoveredAt: /* @__PURE__ */ new Date(),
            investigated: false,
            observationCount: 0,
            childEntities: []
          });
        }
      }
    }
    if (evidence.contactEmail && typeof evidence.contactEmail === "string") {
      const email = evidence.contactEmail;
      if (isEmailInScope(email, rootDomain, scopeRestriction)) {
        const id = makeEntityId("email", email);
        if (!seen.has(id)) {
          seen.add(id);
          entities.push({
            id,
            type: "email",
            value: email,
            parentId,
            depth,
            source: obs.source,
            discoveredAt: /* @__PURE__ */ new Date(),
            investigated: false,
            observationCount: 0,
            childEntities: []
          });
        }
      }
    }
    if (evidence.organization && typeof evidence.organization === "string") {
      const org = evidence.organization;
      const id = makeEntityId("organization", org);
      if (!seen.has(id)) {
        seen.add(id);
        entities.push({
          id,
          type: "organization",
          value: org,
          parentId,
          depth,
          source: obs.source,
          discoveredAt: /* @__PURE__ */ new Date(),
          investigated: false,
          observationCount: 0,
          childEntities: []
        });
      }
    }
    if (obs.assetType === "url" && obs.name) {
      const url = obs.name;
      if (isUrlInScope(url, rootDomain, scopeRestriction)) {
        const id = makeEntityId("url", url);
        if (!seen.has(id)) {
          seen.add(id);
          entities.push({
            id,
            type: "url",
            value: url,
            parentId,
            depth,
            source: obs.source,
            discoveredAt: /* @__PURE__ */ new Date(),
            investigated: false,
            observationCount: 0,
            childEntities: []
          });
        }
      }
    }
    if (obs.assetType === "certificate" && evidence.sans && Array.isArray(evidence.sans)) {
      for (const san of evidence.sans) {
        const cleanSan = san.replace(/^\*\./, "");
        if (isInScope(cleanSan, rootDomain, scopeRestriction)) {
          const id = makeEntityId("domain", cleanSan);
          if (!seen.has(id)) {
            seen.add(id);
            entities.push({
              id,
              type: "domain",
              value: cleanSan,
              parentId,
              depth,
              source: obs.source,
              discoveredAt: /* @__PURE__ */ new Date(),
              investigated: false,
              observationCount: 0,
              childEntities: []
            });
          }
        }
      }
    }
    if (evidence.subjectAlternativeNames && Array.isArray(evidence.subjectAlternativeNames)) {
      for (const san of evidence.subjectAlternativeNames) {
        const cleanSan = san.replace(/^\*\./, "");
        if (isInScope(cleanSan, rootDomain, scopeRestriction)) {
          const id = makeEntityId("domain", cleanSan);
          if (!seen.has(id)) {
            seen.add(id);
            entities.push({
              id,
              type: "domain",
              value: cleanSan,
              parentId,
              depth,
              source: obs.source,
              discoveredAt: /* @__PURE__ */ new Date(),
              investigated: false,
              observationCount: 0,
              childEntities: []
            });
          }
        }
      }
    }
  }
  return entities;
}
function isInScope(hostname, rootDomain, scope) {
  if (scope === "unrestricted") return true;
  const h = hostname.toLowerCase();
  const r = rootDomain.toLowerCase();
  if (scope === "strict") return h === r || h.endsWith(`.${r}`);
  const rootBase = getBaseDomain(r);
  const hostBase = getBaseDomain(h);
  return rootBase === hostBase || h.endsWith(`.${r}`) || h === r;
}
function isEmailInScope(email, rootDomain, scope) {
  if (scope === "unrestricted") return true;
  const domain = email.split("@")[1]?.toLowerCase();
  if (!domain) return false;
  return isInScope(domain, rootDomain, scope);
}
function isUrlInScope(url, rootDomain, scope) {
  if (scope === "unrestricted") return true;
  try {
    const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
    return isInScope(parsed.hostname, rootDomain, scope);
  } catch {
    return false;
  }
}
function getBaseDomain(hostname) {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const commonSLDs = ["co", "com", "org", "net", "gov", "edu", "ac"];
  if (parts.length >= 3 && commonSLDs.includes(parts[parts.length - 2])) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}
async function investigateEntity(entity, connectors, config) {
  const observations = [];
  let apiCalls = 0;
  const timeout = config.timeout || 3e4;
  const selectedConnectors = selectConnectorsForEntity(entity, connectors);
  for (const connector of selectedConnectors) {
    try {
      const connectorConfig = { timeout };
      if (connector.requiresApiKey && config.apiKeys) {
        connectorConfig.apiKey = config.apiKeys[connector.name];
        if (!connectorConfig.apiKey) continue;
      }
      let result;
      apiCalls++;
      switch (entity.type) {
        case "domain":
          result = await connector.collect(entity.value, connectorConfig);
          break;
        case "ip":
          result = await connector.collect(entity.value, connectorConfig);
          break;
        case "email":
          const emailDomain = entity.value.split("@")[1];
          if (emailDomain) {
            result = await connector.collect(emailDomain, connectorConfig);
          } else {
            continue;
          }
          break;
        default:
          continue;
      }
      observations.push(...result.observations);
    } catch (err) {
      console.warn(`[RecursiveDiscovery] Connector ${connector.name} failed for ${entity.value}: ${err.message}`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return { observations, apiCalls };
}
function selectConnectorsForEntity(entity, allConnectors) {
  const connectorNames = [];
  switch (entity.type) {
    case "domain":
      connectorNames.push("shodan-internetdb", "crtsh", "http-security", "dns-deep");
      break;
    case "ip":
      connectorNames.push("shodan-internetdb", "abuseipdb", "greynoise");
      break;
    case "email":
      connectorNames.push("hibp", "hunter");
      break;
    case "organization":
      connectorNames.push("social-media", "hunter");
      break;
    case "url":
      connectorNames.push("urlscan", "virustotal");
      break;
    case "certificate":
      connectorNames.push("crtsh");
      break;
  }
  return allConnectors.filter((c) => connectorNames.includes(c.name));
}
var ENTITY_TYPE_PRIORITY = {
  domain: 1,
  // Domains yield the most child entities
  ip: 0.8,
  // IPs reveal services and ports
  certificate: 0.75,
  // Certs reveal SANs (new domains)
  email: 0.6,
  // Emails useful for breach checks
  url: 0.5,
  // URLs are leaf nodes usually
  organization: 0.4
  // Orgs are context, not actionable
};
function computeEntityPriority(entity) {
  const typePriority = ENTITY_TYPE_PRIORITY[entity.type] || 0.5;
  const depthPenalty = Math.pow(0.8, entity.depth);
  const highQualitySources = ["crtsh", "securitytrails", "dns-deep", "shodan", "censys"];
  const sourceBonus = highQualitySources.includes(entity.source) ? 1.2 : 1;
  return typePriority * depthPenalty * sourceBonus;
}
async function runRecursiveDiscovery(rootDomain, initialObservations, connectors, config = {}) {
  const start = Date.now();
  const cfg = { ...DEFAULT_RECURSIVE_CONFIG, ...config };
  const allEntities = /* @__PURE__ */ new Map();
  const allObservations = [];
  const entityGraph = [];
  let apiCallsUsed = 0;
  let maxDepthReached = 0;
  let stoppedReason = "complete";
  const rootId = makeEntityId("domain", rootDomain);
  const rootEntity = {
    id: rootId,
    type: "domain",
    value: rootDomain,
    parentId: null,
    depth: 0,
    source: "root",
    discoveredAt: /* @__PURE__ */ new Date(),
    investigated: true,
    observationCount: initialObservations.length,
    childEntities: []
  };
  allEntities.set(rootId, rootEntity);
  const initialEntities = extractEntities(
    initialObservations,
    rootId,
    1,
    rootDomain,
    cfg.scopeRestriction
  );
  for (const entity of initialEntities) {
    if (!allEntities.has(entity.id) && cfg.entityTypes.includes(entity.type)) {
      allEntities.set(entity.id, entity);
      rootEntity.childEntities.push(entity.id);
      entityGraph.push({
        sourceId: rootId,
        targetId: entity.id,
        sourceType: "domain",
        targetType: entity.type,
        relationship: `discovered_${entity.type}`,
        discoveredBy: entity.source
      });
      cfg.onEntityDiscovered?.(entity);
    }
  }
  const queue = Array.from(allEntities.keys()).filter((id) => {
    const e = allEntities.get(id);
    return !e.investigated && e.depth <= cfg.maxDepth;
  });
  const sortQueue = () => {
    queue.sort((a, b) => {
      const ea = allEntities.get(a);
      const eb = allEntities.get(b);
      return computeEntityPriority(eb) - computeEntityPriority(ea);
    });
  };
  sortQueue();
  let consecutiveEmptyInvestigations = 0;
  const DIMINISHING_RETURNS_THRESHOLD = 5;
  while (queue.length > 0) {
    if (allEntities.size >= cfg.maxEntities) {
      stoppedReason = "max_entities";
      break;
    }
    if (apiCallsUsed >= cfg.maxApiCalls) {
      stoppedReason = "max_api_calls";
      break;
    }
    if (Date.now() - start > 3e5) {
      stoppedReason = "timeout";
      break;
    }
    if (consecutiveEmptyInvestigations >= DIMINISHING_RETURNS_THRESHOLD) {
      stoppedReason = "complete";
      break;
    }
    const entityId = queue.shift();
    const entity = allEntities.get(entityId);
    if (!entity || entity.investigated) continue;
    if (entity.depth > cfg.maxDepth) {
      stoppedReason = "max_depth";
      continue;
    }
    cfg.onProgress?.({
      totalEntities: allEntities.size,
      investigatedEntities: Array.from(allEntities.values()).filter((e) => e.investigated).length,
      pendingEntities: queue.length,
      currentDepth: entity.depth,
      apiCallsUsed,
      apiCallsBudget: cfg.maxApiCalls,
      currentEntity: entity.value,
      elapsedMs: Date.now() - start
    });
    const { observations, apiCalls } = await investigateEntity(entity, connectors, cfg);
    entity.investigated = true;
    entity.observationCount = observations.length;
    apiCallsUsed += apiCalls;
    maxDepthReached = Math.max(maxDepthReached, entity.depth);
    allObservations.push(...observations);
    cfg.onEntityInvestigated?.(entity, observations);
    let newEntitiesAdded = 0;
    if (entity.depth < cfg.maxDepth) {
      const newEntities = extractEntities(
        observations,
        entity.id,
        entity.depth + 1,
        rootDomain,
        cfg.scopeRestriction
      );
      for (const newEntity of newEntities) {
        if (!allEntities.has(newEntity.id) && cfg.entityTypes.includes(newEntity.type)) {
          if (allEntities.size >= cfg.maxEntities) break;
          allEntities.set(newEntity.id, newEntity);
          entity.childEntities.push(newEntity.id);
          entityGraph.push({
            sourceId: entity.id,
            targetId: newEntity.id,
            sourceType: entity.type,
            targetType: newEntity.type,
            relationship: `discovered_${newEntity.type}`,
            discoveredBy: newEntity.source
          });
          queue.push(newEntity.id);
          newEntitiesAdded++;
          cfg.onEntityDiscovered?.(newEntity);
        }
      }
    }
    if (observations.length === 0 && newEntitiesAdded === 0) {
      consecutiveEmptyInvestigations++;
    } else {
      consecutiveEmptyInvestigations = 0;
    }
    if (newEntitiesAdded > 0) {
      sortQueue();
    }
  }
  const byEntityType = {};
  const byDepth = {};
  for (const entity of Array.from(allEntities.values())) {
    byEntityType[entity.type] = (byEntityType[entity.type] || 0) + 1;
    byDepth[entity.depth] = (byDepth[entity.depth] || 0) + 1;
  }
  return {
    rootDomain,
    entities: Array.from(allEntities.values()),
    observations: allObservations,
    entityGraph,
    stats: {
      totalEntities: allEntities.size,
      investigatedEntities: Array.from(allEntities.values()).filter((e) => e.investigated).length,
      maxDepthReached,
      apiCallsUsed,
      byEntityType,
      byDepth,
      totalObservations: allObservations.length,
      durationMs: Date.now() - start,
      stoppedReason
    }
  };
}
export {
  DEFAULT_RECURSIVE_CONFIG,
  runRecursiveDiscovery
};
