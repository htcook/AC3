/**
 * Recursive Discovery Engine — SpiderFoot-style Entity Spidering
 *
 * Automatically discovers new entities from scan results and recursively
 * investigates them. This is the core "spider" behavior that makes the
 * platform competitive with SpiderFoot's automated OSINT collection.
 *
 * Entity Types:
 * - domain    → run full passive recon on discovered subdomains/related domains
 * - ip        → check Shodan, AbuseIPDB, GreyNoise, LeakIX for the IP
 * - email     → check HIBP, Hunter for breach/org data
 * - org       → check Hunter, social media for org presence
 * - url       → check VirusTotal, URLScan for URL reputation
 * - cert      → extract SANs and discover new domains
 *
 * Safety Controls:
 * - maxDepth: maximum recursion depth (default: 3)
 * - maxEntities: maximum total entities to investigate (default: 200)
 * - scopeRestriction: only recurse into entities related to the root domain
 * - rateLimitBudget: total API calls budget across all recursions
 * - entityDedup: never investigate the same entity twice
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

// ─── Entity Types ───────────────────────────────────────────────────────────

export type EntityType = "domain" | "ip" | "email" | "organization" | "url" | "certificate";

export interface DiscoveredEntity {
  id: string;
  type: EntityType;
  value: string;
  parentId: string | null;
  depth: number;
  source: string;
  discoveredAt: Date;
  investigated: boolean;
  observationCount: number;
  childEntities: string[];
}

export interface RecursiveDiscoveryConfig {
  maxDepth: number;
  maxEntities: number;
  maxApiCalls: number;
  scopeRestriction: "strict" | "related" | "unrestricted";
  entityTypes: EntityType[];
  apiKeys?: Record<string, string>;
  timeout?: number;
  onEntityDiscovered?: (entity: DiscoveredEntity) => void;
  onEntityInvestigated?: (entity: DiscoveredEntity, observations: AssetObservation[]) => void;
  onProgress?: (progress: RecursiveDiscoveryProgress) => void;
}

export interface RecursiveDiscoveryProgress {
  totalEntities: number;
  investigatedEntities: number;
  pendingEntities: number;
  currentDepth: number;
  apiCallsUsed: number;
  apiCallsBudget: number;
  currentEntity: string | null;
  elapsedMs: number;
}

export interface RecursiveDiscoveryResult {
  rootDomain: string;
  entities: DiscoveredEntity[];
  observations: AssetObservation[];
  entityGraph: EntityEdge[];
  stats: {
    totalEntities: number;
    investigatedEntities: number;
    maxDepthReached: number;
    apiCallsUsed: number;
    byEntityType: Record<string, number>;
    byDepth: Record<number, number>;
    totalObservations: number;
    durationMs: number;
    stoppedReason: "complete" | "max_entities" | "max_depth" | "max_api_calls" | "timeout";
  };
}

export interface EntityEdge {
  sourceId: string;
  targetId: string;
  sourceType: EntityType;
  targetType: EntityType;
  relationship: string;
  discoveredBy: string;
}

// ─── Default Config ─────────────────────────────────────────────────────────

export const DEFAULT_RECURSIVE_CONFIG: RecursiveDiscoveryConfig = {
  maxDepth: 3,
  maxEntities: 200,
  maxApiCalls: 500,
  scopeRestriction: "related",
  entityTypes: ["domain", "ip", "email", "organization", "url", "certificate"],
  timeout: 30000,
};

// ─── Entity Extraction ──────────────────────────────────────────────────────

function makeEntityId(type: EntityType, value: string): string {
  return createHash("sha256").update(`${type}|${value}`).digest("hex").slice(0, 16);
}

/**
 * Extract new entities from a set of observations
 */
function extractEntities(
  observations: AssetObservation[],
  parentId: string,
  depth: number,
  rootDomain: string,
  scopeRestriction: "strict" | "related" | "unrestricted"
): DiscoveredEntity[] {
  const entities: DiscoveredEntity[] = [];
  const seen = new Set<string>();

  for (const obs of observations) {
    // Extract domains/subdomains
    if (obs.assetType === "subdomain" || obs.assetType === "cname" || obs.assetType === "ns" || obs.assetType === "mx") {
      const hostname = obs.name;
      if (hostname && isInScope(hostname, rootDomain, scopeRestriction)) {
        const id = makeEntityId("domain", hostname);
        if (!seen.has(id)) {
          seen.add(id);
          entities.push({
            id, type: "domain", value: hostname, parentId, depth,
            source: obs.source, discoveredAt: new Date(),
            investigated: false, observationCount: 0, childEntities: [],
          });
        }
      }
    }

    // Extract IPs
    if (obs.ip) {
      const id = makeEntityId("ip", obs.ip);
      if (!seen.has(id)) {
        seen.add(id);
        entities.push({
          id, type: "ip", value: obs.ip, parentId, depth,
          source: obs.source, discoveredAt: new Date(),
          investigated: false, observationCount: 0, childEntities: [],
        });
      }
    }

    // Extract emails from evidence
    const evidence = obs.evidence || {};
    if (evidence.email && typeof evidence.email === "string") {
      const email = evidence.email;
      if (isEmailInScope(email, rootDomain, scopeRestriction)) {
        const id = makeEntityId("email", email);
        if (!seen.has(id)) {
          seen.add(id);
          entities.push({
            id, type: "email", value: email, parentId, depth,
            source: obs.source, discoveredAt: new Date(),
            investigated: false, observationCount: 0, childEntities: [],
          });
        }
      }
    }

    // Extract contact emails
    if (evidence.contactEmail && typeof evidence.contactEmail === "string") {
      const email = evidence.contactEmail;
      if (isEmailInScope(email, rootDomain, scopeRestriction)) {
        const id = makeEntityId("email", email);
        if (!seen.has(id)) {
          seen.add(id);
          entities.push({
            id, type: "email", value: email, parentId, depth,
            source: obs.source, discoveredAt: new Date(),
            investigated: false, observationCount: 0, childEntities: [],
          });
        }
      }
    }

    // Extract organizations
    if (evidence.organization && typeof evidence.organization === "string") {
      const org = evidence.organization;
      const id = makeEntityId("organization", org);
      if (!seen.has(id)) {
        seen.add(id);
        entities.push({
          id, type: "organization", value: org, parentId, depth,
          source: obs.source, discoveredAt: new Date(),
          investigated: false, observationCount: 0, childEntities: [],
        });
      }
    }

    // Extract URLs
    if (obs.assetType === "url" && obs.name) {
      const url = obs.name;
      if (isUrlInScope(url, rootDomain, scopeRestriction)) {
        const id = makeEntityId("url", url);
        if (!seen.has(id)) {
          seen.add(id);
          entities.push({
            id, type: "url", value: url, parentId, depth,
            source: obs.source, discoveredAt: new Date(),
            investigated: false, observationCount: 0, childEntities: [],
          });
        }
      }
    }

    // Extract certificate SANs as new domains
    if (obs.assetType === "certificate" && evidence.sans && Array.isArray(evidence.sans)) {
      for (const san of evidence.sans) {
        const cleanSan = san.replace(/^\*\./, ""); // Remove wildcard prefix
        if (isInScope(cleanSan, rootDomain, scopeRestriction)) {
          const id = makeEntityId("domain", cleanSan);
          if (!seen.has(id)) {
            seen.add(id);
            entities.push({
              id, type: "domain", value: cleanSan, parentId, depth,
              source: obs.source, discoveredAt: new Date(),
              investigated: false, observationCount: 0, childEntities: [],
            });
          }
        }
      }
    }

    // Extract SANs from subjectAlternativeNames
    if (evidence.subjectAlternativeNames && Array.isArray(evidence.subjectAlternativeNames)) {
      for (const san of evidence.subjectAlternativeNames) {
        const cleanSan = san.replace(/^\*\./, "");
        if (isInScope(cleanSan, rootDomain, scopeRestriction)) {
          const id = makeEntityId("domain", cleanSan);
          if (!seen.has(id)) {
            seen.add(id);
            entities.push({
              id, type: "domain", value: cleanSan, parentId, depth,
              source: obs.source, discoveredAt: new Date(),
              investigated: false, observationCount: 0, childEntities: [],
            });
          }
        }
      }
    }
  }

  return entities;
}

// ─── Scope Checking ─────────────────────────────────────────────────────────

function isInScope(hostname: string, rootDomain: string, scope: "strict" | "related" | "unrestricted"): boolean {
  if (scope === "unrestricted") return true;
  const h = hostname.toLowerCase();
  const r = rootDomain.toLowerCase();
  if (scope === "strict") return h === r || h.endsWith(`.${r}`);
  // "related" — same base domain or common parent
  const rootBase = getBaseDomain(r);
  const hostBase = getBaseDomain(h);
  return rootBase === hostBase || h.endsWith(`.${r}`) || h === r;
}

function isEmailInScope(email: string, rootDomain: string, scope: "strict" | "related" | "unrestricted"): boolean {
  if (scope === "unrestricted") return true;
  const domain = email.split("@")[1]?.toLowerCase();
  if (!domain) return false;
  return isInScope(domain, rootDomain, scope);
}

function isUrlInScope(url: string, rootDomain: string, scope: "strict" | "related" | "unrestricted"): boolean {
  if (scope === "unrestricted") return true;
  try {
    const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
    return isInScope(parsed.hostname, rootDomain, scope);
  } catch {
    return false;
  }
}

function getBaseDomain(hostname: string): string {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  // Handle common TLDs like co.uk, com.au
  const commonSLDs = ["co", "com", "org", "net", "gov", "edu", "ac"];
  if (parts.length >= 3 && commonSLDs.includes(parts[parts.length - 2])) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

// ─── Entity Investigation ───────────────────────────────────────────────────

/**
 * Investigate a single entity using appropriate connectors
 */
async function investigateEntity(
  entity: DiscoveredEntity,
  connectors: PassiveConnector[],
  config: RecursiveDiscoveryConfig
): Promise<{ observations: AssetObservation[]; apiCalls: number }> {
  const observations: AssetObservation[] = [];
  let apiCalls = 0;
  const timeout = config.timeout || 30000;

  // Select connectors based on entity type
  const selectedConnectors = selectConnectorsForEntity(entity, connectors);

  for (const connector of selectedConnectors) {
    try {
      const connectorConfig: ConnectorConfig = { timeout };
      if (connector.requiresApiKey && config.apiKeys) {
        connectorConfig.apiKey = config.apiKeys[connector.name];
        if (!connectorConfig.apiKey) continue; // Skip if no key available
      }

      let result: ConnectorResult;
      apiCalls++;

      switch (entity.type) {
        case "domain":
          result = await connector.collect(entity.value, connectorConfig);
          break;
        case "ip":
          // For IPs, use the IP as the domain parameter (connectors handle this)
          result = await connector.collect(entity.value, connectorConfig);
          break;
        case "email":
          // For emails, use the email domain
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
    } catch (err: any) {
      // Non-fatal — continue with next connector
      console.warn(`[RecursiveDiscovery] Connector ${connector.name} failed for ${entity.value}: ${err.message}`);
    }

    // Small delay between API calls
    await new Promise(r => setTimeout(r, 200));
  }

  return { observations, apiCalls };
}

/**
 * Select appropriate connectors for an entity type
 */
function selectConnectorsForEntity(entity: DiscoveredEntity, allConnectors: PassiveConnector[]): PassiveConnector[] {
  const connectorNames: string[] = [];

  switch (entity.type) {
    case "domain":
      // For discovered subdomains, run a subset of connectors (not the full suite)
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

  return allConnectors.filter(c => connectorNames.includes(c.name));
}

// ─── Entity Priority Scoring ─────────────────────────────────────────

/**
 * Priority weights by entity type.
 * Higher-priority types are investigated first because they
 * tend to yield more downstream entities and actionable intel.
 */
const ENTITY_TYPE_PRIORITY: Record<EntityType, number> = {
  domain: 1.0,       // Domains yield the most child entities
  ip: 0.8,           // IPs reveal services and ports
  certificate: 0.75, // Certs reveal SANs (new domains)
  email: 0.6,        // Emails useful for breach checks
  url: 0.5,          // URLs are leaf nodes usually
  organization: 0.4, // Orgs are context, not actionable
};

/**
 * Compute a priority score for an entity to determine investigation order.
 * Factors: entity type priority, depth penalty, source quality.
 */
function computeEntityPriority(entity: DiscoveredEntity): number {
  const typePriority = ENTITY_TYPE_PRIORITY[entity.type] || 0.5;

  // Depth penalty: deeper entities are less likely to be in-scope and useful
  // Score decays by 20% per depth level
  const depthPenalty = Math.pow(0.8, entity.depth);

  // Source quality bonus: entities from high-quality sources get priority
  const highQualitySources = ["crtsh", "securitytrails", "dns-deep", "shodan", "censys"];
  const sourceBonus = highQualitySources.includes(entity.source) ? 1.2 : 1.0;

  return typePriority * depthPenalty * sourceBonus;
}

// ─── Main Recursive Discovery ───────────────────────────────────────

/**
 * Run recursive discovery starting from initial observations
 */
export async function runRecursiveDiscovery(
  rootDomain: string,
  initialObservations: AssetObservation[],
  connectors: PassiveConnector[],
  config: Partial<RecursiveDiscoveryConfig> = {}
): Promise<RecursiveDiscoveryResult> {
  const start = Date.now();
  const cfg: RecursiveDiscoveryConfig = { ...DEFAULT_RECURSIVE_CONFIG, ...config };

  const allEntities = new Map<string, DiscoveredEntity>();
  const allObservations: AssetObservation[] = [];
  const entityGraph: EntityEdge[] = [];
  let apiCallsUsed = 0;
  let maxDepthReached = 0;
  let stoppedReason: RecursiveDiscoveryResult["stats"]["stoppedReason"] = "complete";

  // Create root entity
  const rootId = makeEntityId("domain", rootDomain);
  const rootEntity: DiscoveredEntity = {
    id: rootId,
    type: "domain",
    value: rootDomain,
    parentId: null,
    depth: 0,
    source: "root",
    discoveredAt: new Date(),
    investigated: true,
    observationCount: initialObservations.length,
    childEntities: [],
  };
  allEntities.set(rootId, rootEntity);

  // Extract initial entities from the first scan's observations
  const initialEntities = extractEntities(
    initialObservations, rootId, 1, rootDomain, cfg.scopeRestriction
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
        discoveredBy: entity.source,
      });
      cfg.onEntityDiscovered?.(entity);
    }
  }

  // Priority-weighted queue for recursive investigation
  // Entities are scored by type priority, depth penalty, and source quality
  const queue: string[] = Array.from(allEntities.keys()).filter(id => {
    const e = allEntities.get(id)!;
    return !e.investigated && e.depth <= cfg.maxDepth;
  });

  // Sort queue by priority score (highest first)
  const sortQueue = () => {
    queue.sort((a, b) => {
      const ea = allEntities.get(a)!;
      const eb = allEntities.get(b)!;
      return computeEntityPriority(eb) - computeEntityPriority(ea);
    });
  };
  sortQueue();

  // Diminishing returns detection
  let consecutiveEmptyInvestigations = 0;
  const DIMINISHING_RETURNS_THRESHOLD = 5; // Stop after 5 consecutive empty results

  while (queue.length > 0) {
    // Check stopping conditions
    if (allEntities.size >= cfg.maxEntities) {
      stoppedReason = "max_entities";
      break;
    }
    if (apiCallsUsed >= cfg.maxApiCalls) {
      stoppedReason = "max_api_calls";
      break;
    }
    if (Date.now() - start > 300000) { // 5 minute timeout
      stoppedReason = "timeout";
      break;
    }
    // Diminishing returns — stop if last N investigations found nothing new
    if (consecutiveEmptyInvestigations >= DIMINISHING_RETURNS_THRESHOLD) {
      stoppedReason = "complete"; // Graceful stop, not a hard limit
      break;
    }

    const entityId = queue.shift()!;
    const entity = allEntities.get(entityId);
    if (!entity || entity.investigated) continue;
    if (entity.depth > cfg.maxDepth) {
      stoppedReason = "max_depth";
      continue;
    }

    // Report progress
    cfg.onProgress?.({
      totalEntities: allEntities.size,
      investigatedEntities: Array.from(allEntities.values()).filter(e => e.investigated).length,
      pendingEntities: queue.length,
      currentDepth: entity.depth,
      apiCallsUsed,
      apiCallsBudget: cfg.maxApiCalls,
      currentEntity: entity.value,
      elapsedMs: Date.now() - start,
    });

    // Investigate the entity
    const { observations, apiCalls } = await investigateEntity(entity, connectors, cfg);
    entity.investigated = true;
    entity.observationCount = observations.length;
    apiCallsUsed += apiCalls;
    maxDepthReached = Math.max(maxDepthReached, entity.depth);

    allObservations.push(...observations);
    cfg.onEntityInvestigated?.(entity, observations);

    // Extract new entities from results (next depth level)
    let newEntitiesAdded = 0;
    if (entity.depth < cfg.maxDepth) {
      const newEntities = extractEntities(
        observations, entity.id, entity.depth + 1, rootDomain, cfg.scopeRestriction
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
            discoveredBy: newEntity.source,
          });
          queue.push(newEntity.id);
          newEntitiesAdded++;
          cfg.onEntityDiscovered?.(newEntity);
        }
      }
    }

    // Diminishing returns tracking
    if (observations.length === 0 && newEntitiesAdded === 0) {
      consecutiveEmptyInvestigations++;
    } else {
      consecutiveEmptyInvestigations = 0;
    }

    // Re-sort queue after adding new entities to maintain priority ordering
    if (newEntitiesAdded > 0) {
      sortQueue();
    }
  }

  // Build stats
  const byEntityType: Record<string, number> = {};
  const byDepth: Record<number, number> = {};
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
      investigatedEntities: Array.from(allEntities.values()).filter(e => e.investigated).length,
      maxDepthReached,
      apiCallsUsed,
      byEntityType,
      byDepth,
      totalObservations: allObservations.length,
      durationMs: Date.now() - start,
      stoppedReason,
    },
  };
}
