/**
 * Vendor Integration Registry — factory for creating vendor clients from DB config.
 * Central entry point for all vendor operations.
 */
import { eq } from "drizzle-orm";
import { getDb } from "../../db";
import { vendorIntegrations, vendorSyncEvents, vendorCachedData } from "../../../drizzle/schema";
import type { VendorIntegration, InsertVendorIntegration } from "../../../drizzle/schema";
import {
  BaseVendorClient,
  VendorError,
} from "./base-client";
import type {
  VendorAuthConfig,
  VendorConnectionConfig,
  VendorHealthResult,
  NormalizedVendorData,
  VendorName,
} from "./base-client";
import { CrowdStrikeClient, createCrowdStrikeClient } from "./crowdstrike";
import { SentinelOneClient, createSentinelOneClient } from "./sentinelone";
import { DefenderClient, createDefenderClient } from "./defender";
import { SplunkClient, createSplunkClient } from "./splunk";
import { XSOARClient, createXSOARClient } from "./xsoar";

// Re-export all types and clients
export {
  BaseVendorClient,
  VendorError,
};
export type {
  VendorAuthConfig,
  VendorConnectionConfig,
  VendorHealthResult,
  NormalizedVendorData,
  VendorName,
};
export {
  CrowdStrikeClient,
  SentinelOneClient,
  DefenderClient,
  SplunkClient,
  XSOARClient,
};

// ─── Vendor Metadata ─────────────────────────────────────────────────────────

export const VENDOR_METADATA: Record<VendorName, {
  displayName: string;
  category: string;
  authType: "oauth2" | "token" | "basic";
  requiredFields: string[];
  optionalFields: string[];
  defaultBaseUrl: string;
  description: string;
  capabilities: string[];
}> = {
  crowdstrike: {
    displayName: "CrowdStrike Falcon",
    category: "EDR",
    authType: "oauth2",
    requiredFields: ["clientId", "clientSecret"],
    optionalFields: ["region"],
    defaultBaseUrl: "https://api.crowdstrike.com",
    description: "Endpoint detection and response with cloud-native architecture",
    capabilities: ["hosts", "detections", "incidents", "iocs", "containment"],
  },
  sentinelone: {
    displayName: "SentinelOne",
    category: "EDR",
    authType: "token",
    requiredFields: ["apiToken"],
    optionalFields: [],
    defaultBaseUrl: "",
    description: "AI-powered endpoint protection with autonomous response",
    capabilities: ["agents", "threats", "activities", "mitigation", "network_isolation"],
  },
  defender: {
    displayName: "Microsoft Defender for Endpoint",
    category: "EDR",
    authType: "oauth2",
    requiredFields: ["tenantId", "clientId", "clientSecret"],
    optionalFields: [],
    defaultBaseUrl: "https://api.securitycenter.microsoft.com/api",
    description: "Enterprise endpoint security with advanced hunting (KQL)",
    capabilities: ["machines", "alerts", "vulnerabilities", "advanced_hunting", "isolation"],
  },
  splunk: {
    displayName: "Splunk Enterprise Security",
    category: "SIEM",
    authType: "token",
    requiredFields: ["apiToken"],
    optionalFields: [],
    defaultBaseUrl: "",
    description: "Security information and event management with SPL search",
    capabilities: ["search", "notable_events", "saved_searches", "correlation"],
  },
  xsoar: {
    displayName: "Palo Alto Cortex XSOAR",
    category: "SOAR",
    authType: "token",
    requiredFields: ["apiToken"],
    optionalFields: ["apiKeyId"],
    defaultBaseUrl: "",
    description: "Security orchestration, automation, and response platform",
    capabilities: ["incidents", "indicators", "playbooks", "war_room", "automation"],
  },
};

// ─── Client Cache ────────────────────────────────────────────────────────────

const clientCache = new Map<number, { client: BaseVendorClient; createdAt: number }>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// ─── Factory ─────────────────────────────────────────────────────────────────

export function createVendorClient(
  vendor: VendorName,
  authConfig: VendorAuthConfig,
  connectionConfig: VendorConnectionConfig
): BaseVendorClient {
  switch (vendor) {
    case "crowdstrike":
      return createCrowdStrikeClient(authConfig, connectionConfig);
    case "sentinelone":
      return createSentinelOneClient(authConfig, connectionConfig);
    case "defender":
      return createDefenderClient(authConfig, connectionConfig);
    case "splunk":
      return createSplunkClient(authConfig, connectionConfig);
    case "xsoar":
      return createXSOARClient(authConfig, connectionConfig);
    default:
      throw new VendorError(vendor, `Unknown vendor: ${vendor}`, "UNKNOWN_VENDOR");
  }
}

// ─── DB Operations ───────────────────────────────────────────────────────────

export async function listIntegrations(): Promise<VendorIntegration[]> {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(vendorIntegrations).orderBy(vendorIntegrations.vendor);
}

export async function getIntegration(id: number): Promise<VendorIntegration | null> {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(vendorIntegrations).where(eq(vendorIntegrations.id, id));
  return rows[0] || null;
}

export async function getIntegrationByVendor(vendor: VendorName): Promise<VendorIntegration | null> {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(vendorIntegrations).where(eq(vendorIntegrations.vendor, vendor));
  return rows[0] || null;
}

export async function upsertIntegration(data: {
  vendor: VendorName;
  displayName: string;
  authConfig: VendorAuthConfig;
  connectionConfig: VendorConnectionConfig;
  enabled?: boolean;
  syncEnabled?: boolean;
  syncIntervalMinutes?: number;
  createdBy?: string;
}): Promise<number> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const existing = await getIntegrationByVendor(data.vendor);

  if (existing) {
    await db.update(vendorIntegrations)
      .set({
        displayName: data.displayName,
        authConfig: data.authConfig,
        connectionConfig: data.connectionConfig,
        enabled: data.enabled ?? existing.enabled,
        syncEnabled: data.syncEnabled ?? existing.syncEnabled,
        syncIntervalMinutes: data.syncIntervalMinutes ?? existing.syncIntervalMinutes,
      })
      .where(eq(vendorIntegrations.id, existing.id));
    // Clear client cache
    clientCache.delete(existing.id);
    return existing.id;
  }

  const result = await db.insert(vendorIntegrations).values({
    vendor: data.vendor,
    displayName: data.displayName,
    authConfig: data.authConfig,
    connectionConfig: data.connectionConfig,
    enabled: data.enabled ?? false,
    syncEnabled: data.syncEnabled ?? false,
    syncIntervalMinutes: data.syncIntervalMinutes ?? 60,
    createdBy: data.createdBy,
  });

  return Number(result[0].insertId);
}

export async function deleteIntegration(id: number): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.delete(vendorIntegrations).where(eq(vendorIntegrations.id, id));
  clientCache.delete(id);
}

export async function updateIntegrationStatus(
  id: number,
  status: "connected" | "disconnected" | "error" | "unconfigured",
  error?: string
): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.update(vendorIntegrations)
    .set({
      status,
      lastHealthCheck: Date.now(),
      lastError: error || null,
    })
    .where(eq(vendorIntegrations.id, id));
}

// ─── Get Client from DB ──────────────────────────────────────────────────────

export async function getClientForIntegration(id: number): Promise<BaseVendorClient> {
  // Check cache
  const cached = clientCache.get(id);
  if (cached && Date.now() - cached.createdAt < CACHE_TTL) {
    return cached.client;
  }

  const integration = await getIntegration(id);
  if (!integration) throw new VendorError("crowdstrike", `Integration ${id} not found`, "NOT_FOUND");
  if (!integration.enabled) throw new VendorError(integration.vendor, `Integration ${integration.vendor} is disabled`, "DISABLED");

  const authConfig = (integration.authConfig || {}) as VendorAuthConfig;
  const connConfig = (integration.connectionConfig || {}) as VendorConnectionConfig;

  const client = createVendorClient(integration.vendor, authConfig, connConfig);

  clientCache.set(id, { client, createdAt: Date.now() });
  return client;
}

// ─── Health Check All ────────────────────────────────────────────────────────

export async function healthCheckAll(): Promise<Array<{ vendor: VendorName; id: number; result: VendorHealthResult }>> {
  const integrations = await listIntegrations();
  const results: Array<{ vendor: VendorName; id: number; result: VendorHealthResult }> = [];

  for (const integration of integrations) {
    if (!integration.enabled) {
      results.push({
        vendor: integration.vendor,
        id: integration.id,
        result: { status: "disconnected", latencyMs: 0, message: "Integration is disabled" },
      });
      continue;
    }

    try {
      const client = await getClientForIntegration(integration.id);
      const result = await client.healthCheck();
      await updateIntegrationStatus(integration.id, result.status, result.status === "error" ? result.message : undefined);
      results.push({ vendor: integration.vendor, id: integration.id, result });
    } catch (error) {
      const result: VendorHealthResult = {
        status: "error",
        latencyMs: 0,
        message: (error as Error).message,
      };
      await updateIntegrationStatus(integration.id, "error", result.message);
      results.push({ vendor: integration.vendor, id: integration.id, result });
    }
  }

  return results;
}

// ─── Sync Event Logging ──────────────────────────────────────────────────────

export async function logSyncEvent(data: {
  integrationId: number;
  eventType: string;
  status: "success" | "partial" | "failed";
  recordsProcessed?: number;
  recordsFailed?: number;
  summary?: unknown;
  errorMessage?: string;
  durationMs?: number;
  triggeredBy?: string;
}): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.insert(vendorSyncEvents).values({
    integrationId: data.integrationId,
    eventType: data.eventType as any,
    status: data.status,
    recordsProcessed: data.recordsProcessed ?? 0,
    recordsFailed: data.recordsFailed ?? 0,
    summary: data.summary,
    errorMessage: data.errorMessage,
    durationMs: data.durationMs,
    triggeredBy: data.triggeredBy,
  });
}

// ─── Cache Vendor Data ───────────────────────────────────────────────────────

export async function cacheVendorData(
  integrationId: number,
  items: NormalizedVendorData[]
): Promise<number> {
  const db = await getDb();
  if (!db) return 0;
  if (!items.length) return 0;

  const values = items.map((item) => ({
    integrationId,
    dataType: item.type as any,
    externalId: item.id,
    title: item.title?.slice(0, 512),
    severity: item.severity as any,
    status: item.status?.slice(0, 64),
    rawData: item.raw,
    normalizedData: item,
    hostname: item.hostname?.slice(0, 255),
    ipAddress: item.ipAddress?.slice(0, 45),
    domain: item.domain?.slice(0, 255),
    mitreAttackId: item.mitreAttackId?.slice(0, 32),
    detectedAt: item.detectedAt,
    lastUpdatedAt: Date.now(),
  }));

  // Insert in batches of 50
  let inserted = 0;
  for (let i = 0; i < values.length; i += 50) {
    const batch = values.slice(i, i + 50);
    await db.insert(vendorCachedData).values(batch);
    inserted += batch.length;
  }

  return inserted;
}

export async function queryCachedData(filters: {
  integrationId?: number;
  dataType?: string;
  hostname?: string;
  ipAddress?: string;
  severity?: string;
  limit?: number;
}): Promise<Array<typeof vendorCachedData.$inferSelect>> {
  const db = await getDb();
  if (!db) return [];

  let query = db.select().from(vendorCachedData);

  // Build conditions
  const conditions = [];
  if (filters.integrationId) conditions.push(eq(vendorCachedData.integrationId, filters.integrationId));
  if (filters.dataType) conditions.push(eq(vendorCachedData.dataType, filters.dataType as any));
  if (filters.hostname) conditions.push(eq(vendorCachedData.hostname, filters.hostname));
  if (filters.ipAddress) conditions.push(eq(vendorCachedData.ipAddress, filters.ipAddress));
  if (filters.severity) conditions.push(eq(vendorCachedData.severity, filters.severity as any));

  if (conditions.length === 1) {
    query = query.where(conditions[0]) as any;
  }

  return query.limit(filters.limit ?? 100);
}
