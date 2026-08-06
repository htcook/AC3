/**
 * Integration Registry — Central Orchestrator (DB-Backed)
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * The single entry point for all integration management. Ties together:
 *   - Built-in catalog (pre-registered platform integrations)
 *   - Auto-discovery engine (LLM-powered API classification)
 *   - Pipeline wiring engine (auto-connects to pipeline stages)
 *   - Value assessment (overlap analysis, coverage gaps)
 *   - Customer review workflow (propose → review → approve → activate)
 * 
 * Customer integrations are persisted to the `customer_integrations` DB table.
 * Built-in integrations are always available from the in-memory catalog.
 * Discovery/wiring caches are transient (in-memory) since they're session-scoped.
 */

import { BUILTIN_CATALOG, CATALOG_BY_ID, type CatalogEntry } from "./builtin-catalog";
import { runDiscoveryPipeline, recordClassificationFeedback, type ApiProbeInput, type DiscoveryPipelineResult } from "./auto-discovery-engine";
import { generateWiringConfig, analyzePipelineCoverage, compareIntegrationValue, type WiringProposal, type PipelineCoverageReport, type ValueComparisonResult } from "./pipeline-wiring-engine";
import type {
  IntegrationDefinition,
  IntegrationCategory,
  IntegrationStatus,
  PipelineStage,
  CustomerReview,
  IntegrationCredential,
  ClassificationFeedback,
  IntegrationValueAssessment,
} from "./types";
import { CATEGORY_METADATA, PIPELINE_STAGE_METADATA } from "./types";

// ═══════════════════════════════════════════════════════════════════════
// §1 — DB HELPERS (lazy import to avoid circular deps)
// ═══════════════════════════════════════════════════════════════════════

async function db() {
  return import("../../db");
}

// ═══════════════════════════════════════════════════════════════════════
// §1b — TRANSIENT CACHES (session-scoped, not persisted)
// ═══════════════════════════════════════════════════════════════════════

/** Discovery results cache (keyed by discovery ID) — transient per session */
const discoveryCache = new Map<string, DiscoveryPipelineResult>();

/** Wiring proposals cache (keyed by discovery ID) — transient per session */
const wiringCache = new Map<string, WiringProposal>();

/** Credential store (keyed by `${integrationId}:${tenantId}`) — in-memory for fast access */
const credentialStore = new Map<string, IntegrationCredential>();

// ═══════════════════════════════════════════════════════════════════════
// §2 — CONVERSION: DB row ↔ IntegrationDefinition
// ═══════════════════════════════════════════════════════════════════════

function dbRowToDefinition(row: any): IntegrationDefinition {
  return {
    id: row.integrationId,
    name: row.name,
    displayName: row.displayName,
    description: row.description || "",
    category: row.category as IntegrationCategory,
    licenseModel: row.licenseModel || "custom",
    status: row.status as IntegrationStatus,
    auth: row.authConfig || {
      method: row.authMethod || "api_key",
      fields: { apiKey: { label: "API Key", placeholder: "Enter your API key", required: true, sensitive: true } },
      injection: "header",
      headerName: "X-API-Key",
    },
    endpoint: row.endpointConfig || {
      baseUrl: row.endpointBaseUrl || "",
      dataFormat: "json",
      timeout: 30_000,
    },
    capabilities: row.capabilities || {
      dataTypes: row.dataTypes || [],
      pipelineStages: row.pipelineStages || [],
      enhancesModules: [],
      inputTypes: row.inputTypes || [],
      outputTypes: row.outputTypes || [],
      supportsPassiveOnly: true,
      requiresActiveProbing: false,
    },
    valueAssessment: row.valueAssessment,
    autoDiscovery: row.autoDiscoveryResult,
    customerReview: row.customerReview,
    pipelineWiring: row.pipelineWiring,
    addedBy: row.addedBy || "customer",
    allowCustomerOverride: true,
    isBuiltIn: Boolean(row.isBuiltIn),
    tags: row.tags || [row.category, ...(row.pipelineStages || [])],
    lastError: row.lastError || undefined,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function definitionToDbRow(def: IntegrationDefinition): any {
  return {
    integrationId: def.id,
    name: def.name,
    displayName: def.displayName,
    description: def.description,
    category: def.category,
    licenseModel: def.licenseModel || "custom",
    status: def.status,
    authMethod: def.auth?.method || "api_key",
    authConfig: def.auth,
    endpointBaseUrl: def.endpoint?.baseUrl || "",
    endpointConfig: def.endpoint,
    pipelineStages: def.capabilities?.pipelineStages || [],
    dataTypes: def.capabilities?.dataTypes || [],
    inputTypes: def.capabilities?.inputTypes || [],
    outputTypes: def.capabilities?.outputTypes || [],
    capabilities: def.capabilities,
    pipelineWiring: def.pipelineWiring,
    valueAssessment: def.valueAssessment,
    autoDiscoveryResult: def.autoDiscovery,
    customerReview: def.customerReview,
    tags: def.tags,
    priority: 3,
    isBuiltIn: 0,
    addedBy: def.addedBy || "customer",
    lastError: def.lastError || null,
    createdAt: def.createdAt || Date.now(),
    updatedAt: def.updatedAt || Date.now(),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — REGISTRY QUERIES (DB-backed)
// ═══════════════════════════════════════════════════════════════════════

/** Get all integrations (built-in + customer-added from DB) */
export async function getAllIntegrations(): Promise<Array<CatalogEntry | IntegrationDefinition>> {
  try {
    const { getAllCustomerIntegrations } = await db();
    const dbRows = await getAllCustomerIntegrations();
    return [...BUILTIN_CATALOG, ...dbRows.map(dbRowToDefinition)];
  } catch {
    return [...BUILTIN_CATALOG];
  }
}

/** Get a specific integration by ID */
export async function getIntegration(id: string): Promise<CatalogEntry | IntegrationDefinition | undefined> {
  const builtIn = CATALOG_BY_ID.get(id);
  if (builtIn) return builtIn;
  try {
    const { getCustomerIntegrationByIntegrationId } = await db();
    const row = await getCustomerIntegrationByIntegrationId(id);
    return row ? dbRowToDefinition(row) : undefined;
  } catch {
    return undefined;
  }
}

/** Get all integrations for a category */
export async function getIntegrationsByCategory(category: IntegrationCategory): Promise<Array<CatalogEntry | IntegrationDefinition>> {
  const builtIn = BUILTIN_CATALOG.filter(e => e.category === category);
  try {
    const { getCustomerIntegrationsByCategory } = await db();
    const dbRows = await getCustomerIntegrationsByCategory(category);
    return [...builtIn, ...dbRows.map(dbRowToDefinition)];
  } catch {
    return builtIn;
  }
}

/** Get all integrations for a pipeline stage */
export async function getIntegrationsByStage(stage: PipelineStage): Promise<Array<CatalogEntry | IntegrationDefinition>> {
  const builtIn = BUILTIN_CATALOG.filter(e => e.pipelineStages.includes(stage));
  try {
    const { getActiveCustomerIntegrationsByStage } = await db();
    const dbRows = await getActiveCustomerIntegrationsByStage(stage);
    return [...builtIn, ...dbRows.map(dbRowToDefinition)];
  } catch {
    return builtIn;
  }
}

/** Get all customer-added integrations from DB */
export async function getCustomerIntegrations(): Promise<IntegrationDefinition[]> {
  try {
    const { getAllCustomerIntegrations } = await db();
    const dbRows = await getAllCustomerIntegrations();
    return dbRows.map(dbRowToDefinition);
  } catch {
    return [];
  }
}

/** Get integrations by status from DB */
export async function getIntegrationsByStatus(status: IntegrationStatus): Promise<IntegrationDefinition[]> {
  try {
    const { getCustomerIntegrationsByStatus } = await db();
    const dbRows = await getCustomerIntegrationsByStatus(status);
    return dbRows.map(dbRowToDefinition);
  } catch {
    return [];
  }
}

/** Get category summary (count per category) */
export async function getCategorySummary(): Promise<Array<{
  category: IntegrationCategory;
  label: string;
  description: string;
  icon: string;
  color: string;
  builtInCount: number;
  customerCount: number;
  totalCount: number;
}>> {
  let customerList: IntegrationDefinition[] = [];
  try {
    customerList = await getCustomerIntegrations();
  } catch { /* fallback to empty */ }

  const categories = Object.keys(CATEGORY_METADATA) as IntegrationCategory[];
  return categories.map(cat => {
    const meta = CATEGORY_METADATA[cat];
    const builtIn = BUILTIN_CATALOG.filter(e => e.category === cat).length;
    const custom = customerList.filter(e => e.category === cat).length;
    return {
      category: cat,
      ...meta,
      builtInCount: builtIn,
      customerCount: custom,
      totalCount: builtIn + custom,
    };
  });
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — DISCOVERY & CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Discover and classify a new API source.
 * Returns a proposal for customer review — does NOT auto-wire.
 */
export async function discoverNewSource(input: ApiProbeInput): Promise<{
  discoveryId: string;
  result: DiscoveryPipelineResult;
  wiringProposal: WiringProposal;
  valueComparison: ValueComparisonResult;
}> {
  const result = await runDiscoveryPipeline(input);

  const discoveryId = `disc_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  discoveryCache.set(discoveryId, result);

  const wiringProposal = generateWiringConfig({
    id: result.classification.suggestedName,
    category: result.classification.category,
    pipelineStages: result.classification.pipelineStages,
    dataTypes: result.classification.dataTypes,
    requiresActiveProbing: !result.classification.hasOpenApiSpec,
    valueAssessment: result.classification.valueAssessment,
  });
  wiringCache.set(discoveryId, wiringProposal);

  const existingForComparison = BUILTIN_CATALOG.map(e => ({
    id: e.id,
    name: e.displayName,
    category: e.category,
    dataTypes: e.dataTypes,
    stages: e.pipelineStages,
  }));
  const valueComparison = compareIntegrationValue(
    {
      id: result.classification.suggestedName,
      name: result.classification.suggestedDisplayName,
      category: result.classification.category,
      dataTypes: result.classification.dataTypes,
      stages: result.classification.pipelineStages,
    },
    existingForComparison,
  );

  return { discoveryId, result, wiringProposal, valueComparison };
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — CUSTOMER REVIEW & APPROVAL (DB-persisted)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Submit a customer review for a discovered integration.
 * If approved, persists the integration to the DB and wires it into the pipeline.
 * If corrections were made, records feedback for future learning.
 */
export async function submitCustomerReview(
  discoveryId: string,
  review: CustomerReview,
): Promise<{ success: boolean; integration?: IntegrationDefinition; error?: string }> {
  const discovery = discoveryCache.get(discoveryId);
  if (!discovery) {
    return { success: false, error: `Discovery ${discoveryId} not found or expired` };
  }

  const classification = discovery.classification;
  const wiring = wiringCache.get(discoveryId);

  // Record feedback if customer made corrections
  const categoryChanged = review.correctedCategory && review.correctedCategory !== classification.category;
  const stagesChanged = review.correctedPipelineStages &&
    JSON.stringify(review.correctedPipelineStages.sort()) !== JSON.stringify(classification.pipelineStages.sort());

  if (categoryChanged || stagesChanged) {
    const feedback: ClassificationFeedback = {
      discoveryId,
      originalCategory: classification.category,
      originalStages: classification.pipelineStages,
      correctedCategory: review.correctedCategory || classification.category,
      correctedStages: review.correctedPipelineStages || classification.pipelineStages,
      apiCharacteristics: {
        hasOpenApiSpec: classification.hasOpenApiSpec,
        detectedAuthMethod: classification.detectedAuthMethod,
        dataTypes: classification.dataTypes,
        confidence: classification.confidence,
      },
      createdAt: Date.now(),
    };
    recordClassificationFeedback(feedback);
  }

  if (!review.approved) {
    return { success: true }; // Rejected — no integration created
  }

  // Apply corrections
  const finalCategory = review.correctedCategory || classification.category;
  const finalStages = review.correctedPipelineStages || classification.pipelineStages;
  const finalDataTypes = review.correctedDataTypes || classification.dataTypes;

  // Re-generate wiring if corrections were made
  let finalWiring = wiring?.config;
  if (categoryChanged || stagesChanged) {
    const newWiring = generateWiringConfig({
      id: classification.suggestedName,
      category: finalCategory,
      pipelineStages: finalStages,
      dataTypes: finalDataTypes,
      requiresActiveProbing: false,
      valueAssessment: classification.valueAssessment,
    });
    finalWiring = newWiring.config;
  }

  // Create the integration definition
  const integration: IntegrationDefinition = {
    id: classification.suggestedName,
    name: classification.suggestedName,
    displayName: classification.suggestedDisplayName,
    description: classification.description,
    category: finalCategory,
    licenseModel: "custom",
    status: "approved",
    auth: {
      method: classification.detectedAuthMethod,
      fields: {
        apiKey: {
          label: "API Key",
          placeholder: "Enter your API key",
          required: true,
          sensitive: true,
        },
      },
      injection: "header",
      headerName: "X-API-Key",
    },
    endpoint: {
      baseUrl: discovery.probe.reachable ? "" : "",
      dataFormat: "json",
      rateLimit: classification.detectedRateLimit,
      timeout: 30_000,
    },
    capabilities: {
      dataTypes: finalDataTypes,
      pipelineStages: finalStages,
      enhancesModules: [],
      inputTypes: classification.inputTypes,
      outputTypes: classification.outputTypes,
      supportsPassiveOnly: true,
      requiresActiveProbing: false,
    },
    valueAssessment: classification.valueAssessment,
    autoDiscovery: classification,
    customerReview: review,
    pipelineWiring: finalWiring,
    addedBy: "customer",
    allowCustomerOverride: true,
    isBuiltIn: false,
    tags: [finalCategory, ...finalStages],
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };

  // Persist to DB
  try {
    const { createCustomerIntegration } = await db();
    await createCustomerIntegration(definitionToDbRow(integration));
  } catch (err: any) {
    console.error(`[IntegrationRegistry] Failed to persist integration to DB: ${err.message}`);
    return { success: false, error: `Database error: ${err.message}` };
  }

  // Clean up transient caches
  discoveryCache.delete(discoveryId);
  wiringCache.delete(discoveryId);

  return { success: true, integration };
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — INTEGRATION LIFECYCLE (DB-backed)
// ═══════════════════════════════════════════════════════════════════════

/** Activate an approved integration (wire into live pipeline) */
export async function activateIntegration(id: string): Promise<{ success: boolean; error?: string }> {
  try {
    const { getCustomerIntegrationByIntegrationId, updateCustomerIntegration } = await db();
    const row = await getCustomerIntegrationByIntegrationId(id);
    if (!row) return { success: false, error: `Integration ${id} not found` };
    if (row.status !== "approved" && row.status !== "paused") {
      return { success: false, error: `Integration must be approved or paused to activate (current: ${row.status})` };
    }
    await updateCustomerIntegration(id, { status: "active" });
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

/** Pause an active integration */
export async function pauseIntegration(id: string): Promise<{ success: boolean; error?: string }> {
  try {
    const { getCustomerIntegrationByIntegrationId, updateCustomerIntegration } = await db();
    const row = await getCustomerIntegrationByIntegrationId(id);
    if (!row) return { success: false, error: `Integration ${id} not found` };
    if (row.status !== "active") {
      return { success: false, error: `Integration must be active to pause (current: ${row.status})` };
    }
    await updateCustomerIntegration(id, { status: "paused" });
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

/** Remove a customer integration */
export async function removeIntegration(id: string): Promise<{ success: boolean; error?: string }> {
  try {
    const { getCustomerIntegrationByIntegrationId, deleteCustomerIntegration } = await db();
    const row = await getCustomerIntegrationByIntegrationId(id);
    if (!row) return { success: false, error: `Integration ${id} not found` };
    await deleteCustomerIntegration(id);
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

/** Update integration status in DB */
export async function updateIntegrationStatus(id: string, status: IntegrationStatus, error?: string): Promise<void> {
  try {
    const { updateCustomerIntegration } = await db();
    await updateCustomerIntegration(id, {
      status: status as any,
      ...(error ? { lastError: error } : {}),
    });
  } catch (err: any) {
    console.error(`[IntegrationRegistry] Failed to update status for ${id}: ${err.message}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — CREDENTIAL MANAGEMENT (in-memory for fast access)
// ═══════════════════════════════════════════════════════════════════════

/** Store credentials for an integration */
export function storeCredentials(cred: IntegrationCredential): void {
  const key = `${cred.integrationId}:${cred.tenantId ?? "platform"}`;
  credentialStore.set(key, cred);
}

/** Get credentials for an integration */
export function getCredentials(integrationId: string, tenantId?: string): IntegrationCredential | undefined {
  const tenantKey = `${integrationId}:${tenantId ?? "platform"}`;
  const platformKey = `${integrationId}:platform`;
  return credentialStore.get(tenantKey) || credentialStore.get(platformKey);
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — PIPELINE COVERAGE & HEALTH (DB-backed)
// ═══════════════════════════════════════════════════════════════════════

/** Get pipeline coverage report */
export async function getPipelineCoverageReport(): Promise<PipelineCoverageReport> {
  let customerList: IntegrationDefinition[] = [];
  try {
    const { getCustomerIntegrationsByStatus } = await db();
    const activeRows = await getCustomerIntegrationsByStatus("active");
    customerList = activeRows.map(dbRowToDefinition);
  } catch { /* fallback to empty */ }

  const activeIntegrations = [
    ...BUILTIN_CATALOG.map(e => ({
      id: e.id,
      category: e.category,
      stages: e.pipelineStages,
      dataTypes: e.dataTypes,
    })),
    ...customerList.map(e => ({
      id: e.id,
      category: e.category,
      stages: e.capabilities?.pipelineStages || [],
      dataTypes: e.capabilities?.dataTypes || [],
    })),
  ];
  return analyzePipelineCoverage(activeIntegrations);
}

/** Get integration health summary (DB-backed) */
export async function getHealthSummary(): Promise<{
  total: number;
  active: number;
  proposed: number;
  paused: number;
  error: number;
  builtIn: number;
  customer: number;
}> {
  try {
    const { getCustomerIntegrationStats } = await db();
    const stats = await getCustomerIntegrationStats();
    return {
      total: BUILTIN_CATALOG.length + stats.total,
      active: stats.active,
      proposed: stats.proposed,
      paused: stats.paused,
      error: stats.error,
      builtIn: BUILTIN_CATALOG.length,
      customer: stats.total,
    };
  } catch {
    return {
      total: BUILTIN_CATALOG.length,
      active: 0, proposed: 0, paused: 0, error: 0,
      builtIn: BUILTIN_CATALOG.length,
      customer: 0,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §9 — EXPORTS
// ═══════════════════════════════════════════════════════════════════════

export {
  BUILTIN_CATALOG,
  CATALOG_BY_ID,
  CATEGORY_METADATA,
  PIPELINE_STAGE_METADATA,
};

export type {
  IntegrationDefinition,
  IntegrationCategory,
  IntegrationStatus,
  PipelineStage,
  CatalogEntry,
  CustomerReview,
  IntegrationCredential,
  WiringProposal,
  PipelineCoverageReport,
  ValueComparisonResult,
  ApiProbeInput,
  DiscoveryPipelineResult,
};
