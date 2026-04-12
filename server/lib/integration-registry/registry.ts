/**
 * Integration Registry — Central Orchestrator
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * The single entry point for all integration management. Ties together:
 *   - Built-in catalog (pre-registered platform integrations)
 *   - Auto-discovery engine (LLM-powered API classification)
 *   - Pipeline wiring engine (auto-connects to pipeline stages)
 *   - Value assessment (overlap analysis, coverage gaps)
 *   - Customer review workflow (propose → review → approve → activate)
 * 
 * State is held in-memory with DB persistence for customer-added integrations.
 * Built-in integrations are always available from the catalog.
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
// §1 — IN-MEMORY STORE
// ═══════════════════════════════════════════════════════════════════════

/** Customer-added integrations (keyed by integration ID) */
const customerIntegrations = new Map<string, IntegrationDefinition>();

/** Credential store (keyed by `${integrationId}:${tenantId}`) */
const credentialStore = new Map<string, IntegrationCredential>();

/** Discovery results cache (keyed by discovery ID) */
const discoveryCache = new Map<string, DiscoveryPipelineResult>();

/** Wiring proposals cache (keyed by integration ID) */
const wiringCache = new Map<string, WiringProposal>();

// ═══════════════════════════════════════════════════════════════════════
// §2 — REGISTRY QUERIES
// ═══════════════════════════════════════════════════════════════════════

/** Get all integrations (built-in + customer-added) */
export function getAllIntegrations(): Array<CatalogEntry | IntegrationDefinition> {
  return [...BUILTIN_CATALOG, ...customerIntegrations.values()];
}

/** Get a specific integration by ID */
export function getIntegration(id: string): CatalogEntry | IntegrationDefinition | undefined {
  return CATALOG_BY_ID.get(id) || customerIntegrations.get(id);
}

/** Get all integrations for a category */
export function getIntegrationsByCategory(category: IntegrationCategory): Array<CatalogEntry | IntegrationDefinition> {
  const builtIn = BUILTIN_CATALOG.filter(e => e.category === category);
  const custom = [...customerIntegrations.values()].filter(e => e.category === category);
  return [...builtIn, ...custom];
}

/** Get all integrations for a pipeline stage */
export function getIntegrationsByStage(stage: PipelineStage): Array<CatalogEntry | IntegrationDefinition> {
  const builtIn = BUILTIN_CATALOG.filter(e => e.pipelineStages.includes(stage));
  const custom = [...customerIntegrations.values()].filter(e =>
    e.capabilities.pipelineStages.includes(stage) || e.pipelineWiring?.stages.includes(stage)
  );
  return [...builtIn, ...custom];
}

/** Get all customer-added integrations */
export function getCustomerIntegrations(): IntegrationDefinition[] {
  return [...customerIntegrations.values()];
}

/** Get integrations by status */
export function getIntegrationsByStatus(status: IntegrationStatus): IntegrationDefinition[] {
  return [...customerIntegrations.values()].filter(e => e.status === status);
}

/** Get category summary (count per category) */
export function getCategorySummary(): Array<{
  category: IntegrationCategory;
  label: string;
  description: string;
  icon: string;
  color: string;
  builtInCount: number;
  customerCount: number;
  totalCount: number;
}> {
  const categories = Object.keys(CATEGORY_METADATA) as IntegrationCategory[];
  return categories.map(cat => {
    const meta = CATEGORY_METADATA[cat];
    const builtIn = BUILTIN_CATALOG.filter(e => e.category === cat).length;
    const custom = [...customerIntegrations.values()].filter(e => e.category === cat).length;
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
// §3 — DISCOVERY & CLASSIFICATION
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
  // Run the discovery pipeline
  const result = await runDiscoveryPipeline(input);

  const discoveryId = `disc_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  discoveryCache.set(discoveryId, result);

  // Generate wiring proposal
  const wiringProposal = generateWiringConfig({
    id: result.classification.suggestedName,
    category: result.classification.category,
    pipelineStages: result.classification.pipelineStages,
    dataTypes: result.classification.dataTypes,
    requiresActiveProbing: !result.classification.hasOpenApiSpec, // Heuristic
    valueAssessment: result.classification.valueAssessment,
  });
  wiringCache.set(discoveryId, wiringProposal);

  // Compare value against existing integrations
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
// §4 — CUSTOMER REVIEW & APPROVAL
// ═══════════════════════════════════════════════════════════════════════

/**
 * Submit a customer review for a discovered integration.
 * If approved, creates the integration and wires it into the pipeline.
 * If corrections were made, records feedback for future learning.
 */
export function submitCustomerReview(
  discoveryId: string,
  review: CustomerReview,
): { success: boolean; integration?: IntegrationDefinition; error?: string } {
  const discovery = discoveryCache.get(discoveryId);
  if (!discovery) {
    return { success: false, error: `Discovery ${discoveryId} not found` };
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

  customerIntegrations.set(integration.id, integration);

  return { success: true, integration };
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — INTEGRATION LIFECYCLE
// ═══════════════════════════════════════════════════════════════════════

/** Activate an approved integration (wire into live pipeline) */
export function activateIntegration(id: string): { success: boolean; error?: string } {
  const integration = customerIntegrations.get(id);
  if (!integration) return { success: false, error: `Integration ${id} not found` };
  if (integration.status !== "approved" && integration.status !== "paused") {
    return { success: false, error: `Integration must be approved or paused to activate (current: ${integration.status})` };
  }
  integration.status = "active";
  integration.updatedAt = Date.now();
  return { success: true };
}

/** Pause an active integration */
export function pauseIntegration(id: string): { success: boolean; error?: string } {
  const integration = customerIntegrations.get(id);
  if (!integration) return { success: false, error: `Integration ${id} not found` };
  if (integration.status !== "active") {
    return { success: false, error: `Integration must be active to pause (current: ${integration.status})` };
  }
  integration.status = "paused";
  integration.updatedAt = Date.now();
  return { success: true };
}

/** Remove a customer integration */
export function removeIntegration(id: string): { success: boolean; error?: string } {
  if (!customerIntegrations.has(id)) {
    return { success: false, error: `Integration ${id} not found` };
  }
  customerIntegrations.delete(id);
  return { success: true };
}

/** Update integration status */
export function updateIntegrationStatus(id: string, status: IntegrationStatus, error?: string): void {
  const integration = customerIntegrations.get(id);
  if (integration) {
    integration.status = status;
    integration.updatedAt = Date.now();
    if (error) integration.lastError = error;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — CREDENTIAL MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════

/** Store credentials for an integration */
export function storeCredentials(cred: IntegrationCredential): void {
  const key = `${cred.integrationId}:${cred.tenantId ?? "platform"}`;
  credentialStore.set(key, cred);
}

/** Get credentials for an integration */
export function getCredentials(integrationId: string, tenantId?: string): IntegrationCredential | undefined {
  // Try tenant-specific first, then platform default
  const tenantKey = `${integrationId}:${tenantId ?? "platform"}`;
  const platformKey = `${integrationId}:platform`;
  return credentialStore.get(tenantKey) || credentialStore.get(platformKey);
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — PIPELINE COVERAGE & HEALTH
// ═══════════════════════════════════════════════════════════════════════

/** Get pipeline coverage report */
export function getPipelineCoverageReport(): PipelineCoverageReport {
  const activeIntegrations = [
    ...BUILTIN_CATALOG.map(e => ({
      id: e.id,
      category: e.category,
      stages: e.pipelineStages,
      dataTypes: e.dataTypes,
    })),
    ...[...customerIntegrations.values()]
      .filter(e => e.status === "active")
      .map(e => ({
        id: e.id,
        category: e.category,
        stages: e.capabilities.pipelineStages,
        dataTypes: e.capabilities.dataTypes,
      })),
  ];
  return analyzePipelineCoverage(activeIntegrations);
}

/** Get integration health summary */
export function getHealthSummary(): {
  total: number;
  active: number;
  proposed: number;
  paused: number;
  error: number;
  builtIn: number;
  customer: number;
} {
  const customer = [...customerIntegrations.values()];
  return {
    total: BUILTIN_CATALOG.length + customer.length,
    active: customer.filter(i => i.status === "active").length,
    proposed: customer.filter(i => i.status === "proposed").length,
    paused: customer.filter(i => i.status === "paused").length,
    error: customer.filter(i => i.status === "error").length,
    builtIn: BUILTIN_CATALOG.length,
    customer: customer.length,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — EXPORTS
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
