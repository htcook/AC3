/**
 * Integration Registry — Public API
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * Re-exports the complete integration registry for use by:
 *   - tRPC routers (server/routers.ts)
 *   - Engagement orchestrator (pipeline wiring)
 *   - Frontend UI (integration settings page)
 */

export {
  // Registry queries
  getAllIntegrations,
  getIntegration,
  getIntegrationsByCategory,
  getIntegrationsByStage,
  getCustomerIntegrations,
  getIntegrationsByStatus,
  getCategorySummary,
  // Discovery & classification
  discoverNewSource,
  // Customer review
  submitCustomerReview,
  // Lifecycle
  activateIntegration,
  pauseIntegration,
  removeIntegration,
  updateIntegrationStatus,
  // Credentials
  storeCredentials,
  getCredentials,
  // Pipeline coverage
  getPipelineCoverageReport,
  getHealthSummary,
  // Catalog
  BUILTIN_CATALOG,
  CATALOG_BY_ID,
  CATEGORY_METADATA,
  PIPELINE_STAGE_METADATA,
} from "./registry";

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
} from "./registry";

// Types
export type {
  IntegrationAuth,
  IntegrationEndpoint,
  IntegrationCapability,
  IntegrationValueAssessment,
  AutoDiscoveryResult,
  PipelineWiringConfig,
  PipelineCondition,
  OutputMapping,
  LicenseModel,
  AuthMethod,
  DataFormat,
  ClassificationFeedback,
} from "./types";
