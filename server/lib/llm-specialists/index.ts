/**
 * AC3 LLM Specialist Architecture — Module Index
 *
 * Specialist dispatch pattern:
 *   Orchestrator
 *     ├── scanAnalyst(scanData)        → asset classification, exposure analysis
 *     ├── vulnVerifier(finding)        → real/false positive, exploitability
 *     ├── threatMapper(assets, vulns)  → APT correlation, sector threats
 *     ├── attackPlanner(assets, vulns) → attack chains, scan strategy
 *     ├── opsDecider(state)            → next scan action
 *     ├── calderaBuilder(attackPath)   → Caldera adversary profile + abilities
 *     ├── reportWriter(engagement)     → professional pentest report
 *     └── interceptionEvasion(findings) → defense evasion strategy & OPSEC
 */

// Core policy & assembly
export { CORE_POLICY, assembleSystemPrompt, buildCustomerContext, buildAssetContext } from "./core-policy";

// Specialists
export { analyzeScan, type ScanAnalystInput, type ScanAnalystOutput } from "./scan-analyst";
export { planAttack, type AttackPlannerInput, type AttackPlannerOutput } from "./attack-planner";
export { verifyVulnerability, type VulnVerifierInput, type VulnVerifierOutput } from "./vuln-verifier";
export { mapThreats, type ThreatMapperInput, type ThreatMapperOutput } from "./threat-mapper";
export { decideNextOp, type OpsDeciderInput, type OpsDeciderOutput } from "./ops-decider";
export { buildCalderaOp, type CalderaBuilderInput, type CalderaBuilderOutput } from "./caldera-builder";
export { writeReportFinding, type ReportWriterInput, type ReportWriterOutput } from "./report-writer";

// Interception & Evasion Analyst
export { analyzeInterceptions, quickEvasionCheck, type InterceptionEvasionInput, type InterceptionEvasionOutput } from "./interception-evasion";

// Hybrid Scorer with Context Awareness
export {
  scoreHybrid,
  scoreFullHybrid,
  buildEngagementContext,
  formatContextForLLM,
  type HybridScorerInput,
  type HybridScorerOutput,
  type FullHybridScoreInput,
  type FullHybridScoreOutput,
  type EngagementContext,
} from "./hybrid-scorer";

// ─── Discovery Context Specialists ────────────────────────────────
// Modular decomposition following Claude's reference architecture:
//   evidence package → deterministic baseline → LLM augmentation → validation → output

// Shared types for discovery context
export type {
  StructuredEvidencePackage,
  AttributionClaim,
  AttributionSpecialistInput,
  AttributionSpecialistOutput,
  RoleSpecialistInput,
  RoleSpecialistOutput,
  LifecycleSpecialistInput,
  LifecycleSpecialistOutput,
  BusinessContextSpecialistInput,
  BusinessContextSpecialistOutput,
  ThreatRelevanceSpecialistInput,
  ThreatRelevanceSpecialistOutput,
  DiscoveryContext,
  NegativeFinding,
  ValidationResult as DiscoveryValidationResult,
  SpecialistInvocationMetadata,
  AttributionScoringOutput,
  CarverScores,
  DiscoveryTier,
  SpecialistMode as DiscoverySpecialistMode,
} from "./types";

// Evidence package construction
export { buildEvidencePackage, renderEvidencePackage, hashPackage } from "./evidence-package";

// Validation
export { validateEvidenceGrounding, validateAttributionOutput, clampDelta, applyBoundedDelta, scoreToBand } from "./validation";

// Asset Attribution Specialist
export { invokeAttributionSpecialist, computeDeterministicAttribution, applyAttributionToAssetRecord, applyAttributionWeightedSectorPreset, inferSectorFromAttribution, getSectorPresets } from "./asset-attribution";

// Asset Role Specialist
export { invokeRoleSpecialist, computeRoleBaseline } from "./asset-role";

// Lifecycle Stage Specialist
export { invokeLifecycleSpecialist, computeLifecycleBaseline } from "./lifecycle-stage";

// Business Context Specialist
export { invokeBusinessContextSpecialist, computeBusinessContextBaseline } from "./business-context";

// Threat Relevance Specialist
export { invokeThreatRelevanceSpecialist, computeThreatRelevanceBaseline } from "./threat-relevance";
