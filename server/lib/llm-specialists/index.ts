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
