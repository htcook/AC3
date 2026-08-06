/**
 * ScanForge — AC3 Vulnerability Scanner & DAST Engine
 *
 * A unified scanning service that replaces per-tool SSH invocation with:
 *   - Priority-based job queue with concurrent execution
 *   - RESTful API for scan lifecycle management
 *   - YAML template engine for extensible detection logic
 *   - Protocol-native scanners for 14+ protocols
 *   - Proactive TI/DFIR enrichment for scan planning and risk scoring
 *   - WebSocket events for real-time scan progress
 *
 * Usage:
 *   import { scanforgeRouter, initializeScanForge } from "./scanforge";
 *   await initializeScanForge();
 *   app.use("/api/v1", scanforgeRouter);
 */

export { scanforgeRouter, initializeScanForge } from "./api/router";
export { getScanQueue, ScanQueue } from "./queue/scan-queue";
export { getTemplateEngine, TemplateEngine } from "./engine/template-engine";
export { ScanOrchestrator } from "./engine/scan-orchestrator";
export { getProtocolRegistry, ProtocolRegistry } from "./protocols/registry";
export { getIntelligenceEngine, IntelligenceEngine } from "./intelligence/ti-engine";
export { getContextEngine, ContextEngine } from "./intelligence/context-engine";
export { getFPFNEngine, FPFNPreventionEngine } from "./intelligence/fp-fn-prevention";
export {
  getDeduplicationEngine, DeduplicationEngine,
  getNormalizationEngine, NormalizationEngine,
  getCoverageGapDetector, CoverageGapDetector,
} from "./intelligence/dedup-coverage";
export type * from "./types";

// ─── ScanForge Prompt Pack Integration ──────────────────────────────────────
export {
  computeHybridScore, batchScore, quickSeverityFromCvss,
  computeTechnicalSeverity, computeExposureModifier, computeMissionImpact,
  computeAttackPathModifier, computeExploitabilityConfidence,
} from "./engine/hybrid-scoring";
export type {
  HybridScoringInput, HybridScoringResult, ExposureLevel, SeverityBand,
  AttackPathCategory, FindingState,
} from "./engine/hybrid-scoring";

export {
  PROMPT_REGISTRY, buildPromptMessages, getResponseFormat, getPromptsForStage,
  SCANFORGE_WORKFLOW_STAGES, STRICT_PASSIVE_MODE_POLICY,
  TRIAGE_SYSTEM_PROMPT, TRIAGE_RESPONSE_SCHEMA,
  FINDING_ENRICHMENT_PROMPT, FINDING_ENRICHMENT_SCHEMA,
  ATTACK_MAPPING_PROMPT, ATTACK_MAPPING_SCHEMA,
  FEDRAMP_ALIGNMENT_PROMPT, FEDRAMP_ALIGNMENT_SCHEMA,
  FALSE_POSITIVE_REVIEWER_PROMPT, FALSE_POSITIVE_REVIEWER_SCHEMA,
  REMEDIATION_PLANNER_PROMPT, REMEDIATION_PLANNER_SCHEMA,
  REPORT_WRITER_PROMPT, REPORT_WRITER_SCHEMA,
  EXECUTIVE_SUMMARY_PROMPT, EXECUTIVE_SUMMARY_SCHEMA,
} from "./engine/llm-prompts";
export type { ScanForgePromptId, ScanForgePromptConfig } from "./engine/llm-prompts";

export {
  BUILTIN_PLUGINS, matchPlugins, getPluginSummary,
  buildPluginExecutionPlan, pluginToLlmContext,
} from "./engine/detection-plugins";
export type { DetectionPlugin, PluginCategory, PluginMatchResult, AssetService } from "./engine/detection-plugins";
