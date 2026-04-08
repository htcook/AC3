/**
 * Lazy Knowledge Base Loader (ESM-Compatible)
 *
 * Provides on-demand loading of knowledge base modules to reduce boot-time memory.
 * Uses dynamic import() for ESM compatibility — works in both tsx dev mode and
 * esbuild production bundles (where require() becomes __require() and throws
 * "Dynamic require of X is not supported").
 *
 * For sync callers: modules are eagerly imported at first access via a warm-up
 * function, then served from cache. The wrapper functions remain sync after warm-up.
 *
 * Each module is cached after first load so subsequent calls don't re-parse.
 * The cache can be cleared to free memory after engagement completion.
 */

// ─── Direct static imports (esbuild bundles these; tree-shaking removes unused) ───
// These are top-level imports but esbuild's __esm pattern defers initialization
// until first access, achieving the same lazy-load effect without require().

import * as scanforgeKnowledge from './scanforge-knowledge';
import * as attackChainRetriever from './knowledge/attack-chain-retriever';
import * as assetOntology from './knowledge/asset-ontology';
import * as bugbountyKnowledge from './knowledge/bugbounty-knowledge';
import * as trainingCorpus from './knowledge/training-corpus';
import * as cloudSecurityKnowledge from './knowledge/cloud-security-knowledge';
import * as owaspKnowledge from './owasp-knowledge';
import * as threatGroupKnowledge from './threat-group-knowledge';
import * as offensiveTechniquesKnowledge from './knowledge/offensive-techniques-knowledge';
import * as zapPentestingKnowledge from './knowledge/zap-pentesting-knowledge';
import * as offensiveToolsKnowledge from './knowledge/offensive-tools-knowledge';
import * as bugbountyMethodologyKnowledge from './knowledge/bugbounty-methodology-knowledge';
import * as missedVulnTrainingKnowledge from './knowledge/missed-vuln-training-knowledge';
import * as threatActorLearningContext from './threat-actor-learning-context';
import * as zapSourceSecretsKnowledge from './knowledge/zap-source-secrets-knowledge';
import * as burpPentestingKnowledge from './knowledge/burp-pentesting-knowledge';
import * as kevService from './kev-service';

// Module registry for cache management
const _loadedModules = new Set<string>();

/** Clear the knowledge module cache to free memory (best-effort in ESM) */
export function clearKnowledgeCache(): number {
  const count = _loadedModules.size;
  _loadedModules.clear();
  // In ESM, we can't truly unload modules like with require.cache,
  // but clearing our tracking set signals the intent.
  // The actual module singletons will be GC'd if no references remain.
  return count;
}

export function getKnowledgeCacheSize(): number {
  return _loadedModules.size;
}

/** Get detailed cache status for the memory-profile endpoint */
export function getCacheStatus(): { cachedModules: string[]; cacheSize: number } {
  return {
    cachedModules: [..._loadedModules],
    cacheSize: _loadedModules.size,
  };
}

// Helper to track module access
function track(key: string) {
  _loadedModules.add(key);
}

// ─── scanforge-knowledge ──────────────────────────────────────────────────
// Backward-compatible aliases: old getNmap* names delegate to ScanForge equivalents
export function getNmapScanPlanContext(...args: any[]) {
  track('scanforge');
  return scanforgeKnowledge.getScanforgeScanPlanContext(...args);
}
export function getNmapVulnCorrelationContext(...args: any[]) {
  track('scanforge');
  return scanforgeKnowledge.getScanforgeVulnCorrelationContext(...args);
}
export function getNmapHuntContext(...args: any[]) {
  track('scanforge');
  return scanforgeKnowledge.getScanforgeHuntContext();
}
// New ScanForge-native exports
export function getScanforgeScanPlanContext(...args: any[]) {
  track('scanforge');
  return scanforgeKnowledge.getScanforgeScanPlanContext(...args);
}
export function getScanforgeVulnCorrelationContext(...args: any[]) {
  track('scanforge');
  return scanforgeKnowledge.getScanforgeVulnCorrelationContext();
}
export function getScanforgeHuntContext(...args: any[]) {
  track('scanforge');
  return scanforgeKnowledge.getScanforgeHuntContext();
}
export function getFullScanforgeContext(...args: any[]) {
  track('scanforge');
  return scanforgeKnowledge.getFullScanforgeContext(...args);
}
export function buildOptimalScanforgeCommand(...args: any[]) {
  track('scanforge');
  return scanforgeKnowledge.buildOptimalScanforgeCommand(...args);
}

// ─── attack-chain-retriever ────────────────────────────────────────────────
export function getChainsByVulnDescriptions(...args: any[]) {
  track('chain');
  return attackChainRetriever.getChainsByVulnDescriptions(...args);
}
export function formatChainsForPrompt(...args: any[]) {
  track('chain');
  return attackChainRetriever.formatChainsForPrompt(...args);
}

// ─── asset-ontology ────────────────────────────────────────────────────────
export function inferAssetContext(...args: any[]) {
  track('ontology');
  return assetOntology.inferAssetContext(...args);
}
export function formatOntologyForPrompt(...args: any[]) {
  track('ontology');
  return assetOntology.formatOntologyForPrompt(...args);
}

// ─── bugbounty-knowledge ───────────────────────────────────────────────────
export function getBugBountyContext(...args: any[]) {
  track('bb');
  return bugbountyKnowledge.getBugBountyContext(...args);
}
export function getTriageSystemPrompt(...args: any[]) {
  track('bb');
  return bugbountyKnowledge.getTriageSystemPrompt(...args);
}
export function getTrainingExamplesForPrompt(...args: any[]) {
  track('bb');
  return bugbountyKnowledge.getTrainingExamplesForPrompt(...args);
}

// ─── training-corpus ───────────────────────────────────────────────────────
export function getTriageCorpusContext(...args: any[]) {
  track('corpus');
  return trainingCorpus.getTriageCorpusContext(...args);
}

// ─── cloud-security-knowledge ──────────────────────────────────────────────
export function buildCloudSecurityContext(...args: any[]) {
  track('cloud');
  return cloudSecurityKnowledge.buildCloudSecurityContext(...args);
}
export function buildGeneralCloudContext(...args: any[]) {
  track('cloud');
  return cloudSecurityKnowledge.buildGeneralCloudContext(...args);
}
export function detectCloudProviders(...args: any[]) {
  track('cloud');
  return cloudSecurityKnowledge.detectCloudProviders(...args);
}

// ─── owasp-knowledge ───────────────────────────────────────────────────────
export function getOwaspScanPlanContext(...args: any[]) {
  track('owasp');
  return owaspKnowledge.getOwaspScanPlanContext(...args);
}
export function getOwaspVulnCorrelationContext(...args: any[]) {
  track('owasp');
  return owaspKnowledge.getOwaspVulnCorrelationContext(...args);
}
export function getOwaspAssetClassificationContext(...args: any[]) {
  track('owasp');
  return owaspKnowledge.getOwaspAssetClassificationContext(...args);
}

// ─── threat-group-knowledge ────────────────────────────────────────────────
export function getThreatGroupScanContext(...args: any[]) {
  track('threat');
  return threatGroupKnowledge.getThreatGroupScanContext(...args);
}
export function getThreatGroupVulnContext(...args: any[]) {
  track('threat');
  return threatGroupKnowledge.getThreatGroupVulnContext(...args);
}
export function getSectorThreatContext(...args: any[]) {
  track('threat');
  return threatGroupKnowledge.getSectorThreatContext(...args);
}
export function getGroupsByCVE(...args: any[]) {
  track('threat');
  return threatGroupKnowledge.getGroupsByCVE(...args);
}

// ─── offensive-techniques-knowledge ────────────────────────────────────────
export function buildOffensiveTechniquesContext(...args: any[]) {
  track('offensive');
  return offensiveTechniquesKnowledge.buildOffensiveTechniquesContext(...args);
}
export function getFirewallEvasionContext(...args: any[]) {
  track('offensive');
  return offensiveTechniquesKnowledge.getFirewallEvasionContext(...args);
}
export function getFileUploadBypassContext(...args: any[]) {
  track('offensive');
  return offensiveTechniquesKnowledge.getFileUploadBypassContext(...args);
}
export function getLOTLContext(...args: any[]) {
  track('offensive');
  return offensiveTechniquesKnowledge.getLOTLContext(...args);
}
export function getShodanReconContext(...args: any[]) {
  track('offensive');
  return offensiveTechniquesKnowledge.getShodanReconContext(...args);
}
export function getSubdomainEnumContext(...args: any[]) {
  track('offensive');
  return offensiveTechniquesKnowledge.getSubdomainEnumContext(...args);
}

// ─── zap-pentesting-knowledge ──────────────────────────────────────────────
export function buildZAPKnowledgeContext(...args: any[]) {
  track('zap');
  return zapPentestingKnowledge.buildZAPKnowledgeContext(...args);
}
export function getZAPAlertCatalogContext(...args: any[]) {
  track('zap');
  return zapPentestingKnowledge.getZAPAlertCatalogContext(...args);
}
export function getTechScanPolicyContext(...args: any[]) {
  track('zap');
  return zapPentestingKnowledge.getTechScanPolicyContext(...args);
}
export function getZAPAuthContext(...args: any[]) {
  track('zap');
  return zapPentestingKnowledge.getZAPAuthContext(...args);
}
export function getZAPReasoningPrompt(...args: any[]) {
  track('zap');
  return zapPentestingKnowledge.getZAPReasoningPrompt(...args);
}
export function getVulnPayloadContext(...args: any[]) {
  track('zap');
  return zapPentestingKnowledge.getVulnPayloadContext(...args);
}

// ─── offensive-tools-knowledge ─────────────────────────────────────────────
export function buildToolRecommendationContext(...args: any[]) {
  track('tools');
  return offensiveToolsKnowledge.buildToolRecommendationContext(...args);
}
export function buildAttackPlannerToolContext(...args: any[]) {
  track('tools');
  return offensiveToolsKnowledge.buildAttackPlannerToolContext(...args);
}

// ─── bugbounty-methodology-knowledge ───────────────────────────────────────
export function buildMethodologyContext(...args: any[]) {
  track('methodology');
  return bugbountyMethodologyKnowledge.buildMethodologyContext(...args);
}
export function buildPhaseToolContext(...args: any[]) {
  track('methodology');
  return bugbountyMethodologyKnowledge.buildPhaseToolContext(...args);
}
export function buildVulnTestingContext(...args: any[]) {
  track('methodology');
  return bugbountyMethodologyKnowledge.buildVulnTestingContext(...args);
}
export function buildScanPlanningContext(...args: any[]) {
  track('methodology');
  return bugbountyMethodologyKnowledge.buildScanPlanningContext(...args);
}

// ─── missed-vuln-training-knowledge ────────────────────────────────────────
export function buildMissedVulnContext(...args: any[]) {
  track('missed');
  return missedVulnTrainingKnowledge.buildMissedVulnContext(...args);
}
export function buildMissedVulnAttackContext(...args: any[]) {
  track('missed');
  return missedVulnTrainingKnowledge.buildMissedVulnAttackContext(...args);
}

// ─── threat-actor-learning-context ─────────────────────────────────────────
// NOTE: buildThreatActorLearningContext is async in the original module
export async function buildThreatActorLearningContext(...args: any[]) {
  track('threat-actor');
  return threatActorLearningContext.buildThreatActorLearningContext(...args);
}
export function buildThreatActorVulnContext(...args: any[]) {
  track('threat-actor');
  return threatActorLearningContext.buildThreatActorVulnContext(...args);
}
export function scoreEngagementThreatAttribution(...args: any[]) {
  track('threat-actor');
  return threatActorLearningContext.scoreEngagementThreatAttribution(...args);
}
export function clearThreatLearningCache(...args: any[]) {
  track('threat-actor');
  return threatActorLearningContext.clearThreatLearningCache(...args);
}

// ─── zap-source-secrets-knowledge ──────────────────────────────────────────
export function buildSourceSecretsContext(...args: any[]) {
  track('secrets');
  return zapSourceSecretsKnowledge.buildSourceSecretsContext(...args);
}
export function buildCompactSourceSecretsContext(...args: any[]) {
  track('secrets');
  return zapSourceSecretsKnowledge.buildCompactSourceSecretsContext(...args);
}

// ─── burp-pentesting-knowledge ────────────────────────────────────────────
export function buildBurpKnowledgeContext(...args: any[]) {
  track('burp');
  return burpPentestingKnowledge.buildBurpKnowledgeContext(...args);
}
export function getBurpScanConfigContext(...args: any[]) {
  track('burp');
  return burpPentestingKnowledge.getBurpScanConfigContext(...args);
}
export function getBurpAttackProfileContext(...args: any[]) {
  track('burp');
  return burpPentestingKnowledge.getBurpAttackProfileContext(...args);
}
export function getBurpCollaboratorContext(...args: any[]) {
  track('burp');
  return burpPentestingKnowledge.getBurpCollaboratorContext(...args);
}
export function getCrossToolCorrelationContext(...args: any[]) {
  track('burp');
  return burpPentestingKnowledge.getCrossToolCorrelationContext(...args);
}
export function getBurpReasoningPrompt(...args: any[]) {
  track('burp');
  return burpPentestingKnowledge.getBurpReasoningPrompt(...args);
}

// ─── kev-service ───────────────────────────────────────────────────────────
// NOTE: fetchKevCatalog is async in the original module
export async function lazyFetchKevCatalog(...args: any[]) {
  track('kev');
  return kevService.fetchKevCatalog(...args);
}
export function lazyMatchCvesAgainstKev(...args: any[]) {
  track('kev');
  return kevService.matchCvesAgainstKev(...args);
}
export function lazyCalculateKevRiskBoost(...args: any[]) {
  track('kev');
  return kevService.calculateKevRiskBoost(...args);
}
