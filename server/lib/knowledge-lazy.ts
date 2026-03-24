/**
 * Lazy Knowledge Base Loader (Sync API)
 *
 * Provides on-demand loading of knowledge base modules to reduce boot-time memory.
 * Uses require() for synchronous lazy loading — modules are only loaded on first call,
 * not at import time. This preserves the sync API so callers don't need await.
 *
 * Each module is cached after first load so subsequent calls don't re-parse.
 * The cache can be cleared to free memory after engagement completion.
 */

// Module cache
const _cache = new Map<string, any>();

function lazy(key: string, path: string): any {
  if (_cache.has(key)) return _cache.get(key)!;
  const mod = require(path);
  _cache.set(key, mod);
  return mod;
}

/** Clear the knowledge module cache to free memory */
export function clearKnowledgeCache(): number {
  const count = _cache.size;
  // Also delete from Node's require cache to truly free memory
  for (const [, mod] of _cache) {
    try {
      const modId = (mod as any).__filename || '';
      if (modId && require.cache[modId]) {
        delete require.cache[modId];
      }
    } catch { /* best effort */ }
  }
  _cache.clear();
  return count;
}

export function getKnowledgeCacheSize(): number {
  return _cache.size;
}

/** Get detailed cache status for the memory-profile endpoint */
export function getCacheStatus(): { cachedModules: string[]; cacheSize: number } {
  return {
    cachedModules: [..._cache.keys()],
    cacheSize: _cache.size,
  };
}

// ─── nmap-knowledge ────────────────────────────────────────────────────────
export function getNmapScanPlanContext(...args: any[]) {
  return lazy('nmap', './nmap-knowledge').getNmapScanPlanContext(...args);
}
export function getNmapVulnCorrelationContext(...args: any[]) {
  return lazy('nmap', './nmap-knowledge').getNmapVulnCorrelationContext(...args);
}
export function getNmapHuntContext(...args: any[]) {
  return lazy('nmap', './nmap-knowledge').getNmapHuntContext(...args);
}

// ─── attack-chain-retriever ────────────────────────────────────────────────
export function getChainsByVulnDescriptions(...args: any[]) {
  return lazy('chain', './knowledge/attack-chain-retriever').getChainsByVulnDescriptions(...args);
}
export function formatChainsForPrompt(...args: any[]) {
  return lazy('chain', './knowledge/attack-chain-retriever').formatChainsForPrompt(...args);
}

// ─── asset-ontology ────────────────────────────────────────────────────────
export function inferAssetContext(...args: any[]) {
  return lazy('ontology', './knowledge/asset-ontology').inferAssetContext(...args);
}
export function formatOntologyForPrompt(...args: any[]) {
  return lazy('ontology', './knowledge/asset-ontology').formatOntologyForPrompt(...args);
}

// ─── bugbounty-knowledge ───────────────────────────────────────────────────
export function getBugBountyContext(...args: any[]) {
  return lazy('bb', './knowledge/bugbounty-knowledge').getBugBountyContext(...args);
}
export function getTriageSystemPrompt(...args: any[]) {
  return lazy('bb', './knowledge/bugbounty-knowledge').getTriageSystemPrompt(...args);
}
export function getTrainingExamplesForPrompt(...args: any[]) {
  return lazy('bb', './knowledge/bugbounty-knowledge').getTrainingExamplesForPrompt(...args);
}

// ─── training-corpus ───────────────────────────────────────────────────────
export function getTriageCorpusContext(...args: any[]) {
  return lazy('corpus', './knowledge/training-corpus').getTriageCorpusContext(...args);
}

// ─── cloud-security-knowledge ──────────────────────────────────────────────
export function buildCloudSecurityContext(...args: any[]) {
  return lazy('cloud', './knowledge/cloud-security-knowledge').buildCloudSecurityContext(...args);
}
export function buildGeneralCloudContext(...args: any[]) {
  return lazy('cloud', './knowledge/cloud-security-knowledge').buildGeneralCloudContext(...args);
}
export function detectCloudProviders(...args: any[]) {
  return lazy('cloud', './knowledge/cloud-security-knowledge').detectCloudProviders(...args);
}

// ─── owasp-knowledge ───────────────────────────────────────────────────────
export function getOwaspScanPlanContext(...args: any[]) {
  return lazy('owasp', './owasp-knowledge').getOwaspScanPlanContext(...args);
}
export function getOwaspVulnCorrelationContext(...args: any[]) {
  return lazy('owasp', './owasp-knowledge').getOwaspVulnCorrelationContext(...args);
}
export function getOwaspAssetClassificationContext(...args: any[]) {
  return lazy('owasp', './owasp-knowledge').getOwaspAssetClassificationContext(...args);
}

// ─── threat-group-knowledge ────────────────────────────────────────────────
export function getThreatGroupScanContext(...args: any[]) {
  return lazy('threat', './threat-group-knowledge').getThreatGroupScanContext(...args);
}
export function getThreatGroupVulnContext(...args: any[]) {
  return lazy('threat', './threat-group-knowledge').getThreatGroupVulnContext(...args);
}
export function getSectorThreatContext(...args: any[]) {
  return lazy('threat', './threat-group-knowledge').getSectorThreatContext(...args);
}
export function getGroupsByCVE(...args: any[]) {
  return lazy('threat', './threat-group-knowledge').getGroupsByCVE(...args);
}

// ─── offensive-techniques-knowledge ────────────────────────────────────────
export function buildOffensiveTechniquesContext(...args: any[]) {
  return lazy('offensive', './knowledge/offensive-techniques-knowledge').buildOffensiveTechniquesContext(...args);
}
export function getFirewallEvasionContext(...args: any[]) {
  return lazy('offensive', './knowledge/offensive-techniques-knowledge').getFirewallEvasionContext(...args);
}
export function getFileUploadBypassContext(...args: any[]) {
  return lazy('offensive', './knowledge/offensive-techniques-knowledge').getFileUploadBypassContext(...args);
}
export function getLOTLContext(...args: any[]) {
  return lazy('offensive', './knowledge/offensive-techniques-knowledge').getLOTLContext(...args);
}
export function getShodanReconContext(...args: any[]) {
  return lazy('offensive', './knowledge/offensive-techniques-knowledge').getShodanReconContext(...args);
}
export function getSubdomainEnumContext(...args: any[]) {
  return lazy('offensive', './knowledge/offensive-techniques-knowledge').getSubdomainEnumContext(...args);
}

// ─── zap-pentesting-knowledge ──────────────────────────────────────────────
export function buildZAPKnowledgeContext(...args: any[]) {
  return lazy('zap', './knowledge/zap-pentesting-knowledge').buildZAPKnowledgeContext(...args);
}
export function getZAPAlertCatalogContext(...args: any[]) {
  return lazy('zap', './knowledge/zap-pentesting-knowledge').getZAPAlertCatalogContext(...args);
}
export function getTechScanPolicyContext(...args: any[]) {
  return lazy('zap', './knowledge/zap-pentesting-knowledge').getTechScanPolicyContext(...args);
}
export function getZAPAuthContext(...args: any[]) {
  return lazy('zap', './knowledge/zap-pentesting-knowledge').getZAPAuthContext(...args);
}
export function getZAPReasoningPrompt(...args: any[]) {
  return lazy('zap', './knowledge/zap-pentesting-knowledge').getZAPReasoningPrompt(...args);
}
export function getVulnPayloadContext(...args: any[]) {
  return lazy('zap', './knowledge/zap-pentesting-knowledge').getVulnPayloadContext(...args);
}

// ─── offensive-tools-knowledge ─────────────────────────────────────────────
export function buildToolRecommendationContext(...args: any[]) {
  return lazy('tools', './knowledge/offensive-tools-knowledge').buildToolRecommendationContext(...args);
}
export function buildAttackPlannerToolContext(...args: any[]) {
  return lazy('tools', './knowledge/offensive-tools-knowledge').buildAttackPlannerToolContext(...args);
}

// ─── bugbounty-methodology-knowledge ───────────────────────────────────────
export function buildMethodologyContext(...args: any[]) {
  return lazy('methodology', './knowledge/bugbounty-methodology-knowledge').buildMethodologyContext(...args);
}
export function buildPhaseToolContext(...args: any[]) {
  return lazy('methodology', './knowledge/bugbounty-methodology-knowledge').buildPhaseToolContext(...args);
}
export function buildVulnTestingContext(...args: any[]) {
  return lazy('methodology', './knowledge/bugbounty-methodology-knowledge').buildVulnTestingContext(...args);
}
export function buildScanPlanningContext(...args: any[]) {
  return lazy('methodology', './knowledge/bugbounty-methodology-knowledge').buildScanPlanningContext(...args);
}

// ─── missed-vuln-training-knowledge ────────────────────────────────────────
export function buildMissedVulnContext(...args: any[]) {
  return lazy('missed', './knowledge/missed-vuln-training-knowledge').buildMissedVulnContext(...args);
}
export function buildMissedVulnAttackContext(...args: any[]) {
  return lazy('missed', './knowledge/missed-vuln-training-knowledge').buildMissedVulnAttackContext(...args);
}

// ─── threat-actor-learning-context ─────────────────────────────────────────
// NOTE: buildThreatActorLearningContext is async in the original module
export async function buildThreatActorLearningContext(...args: any[]) {
  return lazy('threat-actor', './threat-actor-learning-context').buildThreatActorLearningContext(...args);
}
export function buildThreatActorVulnContext(...args: any[]) {
  return lazy('threat-actor', './threat-actor-learning-context').buildThreatActorVulnContext(...args);
}
export function scoreEngagementThreatAttribution(...args: any[]) {
  return lazy('threat-actor', './threat-actor-learning-context').scoreEngagementThreatAttribution(...args);
}
export function clearThreatLearningCache(...args: any[]) {
  return lazy('threat-actor', './threat-actor-learning-context').clearThreatLearningCache(...args);
}

// ─── zap-source-secrets-knowledge ──────────────────────────────────────────
export function buildSourceSecretsContext(...args: any[]) {
  return lazy('secrets', './knowledge/zap-source-secrets-knowledge').buildSourceSecretsContext(...args);
}
export function buildCompactSourceSecretsContext(...args: any[]) {
  return lazy('secrets', './knowledge/zap-source-secrets-knowledge').buildCompactSourceSecretsContext(...args);
}

// ─── kev-service ───────────────────────────────────────────────────────────
// NOTE: fetchKevCatalog is async in the original module
export async function lazyFetchKevCatalog(...args: any[]) {
  return lazy('kev', './kev-service').fetchKevCatalog(...args);
}
export function lazyMatchCvesAgainstKev(...args: any[]) {
  return lazy('kev', './kev-service').matchCvesAgainstKev(...args);
}
export function lazyCalculateKevRiskBoost(...args: any[]) {
  return lazy('kev', './kev-service').calculateKevRiskBoost(...args);
}
