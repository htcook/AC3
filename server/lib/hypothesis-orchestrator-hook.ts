/**
 * Hypothesis Generator — Orchestrator Post-Recon Hook
 * 
 * Wires the Bounty Hypothesis Generator into the engagement orchestrator's
 * post-recon phase. After passive/active reconnaissance completes, this hook
 * automatically converts recon data into ranked, testable vulnerability
 * hypotheses that feed into the scan planning pipeline.
 * 
 * Architecture:
 *   executeRecon() → passive discovery → [THIS HOOK] → scan planning
 *   
 * The hook:
 *   1. Extracts ReconData from the engagement ops state (assets, tech stack, etc.)
 *   2. Calls generateHypotheses() or generateProgramAwareHypotheses()
 *   3. Stores results in state.metadata.hypothesisResults
 *   4. Broadcasts hypothesis summary to the live ops feed
 *   5. Optionally adjusts scan plan priorities based on high-confidence hypotheses
 */

import type { ReconData, TechStackFingerprint, PortInfo, EndpointInfo, ConfigAnomaly, HistoricalArtifact, PassiveFinding, HypothesisGenerationResult, Hypothesis } from './bounty-hypothesis-generator';

// ─── Types ───────────────────────────────────────────────────────────────────

/** Minimal engagement ops state interface for the hook (avoids importing the full 15k-line orchestrator) */
interface OpsStateSlice {
  engagementId?: number;
  engagementType: string;
  phase: string;
  assets: Array<{
    hostname: string;
    ip?: string;
    type: string;
    status: string;
    ports: Array<{ port: number; service: string; version?: string; state?: string }>;
    vulns: Array<any>;
    passiveRecon?: {
      technologies?: string[];
      services?: Array<{ port: number; service: string; version?: string }>;
      riskSignals?: Array<{ severity: string; rationale: string; category?: string }>;
      cloudProvider?: string;
      headers?: Record<string, string>;
    };
    wafDetected?: string;
    cdnDetected?: string;
    zapFindings?: Array<any>;
    toolResults?: Array<any>;
  }>;
  passiveReconResults?: Record<string, any>;
  metadata?: Record<string, any>;
  bbRoeConfig?: {
    programHandle?: string;
    platform?: string;
    testingRestrictions?: any;
    rewardStructure?: any;
  };
  log?: Array<any>;
}

export interface HypothesisHookResult {
  generated: boolean;
  hypothesisCount: number;
  highConfidenceCount: number;
  topHypotheses: Array<{
    title: string;
    vulnClass: string;
    confidence: string;
    confidenceScore: number;
    severity: string;
    endpoint: string;
    estimatedEffort: string;
  }>;
  reconQualityScore: number;
  missingReconData: string[];
  chainOpportunities: number;
  estimatedResearchHours: number;
  generatedAt: number;
}

// ─── ReconData Extraction ────────────────────────────────────────────────────

/**
 * Extract ReconData from the engagement ops state after recon/passive discovery.
 * Maps the orchestrator's internal data structures to the hypothesis generator's input format.
 */
export function extractReconDataFromState(state: OpsStateSlice): ReconData {
  const primaryAsset = state.assets[0];
  const targetDomain = primaryAsset?.hostname || 'unknown';

  // Aggregate tech stack fingerprints from all assets
  const techStack: TechStackFingerprint[] = [];
  const seenTech = new Set<string>();
  
  for (const asset of state.assets) {
    if (asset.passiveRecon?.technologies) {
      for (const tech of asset.passiveRecon.technologies) {
        const techLower = tech.toLowerCase();
        if (!seenTech.has(techLower)) {
          seenTech.add(techLower);
          techStack.push({
            technology: tech,
            confidence: 0.8,
            source: 'wappalyzer',
          });
        }
      }
    }
    // Extract tech from port services
    for (const port of asset.ports) {
      if (port.service && !seenTech.has(port.service.toLowerCase())) {
        seenTech.add(port.service.toLowerCase());
        techStack.push({
          technology: port.service,
          version: port.version,
          confidence: 0.9,
          source: 'header',
        });
      }
    }
  }

  // Aggregate open ports
  const openPorts: PortInfo[] = [];
  const seenPorts = new Set<string>();
  for (const asset of state.assets) {
    for (const port of asset.ports) {
      const key = `${asset.hostname}:${port.port}`;
      if (!seenPorts.has(key)) {
        seenPorts.add(key);
        openPorts.push({
          port: port.port,
          service: port.service || 'unknown',
          version: port.version,
          state: (port.state as any) || 'open',
        });
      }
    }
  }

  // Collect subdomains
  const subdomains = [...new Set(
    state.assets
      .map(a => a.hostname)
      .filter(h => h && h !== targetDomain && h.endsWith(`.${targetDomain}`))
  )];

  // Build endpoint list from passive recon and tool results
  const endpoints: EndpointInfo[] = [];
  for (const asset of state.assets) {
    if (asset.toolResults) {
      for (const tr of asset.toolResults) {
        if (tr.endpoints) {
          for (const ep of tr.endpoints) {
            endpoints.push({
              path: ep.path || ep.url || '/',
              method: ep.method || 'GET',
              statusCode: ep.statusCode || 200,
              responseSize: ep.responseSize,
              contentType: ep.contentType,
              requiresAuth: ep.requiresAuth || false,
              parameters: ep.parameters,
            });
          }
        }
      }
    }
  }

  // Aggregate headers
  const headers: Record<string, string> = {};
  for (const asset of state.assets) {
    if (asset.passiveRecon?.headers) {
      Object.assign(headers, asset.passiveRecon.headers);
    }
  }

  // Extract config anomalies from risk signals
  const configAnomalies: ConfigAnomaly[] = [];
  for (const asset of state.assets) {
    if (asset.passiveRecon?.riskSignals) {
      for (const signal of asset.passiveRecon.riskSignals) {
        const category = inferAnomalyCategory(signal.category || signal.rationale);
        if (category) {
          configAnomalies.push({
            category,
            description: signal.rationale,
            severity: signal.severity as any || 'medium',
            evidence: signal.rationale,
          });
        }
      }
    }
  }

  // Extract passive findings
  const passiveFindings: PassiveFinding[] = [];
  for (const asset of state.assets) {
    for (const vuln of asset.vulns) {
      if (vuln.source === 'passive' || vuln.source === 'nuclei' || vuln.source === 'nikto') {
        passiveFindings.push({
          type: vuln.cve || vuln.title || 'unknown',
          description: vuln.description || vuln.title || '',
          endpoint: vuln.endpoint || vuln.url,
          severity: vuln.severity || 'medium',
        });
      }
    }
  }

  // WAF/CDN detection
  const wafDetected = state.assets.find(a => a.wafDetected)?.wafDetected;
  const cdnDetected = state.assets.find(a => a.cdnDetected)?.cdnDetected;

  return {
    targetDomain,
    programHandle: state.bbRoeConfig?.programHandle,
    techStack,
    openPorts,
    subdomains,
    endpoints,
    headers,
    wafDetected,
    cdnDetected,
    configAnomalies,
    passiveFindings,
  };
}

function inferAnomalyCategory(text: string): ConfigAnomaly['category'] | null {
  const lower = text.toLowerCase();
  if (lower.includes('cors')) return 'cors';
  if (lower.includes('csp') || lower.includes('content-security')) return 'csp';
  if (lower.includes('header') || lower.includes('x-frame') || lower.includes('hsts')) return 'headers';
  if (lower.includes('tls') || lower.includes('ssl') || lower.includes('certificate')) return 'tls';
  if (lower.includes('dns') || lower.includes('nameserver')) return 'dns';
  if (lower.includes('api') || lower.includes('gateway') || lower.includes('rate limit')) return 'api_gateway';
  if (lower.includes('auth') || lower.includes('session') || lower.includes('cookie') || lower.includes('jwt')) return 'auth';
  if (lower.includes('cache') || lower.includes('cdn')) return 'cache';
  return null;
}

// ─── Hypothesis Generation Hook ──────────────────────────────────────────────

/**
 * Post-recon hook: generates vulnerability hypotheses from engagement state.
 * Called after passive discovery completes (or after active recon for deeper analysis).
 * 
 * @param state - The engagement ops state (must have assets populated from recon)
 * @returns HypothesisHookResult with summary and top hypotheses
 */
export async function runHypothesisGeneration(state: OpsStateSlice): Promise<HypothesisHookResult> {
  if (state.assets.length === 0) {
    return {
      generated: false,
      hypothesisCount: 0,
      highConfidenceCount: 0,
      topHypotheses: [],
      reconQualityScore: 0,
      missingReconData: ['No assets discovered yet'],
      chainOpportunities: 0,
      estimatedResearchHours: 0,
      generatedAt: Date.now(),
    };
  }

  // Dynamic import to avoid circular dependency with the full orchestrator
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  let generateHypotheses: (recon: ReconData) => HypothesisGenerationResult;
  let generateProgramAwareHypotheses: (recon: ReconData, ctx: any) => HypothesisGenerationResult;
  try {
    const mod = require('./bounty-hypothesis-generator');
    generateHypotheses = mod.generateHypotheses;
    generateProgramAwareHypotheses = mod.generateProgramAwareHypotheses;
  } catch {
    // Fallback: use top-level import (works in vitest ESM context)
    const mod = await import('./bounty-hypothesis-generator');
    generateHypotheses = mod.generateHypotheses;
    generateProgramAwareHypotheses = mod.generateProgramAwareHypotheses;
  }

  const reconData = extractReconDataFromState(state);

  let result: HypothesisGenerationResult;

  // Use program-aware generation for bug bounty engagements
  if (state.engagementType === 'bug_bounty' && state.bbRoeConfig?.programHandle) {
    const programContext = {
      avgBounty: state.bbRoeConfig.rewardStructure?.avgBounty,
      maxBounty: state.bbRoeConfig.rewardStructure?.maxBounty,
      commonCWEs: state.bbRoeConfig.rewardStructure?.commonCWEs,
    };
    result = generateProgramAwareHypotheses(reconData, programContext);
  } else {
    result = generateHypotheses(reconData);
  }

  // Store full results in state metadata
  if (!state.metadata) state.metadata = {};
  (state.metadata as any).hypothesisResults = {
    targetDomain: result.targetDomain,
    programHandle: result.programHandle,
    summary: result.summary,
    reconQuality: result.reconQuality,
    generatedAt: result.generatedAt,
    hypotheses: result.hypotheses.map(h => ({
      id: h.id,
      vulnClass: h.vulnClass,
      title: h.title,
      description: h.description,
      affectedEndpoint: h.affectedEndpoint,
      confidence: h.confidence,
      confidenceScore: h.confidenceScore,
      reasoning: h.reasoning,
      verificationSteps: h.verificationSteps,
      estimatedEffort: h.estimatedEffort,
      potentialSeverity: h.potentialSeverity,
      potentialBountyRange: h.potentialBountyRange,
      chainPotential: h.chainPotential,
      duplicateLikelihood: h.duplicateLikelihood,
      tags: h.tags,
      supportingEvidence: h.supportingEvidence,
      disconfirmingEvidence: h.disconfirmingEvidence,
      evidenceThatWouldChangeConfidence: h.evidenceThatWouldChangeConfidence,
    })),
  };

  const highConfidence = result.hypotheses.filter(h => h.confidence === 'high');

  return {
    generated: true,
    hypothesisCount: result.hypotheses.length,
    highConfidenceCount: highConfidence.length,
    topHypotheses: result.hypotheses.slice(0, 10).map(h => ({
      title: h.title,
      vulnClass: h.vulnClass,
      confidence: h.confidence,
      confidenceScore: h.confidenceScore,
      severity: h.potentialSeverity,
      endpoint: h.affectedEndpoint,
      estimatedEffort: h.estimatedEffort,
    })),
    reconQualityScore: result.reconQuality.overallScore,
    missingReconData: result.reconQuality.missingData,
    chainOpportunities: result.summary.topChainOpportunities.length,
    estimatedResearchHours: result.summary.estimatedResearchHours,
    generatedAt: result.generatedAt,
  };
}

/**
 * Build scan plan priority adjustments from high-confidence hypotheses.
 * Returns a list of endpoints/vuln classes that should be prioritized in active scanning.
 */
export function buildScanPriorityAdjustments(state: OpsStateSlice): Array<{
  endpoint: string;
  vulnClass: string;
  priority: 'critical' | 'high' | 'medium';
  reason: string;
}> {
  const hypothesisResults = (state.metadata as any)?.hypothesisResults;
  if (!hypothesisResults?.hypotheses) return [];

  const adjustments: Array<{
    endpoint: string;
    vulnClass: string;
    priority: 'critical' | 'high' | 'medium';
    reason: string;
  }> = [];

  for (const h of hypothesisResults.hypotheses as Hypothesis[]) {
    if (h.confidence === 'high' || (h.confidence === 'medium' && h.potentialSeverity === 'critical')) {
      adjustments.push({
        endpoint: h.affectedEndpoint,
        vulnClass: h.vulnClass,
        priority: h.potentialSeverity === 'critical' ? 'critical' : h.confidence === 'high' ? 'high' : 'medium',
        reason: `Hypothesis "${h.title}" (${h.confidence} confidence, ${h.potentialSeverity} severity)`,
      });
    }
  }

  // Also add chain opportunity endpoints
  for (const h of hypothesisResults.hypotheses as Hypothesis[]) {
    if (h.chainPotential && h.chainPotential.length > 0 && h.confidenceScore >= 0.5) {
      for (const chain of h.chainPotential) {
        if (chain.impactMultiplier >= 2.0) {
          adjustments.push({
            endpoint: h.affectedEndpoint,
            vulnClass: chain.toVulnClass,
            priority: 'high',
            reason: `Chain opportunity: ${chain.chainDescription} (${chain.impactMultiplier}x impact)`,
          });
        }
      }
    }
  }

  return adjustments;
}

/**
 * Format hypothesis results for the ops log feed.
 * Returns a human-readable summary suitable for addLog().
 */
export function formatHypothesisLogEntry(hookResult: HypothesisHookResult): {
  title: string;
  detail: string;
} {
  if (!hookResult.generated) {
    return {
      title: '🧠 Hypothesis Generator: No assets to analyze',
      detail: 'Hypothesis generation skipped — no assets discovered during reconnaissance.',
    };
  }

  const topLines = hookResult.topHypotheses.slice(0, 5).map((h, i) =>
    `${i + 1}. [${h.confidence.toUpperCase()}] ${h.title} → ${h.endpoint} (${h.severity}, ~${h.estimatedEffort})`
  );

  return {
    title: `🧠 Hypothesis Generator: ${hookResult.hypothesisCount} hypotheses (${hookResult.highConfidenceCount} high-confidence)`,
    detail: [
      `Recon quality: ${hookResult.reconQualityScore}/100`,
      hookResult.missingReconData.length > 0
        ? `Missing data: ${hookResult.missingReconData.slice(0, 3).join(', ')}`
        : 'Recon data coverage: complete',
      `Chain opportunities: ${hookResult.chainOpportunities}`,
      `Estimated research: ${hookResult.estimatedResearchHours.toFixed(1)} hours`,
      '',
      'Top hypotheses:',
      ...topLines,
    ].join('\n'),
  };
}
