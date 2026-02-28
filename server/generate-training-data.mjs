/**
 * LLM Training Dataset Generator
 * Converts domain scan results into structured training data for:
 *   1. Sector classification training
 *   2. NAICS inference training
 *   3. Risk scoring calibration
 *   4. Regulatory overlay training
 *   5. Threat actor likelihood training
 *   6. Caldera operation prioritization training
 */

import fs from 'fs';

const scanResults = JSON.parse(fs.readFileSync('/home/ubuntu/domain-scan-results.json', 'utf-8'));

// ── 1. Sector Classification Training Data ──────────────────────────

const sectorClassificationTraining = scanResults.domainResults.map(r => ({
  input: {
    domain: r.domain,
    tld: '.' + r.domain.split('.').pop(),
  },
  expected: {
    sector: r.groundTruthSector,
    sectorLabel: r.groundTruthLabel,
    regulatory: r.groundTruthRegulatory,
  },
  inferred: {
    sector: r.sectorInference.inferredSector,
    effectiveSector: r.sectorInference.effectiveSector,
    confidence: r.sectorInference.inferredConfidence,
    overrideApplied: r.sectorInference.sectorOverrideApplied,
  },
  correct: r.sectorInference.effectiveSector === r.groundTruthSector ||
           r.sectorInference.sectorOverrideApplied,
}));

// ── 2. NAICS Inference Training Data ────────────────────────────────

const naicsTraining = scanResults.domainResults.map(r => ({
  input: { domain: r.domain },
  naics: {
    primaryCode: r.naicsInference.primaryNaics,
    primaryLabel: r.naicsInference.primaryLabel,
    confidence: r.naicsInference.confidence,
    band: r.naicsInference.confidenceBand,
    candidates: r.naicsInference.topCandidates,
  },
  evidence: r.naicsInference.evidence,
  groundTruthSector: r.groundTruthSector,
}));

// ── 3. Risk Scoring Calibration Data ────────────────────────────────

const scoringCalibration = scanResults.domainResults.map(r => ({
  domain: r.domain,
  sector: r.sectorInference.effectiveSector,
  sectorLabel: r.groundTruthLabel,
  scores: r.riskCard.scores,
  regulatory: r.riskCard.regulatoryProfile,
  drivers: r.riskCard.topDrivers.map(d => d.driver),
  calderaTier: r.calderaOp.operationTier,
}));

// ── 4. Sector-Level Scoring Baselines ───────────────────────────────

const sectorBaselines = {};
for (const [sector, stats] of Object.entries(scanResults.sectorStatistics)) {
  const sectorDomains = scanResults.domainResults.filter(r => r.groundTruthSector === sector);
  const scores = sectorDomains.map(r => r.riskCard.scores.hybrid);
  const carverScores = sectorDomains.map(r => r.riskCard.scores.carverShock);
  
  sectorBaselines[sector] = {
    label: stats.label,
    domainCount: stats.domainCount,
    regulatory: stats.regulatory,
    scoring: {
      hybridMean: stats.avgHybridScore,
      hybridMin: Math.min(...scores),
      hybridMax: Math.max(...scores),
      hybridStdDev: Math.round(stdDev(scores) * 100) / 100,
      carverMean: stats.avgCarverComposite,
      carverMin: Math.min(...carverScores),
      carverMax: Math.max(...carverScores),
    },
    tierDistribution: stats.tierDistribution,
    sampleDomains: sectorDomains.slice(0, 3).map(r => r.domain),
  };
}

// ── 5. Threat Actor Likelihood Training ─────────────────────────────

const threatTraining = {};
for (const r of scanResults.domainResults) {
  const sector = r.sectorInference.effectiveSector;
  if (!threatTraining[sector]) {
    threatTraining[sector] = {
      sector,
      sectorLabel: r.groundTruthLabel,
      threats: r.threatLikelihood,
      sampleDomains: [],
    };
  }
  threatTraining[sector].sampleDomains.push(r.domain);
}

// ── 6. Caldera Operation Mapping Training ───────────────────────────

const calderaTraining = scanResults.domainResults.map(r => ({
  domain: r.domain,
  priorityTier: r.riskCard.scores.priorityTier,
  hybridScore: r.riskCard.scores.hybrid,
  caldera: {
    operationTier: r.calderaOp.operationTier,
    operationProfile: r.calderaOp.operationProfile,
    objectives: r.calderaOp.objectives,
    recommendedAdversaries: r.calderaOp.recommendedAdversaries,
    recommendedAbilitySets: r.calderaOp.recommendedAbilitySets,
  },
}));

// ── 7. Prompt-Response Training Pairs ───────────────────────────────

const promptResponsePairs = scanResults.domainResults.map(r => ({
  systemPrompt: "You are an expert cybersecurity risk analyst specializing in CARVER+SHOCK hybrid scoring. Given a domain and its sector, provide a risk assessment with CARVER scores, regulatory considerations, threat actor likelihood, and recommended Caldera operation tier.",
  userPrompt: `Analyze the domain "${r.domain}" which belongs to the ${r.groundTruthLabel} sector. Provide a hybrid risk score, identify the top risk drivers, and recommend a Caldera operation tier.`,
  expectedResponse: {
    sector: r.sectorInference.effectiveSector,
    naics: r.naicsInference.primaryNaics,
    regulatory: r.riskCard.regulatoryProfile,
    scores: r.riskCard.scores,
    topDrivers: r.riskCard.topDrivers,
    threatLikelihood: Object.entries(r.riskCard.threatLikelihood || {})
      .sort(([,a], [,b]) => (b || 0) - (a || 0))
      .slice(0, 3)
      .map(([cat, prob]) => ({ category: cat, probability: prob })),
    recommendedActions: r.riskCard.recommendedActions.slice(0, 3),
    calderaPriority: {
      tier: r.calderaOp.operationTier,
      profile: r.calderaOp.operationProfile,
      objectives: r.calderaOp.objectives.slice(0, 3),
    },
  },
}));

// ── Assemble Final Training Dataset ─────────────────────────────────

const trainingDataset = {
  metadata: {
    generatedAt: new Date().toISOString(),
    version: "1.0.0",
    totalDomains: scanResults.metadata.totalDomains,
    totalSectors: scanResults.metadata.sectorCount,
    purpose: "LLM training data for Auto-BIA + hybrid CARVER+SHOCK scoring",
    modules: [
      "sector_classification",
      "naics_inference",
      "scoring_calibration",
      "sector_baselines",
      "threat_likelihood",
      "caldera_operations",
      "prompt_response_pairs",
    ],
  },
  sectorClassification: {
    description: "Domain → sector classification ground truth + inference results",
    count: sectorClassificationTraining.length,
    data: sectorClassificationTraining,
  },
  naicsInference: {
    description: "Domain → NAICS code inference with confidence bands",
    count: naicsTraining.length,
    data: naicsTraining,
  },
  scoringCalibration: {
    description: "Domain → hybrid risk scores with drivers and Caldera tier",
    count: scoringCalibration.length,
    data: scoringCalibration,
  },
  sectorBaselines: {
    description: "Per-sector scoring baselines with statistical distributions",
    count: Object.keys(sectorBaselines).length,
    data: sectorBaselines,
  },
  threatLikelihood: {
    description: "Per-sector threat actor likelihood weights with sample domains",
    count: Object.keys(threatTraining).length,
    data: threatTraining,
  },
  calderaOperations: {
    description: "Domain → Caldera operation tier mapping with objectives",
    count: calderaTraining.length,
    data: calderaTraining,
  },
  promptResponsePairs: {
    description: "System/User/Expected prompt-response pairs for LLM fine-tuning",
    count: promptResponsePairs.length,
    data: promptResponsePairs,
  },
  referenceData: scanResults.referenceData,
};

// Write output
fs.writeFileSync('/home/ubuntu/llm-training-dataset.json', JSON.stringify(trainingDataset, null, 2));
console.log(`Training dataset generated: ${trainingDataset.metadata.totalDomains} domains, ${trainingDataset.metadata.modules.length} modules`);
console.log(`File: /home/ubuntu/llm-training-dataset.json (${Math.round(fs.statSync('/home/ubuntu/llm-training-dataset.json').size / 1024)}KB)`);

// Also generate a compact JSONL version for fine-tuning
const jsonlLines = promptResponsePairs.map(p => JSON.stringify({
  messages: [
    { role: "system", content: p.systemPrompt },
    { role: "user", content: p.userPrompt },
    { role: "assistant", content: JSON.stringify(p.expectedResponse) },
  ]
}));
fs.writeFileSync('/home/ubuntu/llm-training-pairs.jsonl', jsonlLines.join('\n') + '\n');
console.log(`JSONL fine-tuning file: /home/ubuntu/llm-training-pairs.jsonl (${jsonlLines.length} pairs)`);

function stdDev(arr) {
  const mean = arr.reduce((s, v) => s + v, 0) / arr.length;
  const variance = arr.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / arr.length;
  return Math.sqrt(variance);
}
