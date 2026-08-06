/**
 * Bug Bounty Confidence Calibration
 * 
 * Enhances the existing confidence scoring with:
 * - Explicit reasoning chains for every confidence decision
 * - Calibration drift detection (when confidence diverges from outcomes)
 * - Per-vuln-class calibration curves
 * - Bayesian updating from submission outcomes
 * - Program-specific calibration adjustments
 * 
 * Key insight: "Every confidence score should come with an explicit reasoning
 * chain — not just a number, but WHY that number."
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ConfidenceAssessment {
  score: number; // 0.0 - 1.0
  level: 'very_high' | 'high' | 'medium' | 'low' | 'very_low';
  reasoning: ReasoningChain;
  calibrationAdjustment: number; // How much the raw score was adjusted
  driftWarning?: string;
}

export interface ReasoningChain {
  factors: ReasoningFactor[];
  summary: string;
  rawScore: number;
  adjustedScore: number;
  adjustmentExplanation: string;
}

export interface ReasoningFactor {
  name: string;
  weight: number; // 0.0 - 1.0
  contribution: number; // How much this factor contributed to the score
  evidence: string;
  direction: 'positive' | 'negative' | 'neutral';
}

export interface CalibrationRecord {
  vulnClass: string;
  predictedConfidence: number;
  actualOutcome: 'accepted' | 'rejected' | 'duplicate' | 'informational';
  programHandle?: string;
  timestamp: number;
}

export interface CalibrationCurve {
  vulnClass: string;
  buckets: CalibrationBucket[];
  overallBias: number; // Positive = overconfident, negative = underconfident
  sampleSize: number;
  lastUpdated: number;
}

export interface CalibrationBucket {
  predictedRange: { min: number; max: number };
  actualAcceptanceRate: number;
  sampleCount: number;
  isCalibrated: boolean; // Within 10% of predicted
}

export interface DriftReport {
  hasDrift: boolean;
  severity: 'none' | 'mild' | 'moderate' | 'severe';
  direction: 'overconfident' | 'underconfident' | 'well_calibrated';
  overallBias: number;
  worstVulnClasses: Array<{ vulnClass: string; bias: number; sampleSize: number }>;
  recommendation: string;
  lastChecked: number;
}

// ─── Confidence Factor Definitions ───────────────────────────────────────────

interface ConfidenceFactorDef {
  name: string;
  weight: number;
  evaluate: (ctx: FactorContext) => { score: number; evidence: string; direction: 'positive' | 'negative' | 'neutral' };
}

export interface FactorContext {
  vulnClass: string;
  severity: string;
  endpoint: string;
  technology?: string;
  hasEvidence: boolean;
  evidenceCount: number;
  isReproducible: boolean;
  scannerConfidence?: number;
  manuallyVerified: boolean;
  programHandle?: string;
  cweId?: string;
}

const CONFIDENCE_FACTORS: ConfidenceFactorDef[] = [
  {
    name: 'Evidence Quality',
    weight: 0.25,
    evaluate: (ctx) => {
      if (ctx.manuallyVerified && ctx.evidenceCount >= 3) {
        return { score: 1.0, evidence: 'Manually verified with multiple evidence artifacts', direction: 'positive' };
      }
      if (ctx.manuallyVerified) {
        return { score: 0.85, evidence: 'Manually verified but limited evidence', direction: 'positive' };
      }
      if (ctx.hasEvidence && ctx.evidenceCount >= 2) {
        return { score: 0.6, evidence: `${ctx.evidenceCount} evidence artifacts available but not manually verified`, direction: 'neutral' };
      }
      if (ctx.hasEvidence) {
        return { score: 0.4, evidence: 'Minimal evidence available', direction: 'negative' };
      }
      return { score: 0.1, evidence: 'No evidence provided', direction: 'negative' };
    },
  },
  {
    name: 'Reproducibility',
    weight: 0.20,
    evaluate: (ctx) => {
      if (ctx.isReproducible) {
        return { score: 1.0, evidence: 'Finding is reliably reproducible', direction: 'positive' };
      }
      return { score: 0.3, evidence: 'Finding has not been confirmed as reproducible', direction: 'negative' };
    },
  },
  {
    name: 'Vulnerability Class Reliability',
    weight: 0.15,
    evaluate: (ctx) => {
      const highReliability = ['sqli_classic', 'rce', 'command_injection', 'ssrf', 'path_traversal', 'xxe'];
      const medReliability = ['xss_stored', 'idor', 'auth_bypass', 'deserialization', 'ssti'];
      const lowReliability = ['xss_reflected', 'open_redirect', 'csrf', 'info_disclosure', 'cors_misconfiguration'];

      if (highReliability.includes(ctx.vulnClass)) {
        return { score: 0.9, evidence: `${ctx.vulnClass} has high acceptance rates across programs`, direction: 'positive' };
      }
      if (medReliability.includes(ctx.vulnClass)) {
        return { score: 0.6, evidence: `${ctx.vulnClass} has moderate acceptance rates — depends on impact`, direction: 'neutral' };
      }
      if (lowReliability.includes(ctx.vulnClass)) {
        return { score: 0.3, evidence: `${ctx.vulnClass} has lower acceptance rates — often rejected as informational or duplicate`, direction: 'negative' };
      }
      return { score: 0.5, evidence: `Unknown acceptance rate for ${ctx.vulnClass}`, direction: 'neutral' };
    },
  },
  {
    name: 'Scanner Confidence',
    weight: 0.15,
    evaluate: (ctx) => {
      if (ctx.scannerConfidence === undefined) {
        return { score: 0.5, evidence: 'No scanner confidence score available', direction: 'neutral' };
      }
      if (ctx.scannerConfidence >= 0.9) {
        return { score: 0.85, evidence: `Scanner confidence: ${(ctx.scannerConfidence * 100).toFixed(0)}% (high)`, direction: 'positive' };
      }
      if (ctx.scannerConfidence >= 0.7) {
        return { score: 0.6, evidence: `Scanner confidence: ${(ctx.scannerConfidence * 100).toFixed(0)}% (moderate)`, direction: 'neutral' };
      }
      return { score: 0.3, evidence: `Scanner confidence: ${(ctx.scannerConfidence * 100).toFixed(0)}% (low)`, direction: 'negative' };
    },
  },
  {
    name: 'Severity-Impact Alignment',
    weight: 0.15,
    evaluate: (ctx) => {
      const severityExpectation: Record<string, string[]> = {
        critical: ['rce', 'command_injection', 'sqli_classic', 'auth_bypass', 'ssrf'],
        high: ['idor', 'xss_stored', 'deserialization', 'ssti', 'privilege_escalation', 'subdomain_takeover'],
        medium: ['xss_reflected', 'csrf', 'open_redirect', 'cors_misconfiguration', 'jwt_weakness'],
        low: ['info_disclosure', 'missing_header', 'graphql_introspection'],
      };

      const expectedSeverities = Object.entries(severityExpectation)
        .filter(([, classes]) => classes.includes(ctx.vulnClass))
        .map(([sev]) => sev);

      if (expectedSeverities.includes(ctx.severity)) {
        return { score: 0.9, evidence: `Severity ${ctx.severity} aligns with expected range for ${ctx.vulnClass}`, direction: 'positive' };
      }
      if (expectedSeverities.length === 0) {
        return { score: 0.5, evidence: `No severity expectation data for ${ctx.vulnClass}`, direction: 'neutral' };
      }
      return { score: 0.3, evidence: `Severity ${ctx.severity} may not align with typical ${ctx.vulnClass} findings (expected: ${expectedSeverities.join('/')})`, direction: 'negative' };
    },
  },
  {
    name: 'Technology Context',
    weight: 0.10,
    evaluate: (ctx) => {
      if (!ctx.technology) {
        return { score: 0.4, evidence: 'No technology context available — harder to validate', direction: 'negative' };
      }
      // Known tech + matching vuln class = higher confidence
      const techVulnAffinity: Record<string, string[]> = {
        wordpress: ['sqli_classic', 'xss_stored', 'xss_reflected', 'path_traversal', 'auth_bypass'],
        java: ['deserialization', 'xxe', 'ssti', 'rce'],
        php: ['sqli_classic', 'lfi', 'rce', 'command_injection'],
        nodejs: ['ssrf', 'path_traversal', 'prototype_pollution'],
        python: ['ssti', 'command_injection', 'ssrf'],
        dotnet: ['deserialization', 'xxe', 'path_traversal'],
      };

      const techKey = Object.keys(techVulnAffinity).find(t => ctx.technology!.toLowerCase().includes(t));
      if (techKey && techVulnAffinity[techKey].includes(ctx.vulnClass)) {
        return { score: 0.85, evidence: `${ctx.vulnClass} is a known attack surface for ${ctx.technology}`, direction: 'positive' };
      }
      return { score: 0.6, evidence: `Technology ${ctx.technology} identified but no strong affinity with ${ctx.vulnClass}`, direction: 'neutral' };
    },
  },
];

// ─── Calibration Engine ──────────────────────────────────────────────────────

export class ConfidenceCalibrationEngine {
  private records: CalibrationRecord[] = [];
  private curves: Map<string, CalibrationCurve> = new Map();
  private programAdjustments: Map<string, number> = new Map(); // programHandle → bias adjustment

  /**
   * Assess confidence with full reasoning chain
   */
  assessConfidence(ctx: FactorContext): ConfidenceAssessment {
    // Step 1: Evaluate all factors
    const factors: ReasoningFactor[] = CONFIDENCE_FACTORS.map(factorDef => {
      const result = factorDef.evaluate(ctx);
      return {
        name: factorDef.name,
        weight: factorDef.weight,
        contribution: result.score * factorDef.weight,
        evidence: result.evidence,
        direction: result.direction,
      };
    });

    // Step 2: Calculate raw weighted score
    const rawScore = factors.reduce((sum, f) => sum + f.contribution, 0);

    // Step 3: Apply calibration adjustment from historical data
    const calibrationAdj = this.getCalibrationAdjustment(ctx.vulnClass);
    const programAdj = ctx.programHandle ? (this.programAdjustments.get(ctx.programHandle) || 0) : 0;
    const totalAdjustment = calibrationAdj + programAdj;
    const adjustedScore = Math.min(Math.max(rawScore + totalAdjustment, 0), 1);

    // Step 4: Check for drift
    const driftWarning = this.checkDriftForVulnClass(ctx.vulnClass);

    // Step 5: Build reasoning chain
    const reasoning: ReasoningChain = {
      factors,
      summary: this.buildReasoningSummary(factors, adjustedScore),
      rawScore: Math.round(rawScore * 100) / 100,
      adjustedScore: Math.round(adjustedScore * 100) / 100,
      adjustmentExplanation: totalAdjustment !== 0
        ? `Score adjusted by ${totalAdjustment > 0 ? '+' : ''}${(totalAdjustment * 100).toFixed(1)}% based on historical calibration (vuln class: ${(calibrationAdj * 100).toFixed(1)}%, program: ${(programAdj * 100).toFixed(1)}%)`
        : 'No calibration adjustment applied (insufficient historical data)',
    };

    // Step 6: Determine level
    const level = this.scoreToLevel(adjustedScore);

    return {
      score: adjustedScore,
      level,
      reasoning,
      calibrationAdjustment: totalAdjustment,
      driftWarning: driftWarning || undefined,
    };
  }

  /**
   * Record an outcome for calibration
   */
  recordOutcome(record: CalibrationRecord): void {
    this.records.push(record);
    this.updateCurve(record.vulnClass);
    if (record.programHandle) {
      this.updateProgramAdjustment(record.programHandle);
    }
  }

  /**
   * Detect calibration drift across all vuln classes
   */
  detectDrift(): DriftReport {
    if (this.records.length < 10) {
      return {
        hasDrift: false,
        severity: 'none',
        direction: 'well_calibrated',
        overallBias: 0,
        worstVulnClasses: [],
        recommendation: 'Insufficient data for drift detection (need at least 10 records)',
        lastChecked: Date.now(),
      };
    }

    // Calculate overall bias
    const biases: number[] = [];
    for (const record of this.records) {
      const expectedAcceptance = record.predictedConfidence;
      const actualAcceptance = record.actualOutcome === 'accepted' ? 1 : 0;
      biases.push(expectedAcceptance - actualAcceptance);
    }

    const overallBias = biases.reduce((sum, b) => sum + b, 0) / biases.length;

    // Per vuln class bias
    const vulnClassBiases = new Map<string, { total: number; count: number }>();
    for (const record of this.records) {
      const expected = record.predictedConfidence;
      const actual = record.actualOutcome === 'accepted' ? 1 : 0;
      const existing = vulnClassBiases.get(record.vulnClass) || { total: 0, count: 0 };
      existing.total += (expected - actual);
      existing.count++;
      vulnClassBiases.set(record.vulnClass, existing);
    }

    const worstVulnClasses = Array.from(vulnClassBiases.entries())
      .map(([vulnClass, data]) => ({
        vulnClass,
        bias: data.total / data.count,
        sampleSize: data.count,
      }))
      .filter(v => Math.abs(v.bias) > 0.1 && v.sampleSize >= 3)
      .sort((a, b) => Math.abs(b.bias) - Math.abs(a.bias))
      .slice(0, 5);

    // Determine severity
    const absBias = Math.abs(overallBias);
    let severity: DriftReport['severity'];
    if (absBias < 0.05) severity = 'none';
    else if (absBias < 0.15) severity = 'mild';
    else if (absBias < 0.3) severity = 'moderate';
    else severity = 'severe';

    const direction: DriftReport['direction'] = overallBias > 0.05
      ? 'overconfident'
      : overallBias < -0.05
        ? 'underconfident'
        : 'well_calibrated';

    let recommendation: string;
    if (severity === 'none') {
      recommendation = 'Calibration is within acceptable range. Continue monitoring.';
    } else if (direction === 'overconfident') {
      recommendation = `System is overconfident by ${(absBias * 100).toFixed(1)}%. Consider lowering confidence thresholds or adding more validation steps before submission.`;
    } else {
      recommendation = `System is underconfident by ${(absBias * 100).toFixed(1)}%. Consider raising confidence thresholds — valid findings may be missed.`;
    }

    return {
      hasDrift: severity !== 'none',
      severity,
      direction,
      overallBias: Math.round(overallBias * 1000) / 1000,
      worstVulnClasses,
      recommendation,
      lastChecked: Date.now(),
    };
  }

  /**
   * Get calibration curve for a specific vuln class
   */
  getCalibrationCurve(vulnClass: string): CalibrationCurve | undefined {
    return this.curves.get(vulnClass);
  }

  /**
   * Get all calibration records
   */
  getRecords(): CalibrationRecord[] {
    return [...this.records];
  }

  // ─── Private Helpers ─────────────────────────────────────────────────────

  private getCalibrationAdjustment(vulnClass: string): number {
    const curve = this.curves.get(vulnClass);
    if (!curve || curve.sampleSize < 5) return 0;
    // Negative bias means we need to adjust down (overconfident)
    return -curve.overallBias * 0.5; // Apply 50% of the detected bias as correction
  }

  private checkDriftForVulnClass(vulnClass: string): string | null {
    const curve = this.curves.get(vulnClass);
    if (!curve || curve.sampleSize < 5) return null;

    if (Math.abs(curve.overallBias) > 0.2) {
      const direction = curve.overallBias > 0 ? 'overconfident' : 'underconfident';
      return `Calibration drift detected for ${vulnClass}: ${direction} by ${(Math.abs(curve.overallBias) * 100).toFixed(1)}%`;
    }
    return null;
  }

  private updateCurve(vulnClass: string): void {
    const relevant = this.records.filter(r => r.vulnClass === vulnClass);
    if (relevant.length < 3) return;

    const buckets: CalibrationBucket[] = [
      { predictedRange: { min: 0, max: 0.2 }, actualAcceptanceRate: 0, sampleCount: 0, isCalibrated: false },
      { predictedRange: { min: 0.2, max: 0.4 }, actualAcceptanceRate: 0, sampleCount: 0, isCalibrated: false },
      { predictedRange: { min: 0.4, max: 0.6 }, actualAcceptanceRate: 0, sampleCount: 0, isCalibrated: false },
      { predictedRange: { min: 0.6, max: 0.8 }, actualAcceptanceRate: 0, sampleCount: 0, isCalibrated: false },
      { predictedRange: { min: 0.8, max: 1.0 }, actualAcceptanceRate: 0, sampleCount: 0, isCalibrated: false },
    ];

    for (const record of relevant) {
      const bucket = buckets.find(b =>
        record.predictedConfidence >= b.predictedRange.min &&
        record.predictedConfidence < b.predictedRange.max
      ) || buckets[buckets.length - 1]; // Last bucket catches 1.0

      bucket.sampleCount++;
      if (record.actualOutcome === 'accepted') {
        bucket.actualAcceptanceRate = ((bucket.actualAcceptanceRate * (bucket.sampleCount - 1)) + 1) / bucket.sampleCount;
      } else {
        bucket.actualAcceptanceRate = (bucket.actualAcceptanceRate * (bucket.sampleCount - 1)) / bucket.sampleCount;
      }

      const midpoint = (bucket.predictedRange.min + bucket.predictedRange.max) / 2;
      bucket.isCalibrated = Math.abs(bucket.actualAcceptanceRate - midpoint) < 0.1;
    }

    // Calculate overall bias
    let totalBias = 0;
    let totalSamples = 0;
    for (const record of relevant) {
      const actual = record.actualOutcome === 'accepted' ? 1 : 0;
      totalBias += (record.predictedConfidence - actual);
      totalSamples++;
    }

    this.curves.set(vulnClass, {
      vulnClass,
      buckets,
      overallBias: totalSamples > 0 ? totalBias / totalSamples : 0,
      sampleSize: totalSamples,
      lastUpdated: Date.now(),
    });
  }

  private updateProgramAdjustment(programHandle: string): void {
    const relevant = this.records.filter(r => r.programHandle === programHandle);
    if (relevant.length < 5) return;

    let totalBias = 0;
    for (const record of relevant) {
      const actual = record.actualOutcome === 'accepted' ? 1 : 0;
      totalBias += (record.predictedConfidence - actual);
    }

    const avgBias = totalBias / relevant.length;
    this.programAdjustments.set(programHandle, -avgBias * 0.3); // 30% correction
  }

  private scoreToLevel(score: number): ConfidenceAssessment['level'] {
    if (score >= 0.85) return 'very_high';
    if (score >= 0.7) return 'high';
    if (score >= 0.5) return 'medium';
    if (score >= 0.3) return 'low';
    return 'very_low';
  }

  private buildReasoningSummary(factors: ReasoningFactor[], score: number): string {
    const positive = factors.filter(f => f.direction === 'positive');
    const negative = factors.filter(f => f.direction === 'negative');

    const parts: string[] = [];
    if (positive.length > 0) {
      parts.push(`Strengths: ${positive.map(f => f.name.toLowerCase()).join(', ')}`);
    }
    if (negative.length > 0) {
      parts.push(`Weaknesses: ${negative.map(f => f.name.toLowerCase()).join(', ')}`);
    }
    parts.push(`Overall confidence: ${(score * 100).toFixed(0)}%`);

    return parts.join('. ') + '.';
  }

  clear(): void {
    this.records = [];
    this.curves.clear();
    this.programAdjustments.clear();
  }
}

// ─── Singleton Export ────────────────────────────────────────────────────────

export const confidenceCalibrationEngine = new ConfidenceCalibrationEngine();
