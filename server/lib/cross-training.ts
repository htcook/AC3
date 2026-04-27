/**
 * Cross-Training Infrastructure
 * 
 * Enables bug bounty signal to feed back into AC3 specialist capabilities.
 * Handles outcome logging, pattern repository, vulnerability validation calibration,
 * tool effectiveness tracking, and reproduction quality patterns.
 * 
 * Key design principle: CONTAMINATION ISOLATION
 * Bug bounty signal improves AC3 detection patterns WITHOUT leaking target-specific data.
 * Only context-independent patterns are extracted and stored.
 */

// ─── Outcome Logging Schema ────────────────────────────────────────────────────

export type TriageOutcome = 
  | 'accepted'          // Finding accepted by program
  | 'duplicate'         // Finding was a duplicate
  | 'informative'       // Finding is informative but not a vuln
  | 'not_applicable'    // Finding doesn't apply
  | 'out_of_scope'      // Finding was out of scope
  | 'needs_more_info'   // Program requested more information
  | 'resolved'          // Finding was resolved/fixed
  | 'wont_fix'          // Program acknowledged but won't fix
  | 'bounty_paid';      // Bounty was paid

export interface OutcomeLogEntry {
  id: string;
  timestamp: number;
  
  // Finding context (anonymized — no target-specific data)
  vulnClass: string;            // e.g., "SQL Injection", "XSS"
  severity: string;
  cweId?: string;
  detectionMethod: string;      // How was it found
  scannerUsed: string;          // Which scanner detected it
  
  // Triage outcome
  outcome: TriageOutcome;
  triageFeedback?: string;      // Anonymized feedback from program
  
  // Quality metrics
  reproductionQuality: number;  // 0-1 how well the reproduction steps worked
  evidenceQuality: number;      // 0-1 how complete the evidence was
  impactAccuracy: number;       // 0-1 how accurate the impact assessment was
  
  // Time metrics
  discoveryToSubmissionMs: number;
  submissionToTriageMs?: number;
  triageToResolutionMs?: number;
  
  // Pattern extraction (context-independent)
  extractedPatterns: ExtractedPattern[];
}

// ─── Pattern Repository ────────────────────────────────────────────────────────

export type PatternCategory =
  | 'detection'         // How to detect this vuln class
  | 'reproduction'      // How to reproduce reliably
  | 'evidence'          // What evidence to capture
  | 'impact'            // How to assess impact accurately
  | 'evasion'           // How vuln evades detection
  | 'false_positive'    // Common false positive patterns
  | 'tool_config';      // Optimal tool configuration

export interface ExtractedPattern {
  id: string;
  category: PatternCategory;
  vulnClass: string;
  
  // Pattern content (MUST be context-independent)
  title: string;
  description: string;
  applicability: string;        // When this pattern applies
  
  // Confidence and provenance
  confidence: number;           // 0-1
  observationCount: number;     // How many times observed
  successRate: number;          // 0-1 when applied
  
  // Contamination check
  isContextIndependent: boolean; // MUST be true to be stored
  sanitizationApplied: string[];
  
  // Timestamps
  firstObserved: number;
  lastObserved: number;
  lastValidated: number;
}

/**
 * Pattern Repository — stores context-independent patterns learned from
 * bug bounty triage outcomes and vulnerability validation.
 */
export class PatternRepository {
  private patterns: Map<string, ExtractedPattern> = new Map();
  
  /**
   * Add or update a pattern in the repository.
   * Rejects patterns that are not context-independent.
   */
  addPattern(pattern: ExtractedPattern): boolean {
    // Contamination check — reject target-specific patterns
    if (!pattern.isContextIndependent) {
      return false;
    }
    
    if (!passesContaminationCheck(pattern)) {
      return false;
    }
    
    const existing = this.patterns.get(pattern.id);
    if (existing) {
      // Merge: increment observation count, update success rate
      existing.observationCount += 1;
      existing.successRate = (existing.successRate * (existing.observationCount - 1) + pattern.successRate) / existing.observationCount;
      existing.confidence = Math.min(1.0, existing.confidence + 0.05);
      existing.lastObserved = pattern.lastObserved;
      return true;
    }
    
    this.patterns.set(pattern.id, { ...pattern });
    return true;
  }
  
  /**
   * Get patterns for a specific vulnerability class and category.
   */
  getPatterns(vulnClass: string, category?: PatternCategory): ExtractedPattern[] {
    const results: ExtractedPattern[] = [];
    for (const p of this.patterns.values()) {
      if (p.vulnClass === vulnClass || p.vulnClass === '*') {
        if (!category || p.category === category) {
          results.push(p);
        }
      }
    }
    return results.sort((a, b) => b.confidence - a.confidence);
  }
  
  /**
   * Get all patterns above a confidence threshold.
   */
  getHighConfidencePatterns(minConfidence: number = 0.7): ExtractedPattern[] {
    return Array.from(this.patterns.values())
      .filter(p => p.confidence >= minConfidence)
      .sort((a, b) => b.confidence - a.confidence);
  }
  
  /**
   * Export all patterns for serialization.
   */
  exportPatterns(): ExtractedPattern[] {
    return Array.from(this.patterns.values());
  }
  
  /**
   * Import patterns from serialized data.
   */
  importPatterns(patterns: ExtractedPattern[]): { imported: number; rejected: number } {
    let imported = 0;
    let rejected = 0;
    for (const p of patterns) {
      if (this.addPattern(p)) {
        imported++;
      } else {
        rejected++;
      }
    }
    return { imported, rejected };
  }
  
  /**
   * Get repository statistics.
   */
  getStats(): PatternRepositoryStats {
    const patterns = Array.from(this.patterns.values());
    const byCategory: Record<string, number> = {};
    const byVulnClass: Record<string, number> = {};
    
    for (const p of patterns) {
      byCategory[p.category] = (byCategory[p.category] || 0) + 1;
      byVulnClass[p.vulnClass] = (byVulnClass[p.vulnClass] || 0) + 1;
    }
    
    return {
      totalPatterns: patterns.length,
      byCategory,
      byVulnClass,
      averageConfidence: patterns.length > 0 
        ? patterns.reduce((sum, p) => sum + p.confidence, 0) / patterns.length 
        : 0,
      averageObservations: patterns.length > 0
        ? patterns.reduce((sum, p) => sum + p.observationCount, 0) / patterns.length
        : 0,
    };
  }
}

export interface PatternRepositoryStats {
  totalPatterns: number;
  byCategory: Record<string, number>;
  byVulnClass: Record<string, number>;
  averageConfidence: number;
  averageObservations: number;
}

// ─── Vulnerability Validation Calibration ──────────────────────────────────────

export interface CalibrationEntry {
  vulnClass: string;
  scannerUsed: string;
  detectionMethod: string;
  
  // Calibration metrics
  truePositiveRate: number;     // 0-1
  falsePositiveRate: number;    // 0-1
  sampleSize: number;
  
  // Confidence adjustment
  confidenceAdjustment: number; // Additive adjustment to scanner confidence
  
  lastUpdated: number;
}

/**
 * Calibration Pipeline — adjusts scanner confidence based on
 * bug bounty triage outcomes (accepted = true positive, informative/NA = false positive).
 */
export class CalibrationPipeline {
  private entries: Map<string, CalibrationEntry> = new Map();
  
  /**
   * Record a triage outcome for calibration.
   */
  recordOutcome(params: {
    vulnClass: string;
    scannerUsed: string;
    detectionMethod: string;
    wasAccepted: boolean;
  }): void {
    const key = `${params.vulnClass}:${params.scannerUsed}:${params.detectionMethod}`;
    const existing = this.entries.get(key);
    
    if (existing) {
      const newSampleSize = existing.sampleSize + 1;
      if (params.wasAccepted) {
        existing.truePositiveRate = (existing.truePositiveRate * existing.sampleSize + 1) / newSampleSize;
        existing.falsePositiveRate = (existing.falsePositiveRate * existing.sampleSize) / newSampleSize;
      } else {
        existing.truePositiveRate = (existing.truePositiveRate * existing.sampleSize) / newSampleSize;
        existing.falsePositiveRate = (existing.falsePositiveRate * existing.sampleSize + 1) / newSampleSize;
      }
      existing.sampleSize = newSampleSize;
      existing.confidenceAdjustment = computeConfidenceAdjustment(existing.truePositiveRate, existing.sampleSize);
      existing.lastUpdated = Date.now();
    } else {
      this.entries.set(key, {
        vulnClass: params.vulnClass,
        scannerUsed: params.scannerUsed,
        detectionMethod: params.detectionMethod,
        truePositiveRate: params.wasAccepted ? 1.0 : 0.0,
        falsePositiveRate: params.wasAccepted ? 0.0 : 1.0,
        sampleSize: 1,
        confidenceAdjustment: 0, // Not enough data yet
        lastUpdated: Date.now(),
      });
    }
  }
  
  /**
   * Get the confidence adjustment for a specific scanner/vuln class combination.
   * Returns 0 if insufficient data.
   */
  getConfidenceAdjustment(vulnClass: string, scannerUsed: string, detectionMethod: string): number {
    const key = `${vulnClass}:${scannerUsed}:${detectionMethod}`;
    const entry = this.entries.get(key);
    if (!entry || entry.sampleSize < 5) return 0; // Need minimum 5 samples
    return entry.confidenceAdjustment;
  }
  
  /**
   * Get calibration data for a scanner.
   */
  getScannerCalibration(scannerUsed: string): CalibrationEntry[] {
    return Array.from(this.entries.values())
      .filter(e => e.scannerUsed === scannerUsed)
      .sort((a, b) => b.sampleSize - a.sampleSize);
  }
  
  /**
   * Export all calibration data.
   */
  exportCalibration(): CalibrationEntry[] {
    return Array.from(this.entries.values());
  }
  
  /**
   * Import calibration data.
   */
  importCalibration(entries: CalibrationEntry[]): void {
    for (const e of entries) {
      const key = `${e.vulnClass}:${e.scannerUsed}:${e.detectionMethod}`;
      this.entries.set(key, { ...e });
    }
  }
}

// ─── Tool Effectiveness Tracking ───────────────────────────────────────────────

export interface ToolEffectivenessEntry {
  toolName: string;             // e.g., "nuclei", "zap", "burp"
  vulnClass: string;
  
  // Effectiveness metrics
  detectionRate: number;        // 0-1 how often tool detects this vuln class
  falsePositiveRate: number;    // 0-1 false positive rate
  uniqueFindings: number;       // Findings only this tool found
  corroboratedFindings: number; // Findings also found by other tools
  
  // Configuration insights
  bestConfig?: string;          // Optimal configuration for this vuln class
  templateIds?: string[];       // Best templates (for Nuclei)
  
  sampleSize: number;
  lastUpdated: number;
}

/**
 * Track tool effectiveness across vulnerability classes.
 */
export class ToolEffectivenessTracker {
  private entries: Map<string, ToolEffectivenessEntry> = new Map();
  
  /**
   * Record a tool's performance for a vulnerability class.
   */
  recordPerformance(params: {
    toolName: string;
    vulnClass: string;
    detected: boolean;
    wasTruePositive: boolean;
    wasUniqueToTool: boolean;
    wasCorroborated: boolean;
    config?: string;
    templateId?: string;
  }): void {
    const key = `${params.toolName}:${params.vulnClass}`;
    const existing = this.entries.get(key);
    
    if (existing) {
      const n = existing.sampleSize + 1;
      existing.detectionRate = (existing.detectionRate * existing.sampleSize + (params.detected ? 1 : 0)) / n;
      existing.falsePositiveRate = (existing.falsePositiveRate * existing.sampleSize + (params.detected && !params.wasTruePositive ? 1 : 0)) / n;
      if (params.wasUniqueToTool) existing.uniqueFindings++;
      if (params.wasCorroborated) existing.corroboratedFindings++;
      existing.sampleSize = n;
      existing.lastUpdated = Date.now();
      if (params.templateId && !existing.templateIds?.includes(params.templateId)) {
        existing.templateIds = [...(existing.templateIds || []), params.templateId];
      }
    } else {
      this.entries.set(key, {
        toolName: params.toolName,
        vulnClass: params.vulnClass,
        detectionRate: params.detected ? 1.0 : 0.0,
        falsePositiveRate: params.detected && !params.wasTruePositive ? 1.0 : 0.0,
        uniqueFindings: params.wasUniqueToTool ? 1 : 0,
        corroboratedFindings: params.wasCorroborated ? 1 : 0,
        bestConfig: params.config,
        templateIds: params.templateId ? [params.templateId] : undefined,
        sampleSize: 1,
        lastUpdated: Date.now(),
      });
    }
  }
  
  /**
   * Get the best tool for detecting a specific vulnerability class.
   */
  getBestToolForVulnClass(vulnClass: string): ToolEffectivenessEntry | undefined {
    const candidates = Array.from(this.entries.values())
      .filter(e => e.vulnClass === vulnClass && e.sampleSize >= 3);
    
    if (candidates.length === 0) return undefined;
    
    // Score: detection rate * (1 - false positive rate)
    return candidates.sort((a, b) => {
      const scoreA = a.detectionRate * (1 - a.falsePositiveRate);
      const scoreB = b.detectionRate * (1 - b.falsePositiveRate);
      return scoreB - scoreA;
    })[0];
  }
  
  /**
   * Get effectiveness summary for all tools.
   */
  getEffectivenessSummary(): Record<string, {
    overallDetectionRate: number;
    overallFalsePositiveRate: number;
    strongVulnClasses: string[];
    weakVulnClasses: string[];
  }> {
    const byTool = new Map<string, ToolEffectivenessEntry[]>();
    for (const e of this.entries.values()) {
      const existing = byTool.get(e.toolName) || [];
      existing.push(e);
      byTool.set(e.toolName, existing);
    }
    
    const summary: Record<string, any> = {};
    for (const [tool, entries] of byTool) {
      const totalSamples = entries.reduce((s, e) => s + e.sampleSize, 0);
      const weightedDetection = entries.reduce((s, e) => s + e.detectionRate * e.sampleSize, 0) / totalSamples;
      const weightedFP = entries.reduce((s, e) => s + e.falsePositiveRate * e.sampleSize, 0) / totalSamples;
      
      summary[tool] = {
        overallDetectionRate: weightedDetection,
        overallFalsePositiveRate: weightedFP,
        strongVulnClasses: entries.filter(e => e.detectionRate > 0.7 && e.sampleSize >= 3).map(e => e.vulnClass),
        weakVulnClasses: entries.filter(e => e.detectionRate < 0.3 && e.sampleSize >= 3).map(e => e.vulnClass),
      };
    }
    
    return summary;
  }
  
  /**
   * Export all effectiveness data.
   */
  exportData(): ToolEffectivenessEntry[] {
    return Array.from(this.entries.values());
  }
  
  /**
   * Import effectiveness data.
   */
  importData(entries: ToolEffectivenessEntry[]): void {
    for (const e of entries) {
      const key = `${e.toolName}:${e.vulnClass}`;
      this.entries.set(key, { ...e });
    }
  }
}

// ─── Reproduction Quality Patterns ─────────────────────────────────────────────

export interface ReproductionQualityMetrics {
  vulnClass: string;
  
  // Quality dimensions
  stepsClarity: number;         // 0-1 how clear the steps are
  evidenceCompleteness: number; // 0-1 how complete the evidence is
  impactDemonstration: number;  // 0-1 how well impact is demonstrated
  automationPotential: number;  // 0-1 can this be automated
  
  // Best practices for this vuln class
  requiredEvidence: string[];
  optimalStepCount: number;
  commonMistakes: string[];
  
  sampleSize: number;
  lastUpdated: number;
}

/**
 * Get reproduction quality guidelines for a vulnerability class.
 */
export function getReproductionGuidelines(vulnClass: string): ReproductionQualityMetrics {
  const guidelines = REPRODUCTION_GUIDELINES[vulnClass] || REPRODUCTION_GUIDELINES['default'];
  return { ...guidelines };
}

const REPRODUCTION_GUIDELINES: Record<string, ReproductionQualityMetrics> = {
  'SQL Injection': {
    vulnClass: 'SQL Injection',
    stepsClarity: 0.9,
    evidenceCompleteness: 0.85,
    impactDemonstration: 0.9,
    automationPotential: 0.8,
    requiredEvidence: [
      'HTTP request with payload',
      'HTTP response showing injection result',
      'Database error message or extracted data',
      'CVSS vector justification',
    ],
    optimalStepCount: 5,
    commonMistakes: [
      'Not showing data extraction (just error-based proof)',
      'Using automated tool output without manual verification',
      'Not demonstrating impact beyond error message',
      'Missing parameter identification',
    ],
    sampleSize: 0,
    lastUpdated: Date.now(),
  },
  'Cross-Site Scripting': {
    vulnClass: 'Cross-Site Scripting',
    stepsClarity: 0.85,
    evidenceCompleteness: 0.8,
    impactDemonstration: 0.85,
    automationPotential: 0.7,
    requiredEvidence: [
      'HTTP request with XSS payload',
      'Screenshot showing payload execution in browser',
      'DOM inspection showing injected code',
      'Impact demonstration (cookie theft, session hijack, etc.)',
    ],
    optimalStepCount: 4,
    commonMistakes: [
      'Only showing alert(1) without real impact',
      'Self-XSS without demonstrating victim exploitation path',
      'Not specifying XSS type (reflected/stored/DOM)',
      'Missing context (authenticated vs unauthenticated)',
    ],
    sampleSize: 0,
    lastUpdated: Date.now(),
  },
  'Remote Code Execution': {
    vulnClass: 'Remote Code Execution',
    stepsClarity: 0.95,
    evidenceCompleteness: 0.95,
    impactDemonstration: 0.95,
    automationPotential: 0.6,
    requiredEvidence: [
      'HTTP request triggering code execution',
      'Command output proving execution (id, whoami, etc.)',
      'Server response with execution result',
      'Network-level evidence (reverse shell, DNS callback)',
    ],
    optimalStepCount: 6,
    commonMistakes: [
      'Not proving actual code execution (just file read)',
      'Using destructive commands in PoC',
      'Not documenting the execution context (user, permissions)',
      'Missing version/configuration prerequisites',
    ],
    sampleSize: 0,
    lastUpdated: Date.now(),
  },
  'Server-Side Request Forgery': {
    vulnClass: 'Server-Side Request Forgery',
    stepsClarity: 0.85,
    evidenceCompleteness: 0.85,
    impactDemonstration: 0.9,
    automationPotential: 0.7,
    requiredEvidence: [
      'HTTP request with SSRF payload',
      'Evidence of internal resource access (metadata, internal API)',
      'DNS callback or HTTP callback proof',
      'Impact demonstration (cloud metadata, internal network scan)',
    ],
    optimalStepCount: 5,
    commonMistakes: [
      'Only showing DNS callback without internal access',
      'Not demonstrating access to sensitive internal resources',
      'Confusing open redirect with SSRF',
      'Not testing cloud metadata endpoints',
    ],
    sampleSize: 0,
    lastUpdated: Date.now(),
  },
  'default': {
    vulnClass: 'default',
    stepsClarity: 0.8,
    evidenceCompleteness: 0.8,
    impactDemonstration: 0.8,
    automationPotential: 0.5,
    requiredEvidence: [
      'HTTP request demonstrating the vulnerability',
      'HTTP response showing the vulnerability',
      'Screenshot or video of exploitation',
      'Impact assessment with CVSS justification',
    ],
    optimalStepCount: 5,
    commonMistakes: [
      'Insufficient evidence for the claimed severity',
      'Missing reproduction steps',
      'Not demonstrating real-world impact',
      'Automated scan output without manual verification',
    ],
    sampleSize: 0,
    lastUpdated: Date.now(),
  },
};

// ─── Cross-Training Orchestrator ───────────────────────────────────────────────

export interface CrossTrainingResult {
  patternsExtracted: number;
  calibrationUpdates: number;
  toolEffectivenessUpdates: number;
  contaminationRejections: number;
}

/**
 * Process a batch of bug bounty outcomes and feed them into the cross-training pipeline.
 * This is the main entry point for cross-training.
 */
export function processCrossTrainingBatch(
  outcomes: OutcomeLogEntry[],
  patternRepo: PatternRepository,
  calibrationPipeline: CalibrationPipeline,
  toolTracker: ToolEffectivenessTracker
): CrossTrainingResult {
  let patternsExtracted = 0;
  let calibrationUpdates = 0;
  let toolEffectivenessUpdates = 0;
  let contaminationRejections = 0;
  
  for (const outcome of outcomes) {
    // 1. Feed calibration pipeline
    const wasAccepted = outcome.outcome === 'accepted' || outcome.outcome === 'bounty_paid';
    calibrationPipeline.recordOutcome({
      vulnClass: outcome.vulnClass,
      scannerUsed: outcome.scannerUsed,
      detectionMethod: outcome.detectionMethod,
      wasAccepted,
    });
    calibrationUpdates++;
    
    // 2. Feed tool effectiveness tracker
    toolTracker.recordPerformance({
      toolName: outcome.scannerUsed,
      vulnClass: outcome.vulnClass,
      detected: true,
      wasTruePositive: wasAccepted,
      wasUniqueToTool: false, // Would need cross-scanner data
      wasCorroborated: false,
    });
    toolEffectivenessUpdates++;
    
    // 3. Extract patterns from outcomes
    for (const pattern of outcome.extractedPatterns) {
      if (patternRepo.addPattern(pattern)) {
        patternsExtracted++;
      } else {
        contaminationRejections++;
      }
    }
  }
  
  return {
    patternsExtracted,
    calibrationUpdates,
    toolEffectivenessUpdates,
    contaminationRejections,
  };
}

// ─── Contamination Check ───────────────────────────────────────────────────────

/**
 * Check if a pattern is safe to store (context-independent).
 * Rejects patterns that contain target-specific information.
 */
function passesContaminationCheck(pattern: ExtractedPattern): boolean {
  const content = `${pattern.title} ${pattern.description} ${pattern.applicability}`.toLowerCase();
  
  // Check for IP addresses
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(content)) return false;
  
  // Check for domain names (simple heuristic)
  if (/[a-z0-9][-a-z0-9]*\.(com|org|net|io|gov|edu|mil|co\.[a-z]{2})/i.test(content)) return false;
  
  // Check for URLs
  if (/https?:\/\//i.test(content)) return false;
  
  // Check for email addresses
  if (/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(content)) return false;
  
  // Check for API keys / tokens (long hex/base64 strings)
  if (/[a-f0-9]{32,}/i.test(content)) return false;
  if (/[A-Za-z0-9+/]{40,}={0,2}/.test(content)) return false;
  
  // Check for internal paths
  if (/\/home\/|\/var\/|\/etc\/|C:\\|\\Users\\/i.test(content)) return false;
  
  return true;
}

function computeConfidenceAdjustment(truePositiveRate: number, sampleSize: number): number {
  // Only adjust if we have enough data
  if (sampleSize < 5) return 0;
  
  // Positive adjustment for high TP rate, negative for low
  // Capped at ±0.2
  const adjustment = (truePositiveRate - 0.5) * 0.4;
  return Math.max(-0.2, Math.min(0.2, adjustment));
}
