/**
 * Bug Bounty Negative Example Pipeline
 * 
 * Captures and categorizes failed submissions, false positives, and
 * rejected findings to build a training corpus that teaches the system
 * what NOT to report. This is critical for reducing noise and improving
 * precision over time.
 * 
 * Key insight from the review: "The training pipeline needs negative examples
 * as much as positive ones — knowing what was rejected and why is equally
 * valuable for calibration."
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type RejectionReason =
  | 'duplicate'
  | 'out_of_scope'
  | 'informational_only'
  | 'not_reproducible'
  | 'intended_behavior'
  | 'insufficient_impact'
  | 'false_positive'
  | 'known_issue'
  | 'wont_fix'
  | 'spam'
  | 'invalid_vulnerability'
  | 'already_patched';

export interface NegativeExample {
  id: string;
  vulnClass: string;
  title: string;
  affectedEndpoint: string;
  technology?: string;
  severity: string;
  rejectionReason: RejectionReason;
  rejectionDetail: string;
  programHandle?: string;
  submittedAt: string;
  rejectedAt: string;
  triagerFeedback?: string;
  lessonsLearned: string[];
  tags: string[];
}

export interface NegativeExampleStats {
  totalExamples: number;
  byRejectionReason: Record<RejectionReason, number>;
  byVulnClass: Record<string, number>;
  topLessons: Array<{ lesson: string; frequency: number }>;
  falsePositiveRate: number;
  duplicateRate: number;
  averageTimeWasted: string;
}

export interface TrainingSignal {
  vulnClass: string;
  endpoint: string;
  technology?: string;
  isPositive: boolean;
  weight: number; // 0.0 - 1.0
  reason: string;
  source: 'negative_pipeline' | 'positive_outcome' | 'calibration';
}

// ─── Rejection Pattern Analysis ──────────────────────────────────────────────

interface RejectionPattern {
  reasonPattern: RejectionReason;
  vulnClassPattern?: RegExp;
  endpointPattern?: RegExp;
  techPattern?: RegExp;
  frequency: number;
  lesson: string;
  preventionStrategy: string;
}

const COMMON_REJECTION_PATTERNS: RejectionPattern[] = [
  {
    reasonPattern: 'duplicate',
    vulnClassPattern: /xss_reflected/i,
    frequency: 0.35,
    lesson: 'Reflected XSS on common endpoints is almost always already reported',
    preventionStrategy: 'Run duplicate check before investing investigation time',
  },
  {
    reasonPattern: 'out_of_scope',
    endpointPattern: /api\.(third-party|external|cdn)/i,
    frequency: 0.15,
    lesson: 'Third-party API endpoints are typically out of scope',
    preventionStrategy: 'Verify the asset is explicitly listed in the program scope before testing',
  },
  {
    reasonPattern: 'informational_only',
    vulnClassPattern: /info_disclosure|missing_header/i,
    frequency: 0.25,
    lesson: 'Information disclosure and missing headers are often classified as informational, not vulnerabilities',
    preventionStrategy: 'Focus on findings with demonstrable security impact beyond information leakage',
  },
  {
    reasonPattern: 'not_reproducible',
    frequency: 0.10,
    lesson: 'Findings that cannot be reliably reproduced are rejected regardless of severity',
    preventionStrategy: 'Ensure reproduction steps are deterministic and include all necessary context (cookies, headers, timing)',
  },
  {
    reasonPattern: 'intended_behavior',
    vulnClassPattern: /business_logic|rate_limit/i,
    frequency: 0.08,
    lesson: 'What appears to be a business logic flaw may be intended behavior by the application',
    preventionStrategy: 'Research the application documentation and common patterns before reporting business logic issues',
  },
  {
    reasonPattern: 'insufficient_impact',
    vulnClassPattern: /csrf/i,
    endpointPattern: /logout|language|theme|preference/i,
    frequency: 0.12,
    lesson: 'CSRF on non-sensitive actions (logout, language change) is typically rejected as insufficient impact',
    preventionStrategy: 'Only report CSRF when the affected action has meaningful security consequences',
  },
  {
    reasonPattern: 'false_positive',
    vulnClassPattern: /sqli/i,
    frequency: 0.08,
    lesson: 'Scanner-detected SQL injection that cannot be manually confirmed is a false positive',
    preventionStrategy: 'Always manually verify automated scanner findings before submission',
  },
  {
    reasonPattern: 'already_patched',
    frequency: 0.05,
    lesson: 'The vulnerability was already patched between discovery and submission',
    preventionStrategy: 'Submit findings promptly and verify they are still exploitable before final submission',
  },
];

// ─── Negative Example Repository ─────────────────────────────────────────────

export class NegativeExampleRepository {
  private examples: NegativeExample[] = [];
  private trainingSignals: TrainingSignal[] = [];

  addExample(example: NegativeExample): void {
    this.examples.push(example);
    
    // Generate training signal from the negative example
    this.trainingSignals.push({
      vulnClass: example.vulnClass,
      endpoint: example.affectedEndpoint,
      technology: example.technology,
      isPositive: false,
      weight: this.calculateWeight(example),
      reason: `Rejected: ${example.rejectionReason} — ${example.rejectionDetail}`,
      source: 'negative_pipeline',
    });
  }

  addPositiveExample(vulnClass: string, endpoint: string, technology?: string, reason?: string): void {
    this.trainingSignals.push({
      vulnClass,
      endpoint,
      technology,
      isPositive: true,
      weight: 1.0,
      reason: reason || 'Accepted finding',
      source: 'positive_outcome',
    });
  }

  private calculateWeight(example: NegativeExample): number {
    // Weight negative examples by how informative they are
    const weights: Record<RejectionReason, number> = {
      false_positive: 1.0,       // Most informative — system was wrong
      duplicate: 0.7,            // Useful for duplicate detection training
      out_of_scope: 0.8,         // Important for scope awareness
      informational_only: 0.6,   // Helps calibrate severity thresholds
      not_reproducible: 0.5,     // Moderately useful
      intended_behavior: 0.9,    // Very informative — system misunderstood the app
      insufficient_impact: 0.6,  // Helps calibrate impact assessment
      known_issue: 0.4,          // Less informative — timing issue
      wont_fix: 0.3,             // Least informative — vendor decision
      spam: 0.1,                 // Not useful for training
      invalid_vulnerability: 0.9, // Very informative — fundamental misclassification
      already_patched: 0.2,      // Timing issue, not a learning opportunity
    };
    return weights[example.rejectionReason] || 0.5;
  }

  getExamples(filter?: { vulnClass?: string; rejectionReason?: RejectionReason; programHandle?: string }): NegativeExample[] {
    let results = [...this.examples];
    if (filter?.vulnClass) results = results.filter(e => e.vulnClass === filter.vulnClass);
    if (filter?.rejectionReason) results = results.filter(e => e.rejectionReason === filter.rejectionReason);
    if (filter?.programHandle) results = results.filter(e => e.programHandle === filter.programHandle);
    return results;
  }

  getTrainingSignals(vulnClass?: string): TrainingSignal[] {
    if (vulnClass) return this.trainingSignals.filter(s => s.vulnClass === vulnClass);
    return [...this.trainingSignals];
  }

  getStats(): NegativeExampleStats {
    const byReason: Record<string, number> = {};
    const byVulnClass: Record<string, number> = {};
    const lessonFreq = new Map<string, number>();

    for (const ex of this.examples) {
      byReason[ex.rejectionReason] = (byReason[ex.rejectionReason] || 0) + 1;
      byVulnClass[ex.vulnClass] = (byVulnClass[ex.vulnClass] || 0) + 1;
      for (const lesson of ex.lessonsLearned) {
        lessonFreq.set(lesson, (lessonFreq.get(lesson) || 0) + 1);
      }
    }

    const total = this.examples.length;
    const fpCount = byReason['false_positive'] || 0;
    const dupCount = byReason['duplicate'] || 0;

    return {
      totalExamples: total,
      byRejectionReason: byReason as Record<RejectionReason, number>,
      byVulnClass,
      topLessons: Array.from(lessonFreq.entries())
        .map(([lesson, frequency]) => ({ lesson, frequency }))
        .sort((a, b) => b.frequency - a.frequency)
        .slice(0, 10),
      falsePositiveRate: total > 0 ? fpCount / total : 0,
      duplicateRate: total > 0 ? dupCount / total : 0,
      averageTimeWasted: `${(total * 2.5).toFixed(1)} hours`, // ~2.5 hours per rejected submission
    };
  }

  /**
   * Analyze rejection patterns to identify systemic issues
   */
  analyzePatterns(): Array<{
    pattern: string;
    frequency: number;
    affectedVulnClasses: string[];
    preventionStrategy: string;
    estimatedTimeSavings: string;
  }> {
    const patternMatches = new Map<string, { count: number; vulnClasses: Set<string>; strategy: string }>();

    for (const example of this.examples) {
      for (const pattern of COMMON_REJECTION_PATTERNS) {
        if (pattern.reasonPattern !== example.rejectionReason) continue;
        if (pattern.vulnClassPattern && !pattern.vulnClassPattern.test(example.vulnClass)) continue;
        if (pattern.endpointPattern && !pattern.endpointPattern.test(example.affectedEndpoint)) continue;

        const key = pattern.lesson;
        const existing = patternMatches.get(key) || { count: 0, vulnClasses: new Set<string>(), strategy: pattern.preventionStrategy };
        existing.count++;
        existing.vulnClasses.add(example.vulnClass);
        patternMatches.set(key, existing);
      }
    }

    return Array.from(patternMatches.entries())
      .map(([pattern, data]) => ({
        pattern,
        frequency: data.count / Math.max(this.examples.length, 1),
        affectedVulnClasses: Array.from(data.vulnClasses),
        preventionStrategy: data.strategy,
        estimatedTimeSavings: `${(data.count * 2.5).toFixed(1)} hours`,
      }))
      .sort((a, b) => b.frequency - a.frequency);
  }

  /**
   * Generate a training context string for LLM prompts
   */
  buildNegativeExampleContext(vulnClass?: string, limit: number = 5): string {
    const relevant = vulnClass
      ? this.examples.filter(e => e.vulnClass === vulnClass)
      : this.examples;

    const topExamples = relevant
      .sort((a, b) => this.calculateWeight(b) - this.calculateWeight(a))
      .slice(0, limit);

    if (topExamples.length === 0) return '';

    const lines = ['## Known Rejection Patterns (Learn from past mistakes)'];
    for (const ex of topExamples) {
      lines.push(`- **${ex.vulnClass}** at ${ex.affectedEndpoint}: Rejected as "${ex.rejectionReason}" — ${ex.rejectionDetail}`);
      if (ex.lessonsLearned.length > 0) {
        lines.push(`  Lesson: ${ex.lessonsLearned[0]}`);
      }
    }

    return lines.join('\n');
  }

  clear(): void {
    this.examples = [];
    this.trainingSignals = [];
  }
}

// ─── Program-Aware Context ───────────────────────────────────────────────────

export interface ProgramContext {
  handle: string;
  platform: 'hackerone' | 'bugcrowd' | 'intigriti' | 'other';
  scopeAssets: ScopeAsset[];
  outOfScopePatterns: string[];
  rewardStructure: RewardTier[];
  responseTimeSLA: { firstResponse: string; triage: string; bounty: string };
  acceptedVulnClasses: string[];
  rejectedVulnClasses: string[];
  historicalAcceptanceRate: number;
  averageBountyByClass: Record<string, number>;
  notes: string[];
}

export interface ScopeAsset {
  type: 'domain' | 'wildcard' | 'api' | 'mobile_app' | 'source_code' | 'hardware';
  identifier: string;
  eligible: boolean;
  maxSeverity?: string;
  notes?: string;
}

export interface RewardTier {
  severity: string;
  minBounty: number;
  maxBounty: number;
  currency: string;
}

export class ProgramContextManager {
  private programs: Map<string, ProgramContext> = new Map();

  addProgram(context: ProgramContext): void {
    this.programs.set(context.handle, context);
  }

  getProgram(handle: string): ProgramContext | undefined {
    return this.programs.get(handle);
  }

  /**
   * Check if a finding is in scope for a program
   */
  isInScope(programHandle: string, endpoint: string, vulnClass: string): {
    inScope: boolean;
    reason: string;
    maxBounty?: number;
  } {
    const program = this.programs.get(programHandle);
    if (!program) return { inScope: true, reason: 'Program context not available — assume in scope' };

    // Check if vuln class is explicitly rejected
    if (program.rejectedVulnClasses.includes(vulnClass)) {
      return { inScope: false, reason: `${vulnClass} is explicitly excluded by ${programHandle}` };
    }

    // Check out-of-scope patterns
    for (const pattern of program.outOfScopePatterns) {
      try {
        if (new RegExp(pattern, 'i').test(endpoint)) {
          return { inScope: false, reason: `Endpoint matches out-of-scope pattern: ${pattern}` };
        }
      } catch {
        // Invalid regex, skip
      }
    }

    // Check scope assets
    const matchedAsset = program.scopeAssets.find(asset => {
      if (asset.type === 'wildcard') {
        const wildcardRegex = new RegExp(asset.identifier.replace(/\*/g, '.*'), 'i');
        return wildcardRegex.test(endpoint);
      }
      return endpoint.includes(asset.identifier);
    });

    if (matchedAsset && !matchedAsset.eligible) {
      return { inScope: false, reason: `Asset ${matchedAsset.identifier} is listed but not eligible for bounty` };
    }

    // Estimate max bounty
    const bountyEstimate = program.averageBountyByClass[vulnClass];
    const rewardTier = program.rewardStructure.find(t => t.severity === 'high');

    return {
      inScope: true,
      reason: matchedAsset ? `Matches scope asset: ${matchedAsset.identifier}` : 'No explicit exclusion found',
      maxBounty: bountyEstimate || rewardTier?.maxBounty,
    };
  }

  /**
   * Estimate expected bounty for a finding
   */
  estimateBounty(programHandle: string, vulnClass: string, severity: string): {
    estimate: number;
    range: { min: number; max: number };
    confidence: 'high' | 'medium' | 'low';
    currency: string;
  } {
    const program = this.programs.get(programHandle);
    if (!program) {
      return { estimate: 0, range: { min: 0, max: 0 }, confidence: 'low', currency: 'USD' };
    }

    // Check historical average for this vuln class
    const historicalAvg = program.averageBountyByClass[vulnClass];
    if (historicalAvg) {
      return {
        estimate: historicalAvg,
        range: { min: Math.round(historicalAvg * 0.5), max: Math.round(historicalAvg * 1.5) },
        confidence: 'high',
        currency: program.rewardStructure[0]?.currency || 'USD',
      };
    }

    // Fall back to reward tier
    const tier = program.rewardStructure.find(t => t.severity === severity);
    if (tier) {
      return {
        estimate: Math.round((tier.minBounty + tier.maxBounty) / 2),
        range: { min: tier.minBounty, max: tier.maxBounty },
        confidence: 'medium',
        currency: tier.currency,
      };
    }

    return { estimate: 0, range: { min: 0, max: 0 }, confidence: 'low', currency: 'USD' };
  }

  /**
   * Build program context string for LLM prompts
   */
  buildProgramContext(programHandle: string): string {
    const program = this.programs.get(programHandle);
    if (!program) return '';

    const lines = [
      `## Program Context: ${program.handle} (${program.platform})`,
      `Acceptance Rate: ${(program.historicalAcceptanceRate * 100).toFixed(0)}%`,
      `Response SLA: First response ${program.responseTimeSLA.firstResponse}, Triage ${program.responseTimeSLA.triage}`,
      '',
      '### Scope:',
      ...program.scopeAssets.map(a => `- ${a.eligible ? '✅' : '❌'} ${a.type}: ${a.identifier}${a.notes ? ` (${a.notes})` : ''}`),
      '',
      '### Out of Scope:',
      ...program.outOfScopePatterns.map(p => `- ${p}`),
      '',
      '### Rejected Vuln Classes:',
      ...program.rejectedVulnClasses.map(v => `- ${v}`),
      '',
      '### Reward Structure:',
      ...program.rewardStructure.map(t => `- ${t.severity}: ${t.currency} ${t.minBounty} - ${t.maxBounty}`),
    ];

    return lines.join('\n');
  }

  getAllPrograms(): ProgramContext[] {
    return Array.from(this.programs.values());
  }

  clear(): void {
    this.programs.clear();
  }
}

// ─── Singleton Exports ───────────────────────────────────────────────────────

export const negativeExampleRepo = new NegativeExampleRepository();
export const programContextManager = new ProgramContextManager();
