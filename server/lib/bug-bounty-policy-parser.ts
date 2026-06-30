/**
 * Bug Bounty Program Policy Parser & Scope Enforcement
 * 
 * Parses program policies from HackerOne, Bugcrowd, Intigriti, Synack, and YesWeHack
 * into structured PolicyROE (Rules of Engagement) format.
 * 
 * Provides scope enforcement, finding documentation workflow,
 * originality verification, and submission formatting.
 */

// ─── Policy ROE Interface ──────────────────────────────────────────────────────

export interface PolicyROE {
  programId: string;
  programName: string;
  platform: BugBountyPlatform;
  programUrl: string;
  
  // Scope
  scope: {
    inScope: ScopeTarget[];
    outOfScope: ScopeTarget[];
    wildcardDomains: string[];     // *.example.com patterns
  };
  
  // Rules
  rules: {
    allowedTestTypes: TestType[];
    prohibitedActions: string[];
    safeHarborStatement?: string;
    disclosurePolicy: 'coordinated' | 'full' | 'none' | 'custom';
    disclosureTimeline?: number;   // Days until public disclosure
    requiresAccountCreation: boolean;
    requiresVPN: boolean;
    testingHoursRestriction?: string;
  };
  
  // Bounty structure
  bounty: {
    hasBounty: boolean;
    currency: string;
    ranges: BountyRange[];
    bonusCategories?: string[];
  };
  
  // Vulnerability types
  vulnTypes: {
    accepted: VulnTypePolicy[];
    excluded: string[];           // Excluded vuln types (e.g., "self-XSS", "clickjacking on non-sensitive pages")
  };
  
  // Response expectations
  responseExpectations: {
    firstResponseDays?: number;
    triageDays?: number;
    resolutionDays?: number;
    bountyPaymentDays?: number;
  };
  
  // Metadata
  lastUpdated: number;
  parsedAt: number;
  parseConfidence: number;       // 0-1 how confident the parse is
  rawPolicyText?: string;
}

export type BugBountyPlatform = 'hackerone' | 'bugcrowd' | 'intigriti' | 'synack' | 'yeswehack' | 'openbugbounty' | 'custom';

export type TestType = 
  | 'web_application'
  | 'api'
  | 'mobile_android'
  | 'mobile_ios'
  | 'network'
  | 'cloud'
  | 'iot'
  | 'hardware'
  | 'source_code'
  | 'social_engineering'
  | 'physical';

export interface ScopeTarget {
  type: 'domain' | 'ip' | 'cidr' | 'url' | 'mobile_app' | 'source_code' | 'other';
  target: string;               // The actual target (domain, IP, URL, etc.)
  instruction?: string;         // Special instructions for this target
  bountyEligible: boolean;
  maxSeverity?: string;         // Max severity accepted for this target
}

export interface BountyRange {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  minBounty: number;
  maxBounty: number;
}

export interface VulnTypePolicy {
  vulnType: string;
  accepted: boolean;
  maxSeverity?: string;
  specialInstructions?: string;
}

// ─── Scope Enforcement ─────────────────────────────────────────────────────────

export interface ScopeCheckResult {
  inScope: boolean;
  matchedTarget?: ScopeTarget;
  reason: string;
  bountyEligible: boolean;
  warnings: string[];
}

/**
 * Check if a target URL/domain is in scope for a bug bounty program.
 */
export function checkScope(target: string, policy: PolicyROE): ScopeCheckResult {
  const warnings: string[] = [];
  const normalizedTarget = normalizeTarget(target);
  
  // Check out-of-scope first (explicit exclusions take priority)
  for (const oos of policy.scope.outOfScope) {
    if (matchesScopeTarget(normalizedTarget, oos)) {
      return {
        inScope: false,
        matchedTarget: oos,
        reason: `Target matches out-of-scope entry: ${oos.target}`,
        bountyEligible: false,
        warnings,
      };
    }
  }
  
  // Check in-scope
  for (const is of policy.scope.inScope) {
    if (matchesScopeTarget(normalizedTarget, is)) {
      if (!is.bountyEligible) {
        warnings.push('Target is in scope but NOT bounty eligible');
      }
      return {
        inScope: true,
        matchedTarget: is,
        reason: `Target matches in-scope entry: ${is.target}`,
        bountyEligible: is.bountyEligible,
        warnings,
      };
    }
  }
  
  // Check wildcard domains
  for (const wildcard of policy.scope.wildcardDomains) {
    if (matchesWildcard(normalizedTarget, wildcard)) {
      return {
        inScope: true,
        reason: `Target matches wildcard domain: ${wildcard}`,
        bountyEligible: true,
        warnings,
      };
    }
  }
  
  return {
    inScope: false,
    reason: 'Target does not match any in-scope entry',
    bountyEligible: false,
    warnings: ['Target not found in program scope — testing may violate program rules'],
  };
}

/**
 * Batch check multiple targets against scope.
 */
export function batchCheckScope(targets: string[], policy: PolicyROE): Map<string, ScopeCheckResult> {
  const results = new Map<string, ScopeCheckResult>();
  for (const target of targets) {
    results.set(target, checkScope(target, policy));
  }
  return results;
}

// ─── Finding Documentation ─────────────────────────────────────────────────────

export interface BugBountyFinding {
  id: string;
  engagementId: number;
  
  // Finding details
  title: string;
  vulnType: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  cvssVector?: string;
  cvssScore?: number;
  cweId?: string;
  
  // Affected target
  target: string;
  endpoint?: string;
  parameter?: string;
  
  // Reproduction
  reproductionSteps: ReproductionStep[];
  prerequisites: string[];
  
  // Evidence
  evidence: BugBountyEvidence[];
  
  // Impact
  impactAnalysis: {
    technicalImpact: string;
    businessImpact: string;
    affectedUsers: 'all' | 'authenticated' | 'admin' | 'specific' | 'unknown';
    dataAtRisk: string[];
  };
  
  // Submission status
  status: FindingStatus;
  
  // Originality
  originalityCheck?: {
    isOriginal: boolean;
    similarFindings: string[];
    knownIssueRefs: string[];
    confidence: number;
  };
  
  // Platform-specific
  platformSubmissionId?: string;
  platformStatus?: string;
  bountyAmount?: number;
  
  // Timestamps
  discoveredAt: number;
  submittedAt?: number;
  triageAt?: number;
  resolvedAt?: number;
}

export type FindingStatus =
  | 'draft'
  | 'ready_for_review'
  | 'submitted'
  | 'triaged'
  | 'accepted'
  | 'duplicate'
  | 'informative'
  | 'not_applicable'
  | 'resolved'
  | 'bounty_paid';

export interface ReproductionStep {
  stepNumber: number;
  action: string;
  expectedResult: string;
  actualResult?: string;
  screenshot?: string;          // URL to screenshot
  request?: string;             // HTTP request
  response?: string;            // HTTP response (truncated)
}

export interface BugBountyEvidence {
  type: 'screenshot' | 'video' | 'http_request' | 'http_response' | 'log' | 'code_snippet' | 'poc_script';
  title: string;
  content: string;              // Content or URL
  timestamp: number;
  annotations?: string[];       // Highlights or callouts
}

// ─── Originality Verification ──────────────────────────────────────────────────

export interface OriginalityCheckResult {
  isLikelyOriginal: boolean;
  confidence: number;           // 0-1
  duplicateIndicators: string[];
  knownIssueMatches: string[];
  recommendations: string[];
}

/**
 * Check if a finding is likely original (not a known issue or duplicate).
 * Uses heuristic matching against common known issues and patterns.
 */
export function checkOriginality(
  finding: BugBountyFinding,
  knownIssues: KnownIssue[],
  previousFindings: BugBountyFinding[]
): OriginalityCheckResult {
  const duplicateIndicators: string[] = [];
  const knownIssueMatches: string[] = [];
  const recommendations: string[] = [];
  
  // Check against known issues
  for (const ki of knownIssues) {
    if (matchesKnownIssue(finding, ki)) {
      knownIssueMatches.push(`Matches known issue: ${ki.title} (${ki.source})`);
    }
  }
  
  // Check against previous findings
  for (const pf of previousFindings) {
    if (pf.id === finding.id) continue;
    const similarity = computeFindingSimilarity(finding, pf);
    if (similarity > 0.8) {
      duplicateIndicators.push(`High similarity (${(similarity * 100).toFixed(0)}%) with finding: ${pf.title}`);
    } else if (similarity > 0.5) {
      duplicateIndicators.push(`Moderate similarity (${(similarity * 100).toFixed(0)}%) with finding: ${pf.title}`);
    }
  }
  
  // Check against common non-original patterns
  const nonOriginalPatterns = checkNonOriginalPatterns(finding);
  if (nonOriginalPatterns.length > 0) {
    duplicateIndicators.push(...nonOriginalPatterns);
  }
  
  // Compute confidence
  const isLikelyOriginal = knownIssueMatches.length === 0 && 
    duplicateIndicators.filter(d => d.includes('High similarity')).length === 0;
  
  let confidence = 1.0;
  if (knownIssueMatches.length > 0) confidence -= 0.4;
  if (duplicateIndicators.some(d => d.includes('High similarity'))) confidence -= 0.3;
  if (duplicateIndicators.some(d => d.includes('Moderate similarity'))) confidence -= 0.15;
  if (nonOriginalPatterns.length > 0) confidence -= 0.1 * nonOriginalPatterns.length;
  confidence = Math.max(0, Math.min(1, confidence));
  
  // Recommendations
  if (!isLikelyOriginal) {
    recommendations.push('Consider searching the program\'s disclosed reports for similar findings');
    recommendations.push('Verify your finding has a unique root cause, not just a different endpoint');
  }
  if (knownIssueMatches.length > 0) {
    recommendations.push('This may be a known/accepted risk — check program policy for exclusions');
  }
  
  return {
    isLikelyOriginal,
    confidence,
    duplicateIndicators,
    knownIssueMatches,
    recommendations,
  };
}

export interface KnownIssue {
  title: string;
  vulnType: string;
  target?: string;
  endpoint?: string;
  source: string;               // "program_disclosure", "public_cve", "common_pattern"
  dateReported?: string;
}

// ─── Submission Formatting ─────────────────────────────────────────────────────

export interface SubmissionDraft {
  platform: BugBountyPlatform;
  title: string;
  severity: string;
  vulnType: string;
  description: string;          // Formatted for the platform
  reproductionSteps: string;    // Formatted step-by-step
  impact: string;               // Impact statement
  attachments: string[];        // URLs to evidence files
  suggestedFix?: string;
}

/**
 * Format a finding for submission to a specific bug bounty platform.
 */
export function formatSubmission(
  finding: BugBountyFinding,
  platform: BugBountyPlatform
): SubmissionDraft {
  const reproSteps = finding.reproductionSteps
    .map(s => `${s.stepNumber}. ${s.action}\n   Expected: ${s.expectedResult}${s.actualResult ? `\n   Actual: ${s.actualResult}` : ''}`)
    .join('\n\n');
  
  const attachments = finding.evidence
    .filter(e => e.type === 'screenshot' || e.type === 'video' || e.type === 'poc_script')
    .map(e => e.content);
  
  switch (platform) {
    case 'hackerone':
      return formatHackerOneSubmission(finding, reproSteps, attachments);
    case 'bugcrowd':
      return formatBugcrowdSubmission(finding, reproSteps, attachments);
    default:
      return formatGenericSubmission(finding, reproSteps, attachments);
  }
}

function formatHackerOneSubmission(
  finding: BugBountyFinding,
  reproSteps: string,
  attachments: string[]
): SubmissionDraft {
  const description = `## Summary
${finding.title}

## Vulnerability Type
${finding.vulnType}${finding.cweId ? ` (${finding.cweId})` : ''}

## Description
A ${finding.severity} severity ${finding.vulnType} vulnerability was identified at \`${finding.target}${finding.endpoint || ''}\`${finding.parameter ? ` in the \`${finding.parameter}\` parameter` : ''}.

## Steps to Reproduce
${reproSteps}

## Impact
**Technical Impact:** ${finding.impactAnalysis.technicalImpact}

**Business Impact:** ${finding.impactAnalysis.businessImpact}

**Affected Users:** ${finding.impactAnalysis.affectedUsers}
${finding.impactAnalysis.dataAtRisk.length > 0 ? `\n**Data at Risk:** ${finding.impactAnalysis.dataAtRisk.join(', ')}` : ''}

## Prerequisites
${finding.prerequisites.length > 0 ? finding.prerequisites.map(p => `- ${p}`).join('\n') : 'None'}

## Supporting Material/References
${finding.evidence.filter(e => e.type === 'http_request' || e.type === 'http_response' || e.type === 'code_snippet').map(e => `### ${e.title}\n\`\`\`\n${e.content}\n\`\`\``).join('\n\n')}`;

  return {
    platform: 'hackerone',
    title: finding.title,
    severity: finding.severity,
    vulnType: finding.vulnType,
    description,
    reproductionSteps: reproSteps,
    impact: `${finding.impactAnalysis.technicalImpact}. ${finding.impactAnalysis.businessImpact}`,
    attachments,
  };
}

function formatBugcrowdSubmission(
  finding: BugBountyFinding,
  reproSteps: string,
  attachments: string[]
): SubmissionDraft {
  const description = `# ${finding.title}

**Severity:** ${finding.severity}
**Vulnerability Type:** ${finding.vulnType}
**Target:** ${finding.target}${finding.endpoint || ''}
${finding.parameter ? `**Parameter:** ${finding.parameter}` : ''}
${finding.cweId ? `**CWE:** ${finding.cweId}` : ''}
${finding.cvssScore ? `**CVSS:** ${finding.cvssScore}` : ''}

## Description
A ${finding.severity} severity ${finding.vulnType} vulnerability was found.

## Proof of Concept
${reproSteps}

## Impact
${finding.impactAnalysis.technicalImpact}

${finding.impactAnalysis.businessImpact}`;

  return {
    platform: 'bugcrowd',
    title: finding.title,
    severity: finding.severity,
    vulnType: finding.vulnType,
    description,
    reproductionSteps: reproSteps,
    impact: finding.impactAnalysis.technicalImpact,
    attachments,
  };
}

function formatGenericSubmission(
  finding: BugBountyFinding,
  reproSteps: string,
  attachments: string[]
): SubmissionDraft {
  return {
    platform: 'custom',
    title: finding.title,
    severity: finding.severity,
    vulnType: finding.vulnType,
    description: `${finding.title}\n\nSeverity: ${finding.severity}\nType: ${finding.vulnType}\nTarget: ${finding.target}${finding.endpoint || ''}\n\n${finding.impactAnalysis.technicalImpact}`,
    reproductionSteps: reproSteps,
    impact: `${finding.impactAnalysis.technicalImpact}. ${finding.impactAnalysis.businessImpact}`,
    attachments,
  };
}

// ─── Policy Parsing from Platform URLs ─────────────────────────────────────────

/**
 * Parse a program policy URL into a PolicyROE structure.
 * This creates a skeleton that can be enriched by LLM analysis of the actual policy page.
 */
export function parseProgramUrl(url: string): { platform: BugBountyPlatform; programSlug: string } | null {
  const patterns: Array<{ pattern: RegExp; platform: BugBountyPlatform; slugIndex?: number }> = [
    { pattern: /hackerone\.com\/([^/?#]+)/i, platform: 'hackerone' },
    // Bugcrowd: /engagements/slug or /slug
    { pattern: /bugcrowd\.com\/engagements\/([^/?#]+)/i, platform: 'bugcrowd' },
    { pattern: /bugcrowd\.com\/([^/?#]+)/i, platform: 'bugcrowd' },
    // Intigriti: /programs/company/handle/detail or old app.intigriti.com format
    { pattern: /intigriti\.com\/programs\/([^/?#]+)\/([^/?#]+)/i, platform: 'intigriti', slugIndex: 2 },
    { pattern: /app\.intigriti\.com\/(?:researcher\/)?programs\/([^/?#]+)/i, platform: 'intigriti' },
    // YesWeHack
    { pattern: /yeswehack\.com\/programs\/([^/?#]+)/i, platform: 'yeswehack' },
    // OpenBugBounty: /bugbounty/slug/ or /reports/NNN/
    { pattern: /openbugbounty\.org\/bugbounty\/([^/?#]+)/i, platform: 'openbugbounty' },
  ];
  
  for (const { pattern, platform, slugIndex } of patterns) {
    const match = url.match(pattern);
    if (match) {
      // For Intigriti with company/handle format, use the handle (2nd capture group)
      const slug = slugIndex ? match[slugIndex] : match[1];
      // For Bugcrowd, skip non-program paths
      if (platform === 'bugcrowd' && ['engagements', 'programs', 'blog', 'resources', 'about', 'contact', 'customers', 'researchers', 'platform', 'solutions', 'pricing', 'vulnerability-disclosure-program'].includes(slug.toLowerCase())) {
        continue;
      }
      return { platform, programSlug: slug };
    }
  }
  
  return null;
}

/**
 * Create a skeleton PolicyROE from a parsed program URL.
 * The actual policy details would be populated by fetching and parsing the program page.
 */
export function createSkeletonPolicy(params: {
  platform: BugBountyPlatform;
  programSlug: string;
  programUrl: string;
  programName?: string;
}): PolicyROE {
  return {
    programId: `${params.platform}:${params.programSlug}`,
    programName: params.programName || params.programSlug,
    platform: params.platform,
    programUrl: params.programUrl,
    scope: {
      inScope: [],
      outOfScope: [],
      wildcardDomains: [],
    },
    rules: {
      allowedTestTypes: ['web_application', 'api'],
      prohibitedActions: [
        'Denial of Service (DoS/DDoS)',
        'Social Engineering of staff',
        'Physical access attacks',
        'Automated scanning without rate limiting',
      ],
      disclosurePolicy: 'coordinated',
      requiresAccountCreation: false,
      requiresVPN: false,
    },
    bounty: {
      hasBounty: true,
      currency: 'USD',
      ranges: [
        { severity: 'critical', minBounty: 1000, maxBounty: 10000 },
        { severity: 'high', minBounty: 500, maxBounty: 5000 },
        { severity: 'medium', minBounty: 100, maxBounty: 1000 },
        { severity: 'low', minBounty: 50, maxBounty: 500 },
      ],
    },
    vulnTypes: {
      accepted: [],
      excluded: [
        'Self-XSS',
        'Clickjacking on non-sensitive pages',
        'CSRF on logout',
        'Missing security headers without demonstrated impact',
        'SPF/DKIM/DMARC misconfiguration',
        'Rate limiting issues',
      ],
    },
    responseExpectations: {
      firstResponseDays: 5,
      triageDays: 10,
    },
    lastUpdated: Date.now(),
    parsedAt: Date.now(),
    parseConfidence: 0.3, // Low confidence for skeleton
  };
}

/**
 * Enrich a skeleton policy with LLM-parsed policy text.
 * This would be called after fetching the actual program page.
 */
export function enrichPolicyFromParsedText(
  skeleton: PolicyROE,
  parsed: Partial<PolicyROE>
): PolicyROE {
  return {
    ...skeleton,
    ...parsed,
    scope: {
      ...skeleton.scope,
      ...parsed.scope,
      inScope: [...(skeleton.scope.inScope || []), ...(parsed.scope?.inScope || [])],
      outOfScope: [...(skeleton.scope.outOfScope || []), ...(parsed.scope?.outOfScope || [])],
    },
    rules: { ...skeleton.rules, ...parsed.rules },
    bounty: { ...skeleton.bounty, ...parsed.bounty },
    vulnTypes: {
      accepted: [...(skeleton.vulnTypes.accepted || []), ...(parsed.vulnTypes?.accepted || [])],
      excluded: [...new Set([...(skeleton.vulnTypes.excluded || []), ...(parsed.vulnTypes?.excluded || [])])],
    },
    parseConfidence: Math.max(skeleton.parseConfidence, parsed.parseConfidence || 0),
    parsedAt: Date.now(),
  };
}

// ─── Utility Functions ─────────────────────────────────────────────────────────

function normalizeTarget(target: string): string {
  try {
    if (target.includes('://')) {
      const u = new URL(target);
      return u.hostname.toLowerCase();
    }
    return target.toLowerCase().replace(/^www\./, '');
  } catch {
    return target.toLowerCase();
  }
}

function matchesScopeTarget(normalizedTarget: string, scopeTarget: ScopeTarget): boolean {
  const scopeNormalized = normalizeTarget(scopeTarget.target);
  
  switch (scopeTarget.type) {
    case 'domain':
      return normalizedTarget === scopeNormalized || 
             normalizedTarget.endsWith(`.${scopeNormalized}`);
    case 'url':
      return normalizedTarget === normalizeTarget(scopeTarget.target);
    case 'ip':
      return normalizedTarget === scopeTarget.target;
    case 'cidr':
      // Simplified CIDR matching — in production would use proper IP math
      return normalizedTarget.startsWith(scopeTarget.target.split('/')[0].split('.').slice(0, 3).join('.'));
    default:
      return normalizedTarget === scopeNormalized;
  }
}

function matchesWildcard(target: string, wildcard: string): boolean {
  // *.example.com matches sub.example.com but not example.com
  const domain = wildcard.replace(/^\*\./, '');
  return target.endsWith(`.${domain}`) || target === domain;
}

function computeFindingSimilarity(a: BugBountyFinding, b: BugBountyFinding): number {
  let score = 0;
  let weights = 0;
  
  // Same vuln type = high weight
  if (a.vulnType === b.vulnType) { score += 0.3; }
  weights += 0.3;
  
  // Same target
  if (normalizeTarget(a.target) === normalizeTarget(b.target)) { score += 0.2; }
  weights += 0.2;
  
  // Same endpoint
  if (a.endpoint && b.endpoint && a.endpoint === b.endpoint) { score += 0.2; }
  weights += 0.2;
  
  // Same parameter
  if (a.parameter && b.parameter && a.parameter === b.parameter) { score += 0.2; }
  weights += 0.2;
  
  // Same CWE
  if (a.cweId && b.cweId && a.cweId === b.cweId) { score += 0.1; }
  weights += 0.1;
  
  return weights > 0 ? score / weights : 0;
}

function matchesKnownIssue(finding: BugBountyFinding, ki: KnownIssue): boolean {
  if (finding.vulnType !== ki.vulnType) return false;
  if (ki.target && normalizeTarget(finding.target) !== normalizeTarget(ki.target)) return false;
  if (ki.endpoint && finding.endpoint !== ki.endpoint) return false;
  return true;
}

function checkNonOriginalPatterns(finding: BugBountyFinding): string[] {
  const patterns: string[] = [];
  
  // Common non-original findings
  const commonNonOriginal = [
    { pattern: /missing.*header/i, msg: 'Missing security header findings are commonly excluded' },
    { pattern: /clickjack/i, msg: 'Clickjacking is commonly excluded unless on sensitive pages' },
    { pattern: /self.?xss/i, msg: 'Self-XSS is almost universally excluded' },
    { pattern: /csrf.*logout/i, msg: 'CSRF on logout is commonly excluded' },
    { pattern: /rate.?limit/i, msg: 'Rate limiting issues are commonly excluded' },
    { pattern: /spf|dkim|dmarc/i, msg: 'Email security misconfigurations are commonly excluded' },
    { pattern: /best.?practice/i, msg: 'Best practice recommendations are not vulnerabilities' },
  ];
  
  for (const { pattern, msg } of commonNonOriginal) {
    if (pattern.test(finding.title) || pattern.test(finding.vulnType)) {
      patterns.push(msg);
    }
  }
  
  return patterns;
}
