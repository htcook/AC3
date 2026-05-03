/**
 * Bug Bounty Duplicate Detector
 * 
 * Assesses whether a potential finding is likely already known before
 * investing deep investigation time. Cross-references against:
 * - Public CVE disclosures matching the tech stack
 * - Recent program findings (from HackerOne hacktivity)
 * - Common vulnerability patterns that are frequently reported
 * - Historical findings from our own engagements
 * 
 * The goal is to save researcher time by flagging high-duplicate-probability
 * findings early, allowing focus on novel discoveries.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface DuplicateCheckInput {
  vulnClass: string;
  title: string;
  affectedEndpoint: string;
  technology?: string;
  technologyVersion?: string;
  cweId?: string;
  description?: string;
  programHandle?: string;
}

export interface DuplicateCheckResult {
  isDuplicate: boolean;
  duplicateProbability: number; // 0.0 - 1.0
  confidence: 'high' | 'medium' | 'low';
  reasoning: string[];
  matchedReferences: DuplicateReference[];
  recommendation: 'skip' | 'investigate_carefully' | 'proceed' | 'novel_opportunity';
  timeEstimateSaved?: string; // e.g., "2-4 hours" if skipping
}

export interface DuplicateReference {
  source: 'cve' | 'hacktivity' | 'common_pattern' | 'internal_finding' | 'public_disclosure';
  identifier: string;
  title: string;
  similarity: number; // 0.0 - 1.0
  url?: string;
  disclosedAt?: string;
}

// ─── Common Vulnerability Patterns (Frequently Reported) ─────────────────────

interface CommonPattern {
  vulnClassPattern: RegExp;
  techPattern?: RegExp;
  endpointPattern?: RegExp;
  duplicateProbability: number;
  reasoning: string;
}

const COMMON_PATTERNS: CommonPattern[] = [
  // GraphQL introspection — almost always already reported
  { vulnClassPattern: /graphql_introspection/i, duplicateProbability: 0.9, reasoning: 'GraphQL introspection is one of the most commonly reported and frequently duplicated findings' },
  
  // Generic info disclosure via server headers
  { vulnClassPattern: /info_disclosure/i, endpointPattern: /^\/$|^\/index/i, duplicateProbability: 0.8, reasoning: 'Server version disclosure on main page is almost always already reported' },
  
  // Open redirect on login pages
  { vulnClassPattern: /open_redirect/i, endpointPattern: /login|auth|oauth|callback/i, duplicateProbability: 0.7, reasoning: 'Open redirect on authentication endpoints is a very common finding' },
  
  // Missing security headers
  { vulnClassPattern: /info_disclosure|sensitive_data/i, techPattern: /header|csp|hsts/i, duplicateProbability: 0.85, reasoning: 'Missing security headers are among the most frequently reported low-severity findings' },
  
  // WordPress plugin vulns
  { vulnClassPattern: /sqli|xss/i, techPattern: /wordpress/i, duplicateProbability: 0.6, reasoning: 'WordPress plugin vulnerabilities are heavily researched and frequently reported' },
  
  // CORS wildcard
  { vulnClassPattern: /cors/i, duplicateProbability: 0.7, reasoning: 'CORS misconfiguration is a commonly reported finding across most programs' },
  
  // Subdomain takeover on common providers
  { vulnClassPattern: /subdomain_takeover/i, duplicateProbability: 0.5, reasoning: 'Subdomain takeover is moderately common — depends on whether the specific subdomain was already reported' },
  
  // S3 bucket exposure
  { vulnClassPattern: /sensitive_data/i, techPattern: /s3|aws|bucket/i, duplicateProbability: 0.65, reasoning: 'S3 bucket misconfigurations are well-known and frequently reported' },
  
  // JWT algorithm confusion
  { vulnClassPattern: /jwt/i, duplicateProbability: 0.55, reasoning: 'JWT algorithm confusion is a known attack class — depends on whether this specific implementation was tested' },
  
  // Spring Boot actuator exposure
  { vulnClassPattern: /info_disclosure|ssrf/i, techPattern: /spring/i, endpointPattern: /actuator/i, duplicateProbability: 0.75, reasoning: 'Spring Boot actuator exposure is a well-known and frequently reported finding' },
  
  // CSRF on non-critical endpoints
  { vulnClassPattern: /csrf/i, endpointPattern: /profile|settings|preference/i, duplicateProbability: 0.6, reasoning: 'CSRF on profile/settings pages is commonly reported with varying acceptance rates' },
  
  // Rate limiting issues
  { vulnClassPattern: /business_logic|broken_auth/i, endpointPattern: /login|register|password|otp|verify/i, duplicateProbability: 0.5, reasoning: 'Missing rate limiting on auth endpoints is a common finding' },
];

// ─── Known CVE Pattern Matching ──────────────────────────────────────────────

interface KnownCVEPattern {
  techPattern: RegExp;
  versionPattern?: RegExp;
  vulnClassPattern: RegExp;
  cveId: string;
  title: string;
  duplicateProbability: number;
}

const KNOWN_CVE_PATTERNS: KnownCVEPattern[] = [
  { techPattern: /spring/i, versionPattern: /^[12]\./i, vulnClassPattern: /rce|command_injection/i, cveId: 'CVE-2022-22965', title: 'Spring4Shell RCE', duplicateProbability: 0.95 },
  { techPattern: /log4j|java/i, vulnClassPattern: /rce|command_injection/i, cveId: 'CVE-2021-44228', title: 'Log4Shell RCE', duplicateProbability: 0.98 },
  { techPattern: /apache/i, versionPattern: /2\.4\.(49|50)/i, vulnClassPattern: /path_traversal/i, cveId: 'CVE-2021-41773', title: 'Apache Path Traversal', duplicateProbability: 0.95 },
  { techPattern: /wordpress/i, vulnClassPattern: /sqli/i, cveId: 'CVE-2022-21661', title: 'WordPress WP_Query SQL Injection', duplicateProbability: 0.85 },
  { techPattern: /laravel/i, vulnClassPattern: /rce|deserialization/i, cveId: 'CVE-2021-3129', title: 'Laravel Ignition RCE', duplicateProbability: 0.9 },
  { techPattern: /nginx/i, vulnClassPattern: /path_traversal/i, cveId: 'CVE-2024-7347', title: 'Nginx alias traversal', duplicateProbability: 0.7 },
  { techPattern: /jquery/i, versionPattern: /^[12]\./i, vulnClassPattern: /xss/i, cveId: 'CVE-2020-11022', title: 'jQuery XSS via HTML', duplicateProbability: 0.9 },
  { techPattern: /express|node/i, vulnClassPattern: /path_traversal/i, cveId: 'CVE-2017-14849', title: 'Node.js path traversal', duplicateProbability: 0.7 },
];

// ─── Program-Specific Duplicate Patterns ─────────────────────────────────────

interface ProgramDuplicateProfile {
  programPattern: RegExp;
  highDuplicateVulnClasses: string[];
  lowDuplicateVulnClasses: string[];
  notes: string;
}

const PROGRAM_PROFILES: ProgramDuplicateProfile[] = [
  {
    programPattern: /google|alphabet/i,
    highDuplicateVulnClasses: ['xss_reflected', 'open_redirect', 'info_disclosure', 'cors_misconfiguration'],
    lowDuplicateVulnClasses: ['rce', 'ssrf', 'deserialization', 'http_request_smuggling'],
    notes: 'Google VRP receives extremely high volume — common findings are almost always duplicates',
  },
  {
    programPattern: /facebook|meta/i,
    highDuplicateVulnClasses: ['xss_reflected', 'open_redirect', 'csrf', 'info_disclosure'],
    lowDuplicateVulnClasses: ['rce', 'ssrf', 'privilege_escalation', 'business_logic'],
    notes: 'Meta BBP has extensive internal testing — novel logic bugs have best acceptance rates',
  },
  {
    programPattern: /microsoft/i,
    highDuplicateVulnClasses: ['info_disclosure', 'open_redirect', 'cors_misconfiguration'],
    lowDuplicateVulnClasses: ['rce', 'auth_bypass', 'privilege_escalation'],
    notes: 'Microsoft MSRC has broad scope — focus on Azure/O365 specific issues for novelty',
  },
  {
    programPattern: /hackerone/i,
    highDuplicateVulnClasses: ['xss_reflected', 'open_redirect', 'info_disclosure'],
    lowDuplicateVulnClasses: ['idor', 'auth_bypass', 'privilege_escalation'],
    notes: 'HackerOne own program is heavily tested by researchers — IDOR and auth issues still found',
  },
];

// ─── Core Duplicate Detection ────────────────────────────────────────────────

function checkCommonPatterns(input: DuplicateCheckInput): { probability: number; references: DuplicateReference[]; reasoning: string[] } {
  let maxProbability = 0;
  const references: DuplicateReference[] = [];
  const reasoning: string[] = [];

  for (const pattern of COMMON_PATTERNS) {
    if (!pattern.vulnClassPattern.test(input.vulnClass)) continue;
    if (pattern.techPattern && input.technology && !pattern.techPattern.test(input.technology)) continue;
    if (pattern.endpointPattern && !pattern.endpointPattern.test(input.affectedEndpoint)) continue;

    // If tech pattern is required but no tech provided, reduce probability
    const adjustedProbability = pattern.techPattern && !input.technology
      ? pattern.duplicateProbability * 0.5
      : pattern.duplicateProbability;

    if (adjustedProbability > maxProbability) {
      maxProbability = adjustedProbability;
    }

    references.push({
      source: 'common_pattern',
      identifier: `PATTERN-${input.vulnClass}`,
      title: pattern.reasoning,
      similarity: adjustedProbability,
    });
    reasoning.push(pattern.reasoning);
  }

  return { probability: maxProbability, references, reasoning };
}

function checkKnownCVEs(input: DuplicateCheckInput): { probability: number; references: DuplicateReference[]; reasoning: string[] } {
  let maxProbability = 0;
  const references: DuplicateReference[] = [];
  const reasoning: string[] = [];

  for (const cve of KNOWN_CVE_PATTERNS) {
    if (!input.technology || !cve.techPattern.test(input.technology)) continue;
    if (!cve.vulnClassPattern.test(input.vulnClass)) continue;
    if (cve.versionPattern && input.technologyVersion && !cve.versionPattern.test(input.technologyVersion)) continue;

    // If version matches exactly, very high duplicate probability
    const versionMatch = cve.versionPattern && input.technologyVersion && cve.versionPattern.test(input.technologyVersion);
    const adjustedProbability = versionMatch ? cve.duplicateProbability : cve.duplicateProbability * 0.7;

    if (adjustedProbability > maxProbability) {
      maxProbability = adjustedProbability;
    }

    references.push({
      source: 'cve',
      identifier: cve.cveId,
      title: cve.title,
      similarity: adjustedProbability,
      url: `https://nvd.nist.gov/vuln/detail/${cve.cveId}`,
    });
    reasoning.push(`Known CVE ${cve.cveId} (${cve.title}) matches this finding pattern`);
  }

  return { probability: maxProbability, references, reasoning };
}

function checkProgramProfile(input: DuplicateCheckInput): { adjustment: number; reasoning: string[] } {
  if (!input.programHandle) return { adjustment: 0, reasoning: [] };

  for (const profile of PROGRAM_PROFILES) {
    if (!profile.programPattern.test(input.programHandle)) continue;

    if (profile.highDuplicateVulnClasses.some(vc => input.vulnClass.includes(vc) || vc.includes(input.vulnClass))) {
      return {
        adjustment: 0.15,
        reasoning: [`${input.programHandle} has high duplicate rates for ${input.vulnClass} findings. ${profile.notes}`],
      };
    }

    if (profile.lowDuplicateVulnClasses.some(vc => input.vulnClass.includes(vc) || vc.includes(input.vulnClass))) {
      return {
        adjustment: -0.15,
        reasoning: [`${input.programHandle} has lower duplicate rates for ${input.vulnClass} — this may be a novel opportunity. ${profile.notes}`],
      };
    }
  }

  return { adjustment: 0, reasoning: [] };
}

// ─── Main Export ─────────────────────────────────────────────────────────────

export function checkForDuplicate(input: DuplicateCheckInput): DuplicateCheckResult {
  const commonResult = checkCommonPatterns(input);
  const cveResult = checkKnownCVEs(input);
  const programResult = checkProgramProfile(input);

  // Combine probabilities (take max, then adjust for program)
  let combinedProbability = Math.max(commonResult.probability, cveResult.probability);
  combinedProbability = Math.min(Math.max(combinedProbability + programResult.adjustment, 0), 1);

  const allReferences = [...cveResult.references, ...commonResult.references];
  const allReasoning = [...cveResult.reasoning, ...commonResult.reasoning, ...programResult.reasoning];

  // Determine confidence based on evidence quality
  let confidence: 'high' | 'medium' | 'low';
  if (cveResult.references.length > 0 && commonResult.references.length > 0) {
    confidence = 'high';
  } else if (cveResult.references.length > 0 || commonResult.probability > 0.6) {
    confidence = 'medium';
  } else {
    confidence = 'low';
  }

  // Determine recommendation
  let recommendation: DuplicateCheckResult['recommendation'];
  if (combinedProbability >= 0.8) {
    recommendation = 'skip';
  } else if (combinedProbability >= 0.5) {
    recommendation = 'investigate_carefully';
  } else if (combinedProbability >= 0.2) {
    recommendation = 'proceed';
  } else {
    recommendation = 'novel_opportunity';
  }

  // Estimate time saved if skipping
  let timeEstimateSaved: string | undefined;
  if (recommendation === 'skip') {
    timeEstimateSaved = '2-4 hours';
  } else if (recommendation === 'investigate_carefully') {
    timeEstimateSaved = '1-2 hours (if confirmed duplicate)';
  }

  return {
    isDuplicate: combinedProbability >= 0.7,
    duplicateProbability: Math.round(combinedProbability * 100) / 100,
    confidence,
    reasoning: allReasoning.length > 0 ? allReasoning : ['No matching patterns found — this appears to be a potentially novel finding'],
    matchedReferences: allReferences.sort((a, b) => b.similarity - a.similarity),
    recommendation,
    timeEstimateSaved,
  };
}

/**
 * Batch check multiple findings for duplicates
 */
export function batchCheckDuplicates(inputs: DuplicateCheckInput[]): Map<string, DuplicateCheckResult> {
  const results = new Map<string, DuplicateCheckResult>();
  for (const input of inputs) {
    const key = `${input.vulnClass}:${input.affectedEndpoint}`;
    results.set(key, checkForDuplicate(input));
  }
  return results;
}

/**
 * Get duplicate statistics for a set of findings
 */
export function getDuplicateStats(results: Map<string, DuplicateCheckResult>): {
  total: number;
  likelyDuplicates: number;
  novelOpportunities: number;
  estimatedTimeSaved: string;
  recommendationBreakdown: Record<string, number>;
} {
  const entries = Array.from(results.values());
  const breakdown: Record<string, number> = { skip: 0, investigate_carefully: 0, proceed: 0, novel_opportunity: 0 };

  for (const r of entries) {
    breakdown[r.recommendation] = (breakdown[r.recommendation] || 0) + 1;
  }

  const hoursPerSkip = 3;
  const estimatedHoursSaved = breakdown.skip * hoursPerSkip + breakdown.investigate_carefully * 1.5;

  return {
    total: entries.length,
    likelyDuplicates: entries.filter(r => r.isDuplicate).length,
    novelOpportunities: breakdown.novel_opportunity,
    estimatedTimeSaved: `${estimatedHoursSaved.toFixed(1)} hours`,
    recommendationBreakdown: breakdown,
  };
}
