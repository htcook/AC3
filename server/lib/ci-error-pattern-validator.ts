/**
 * CI Pre-Merge Error Pattern Validator
 * 
 * Integrates the Error Pattern Analyzer into a CI-compatible validation step.
 * Scans source files for error handling anti-patterns before code ships.
 * 
 * Usage:
 *   - As a tRPC procedure: POST /api/trpc/system.runErrorPatternScan
 *   - As a standalone script: npx tsx server/lib/ci-error-pattern-validator.ts [--strict]
 * 
 * Features:
 * 1. AST-LITE SCANNING — Regex-based catch block analysis (no full AST parser needed)
 * 2. BASELINE TRACKING — Compares against known baseline to detect NEW anti-patterns only
 * 3. SEVERITY GATING — Blocks merge on critical/high issues, warns on medium/low
 * 4. DIFF-AWARE — Can scan only changed files (git diff) for incremental checks
 */

import {
  ErrorPatternAnalyzer,
  ErrorSite,
  ErrorHandlingPattern,
  DebtItem,
} from './architectural-debt-tracker';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CIValidationResult {
  passed: boolean;
  mode: 'full' | 'diff' | 'baseline_compare';
  filesScanned: number;
  totalSites: number;
  newIssues: CIIssue[];
  existingIssues: CIIssue[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    swallowedErrors: number;
    inconsistencies: number;
    newAntiPatterns: number;
  };
  /** Human-readable report for CI output */
  report: string;
  /** Exit code: 0 = pass, 1 = fail (critical/high), 2 = warnings only */
  exitCode: 0 | 1 | 2;
}

export interface CIIssue {
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: 'swallowed_error' | 'inconsistent_error' | 'new_anti_pattern' | 'missing_context';
  file: string;
  line: number;
  function: string;
  pattern: ErrorHandlingPattern;
  message: string;
  isNew: boolean; // True if not in baseline
}

export interface ErrorBaseline {
  generatedAt: number;
  version: string;
  sites: Array<{
    file: string;
    line: number;
    function: string;
    pattern: ErrorHandlingPattern;
    hash: string; // Content hash for drift detection
  }>;
}

// ─── Catch Block Scanner ────────────────────────────────────────────────────

/**
 * Regex-based catch block scanner. Extracts error handling sites from TypeScript source.
 * This is intentionally lightweight (no full AST) to run fast in CI.
 */
export function scanFileForCatchBlocks(content: string, filePath: string): ErrorSite[] {
  const sites: ErrorSite[] = [];
  const lines = content.split('\n');
  
  // Track current function context
  let currentFunction = 'module';
  const functionStack: string[] = [];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    
    // Track function context
    const funcMatch = trimmed.match(
      /(?:async\s+)?(?:function\s+(\w+)|(?:const|let)\s+(\w+)\s*=\s*(?:async\s+)?(?:\(|=>)|(\w+)\s*\(.*\)\s*(?::\s*\w+)?\s*\{)/
    );
    if (funcMatch) {
      currentFunction = funcMatch[1] || funcMatch[2] || funcMatch[3] || currentFunction;
      functionStack.push(currentFunction);
    }
    
    // Detect catch blocks
    const catchMatch = trimmed.match(/}\s*catch\s*\(?\s*(\w*)\s*(?::\s*\w+)?\s*\)?\s*\{/);
    if (catchMatch) {
      const catchVar = catchMatch[1] || '_unnamed';
      
      // Look ahead to analyze the catch body (up to 15 lines or closing brace)
      const catchBody: string[] = [];
      let braceDepth = 1;
      for (let j = i + 1; j < Math.min(i + 30, lines.length) && braceDepth > 0; j++) {
        const bodyLine = lines[j];
        for (const ch of bodyLine) {
          if (ch === '{') braceDepth++;
          if (ch === '}') braceDepth--;
        }
        if (braceDepth > 0) catchBody.push(bodyLine.trim());
      }
      
      const bodyText = catchBody.join(' ');
      
      // Classify the error handling pattern
      const pattern = classifyCatchPattern(bodyText, catchVar);
      const hasLogging = /console\.(log|warn|error|info)|logger\.|log\(/.test(bodyText);
      const hasMetrics = /metrics\.|telemetry\.|record|track|emit|increment/.test(bodyText);
      const propagates = /throw\s|reject\(|return\s+(?:err|error|new Error)/.test(bodyText);
      
      // Extract context from surrounding code
      const contextLine = i > 0 ? lines[i - 1].trim() : '';
      const context = contextLine.match(/\/\/\s*(.+)$/)?.[1] 
        || contextLine.match(/try\s*\{?\s*\/\*\s*(.+?)\s*\*\/$/)?.[1]
        || `catch block in ${currentFunction}`;
      
      sites.push({
        file: filePath,
        line: i + 1,
        function: currentFunction,
        pattern,
        catchesType: catchVar === 'e' || catchVar === 'err' || catchVar === 'error' ? 'any' : catchVar,
        hasLogging,
        hasMetrics,
        propagates,
        context,
      });
    }
    
    // Track function exits
    if (trimmed === '}' && functionStack.length > 0) {
      functionStack.pop();
      currentFunction = functionStack[functionStack.length - 1] || 'module';
    }
  }
  
  return sites;
}

/**
 * Classify a catch block's error handling pattern based on its body content.
 */
function classifyCatchPattern(bodyText: string, catchVar: string): ErrorHandlingPattern {
  const isEmpty = bodyText.replace(/\/\*.*?\*\//g, '').replace(/\/\/.*/g, '').trim().length === 0;
  
  if (isEmpty) return 'swallow_silent';
  
  const hasThrow = /throw\s/.test(bodyText);
  const hasLog = /console\.(log|warn|error|info)|logger\./.test(bodyText);
  const hasReturn = /return\s/.test(bodyText);
  const hasRetry = /retry|attempt|again|backoff/.test(bodyText);
  const hasNotify = /notify|alert|emit|broadcast/.test(bodyText);
  const hasFallback = /fallback|default|alternative|\?\?/.test(bodyText);
  
  // Check for "/* ignore */" or "// best effort" comments that indicate intentional swallowing
  const hasIntentionalComment = /\/\*\s*(ignore|best.?effort|non.?critical|telemetry|optional)\s*\*\/|\/\/\s*(ignore|best.?effort|non.?critical|telemetry|optional)/i.test(bodyText);
  
  if (hasRetry) return 'retry';
  if (hasThrow && hasLog) return 'log_and_throw';
  if (hasThrow) return 'propagate';
  if (hasLog && !hasThrow && !hasReturn) {
    // Logged but not propagated — but check for intentional comments
    if (hasIntentionalComment) return 'fallback';
    return 'log_and_swallow';
  }
  if (hasNotify) return 'notify';
  if (hasFallback || hasReturn) return 'fallback';
  if (hasLog && hasReturn) return 'transform';
  
  // If the catch variable isn't used at all, it's likely swallowed
  if (!bodyText.includes(catchVar) && catchVar !== '_unnamed') return 'swallow_silent';
  
  return 'unknown';
}

// ─── Baseline Management ────────────────────────────────────────────────────

/**
 * Generate a content hash for an error site to detect drift.
 */
function hashErrorSite(site: ErrorSite): string {
  const key = `${site.file}:${site.function}:${site.pattern}:${site.catchesType}`;
  let hash = 0;
  for (let i = 0; i < key.length; i++) {
    const char = key.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0;
  }
  return Math.abs(hash).toString(36);
}

/**
 * Generate a baseline from current error sites.
 */
export function generateBaseline(sites: ErrorSite[], version: string = 'auto'): ErrorBaseline {
  return {
    generatedAt: Date.now(),
    version,
    sites: sites.map(s => ({
      file: s.file,
      line: s.line,
      function: s.function,
      pattern: s.pattern,
      hash: hashErrorSite(s),
    })),
  };
}

/**
 * Compare current sites against a baseline to find new issues.
 */
export function compareToBaseline(
  currentSites: ErrorSite[],
  baseline: ErrorBaseline
): { newSites: ErrorSite[]; removedCount: number; unchangedCount: number } {
  const baselineHashes = new Set(baseline.sites.map(s => s.hash));
  
  const newSites: ErrorSite[] = [];
  let unchangedCount = 0;
  
  for (const site of currentSites) {
    const hash = hashErrorSite(site);
    if (baselineHashes.has(hash)) {
      unchangedCount++;
    } else {
      newSites.push(site);
    }
  }
  
  // Count removed: baseline entries not found in current
  const currentHashes = new Set(currentSites.map(s => hashErrorSite(s)));
  const removedCount = baseline.sites.filter(s => !currentHashes.has(s.hash)).length;
  
  return { newSites, removedCount, unchangedCount };
}

// ─── CI Validation Runner ───────────────────────────────────────────────────

/**
 * Run the full CI validation pipeline.
 * 
 * @param fileContents - Map of file path → file content to scan
 * @param baseline - Optional baseline for incremental comparison
 * @param strict - If true, fail on any medium+ issues (not just critical/high)
 */
export function runCIValidation(
  fileContents: Map<string, string>,
  baseline?: ErrorBaseline,
  strict: boolean = false
): CIValidationResult {
  const analyzer = new ErrorPatternAnalyzer();
  const allSites: ErrorSite[] = [];
  
  // Scan all files
  for (const [filePath, content] of fileContents) {
    const sites = scanFileForCatchBlocks(content, filePath);
    allSites.push(...sites);
    for (const site of sites) {
      analyzer.registerSite(site);
    }
  }
  
  // Get analysis results
  const swallowed = analyzer.findSwallowedErrors();
  const inconsistencies = analyzer.findInconsistencies();
  const debtItems = analyzer.generateDebtItems();
  
  // Compare to baseline if provided
  let newSites: ErrorSite[] = allSites;
  let baselineComparison: { removedCount: number; unchangedCount: number } | undefined;
  
  if (baseline) {
    const comparison = compareToBaseline(allSites, baseline);
    newSites = comparison.newSites;
    baselineComparison = { removedCount: comparison.removedCount, unchangedCount: comparison.unchangedCount };
  }
  
  // Build CI issues
  const issues: CIIssue[] = [];
  
  for (const site of swallowed) {
    const isNew = baseline ? newSites.includes(site) : true;
    const isSilent = site.pattern === 'swallow_silent';
    issues.push({
      severity: isSilent ? 'critical' : 'high',
      category: 'swallowed_error',
      file: site.file,
      line: site.line,
      function: site.function,
      pattern: site.pattern,
      message: isSilent
        ? `Silent swallowed error in ${site.function}() — catch block is empty. This hides failures.`
        : `Logged but swallowed error in ${site.function}() — error is not propagated to caller.`,
      isNew,
    });
  }
  
  for (const { group, sites, issue } of inconsistencies) {
    const isNew = baseline ? sites.some(s => newSites.includes(s)) : true;
    issues.push({
      severity: 'medium',
      category: 'inconsistent_error',
      file: sites[0].file,
      line: sites[0].line,
      function: group,
      pattern: sites[0].pattern,
      message: issue,
      isNew,
    });
  }
  
  // Detect new anti-patterns not in baseline
  for (const site of newSites) {
    if (site.pattern === 'unknown') {
      issues.push({
        severity: 'low',
        category: 'new_anti_pattern',
        file: site.file,
        line: site.line,
        function: site.function,
        pattern: site.pattern,
        message: `New unclassified error handling pattern in ${site.function}() — review recommended.`,
        isNew: true,
      });
    }
    // Missing context: catch block without logging or metrics
    if (!site.hasLogging && !site.hasMetrics && site.pattern !== 'propagate' && site.pattern !== 'swallow_silent') {
      issues.push({
        severity: 'low',
        category: 'missing_context',
        file: site.file,
        line: site.line,
        function: site.function,
        pattern: site.pattern,
        message: `Catch block in ${site.function}() has no logging or metrics — errors may be invisible.`,
        isNew: baseline ? newSites.includes(site) : true,
      });
    }
  }
  
  // Separate new vs existing
  const newIssues = issues.filter(i => i.isNew);
  const existingIssues = issues.filter(i => !i.isNew);
  
  // Summary
  const summary = {
    critical: issues.filter(i => i.severity === 'critical').length,
    high: issues.filter(i => i.severity === 'high').length,
    medium: issues.filter(i => i.severity === 'medium').length,
    low: issues.filter(i => i.severity === 'low').length,
    swallowedErrors: swallowed.length,
    inconsistencies: inconsistencies.length,
    newAntiPatterns: newSites.filter(s => s.pattern === 'unknown').length,
  };
  
  // Determine pass/fail
  const newCritical = newIssues.filter(i => i.severity === 'critical').length;
  const newHigh = newIssues.filter(i => i.severity === 'high').length;
  const newMedium = newIssues.filter(i => i.severity === 'medium').length;
  
  let passed: boolean;
  let exitCode: 0 | 1 | 2;
  
  if (newCritical > 0 || newHigh > 0) {
    passed = false;
    exitCode = 1;
  } else if (strict && newMedium > 0) {
    passed = false;
    exitCode = 1;
  } else if (newIssues.length > 0) {
    passed = true;
    exitCode = 2; // Warnings
  } else {
    passed = true;
    exitCode = 0;
  }
  
  // Generate report
  const report = formatCIReport({
    passed,
    exitCode,
    filesScanned: fileContents.size,
    totalSites: allSites.length,
    newIssues,
    existingIssues,
    summary,
    baselineComparison,
  });
  
  return {
    passed,
    mode: baseline ? 'baseline_compare' : 'full',
    filesScanned: fileContents.size,
    totalSites: allSites.length,
    newIssues,
    existingIssues,
    summary,
    report,
    exitCode,
  };
}

// ─── Report Formatting ──────────────────────────────────────────────────────

function formatCIReport(opts: {
  passed: boolean;
  exitCode: number;
  filesScanned: number;
  totalSites: number;
  newIssues: CIIssue[];
  existingIssues: CIIssue[];
  summary: CIValidationResult['summary'];
  baselineComparison?: { removedCount: number; unchangedCount: number };
}): string {
  const lines: string[] = [];
  
  lines.push('╔══════════════════════════════════════════════════════════════╗');
  lines.push(`║  Error Pattern CI Validation — ${opts.passed ? '✅ PASSED' : '❌ FAILED'}${' '.repeat(Math.max(0, 27 - (opts.passed ? 8 : 8)))}║`);
  lines.push('╠══════════════════════════════════════════════════════════════╣');
  lines.push(`║  Files scanned: ${opts.filesScanned}  |  Error sites: ${opts.totalSites}${' '.repeat(Math.max(0, 30 - String(opts.filesScanned).length - String(opts.totalSites).length))}║`);
  
  if (opts.baselineComparison) {
    lines.push(`║  Baseline: ${opts.baselineComparison.unchangedCount} unchanged, ${opts.baselineComparison.removedCount} removed${' '.repeat(Math.max(0, 30))}║`);
  }
  
  lines.push('╠══════════════════════════════════════════════════════════════╣');
  lines.push(`║  Critical: ${opts.summary.critical}  |  High: ${opts.summary.high}  |  Medium: ${opts.summary.medium}  |  Low: ${opts.summary.low}${' '.repeat(10)}║`);
  lines.push(`║  Swallowed: ${opts.summary.swallowedErrors}  |  Inconsistent: ${opts.summary.inconsistencies}  |  New: ${opts.summary.newAntiPatterns}${' '.repeat(10)}║`);
  lines.push('╚══════════════════════════════════════════════════════════════╝');
  
  if (opts.newIssues.length > 0) {
    lines.push('');
    lines.push('── NEW Issues (blocking if critical/high) ──');
    for (const issue of opts.newIssues.slice(0, 20)) {
      const icon = issue.severity === 'critical' ? '🔴' : issue.severity === 'high' ? '🟠' : issue.severity === 'medium' ? '🟡' : '⚪';
      lines.push(`  ${icon} [${issue.severity.toUpperCase()}] ${issue.file}:${issue.line} (${issue.function})`);
      lines.push(`     ${issue.message}`);
    }
    if (opts.newIssues.length > 20) {
      lines.push(`  ... and ${opts.newIssues.length - 20} more`);
    }
  }
  
  if (opts.existingIssues.length > 0) {
    lines.push('');
    lines.push(`── Existing Issues (${opts.existingIssues.length} in baseline — not blocking) ──`);
    const topExisting = opts.existingIssues.filter(i => i.severity === 'critical' || i.severity === 'high').slice(0, 5);
    for (const issue of topExisting) {
      lines.push(`  ⬜ [${issue.severity.toUpperCase()}] ${issue.file}:${issue.line} — ${issue.message.slice(0, 80)}`);
    }
    if (opts.existingIssues.length > topExisting.length) {
      lines.push(`  ... ${opts.existingIssues.length - topExisting.length} more existing issues`);
    }
  }
  
  return lines.join('\n');
}

// ─── Git Diff Integration ───────────────────────────────────────────────────

/**
 * Parse git diff output to extract changed file paths.
 * Filters to only TypeScript files in server/ and shared/ directories.
 */
export function parseGitDiffFiles(diffOutput: string): string[] {
  return diffOutput
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0)
    .filter(line => /\.(ts|tsx)$/.test(line))
    .filter(line => line.startsWith('server/') || line.startsWith('shared/') || line.startsWith('client/'));
}

// ─── Singleton for Baseline Persistence ─────────────────────────────────────

let currentBaseline: ErrorBaseline | undefined;

export function setBaseline(baseline: ErrorBaseline): void {
  currentBaseline = baseline;
}

export function getBaseline(): ErrorBaseline | undefined {
  return currentBaseline;
}

/**
 * Convenience: scan a set of file contents and return a validation result.
 * Used by the tRPC procedure.
 */
export function quickScan(
  fileContents: Map<string, string>,
  strict: boolean = false
): CIValidationResult {
  return runCIValidation(fileContents, currentBaseline, strict);
}
