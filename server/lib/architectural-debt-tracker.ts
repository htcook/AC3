/**
 * Architectural Debt Tracker & Error Pattern Analyzer
 * 
 * Addresses Claude's review recommendations:
 * - "Track unused/dead code paths and superseded features"
 * - "Catalog error handling patterns and identify swallowed errors"
 * - "Monitor documentation-to-code drift"
 * - "Prioritize debt items by maintenance burden"
 * 
 * This module provides:
 * 1. DEAD CODE DETECTION — Identifies exported functions/types never imported elsewhere
 * 2. FEATURE FLAG HYGIENE — Tracks env vars declared vs actually read, stale flags
 * 3. ERROR PATTERN ANALYSIS — Catalogs catch blocks, identifies swallowed errors
 * 4. MODULE COUPLING HEALTH — Tracks cross-module imports, detects god modules
 * 5. DEBT PRIORITIZATION — Scores debt items by maintenance burden and risk
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface DebtItem {
  id: string;
  category: DebtCategory;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  location: {
    file: string;
    line?: number;
    function?: string;
  };
  /** Maintenance burden score (0-1) — higher = more costly to maintain */
  maintenanceBurden: number;
  /** Risk score (0-1) — higher = more likely to cause production issues */
  riskScore: number;
  /** Combined priority score */
  priorityScore: number;
  /** Suggested fix */
  recommendation: string;
  /** When this debt was first detected */
  detectedAt: number;
  /** Whether this has been acknowledged/deferred */
  acknowledged: boolean;
}

export type DebtCategory =
  | 'dead_code'           // Unused exports, unreachable paths
  | 'stale_feature_flag'  // Feature flags not toggled in N days
  | 'swallowed_error'     // Catch blocks that don't propagate
  | 'inconsistent_error'  // Error handling varies across similar code
  | 'god_module'          // Module with too many responsibilities
  | 'circular_dep'        // Circular dependency chains
  | 'missing_test'        // Critical path without test coverage
  | 'doc_drift'           // Documentation doesn't match implementation
  | 'superseded_feature'  // Old code replaced but not removed
  | 'config_hygiene';     // Unused env vars, stale config

// ─── Dead Code Detector ──────────────────────────────────────────────────────

export interface ExportedSymbol {
  name: string;
  file: string;
  line: number;
  type: 'function' | 'class' | 'type' | 'const' | 'interface';
  importedBy: string[]; // Files that import this symbol
}

export class DeadCodeDetector {
  private exports: ExportedSymbol[] = [];
  
  /**
   * Register an exported symbol found in the codebase.
   */
  registerExport(symbol: ExportedSymbol): void {
    this.exports.push(symbol);
  }
  
  /**
   * Register that a file imports a symbol.
   */
  registerImport(symbolName: string, sourceFile: string, importingFile: string): void {
    const symbol = this.exports.find(e => e.name === symbolName && e.file === sourceFile);
    if (symbol && !symbol.importedBy.includes(importingFile)) {
      symbol.importedBy.push(importingFile);
    }
  }
  
  /**
   * Find all exported symbols that are never imported anywhere.
   */
  findDeadExports(): ExportedSymbol[] {
    return this.exports.filter(e => e.importedBy.length === 0);
  }
  
  /**
   * Generate debt items for dead code.
   */
  generateDebtItems(): DebtItem[] {
    const deadExports = this.findDeadExports();
    return deadExports.map(symbol => ({
      id: `dead-code:${symbol.file}:${symbol.name}`,
      category: 'dead_code' as DebtCategory,
      severity: symbol.type === 'function' ? 'medium' : 'low',
      title: `Unused export: ${symbol.name}`,
      description: `${symbol.type} "${symbol.name}" is exported from ${symbol.file} but never imported by any other module.`,
      location: { file: symbol.file, line: symbol.line, function: symbol.name },
      maintenanceBurden: symbol.type === 'function' ? 0.4 : 0.2,
      riskScore: 0.1, // Dead code is low risk but adds confusion
      priorityScore: 0,
      recommendation: `Remove or mark as internal. If needed for external consumers, document the use case.`,
      detectedAt: Date.now(),
      acknowledged: false,
    }));
  }
}

// ─── Feature Flag Hygiene ────────────────────────────────────────────────────

export interface FeatureFlagStatus {
  name: string;
  declaredIn: string; // Where it's declared (env.ts, .env, etc.)
  readBy: string[]; // Files that read this flag
  lastToggled?: number; // Timestamp of last change
  currentValue?: string;
  isStale: boolean; // Not toggled in > staleDays
}

export class FeatureFlagTracker {
  private flags: Map<string, FeatureFlagStatus> = new Map();
  private staleDays: number;
  
  constructor(staleDays: number = 30) {
    this.staleDays = staleDays;
  }
  
  /**
   * Register a declared feature flag / env var.
   */
  registerFlag(name: string, declaredIn: string, currentValue?: string): void {
    if (!this.flags.has(name)) {
      this.flags.set(name, {
        name,
        declaredIn,
        readBy: [],
        currentValue,
        isStale: false,
      });
    }
  }
  
  /**
   * Register that a file reads this flag.
   */
  registerRead(flagName: string, readByFile: string): void {
    const flag = this.flags.get(flagName);
    if (flag && !flag.readBy.includes(readByFile)) {
      flag.readBy.push(readByFile);
    }
  }
  
  /**
   * Record that a flag was toggled/changed.
   */
  recordToggle(flagName: string, timestamp: number = Date.now()): void {
    const flag = this.flags.get(flagName);
    if (flag) {
      flag.lastToggled = timestamp;
      flag.isStale = false;
    }
  }
  
  /**
   * Compute staleness for all flags.
   */
  computeStaleness(): void {
    const staleThreshold = Date.now() - (this.staleDays * 24 * 60 * 60 * 1000);
    for (const flag of this.flags.values()) {
      if (flag.lastToggled && flag.lastToggled < staleThreshold) {
        flag.isStale = true;
      } else if (!flag.lastToggled) {
        flag.isStale = true; // Never toggled = stale
      }
    }
  }
  
  /**
   * Get flags that are declared but never read.
   */
  getUnusedFlags(): FeatureFlagStatus[] {
    return Array.from(this.flags.values()).filter(f => f.readBy.length === 0);
  }
  
  /**
   * Get flags that haven't been toggled in staleDays.
   */
  getStaleFlags(): FeatureFlagStatus[] {
    this.computeStaleness();
    return Array.from(this.flags.values()).filter(f => f.isStale);
  }
  
  /**
   * Generate debt items for flag hygiene issues.
   */
  generateDebtItems(): DebtItem[] {
    const items: DebtItem[] = [];
    
    for (const flag of this.getUnusedFlags()) {
      items.push({
        id: `config-unused:${flag.name}`,
        category: 'config_hygiene',
        severity: 'low',
        title: `Unused env var: ${flag.name}`,
        description: `${flag.name} is declared in ${flag.declaredIn} but never read by any module.`,
        location: { file: flag.declaredIn },
        maintenanceBurden: 0.1,
        riskScore: 0.05,
        priorityScore: 0,
        recommendation: `Remove from env declaration if no longer needed. If needed for future use, add a comment explaining when it will be activated.`,
        detectedAt: Date.now(),
        acknowledged: false,
      });
    }
    
    for (const flag of this.getStaleFlags()) {
      if (flag.readBy.length > 0) { // Only flag stale if it IS read (unused handled above)
        items.push({
          id: `config-stale:${flag.name}`,
          category: 'stale_feature_flag',
          severity: 'medium',
          title: `Stale feature flag: ${flag.name}`,
          description: `${flag.name} hasn't been toggled in ${this.staleDays}+ days. Consider making it permanent or removing it.`,
          location: { file: flag.declaredIn },
          maintenanceBurden: 0.3,
          riskScore: 0.2,
          priorityScore: 0,
          recommendation: `If the feature is stable, remove the flag and hardcode the behavior. If deprecated, remove both the flag and the gated code.`,
          detectedAt: Date.now(),
          acknowledged: false,
        });
      }
    }
    
    return items;
  }
}

// ─── Error Pattern Analyzer ──────────────────────────────────────────────────

export type ErrorHandlingPattern =
  | 'propagate'        // Re-throws or returns error
  | 'log_and_throw'    // Logs then re-throws
  | 'log_and_swallow'  // Logs but doesn't propagate (DANGEROUS)
  | 'swallow_silent'   // Empty catch block (VERY DANGEROUS)
  | 'transform'        // Catches and throws different error
  | 'fallback'         // Catches and provides fallback value
  | 'retry'            // Catches and retries the operation
  | 'notify'           // Catches and notifies (alerts, metrics)
  | 'unknown';

export interface ErrorSite {
  file: string;
  line: number;
  function: string;
  pattern: ErrorHandlingPattern;
  catchesType: string; // What error type is caught
  hasLogging: boolean;
  hasMetrics: boolean;
  propagates: boolean;
  context: string; // Brief description of what's being caught
}

export class ErrorPatternAnalyzer {
  private sites: ErrorSite[] = [];
  
  /**
   * Register an error handling site found in the codebase.
   */
  registerSite(site: ErrorSite): void {
    this.sites.push(site);
  }
  
  /**
   * Find all swallowed errors (catch blocks that don't propagate).
   */
  findSwallowedErrors(): ErrorSite[] {
    return this.sites.filter(s =>
      s.pattern === 'swallow_silent' || s.pattern === 'log_and_swallow'
    );
  }
  
  /**
   * Find inconsistent error handling across similar functions.
   * Groups by function name pattern and checks for inconsistency.
   */
  findInconsistencies(): { group: string; sites: ErrorSite[]; issue: string }[] {
    // Group by function name prefix (e.g., "handle*", "process*", "fetch*")
    const groups = new Map<string, ErrorSite[]>();
    
    for (const site of this.sites) {
      const prefix = site.function.replace(/[A-Z][a-z]+$/, '').replace(/\d+$/, '');
      if (!groups.has(prefix)) groups.set(prefix, []);
      groups.get(prefix)!.push(site);
    }
    
    const inconsistencies: { group: string; sites: ErrorSite[]; issue: string }[] = [];
    
    for (const [group, sites] of groups) {
      if (sites.length < 2) continue;
      
      const patterns = new Set(sites.map(s => s.pattern));
      if (patterns.size > 1) {
        // Multiple patterns in same group = inconsistency
        const patternList = Array.from(patterns).join(', ');
        inconsistencies.push({
          group,
          sites,
          issue: `Functions in "${group}" group use ${patterns.size} different error patterns: ${patternList}. Should be standardized.`,
        });
      }
    }
    
    return inconsistencies;
  }
  
  /**
   * Get a summary of error handling patterns across the codebase.
   */
  getPatternDistribution(): Record<ErrorHandlingPattern, number> {
    const dist: Record<ErrorHandlingPattern, number> = {
      propagate: 0, log_and_throw: 0, log_and_swallow: 0,
      swallow_silent: 0, transform: 0, fallback: 0,
      retry: 0, notify: 0, unknown: 0,
    };
    for (const site of this.sites) {
      dist[site.pattern]++;
    }
    return dist;
  }
  
  /**
   * Generate debt items for error handling issues.
   */
  generateDebtItems(): DebtItem[] {
    const items: DebtItem[] = [];
    
    // Swallowed errors
    for (const site of this.findSwallowedErrors()) {
      const isSilent = site.pattern === 'swallow_silent';
      items.push({
        id: `error-swallowed:${site.file}:${site.line}`,
        category: 'swallowed_error',
        severity: isSilent ? 'critical' : 'high',
        title: `${isSilent ? 'Silent' : 'Logged but'} swallowed error in ${site.function}`,
        description: `Error caught at ${site.file}:${site.line} in ${site.function}() is ${isSilent ? 'silently discarded' : 'logged but not propagated'}. Context: ${site.context}`,
        location: { file: site.file, line: site.line, function: site.function },
        maintenanceBurden: isSilent ? 0.8 : 0.6,
        riskScore: isSilent ? 0.9 : 0.7,
        priorityScore: 0,
        recommendation: isSilent
          ? `Add proper error handling: either propagate the error, provide a meaningful fallback, or at minimum log it with context.`
          : `Consider propagating this error to the caller so it can make an informed decision. If swallowing is intentional, add a comment explaining why.`,
        detectedAt: Date.now(),
        acknowledged: false,
      });
    }
    
    // Inconsistencies
    for (const { group, sites, issue } of this.findInconsistencies()) {
      items.push({
        id: `error-inconsistent:${group}`,
        category: 'inconsistent_error',
        severity: 'medium',
        title: `Inconsistent error handling in "${group}" functions`,
        description: issue,
        location: { file: sites[0].file, line: sites[0].line, function: group },
        maintenanceBurden: 0.5,
        riskScore: 0.4,
        priorityScore: 0,
        recommendation: `Standardize error handling across all ${group}* functions. Choose one pattern (preferably log_and_throw or transform) and apply consistently.`,
        detectedAt: Date.now(),
        acknowledged: false,
      });
    }
    
    return items;
  }
}

// ─── Module Coupling Analyzer ────────────────────────────────────────────────

export interface ModuleInfo {
  path: string;
  name: string;
  lineCount: number;
  exportCount: number;
  importCount: number;
  importedBy: string[]; // Modules that import from this one
  imports: string[]; // Modules this one imports from
}

export class ModuleCouplingAnalyzer {
  private modules: Map<string, ModuleInfo> = new Map();
  
  registerModule(info: ModuleInfo): void {
    this.modules.set(info.path, info);
  }
  
  /**
   * Find "god modules" — modules with too many responsibilities.
   * Heuristic: high line count + high export count + many importers.
   */
  findGodModules(thresholds: { maxLines?: number; maxExports?: number; maxImporters?: number } = {}): ModuleInfo[] {
    const { maxLines = 2000, maxExports = 30, maxImporters = 15 } = thresholds;
    
    return Array.from(this.modules.values()).filter(m =>
      m.lineCount > maxLines || m.exportCount > maxExports || m.importedBy.length > maxImporters
    );
  }
  
  /**
   * Detect circular dependency chains.
   */
  findCircularDeps(): string[][] {
    const cycles: string[][] = [];
    const visited = new Set<string>();
    const stack = new Set<string>();
    
    const dfs = (path: string, chain: string[]): void => {
      if (stack.has(path)) {
        // Found a cycle
        const cycleStart = chain.indexOf(path);
        if (cycleStart >= 0) {
          cycles.push(chain.slice(cycleStart));
        }
        return;
      }
      if (visited.has(path)) return;
      
      visited.add(path);
      stack.add(path);
      
      const mod = this.modules.get(path);
      if (mod) {
        for (const imp of mod.imports) {
          if (this.modules.has(imp)) {
            dfs(imp, [...chain, path]);
          }
        }
      }
      
      stack.delete(path);
    };
    
    for (const path of this.modules.keys()) {
      visited.clear();
      stack.clear();
      dfs(path, []);
    }
    
    return cycles;
  }
  
  /**
   * Compute coupling score for each module (0-1, higher = more coupled).
   */
  computeCouplingScores(): Map<string, number> {
    const scores = new Map<string, number>();
    const maxImports = Math.max(...Array.from(this.modules.values()).map(m => m.imports.length), 1);
    const maxImporters = Math.max(...Array.from(this.modules.values()).map(m => m.importedBy.length), 1);
    
    for (const [path, mod] of this.modules) {
      const afferentCoupling = mod.importedBy.length / maxImporters; // How many depend on this
      const efferentCoupling = mod.imports.length / maxImports; // How many this depends on
      scores.set(path, (afferentCoupling + efferentCoupling) / 2);
    }
    
    return scores;
  }
  
  /**
   * Generate debt items for coupling issues.
   */
  generateDebtItems(): DebtItem[] {
    const items: DebtItem[] = [];
    
    for (const mod of this.findGodModules()) {
      items.push({
        id: `god-module:${mod.path}`,
        category: 'god_module',
        severity: mod.lineCount > 5000 ? 'critical' : 'high',
        title: `God module: ${mod.name}`,
        description: `${mod.name} has ${mod.lineCount} lines, ${mod.exportCount} exports, and is imported by ${mod.importedBy.length} modules. Consider splitting into focused sub-modules.`,
        location: { file: mod.path },
        maintenanceBurden: Math.min(1, mod.lineCount / 5000),
        riskScore: Math.min(1, mod.importedBy.length / 20),
        priorityScore: 0,
        recommendation: `Split ${mod.name} into focused sub-modules by responsibility. Start by extracting the most cohesive groups of exports into separate files.`,
        detectedAt: Date.now(),
        acknowledged: false,
      });
    }
    
    for (const cycle of this.findCircularDeps()) {
      items.push({
        id: `circular-dep:${cycle.join('->')}`,
        category: 'circular_dep',
        severity: 'high',
        title: `Circular dependency: ${cycle.map(c => c.split('/').pop()).join(' → ')}`,
        description: `Circular import chain detected: ${cycle.join(' → ')}. This can cause initialization order issues and makes the code harder to reason about.`,
        location: { file: cycle[0] },
        maintenanceBurden: 0.7,
        riskScore: 0.6,
        priorityScore: 0,
        recommendation: `Break the cycle by extracting shared types/interfaces into a separate module, or restructure the dependency direction.`,
        detectedAt: Date.now(),
        acknowledged: false,
      });
    }
    
    return items;
  }
}

// ─── Debt Registry (aggregates all sources) ──────────────────────────────────

export interface DebtReport {
  generatedAt: number;
  totalItems: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  topPriority: DebtItem[];
  totalMaintenanceBurden: number; // Sum of all burden scores
  healthScore: number; // 0-100, higher = healthier
}

export class ArchitecturalDebtRegistry {
  private items: DebtItem[] = [];
  private deadCodeDetector = new DeadCodeDetector();
  private featureFlagTracker: FeatureFlagTracker;
  private errorAnalyzer = new ErrorPatternAnalyzer();
  private couplingAnalyzer = new ModuleCouplingAnalyzer();
  
  constructor(staleFlagDays: number = 30) {
    this.featureFlagTracker = new FeatureFlagTracker(staleFlagDays);
  }
  
  /** Access sub-analyzers for registration */
  get deadCode() { return this.deadCodeDetector; }
  get flags() { return this.featureFlagTracker; }
  get errors() { return this.errorAnalyzer; }
  get coupling() { return this.couplingAnalyzer; }
  
  /**
   * Add a manually identified debt item.
   */
  addItem(item: DebtItem): void {
    item.priorityScore = computePriorityScore(item);
    this.items.push(item);
  }
  
  /**
   * Collect all debt items from all analyzers and compute priority scores.
   */
  collectAll(): DebtItem[] {
    const allItems = [
      ...this.items,
      ...this.deadCodeDetector.generateDebtItems(),
      ...this.featureFlagTracker.generateDebtItems(),
      ...this.errorAnalyzer.generateDebtItems(),
      ...this.couplingAnalyzer.generateDebtItems(),
    ];
    
    // Compute priority scores
    for (const item of allItems) {
      item.priorityScore = computePriorityScore(item);
    }
    
    // Sort by priority score descending
    allItems.sort((a, b) => b.priorityScore - a.priorityScore);
    
    return allItems;
  }
  
  /**
   * Generate a comprehensive debt report.
   */
  generateReport(topN: number = 20): DebtReport {
    const allItems = this.collectAll();
    
    const bySeverity: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    let totalBurden = 0;
    
    for (const item of allItems) {
      bySeverity[item.severity] = (bySeverity[item.severity] || 0) + 1;
      byCategory[item.category] = (byCategory[item.category] || 0) + 1;
      totalBurden += item.maintenanceBurden;
    }
    
    // Health score: 100 = no debt, 0 = critical debt everywhere
    // Weighted by severity: critical=10, high=5, medium=2, low=1
    const weightedDebt = (bySeverity['critical'] || 0) * 10
      + (bySeverity['high'] || 0) * 5
      + (bySeverity['medium'] || 0) * 2
      + (bySeverity['low'] || 0) * 1;
    const healthScore = Math.max(0, Math.min(100, 100 - weightedDebt));
    
    return {
      generatedAt: Date.now(),
      totalItems: allItems.length,
      bySeverity,
      byCategory,
      topPriority: allItems.slice(0, topN),
      totalMaintenanceBurden: totalBurden,
      healthScore,
    };
  }
}

// ─── Priority Scoring ────────────────────────────────────────────────────────

function computePriorityScore(item: DebtItem): number {
  // Weighted combination of maintenance burden and risk
  const severityMultiplier = {
    critical: 1.5,
    high: 1.2,
    medium: 1.0,
    low: 0.7,
  }[item.severity];
  
  return (item.maintenanceBurden * 0.4 + item.riskScore * 0.6) * severityMultiplier;
}

// ─── Convenience: Quick Audit ────────────────────────────────────────────────

/**
 * Run a quick architectural audit given module info and error sites.
 * Returns a formatted summary suitable for logging or dashboard display.
 */
export function runQuickAudit(
  modules: ModuleInfo[],
  errorSites: ErrorSite[],
  flags: { name: string; declaredIn: string; readBy: string[]; lastToggled?: number }[]
): DebtReport {
  const registry = new ArchitecturalDebtRegistry();
  
  // Register modules
  for (const mod of modules) {
    registry.coupling.registerModule(mod);
  }
  
  // Register error sites
  for (const site of errorSites) {
    registry.errors.registerSite(site);
  }
  
  // Register flags
  for (const flag of flags) {
    registry.flags.registerFlag(flag.name, flag.declaredIn);
    for (const reader of flag.readBy) {
      registry.flags.registerRead(flag.name, reader);
    }
    if (flag.lastToggled) {
      registry.flags.recordToggle(flag.name, flag.lastToggled);
    }
  }
  
  return registry.generateReport();
}

/**
 * Format a debt report as a human-readable summary.
 */
export function formatDebtReport(report: DebtReport): string {
  const lines: string[] = [
    `=== Architectural Debt Report ===`,
    `Health Score: ${report.healthScore}/100 | Total Items: ${report.totalItems} | Burden: ${report.totalMaintenanceBurden.toFixed(1)}`,
    ``,
    `By Severity: ${Object.entries(report.bySeverity).map(([k, v]) => `${k}=${v}`).join(', ')}`,
    `By Category: ${Object.entries(report.byCategory).map(([k, v]) => `${k}=${v}`).join(', ')}`,
    ``,
    `--- Top Priority Items ---`,
  ];
  
  for (const item of report.topPriority.slice(0, 10)) {
    lines.push(`  [${item.severity.toUpperCase()}] ${item.title} (score: ${item.priorityScore.toFixed(2)})`);
    lines.push(`    → ${item.recommendation}`);
  }
  
  return lines.join('\n');
}
