// server/lib/architectural-debt-tracker.ts
var DeadCodeDetector = class {
  constructor() {
    this.exports = [];
  }
  /**
   * Register an exported symbol found in the codebase.
   */
  registerExport(symbol) {
    this.exports.push(symbol);
  }
  /**
   * Register that a file imports a symbol.
   */
  registerImport(symbolName, sourceFile, importingFile) {
    const symbol = this.exports.find((e) => e.name === symbolName && e.file === sourceFile);
    if (symbol && !symbol.importedBy.includes(importingFile)) {
      symbol.importedBy.push(importingFile);
    }
  }
  /**
   * Find all exported symbols that are never imported anywhere.
   */
  findDeadExports() {
    return this.exports.filter((e) => e.importedBy.length === 0);
  }
  /**
   * Generate debt items for dead code.
   */
  generateDebtItems() {
    const deadExports = this.findDeadExports();
    return deadExports.map((symbol) => ({
      id: `dead-code:${symbol.file}:${symbol.name}`,
      category: "dead_code",
      severity: symbol.type === "function" ? "medium" : "low",
      title: `Unused export: ${symbol.name}`,
      description: `${symbol.type} "${symbol.name}" is exported from ${symbol.file} but never imported by any other module.`,
      location: { file: symbol.file, line: symbol.line, function: symbol.name },
      maintenanceBurden: symbol.type === "function" ? 0.4 : 0.2,
      riskScore: 0.1,
      // Dead code is low risk but adds confusion
      priorityScore: 0,
      recommendation: `Remove or mark as internal. If needed for external consumers, document the use case.`,
      detectedAt: Date.now(),
      acknowledged: false
    }));
  }
};
var FeatureFlagTracker = class {
  constructor(staleDays = 30) {
    this.flags = /* @__PURE__ */ new Map();
    this.staleDays = staleDays;
  }
  /**
   * Register a declared feature flag / env var.
   */
  registerFlag(name, declaredIn, currentValue) {
    if (!this.flags.has(name)) {
      this.flags.set(name, {
        name,
        declaredIn,
        readBy: [],
        currentValue,
        isStale: false
      });
    }
  }
  /**
   * Register that a file reads this flag.
   */
  registerRead(flagName, readByFile) {
    const flag = this.flags.get(flagName);
    if (flag && !flag.readBy.includes(readByFile)) {
      flag.readBy.push(readByFile);
    }
  }
  /**
   * Record that a flag was toggled/changed.
   */
  recordToggle(flagName, timestamp = Date.now()) {
    const flag = this.flags.get(flagName);
    if (flag) {
      flag.lastToggled = timestamp;
      flag.isStale = false;
    }
  }
  /**
   * Compute staleness for all flags.
   */
  computeStaleness() {
    const staleThreshold = Date.now() - this.staleDays * 24 * 60 * 60 * 1e3;
    for (const flag of this.flags.values()) {
      if (flag.lastToggled && flag.lastToggled < staleThreshold) {
        flag.isStale = true;
      } else if (!flag.lastToggled) {
        flag.isStale = true;
      }
    }
  }
  /**
   * Get flags that are declared but never read.
   */
  getUnusedFlags() {
    return Array.from(this.flags.values()).filter((f) => f.readBy.length === 0);
  }
  /**
   * Get flags that haven't been toggled in staleDays.
   */
  getStaleFlags() {
    this.computeStaleness();
    return Array.from(this.flags.values()).filter((f) => f.isStale);
  }
  /**
   * Generate debt items for flag hygiene issues.
   */
  generateDebtItems() {
    const items = [];
    for (const flag of this.getUnusedFlags()) {
      items.push({
        id: `config-unused:${flag.name}`,
        category: "config_hygiene",
        severity: "low",
        title: `Unused env var: ${flag.name}`,
        description: `${flag.name} is declared in ${flag.declaredIn} but never read by any module.`,
        location: { file: flag.declaredIn },
        maintenanceBurden: 0.1,
        riskScore: 0.05,
        priorityScore: 0,
        recommendation: `Remove from env declaration if no longer needed. If needed for future use, add a comment explaining when it will be activated.`,
        detectedAt: Date.now(),
        acknowledged: false
      });
    }
    for (const flag of this.getStaleFlags()) {
      if (flag.readBy.length > 0) {
        items.push({
          id: `config-stale:${flag.name}`,
          category: "stale_feature_flag",
          severity: "medium",
          title: `Stale feature flag: ${flag.name}`,
          description: `${flag.name} hasn't been toggled in ${this.staleDays}+ days. Consider making it permanent or removing it.`,
          location: { file: flag.declaredIn },
          maintenanceBurden: 0.3,
          riskScore: 0.2,
          priorityScore: 0,
          recommendation: `If the feature is stable, remove the flag and hardcode the behavior. If deprecated, remove both the flag and the gated code.`,
          detectedAt: Date.now(),
          acknowledged: false
        });
      }
    }
    return items;
  }
};
var ErrorPatternAnalyzer = class {
  constructor() {
    this.sites = [];
  }
  /**
   * Register an error handling site found in the codebase.
   */
  registerSite(site) {
    this.sites.push(site);
  }
  /**
   * Find all swallowed errors (catch blocks that don't propagate).
   */
  findSwallowedErrors() {
    return this.sites.filter(
      (s) => s.pattern === "swallow_silent" || s.pattern === "log_and_swallow"
    );
  }
  /**
   * Find inconsistent error handling across similar functions.
   * Groups by function name pattern and checks for inconsistency.
   */
  findInconsistencies() {
    const groups = /* @__PURE__ */ new Map();
    for (const site of this.sites) {
      const prefix = site.function.replace(/[A-Z][a-z]+$/, "").replace(/\d+$/, "");
      if (!groups.has(prefix)) groups.set(prefix, []);
      groups.get(prefix).push(site);
    }
    const inconsistencies = [];
    for (const [group, sites] of groups) {
      if (sites.length < 2) continue;
      const patterns = new Set(sites.map((s) => s.pattern));
      if (patterns.size > 1) {
        const patternList = Array.from(patterns).join(", ");
        inconsistencies.push({
          group,
          sites,
          issue: `Functions in "${group}" group use ${patterns.size} different error patterns: ${patternList}. Should be standardized.`
        });
      }
    }
    return inconsistencies;
  }
  /**
   * Get a summary of error handling patterns across the codebase.
   */
  getPatternDistribution() {
    const dist = {
      propagate: 0,
      log_and_throw: 0,
      log_and_swallow: 0,
      swallow_silent: 0,
      transform: 0,
      fallback: 0,
      retry: 0,
      notify: 0,
      unknown: 0
    };
    for (const site of this.sites) {
      dist[site.pattern]++;
    }
    return dist;
  }
  /**
   * Generate debt items for error handling issues.
   */
  generateDebtItems() {
    const items = [];
    for (const site of this.findSwallowedErrors()) {
      const isSilent = site.pattern === "swallow_silent";
      items.push({
        id: `error-swallowed:${site.file}:${site.line}`,
        category: "swallowed_error",
        severity: isSilent ? "critical" : "high",
        title: `${isSilent ? "Silent" : "Logged but"} swallowed error in ${site.function}`,
        description: `Error caught at ${site.file}:${site.line} in ${site.function}() is ${isSilent ? "silently discarded" : "logged but not propagated"}. Context: ${site.context}`,
        location: { file: site.file, line: site.line, function: site.function },
        maintenanceBurden: isSilent ? 0.8 : 0.6,
        riskScore: isSilent ? 0.9 : 0.7,
        priorityScore: 0,
        recommendation: isSilent ? `Add proper error handling: either propagate the error, provide a meaningful fallback, or at minimum log it with context.` : `Consider propagating this error to the caller so it can make an informed decision. If swallowing is intentional, add a comment explaining why.`,
        detectedAt: Date.now(),
        acknowledged: false
      });
    }
    for (const { group, sites, issue } of this.findInconsistencies()) {
      items.push({
        id: `error-inconsistent:${group}`,
        category: "inconsistent_error",
        severity: "medium",
        title: `Inconsistent error handling in "${group}" functions`,
        description: issue,
        location: { file: sites[0].file, line: sites[0].line, function: group },
        maintenanceBurden: 0.5,
        riskScore: 0.4,
        priorityScore: 0,
        recommendation: `Standardize error handling across all ${group}* functions. Choose one pattern (preferably log_and_throw or transform) and apply consistently.`,
        detectedAt: Date.now(),
        acknowledged: false
      });
    }
    return items;
  }
};
var ModuleCouplingAnalyzer = class {
  constructor() {
    this.modules = /* @__PURE__ */ new Map();
  }
  registerModule(info) {
    this.modules.set(info.path, info);
  }
  /**
   * Find "god modules" — modules with too many responsibilities.
   * Heuristic: high line count + high export count + many importers.
   */
  findGodModules(thresholds = {}) {
    const { maxLines = 2e3, maxExports = 30, maxImporters = 15 } = thresholds;
    return Array.from(this.modules.values()).filter(
      (m) => m.lineCount > maxLines || m.exportCount > maxExports || m.importedBy.length > maxImporters
    );
  }
  /**
   * Detect circular dependency chains.
   */
  findCircularDeps() {
    const cycles = [];
    const visited = /* @__PURE__ */ new Set();
    const stack = /* @__PURE__ */ new Set();
    const dfs = (path, chain) => {
      if (stack.has(path)) {
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
  computeCouplingScores() {
    const scores = /* @__PURE__ */ new Map();
    const maxImports = Math.max(...Array.from(this.modules.values()).map((m) => m.imports.length), 1);
    const maxImporters = Math.max(...Array.from(this.modules.values()).map((m) => m.importedBy.length), 1);
    for (const [path, mod] of this.modules) {
      const afferentCoupling = mod.importedBy.length / maxImporters;
      const efferentCoupling = mod.imports.length / maxImports;
      scores.set(path, (afferentCoupling + efferentCoupling) / 2);
    }
    return scores;
  }
  /**
   * Generate debt items for coupling issues.
   */
  generateDebtItems() {
    const items = [];
    for (const mod of this.findGodModules()) {
      items.push({
        id: `god-module:${mod.path}`,
        category: "god_module",
        severity: mod.lineCount > 5e3 ? "critical" : "high",
        title: `God module: ${mod.name}`,
        description: `${mod.name} has ${mod.lineCount} lines, ${mod.exportCount} exports, and is imported by ${mod.importedBy.length} modules. Consider splitting into focused sub-modules.`,
        location: { file: mod.path },
        maintenanceBurden: Math.min(1, mod.lineCount / 5e3),
        riskScore: Math.min(1, mod.importedBy.length / 20),
        priorityScore: 0,
        recommendation: `Split ${mod.name} into focused sub-modules by responsibility. Start by extracting the most cohesive groups of exports into separate files.`,
        detectedAt: Date.now(),
        acknowledged: false
      });
    }
    for (const cycle of this.findCircularDeps()) {
      items.push({
        id: `circular-dep:${cycle.join("->")}`,
        category: "circular_dep",
        severity: "high",
        title: `Circular dependency: ${cycle.map((c) => c.split("/").pop()).join(" \u2192 ")}`,
        description: `Circular import chain detected: ${cycle.join(" \u2192 ")}. This can cause initialization order issues and makes the code harder to reason about.`,
        location: { file: cycle[0] },
        maintenanceBurden: 0.7,
        riskScore: 0.6,
        priorityScore: 0,
        recommendation: `Break the cycle by extracting shared types/interfaces into a separate module, or restructure the dependency direction.`,
        detectedAt: Date.now(),
        acknowledged: false
      });
    }
    return items;
  }
};
var ArchitecturalDebtRegistry = class {
  constructor(staleFlagDays = 30) {
    this.items = [];
    this.deadCodeDetector = new DeadCodeDetector();
    this.errorAnalyzer = new ErrorPatternAnalyzer();
    this.couplingAnalyzer = new ModuleCouplingAnalyzer();
    this.featureFlagTracker = new FeatureFlagTracker(staleFlagDays);
  }
  /** Access sub-analyzers for registration */
  get deadCode() {
    return this.deadCodeDetector;
  }
  get flags() {
    return this.featureFlagTracker;
  }
  get errors() {
    return this.errorAnalyzer;
  }
  get coupling() {
    return this.couplingAnalyzer;
  }
  /**
   * Add a manually identified debt item.
   */
  addItem(item) {
    item.priorityScore = computePriorityScore(item);
    this.items.push(item);
  }
  /**
   * Collect all debt items from all analyzers and compute priority scores.
   */
  collectAll() {
    const allItems = [
      ...this.items,
      ...this.deadCodeDetector.generateDebtItems(),
      ...this.featureFlagTracker.generateDebtItems(),
      ...this.errorAnalyzer.generateDebtItems(),
      ...this.couplingAnalyzer.generateDebtItems()
    ];
    for (const item of allItems) {
      item.priorityScore = computePriorityScore(item);
    }
    allItems.sort((a, b) => b.priorityScore - a.priorityScore);
    return allItems;
  }
  /**
   * Generate a comprehensive debt report.
   */
  generateReport(topN = 20) {
    const allItems = this.collectAll();
    const bySeverity = {};
    const byCategory = {};
    let totalBurden = 0;
    for (const item of allItems) {
      bySeverity[item.severity] = (bySeverity[item.severity] || 0) + 1;
      byCategory[item.category] = (byCategory[item.category] || 0) + 1;
      totalBurden += item.maintenanceBurden;
    }
    const weightedDebt = (bySeverity["critical"] || 0) * 10 + (bySeverity["high"] || 0) * 5 + (bySeverity["medium"] || 0) * 2 + (bySeverity["low"] || 0) * 1;
    const healthScore = Math.max(0, Math.min(100, 100 - weightedDebt));
    return {
      generatedAt: Date.now(),
      totalItems: allItems.length,
      bySeverity,
      byCategory,
      topPriority: allItems.slice(0, topN),
      totalMaintenanceBurden: totalBurden,
      healthScore
    };
  }
};
function computePriorityScore(item) {
  const severityMultiplier = {
    critical: 1.5,
    high: 1.2,
    medium: 1,
    low: 0.7
  }[item.severity];
  return (item.maintenanceBurden * 0.4 + item.riskScore * 0.6) * severityMultiplier;
}
function runQuickAudit(modules, errorSites, flags) {
  const registry = new ArchitecturalDebtRegistry();
  for (const mod of modules) {
    registry.coupling.registerModule(mod);
  }
  for (const site of errorSites) {
    registry.errors.registerSite(site);
  }
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
function formatDebtReport(report) {
  const lines = [
    `=== Architectural Debt Report ===`,
    `Health Score: ${report.healthScore}/100 | Total Items: ${report.totalItems} | Burden: ${report.totalMaintenanceBurden.toFixed(1)}`,
    ``,
    `By Severity: ${Object.entries(report.bySeverity).map(([k, v]) => `${k}=${v}`).join(", ")}`,
    `By Category: ${Object.entries(report.byCategory).map(([k, v]) => `${k}=${v}`).join(", ")}`,
    ``,
    `--- Top Priority Items ---`
  ];
  for (const item of report.topPriority.slice(0, 10)) {
    lines.push(`  [${item.severity.toUpperCase()}] ${item.title} (score: ${item.priorityScore.toFixed(2)})`);
    lines.push(`    \u2192 ${item.recommendation}`);
  }
  return lines.join("\n");
}

export {
  DeadCodeDetector,
  FeatureFlagTracker,
  ErrorPatternAnalyzer,
  ModuleCouplingAnalyzer,
  ArchitecturalDebtRegistry,
  runQuickAudit,
  formatDebtReport
};
