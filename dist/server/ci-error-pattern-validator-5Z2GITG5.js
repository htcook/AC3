import {
  ErrorPatternAnalyzer
} from "./chunk-EMEAZ7CT.js";
import "./chunk-KFQGP6VL.js";

// server/lib/ci-error-pattern-validator.ts
function scanFileForCatchBlocks(content, filePath) {
  const sites = [];
  const lines = content.split("\n");
  let currentFunction = "module";
  const functionStack = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const funcMatch = trimmed.match(
      /(?:async\s+)?(?:function\s+(\w+)|(?:const|let)\s+(\w+)\s*=\s*(?:async\s+)?(?:\(|=>)|(\w+)\s*\(.*\)\s*(?::\s*\w+)?\s*\{)/
    );
    if (funcMatch) {
      currentFunction = funcMatch[1] || funcMatch[2] || funcMatch[3] || currentFunction;
      functionStack.push(currentFunction);
    }
    const catchMatch = trimmed.match(/}\s*catch\s*\(?\s*(\w*)\s*(?::\s*\w+)?\s*\)?\s*\{/);
    if (catchMatch) {
      const catchVar = catchMatch[1] || "_unnamed";
      const catchBody = [];
      let braceDepth = 1;
      for (let j = i + 1; j < Math.min(i + 30, lines.length) && braceDepth > 0; j++) {
        const bodyLine = lines[j];
        for (const ch of bodyLine) {
          if (ch === "{") braceDepth++;
          if (ch === "}") braceDepth--;
        }
        if (braceDepth > 0) catchBody.push(bodyLine.trim());
      }
      const bodyText = catchBody.join(" ");
      const pattern = classifyCatchPattern(bodyText, catchVar);
      const hasLogging = /console\.(log|warn|error|info)|logger\.|log\(/.test(bodyText);
      const hasMetrics = /metrics\.|telemetry\.|record|track|emit|increment/.test(bodyText);
      const propagates = /throw\s|reject\(|return\s+(?:err|error|new Error)/.test(bodyText);
      const contextLine = i > 0 ? lines[i - 1].trim() : "";
      const context = contextLine.match(/\/\/\s*(.+)$/)?.[1] || contextLine.match(/try\s*\{?\s*\/\*\s*(.+?)\s*\*\/$/)?.[1] || `catch block in ${currentFunction}`;
      sites.push({
        file: filePath,
        line: i + 1,
        function: currentFunction,
        pattern,
        catchesType: catchVar === "e" || catchVar === "err" || catchVar === "error" ? "any" : catchVar,
        hasLogging,
        hasMetrics,
        propagates,
        context
      });
    }
    if (trimmed === "}" && functionStack.length > 0) {
      functionStack.pop();
      currentFunction = functionStack[functionStack.length - 1] || "module";
    }
  }
  return sites;
}
function classifyCatchPattern(bodyText, catchVar) {
  const isEmpty = bodyText.replace(/\/\*.*?\*\//g, "").replace(/\/\/.*/g, "").trim().length === 0;
  if (isEmpty) return "swallow_silent";
  const hasThrow = /throw\s/.test(bodyText);
  const hasLog = /console\.(log|warn|error|info)|logger\./.test(bodyText);
  const hasReturn = /return\s/.test(bodyText);
  const hasRetry = /retry|attempt|again|backoff/.test(bodyText);
  const hasNotify = /notify|alert|emit|broadcast/.test(bodyText);
  const hasFallback = /fallback|default|alternative|\?\?/.test(bodyText);
  const hasIntentionalComment = /\/\*\s*(ignore|best.?effort|non.?critical|telemetry|optional)\s*\*\/|\/\/\s*(ignore|best.?effort|non.?critical|telemetry|optional)/i.test(bodyText);
  if (hasRetry) return "retry";
  if (hasThrow && hasLog) return "log_and_throw";
  if (hasThrow) return "propagate";
  if (hasLog && !hasThrow && !hasReturn) {
    if (hasIntentionalComment) return "fallback";
    return "log_and_swallow";
  }
  if (hasNotify) return "notify";
  if (hasFallback || hasReturn) return "fallback";
  if (hasLog && hasReturn) return "transform";
  if (!bodyText.includes(catchVar) && catchVar !== "_unnamed") return "swallow_silent";
  return "unknown";
}
function hashErrorSite(site) {
  const key = `${site.file}:${site.function}:${site.pattern}:${site.catchesType}`;
  let hash = 0;
  for (let i = 0; i < key.length; i++) {
    const char = key.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return Math.abs(hash).toString(36);
}
function generateBaseline(sites, version = "auto") {
  return {
    generatedAt: Date.now(),
    version,
    sites: sites.map((s) => ({
      file: s.file,
      line: s.line,
      function: s.function,
      pattern: s.pattern,
      hash: hashErrorSite(s)
    }))
  };
}
function compareToBaseline(currentSites, baseline) {
  const baselineHashes = new Set(baseline.sites.map((s) => s.hash));
  const newSites = [];
  let unchangedCount = 0;
  for (const site of currentSites) {
    const hash = hashErrorSite(site);
    if (baselineHashes.has(hash)) {
      unchangedCount++;
    } else {
      newSites.push(site);
    }
  }
  const currentHashes = new Set(currentSites.map((s) => hashErrorSite(s)));
  const removedCount = baseline.sites.filter((s) => !currentHashes.has(s.hash)).length;
  return { newSites, removedCount, unchangedCount };
}
function runCIValidation(fileContents, baseline, strict = false) {
  const analyzer = new ErrorPatternAnalyzer();
  const allSites = [];
  for (const [filePath, content] of fileContents) {
    const sites = scanFileForCatchBlocks(content, filePath);
    allSites.push(...sites);
    for (const site of sites) {
      analyzer.registerSite(site);
    }
  }
  const swallowed = analyzer.findSwallowedErrors();
  const inconsistencies = analyzer.findInconsistencies();
  const debtItems = analyzer.generateDebtItems();
  let newSites = allSites;
  let baselineComparison;
  if (baseline) {
    const comparison = compareToBaseline(allSites, baseline);
    newSites = comparison.newSites;
    baselineComparison = { removedCount: comparison.removedCount, unchangedCount: comparison.unchangedCount };
  }
  const issues = [];
  for (const site of swallowed) {
    const isNew = baseline ? newSites.includes(site) : true;
    const isSilent = site.pattern === "swallow_silent";
    issues.push({
      severity: isSilent ? "critical" : "high",
      category: "swallowed_error",
      file: site.file,
      line: site.line,
      function: site.function,
      pattern: site.pattern,
      message: isSilent ? `Silent swallowed error in ${site.function}() \u2014 catch block is empty. This hides failures.` : `Logged but swallowed error in ${site.function}() \u2014 error is not propagated to caller.`,
      isNew
    });
  }
  for (const { group, sites, issue } of inconsistencies) {
    const isNew = baseline ? sites.some((s) => newSites.includes(s)) : true;
    issues.push({
      severity: "medium",
      category: "inconsistent_error",
      file: sites[0].file,
      line: sites[0].line,
      function: group,
      pattern: sites[0].pattern,
      message: issue,
      isNew
    });
  }
  for (const site of newSites) {
    if (site.pattern === "unknown") {
      issues.push({
        severity: "low",
        category: "new_anti_pattern",
        file: site.file,
        line: site.line,
        function: site.function,
        pattern: site.pattern,
        message: `New unclassified error handling pattern in ${site.function}() \u2014 review recommended.`,
        isNew: true
      });
    }
    if (!site.hasLogging && !site.hasMetrics && site.pattern !== "propagate" && site.pattern !== "swallow_silent") {
      issues.push({
        severity: "low",
        category: "missing_context",
        file: site.file,
        line: site.line,
        function: site.function,
        pattern: site.pattern,
        message: `Catch block in ${site.function}() has no logging or metrics \u2014 errors may be invisible.`,
        isNew: baseline ? newSites.includes(site) : true
      });
    }
  }
  const newIssues = issues.filter((i) => i.isNew);
  const existingIssues = issues.filter((i) => !i.isNew);
  const summary = {
    critical: issues.filter((i) => i.severity === "critical").length,
    high: issues.filter((i) => i.severity === "high").length,
    medium: issues.filter((i) => i.severity === "medium").length,
    low: issues.filter((i) => i.severity === "low").length,
    swallowedErrors: swallowed.length,
    inconsistencies: inconsistencies.length,
    newAntiPatterns: newSites.filter((s) => s.pattern === "unknown").length
  };
  const newCritical = newIssues.filter((i) => i.severity === "critical").length;
  const newHigh = newIssues.filter((i) => i.severity === "high").length;
  const newMedium = newIssues.filter((i) => i.severity === "medium").length;
  let passed;
  let exitCode;
  if (newCritical > 0 || newHigh > 0) {
    passed = false;
    exitCode = 1;
  } else if (strict && newMedium > 0) {
    passed = false;
    exitCode = 1;
  } else if (newIssues.length > 0) {
    passed = true;
    exitCode = 2;
  } else {
    passed = true;
    exitCode = 0;
  }
  const report = formatCIReport({
    passed,
    exitCode,
    filesScanned: fileContents.size,
    totalSites: allSites.length,
    newIssues,
    existingIssues,
    summary,
    baselineComparison
  });
  return {
    passed,
    mode: baseline ? "baseline_compare" : "full",
    filesScanned: fileContents.size,
    totalSites: allSites.length,
    newIssues,
    existingIssues,
    summary,
    report,
    exitCode
  };
}
function formatCIReport(opts) {
  const lines = [];
  lines.push("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
  lines.push(`\u2551  Error Pattern CI Validation \u2014 ${opts.passed ? "\u2705 PASSED" : "\u274C FAILED"}${" ".repeat(Math.max(0, 27 - (opts.passed ? 8 : 8)))}\u2551`);
  lines.push("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
  lines.push(`\u2551  Files scanned: ${opts.filesScanned}  |  Error sites: ${opts.totalSites}${" ".repeat(Math.max(0, 30 - String(opts.filesScanned).length - String(opts.totalSites).length))}\u2551`);
  if (opts.baselineComparison) {
    lines.push(`\u2551  Baseline: ${opts.baselineComparison.unchangedCount} unchanged, ${opts.baselineComparison.removedCount} removed${" ".repeat(Math.max(0, 30))}\u2551`);
  }
  lines.push("\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563");
  lines.push(`\u2551  Critical: ${opts.summary.critical}  |  High: ${opts.summary.high}  |  Medium: ${opts.summary.medium}  |  Low: ${opts.summary.low}${" ".repeat(10)}\u2551`);
  lines.push(`\u2551  Swallowed: ${opts.summary.swallowedErrors}  |  Inconsistent: ${opts.summary.inconsistencies}  |  New: ${opts.summary.newAntiPatterns}${" ".repeat(10)}\u2551`);
  lines.push("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
  if (opts.newIssues.length > 0) {
    lines.push("");
    lines.push("\u2500\u2500 NEW Issues (blocking if critical/high) \u2500\u2500");
    for (const issue of opts.newIssues.slice(0, 20)) {
      const icon = issue.severity === "critical" ? "\u{1F534}" : issue.severity === "high" ? "\u{1F7E0}" : issue.severity === "medium" ? "\u{1F7E1}" : "\u26AA";
      lines.push(`  ${icon} [${issue.severity.toUpperCase()}] ${issue.file}:${issue.line} (${issue.function})`);
      lines.push(`     ${issue.message}`);
    }
    if (opts.newIssues.length > 20) {
      lines.push(`  ... and ${opts.newIssues.length - 20} more`);
    }
  }
  if (opts.existingIssues.length > 0) {
    lines.push("");
    lines.push(`\u2500\u2500 Existing Issues (${opts.existingIssues.length} in baseline \u2014 not blocking) \u2500\u2500`);
    const topExisting = opts.existingIssues.filter((i) => i.severity === "critical" || i.severity === "high").slice(0, 5);
    for (const issue of topExisting) {
      lines.push(`  \u2B1C [${issue.severity.toUpperCase()}] ${issue.file}:${issue.line} \u2014 ${issue.message.slice(0, 80)}`);
    }
    if (opts.existingIssues.length > topExisting.length) {
      lines.push(`  ... ${opts.existingIssues.length - topExisting.length} more existing issues`);
    }
  }
  return lines.join("\n");
}
function parseGitDiffFiles(diffOutput) {
  return diffOutput.split("\n").map((line) => line.trim()).filter((line) => line.length > 0).filter((line) => /\.(ts|tsx)$/.test(line)).filter((line) => line.startsWith("server/") || line.startsWith("shared/") || line.startsWith("client/"));
}
var currentBaseline;
function setBaseline(baseline) {
  currentBaseline = baseline;
}
function getBaseline() {
  return currentBaseline;
}
function quickScan(fileContents, strict = false) {
  return runCIValidation(fileContents, currentBaseline, strict);
}
export {
  compareToBaseline,
  generateBaseline,
  getBaseline,
  parseGitDiffFiles,
  quickScan,
  runCIValidation,
  scanFileForCatchBlocks,
  setBaseline
};
