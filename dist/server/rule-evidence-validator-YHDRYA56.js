import "./chunk-KFQGP6VL.js";

// server/lib/rule-evidence-validator.ts
function extractPatternsFromRule(rule) {
  const patterns = [];
  const content = rule.content;
  switch (rule.format) {
    case "sigma":
      patterns.push(...extractSigmaPatterns(content));
      break;
    case "yara":
      patterns.push(...extractYaraPatterns(content));
      break;
    case "snort":
    case "suricata":
      patterns.push(...extractSnortPatterns(content));
      break;
    case "kql":
      patterns.push(...extractKqlPatterns(content));
      break;
    case "spl":
      patterns.push(...extractSplPatterns(content));
      break;
  }
  return patterns;
}
function extractSigmaPatterns(content) {
  const patterns = [];
  const lines = content.split("\n");
  let inDetection = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("detection:")) {
      inDetection = true;
      continue;
    }
    if (inDetection && !trimmed.startsWith("-") && !trimmed.startsWith(" ") && trimmed.includes(":") && !trimmed.startsWith("condition")) {
      inDetection = false;
    }
    if (inDetection) {
      const valueMatch = trimmed.match(/:\s*['"]?(.+?)['"]?\s*$/);
      if (valueMatch && valueMatch[1] && !trimmed.startsWith("condition") && !trimmed.startsWith("selection")) {
        const value = valueMatch[1].replace(/['"]/g, "");
        if (value.length > 2 && value !== "true" && value !== "false") {
          patterns.push({
            pattern: value,
            type: value.includes("*") ? "regex" : "string",
            required: true
          });
        }
      }
      if (trimmed.startsWith("- ")) {
        const listValue = trimmed.slice(2).replace(/['"]/g, "").trim();
        if (listValue.length > 2) {
          patterns.push({ pattern: listValue, type: "string", required: false });
        }
      }
    }
    const portMatch = trimmed.match(/dst_port:\s*(\d+)/);
    if (portMatch) {
      patterns.push({ pattern: portMatch[1], type: "port", required: true });
    }
  }
  return patterns;
}
function extractYaraPatterns(content) {
  const patterns = [];
  const stringMatches = Array.from(content.matchAll(/\$\w+\s*=\s*"([^"]+)"/g));
  for (const match of stringMatches) {
    patterns.push({
      pattern: match[1],
      type: "string",
      required: false
    });
  }
  const hexMatches = Array.from(content.matchAll(/\$\w+\s*=\s*\{([^}]+)\}/g));
  for (const match of hexMatches) {
    patterns.push({
      pattern: match[1].trim(),
      type: "regex",
      required: false
    });
  }
  return patterns;
}
function extractSnortPatterns(content) {
  const patterns = [];
  const contentMatches = Array.from(content.matchAll(/content:"([^"]+)"/g));
  for (const match of contentMatches) {
    patterns.push({
      pattern: match[1],
      type: "string",
      required: true
    });
  }
  const portMatch = content.match(/->\s*any\s+(\d+)/);
  if (portMatch) {
    patterns.push({ pattern: portMatch[1], type: "port", required: true });
  }
  const pcreMatches = Array.from(content.matchAll(/pcre:"\/([^"]+)\/"/g));
  for (const match of pcreMatches) {
    patterns.push({ pattern: match[1], type: "regex", required: true });
  }
  return patterns;
}
function extractKqlPatterns(content) {
  const patterns = [];
  const hasMatches = Array.from(content.matchAll(/has\s+"([^"]+)"/g));
  for (const match of hasMatches) {
    patterns.push({ pattern: match[1], type: "keyword", required: true });
  }
  const containsMatches = Array.from(content.matchAll(/contains\s+"([^"]+)"/g));
  for (const match of containsMatches) {
    patterns.push({ pattern: match[1], type: "string", required: true });
  }
  const portMatches = Array.from(content.matchAll(/Port\s*==\s*(\d+)/g));
  for (const match of portMatches) {
    patterns.push({ pattern: match[1], type: "port", required: true });
  }
  return patterns;
}
function extractSplPatterns(content) {
  const patterns = [];
  const searchMatches = Array.from(content.matchAll(/search\s+"?([^"|]+)"?/g));
  for (const match of searchMatches) {
    patterns.push({ pattern: match[1].trim(), type: "keyword", required: true });
  }
  const portMatches2 = Array.from(content.matchAll(/dest_port[=](\d+)/g));
  for (const match of portMatches2) {
    patterns.push({ pattern: match[1], type: "port", required: true });
  }
  return patterns;
}
function validateRuleAgainstEvidence(rule, evidence) {
  const patterns = extractPatternsFromRule(rule);
  const matchedPatterns = [];
  const missedPatterns = [];
  const evidenceText = evidence.content.toLowerCase();
  for (const pattern of patterns) {
    const found = testPattern(pattern, evidenceText, evidence);
    if (found) {
      matchedPatterns.push(pattern.pattern);
    } else {
      missedPatterns.push(pattern.pattern);
    }
  }
  const totalPatterns = patterns.length;
  const matchCount = matchedPatterns.length;
  const coveragePercent = totalPatterns > 0 ? Math.round(matchCount / totalPatterns * 100) : 0;
  const requiredPatterns = patterns.filter((p) => p.required);
  const requiredMatched = requiredPatterns.filter((p) => matchedPatterns.includes(p.pattern)).length;
  const detected = requiredPatterns.length > 0 ? requiredMatched >= Math.ceil(requiredPatterns.length * 0.5) : matchCount > 0;
  let detectionConfidence;
  if (!detected) {
    detectionConfidence = "none";
  } else if (coveragePercent >= 80) {
    detectionConfidence = "high";
  } else if (coveragePercent >= 50) {
    detectionConfidence = "medium";
  } else {
    detectionConfidence = "low";
  }
  const falsePositiveRisk = patterns.length <= 1 ? "high" : patterns.length <= 3 ? "medium" : "low";
  const analysis = buildAnalysis(rule, evidence, matchedPatterns, missedPatterns, detected, coveragePercent);
  const recommendations = buildRecommendations(rule, matchedPatterns, missedPatterns, detected, coveragePercent);
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    ruleFormat: rule.format,
    evidenceId: evidence.id,
    detected,
    matchCount,
    matchedPatterns,
    missedPatterns,
    detectionConfidence,
    falsePositiveRisk,
    coveragePercent,
    analysis,
    recommendations,
    validatedAt: Date.now()
  };
}
function batchValidateRules(rules, evidence) {
  const results = [];
  for (const rule of rules) {
    let bestResult = null;
    for (const artifact of evidence) {
      const result = validateRuleAgainstEvidence(rule, artifact);
      if (!bestResult || result.coveragePercent > bestResult.coveragePercent) {
        bestResult = result;
      }
    }
    if (bestResult) {
      results.push(bestResult);
    }
  }
  const rulesDetected = results.filter((r) => r.detected).length;
  const rulesMissed = results.filter((r) => !r.detected).length;
  const avgCoverage = results.length > 0 ? Math.round(results.reduce((sum, r) => sum + r.coveragePercent, 0) / results.length) : 0;
  const summary = `Validated ${results.length} rule(s) against ${evidence.length} evidence artifact(s). ${rulesDetected} detected the attack (${Math.round(rulesDetected / Math.max(results.length, 1) * 100)}% detection rate). Average pattern coverage: ${avgCoverage}%.`;
  return {
    totalRules: rules.length,
    totalEvidence: evidence.length,
    rulesValidated: results.length,
    rulesDetected,
    rulesMissed,
    avgCoverage,
    results,
    summary
  };
}
function testPattern(pattern, evidenceText, evidence) {
  const searchText = pattern.pattern.toLowerCase();
  switch (pattern.type) {
    case "string":
    case "keyword":
      if (searchText.includes("*")) {
        const regexStr = searchText.replace(/\*/g, ".*").replace(/\?/g, ".");
        try {
          return new RegExp(regexStr).test(evidenceText);
        } catch {
          return evidenceText.includes(searchText.replace(/\*/g, ""));
        }
      }
      return evidenceText.includes(searchText);
    case "regex":
      try {
        return new RegExp(searchText, "i").test(evidenceText);
      } catch {
        return evidenceText.includes(searchText);
      }
    case "port":
      const portNum = parseInt(searchText, 10);
      if (evidence.targetPort === portNum) return true;
      return evidenceText.includes(`:${portNum}`) || evidenceText.includes(`port ${portNum}`);
    case "protocol":
      return evidenceText.includes(searchText);
    default:
      return evidenceText.includes(searchText);
  }
}
function buildAnalysis(rule, evidence, matched, missed, detected, coverage) {
  if (detected && coverage >= 80) {
    return `Rule "${rule.name}" successfully detected the attack pattern in evidence artifact ${evidence.id}. ${matched.length} of ${matched.length + missed.length} patterns matched (${coverage}% coverage). The rule demonstrates strong detection capability against this exploit.`;
  }
  if (detected && coverage >= 50) {
    return `Rule "${rule.name}" partially detected the attack pattern. ${matched.length} of ${matched.length + missed.length} patterns matched (${coverage}% coverage). Some patterns did not match the evidence, which may indicate the rule needs refinement or the evidence is incomplete.`;
  }
  if (detected) {
    return `Rule "${rule.name}" detected the attack with low confidence. Only ${matched.length} of ${matched.length + missed.length} patterns matched (${coverage}% coverage). The rule may produce false negatives in production.`;
  }
  return `Rule "${rule.name}" failed to detect the attack pattern in evidence artifact ${evidence.id}. ${missed.length} pattern(s) did not match. The rule may need revision to detect this specific exploit variant.`;
}
function buildRecommendations(rule, matched, missed, detected, coverage) {
  const recs = [];
  if (!detected) {
    recs.push("Rule failed to detect the attack. Consider regenerating with more specific evidence data.");
    if (missed.length > 0) {
      recs.push(`${missed.length} pattern(s) did not match. Review and update: ${missed.slice(0, 3).join(", ")}`);
    }
  }
  if (coverage < 50 && detected) {
    recs.push("Low pattern coverage. Add more specific detection patterns to reduce false negatives.");
  }
  if (matched.length <= 1) {
    recs.push("Rule relies on very few patterns. Add additional indicators to reduce false positive risk.");
  }
  if (coverage >= 80 && detected) {
    recs.push("Rule shows strong detection. Consider promoting to production after peer review.");
  }
  if (rule.format === "sigma" && !rule.content.includes("falsepositives")) {
    recs.push("Add a falsepositives section to document known benign triggers.");
  }
  return recs;
}
export {
  batchValidateRules,
  validateRuleAgainstEvidence
};
