import {
  init_llm,
  invokeLLM
} from "./chunk-RL7LHL4I.js";
import {
  getExploitLearningDbStats,
  init_db,
  insertExploitOutcome,
  loadAllExploitChains,
  loadAllExploitPatterns,
  upsertExploitChain,
  upsertExploitPattern
} from "./chunk-B7OU3XQL.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/exploit-learning-engine.ts
async function hydrateFromDb() {
  if (_hydrated) return;
  if (_hydrating) return _hydrating;
  _hydrating = _doHydrate();
  return _hydrating;
}
async function _doHydrate() {
  try {
    const dbPatterns = await loadAllExploitPatterns();
    for (const p of dbPatterns) {
      const pattern = {
        vulnClass: p.vulnClass,
        techStack: p.techStack,
        successfulApproaches: p.successfulApproaches,
        failedApproaches: p.failedApproaches,
        knownChains: [],
        // populated below from chains table
        updatedAt: p.updatedAt
      };
      exploitPatterns.set(p.patternKey, pattern);
    }
    const dbChains = await loadAllExploitChains();
    for (const c of dbChains) {
      const chain = {
        name: c.chainName,
        steps: c.steps,
        successRate: c.successRate,
        discoveredFrom: c.discoveredFrom,
        mitreTechniques: c.mitreTechniques
      };
      for (const step of chain.steps) {
        for (const [, pattern] of exploitPatterns) {
          if (pattern.vulnClass === step.vulnClass && !pattern.knownChains.some((k) => k.name === chain.name)) {
            pattern.knownChains.push(chain);
          }
        }
      }
    }
    console.log(`[ExploitLearning] Hydrated ${dbPatterns.length} patterns, ${dbChains.length} chains from DB`);
    _hydrated = true;
  } catch (err) {
    console.warn(`[ExploitLearning] DB hydration failed (will use empty state): ${err.message}`);
    _hydrated = true;
  } finally {
    _hydrating = null;
  }
}
function classifyVulnClass(title, description) {
  const text = `${title} ${description || ""}`.toLowerCase();
  for (const { pattern, vulnClass } of VULN_CLASS_PATTERNS) {
    if (pattern.test(text)) return vulnClass;
  }
  return "unknown";
}
function accumulateOutcome(outcome) {
  recentOutcomes.push(outcome);
  if (recentOutcomes.length > MAX_RECENT_OUTCOMES) {
    recentOutcomes.shift();
  }
  const key = `${outcome.vulnClass}:${outcome.targetTechnologies.sort().join(",")}`;
  let pattern = exploitPatterns.get(key);
  if (!pattern) {
    pattern = {
      vulnClass: outcome.vulnClass,
      techStack: outcome.targetTechnologies,
      successfulApproaches: [],
      failedApproaches: [],
      knownChains: [],
      updatedAt: Date.now()
    };
    exploitPatterns.set(key, pattern);
  }
  const approach = extractApproach(outcome.code);
  if (outcome.success && !outcome.falsePositiveCheck?.isFalsePositive) {
    const existing = pattern.successfulApproaches.find((a) => a.approach === approach);
    if (existing) {
      existing.sampleCount++;
      existing.successRate = (existing.successRate * (existing.sampleCount - 1) + 1) / existing.sampleCount;
    } else {
      pattern.successfulApproaches.push({
        approach,
        payloadPattern: extractPayloadPattern(outcome.code),
        successRate: 1,
        avgConfidence: outcome.guardrailResult?.riskScore ? 100 - outcome.guardrailResult.riskScore : 70,
        sampleCount: 1
      });
    }
  } else {
    const failureReason = outcome.falsePositiveCheck?.isFalsePositive ? "false_positive_claim" : extractFailureReason(outcome.stderr, outcome.stdout);
    const existing = pattern.failedApproaches.find((a) => a.approach === approach);
    if (existing) {
      existing.failureCount++;
    } else {
      pattern.failedApproaches.push({
        approach,
        failureReason,
        failureCount: 1
      });
    }
  }
  pattern.updatedAt = Date.now();
  persistOutcomeToDb(outcome, key, pattern).catch(
    (err) => console.warn(`[ExploitLearning] DB persist failed: ${err.message}`)
  );
}
async function persistOutcomeToDb(outcome, patternKey, pattern) {
  await insertExploitOutcome({
    attemptId: outcome.attemptId,
    engagementId: outcome.engagementId,
    vulnTitle: outcome.vulnTitle,
    vulnCve: outcome.vulnCVE,
    vulnSeverity: outcome.vulnSeverity,
    vulnClass: outcome.vulnClass,
    targetHostname: outcome.targetHostname,
    targetPort: outcome.targetPort,
    targetTechnologies: outcome.targetTechnologies,
    language: outcome.language,
    code: outcome.code,
    success: outcome.success,
    exitCode: outcome.exitCode,
    stdout: outcome.stdout,
    stderr: outcome.stderr,
    guardrailPassed: outcome.guardrailResult?.passed,
    guardrailRiskScore: outcome.guardrailResult?.riskScore,
    guardrailBlockedReasons: outcome.guardrailResult?.violations?.map((v) => v.rule || v.message || String(v)),
    falsePositive: outcome.falsePositiveCheck?.isFalsePositive,
    falsePositiveReasons: outcome.falsePositiveCheck?.reasons,
    executionTimeMs: outcome.executionTimeMs,
    attemptNumber: outcome.attemptNumber,
    previousAttemptIds: outcome.previousAttemptIds,
    correctionApplied: outcome.correctionApplied
  });
  const totalSuccesses = pattern.successfulApproaches.reduce((s, a) => s + a.sampleCount, 0);
  const totalFailures = pattern.failedApproaches.reduce((s, a) => s + a.failureCount, 0);
  const total = totalSuccesses + totalFailures;
  await upsertExploitPattern({
    patternKey,
    vulnClass: pattern.vulnClass,
    techStack: pattern.techStack,
    successfulApproaches: pattern.successfulApproaches,
    failedApproaches: pattern.failedApproaches,
    knownChainIds: [],
    // chains are stored separately
    totalSuccesses,
    totalFailures,
    successRate: total > 0 ? totalSuccesses / total : 0,
    updatedAt: pattern.updatedAt
  });
}
function extractApproach(code) {
  const commentMatch = code.match(/^#\s*(.+?)$/m) || code.match(/^\/\/\s*(.+?)$/m);
  if (commentMatch) return commentMatch[1].slice(0, 80);
  const funcMatch = code.match(/def\s+(\w+)|function\s+(\w+)/);
  if (funcMatch) return funcMatch[1] || funcMatch[2] || "unknown";
  return "direct_execution";
}
function extractPayloadPattern(code) {
  const patterns = [
    /(['"].*?(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|OR\s+1=1).*?['"])/i,
    /(['"].*?<script.*?>.*?<\/script>.*?['"])/i,
    /(['"].*?(?:;|\||`|\$\().*?(?:cat|whoami|id|ls|dir|pwd).*?['"])/i,
    /(['"].*?\{\{.*?\}\}.*?['"])/i
  ];
  for (const p of patterns) {
    const match = code.match(p);
    if (match) return match[1].slice(0, 100);
  }
  return "custom";
}
function extractFailureReason(stderr, stdout) {
  const combined = `${stderr} ${stdout}`.toLowerCase();
  if (combined.includes("connection refused")) return "connection_refused";
  if (combined.includes("timeout")) return "timeout";
  if (combined.includes("403") || combined.includes("forbidden")) return "waf_blocked";
  if (combined.includes("404") || combined.includes("not found")) return "endpoint_not_found";
  if (combined.includes("500")) return "server_error";
  if (combined.includes("authentication") || combined.includes("access denied")) return "auth_required";
  if (combined.includes("patched") || combined.includes("not vulnerable")) return "target_patched";
  if (combined.includes("import") || combined.includes("module")) return "missing_dependency";
  return "unknown";
}
function prioritizeVulns(vulns, technologies) {
  return vulns.map((v) => {
    const vulnClass = classifyVulnClass(v.title, v.description);
    const key = `${vulnClass}:${technologies.sort().join(",")}`;
    const pattern = exploitPatterns.get(key);
    let exploitabilityScore = 50;
    let reasoning = "No historical data \u2014 using severity-based estimate";
    let suggestedApproach;
    const chainOpportunities = [];
    const severityBonus = { critical: 30, high: 20, medium: 10, low: 0 };
    exploitabilityScore += severityBonus[v.severity.toLowerCase()] || 0;
    if (pattern) {
      const totalSuccesses = pattern.successfulApproaches.reduce((sum, a) => sum + a.sampleCount, 0);
      const totalFailures = pattern.failedApproaches.reduce((sum, a) => sum + a.failureCount, 0);
      const total = totalSuccesses + totalFailures;
      if (total > 0) {
        const historicalRate = totalSuccesses / total;
        exploitabilityScore = Math.round(historicalRate * 60 + (severityBonus[v.severity.toLowerCase()] || 0));
        reasoning = `Historical success rate: ${Math.round(historicalRate * 100)}% (${totalSuccesses}/${total} attempts)`;
      }
      if (pattern.successfulApproaches.length > 0) {
        const best = pattern.successfulApproaches.sort((a, b) => b.successRate - a.successRate)[0];
        suggestedApproach = best.approach;
      }
      for (const chain of pattern.knownChains) {
        chainOpportunities.push(chain.name);
      }
      const allFailed = pattern.failedApproaches.filter((f) => f.failureReason === "target_patched");
      if (allFailed.length > 0 && pattern.successfulApproaches.length === 0) {
        exploitabilityScore = Math.max(5, exploitabilityScore - 40);
        reasoning += " | WARNING: All previous attempts failed (target may be patched)";
      }
    }
    const classBoost = {
      rce: 15,
      sqli: 12,
      ssti: 10,
      file_inclusion: 8,
      deserialization: 8,
      auth_bypass: 7,
      file_upload: 6,
      ssrf: 5,
      xxe: 5,
      xss: 3
    };
    exploitabilityScore += classBoost[vulnClass] || 0;
    return {
      title: v.title,
      cve: v.cve,
      severity: v.severity,
      vulnClass,
      exploitabilityScore: Math.min(100, Math.max(0, exploitabilityScore)),
      reasoning,
      suggestedApproach,
      chainOpportunities
    };
  }).sort((a, b) => b.exploitabilityScore - a.exploitabilityScore);
}
async function buildSelfCorrectionPrompt(correctionCtx, vulnTitle, targetHostname) {
  const previousSummary = correctionCtx.previousAttempts.map((a, i) => `
### Attempt ${i + 1}
- Exit code: ${a.exitCode}
- Failure analysis: ${a.failureAnalysis}
- Correction applied: ${a.correctionApplied}
- STDOUT (last 300 chars): ${a.stdout.slice(-300)}
- STDERR (last 300 chars): ${a.stderr.slice(-300)}
`).join("\n");
  const guardrailSummary = correctionCtx.guardrailViolations.length > 0 ? `
## Guardrail Violations (MUST FIX)
${correctionCtx.guardrailViolations.map((v) => `- ${v}`).join("\n")}` : "";
  const driftSummary = correctionCtx.driftSignals.length > 0 ? `
## Drift Signals Detected (MUST ADDRESS)
${correctionCtx.driftSignals.map((d) => `- [${d.severity}] ${d.type}: ${d.description}
  Correction: ${d.correction || "N/A"}`).join("\n")}` : "";
  const patternSummary = correctionCtx.relevantPatterns.length > 0 ? `
## Historical Knowledge
${correctionCtx.relevantPatterns.map((p) => {
    const successes = p.successfulApproaches.map((a) => `  \u2705 ${a.approach} (${Math.round(a.successRate * 100)}% success, n=${a.sampleCount})`).join("\n");
    const failures = p.failedApproaches.map((a) => `  \u274C ${a.approach}: ${a.failureReason} (failed ${a.failureCount}x)`).join("\n");
    return `### ${p.vulnClass} on [${p.techStack.join(", ")}]
${successes}
${failures}`;
  }).join("\n")}` : "";
  return `## SELF-CORRECTION MODE \u2014 Attempt ${correctionCtx.previousAttempts.length + 1}/${MAX_SELF_CORRECTIONS}

You are retrying an exploit for "${vulnTitle}" against ${targetHostname}.
Previous attempts FAILED. You MUST analyze what went wrong and try a DIFFERENT approach.

## MANDATORY RULES FOR SELF-CORRECTION:
1. DO NOT repeat the same approach that already failed
2. DO NOT ignore guardrail violations \u2014 they indicate hallucination or drift
3. If a port was unreachable, try a different port from the confirmed open ports
4. If a technology was wrong, rewrite for the confirmed tech stack
5. If authentication failed, try default credentials or a different auth bypass
6. If the payload was blocked, try encoding/obfuscation or a different payload class
7. Reference the historical knowledge below \u2014 use approaches that worked before
8. If all reasonable approaches have been tried, set confidence to 0 and explain why

## Previous Attempts
${previousSummary}
${guardrailSummary}
${driftSummary}
${patternSummary}

IMPORTANT: Your next attempt MUST be materially different from all previous attempts.
Explain what you're changing and why in the reasoningChain.context field.`;
}
function shouldRetry(outcome, attemptNumber) {
  if (attemptNumber >= MAX_SELF_CORRECTIONS) {
    return { retry: false, reason: `Max self-correction attempts (${MAX_SELF_CORRECTIONS}) reached` };
  }
  if (outcome.success && !outcome.falsePositiveCheck?.isFalsePositive) {
    return { retry: false, reason: "Exploit succeeded" };
  }
  if (outcome.falsePositiveCheck?.isFalsePositive) {
    return { retry: true, reason: `False positive detected (${outcome.falsePositiveCheck.reasons.join("; ")}) \u2014 retrying with stricter evidence requirements` };
  }
  const failureReason = extractFailureReason(outcome.stderr, outcome.stdout);
  const nonRetryable = ["target_patched", "connection_refused"];
  if (nonRetryable.includes(failureReason)) {
    return { retry: false, reason: `Non-retryable failure: ${failureReason}` };
  }
  if (outcome.guardrailResult && outcome.guardrailResult.riskScore >= 80) {
    return { retry: true, reason: `High guardrail risk (${outcome.guardrailResult.riskScore}) \u2014 retrying with grounding corrections` };
  }
  return { retry: true, reason: `Failure (${failureReason}) \u2014 retrying with adjusted strategy` };
}
async function discoverExploitChains(vulns, technologies, targetHostname) {
  if (vulns.length < 2) return [];
  const existingChains = [];
  for (const [, pattern] of exploitPatterns) {
    if (pattern.knownChains.length > 0) {
      existingChains.push(...pattern.knownChains);
    }
  }
  try {
    const vulnList = vulns.map(
      (v) => `- ${v.title} (${v.severity}, ${v.vulnClass})${v.cve ? ` [${v.cve}]` : ""}${v.port ? ` port:${v.port}` : ""}`
    ).join("\n");
    const response = await invokeLLM({
      _caller: "exploit-learning-engine.discoverChains",
      _priority: "normal",
      messages: [
        {
          role: "system",
          content: `You are an expert penetration tester analyzing vulnerabilities for exploit chaining opportunities.
Given a list of vulnerabilities on a target, identify multi-step attack chains where one vulnerability's exploitation enables or enhances another.

GROUNDING RULES (MANDATORY):
- ONLY reference vulnerabilities from the provided list \u2014 do NOT invent new ones
- ONLY reference technologies from the confirmed list \u2014 do NOT assume unconfirmed tech
- Each chain step MUST reference a specific vulnerability from the list by exact title
- Confidence must reflect actual exploitability, not theoretical possibility
- If no meaningful chains exist, return an empty array

Respond in JSON: { "chains": [{ "name": string, "steps": [{ "vulnClass": string, "vulnTitle": string, "purpose": string, "dependsOn": string|null }], "successLikelihood": number (0-100), "mitreTechniques": string[], "reasoning": string }] }`
        },
        {
          role: "user",
          content: `Target: ${targetHostname}
Technologies: ${technologies.join(", ")}

Vulnerabilities found:
${vulnList}

${existingChains.length > 0 ? `
Previously discovered chains (for reference, do not duplicate):
${existingChains.map((c) => `- ${c.name}: ${c.steps.map((s) => s.vulnClass).join(" \u2192 ")}`).join("\n")}` : ""}

Identify exploit chains. Each chain must use at least 2 vulnerabilities from the list above.`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "exploit_chains",
          strict: true,
          schema: {
            type: "object",
            properties: {
              chains: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    steps: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          vulnClass: { type: "string" },
                          vulnTitle: { type: "string" },
                          purpose: { type: "string" },
                          dependsOn: { type: ["string", "null"] }
                        },
                        required: ["vulnClass", "vulnTitle", "purpose", "dependsOn"],
                        additionalProperties: false
                      }
                    },
                    successLikelihood: { type: "number" },
                    mitreTechniques: { type: "array", items: { type: "string" } },
                    reasoning: { type: "string" }
                  },
                  required: ["name", "steps", "successLikelihood", "mitreTechniques", "reasoning"],
                  additionalProperties: false
                }
              }
            },
            required: ["chains"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) return existingChains;
    const parsed = JSON.parse(content);
    const newChains = [];
    for (const chain of parsed.chains || []) {
      const allStepsGrounded = chain.steps.every(
        (step) => vulns.some(
          (v) => v.title.toLowerCase().includes(step.vulnTitle.toLowerCase()) || step.vulnTitle.toLowerCase().includes(v.title.toLowerCase())
        )
      );
      if (!allStepsGrounded) {
        console.warn(`[ExploitLearning] Chain "${chain.name}" references unconfirmed vulns \u2014 REJECTED (hallucination guard)`);
        continue;
      }
      newChains.push({
        name: chain.name,
        steps: chain.steps,
        successRate: chain.successLikelihood / 100,
        discoveredFrom: `llm_analysis:${targetHostname}`,
        mitreTechniques: chain.mitreTechniques || []
      });
    }
    for (const chain of newChains) {
      upsertExploitChain({
        chainName: chain.name,
        steps: chain.steps,
        successRate: chain.successRate,
        discoveredFrom: chain.discoveredFrom,
        mitreTechniques: chain.mitreTechniques,
        targetHostname
      }).catch((err) => console.warn(`[ExploitLearning] Chain DB persist failed: ${err.message}`));
      for (const step of chain.steps) {
        const key = `${step.vulnClass}:${technologies.sort().join(",")}`;
        let pattern = exploitPatterns.get(key);
        if (!pattern) {
          pattern = {
            vulnClass: step.vulnClass,
            techStack: technologies,
            successfulApproaches: [],
            failedApproaches: [],
            knownChains: [],
            updatedAt: Date.now()
          };
          exploitPatterns.set(key, pattern);
        }
        if (!pattern.knownChains.some((c) => c.name === chain.name)) {
          pattern.knownChains.push(chain);
        }
      }
    }
    return [...existingChains, ...newChains];
  } catch (err) {
    console.warn(`[ExploitLearning] Chain discovery failed: ${err.message}`);
    return existingChains;
  }
}
function buildLearningContext(vulnClass, technologies) {
  const key = `${vulnClass}:${technologies.sort().join(",")}`;
  const pattern = exploitPatterns.get(key);
  if (!pattern) return "";
  let ctx = `

## EXPLOIT LEARNING ENGINE \u2014 Historical Knowledge for ${vulnClass}
`;
  if (pattern.successfulApproaches.length > 0) {
    ctx += `
### Approaches That Worked:
`;
    for (const a of pattern.successfulApproaches.sort((x, y) => y.successRate - x.successRate).slice(0, 5)) {
      ctx += `- \u2705 "${a.approach}" \u2014 ${Math.round(a.successRate * 100)}% success (n=${a.sampleCount})
`;
      if (a.payloadPattern !== "custom") ctx += `  Payload pattern: ${a.payloadPattern}
`;
    }
  }
  if (pattern.failedApproaches.length > 0) {
    ctx += `
### Approaches That FAILED (DO NOT REPEAT):
`;
    for (const a of pattern.failedApproaches.slice(0, 5)) {
      ctx += `- \u274C "${a.approach}" \u2014 failed ${a.failureCount}x (reason: ${a.failureReason})
`;
    }
  }
  if (pattern.knownChains.length > 0) {
    ctx += `
### Known Exploit Chains:
`;
    for (const c of pattern.knownChains) {
      ctx += `- \u{1F517} "${c.name}": ${c.steps.map((s) => s.vulnClass).join(" \u2192 ")} (${Math.round(c.successRate * 100)}% likelihood)
`;
    }
  }
  return ctx;
}
function buildGroundingContextFromAsset(asset) {
  return {
    confirmedPorts: asset.ports || [],
    confirmedTechnologies: asset.technologies || [],
    confirmedCVEs: (asset.vulns || []).map((v) => v.cve).filter((c) => !!c),
    scopeTargets: asset.scope || [asset.hostname],
    targetHostname: asset.hostname,
    reconEvidence: `Ports: ${(asset.ports || []).map((p) => `${p.port}/${p.service}`).join(", ")} | Tech: ${(asset.technologies || []).join(", ")}`
  };
}
function getLearningStats() {
  const successes = recentOutcomes.filter((o) => o.success && !o.falsePositiveCheck?.isFalsePositive);
  const falsePositives = recentOutcomes.filter((o) => o.falsePositiveCheck?.isFalsePositive);
  const guardrailBlocks = recentOutcomes.filter((o) => o.guardrailResult && !o.guardrailResult.passed);
  const vulnClassStats = /* @__PURE__ */ new Map();
  for (const o of recentOutcomes) {
    const stats = vulnClassStats.get(o.vulnClass) || { successes: 0, total: 0 };
    stats.total++;
    if (o.success && !o.falsePositiveCheck?.isFalsePositive) stats.successes++;
    vulnClassStats.set(o.vulnClass, stats);
  }
  let chainsDiscovered = 0;
  for (const [, pattern] of exploitPatterns) {
    chainsDiscovered += pattern.knownChains.length;
  }
  return {
    totalOutcomes: recentOutcomes.length,
    successRate: recentOutcomes.length > 0 ? successes.length / recentOutcomes.length : 0,
    patternsLearned: exploitPatterns.size,
    chainsDiscovered,
    topVulnClasses: [...vulnClassStats.entries()].map(([vulnClass, stats]) => ({
      vulnClass,
      successRate: stats.total > 0 ? stats.successes / stats.total : 0,
      attempts: stats.total
    })).sort((a, b) => b.attempts - a.attempts).slice(0, 10),
    falsePositivesDetected: falsePositives.length,
    guardrailBlocks: guardrailBlocks.length
  };
}
async function getPersistedLearningStats() {
  const inMemory = getLearningStats();
  const database = await getExploitLearningDbStats();
  return {
    inMemory,
    database,
    combined: {
      totalOutcomes: database.totalOutcomes,
      // DB is the source of truth for totals
      patternsLearned: database.patternsStored,
      chainsDiscovered: database.chainsStored,
      dbSuccessRate: database.successRate
    }
  };
}
var exploitPatterns, recentOutcomes, MAX_RECENT_OUTCOMES, _hydrated, _hydrating, VULN_CLASS_PATTERNS, VULN_CLASS_TO_OWASP, MAX_SELF_CORRECTIONS;
var init_exploit_learning_engine = __esm({
  "server/lib/exploit-learning-engine.ts"() {
    init_llm();
    init_db();
    exploitPatterns = /* @__PURE__ */ new Map();
    recentOutcomes = [];
    MAX_RECENT_OUTCOMES = 500;
    _hydrated = false;
    _hydrating = null;
    VULN_CLASS_PATTERNS = [
      // ── Injection (A03) ──
      { pattern: /sql\s*inject|sqli|blind.*sql|union.*select/i, vulnClass: "sqli", owaspCategory: "A03" },
      { pattern: /cross.site.script|xss|stored.*xss|reflected.*xss|dom.*xss/i, vulnClass: "xss", owaspCategory: "A03" },
      { pattern: /remote.code.exec|\brce\b|command.inject|os.command|spawn/i, vulnClass: "rce", owaspCategory: "A03" },
      { pattern: /server.side.template|ssti|template.inject/i, vulnClass: "ssti", owaspCategory: "A03" },
      { pattern: /xxe|xml.external|xml.inject/i, vulnClass: "xxe", owaspCategory: "A05" },
      { pattern: /ldap.inject/i, vulnClass: "ldap_injection", owaspCategory: "A03" },
      { pattern: /xpath.inject/i, vulnClass: "xpath_injection", owaspCategory: "A03" },
      { pattern: /html.inject/i, vulnClass: "html_injection", owaspCategory: "A03" },
      { pattern: /css.inject/i, vulnClass: "css_injection", owaspCategory: "A03" },
      { pattern: /iframe.inject/i, vulnClass: "iframe_injection", owaspCategory: "A03" },
      { pattern: /email.inject|header.inject.*email/i, vulnClass: "email_injection", owaspCategory: "A03" },
      { pattern: /prototype.pollut/i, vulnClass: "prototype_pollution", owaspCategory: "A03" },
      { pattern: /code.inject|javascript.inject|ssji/i, vulnClass: "code_injection", owaspCategory: "A03" },
      // ── File Inclusion / Upload (A01/A04) ──
      { pattern: /file.inclus|lfi|rfi|path.travers|directory.travers/i, vulnClass: "file_inclusion", owaspCategory: "A01" },
      { pattern: /file.upload|unrestrict.*upload/i, vulnClass: "file_upload", owaspCategory: "A04" },
      // ── Deserialization (A08) ──
      { pattern: /deserializ|insecure.*deserial/i, vulnClass: "deserialization", owaspCategory: "A08" },
      // ── SSRF / Cloud Metadata (A10) ──
      { pattern: /ssrf|server.side.request/i, vulnClass: "ssrf", owaspCategory: "A10" },
      { pattern: /metadata.service|cloud.metadata|169\.254\.169\.254/i, vulnClass: "ssrf", owaspCategory: "A10" },
      // ── Authentication / JWT (A07) ──
      { pattern: /auth.*bypass|broken.*auth|weak.*password|default.*cred|brute.?force/i, vulnClass: "auth_bypass", owaspCategory: "A07" },
      { pattern: /jwt|json.web.token/i, vulnClass: "jwt_attack", owaspCategory: "A07" },
      // ── Access Control (A01) ──
      { pattern: /idor|insecure.direct|broken.*access|bfla|bopla|mass.assign|privilege.escal/i, vulnClass: "broken_access_control", owaspCategory: "A01" },
      { pattern: /open.redirect|unvalidated.redirect/i, vulnClass: "open_redirect", owaspCategory: "A01" },
      // ── CSRF (A01) ──
      { pattern: /csrf|cross.site.request/i, vulnClass: "csrf", owaspCategory: "A01" },
      // ── Security Misconfiguration (A05) ──
      { pattern: /\.env.*disclos|env.*file.*(expos|discov|disclos|detect)|env.*leak|sensitive.*info.*disclos/i, vulnClass: "info_disclosure", owaspCategory: "A05" },
      { pattern: /config.*expos|config.*file.*detect|configuration.*file/i, vulnClass: "info_disclosure", owaspCategory: "A05" },
      { pattern: /\.git.*config|\.git.*expos|git.*detect|svn.*expos|svn.*wc\.db|hg.*expos|version.control/i, vulnClass: "vcs_exposure", owaspCategory: "A05" },
      { pattern: /directory.list|autoindex|dir.*list/i, vulnClass: "directory_listing", owaspCategory: "A05" },
      { pattern: /common.file|htaccess|nginx\.conf|phpinfo|ssh.key/i, vulnClass: "info_disclosure", owaspCategory: "A05" },
      { pattern: /secret.*token|api.*key.*expos|credential.*expos|connection.*string/i, vulnClass: "info_disclosure", owaspCategory: "A05" },
      { pattern: /full.path.disclos|stack.trace|error.message.*disclos/i, vulnClass: "info_disclosure", owaspCategory: "A05" },
      { pattern: /missing.*header|security.*header|x-frame|x-content-type|strict-transport|content-security-policy/i, vulnClass: "missing_headers", owaspCategory: "A05" },
      { pattern: /cookie.*secure|cookie.*httponly|insecure.*cookie/i, vulnClass: "insecure_cookie", owaspCategory: "A05" },
      { pattern: /cors.*misconfig|access-control-allow-origin/i, vulnClass: "cors_misconfiguration", owaspCategory: "A05" },
      // ── Vulnerable Components (A06) ──
      { pattern: /outdated.*lib|vulnerable.*component|known.*vuln.*version|cve-\d{4}/i, vulnClass: "vulnerable_component", owaspCategory: "A06" },
      { pattern: /null.*pointer|apache.*http.*server.*null/i, vulnClass: "vulnerable_component", owaspCategory: "A06" },
      // ── Buffer Overflow ──
      { pattern: /buffer.overflow|stack.overflow|heap.overflow/i, vulnClass: "buffer_overflow", owaspCategory: "A03" },
      // ── DoS ──
      { pattern: /denial.of.service|dos|date.manipul/i, vulnClass: "dos", owaspCategory: "A04" },
      // ── Insecure Output ──
      { pattern: /insecure.output|llm.*xss/i, vulnClass: "insecure_output", owaspCategory: "A03" }
    ];
    VULN_CLASS_TO_OWASP = {};
    for (const p of VULN_CLASS_PATTERNS) {
      if (p.owaspCategory && !VULN_CLASS_TO_OWASP[p.vulnClass]) {
        VULN_CLASS_TO_OWASP[p.vulnClass] = p.owaspCategory;
      }
    }
    MAX_SELF_CORRECTIONS = 3;
  }
});

export {
  exploitPatterns,
  recentOutcomes,
  hydrateFromDb,
  VULN_CLASS_TO_OWASP,
  classifyVulnClass,
  accumulateOutcome,
  prioritizeVulns,
  MAX_SELF_CORRECTIONS,
  buildSelfCorrectionPrompt,
  shouldRetry,
  discoverExploitChains,
  buildLearningContext,
  buildGroundingContextFromAsset,
  getLearningStats,
  getPersistedLearningStats,
  init_exploit_learning_engine
};
