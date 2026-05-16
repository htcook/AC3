import {
  init_llm,
  invokeLLM
} from "./chunk-2CCDF2QL.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/attack-narrative-generator.ts
async function generateAttackNarratives(input) {
  const narratives = [];
  const allFindings = [];
  for (const asset of input.assets) {
    const evidencedVulns = (asset.vulns || []).filter(
      (v) => v.rawEvidence || v.corroborationTier === "confirmed" || v.screenshotPath
    );
    for (const vuln of evidencedVulns) {
      allFindings.push({
        asset: asset.hostname || asset.ip || "unknown",
        vuln,
        exploits: (asset.exploitAttempts || []).filter(
          (e) => e.target?.includes(vuln.endpoint || "") || e.technique?.includes(vuln.title || "")
        ),
        toolResults: asset.toolResults || []
      });
    }
  }
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  allFindings.sort(
    (a, b) => (severityOrder[b.vuln.severity?.toLowerCase()] || 0) - (severityOrder[a.vuln.severity?.toLowerCase()] || 0)
  );
  const topFindings = allFindings.slice(0, 20);
  const criticalHighFindings = topFindings.filter(
    (f) => f.vuln.severity === "critical" || f.vuln.severity === "high"
  );
  const mediumFindings = topFindings.filter((f) => f.vuln.severity === "medium");
  for (const finding of criticalHighFindings) {
    try {
      const narrative = await generateSingleNarrative(input, finding);
      if (narrative) narratives.push(narrative);
    } catch (err) {
      console.warn(`[AttackNarrative] Failed for ${finding.vuln.title}:`, err.message);
    }
  }
  if (mediumFindings.length > 0) {
    try {
      const batchNarratives = await generateBatchNarratives(input, mediumFindings);
      narratives.push(...batchNarratives);
    } catch (err) {
      console.warn("[AttackNarrative] Batch generation failed:", err.message);
    }
  }
  return narratives;
}
async function generateSingleNarrative(input, finding) {
  const evidenceContext = [
    `## Finding: ${finding.vuln.title}`,
    `Severity: ${finding.vuln.severity}`,
    `Asset: ${finding.asset}`,
    finding.vuln.cve ? `CVE: ${finding.vuln.cve}` : "",
    finding.vuln.endpoint ? `Endpoint: ${finding.vuln.endpoint}` : "",
    finding.vuln.tool ? `Detected by: ${finding.vuln.tool}` : "",
    finding.vuln.description ? `Description: ${finding.vuln.description}` : "",
    "",
    "## Raw Evidence:",
    finding.vuln.rawEvidence?.slice(0, 2e3) || "No raw evidence captured",
    "",
    finding.exploits && finding.exploits.length > 0 ? [
      "## Exploit Attempts:",
      ...finding.exploits.map(
        (e) => `- ${e.technique} via ${e.tool}: ${e.succeeded ? "SUCCEEDED" : "FAILED"}${e.rawEvidence ? `
  Evidence: ${e.rawEvidence.slice(0, 500)}` : ""}`
      )
    ].join("\n") : "",
    "",
    finding.toolResults && finding.toolResults.length > 0 ? [
      "## Related Tool Results:",
      ...finding.toolResults.slice(0, 5).map(
        (tr) => `- ${tr.tool}: ${tr.findingCount || 0} findings (exit: ${tr.exitCode})`
      )
    ].join("\n") : ""
  ].filter(Boolean).join("\n");
  const targetContext = input.targetProfile ? [
    `Industry: ${input.targetProfile.industry || "Unknown"}`,
    input.targetProfile.waf ? `WAF: ${input.targetProfile.waf}` : "",
    input.targetProfile.cdn ? `CDN: ${input.targetProfile.cdn}` : "",
    input.targetProfile.techStack?.length ? `Tech Stack: ${input.targetProfile.techStack.join(", ")}` : ""
  ].filter(Boolean).join(" | ") : "";
  try {
    const response = await invokeLLM({
      _caller: "attack-narrative-generator:generateNarrative",
      messages: [
        {
          role: "system",
          content: `You are an expert penetration tester writing detailed attack narratives for a pentest report. Your narratives must be:
1. Evidence-based \u2014 every claim must reference specific tool output or captured data
2. Technically precise \u2014 include exact commands, endpoints, parameters, and responses
3. Business-relevant \u2014 explain what an attacker could achieve and the real-world impact
4. Actionable \u2014 provide specific, prioritized remediation steps with effort estimates

Write in a professional but direct style. No filler text. Every sentence must add value.

Target context: ${targetContext}`
        },
        {
          role: "user",
          content: `Generate a detailed attack narrative for this finding. Return valid JSON matching this schema:
{
  "title": "string - concise attack path title",
  "attackPath": "string - 2-3 sentence kill chain summary",
  "businessImpact": "string - what an attacker could achieve in business terms",
  "technicalImpact": "string - technical consequences (data access, system control, etc.)",
  "steps": [
    {
      "stepNumber": 1,
      "phase": "recon|enumeration|vuln_detection|exploitation|post_exploitation",
      "tool": "string",
      "command": "string or null",
      "target": "string",
      "finding": "string - what was discovered",
      "evidence": "string - specific evidence from tool output"
    }
  ],
  "remediationSteps": [
    {
      "priority": 1,
      "action": "string - specific fix",
      "effort": "low|medium|high",
      "timeEstimate": "string - e.g. '2 hours', '1 day'"
    }
  ],
  "mitreTechniques": ["T1190", "T1059", etc.],
  "cvssScore": number or null
}

Finding data:
${evidenceContext}`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "attack_narrative",
          strict: true,
          schema: {
            type: "object",
            properties: {
              title: { type: "string" },
              attackPath: { type: "string" },
              businessImpact: { type: "string" },
              technicalImpact: { type: "string" },
              steps: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    stepNumber: { type: "integer" },
                    phase: { type: "string" },
                    tool: { type: "string" },
                    command: { type: ["string", "null"] },
                    target: { type: "string" },
                    finding: { type: "string" },
                    evidence: { type: "string" }
                  },
                  required: ["stepNumber", "phase", "tool", "target", "finding", "evidence"],
                  additionalProperties: false
                }
              },
              remediationSteps: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    priority: { type: "integer" },
                    action: { type: "string" },
                    effort: { type: "string" },
                    timeEstimate: { type: "string" }
                  },
                  required: ["priority", "action", "effort", "timeEstimate"],
                  additionalProperties: false
                }
              },
              mitreTechniques: { type: "array", items: { type: "string" } },
              cvssScore: { type: ["number", "null"] }
            },
            required: ["title", "attackPath", "businessImpact", "technicalImpact", "steps", "remediationSteps", "mitreTechniques", "cvssScore"],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) return null;
    const parsed = JSON.parse(content);
    return {
      id: `narr-${input.engagementId}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      engagementId: input.engagementId,
      title: parsed.title,
      severity: finding.vuln.severity,
      attackPath: parsed.attackPath,
      steps: parsed.steps.map((s) => ({
        ...s,
        screenshotPath: finding.vuln.screenshotPath
      })),
      businessImpact: parsed.businessImpact,
      technicalImpact: parsed.technicalImpact,
      remediationSteps: parsed.remediationSteps,
      affectedAssets: [finding.asset],
      mitreTechniques: parsed.mitreTechniques || [],
      cvssScore: parsed.cvssScore,
      generatedAt: Date.now()
    };
  } catch (err) {
    console.warn(`[AttackNarrative] LLM generation failed:`, err.message);
    return null;
  }
}
async function generateBatchNarratives(input, findings) {
  const findingSummaries = findings.map((f, i) => [
    `### Finding ${i + 1}: ${f.vuln.title}`,
    `Severity: ${f.vuln.severity} | Asset: ${f.asset}`,
    f.vuln.cve ? `CVE: ${f.vuln.cve}` : "",
    f.vuln.endpoint ? `Endpoint: ${f.vuln.endpoint}` : "",
    `Evidence: ${(f.vuln.rawEvidence || "No raw evidence").slice(0, 500)}`
  ].filter(Boolean).join("\n")).join("\n\n");
  try {
    const response = await invokeLLM({
      _caller: "attack-narrative-generator:batchNarratives",
      messages: [
        {
          role: "system",
          content: `You are an expert penetration tester. Generate concise attack narratives for multiple medium-severity findings. Each narrative should include: attack path, business impact, and top remediation action. Return a JSON array.`
        },
        {
          role: "user",
          content: `Generate narratives for these ${findings.length} findings. Return JSON array where each element has: title, attackPath, businessImpact, technicalImpact, remediationAction, effort (low/medium/high), mitreTechniques (array of strings).
${findingSummaries}`
        }
      ]
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) return [];
    const jsonMatch = content.match(/\[[\s\S]*\]/);
    if (!jsonMatch) return [];
    const parsed = JSON.parse(jsonMatch[0]);
    return parsed.map((n, i) => ({
      id: `narr-${input.engagementId}-batch-${Date.now()}-${i}`,
      engagementId: input.engagementId,
      title: n.title || findings[i]?.vuln.title || "Unknown",
      severity: findings[i]?.vuln.severity || "medium",
      attackPath: n.attackPath || "",
      steps: [],
      businessImpact: n.businessImpact || "",
      technicalImpact: n.technicalImpact || "",
      remediationSteps: [{
        priority: 1,
        action: n.remediationAction || "Review and patch",
        effort: n.effort || "medium",
        timeEstimate: n.effort === "low" ? "1-2 hours" : n.effort === "high" ? "1-2 days" : "4-8 hours"
      }],
      affectedAssets: [findings[i]?.asset || "unknown"],
      mitreTechniques: n.mitreTechniques || [],
      generatedAt: Date.now()
    }));
  } catch (err) {
    console.warn("[AttackNarrative] Batch generation failed:", err.message);
    return [];
  }
}
async function generateExecutiveSummary(input) {
  const criticalCount = input.assets.flatMap((a) => a.vulns).filter((v) => v.severity === "critical").length;
  const highCount = input.assets.flatMap((a) => a.vulns).filter((v) => v.severity === "high").length;
  const topNarratives = input.narratives.filter((n) => n.severity === "critical" || n.severity === "high").slice(0, 5).map((n) => `- **${n.title}** (${n.severity}): ${n.attackPath}`).join("\n");
  try {
    const response = await invokeLLM({
      _caller: "attack-narrative-generator:executiveSummary",
      messages: [
        {
          role: "system",
          content: `You are a senior penetration testing consultant writing an executive summary for a pentest report. The summary should be 3-5 paragraphs, written for C-level executives and security leadership. Focus on business risk, not technical details. Be direct and specific about what was found and what needs to happen next.`
        },
        {
          role: "user",
          content: `Write an executive summary for this penetration test engagement:

Engagement: ${input.engagementName}
Assets tested: ${input.assets.length}
Total vulnerabilities: ${input.stats.vulnsFound} (${input.stats.verifiedVulns || 0} verified with evidence)
Critical: ${criticalCount} | High: ${highCount}
Exploit attempts: ${input.stats.exploitsAttempted} (${input.stats.exploitsSucceeded} succeeded)
Ports discovered: ${input.stats.portsFound}

Top attack paths:
${topNarratives || "No critical/high attack paths identified"}

Industry: ${input.targetProfile?.industry || "Unknown"}
WAF/CDN: ${input.targetProfile?.waf || "None detected"} / ${input.targetProfile?.cdn || "None detected"}`
        }
      ]
    });
    return response.choices?.[0]?.message?.content || "Executive summary generation failed.";
  } catch (err) {
    return `Executive summary generation failed: ${err.message}`;
  }
}
var init_attack_narrative_generator = __esm({
  "server/lib/attack-narrative-generator.ts"() {
    init_llm();
  }
});
init_attack_narrative_generator();
export {
  generateAttackNarratives,
  generateExecutiveSummary
};
