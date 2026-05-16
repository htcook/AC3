import {
  init_llm,
  invokeLLM
} from "./chunk-NLTQ4N7G.js";
import "./chunk-RUIEEOYK.js";
import {
  getDb,
  init_db
} from "./chunk-CKIMRR6W.js";
import "./chunk-KDOLKO2A.js";
import {
  ac3ReportFindings,
  bugBountyFindings,
  bugBountyLlmTrainingSamples,
  exploitationAttempts,
  init_schema,
  nucleiFindings,
  scanforgeGeneratedTemplates,
  scanforgeResearchLog,
  webAppFindings
} from "./chunk-Q4QB2XQC.js";
import "./chunk-KFQGP6VL.js";

// server/lib/bounty-training-engine.ts
init_db();
init_schema();
init_llm();
import { eq, desc, sql, and, or, isNotNull } from "drizzle-orm";
async function getDb2() {
  const db = await getDb();
  return db;
}
function computeQualityScore(opts) {
  let score = 0.1;
  if (opts.hasSummary) score += 0.15;
  if (opts.hasCve) score += 0.1;
  if (opts.hasCwe) score += 0.1;
  if (opts.hasExploit) score += 0.15;
  if (opts.hasEvidence) score += 0.1;
  if (opts.isNovel) score += 0.2;
  if (opts.severity === "critical") score += 0.15;
  else if (opts.severity === "high") score += 0.1;
  else if (opts.severity === "medium") score += 0.05;
  if (opts.bountyAmount > 0) score += Math.min(0.1, Math.log10(opts.bountyAmount) / 50);
  return Math.min(0.99, Math.round(score * 100) / 100);
}
var SYSTEM_PROMPTS = {
  vuln_pattern: `You are an expert penetration tester specializing in identifying security vulnerabilities in web applications, APIs, network services, and cloud infrastructure. You analyze target systems methodically, identify vulnerability patterns based on CWE classifications, and explain how to discover and verify each vulnerability class. Your analysis includes the technical root cause, exploitation prerequisites, and detection methodology.`,
  exploit_chain: `You are an advanced red team operator who specializes in chaining multiple vulnerabilities into complete attack paths. You understand how initial access vulnerabilities can be combined with privilege escalation, lateral movement, and data exfiltration techniques to achieve full compromise. You explain each step of the chain, the MITRE ATT&CK techniques involved, and the conditions required for successful exploitation.`,
  report_template: `You are a professional penetration test report writer who produces clear, actionable vulnerability reports for both technical and executive audiences. Your reports include precise technical details, proof-of-concept steps, business impact analysis, CVSS scoring rationale, and prioritized remediation guidance. You follow NIST 800-115 and OWASP reporting standards.`,
  scope_recon: `You are a reconnaissance specialist who analyzes bug bounty program scopes, identifies high-value targets within scope boundaries, and develops systematic testing strategies. You understand asset types (URLs, APIs, mobile apps, CIDR ranges), scope exclusions, and how to prioritize targets based on program history, bounty amounts, and attack surface complexity.`,
  cwe_analysis: `You are a vulnerability classification expert who deeply understands the Common Weakness Enumeration (CWE) taxonomy. You analyze vulnerability instances, map them to precise CWE identifiers, explain the root cause weakness pattern, identify related CWEs in the hierarchy, and describe detection techniques specific to each weakness class.`,
  bounty_strategy: `You are a bug bounty strategist who analyzes program data to optimize researcher ROI. You evaluate programs based on payout history, scope breadth, response time, vulnerability acceptance patterns, and competition level. You recommend which CWE categories, asset types, and testing methodologies yield the highest payouts per hour of research effort.`,
  novel_finding: `You are an elite vulnerability researcher who discovers zero-day and previously unreported vulnerabilities. You analyze systems for novel attack vectors that automated scanners miss, including business logic flaws, race conditions, authentication bypasses, and complex injection chains. You document your discovery methodology so it can be replicated on similar targets, and you assess whether the finding is reportable to the vendor or eligible for bug bounty submission.`
};
async function extractFromHackerOneFindings(opts) {
  const db = await getDb2();
  const limit = opts.limit || 100;
  const existingIds = await db.select({ findingId: bugBountyLlmTrainingSamples.findingId }).from(bugBountyLlmTrainingSamples).where(isNotNull(bugBountyLlmTrainingSamples.findingId));
  const existingSet = new Set(existingIds.map((r) => r.findingId));
  const findings = await db.select().from(bugBountyFindings).where(and(eq(bugBountyFindings.platform, "hackerone"), sql`${bugBountyFindings.awardedAmount} >= ${opts.minBounty || 0}`)).orderBy(desc(bugBountyFindings.awardedAmount)).limit(limit * 2);
  let extracted = 0, skipped = 0;
  for (const f of findings) {
    if (extracted >= limit) break;
    if (existingSet.has(f.id)) {
      skipped++;
      continue;
    }
    const bounty = Number(f.awardedAmount) || 0;
    const hasCve = Array.isArray(f.cveIds) && f.cveIds.length > 0;
    const hasCwe = !!f.cweId;
    let category = "vuln_pattern";
    if (bounty >= 5e3) category = "bounty_strategy";
    if (hasCwe) category = "cwe_analysis";
    if (hasCve && bounty >= 1e3) category = "exploit_chain";
    const quality = computeQualityScore({
      hasSummary: !!f.summary,
      hasCve,
      hasCwe,
      severity: f.severityRating,
      bountyAmount: bounty,
      hasExploit: false,
      hasEvidence: !!f.summary,
      isNovel: false
    });
    const cveList = Array.isArray(f.cveIds) ? f.cveIds : [];
    const tags = ["hackerone", "disclosed"];
    if (hasCve) tags.push("has_cve");
    if (bounty >= 5e3) tags.push("high_bounty");
    const systemPrompt = SYSTEM_PROMPTS[category];
    const userPrompt = buildH1UserPrompt(category, f, bounty, cveList);
    const assistantResponse = buildH1AssistantResponse(f, bounty, cveList);
    await db.insert(bugBountyLlmTrainingSamples).values({
      findingId: f.id,
      category,
      qualityScore: String(quality),
      bountyAmount: String(bounty),
      severityRating: f.severityRating,
      cweId: f.cweId,
      cveIds: cveList,
      programHandle: f.programHandle,
      programName: f.programName,
      assetType: f.assetType,
      assetIdentifier: f.assetIdentifier,
      systemPrompt,
      userPrompt,
      assistantResponse,
      rawTitle: f.title,
      rawSummary: f.summary,
      enrichmentStatus: "raw",
      tags
    });
    extracted++;
  }
  return { extracted, skipped };
}
async function extractFromEngagementFindings(opts) {
  const db = await getDb2();
  const limit = opts.limit || 200;
  const sources = { nuclei: 0, zap: 0, exploit: 0, protocol: 0, report: 0 };
  let total = 0;
  const existing = await db.select({ tags: bugBountyLlmTrainingSamples.tags }).from(bugBountyLlmTrainingSamples);
  const existingKeys = /* @__PURE__ */ new Set();
  for (const row of existing) {
    const t = row.tags;
    if (t) {
      const srcTag = t.find((x) => x.startsWith("src:"));
      if (srcTag) existingKeys.add(srcTag);
    }
  }
  const nuclei = await db.select().from(nucleiFindings).where(and(
    sql`(${nucleiFindings.verified} = 1 OR ${nucleiFindings.severity} IN ('critical', 'high'))`,
    sql`(${nucleiFindings.falsePositive} = 0 OR ${nucleiFindings.falsePositive} IS NULL)`
  )).orderBy(desc(nucleiFindings.createdAt)).limit(limit);
  for (const nf of nuclei) {
    if (total >= limit) break;
    const key = `src:nuclei:${nf.id}`;
    if (existingKeys.has(key)) continue;
    const isNovel = !nf.cveId;
    const cat = isNovel ? "novel_finding" : "vuln_pattern";
    const quality = computeQualityScore({ hasSummary: !!nf.description, hasCve: !!nf.cveId, hasCwe: !!nf.cweId, severity: nf.severity, bountyAmount: 0, hasExploit: !!nf.curlCommand, hasEvidence: !!nf.extractedResults, isNovel });
    const tags = ["engagement", "nuclei", key];
    if (isNovel) tags.push("novel", "unreported");
    await db.insert(bugBountyLlmTrainingSamples).values({
      category: cat,
      qualityScore: String(quality),
      bountyAmount: "0",
      severityRating: nf.severity,
      cweId: nf.cweId,
      cveIds: nf.cveId ? [nf.cveId] : null,
      assetIdentifier: nf.host,
      assetType: "URL",
      systemPrompt: SYSTEM_PROMPTS[cat],
      userPrompt: `Analyze this ${isNovel ? "potentially unreported" : "known"} vulnerability:

Template: ${nf.templateId}
Host: ${nf.host}
Severity: ${nf.severity}
${nf.cveId ? `CVE: ${nf.cveId}` : "No CVE (potentially novel)"}
${nf.cweId ? `CWE: ${nf.cweId}` : ""}
${nf.description || ""}
${nf.curlCommand ? `PoC: ${nf.curlCommand}` : ""}
${nf.extractedResults ? `Evidence: ${nf.extractedResults}` : ""}`,
      assistantResponse: `## ${isNovel ? "Novel " : ""}Finding: ${nf.templateName || nf.templateId}

**Severity:** ${(nf.severity || "unknown").toUpperCase()}
${nf.cveId ? `**CVE:** ${nf.cveId}` : "**CVE:** None \u2014 potentially unreported"}
${nf.cweId ? `**CWE:** ${nf.cweId}` : ""}
**Target:** ${nf.host}

### Analysis
${nf.description || "Vulnerability identified during penetration testing."}
${nf.curlCommand ? `
### Proof of Concept
\`\`\`
${nf.curlCommand}
\`\`\`` : ""}
${nf.extractedResults ? `
### Evidence
\`\`\`
${nf.extractedResults}
\`\`\`` : ""}
${isNovel ? "\n### Novelty Assessment\nNo CVE assigned. Consider responsible disclosure to vendor and bug bounty submission." : ""}

### Remediation
${nf.remediation || "Apply vendor patches and security hardening."}`,
      rawTitle: nf.templateName || nf.templateId,
      rawSummary: nf.description,
      enrichmentStatus: "raw",
      attackTechnique: nf.attackTechnique,
      tags
    });
    total++;
    sources.nuclei++;
  }
  const zap = await db.select().from(webAppFindings).where(or(sql`${webAppFindings.severity} IN ('High', 'Medium', 'critical', 'high')`, sql`${webAppFindings.attack} IS NOT NULL AND ${webAppFindings.attack} != ''`)).orderBy(desc(webAppFindings.createdAt)).limit(limit);
  for (const wf of zap) {
    if (total >= limit) break;
    const key = `src:zap:${wf.id}`;
    if (existingKeys.has(key)) continue;
    const cat = wf.attack ? "exploit_chain" : "vuln_pattern";
    const quality = computeQualityScore({ hasSummary: !!wf.description, hasCve: false, hasCwe: !!wf.cweId && wf.cweId !== 0, severity: wf.severity, bountyAmount: 0, hasExploit: !!wf.attack, hasEvidence: !!wf.evidence, isNovel: false });
    const tags = ["engagement", "zap", key];
    if (wf.mitreAttackId) tags.push(`mitre:${wf.mitreAttackId}`);
    await db.insert(bugBountyLlmTrainingSamples).values({
      category: cat,
      qualityScore: String(quality),
      bountyAmount: "0",
      severityRating: wf.severity,
      cweId: wf.cweId ? `CWE-${wf.cweId}` : null,
      assetIdentifier: wf.url,
      assetType: "URL",
      systemPrompt: SYSTEM_PROMPTS[cat],
      userPrompt: `Analyze this web vulnerability:

Alert: ${wf.alertName}
Severity: ${wf.severity}
URL: ${wf.url || "N/A"}
Method: ${wf.method || "N/A"}
Param: ${wf.param || "N/A"}
${wf.cweId ? `CWE: CWE-${wf.cweId}` : ""}
${wf.attack ? `Attack: ${wf.attack}` : ""}
${wf.evidence ? `Evidence: ${wf.evidence}` : ""}
${wf.mitreAttackId ? `MITRE: ${wf.mitreAttackId}` : ""}`,
      assistantResponse: `## Finding: ${wf.alertName}

**Severity:** ${(wf.severity || "unknown").toUpperCase()}
${wf.cweId ? `**CWE:** CWE-${wf.cweId}` : ""}
**URL:** ${wf.url || "N/A"}

### Analysis
${wf.description || "Web application vulnerability."}
${wf.attack ? `
### Attack Payload
\`\`\`
${wf.attack}
\`\`\`
${wf.param ? `**Parameter:** \`${wf.param}\`` : ""}` : ""}
${wf.evidence ? `
### Evidence
\`\`\`
${String(wf.evidence).slice(0, 500)}
\`\`\`` : ""}

### Remediation
${wf.solution || "Apply input validation and output encoding."}`,
      rawTitle: wf.alertName || "Web App Finding",
      rawSummary: wf.description,
      enrichmentStatus: "raw",
      mitreTechniques: wf.mitreAttackId ? [wf.mitreAttackId] : null,
      tags
    });
    total++;
    sources.zap++;
  }
  const exploits = await db.select().from(exploitationAttempts).where(eq(exploitationAttempts.eaStatus, "succeeded")).orderBy(desc(exploitationAttempts.eaCreatedAt)).limit(limit);
  for (const ea of exploits) {
    if (total >= limit) break;
    const key = `src:exploit:${ea.id}`;
    if (existingKeys.has(key)) continue;
    const isNovel = !ea.vulnerabilityCve;
    const cat = isNovel ? "novel_finding" : "exploit_chain";
    const sev = ea.eaAccessLevel === "root" || ea.eaAccessLevel === "system" ? "critical" : "high";
    const quality = computeQualityScore({ hasSummary: !!ea.resultOutput, hasCve: !!ea.vulnerabilityCve, hasCwe: false, severity: sev, bountyAmount: 0, hasExploit: true, hasEvidence: !!ea.resultOutput, isNovel });
    const tags = ["engagement", "exploit", "successful", key];
    if (ea.shellObtained) tags.push("shell_obtained");
    if (isNovel) tags.push("novel", "unreported");
    await db.insert(bugBountyLlmTrainingSamples).values({
      category: cat,
      qualityScore: String(quality),
      bountyAmount: "0",
      severityRating: sev,
      cveIds: ea.vulnerabilityCve ? [ea.vulnerabilityCve] : null,
      assetIdentifier: ea.targetHost,
      assetType: ea.targetService || "service",
      systemPrompt: SYSTEM_PROMPTS[cat],
      userPrompt: `Analyze this successful exploit:

Target: ${ea.targetHost}:${ea.targetPort || ""}
Service: ${ea.targetService || "N/A"}
Source: ${ea.exploitSource}
Module: ${ea.exploitModule || "N/A"}
${ea.vulnerabilityCve ? `CVE: ${ea.vulnerabilityCve}` : "No CVE (novel)"}
Result: ${ea.resultType || "N/A"}
Access: ${ea.eaAccessLevel || "N/A"}
Shell: ${ea.shellObtained ? "Yes" : "No"}
${ea.eaAttackTechnique ? `MITRE: ${ea.eaAttackTechnique}` : ""}
${ea.resultOutput ? `Output: ${String(ea.resultOutput).slice(0, 800)}` : ""}`,
      assistantResponse: `## Successful Exploit: ${ea.exploitModule || ea.exploitSource}

**Target:** ${ea.targetHost}:${ea.targetPort || ""}
**Access Level:** ${ea.eaAccessLevel || "N/A"}
**Shell:** ${ea.shellObtained ? "Yes" : "No"}
${ea.vulnerabilityCve ? `**CVE:** ${ea.vulnerabilityCve}` : "**CVE:** None \u2014 potentially novel"}

### Technique
${ea.exploitSource} module \`${ea.exploitModule || "N/A"}\` achieved ${ea.eaAccessLevel || "unknown"}-level access.
${ea.resultOutput ? `
### Output
\`\`\`
${String(ea.resultOutput).slice(0, 500)}
\`\`\`` : ""}
${isNovel ? "\n### Novelty\nNo CVE assigned. Document for responsible disclosure and bug bounty submission." : ""}

### Defensive Recommendations
1. Patch the affected service
2. Implement network segmentation
3. Deploy IDS signatures for this pattern`,
      rawTitle: `Exploit: ${ea.exploitModule || ea.exploitSource} \u2192 ${ea.targetHost}`,
      rawSummary: ea.resultOutput ? String(ea.resultOutput).slice(0, 500) : null,
      enrichmentStatus: "raw",
      attackTechnique: ea.eaAttackTechnique,
      mitreTechniques: ea.eaAttackTechnique ? [ea.eaAttackTechnique] : null,
      tags
    });
    total++;
    sources.exploit++;
  }
  const reports = await db.select().from(ac3ReportFindings).where(or(sql`${ac3ReportFindings.rfSeverity} IN ('critical', 'high', 'moderate')`, sql`${ac3ReportFindings.rfTechnicalDetails} IS NOT NULL`)).orderBy(desc(ac3ReportFindings.rfCreatedAt)).limit(limit);
  for (const rf of reports) {
    if (total >= limit) break;
    const key = `src:report:${rf.id}`;
    if (existingKeys.has(key)) continue;
    const quality = computeQualityScore({ hasSummary: !!rf.rfSummary, hasCve: !!rf.rfCvssScore, hasCwe: false, severity: rf.rfSeverity, bountyAmount: 0, hasExploit: false, hasEvidence: !!rf.rfEvidence, isNovel: false });
    const tags = ["engagement", "report", key];
    const attackTechniques = rf.rfAttackTechniques || [];
    const mitre = attackTechniques.map((t) => t.id).filter(Boolean);
    await db.insert(bugBountyLlmTrainingSamples).values({
      category: "report_template",
      qualityScore: String(quality),
      bountyAmount: "0",
      severityRating: rf.rfSeverity,
      systemPrompt: SYSTEM_PROMPTS.report_template,
      userPrompt: `Write a pentest finding report:

Title: ${rf.rfTitle}
Severity: ${rf.rfSeverity}
${rf.rfCvssScore ? `CVSS: ${rf.rfCvssScore}` : ""}
${rf.rfSummary || ""}
${rf.rfTechnicalDetails ? String(rf.rfTechnicalDetails).slice(0, 1500) : ""}
${rf.rfBusinessImpact || ""}`,
      assistantResponse: `## ${rf.rfTitle}

**Severity:** ${rf.rfSeverity?.toUpperCase()}${rf.rfCvssScore ? ` (CVSS ${rf.rfCvssScore})` : ""}

### Summary
${rf.rfSummary || rf.rfTitle}

### Technical Details
${rf.rfTechnicalDetails || "See evidence."}

### Business Impact
${rf.rfBusinessImpact || "Impacts confidentiality, integrity, or availability."}

### Remediation
${rf.rfRemediation || "Apply appropriate controls."}`,
      rawTitle: rf.rfTitle,
      rawSummary: rf.rfSummary,
      enrichmentStatus: "raw",
      mitreTechniques: mitre.length ? mitre : null,
      tags
    });
    total++;
    sources.report++;
  }
  return { extracted: total, sources };
}
async function generateScanForgeTemplatesFromFindings(opts) {
  const db = await getDb2();
  const limit = opts.limit || 50;
  const existingRefs = await db.select({ sourceReference: scanforgeGeneratedTemplates.sourceReference }).from(scanforgeGeneratedTemplates).where(eq(scanforgeGeneratedTemplates.generationSource, "bug_bounty"));
  const existingRefSet = new Set(existingRefs.map((r) => r.sourceReference));
  const severityOrder = ["critical", "high", "medium", "low", "none"];
  const minIdx = opts.minSeverity ? severityOrder.indexOf(opts.minSeverity) : severityOrder.length - 1;
  const allowedSeverities = severityOrder.slice(0, minIdx + 1);
  const findings = await db.select().from(bugBountyFindings).where(eq(bugBountyFindings.platform, "hackerone")).orderBy(desc(bugBountyFindings.awardedAmount)).limit(limit * 3);
  let generated = 0, skipped = 0, failed = 0;
  for (const f of findings) {
    if (generated >= limit) break;
    const ref = `h1:${f.externalId || f.id}`;
    if (existingRefSet.has(ref)) {
      skipped++;
      continue;
    }
    if (f.severityRating && !allowedSeverities.includes(f.severityRating)) {
      skipped++;
      continue;
    }
    try {
      const response = await invokeLLM({
        _caller: "bounty-training-engine.generateTemplates",
        messages: [
          {
            role: "system",
            content: `You are the ScanForge Detection Engineer. Given a disclosed bug bounty vulnerability, generate a detection template that can identify the same vulnerability pattern via network scanning.

Template JSON schema:
{
  "actionable": boolean,
  "reason": "why this is/isn't detectable via scanning",
  "template": {
    "templateId": "bb-<cwe>-<short-name>",
    "name": "Human-readable name",
    "description": "What this detects and how",
    "severity": "critical|high|medium|low|info",
    "category": "sqli|xss|rce|ssrf|lfi|auth|misconfig|exposure|cve|idor|csrf|logic",
    "detectionMethod": "How the template detects this",
    "requests": [{ "method": "GET|POST", "path": "/path", "headers": {}, "body": "" }],
    "matchers": [{ "type": "status|body|header|regex", "condition": "and|or", "values": ["match1"] }],
    "metadata": { "cve": "", "cwe": "", "cvss": 0, "references": [], "bountySource": "hackerone" }
  }
}

Only set actionable=true if the vulnerability pattern can be reliably detected via HTTP/TCP network scanning. Business logic flaws, race conditions, and account-specific issues are typically NOT actionable.`
          },
          {
            role: "user",
            content: `Generate a ScanForge detection template from this disclosed HackerOne vulnerability:

Title: ${f.title}
Severity: ${f.severityRating || "N/A"}
CWE: ${f.cweId || "N/A"}
CVEs: ${Array.isArray(f.cveIds) ? f.cveIds.join(", ") : "N/A"}
Asset: ${f.assetIdentifier || "N/A"} (${f.assetType || "N/A"})
Program: ${f.programName || f.programHandle || "N/A"}
Bounty: $${Number(f.awardedAmount) || 0}
Summary: ${f.summary || "No summary available"}
Report URL: ${f.reportUrl || "N/A"}

Analyze the vulnerability pattern and generate a generalizable detection template.`
          }
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "scanforge_template",
            strict: true,
            schema: {
              type: "object",
              properties: {
                actionable: { type: "boolean" },
                reason: { type: "string" },
                template: {
                  type: "object",
                  properties: {
                    templateId: { type: "string" },
                    name: { type: "string" },
                    description: { type: "string" },
                    severity: { type: "string" },
                    category: { type: "string" },
                    detectionMethod: { type: "string" },
                    requests: { type: "array", items: { type: "object", properties: { method: { type: "string" }, path: { type: "string" }, headers: { type: "object", additionalProperties: true }, body: { type: "string" } }, required: ["method", "path"], additionalProperties: false } },
                    matchers: { type: "array", items: { type: "object", properties: { type: { type: "string" }, condition: { type: "string" }, values: { type: "array", items: { type: "string" } } }, required: ["type", "condition", "values"], additionalProperties: false } },
                    metadata: { type: "object", properties: { cve: { type: "string" }, cwe: { type: "string" }, cvss: { type: "number" }, references: { type: "array", items: { type: "string" } }, bountySource: { type: "string" } }, required: ["references", "bountySource"], additionalProperties: false }
                  },
                  required: ["templateId", "name", "description", "severity", "category", "detectionMethod", "requests", "matchers", "metadata"],
                  additionalProperties: false
                }
              },
              required: ["actionable", "reason", "template"],
              additionalProperties: false
            }
          }
        },
        _priority: "bulk"
      });
      const content = response.choices?.[0]?.message?.content;
      if (!content) {
        failed++;
        continue;
      }
      const parsed = JSON.parse(content);
      if (!parsed.actionable) {
        skipped++;
        continue;
      }
      await db.insert(scanforgeGeneratedTemplates).values({
        templateId: parsed.template.templateId,
        name: parsed.template.name,
        generationSource: "bug_bounty",
        sourceReference: ref,
        templateData: parsed.template,
        status: "draft",
        generationConfidence: parsed.template.metadata?.cvss ? Math.min(0.95, parsed.template.metadata.cvss / 10) : 0.6
      });
      await db.insert(scanforgeResearchLog).values({
        feedSource: "hackerone",
        researchSubject: f.title,
        researchType: "bug_bounty_pattern",
        analysisResult: { finding: { title: f.title, severity: f.severityRating, cwe: f.cweId, bounty: Number(f.awardedAmount) }, template: parsed.template },
        generatedTemplateIds: [parsed.template.templateId],
        actionable: true
      });
      generated++;
    } catch (err) {
      console.error(`[BountyBridge] Template generation failed for finding ${f.id}:`, err.message);
      failed++;
    }
  }
  return { generated, skipped, failed };
}
async function getScanForgeBridgeStats() {
  const db = await getDb2();
  const [totalF] = await db.select({ count: sql`COUNT(*)` }).from(bugBountyFindings).where(eq(bugBountyFindings.platform, "hackerone"));
  const [totalT] = await db.select({ count: sql`COUNT(*)` }).from(scanforgeGeneratedTemplates).where(eq(scanforgeGeneratedTemplates.generationSource, "bug_bounty"));
  const statusRows = await db.select({ status: scanforgeGeneratedTemplates.status, count: sql`COUNT(*)` }).from(scanforgeGeneratedTemplates).where(eq(scanforgeGeneratedTemplates.generationSource, "bug_bounty")).groupBy(scanforgeGeneratedTemplates.status);
  const recent = await db.select({ templateId: scanforgeGeneratedTemplates.templateId, name: scanforgeGeneratedTemplates.name, status: scanforgeGeneratedTemplates.status, createdAt: scanforgeGeneratedTemplates.createdAt }).from(scanforgeGeneratedTemplates).where(eq(scanforgeGeneratedTemplates.generationSource, "bug_bounty")).orderBy(desc(scanforgeGeneratedTemplates.createdAt)).limit(10);
  return {
    totalFindings: totalF?.count || 0,
    templatesGenerated: totalT?.count || 0,
    templatesByStatus: Object.fromEntries(statusRows.map((r) => [r.status, r.count])),
    templatesBySeverity: {},
    topCwes: [],
    recentTemplates: recent
  };
}
async function enrichTrainingSamples(opts) {
  const db = await getDb2();
  const conditions = [eq(bugBountyLlmTrainingSamples.enrichmentStatus, "raw")];
  if (opts.category) conditions.push(eq(bugBountyLlmTrainingSamples.category, opts.category));
  const samples = await db.select().from(bugBountyLlmTrainingSamples).where(and(...conditions)).orderBy(desc(bugBountyLlmTrainingSamples.qualityScore)).limit(opts.limit || 20);
  let enriched = 0, failed = 0;
  for (const sample of samples) {
    try {
      const result = await invokeLLM({
        _caller: "bounty-training-engine.enrichSamples",
        messages: [
          { role: "system", content: `You are a cybersecurity training data curator. Produce JSON with: "enriched_narrative" (2-3 paragraph technical narrative), "attack_technique" (step-by-step discovery methodology for pentesting AI), "remediation_guidance" (specific actionable steps), "improved_response" (better assistant response for LLM training).` },
          { role: "user", content: `Enrich:

Category: ${sample.category}
Title: ${sample.rawTitle}
Severity: ${sample.severityRating}
CWE: ${sample.cweId || "N/A"}
Summary: ${sample.rawSummary || "N/A"}

Original response:
${sample.assistantResponse.slice(0, 2e3)}` }
        ],
        response_format: { type: "json_schema", json_schema: { name: "enrichment", strict: true, schema: { type: "object", properties: { enriched_narrative: { type: "string" }, attack_technique: { type: "string" }, remediation_guidance: { type: "string" }, improved_response: { type: "string" } }, required: ["enriched_narrative", "attack_technique", "remediation_guidance", "improved_response"], additionalProperties: false } } },
        _priority: "bulk"
      });
      const content = result.choices?.[0]?.message?.content;
      if (content && typeof content === "string") {
        const parsed = JSON.parse(content);
        await db.update(bugBountyLlmTrainingSamples).set({
          enrichmentStatus: "enriched",
          enrichedNarrative: parsed.enriched_narrative,
          attackTechnique: parsed.attack_technique,
          remediationGuidance: parsed.remediation_guidance,
          assistantResponse: parsed.improved_response || sample.assistantResponse
        }).where(eq(bugBountyLlmTrainingSamples.id, sample.id));
        enriched++;
      } else {
        failed++;
      }
    } catch {
      failed++;
    }
  }
  return { enriched, failed };
}
async function exportAsJSONL(opts) {
  const db = await getDb2();
  const conditions = [];
  if (opts.minQuality) conditions.push(sql`${bugBountyLlmTrainingSamples.qualityScore} >= ${opts.minQuality}`);
  if (opts.enrichedOnly) conditions.push(or(eq(bugBountyLlmTrainingSamples.enrichmentStatus, "enriched"), eq(bugBountyLlmTrainingSamples.enrichmentStatus, "reviewed")));
  const samples = await db.select().from(bugBountyLlmTrainingSamples).where(conditions.length ? and(...conditions) : void 0).orderBy(desc(bugBountyLlmTrainingSamples.qualityScore));
  const lines = [];
  const stats = {};
  for (const s of samples) {
    if (opts.categories && !opts.categories.includes(s.category)) continue;
    lines.push(JSON.stringify({ messages: [{ role: "system", content: s.systemPrompt }, { role: "user", content: s.userPrompt }, { role: "assistant", content: s.assistantResponse }] }));
    stats[s.category] = (stats[s.category] || 0) + 1;
    await db.update(bugBountyLlmTrainingSamples).set({ enrichmentStatus: "exported", exportedAt: (/* @__PURE__ */ new Date()).toISOString().slice(0, 19).replace("T", " ") }).where(eq(bugBountyLlmTrainingSamples.id, s.id));
  }
  return { lines, count: lines.length, stats };
}
async function getBountyROIAnalytics() {
  const db = await getDb2();
  const byCwe = await db.select({ cweId: bugBountyFindings.cweId, count: sql`COUNT(*)`, avgBounty: sql`COALESCE(AVG(${bugBountyFindings.awardedAmount}), 0)`, maxBounty: sql`COALESCE(MAX(${bugBountyFindings.awardedAmount}), 0)`, totalBounty: sql`COALESCE(SUM(${bugBountyFindings.awardedAmount}), 0)` }).from(bugBountyFindings).where(sql`${bugBountyFindings.cweId} IS NOT NULL AND ${bugBountyFindings.awardedAmount} > 0`).groupBy(bugBountyFindings.cweId).orderBy(sql`AVG(${bugBountyFindings.awardedAmount}) DESC`).limit(20);
  const byProgram = await db.select({ programHandle: bugBountyFindings.programHandle, programName: bugBountyFindings.programName, count: sql`COUNT(*)`, avgBounty: sql`COALESCE(AVG(${bugBountyFindings.awardedAmount}), 0)`, totalBounty: sql`COALESCE(SUM(${bugBountyFindings.awardedAmount}), 0)` }).from(bugBountyFindings).where(sql`${bugBountyFindings.programHandle} IS NOT NULL AND ${bugBountyFindings.awardedAmount} > 0`).groupBy(bugBountyFindings.programHandle, bugBountyFindings.programName).orderBy(sql`AVG(${bugBountyFindings.awardedAmount}) DESC`).limit(15);
  const bySeverity = await db.select({ severity: bugBountyFindings.severityRating, count: sql`COUNT(*)`, avgBounty: sql`COALESCE(AVG(${bugBountyFindings.awardedAmount}), 0)`, totalBounty: sql`COALESCE(SUM(${bugBountyFindings.awardedAmount}), 0)` }).from(bugBountyFindings).where(sql`${bugBountyFindings.severityRating} IS NOT NULL AND ${bugBountyFindings.awardedAmount} > 0`).groupBy(bugBountyFindings.severityRating).orderBy(sql`AVG(${bugBountyFindings.awardedAmount}) DESC`);
  return { byCwe, byProgram, bySeverity };
}
async function getTrainingStats() {
  const db = await getDb2();
  const [total] = await db.select({ count: sql`COUNT(*)` }).from(bugBountyLlmTrainingSamples);
  const categoryRows = await db.select({ category: bugBountyLlmTrainingSamples.category, count: sql`COUNT(*)` }).from(bugBountyLlmTrainingSamples).groupBy(bugBountyLlmTrainingSamples.category);
  const statusRows = await db.select({ status: bugBountyLlmTrainingSamples.enrichmentStatus, count: sql`COUNT(*)` }).from(bugBountyLlmTrainingSamples).groupBy(bugBountyLlmTrainingSamples.enrichmentStatus);
  const [avgQ] = await db.select({ avg: sql`COALESCE(AVG(${bugBountyLlmTrainingSamples.qualityScore}), 0)` }).from(bugBountyLlmTrainingSamples);
  const [novel] = await db.select({ count: sql`COUNT(*)` }).from(bugBountyLlmTrainingSamples).where(eq(bugBountyLlmTrainingSamples.category, "novel_finding"));
  const allTags = await db.select({ tags: bugBountyLlmTrainingSamples.tags }).from(bugBountyLlmTrainingSamples);
  let engagementSources = 0, hackeroneSources = 0;
  for (const row of allTags) {
    const t = row.tags;
    if (t?.includes("engagement")) engagementSources++;
    if (t?.includes("hackerone")) hackeroneSources++;
  }
  return {
    totalSamples: total?.count || 0,
    byCategory: Object.fromEntries(categoryRows.map((r) => [r.category, r.count])),
    byEnrichmentStatus: Object.fromEntries(statusRows.map((r) => [r.status, r.count])),
    avgQuality: avgQ?.avg || 0,
    novelFindings: novel?.count || 0,
    engagementSources,
    hackeroneSources
  };
}
function buildH1UserPrompt(category, f, bounty, cveList) {
  const base = `Title: ${f.title}
Severity: ${f.severityRating || "N/A"}
${f.cweId ? `CWE: ${f.cweId}` : ""}
${cveList.length ? `CVEs: ${cveList.join(", ")}` : ""}
Asset: ${f.assetIdentifier || "N/A"} (${f.assetType || "N/A"})
Program: ${f.programName || f.programHandle || "N/A"}
Bounty: $${bounty}
${f.summary ? `Summary: ${f.summary}` : ""}`;
  switch (category) {
    case "vuln_pattern":
      return `Analyze this disclosed vulnerability and explain how to discover similar issues:

${base}`;
    case "exploit_chain":
      return `Analyze this exploited vulnerability and explain the attack chain:

${base}`;
    case "cwe_analysis":
      return `Provide a deep CWE analysis:

${base}`;
    case "bounty_strategy":
      return `Analyze this high-value bounty for strategic insights:

${base}`;
    default:
      return `Analyze this vulnerability:

${base}`;
  }
}
function buildH1AssistantResponse(f, bounty, cveList) {
  return `## Analysis: ${f.title}

**Severity:** ${(f.severityRating || "unknown").toUpperCase()}
${f.cweId ? `**CWE:** ${f.cweId}` : ""}${cveList.length ? `
**CVEs:** ${cveList.join(", ")}` : ""}
**Asset:** ${f.assetIdentifier || "N/A"} (${f.assetType || "N/A"})
**Program:** ${f.programName || f.programHandle || "N/A"}
${bounty > 0 ? `**Bounty:** $${bounty.toLocaleString()}` : ""}

### Analysis
${f.summary || `${(f.severityRating || "").toUpperCase()}-severity vulnerability in ${f.assetIdentifier || "target"}.`}

### Discovery Methodology
1. Map the attack surface for ${f.assetType || "web"} assets
2. Test for ${f.cweId || "common vulnerability"} patterns
3. Verify with proof-of-concept

### Key Takeaways
- ${f.cweId || "This vulnerability class"} remains impactful
- ${bounty >= 5e3 ? "High" : "Moderate"} bounty indicates program values this finding type`;
}
export {
  enrichTrainingSamples,
  exportAsJSONL,
  extractFromEngagementFindings,
  extractFromHackerOneFindings,
  generateScanForgeTemplatesFromFindings,
  getBountyROIAnalytics,
  getScanForgeBridgeStats,
  getTrainingStats
};
