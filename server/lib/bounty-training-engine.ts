/**
 * Bounty Training Engine + ScanForge Bridge
 * 
 * Two interconnected pipelines:
 * 
 * 1. LLM TRAINING PIPELINE
 *    Extracts high-quality training samples from:
 *    - HackerOne disclosed findings (hacktivity)
 *    - AC3 engagement findings (Nuclei, ZAP, ScanForge, exploit attempts)
 *    - AC3 report findings (pentest reports with technical details)
 *    Each sample → OpenAI chat-format triple (system/user/assistant)
 * 
 * 2. SCANFORGE BRIDGE
 *    Converts ALL disclosed HackerOne vulnerabilities into ScanForge detection
 *    templates so the scanner actively looks for the same patterns.
 *    Disclosed vuln → LLM analysis → detection template → scanforge_generated_templates
 * 
 * Categories:
 *   vuln_pattern | exploit_chain | report_template | scope_recon
 *   cwe_analysis | bounty_strategy | novel_finding
 */

import { getDb as _getDb } from "../db";
import {
  bugBountyFindings,
  bugBountyLlmTrainingSamples,
  bugBountyPrograms,
  bugBountyProgramScopes,
  bugBountyProgramWeaknesses,
  nucleiFindings,
  webAppFindings,
  exploitationAttempts,
  protocolFindings,
  ac3ReportFindings,
  scanforgeGeneratedTemplates,
  scanforgeResearchLog,
} from "../../drizzle/schema";
import { eq, desc, sql, and, or, isNotNull, ne } from "drizzle-orm";
import { invokeLLM } from "../_core/llm";

async function getDb() {
  const db = await _getDb();
  return db!;
}

// ─── Types ───

export type TrainingCategory =
  | "vuln_pattern" | "exploit_chain" | "report_template" | "scope_recon"
  | "cwe_analysis" | "bounty_strategy" | "novel_finding";

// ─── Quality Scoring ───

function computeQualityScore(opts: {
  hasSummary: boolean; hasCve: boolean; hasCwe: boolean;
  severity: string | null; bountyAmount: number;
  hasExploit: boolean; hasEvidence: boolean; isNovel: boolean;
}): number {
  let score = 0.1;
  if (opts.hasSummary) score += 0.15;
  if (opts.hasCve) score += 0.10;
  if (opts.hasCwe) score += 0.10;
  if (opts.hasExploit) score += 0.15;
  if (opts.hasEvidence) score += 0.10;
  if (opts.isNovel) score += 0.20;
  if (opts.severity === "critical") score += 0.15;
  else if (opts.severity === "high") score += 0.10;
  else if (opts.severity === "medium") score += 0.05;
  if (opts.bountyAmount > 0) score += Math.min(0.10, Math.log10(opts.bountyAmount) / 50);
  return Math.min(0.99, Math.round(score * 100) / 100);
}

// ─── System Prompts by Category ───

const SYSTEM_PROMPTS: Record<TrainingCategory, string> = {
  vuln_pattern: `You are an expert penetration tester specializing in identifying security vulnerabilities in web applications, APIs, network services, and cloud infrastructure. You analyze target systems methodically, identify vulnerability patterns based on CWE classifications, and explain how to discover and verify each vulnerability class. Your analysis includes the technical root cause, exploitation prerequisites, and detection methodology.`,
  exploit_chain: `You are an advanced red team operator who specializes in chaining multiple vulnerabilities into complete attack paths. You understand how initial access vulnerabilities can be combined with privilege escalation, lateral movement, and data exfiltration techniques to achieve full compromise. You explain each step of the chain, the MITRE ATT&CK techniques involved, and the conditions required for successful exploitation.`,
  report_template: `You are a professional penetration test report writer who produces clear, actionable vulnerability reports for both technical and executive audiences. Your reports include precise technical details, proof-of-concept steps, business impact analysis, CVSS scoring rationale, and prioritized remediation guidance. You follow NIST 800-115 and OWASP reporting standards.`,
  scope_recon: `You are a reconnaissance specialist who analyzes bug bounty program scopes, identifies high-value targets within scope boundaries, and develops systematic testing strategies. You understand asset types (URLs, APIs, mobile apps, CIDR ranges), scope exclusions, and how to prioritize targets based on program history, bounty amounts, and attack surface complexity.`,
  cwe_analysis: `You are a vulnerability classification expert who deeply understands the Common Weakness Enumeration (CWE) taxonomy. You analyze vulnerability instances, map them to precise CWE identifiers, explain the root cause weakness pattern, identify related CWEs in the hierarchy, and describe detection techniques specific to each weakness class.`,
  bounty_strategy: `You are a bug bounty strategist who analyzes program data to optimize researcher ROI. You evaluate programs based on payout history, scope breadth, response time, vulnerability acceptance patterns, and competition level. You recommend which CWE categories, asset types, and testing methodologies yield the highest payouts per hour of research effort.`,
  novel_finding: `You are an elite vulnerability researcher who discovers zero-day and previously unreported vulnerabilities. You analyze systems for novel attack vectors that automated scanners miss, including business logic flaws, race conditions, authentication bypasses, and complex injection chains. You document your discovery methodology so it can be replicated on similar targets, and you assess whether the finding is reportable to the vendor or eligible for bug bounty submission.`,
};

// ═══════════════════════════════════════════════════════════════════════════
// PIPELINE 1: LLM TRAINING EXTRACTION
// ═══════════════════════════════════════════════════════════════════════════

export async function extractFromHackerOneFindings(opts: {
  minBounty?: number; minSeverity?: string; limit?: number;
}): Promise<{ extracted: number; skipped: number }> {
  const db = await getDb();
  const limit = opts.limit || 100;

  const existingIds = await db
    .select({ findingId: bugBountyLlmTrainingSamples.findingId })
    .from(bugBountyLlmTrainingSamples)
    .where(isNotNull(bugBountyLlmTrainingSamples.findingId));
  const existingSet = new Set(existingIds.map((r) => r.findingId));

  const findings = await db.select().from(bugBountyFindings)
    .where(and(eq(bugBountyFindings.platform, "hackerone"), sql`${bugBountyFindings.awardedAmount} >= ${opts.minBounty || 0}`))
    .orderBy(desc(bugBountyFindings.awardedAmount))
    .limit(limit * 2);

  let extracted = 0, skipped = 0;
  for (const f of findings) {
    if (extracted >= limit) break;
    if (existingSet.has(f.id)) { skipped++; continue; }

    const bounty = Number(f.awardedAmount) || 0;
    const hasCve = Array.isArray(f.cveIds) && f.cveIds.length > 0;
    const hasCwe = !!f.cweId;
    let category: TrainingCategory = "vuln_pattern";
    if (bounty >= 5000) category = "bounty_strategy";
    if (hasCwe) category = "cwe_analysis";
    if (hasCve && bounty >= 1000) category = "exploit_chain";

    const quality = computeQualityScore({
      hasSummary: !!f.summary, hasCve, hasCwe, severity: f.severityRating,
      bountyAmount: bounty, hasExploit: false, hasEvidence: !!f.summary, isNovel: false,
    });
    const cveList = (Array.isArray(f.cveIds) ? f.cveIds : []) as string[];
    const tags: string[] = ["hackerone", "disclosed"];
    if (hasCve) tags.push("has_cve");
    if (bounty >= 5000) tags.push("high_bounty");

    const systemPrompt = SYSTEM_PROMPTS[category];
    const userPrompt = buildH1UserPrompt(category, f, bounty, cveList);
    const assistantResponse = buildH1AssistantResponse(f, bounty, cveList);

    await db.insert(bugBountyLlmTrainingSamples).values({
      findingId: f.id, category, qualityScore: String(quality), bountyAmount: String(bounty),
      severityRating: f.severityRating, cweId: f.cweId, cveIds: cveList,
      programHandle: f.programHandle, programName: f.programName,
      assetType: f.assetType, assetIdentifier: f.assetIdentifier,
      systemPrompt, userPrompt, assistantResponse,
      rawTitle: f.title, rawSummary: f.summary, enrichmentStatus: "raw", tags,
    });
    extracted++;
  }
  return { extracted, skipped };
}

export async function extractFromEngagementFindings(opts: {
  engagementId?: number; limit?: number;
}): Promise<{ extracted: number; sources: Record<string, number> }> {
  const db = await getDb();
  const limit = opts.limit || 200;
  const sources: Record<string, number> = { nuclei: 0, zap: 0, exploit: 0, protocol: 0, report: 0 };
  let total = 0;

  // Existing keys to avoid duplicates
  const existing = await db.select({ tags: bugBountyLlmTrainingSamples.tags }).from(bugBountyLlmTrainingSamples);
  const existingKeys = new Set<string>();
  for (const row of existing) {
    const t = row.tags as string[] | null;
    if (t) { const srcTag = t.find((x) => x.startsWith("src:")); if (srcTag) existingKeys.add(srcTag); }
  }

  // 1. Nuclei findings — verified vulns
  const nuclei = await db.select().from(nucleiFindings)
    .where(and(sql`(${nucleiFindings.verified} = 1 OR ${nucleiFindings.severity} IN ('critical', 'high'))`,
      sql`(${nucleiFindings.falsePositive} = 0 OR ${nucleiFindings.falsePositive} IS NULL)`))
    .orderBy(desc(nucleiFindings.createdAt)).limit(limit);

  for (const nf of nuclei) {
    if (total >= limit) break;
    const key = `src:nuclei:${nf.id}`;
    if (existingKeys.has(key)) continue;
    const isNovel = !nf.cveId;
    const cat: TrainingCategory = isNovel ? "novel_finding" : "vuln_pattern";
    const quality = computeQualityScore({ hasSummary: !!nf.description, hasCve: !!nf.cveId, hasCwe: !!nf.cweId, severity: nf.severity, bountyAmount: 0, hasExploit: !!nf.curlCommand, hasEvidence: !!nf.extractedResults, isNovel });
    const tags = ["engagement", "nuclei", key]; if (isNovel) tags.push("novel", "unreported");
    await db.insert(bugBountyLlmTrainingSamples).values({
      category: cat, qualityScore: String(quality), bountyAmount: "0", severityRating: nf.severity,
      cweId: nf.cweId, cveIds: nf.cveId ? [nf.cveId] : null, assetIdentifier: nf.host, assetType: "URL",
      systemPrompt: SYSTEM_PROMPTS[cat],
      userPrompt: `Analyze this ${isNovel ? "potentially unreported" : "known"} vulnerability:\n\nTemplate: ${nf.templateId}\nHost: ${nf.host}\nSeverity: ${nf.severity}\n${nf.cveId ? `CVE: ${nf.cveId}` : "No CVE (potentially novel)"}\n${nf.cweId ? `CWE: ${nf.cweId}` : ""}\n${nf.description || ""}\n${nf.curlCommand ? `PoC: ${nf.curlCommand}` : ""}\n${nf.extractedResults ? `Evidence: ${nf.extractedResults}` : ""}`,
      assistantResponse: `## ${isNovel ? "Novel " : ""}Finding: ${nf.templateName || nf.templateId}\n\n**Severity:** ${(nf.severity || "unknown").toUpperCase()}\n${nf.cveId ? `**CVE:** ${nf.cveId}` : "**CVE:** None — potentially unreported"}\n${nf.cweId ? `**CWE:** ${nf.cweId}` : ""}\n**Target:** ${nf.host}\n\n### Analysis\n${nf.description || "Vulnerability identified during penetration testing."}\n${nf.curlCommand ? `\n### Proof of Concept\n\`\`\`\n${nf.curlCommand}\n\`\`\`` : ""}\n${nf.extractedResults ? `\n### Evidence\n\`\`\`\n${nf.extractedResults}\n\`\`\`` : ""}\n${isNovel ? "\n### Novelty Assessment\nNo CVE assigned. Consider responsible disclosure to vendor and bug bounty submission." : ""}\n\n### Remediation\n${nf.remediation || "Apply vendor patches and security hardening."}`,
      rawTitle: nf.templateName || nf.templateId, rawSummary: nf.description,
      enrichmentStatus: "raw", attackTechnique: nf.attackTechnique, tags,
    });
    total++; sources.nuclei++;
  }

  // 2. ZAP/Web App findings — with attack payloads
  const zap = await db.select().from(webAppFindings)
    .where(or(sql`${webAppFindings.severity} IN ('High', 'Medium', 'critical', 'high')`, sql`${webAppFindings.attack} IS NOT NULL AND ${webAppFindings.attack} != ''`))
    .orderBy(desc(webAppFindings.createdAt)).limit(limit);

  for (const wf of zap) {
    if (total >= limit) break;
    const key = `src:zap:${wf.id}`;
    if (existingKeys.has(key)) continue;
    const cat: TrainingCategory = wf.attack ? "exploit_chain" : "vuln_pattern";
    const quality = computeQualityScore({ hasSummary: !!wf.description, hasCve: false, hasCwe: !!wf.cweId && wf.cweId !== 0, severity: wf.severity, bountyAmount: 0, hasExploit: !!wf.attack, hasEvidence: !!wf.evidence, isNovel: false });
    const tags = ["engagement", "zap", key]; if (wf.mitreAttackId) tags.push(`mitre:${wf.mitreAttackId}`);
    await db.insert(bugBountyLlmTrainingSamples).values({
      category: cat, qualityScore: String(quality), bountyAmount: "0", severityRating: wf.severity,
      cweId: wf.cweId ? `CWE-${wf.cweId}` : null, assetIdentifier: wf.url, assetType: "URL",
      systemPrompt: SYSTEM_PROMPTS[cat],
      userPrompt: `Analyze this web vulnerability:\n\nAlert: ${wf.alertName}\nSeverity: ${wf.severity}\nURL: ${wf.url || "N/A"}\nMethod: ${wf.method || "N/A"}\nParam: ${wf.param || "N/A"}\n${wf.cweId ? `CWE: CWE-${wf.cweId}` : ""}\n${wf.attack ? `Attack: ${wf.attack}` : ""}\n${wf.evidence ? `Evidence: ${wf.evidence}` : ""}\n${wf.mitreAttackId ? `MITRE: ${wf.mitreAttackId}` : ""}`,
      assistantResponse: `## Finding: ${wf.alertName}\n\n**Severity:** ${(wf.severity || "unknown").toUpperCase()}\n${wf.cweId ? `**CWE:** CWE-${wf.cweId}` : ""}\n**URL:** ${wf.url || "N/A"}\n\n### Analysis\n${wf.description || "Web application vulnerability."}\n${wf.attack ? `\n### Attack Payload\n\`\`\`\n${wf.attack}\n\`\`\`\n${wf.param ? `**Parameter:** \`${wf.param}\`` : ""}` : ""}\n${wf.evidence ? `\n### Evidence\n\`\`\`\n${String(wf.evidence).slice(0, 500)}\n\`\`\`` : ""}\n\n### Remediation\n${wf.solution || "Apply input validation and output encoding."}`,
      rawTitle: wf.alertName || "Web App Finding", rawSummary: wf.description,
      enrichmentStatus: "raw", mitreTechniques: wf.mitreAttackId ? [wf.mitreAttackId] : null, tags,
    });
    total++; sources.zap++;
  }

  // 3. Successful exploitation attempts — highest value
  const exploits = await db.select().from(exploitationAttempts)
    .where(eq(exploitationAttempts.eaStatus, "succeeded"))
    .orderBy(desc(exploitationAttempts.eaCreatedAt)).limit(limit);

  for (const ea of exploits) {
    if (total >= limit) break;
    const key = `src:exploit:${ea.id}`;
    if (existingKeys.has(key)) continue;
    const isNovel = !ea.vulnerabilityCve;
    const cat: TrainingCategory = isNovel ? "novel_finding" : "exploit_chain";
    const sev = ea.eaAccessLevel === "root" || ea.eaAccessLevel === "system" ? "critical" : "high";
    const quality = computeQualityScore({ hasSummary: !!ea.resultOutput, hasCve: !!ea.vulnerabilityCve, hasCwe: false, severity: sev, bountyAmount: 0, hasExploit: true, hasEvidence: !!ea.resultOutput, isNovel });
    const tags = ["engagement", "exploit", "successful", key]; if (ea.shellObtained) tags.push("shell_obtained"); if (isNovel) tags.push("novel", "unreported");
    await db.insert(bugBountyLlmTrainingSamples).values({
      category: cat, qualityScore: String(quality), bountyAmount: "0", severityRating: sev,
      cveIds: ea.vulnerabilityCve ? [ea.vulnerabilityCve] : null,
      assetIdentifier: ea.targetHost, assetType: ea.targetService || "service",
      systemPrompt: SYSTEM_PROMPTS[cat],
      userPrompt: `Analyze this successful exploit:\n\nTarget: ${ea.targetHost}:${ea.targetPort || ""}\nService: ${ea.targetService || "N/A"}\nSource: ${ea.exploitSource}\nModule: ${ea.exploitModule || "N/A"}\n${ea.vulnerabilityCve ? `CVE: ${ea.vulnerabilityCve}` : "No CVE (novel)"}\nResult: ${ea.resultType || "N/A"}\nAccess: ${ea.eaAccessLevel || "N/A"}\nShell: ${ea.shellObtained ? "Yes" : "No"}\n${ea.eaAttackTechnique ? `MITRE: ${ea.eaAttackTechnique}` : ""}\n${ea.resultOutput ? `Output: ${String(ea.resultOutput).slice(0, 800)}` : ""}`,
      assistantResponse: `## Successful Exploit: ${ea.exploitModule || ea.exploitSource}\n\n**Target:** ${ea.targetHost}:${ea.targetPort || ""}\n**Access Level:** ${ea.eaAccessLevel || "N/A"}\n**Shell:** ${ea.shellObtained ? "Yes" : "No"}\n${ea.vulnerabilityCve ? `**CVE:** ${ea.vulnerabilityCve}` : "**CVE:** None — potentially novel"}\n\n### Technique\n${ea.exploitSource} module \`${ea.exploitModule || "N/A"}\` achieved ${ea.eaAccessLevel || "unknown"}-level access.\n${ea.resultOutput ? `\n### Output\n\`\`\`\n${String(ea.resultOutput).slice(0, 500)}\n\`\`\`` : ""}\n${isNovel ? "\n### Novelty\nNo CVE assigned. Document for responsible disclosure and bug bounty submission." : ""}\n\n### Defensive Recommendations\n1. Patch the affected service\n2. Implement network segmentation\n3. Deploy IDS signatures for this pattern`,
      rawTitle: `Exploit: ${ea.exploitModule || ea.exploitSource} → ${ea.targetHost}`,
      rawSummary: ea.resultOutput ? String(ea.resultOutput).slice(0, 500) : null,
      enrichmentStatus: "raw", attackTechnique: ea.eaAttackTechnique,
      mitreTechniques: ea.eaAttackTechnique ? [ea.eaAttackTechnique] : null, tags,
    });
    total++; sources.exploit++;
  }

  // 4. AC3 Report findings — richest data
  const reports = await db.select().from(ac3ReportFindings)
    .where(or(sql`${ac3ReportFindings.rfSeverity} IN ('critical', 'high', 'moderate')`, sql`${ac3ReportFindings.rfTechnicalDetails} IS NOT NULL`))
    .orderBy(desc(ac3ReportFindings.rfCreatedAt)).limit(limit);

  for (const rf of reports) {
    if (total >= limit) break;
    const key = `src:report:${rf.id}`;
    if (existingKeys.has(key)) continue;
    const quality = computeQualityScore({ hasSummary: !!rf.rfSummary, hasCve: !!rf.rfCvssScore, hasCwe: false, severity: rf.rfSeverity, bountyAmount: 0, hasExploit: false, hasEvidence: !!rf.rfEvidence, isNovel: false });
    const tags = ["engagement", "report", key];
    const attackTechniques = (rf.rfAttackTechniques as Array<{ id?: string; name?: string }>) || [];
    const mitre = attackTechniques.map((t) => t.id).filter(Boolean) as string[];
    await db.insert(bugBountyLlmTrainingSamples).values({
      category: "report_template", qualityScore: String(quality), bountyAmount: "0",
      severityRating: rf.rfSeverity, systemPrompt: SYSTEM_PROMPTS.report_template,
      userPrompt: `Write a pentest finding report:\n\nTitle: ${rf.rfTitle}\nSeverity: ${rf.rfSeverity}\n${rf.rfCvssScore ? `CVSS: ${rf.rfCvssScore}` : ""}\n${rf.rfSummary || ""}\n${rf.rfTechnicalDetails ? String(rf.rfTechnicalDetails).slice(0, 1500) : ""}\n${rf.rfBusinessImpact || ""}`,
      assistantResponse: `## ${rf.rfTitle}\n\n**Severity:** ${rf.rfSeverity?.toUpperCase()}${rf.rfCvssScore ? ` (CVSS ${rf.rfCvssScore})` : ""}\n\n### Summary\n${rf.rfSummary || rf.rfTitle}\n\n### Technical Details\n${rf.rfTechnicalDetails || "See evidence."}\n\n### Business Impact\n${rf.rfBusinessImpact || "Impacts confidentiality, integrity, or availability."}\n\n### Remediation\n${rf.rfRemediation || "Apply appropriate controls."}`,
      rawTitle: rf.rfTitle, rawSummary: rf.rfSummary,
      enrichmentStatus: "raw", mitreTechniques: mitre.length ? mitre : null, tags,
    });
    total++; sources.report++;
  }

  return { extracted: total, sources };
}

// ═══════════════════════════════════════════════════════════════════════════
// PIPELINE 2: SCANFORGE BRIDGE — Disclosed Vulns → Detection Templates
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Convert ALL disclosed HackerOne findings into ScanForge detection templates.
 * Uses LLM to analyze each finding and generate a network-detectable template.
 */
export async function generateScanForgeTemplatesFromFindings(opts: {
  limit?: number;
  minSeverity?: string;
}): Promise<{ generated: number; skipped: number; failed: number }> {
  const db = await getDb();
  const limit = opts.limit || 50;

  // Get findings not yet converted to templates
  const existingRefs = await db.select({ sourceReference: scanforgeGeneratedTemplates.sourceReference })
    .from(scanforgeGeneratedTemplates)
    .where(eq(scanforgeGeneratedTemplates.generationSource, "bug_bounty"));
  const existingRefSet = new Set(existingRefs.map(r => r.sourceReference));

  const severityOrder = ["critical", "high", "medium", "low", "none"];
  const minIdx = opts.minSeverity ? severityOrder.indexOf(opts.minSeverity) : severityOrder.length - 1;
  const allowedSeverities = severityOrder.slice(0, minIdx + 1);

  const findings = await db.select().from(bugBountyFindings)
    .where(eq(bugBountyFindings.platform, "hackerone"))
    .orderBy(desc(bugBountyFindings.awardedAmount))
    .limit(limit * 3);

  let generated = 0, skipped = 0, failed = 0;

  for (const f of findings) {
    if (generated >= limit) break;
    const ref = `h1:${f.externalId || f.id}`;
    if (existingRefSet.has(ref)) { skipped++; continue; }
    if (f.severityRating && !allowedSeverities.includes(f.severityRating)) { skipped++; continue; }

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

Only set actionable=true if the vulnerability pattern can be reliably detected via HTTP/TCP network scanning. Business logic flaws, race conditions, and account-specific issues are typically NOT actionable.`,
          },
          {
            role: "user",
            content: `Generate a ScanForge detection template from this disclosed HackerOne vulnerability:

Title: ${f.title}
Severity: ${f.severityRating || "N/A"}
CWE: ${f.cweId || "N/A"}
CVEs: ${Array.isArray(f.cveIds) ? (f.cveIds as string[]).join(", ") : "N/A"}
Asset: ${f.assetIdentifier || "N/A"} (${f.assetType || "N/A"})
Program: ${f.programName || f.programHandle || "N/A"}
Bounty: $${Number(f.awardedAmount) || 0}
Summary: ${f.summary || "No summary available"}
Report URL: ${f.reportUrl || "N/A"}

Analyze the vulnerability pattern and generate a generalizable detection template.`,
          },
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
                    metadata: { type: "object", properties: { cve: { type: "string" }, cwe: { type: "string" }, cvss: { type: "number" }, references: { type: "array", items: { type: "string" } }, bountySource: { type: "string" } }, required: ["references", "bountySource"], additionalProperties: false },
                  },
                  required: ["templateId", "name", "description", "severity", "category", "detectionMethod", "requests", "matchers", "metadata"],
                  additionalProperties: false,
                },
              },
              required: ["actionable", "reason", "template"],
              additionalProperties: false,
            },
          },
        },
        _priority: "bulk",
      });

      const content = response.choices?.[0]?.message?.content;
      if (!content) { failed++; continue; }

      const parsed = JSON.parse(content);
      if (!parsed.actionable) { skipped++; continue; }

      // Store in scanforge_generated_templates
      await db.insert(scanforgeGeneratedTemplates).values({
        templateId: parsed.template.templateId,
        name: parsed.template.name,
        generationSource: "bug_bounty",
        sourceReference: ref,
        templateData: parsed.template,
        status: "draft",
        generationConfidence: parsed.template.metadata?.cvss ? Math.min(0.95, parsed.template.metadata.cvss / 10) : 0.6,
      });

      // Log the research
      await db.insert(scanforgeResearchLog).values({
        feedSource: "hackerone",
        researchSubject: f.title,
        researchType: "bug_bounty_pattern",
        analysisResult: { finding: { title: f.title, severity: f.severityRating, cwe: f.cweId, bounty: Number(f.awardedAmount) }, template: parsed.template },
        generatedTemplateIds: [parsed.template.templateId],
        actionable: true,
      });

      generated++;
    } catch (err) {
      console.error(`[BountyBridge] Template generation failed for finding ${f.id}:`, (err as Error).message);
      failed++;
    }
  }

  return { generated, skipped, failed };
}

/**
 * Get bridge stats — how many findings have been converted to templates.
 */
export async function getScanForgeBridgeStats(): Promise<{
  totalFindings: number;
  templatesGenerated: number;
  templatesByStatus: Record<string, number>;
  templatesBySeverity: Record<string, number>;
  topCwes: Array<{ cwe: string; count: number }>;
  recentTemplates: Array<{ templateId: string; name: string; status: string; createdAt: string }>;
}> {
  const db = await getDb();

  const [totalF] = await db.select({ count: sql<number>`COUNT(*)` }).from(bugBountyFindings).where(eq(bugBountyFindings.platform, "hackerone"));
  const [totalT] = await db.select({ count: sql<number>`COUNT(*)` }).from(scanforgeGeneratedTemplates).where(eq(scanforgeGeneratedTemplates.generationSource, "bug_bounty"));

  const statusRows = await db.select({ status: scanforgeGeneratedTemplates.status, count: sql<number>`COUNT(*)` })
    .from(scanforgeGeneratedTemplates).where(eq(scanforgeGeneratedTemplates.generationSource, "bug_bounty"))
    .groupBy(scanforgeGeneratedTemplates.status);

  const recent = await db.select({ templateId: scanforgeGeneratedTemplates.templateId, name: scanforgeGeneratedTemplates.name, status: scanforgeGeneratedTemplates.status, createdAt: scanforgeGeneratedTemplates.createdAt })
    .from(scanforgeGeneratedTemplates).where(eq(scanforgeGeneratedTemplates.generationSource, "bug_bounty"))
    .orderBy(desc(scanforgeGeneratedTemplates.createdAt)).limit(10);

  return {
    totalFindings: totalF?.count || 0,
    templatesGenerated: totalT?.count || 0,
    templatesByStatus: Object.fromEntries(statusRows.map(r => [r.status, r.count])),
    templatesBySeverity: {},
    topCwes: [],
    recentTemplates: recent as any,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// LLM ENRICHMENT
// ═══════════════════════════════════════════════════════════════════════════

export async function enrichTrainingSamples(opts: {
  limit?: number; category?: TrainingCategory;
}): Promise<{ enriched: number; failed: number }> {
  const db = await getDb();
  const conditions: any[] = [eq(bugBountyLlmTrainingSamples.enrichmentStatus, "raw")];
  if (opts.category) conditions.push(eq(bugBountyLlmTrainingSamples.category, opts.category));

  const samples = await db.select().from(bugBountyLlmTrainingSamples)
    .where(and(...conditions)).orderBy(desc(bugBountyLlmTrainingSamples.qualityScore))
    .limit(opts.limit || 20);

  let enriched = 0, failed = 0;
  for (const sample of samples) {
    try {
      const result = await invokeLLM({
        _caller: "bounty-training-engine.enrichSamples",
        messages: [
          { role: "system", content: `You are a cybersecurity training data curator. Produce JSON with: "enriched_narrative" (2-3 paragraph technical narrative), "attack_technique" (step-by-step discovery methodology for pentesting AI), "remediation_guidance" (specific actionable steps), "improved_response" (better assistant response for LLM training).` },
          { role: "user", content: `Enrich:\n\nCategory: ${sample.category}\nTitle: ${sample.rawTitle}\nSeverity: ${sample.severityRating}\nCWE: ${sample.cweId || "N/A"}\nSummary: ${sample.rawSummary || "N/A"}\n\nOriginal response:\n${sample.assistantResponse.slice(0, 2000)}` },
        ],
        response_format: { type: "json_schema", json_schema: { name: "enrichment", strict: true, schema: { type: "object", properties: { enriched_narrative: { type: "string" }, attack_technique: { type: "string" }, remediation_guidance: { type: "string" }, improved_response: { type: "string" } }, required: ["enriched_narrative", "attack_technique", "remediation_guidance", "improved_response"], additionalProperties: false } } },
        _priority: "bulk",
      });
      const content = result.choices?.[0]?.message?.content;
      if (content && typeof content === "string") {
        const parsed = JSON.parse(content);
        await db.update(bugBountyLlmTrainingSamples).set({
          enrichmentStatus: "enriched", enrichedNarrative: parsed.enriched_narrative,
          attackTechnique: parsed.attack_technique, remediationGuidance: parsed.remediation_guidance,
          assistantResponse: parsed.improved_response || sample.assistantResponse,
        }).where(eq(bugBountyLlmTrainingSamples.id, sample.id));
        enriched++;
      } else { failed++; }
    } catch { failed++; }
  }
  return { enriched, failed };
}

// ═══════════════════════════════════════════════════════════════════════════
// JSONL EXPORT
// ═══════════════════════════════════════════════════════════════════════════

export async function exportAsJSONL(opts: {
  minQuality?: number; categories?: TrainingCategory[]; enrichedOnly?: boolean;
}): Promise<{ lines: string[]; count: number; stats: Record<string, number> }> {
  const db = await getDb();
  const conditions: any[] = [];
  if (opts.minQuality) conditions.push(sql`${bugBountyLlmTrainingSamples.qualityScore} >= ${opts.minQuality}`);
  if (opts.enrichedOnly) conditions.push(or(eq(bugBountyLlmTrainingSamples.enrichmentStatus, "enriched"), eq(bugBountyLlmTrainingSamples.enrichmentStatus, "reviewed")));

  const samples = await db.select().from(bugBountyLlmTrainingSamples)
    .where(conditions.length ? and(...conditions) : undefined)
    .orderBy(desc(bugBountyLlmTrainingSamples.qualityScore));

  const lines: string[] = [];
  const stats: Record<string, number> = {};
  for (const s of samples) {
    if (opts.categories && !opts.categories.includes(s.category as TrainingCategory)) continue;
    lines.push(JSON.stringify({ messages: [{ role: "system", content: s.systemPrompt }, { role: "user", content: s.userPrompt }, { role: "assistant", content: s.assistantResponse }] }));
    stats[s.category] = (stats[s.category] || 0) + 1;
    await db.update(bugBountyLlmTrainingSamples).set({ enrichmentStatus: "exported", exportedAt: new Date().toISOString().slice(0, 19).replace("T", " ") }).where(eq(bugBountyLlmTrainingSamples.id, s.id));
  }
  return { lines, count: lines.length, stats };
}

// ═══════════════════════════════════════════════════════════════════════════
// ANALYTICS
// ═══════════════════════════════════════════════════════════════════════════

export async function getBountyROIAnalytics() {
  const db = await getDb();
  const byCwe = await db.select({ cweId: bugBountyFindings.cweId, count: sql<number>`COUNT(*)`, avgBounty: sql<number>`COALESCE(AVG(${bugBountyFindings.awardedAmount}), 0)`, maxBounty: sql<number>`COALESCE(MAX(${bugBountyFindings.awardedAmount}), 0)`, totalBounty: sql<number>`COALESCE(SUM(${bugBountyFindings.awardedAmount}), 0)` })
    .from(bugBountyFindings).where(sql`${bugBountyFindings.cweId} IS NOT NULL AND ${bugBountyFindings.awardedAmount} > 0`)
    .groupBy(bugBountyFindings.cweId).orderBy(sql`AVG(${bugBountyFindings.awardedAmount}) DESC`).limit(20);

  const byProgram = await db.select({ programHandle: bugBountyFindings.programHandle, programName: bugBountyFindings.programName, count: sql<number>`COUNT(*)`, avgBounty: sql<number>`COALESCE(AVG(${bugBountyFindings.awardedAmount}), 0)`, totalBounty: sql<number>`COALESCE(SUM(${bugBountyFindings.awardedAmount}), 0)` })
    .from(bugBountyFindings).where(sql`${bugBountyFindings.programHandle} IS NOT NULL AND ${bugBountyFindings.awardedAmount} > 0`)
    .groupBy(bugBountyFindings.programHandle, bugBountyFindings.programName).orderBy(sql`AVG(${bugBountyFindings.awardedAmount}) DESC`).limit(15);

  const bySeverity = await db.select({ severity: bugBountyFindings.severityRating, count: sql<number>`COUNT(*)`, avgBounty: sql<number>`COALESCE(AVG(${bugBountyFindings.awardedAmount}), 0)`, totalBounty: sql<number>`COALESCE(SUM(${bugBountyFindings.awardedAmount}), 0)` })
    .from(bugBountyFindings).where(sql`${bugBountyFindings.severityRating} IS NOT NULL AND ${bugBountyFindings.awardedAmount} > 0`)
    .groupBy(bugBountyFindings.severityRating).orderBy(sql`AVG(${bugBountyFindings.awardedAmount}) DESC`);

  return { byCwe, byProgram, bySeverity };
}

export async function getTrainingStats() {
  const db = await getDb();
  const [total] = await db.select({ count: sql<number>`COUNT(*)` }).from(bugBountyLlmTrainingSamples);
  const categoryRows = await db.select({ category: bugBountyLlmTrainingSamples.category, count: sql<number>`COUNT(*)` }).from(bugBountyLlmTrainingSamples).groupBy(bugBountyLlmTrainingSamples.category);
  const statusRows = await db.select({ status: bugBountyLlmTrainingSamples.enrichmentStatus, count: sql<number>`COUNT(*)` }).from(bugBountyLlmTrainingSamples).groupBy(bugBountyLlmTrainingSamples.enrichmentStatus);
  const [avgQ] = await db.select({ avg: sql<number>`COALESCE(AVG(${bugBountyLlmTrainingSamples.qualityScore}), 0)` }).from(bugBountyLlmTrainingSamples);
  const [novel] = await db.select({ count: sql<number>`COUNT(*)` }).from(bugBountyLlmTrainingSamples).where(eq(bugBountyLlmTrainingSamples.category, "novel_finding"));

  const allTags = await db.select({ tags: bugBountyLlmTrainingSamples.tags }).from(bugBountyLlmTrainingSamples);
  let engagementSources = 0, hackeroneSources = 0;
  for (const row of allTags) {
    const t = row.tags as string[] | null;
    if (t?.includes("engagement")) engagementSources++;
    if (t?.includes("hackerone")) hackeroneSources++;
  }

  return {
    totalSamples: total?.count || 0,
    byCategory: Object.fromEntries(categoryRows.map(r => [r.category, r.count])),
    byEnrichmentStatus: Object.fromEntries(statusRows.map(r => [r.status, r.count])),
    avgQuality: avgQ?.avg || 0,
    novelFindings: novel?.count || 0,
    engagementSources, hackeroneSources,
  };
}

// ─── Prompt Builders (H1) ───

function buildH1UserPrompt(category: TrainingCategory, f: any, bounty: number, cveList: string[]): string {
  const base = `Title: ${f.title}\nSeverity: ${f.severityRating || "N/A"}\n${f.cweId ? `CWE: ${f.cweId}` : ""}\n${cveList.length ? `CVEs: ${cveList.join(", ")}` : ""}\nAsset: ${f.assetIdentifier || "N/A"} (${f.assetType || "N/A"})\nProgram: ${f.programName || f.programHandle || "N/A"}\nBounty: $${bounty}\n${f.summary ? `Summary: ${f.summary}` : ""}`;
  switch (category) {
    case "vuln_pattern": return `Analyze this disclosed vulnerability and explain how to discover similar issues:\n\n${base}`;
    case "exploit_chain": return `Analyze this exploited vulnerability and explain the attack chain:\n\n${base}`;
    case "cwe_analysis": return `Provide a deep CWE analysis:\n\n${base}`;
    case "bounty_strategy": return `Analyze this high-value bounty for strategic insights:\n\n${base}`;
    default: return `Analyze this vulnerability:\n\n${base}`;
  }
}

function buildH1AssistantResponse(f: any, bounty: number, cveList: string[]): string {
  return `## Analysis: ${f.title}\n\n**Severity:** ${(f.severityRating || "unknown").toUpperCase()}\n${f.cweId ? `**CWE:** ${f.cweId}` : ""}${cveList.length ? `\n**CVEs:** ${cveList.join(", ")}` : ""}\n**Asset:** ${f.assetIdentifier || "N/A"} (${f.assetType || "N/A"})\n**Program:** ${f.programName || f.programHandle || "N/A"}\n${bounty > 0 ? `**Bounty:** $${bounty.toLocaleString()}` : ""}\n\n### Analysis\n${f.summary || `${(f.severityRating || "").toUpperCase()}-severity vulnerability in ${f.assetIdentifier || "target"}.`}\n\n### Discovery Methodology\n1. Map the attack surface for ${f.assetType || "web"} assets\n2. Test for ${f.cweId || "common vulnerability"} patterns\n3. Verify with proof-of-concept\n\n### Key Takeaways\n- ${f.cweId || "This vulnerability class"} remains impactful\n- ${bounty >= 5000 ? "High" : "Moderate"} bounty indicates program values this finding type`;
}
