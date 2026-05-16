import {
  init_llm
} from "./chunk-TCEHBLTC.js";
import {
  getDbRequired,
  init_db
} from "./chunk-L5ZLWR7T.js";
import {
  init_schema,
  scanforgeEngagementReport,
  scanforgeFindingLog,
  scanforgeGeneratedTemplates,
  scanforgePromotionHistory,
  scanforgeResearchLog,
  scanforgeTemplateMetrics
} from "./chunk-L4JENJ4Z.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// shared/domain-safety-whitelist.ts
function isSourceCodeTarget(target) {
  const hostname = extractHostname(target);
  const isSourceCode = SOURCE_CODE_HOSTS.some((h) => hostname === h || hostname.endsWith(`.${h}`));
  if (isSourceCode) {
    const repoUrl = target.includes("://") ? target : `https://${target}`;
    return { isSourceCode: true, repoUrl, host: hostname };
  }
  return { isSourceCode: false };
}
function extractHostname(target) {
  let cleaned = target.trim();
  if (cleaned.includes("://")) {
    try {
      const url = new URL(cleaned);
      cleaned = url.hostname;
    } catch {
      cleaned = cleaned.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
    }
  } else {
    cleaned = cleaned.split("/")[0].split(":")[0];
  }
  return cleaned.toLowerCase();
}
function isDomainWhitelisted(target) {
  const hostname = extractHostname(target);
  if (!hostname) return false;
  if (SAFE_PRIVATE_PATTERNS.some((p) => p.test(hostname))) return true;
  if (WHITELISTED_IPS.includes(hostname)) return true;
  for (const whitelisted of WHITELISTED_DOMAINS) {
    if (hostname === whitelisted || hostname.endsWith(`.${whitelisted}`)) {
      return true;
    }
  }
  return false;
}
function parseTargets(targetString) {
  if (!targetString) return [];
  return targetString.split(/[,;\s]+/).map((t) => t.trim()).filter(Boolean);
}
function validateEngagementTargets(targetDomain, targetIpRange) {
  const allTargets = [];
  for (const t of parseTargets(targetDomain || "")) {
    const hostname = extractHostname(t);
    allTargets.push({ original: t, hostname, whitelisted: isDomainWhitelisted(t) });
  }
  for (const t of parseTargets(targetIpRange || "")) {
    const hostname = extractHostname(t);
    allTargets.push({ original: t, hostname, whitelisted: isDomainWhitelisted(t) });
  }
  const whitelisted = allTargets.filter((t) => t.whitelisted);
  const nonWhitelisted = allTargets.filter((t) => !t.whitelisted);
  return {
    allWhitelisted: nonWhitelisted.length === 0 && allTargets.length > 0,
    totalTargets: allTargets.length,
    whitelistedCount: whitelisted.length,
    nonWhitelistedCount: nonWhitelisted.length,
    targets: allTargets,
    nonWhitelistedTargets: nonWhitelisted.map((t) => t.hostname)
  };
}
function getSafetyWarning(validation) {
  if (validation.allWhitelisted) return null;
  if (validation.totalTargets === 0) return null;
  const nonWL = validation.nonWhitelistedTargets;
  return `\u26A0\uFE0F SAFETY GUARDRAIL: ${nonWL.length} target(s) are NOT on the approved test lab whitelist: ${nonWL.join(", ")}. Active scanning, exploitation, and C2 operations are BLOCKED for non-whitelisted domains. Only passive reconnaissance (OSINT, DNS, certificate transparency) is permitted. An admin can override this restriction if a signed RoE authorizes active testing on these targets.`;
}
var WHITELISTED_DOMAINS, SOURCE_CODE_HOSTS, WHITELISTED_IPS, SAFE_PRIVATE_PATTERNS;
var init_domain_safety_whitelist = __esm({
  "shared/domain-safety-whitelist.ts"() {
    "use strict";
    WHITELISTED_DOMAINS = [
      // AC3-owned test lab infrastructure
      "scan.aceofcloud.io",
      "aceofcloud.io",
      "aceofcloud.com",
      // Public intentionally-vulnerable web applications
      "testphp.vulnweb.com",
      // Acunetix PHP test site
      "testasp.vulnweb.com",
      // Acunetix ASP test site
      "testaspnet.vulnweb.com",
      // Acunetix ASP.NET test site
      "testhtml5.vulnweb.com",
      // Acunetix HTML5 test site
      "rest.vulnweb.com",
      // Acunetix REST API test site
      "hackazon.webscantest.com",
      // Rapid7 Hackazon
      "www.webscantest.com",
      // Rapid7 WebScanTest
      "demo.testfire.net",
      // IBM Altoro Mutual
      "brokencrystals.com",
      // Broken Crystals
      "ginandjuice.shop",
      // PortSwigger Gin & Juice Shop
      "public-firing-range.appspot.com",
      // Google Firing Range
      "google-gruyere.appspot.com",
      // Google Gruyere
      "hack-yourself-first.com",
      // Troy Hunt's test site
      "pentest-ground.com",
      // Pentest Ground
      "angular.testsparker.com",
      // Netsparker Angular
      "aspnet.testsparker.com",
      // Netsparker ASP.NET
      "php.testsparker.com",
      // Netsparker PHP
      "zero.webappsecurity.com",
      // HP Zero Bank
      // Nmap official scan target
      "scanme.nmap.org",
      // Source code hosting platforms (for bug bounty source code audits)
      "github.com",
      "gitlab.com",
      "bitbucket.org",
      "codeberg.org",
      "sr.ht"
    ];
    SOURCE_CODE_HOSTS = [
      "github.com",
      "gitlab.com",
      "bitbucket.org",
      "codeberg.org",
      "sr.ht"
    ];
    WHITELISTED_IPS = [
      "159.223.152.190",
      // AC3 DigitalOcean test lab droplet
      "159.223.154.80",
      // ac3-lab-linux-target (Sprint 11B)
      "104.248.62.133",
      // ac3-lab-windows-target (Sprint 11B)
      "45.33.32.156"
      // scanme.nmap.org
    ];
    SAFE_PRIVATE_PATTERNS = [
      /^127\.\d+\.\d+\.\d+$/,
      // Loopback
      /^10\.\d+\.\d+\.\d+$/,
      // Class A private
      /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
      // Class B private
      /^192\.168\.\d+\.\d+$/,
      // Class C private
      /^localhost$/i,
      /^::1$/
    ];
  }
});

// server/scanforge/engine/accuracy-tracker.ts
import { eq, and, desc, sql } from "drizzle-orm";
async function logFinding(entry) {
  const _db = await getDbRequired();
  const result = await _db.insert(scanforgeFindingLog).values({
    engagementId: entry.engagementId,
    templateId: entry.templateId,
    templateVersion: entry.templateVersion || "1.0.0",
    target: entry.target,
    findingTitle: entry.findingTitle,
    severity: entry.severity,
    confidence: entry.confidence,
    proofVerified: entry.proofVerified || false,
    findingData: entry.findingData || {},
    verdict: "PENDING"
  });
  return Number(result[0].insertId);
}
async function assessFindings(engagementId, legacyFindings, verdictSource = "auto-crossref") {
  const _db = await getDbRequired();
  const pendingFindings = await _db.select().from(scanforgeFindingLog).where(and(
    eq(scanforgeFindingLog.engagementId, engagementId),
    eq(scanforgeFindingLog.verdict, "PENDING")
  ));
  let tp = 0, fp = 0;
  const legacyIndex = /* @__PURE__ */ new Map();
  for (const lf of legacyFindings) {
    const key = normalizeTarget(lf.target);
    if (!legacyIndex.has(key)) legacyIndex.set(key, []);
    legacyIndex.get(key).push(lf);
  }
  for (const finding of pendingFindings) {
    const targetKey = normalizeTarget(finding.target);
    const candidates = legacyIndex.get(targetKey) || [];
    const matches = findCrossToolMatches(finding, candidates);
    if (matches.length > 0) {
      tp++;
      await _db.update(scanforgeFindingLog).set({
        verdict: "TP",
        verdictSource,
        verdictReason: `Confirmed by ${matches.map((m) => m.tool).join(", ")}`,
        crossToolMatches: matches,
        assessedAt: sql`CURRENT_TIMESTAMP`
      }).where(eq(scanforgeFindingLog.id, finding.id));
    } else if (finding.proofVerified) {
      tp++;
      await _db.update(scanforgeFindingLog).set({
        verdict: "TP",
        verdictSource: "proof-verified",
        verdictReason: "Proof-based verification confirmed this finding even without legacy tool match",
        assessedAt: sql`CURRENT_TIMESTAMP`
      }).where(eq(scanforgeFindingLog.id, finding.id));
    } else {
      fp++;
      await _db.update(scanforgeFindingLog).set({
        verdict: "FP",
        verdictSource,
        verdictReason: "No matching finding from legacy tools and no proof verification",
        assessedAt: sql`CURRENT_TIMESTAMP`
      }).where(eq(scanforgeFindingLog.id, finding.id));
    }
  }
  const allScanforgeFindings = await _db.select().from(scanforgeFindingLog).where(eq(scanforgeFindingLog.engagementId, engagementId));
  let fn = 0;
  for (const lf of legacyFindings) {
    const matched = allScanforgeFindings.some(
      (sf) => isSameFinding(sf, lf)
    );
    if (!matched) {
      fn++;
      await _db.insert(scanforgeFindingLog).values({
        engagementId,
        templateId: "MISSED",
        target: lf.target,
        findingTitle: `[MISSED] ${lf.title}`,
        severity: lf.severity,
        confidence: 0,
        verdict: "FN",
        verdictSource,
        verdictReason: `Found by ${lf.tool} but missed by ScanForge`,
        crossToolMatches: [{ tool: lf.tool, title: lf.title, severity: lf.severity, matchConfidence: 1 }],
        assessedAt: sql`CURRENT_TIMESTAMP`
      });
    }
  }
  return { assessed: pendingFindings.length, tp, fp, fn };
}
async function generateEngagementReport(engagementId, legacyCounts) {
  const _db = await getDbRequired();
  const findings = await _db.select().from(scanforgeFindingLog).where(eq(scanforgeFindingLog.engagementId, engagementId));
  const scanforgeFindings = findings.filter((f) => f.templateId !== "MISSED").length;
  const tp = findings.filter((f) => f.verdict === "TP" && f.templateId !== "MISSED").length;
  const fp = findings.filter((f) => f.verdict === "FP").length;
  const fn = findings.filter((f) => f.verdict === "FN").length;
  const totalLegacy = legacyCounts.nuclei + legacyCounts.zap;
  const sharedFindings = tp;
  const scanforgeOnly = findings.filter((f) => f.verdict === "TP" && f.verdictSource === "proof-verified").length;
  const legacyOnly = fn;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
  const report = {
    engagementId,
    scanforgeFindings,
    nucleiFindings: legacyCounts.nuclei,
    zapFindings: legacyCounts.zap,
    sharedFindings,
    scanforgeOnly,
    legacyOnly,
    scanforgePrecision: precision,
    scanforgeRecall: recall,
    scanforgeF1: f1
  };
  await _db.insert(scanforgeEngagementReport).values({
    engagementId,
    scanforgeFindings,
    nucleiFindings: legacyCounts.nuclei,
    zapFindings: legacyCounts.zap,
    sharedFindings,
    scanforgeOnly,
    legacyOnly,
    scanforgePrecision: precision,
    scanforgeRecall: recall,
    scanforgeF1: f1
  });
  return report;
}
async function getTemplateEffectiveness(minScans = 5) {
  const _db = await getDbRequired();
  const metrics = await _db.select().from(scanforgeTemplateMetrics).where(sql`${scanforgeTemplateMetrics.totalScans} >= ${minScans}`).orderBy(desc(scanforgeTemplateMetrics.effectivenessScore));
  return metrics.map((m) => ({
    templateId: m.templateId,
    precision: m.precision || 0,
    recall: m.recall || 0,
    f1Score: m.f1Score || 0,
    calibratedConfidence: m.calibratedConfidence || 0.5,
    effectivenessScore: m.effectivenessScore || 50,
    totalScans: m.totalScans,
    truePositives: m.truePositives,
    falsePositives: m.falsePositives,
    falseNegatives: m.falseNegatives
  }));
}
async function getEngagementReports(limit = 20) {
  const _db = await getDbRequired();
  return _db.select().from(scanforgeEngagementReport).orderBy(desc(scanforgeEngagementReport.createdAt)).limit(limit);
}
async function getEngagementFindings(engagementId) {
  const _db = await getDbRequired();
  return _db.select().from(scanforgeFindingLog).where(eq(scanforgeFindingLog.engagementId, engagementId)).orderBy(desc(scanforgeFindingLog.createdAt));
}
function normalizeTarget(target) {
  return target.toLowerCase().replace(/^https?:\/\//, "").replace(/\/+$/, "").replace(/:\d+$/, "");
}
function findCrossToolMatches(scanforgeFinding, legacyCandidates) {
  const matches = [];
  const sfTitle = scanforgeFinding.findingTitle.toLowerCase();
  for (const candidate of legacyCandidates) {
    const ltTitle = candidate.title.toLowerCase();
    if (sfTitle === ltTitle) {
      matches.push({ tool: candidate.tool, title: candidate.title, severity: candidate.severity, matchConfidence: 1 });
      continue;
    }
    const sfWords = new Set(sfTitle.split(/[\s\-_\/]+/).filter((w) => w.length > 3));
    const ltWords = new Set(ltTitle.split(/[\s\-_\/]+/).filter((w) => w.length > 3));
    const shared = [...sfWords].filter((w) => ltWords.has(w));
    const jaccardSimilarity = shared.length / (sfWords.size + ltWords.size - shared.length);
    if (jaccardSimilarity > 0.3) {
      matches.push({ tool: candidate.tool, title: candidate.title, severity: candidate.severity, matchConfidence: jaccardSimilarity });
    }
    const sfCves = extractCVEs(scanforgeFinding.findingTitle);
    const ltCves = extractCVEs(candidate.title);
    if (sfCves.length > 0 && ltCves.length > 0) {
      const sharedCves = sfCves.filter((c) => ltCves.includes(c));
      if (sharedCves.length > 0) {
        matches.push({ tool: candidate.tool, title: candidate.title, severity: candidate.severity, matchConfidence: 0.95 });
      }
    }
  }
  return matches;
}
function isSameFinding(sf, lf) {
  const sfNorm = normalizeTarget(sf.target);
  const lfNorm = normalizeTarget(lf.target);
  if (sfNorm !== lfNorm) return false;
  const sfTitle = sf.findingTitle.toLowerCase().replace(/\[missed\]\s*/i, "");
  const lfTitle = lf.title.toLowerCase();
  if (sfTitle === lfTitle) return true;
  const sfCves = extractCVEs(sfTitle);
  const lfCves = extractCVEs(lfTitle);
  if (sfCves.length > 0 && lfCves.length > 0) {
    return sfCves.some((c) => lfCves.includes(c));
  }
  const sfWords = new Set(sfTitle.split(/[\s\-_\/]+/).filter((w) => w.length > 3));
  const lfWords = new Set(lfTitle.split(/[\s\-_\/]+/).filter((w) => w.length > 3));
  const shared = [...sfWords].filter((w) => lfWords.has(w));
  return shared.length / Math.max(sfWords.size, lfWords.size) > 0.5;
}
function extractCVEs(text) {
  const matches = text.match(/CVE-\d{4}-\d{4,}/gi);
  return matches ? matches.map((m) => m.toUpperCase()) : [];
}
var init_accuracy_tracker = __esm({
  "server/scanforge/engine/accuracy-tracker.ts"() {
    "use strict";
    init_db();
    init_schema();
  }
});

// server/scanforge/engine/auto-promoter.ts
import { eq as eq2, desc as desc2, sql as sql2, inArray as inArray2 } from "drizzle-orm";
function evaluateTemplate(template, metrics, rules = DEFAULT_PROMOTION_RULES) {
  const templateId = template.templateId;
  const generationConfidence = template.generationConfidence ?? 0.5;
  if (!metrics) {
    return {
      templateId,
      generatedTemplateDbId: template.id,
      currentStatus: template.status,
      decision: "deferred",
      newStatus: template.status,
      reason: "No accuracy metrics available yet \u2014 template has not been used in any engagement",
      rulesEvaluated: [],
      rulesPassed: 0,
      rulesFailed: 0,
      metricsSnapshot: {
        precision: 0,
        recall: 0,
        f1Score: 0,
        effectivenessScore: 0,
        totalScans: 0,
        truePositives: 0,
        falsePositives: 0,
        falseNegatives: 0,
        engagementCount: 0,
        generationConfidence
      }
    };
  }
  const engagementWindow = metrics.engagementWindow ?? [];
  const engagementCount = engagementWindow.length;
  const totalScans = metrics.totalScans ?? 0;
  const precision = metrics.precision ?? 0;
  const recall = metrics.recall ?? 0;
  const f1Score = metrics.f1Score ?? 0;
  const effectivenessScore = metrics.effectivenessScore ?? 0;
  const tp = metrics.truePositives ?? 0;
  const fp = metrics.falsePositives ?? 0;
  const fn = metrics.falseNegatives ?? 0;
  const fpRate = tp + fp > 0 ? fp / (tp + fp) : 0;
  const metricsSnapshot = {
    precision,
    recall,
    f1Score,
    effectivenessScore,
    totalScans,
    truePositives: tp,
    falsePositives: fp,
    falseNegatives: fn,
    engagementCount,
    generationConfidence
  };
  const evaluations = [
    { rule: "minEngagements", threshold: rules.minEngagements, actual: engagementCount, passed: engagementCount >= rules.minEngagements },
    { rule: "minTotalScans", threshold: rules.minTotalScans, actual: totalScans, passed: totalScans >= rules.minTotalScans },
    { rule: "minPrecision", threshold: rules.minPrecision, actual: precision, passed: precision >= rules.minPrecision },
    { rule: "minRecall", threshold: rules.minRecall, actual: recall, passed: recall >= rules.minRecall },
    { rule: "minF1Score", threshold: rules.minF1Score, actual: f1Score, passed: f1Score >= rules.minF1Score },
    { rule: "maxFalsePositiveRate", threshold: rules.maxFalsePositiveRate, actual: fpRate, passed: fpRate <= rules.maxFalsePositiveRate },
    { rule: "minEffectivenessScore", threshold: rules.minEffectivenessScore, actual: effectivenessScore, passed: effectivenessScore >= rules.minEffectivenessScore },
    { rule: "minGenerationConfidence", threshold: rules.minGenerationConfidence, actual: generationConfidence, passed: generationConfidence >= rules.minGenerationConfidence }
  ];
  const passed = evaluations.filter((e) => e.passed).length;
  const failed = evaluations.filter((e) => !e.passed).length;
  const failedRules = evaluations.filter((e) => !e.passed);
  let decision;
  let newStatus;
  let reason;
  if (failed === 0) {
    const isFastTrack = rules === FAST_TRACK_RULES;
    const isAlreadyFlagged = template.status === "production_flagged";
    if (isFastTrack && !isAlreadyFlagged) {
      decision = "promoted";
      newStatus = "production_flagged";
      reason = `Fast-track promotion to production_flagged (reduced confidence ${PRODUCTION_FLAGGED_CONFIDENCE_MULTIPLIER}x). All ${passed} rules passed: precision=${(precision * 100).toFixed(1)}%, recall=${(recall * 100).toFixed(1)}%, F1=${(f1Score * 100).toFixed(1)}% across ${totalScans} scans. Template will run with reduced confidence weighting until ${PRODUCTION_FLAGGED_GRADUATION_SCANS} scans accumulated for full promotion.`;
    } else if (isAlreadyFlagged && totalScans >= PRODUCTION_FLAGGED_GRADUATION_SCANS) {
      decision = "promoted";
      newStatus = "promoted";
      reason = `Graduated from production_flagged to full promoted status. Template accumulated ${totalScans} scans (threshold: ${PRODUCTION_FLAGGED_GRADUATION_SCANS}) with sustained quality: precision=${(precision * 100).toFixed(1)}%, recall=${(recall * 100).toFixed(1)}%, F1=${(f1Score * 100).toFixed(1)}%, effectiveness=${effectivenessScore.toFixed(0)}/100 across ${engagementCount} engagements`;
    } else {
      decision = "promoted";
      newStatus = "promoted";
      reason = `All ${passed} promotion rules passed. Template meets production quality thresholds: precision=${(precision * 100).toFixed(1)}%, recall=${(recall * 100).toFixed(1)}%, F1=${(f1Score * 100).toFixed(1)}%, effectiveness=${effectivenessScore.toFixed(0)}/100 across ${engagementCount} engagements (${totalScans} scans)`;
    }
  } else if (fpRate > rules.maxFalsePositiveRate * 2) {
    decision = "rejected";
    newStatus = "rejected";
    reason = `Template rejected due to excessive false positive rate: ${(fpRate * 100).toFixed(1)}% (threshold: ${(rules.maxFalsePositiveRate * 100).toFixed(1)}%). ${fp} false positives out of ${tp + fp} total detections`;
  } else if (engagementCount < rules.minEngagements || totalScans < rules.minTotalScans) {
    decision = "deferred";
    newStatus = template.status === "draft" ? "review" : template.status;
    reason = `Insufficient data for promotion decision. Engagements: ${engagementCount}/${rules.minEngagements}, Scans: ${totalScans}/${rules.minTotalScans}. Template moved to review for continued evaluation`;
  } else {
    decision = "deferred";
    newStatus = "review";
    reason = `${failed} of ${passed + failed} rules failed: ` + failedRules.map((r) => `${r.rule} (actual=${r.actual.toFixed(2)}, threshold=${r.threshold})`).join(", ") + `. Template needs improvement before promotion`;
  }
  return {
    templateId,
    generatedTemplateDbId: template.id,
    currentStatus: template.status,
    decision,
    newStatus,
    reason,
    rulesEvaluated: evaluations,
    rulesPassed: passed,
    rulesFailed: failed,
    metricsSnapshot
  };
}
async function runAutoPromotion(triggerEngagementId, rules = DEFAULT_PROMOTION_RULES) {
  const db = await getDbRequired();
  const eligibleTemplates = await db.select().from(scanforgeGeneratedTemplates).where(
    inArray2(scanforgeGeneratedTemplates.status, ["draft", "review", "approved", "production_flagged"])
  );
  if (eligibleTemplates.length === 0) {
    return [];
  }
  const templateIds = eligibleTemplates.map((t) => t.templateId);
  const allMetrics = await db.select().from(scanforgeTemplateMetrics).where(inArray2(scanforgeTemplateMetrics.templateId, templateIds));
  const metricsMap = /* @__PURE__ */ new Map();
  for (const m of allMetrics) {
    metricsMap.set(m.templateId, m);
  }
  const evaluations = [];
  for (const template of eligibleTemplates) {
    const metrics = metricsMap.get(template.templateId) ?? null;
    const evaluation = evaluateTemplate(template, metrics, rules);
    evaluations.push(evaluation);
    if (evaluation.decision !== "deferred" || evaluation.newStatus !== template.status) {
      await db.update(scanforgeGeneratedTemplates).set({
        status: evaluation.newStatus,
        reviewNotes: evaluation.reason
      }).where(eq2(scanforgeGeneratedTemplates.id, template.id));
      const historyEntry = {
        templateId: template.templateId,
        generatedTemplateDbId: template.id,
        decision: evaluation.decision,
        reason: evaluation.reason,
        metricsSnapshot: evaluation.metricsSnapshot,
        rulesEvaluated: evaluation.rulesEvaluated,
        triggerEngagementId: triggerEngagementId ?? null,
        previousStatus: template.status,
        newStatus: evaluation.newStatus,
        evaluatedBy: "auto"
      };
      await db.insert(scanforgePromotionHistory).values(historyEntry);
    }
  }
  return evaluations;
}
async function manualPromote(generatedTemplateDbId, reason, evaluatedBy = "manual") {
  const db = await getDbRequired();
  const [template] = await db.select().from(scanforgeGeneratedTemplates).where(eq2(scanforgeGeneratedTemplates.id, generatedTemplateDbId));
  if (!template) return null;
  const [metrics] = await db.select().from(scanforgeTemplateMetrics).where(eq2(scanforgeTemplateMetrics.templateId, template.templateId));
  const metricsSnapshot = metrics ? {
    precision: metrics.precision ?? 0,
    recall: metrics.recall ?? 0,
    f1Score: metrics.f1Score ?? 0,
    effectivenessScore: metrics.effectivenessScore ?? 0,
    totalScans: metrics.totalScans ?? 0,
    truePositives: metrics.truePositives ?? 0,
    falsePositives: metrics.falsePositives ?? 0,
    falseNegatives: metrics.falseNegatives ?? 0,
    engagementCount: (metrics.engagementWindow ?? []).length,
    generationConfidence: template.generationConfidence ?? 0.5
  } : {
    precision: 0,
    recall: 0,
    f1Score: 0,
    effectivenessScore: 0,
    totalScans: 0,
    truePositives: 0,
    falsePositives: 0,
    falseNegatives: 0,
    engagementCount: 0,
    generationConfidence: template.generationConfidence ?? 0.5
  };
  await db.update(scanforgeGeneratedTemplates).set({ status: "promoted", reviewNotes: `[Manual] ${reason}` }).where(eq2(scanforgeGeneratedTemplates.id, generatedTemplateDbId));
  await db.insert(scanforgePromotionHistory).values({
    templateId: template.templateId,
    generatedTemplateDbId,
    decision: "promoted",
    reason: `[Manual] ${reason}`,
    metricsSnapshot,
    rulesEvaluated: [{ rule: "manual_override", threshold: 0, actual: 1, passed: true }],
    triggerEngagementId: null,
    previousStatus: template.status,
    newStatus: "promoted",
    evaluatedBy
  });
  return {
    templateId: template.templateId,
    generatedTemplateDbId,
    currentStatus: template.status,
    decision: "promoted",
    newStatus: "promoted",
    reason: `[Manual] ${reason}`,
    rulesEvaluated: [{ rule: "manual_override", threshold: 0, actual: 1, passed: true }],
    rulesPassed: 1,
    rulesFailed: 0,
    metricsSnapshot
  };
}
async function manualReject(generatedTemplateDbId, reason, evaluatedBy = "manual") {
  const db = await getDbRequired();
  const [template] = await db.select().from(scanforgeGeneratedTemplates).where(eq2(scanforgeGeneratedTemplates.id, generatedTemplateDbId));
  if (!template) return;
  await db.update(scanforgeGeneratedTemplates).set({ status: "rejected", reviewNotes: `[Manual] ${reason}` }).where(eq2(scanforgeGeneratedTemplates.id, generatedTemplateDbId));
  const [metrics] = await db.select().from(scanforgeTemplateMetrics).where(eq2(scanforgeTemplateMetrics.templateId, template.templateId));
  await db.insert(scanforgePromotionHistory).values({
    templateId: template.templateId,
    generatedTemplateDbId,
    decision: "rejected",
    reason: `[Manual] ${reason}`,
    metricsSnapshot: metrics ? {
      precision: metrics.precision ?? 0,
      recall: metrics.recall ?? 0,
      f1Score: metrics.f1Score ?? 0,
      effectivenessScore: metrics.effectivenessScore ?? 0,
      totalScans: metrics.totalScans ?? 0,
      truePositives: metrics.truePositives ?? 0,
      falsePositives: metrics.falsePositives ?? 0,
      falseNegatives: metrics.falseNegatives ?? 0,
      engagementCount: (metrics.engagementWindow ?? []).length,
      generationConfidence: template.generationConfidence ?? 0.5
    } : { precision: 0, recall: 0, f1Score: 0, effectivenessScore: 0, totalScans: 0, truePositives: 0, falsePositives: 0, falseNegatives: 0, engagementCount: 0, generationConfidence: 0.5 },
    rulesEvaluated: [{ rule: "manual_rejection", threshold: 0, actual: 0, passed: false }],
    triggerEngagementId: null,
    previousStatus: template.status,
    newStatus: "rejected",
    evaluatedBy
  });
}
async function getPromotionHistory(templateId, limit = 50) {
  const db = await getDbRequired();
  if (templateId) {
    return db.select().from(scanforgePromotionHistory).where(eq2(scanforgePromotionHistory.templateId, templateId)).orderBy(desc2(scanforgePromotionHistory.createdAt)).limit(limit);
  }
  return db.select().from(scanforgePromotionHistory).orderBy(desc2(scanforgePromotionHistory.createdAt)).limit(limit);
}
async function getPromotionStats() {
  const db = await getDbRequired();
  const historyStats = await db.select({
    decision: scanforgePromotionHistory.decision,
    count: sql2`COUNT(*)`
  }).from(scanforgePromotionHistory).groupBy(scanforgePromotionHistory.decision);
  const counts = {};
  for (const row of historyStats) {
    counts[row.decision] = row.count;
  }
  const [pendingResult] = await db.select({ count: sql2`COUNT(*)` }).from(scanforgeGeneratedTemplates).where(inArray2(scanforgeGeneratedTemplates.status, ["draft", "review", "approved", "production_flagged"]));
  const promotedHistory = await db.select({ metricsSnapshot: scanforgePromotionHistory.metricsSnapshot }).from(scanforgePromotionHistory).where(eq2(scanforgePromotionHistory.decision, "promoted")).limit(100);
  let avgPrecision = 0;
  let avgF1 = 0;
  if (promotedHistory.length > 0) {
    let totalPrecision = 0;
    let totalF1 = 0;
    for (const row of promotedHistory) {
      const snap = row.metricsSnapshot;
      totalPrecision += snap?.precision ?? 0;
      totalF1 += snap?.f1Score ?? 0;
    }
    avgPrecision = totalPrecision / promotedHistory.length;
    avgF1 = totalF1 / promotedHistory.length;
  }
  return {
    totalEvaluated: Object.values(counts).reduce((a, b) => a + b, 0),
    promoted: counts["promoted"] ?? 0,
    deferred: counts["deferred"] ?? 0,
    rejected: counts["rejected"] ?? 0,
    pendingReview: pendingResult?.count ?? 0,
    avgPrecisionAtPromotion: avgPrecision,
    avgF1AtPromotion: avgF1
  };
}
var DEFAULT_PROMOTION_RULES, FAST_TRACK_RULES, PRODUCTION_FLAGGED_CONFIDENCE_MULTIPLIER, PRODUCTION_FLAGGED_GRADUATION_SCANS;
var init_auto_promoter = __esm({
  "server/scanforge/engine/auto-promoter.ts"() {
    "use strict";
    init_db();
    init_schema();
    DEFAULT_PROMOTION_RULES = {
      minEngagements: 3,
      minPrecision: 0.8,
      minRecall: 0.6,
      minF1Score: 0.7,
      maxFalsePositiveRate: 0.15,
      minEffectivenessScore: 65,
      minGenerationConfidence: 0.6,
      minTotalScans: 5
    };
    FAST_TRACK_RULES = {
      minEngagements: 3,
      minPrecision: 0.95,
      minRecall: 0.8,
      minF1Score: 0.85,
      maxFalsePositiveRate: 0.05,
      minEffectivenessScore: 80,
      minGenerationConfidence: 0.85,
      minTotalScans: 15
    };
    PRODUCTION_FLAGGED_CONFIDENCE_MULTIPLIER = 0.7;
    PRODUCTION_FLAGGED_GRADUATION_SCANS = 25;
  }
});

// server/scanforge/engine/deep-research-agent.ts
import { eq as eq3, desc as desc3 } from "drizzle-orm";
async function runTargetedResearch(engagementId, targets, targetType) {
  console.log(`[ScanForge Deep Research] Targeted research for ${engagementId}: ${targets.length} targets`);
  const inputs = [];
  for (const target of targets.slice(0, 10)) {
    const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target);
    const domain = isIP ? null : target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
    if (isIP) {
      try {
        const { shodanHostLookup } = await import("./darkweb-osint-service-NNZQRTZ2.js");
        const result = await shodanHostLookup?.(target);
        if (result) {
          inputs.push({
            feedSource: "shodan",
            researchType: "service_exposure",
            subject: target,
            data: result,
            urgency: "high"
          });
        }
      } catch {
      }
    }
    if (isIP) {
      try {
        const { censysHostSearch } = await import("./darkweb-osint-service-NNZQRTZ2.js");
        const result = await censysHostSearch?.(target);
        if (result) {
          inputs.push({
            feedSource: "censys",
            researchType: "service_exposure",
            subject: target,
            data: result,
            urgency: "medium"
          });
        }
      } catch {
      }
    }
    if (domain) {
      try {
        const { securityTrailsDomainInfo } = await import("./darkweb-osint-service-NNZQRTZ2.js");
        const result = await securityTrailsDomainInfo?.(domain);
        if (result) {
          inputs.push({
            feedSource: "securitytrails",
            researchType: "service_exposure",
            subject: domain,
            data: result,
            urgency: "medium"
          });
        }
      } catch {
      }
    }
    if (domain) {
      try {
        const { enrichDomainIntel } = await import("./bug-bounty-intelligence-G4EZWGJR.js");
        const result = await enrichDomainIntel?.(domain);
        if (result) {
          inputs.push({
            feedSource: "bug_bounty",
            researchType: "bug_bounty_pattern",
            subject: domain,
            data: result,
            urgency: "medium"
          });
        }
      } catch {
      }
    }
    if (isIP) {
      try {
        const { queryAbuseIpdb } = await import("./darkweb-osint-service-NNZQRTZ2.js");
        const result = await queryAbuseIpdb?.(target);
        if (result) {
          inputs.push({
            feedSource: "abuseipdb",
            researchType: "trend_analysis",
            subject: target,
            data: result,
            urgency: result.abuseConfidenceScore > 80 ? "high" : "low"
          });
        }
      } catch {
      }
    }
    if (domain) {
      try {
        const { queryDehashed } = await import("./darkweb-osint-service-NNZQRTZ2.js");
        const result = await queryDehashed?.(domain);
        if (result) {
          inputs.push({
            feedSource: "dehashed",
            researchType: "credential_exposure",
            subject: domain,
            data: { resultCount: Array.isArray(result) ? result.length : 0, sample: Array.isArray(result) ? result.slice(0, 3) : [] },
            urgency: Array.isArray(result) && result.length > 100 ? "high" : "medium"
          });
        }
      } catch {
      }
    }
    if (domain || target.startsWith("http")) {
      try {
        const { queryUrlscan } = await import("./darkweb-osint-service-NNZQRTZ2.js");
        const result = await queryUrlscan?.(domain || target);
        if (result) {
          inputs.push({
            feedSource: "urlscan",
            researchType: "service_exposure",
            subject: domain || target,
            data: result,
            urgency: "low"
          });
        }
      } catch {
      }
    }
  }
  for (const input of inputs) {
    const _db1 = await getDbRequired();
    await _db1.insert(scanforgeResearchLog).values({
      feedSource: input.feedSource,
      researchSubject: input.subject,
      researchType: input.researchType,
      analysisResult: input.data,
      actionable: false
      // Will be updated after LLM analysis
    });
  }
  console.log(`[ScanForge Deep Research] Targeted research produced ${inputs.length} inputs`);
  return inputs;
}
async function promoteTemplate(templateId) {
  const _db = await getDbRequired();
  const rows = await _db.select().from(scanforgeGeneratedTemplates).where(eq3(scanforgeGeneratedTemplates.templateId, templateId)).limit(1);
  if (!rows[0] || rows[0].status !== "review") return false;
  await _db.update(scanforgeGeneratedTemplates).set({ status: "promoted", promotedToTemplateId: templateId }).where(eq3(scanforgeGeneratedTemplates.templateId, templateId));
  return true;
}
var CIRCUIT_BREAKER_CONFIG;
var init_deep_research_agent = __esm({
  "server/scanforge/engine/deep-research-agent.ts"() {
    "use strict";
    init_llm();
    init_db();
    init_schema();
    CIRCUIT_BREAKER_CONFIG = {
      /** Number of consecutive failures before tripping open */
      FAILURE_THRESHOLD: 3,
      /** Time in ms to wait before allowing a probe request (5 minutes) */
      RECOVERY_TIMEOUT_MS: 5 * 60 * 1e3,
      /** Maximum time a circuit can stay open before forced half-open (30 minutes) */
      MAX_OPEN_DURATION_MS: 30 * 60 * 1e3,
      /** Timeout for individual adapter calls (30 seconds) */
      ADAPTER_TIMEOUT_MS: 3e4,
      /** Slow-start: after recovery, only allow 50% of normal batch size for first cycle */
      SLOW_START_CYCLES: 2
    };
  }
});

// server/scanforge/engine/confidence-tuner.ts
import { eq as eq4, desc as desc4, sql as sql4 } from "drizzle-orm";
async function getTemplateConfidenceMap(templateIds) {
  if (templateIds.length === 0) return /* @__PURE__ */ new Map();
  const _db = await getDbRequired();
  const metrics = await _db.select({
    templateId: scanforgeTemplateMetrics.templateId,
    calibratedConfidence: scanforgeTemplateMetrics.calibratedConfidence
  }).from(scanforgeTemplateMetrics);
  const map = /* @__PURE__ */ new Map();
  for (const m of metrics) {
    map.set(m.templateId, m.calibratedConfidence || CONFIG.DEFAULT_CONFIDENCE);
  }
  for (const id of templateIds) {
    if (!map.has(id)) map.set(id, CONFIG.DEFAULT_CONFIDENCE);
  }
  return map;
}
async function getScanForgeHealthMetrics() {
  const _db = await getDbRequired();
  const allMetrics = await _db.select().from(scanforgeTemplateMetrics);
  let totalTP = 0, totalFP = 0, totalFN = 0;
  let precisionSum = 0, recallSum = 0, f1Sum = 0;
  let activeCount = 0;
  const performanceData = [];
  for (const m of allMetrics) {
    const tp = m.truePositives || 0;
    const fp = m.falsePositives || 0;
    const fn = m.falseNegatives || 0;
    const total = tp + fp;
    totalTP += tp;
    totalFP += fp;
    totalFN += fn;
    if (total >= CONFIG.MIN_FINDINGS_FOR_TUNING) {
      const precision = tp / (tp + fp) || 0;
      const recall = tp / (tp + fn) || 0;
      const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
      const fpRate = fp / total;
      precisionSum += precision;
      recallSum += recall;
      f1Sum += f1;
      activeCount++;
      performanceData.push({ templateId: m.templateId, f1, fpRate, findings: total });
    }
  }
  const generatedCounts = await _db.select({
    status: scanforgeGeneratedTemplates.status,
    count: sql4`count(*)`
  }).from(scanforgeGeneratedTemplates).groupBy(scanforgeGeneratedTemplates.status);
  const statusMap = new Map(generatedCounts.map((r) => [r.status, r.count]));
  const sorted = [...performanceData].sort((a, b) => b.f1 - a.f1);
  const topPerformers = sorted.slice(0, 5).map((p) => ({ templateId: p.templateId, f1: p.f1, findings: p.findings }));
  const worstPerformers = [...performanceData].sort((a, b) => b.fpRate - a.fpRate).slice(0, 5).map((p) => ({ templateId: p.templateId, fpRate: p.fpRate, findings: p.findings }));
  return {
    totalTemplates: allMetrics.length + (statusMap.get("promoted") || 0),
    activeTemplates: activeCount,
    deprecatedTemplates: statusMap.get("deprecated") || 0,
    avgPrecision: activeCount > 0 ? precisionSum / activeCount : 0,
    avgRecall: activeCount > 0 ? recallSum / activeCount : 0,
    avgF1: activeCount > 0 ? f1Sum / activeCount : 0,
    totalFindings: totalTP + totalFP,
    truePositives: totalTP,
    falsePositives: totalFP,
    falseNegatives: totalFN,
    topPerformers,
    worstPerformers
  };
}
async function getTuningHistory(limit = 50) {
  const _db = await getDbRequired();
  return _db.select().from(scanforgeTemplateMetrics).orderBy(desc4(scanforgeTemplateMetrics.lastUpdated)).limit(limit);
}
var CONFIG;
var init_confidence_tuner = __esm({
  "server/scanforge/engine/confidence-tuner.ts"() {
    "use strict";
    init_db();
    init_schema();
    CONFIG = {
      // Minimum number of findings before we adjust confidence
      MIN_FINDINGS_FOR_TUNING: 5,
      // Confidence bounds — never go below or above these
      // These are HARD bounds that prevent runaway drift in either direction.
      // Even if a template has 100% FP rate, it never drops below MIN_CONFIDENCE
      // (so it remains in the system for monitoring rather than silently disappearing).
      MIN_CONFIDENCE: 0.15,
      MAX_CONFIDENCE: 0.98,
      DEFAULT_CONFIDENCE: 0.5,
      // Adjustment step sizes
      BOOST_STEP: 0.05,
      // Reward for high precision
      PENALTY_STEP: 0.08,
      // Penalty for high FP rate
      DECAY_STEP: 0.02,
      // Slow decay for templates with no recent activity
      // ─── Drift Prevention ─────────────────────────────────────────────────────
      //
      // Without bounds, repeated tuning cycles can cause monotonic drift:
      //   - A template with borderline precision (0.79) gets penalized every cycle
      //   - After 10 cycles: confidence drops from 0.5 to 0.15 (floor)
      //   - This is correct behavior IF the template is truly bad
      //   - But if the sample size is small (5-10 findings), this is premature
      //
      // Solution: per-cycle max adjustment cap + minimum sample size scaling.
      // The cap limits how much a single tuning cycle can move confidence,
      // and the sample scaling requires more data before larger adjustments.
      /** Maximum total confidence change per tuning cycle (prevents sudden jumps) */
      MAX_ADJUSTMENT_PER_CYCLE: 0.12,
      /** Minimum sample size to apply full step size (below this, step is scaled down) */
      FULL_STEP_SAMPLE_SIZE: 20,
      /** Number of consecutive penalty cycles before triggering deprecation review */
      CONSECUTIVE_PENALTY_THRESHOLD: 5,
      /** Minimum precision improvement required to reverse a penalty streak */
      RECOVERY_PRECISION_THRESHOLD: 0.65,
      // ─── End Drift Prevention ─────────────────────────────────────────────────
      // Thresholds for actions
      FP_RATE_DEPRECATE: 0.7,
      // Deprecate if >70% false positive rate
      FP_RATE_PENALIZE: 0.3,
      // Penalize if >30% false positive rate
      TP_RATE_BOOST: 0.8,
      // Boost if >80% true positive rate
      // Auto-template promotion thresholds
      DRAFT_TO_REVIEW_CONFIDENCE: 0.6,
      REVIEW_TO_PROMOTED_CONFIDENCE: 0.75,
      // Time window for recent activity (ms)
      RECENT_WINDOW_MS: 30 * 24 * 60 * 60 * 1e3
      // 30 days
    };
  }
});

export {
  isSourceCodeTarget,
  validateEngagementTargets,
  getSafetyWarning,
  init_domain_safety_whitelist,
  logFinding,
  assessFindings,
  generateEngagementReport,
  getTemplateEffectiveness,
  getEngagementReports,
  getEngagementFindings,
  init_accuracy_tracker,
  DEFAULT_PROMOTION_RULES,
  FAST_TRACK_RULES,
  runAutoPromotion,
  manualPromote,
  manualReject,
  getPromotionHistory,
  getPromotionStats,
  init_auto_promoter,
  runTargetedResearch,
  promoteTemplate,
  init_deep_research_agent,
  getTemplateConfidenceMap,
  getScanForgeHealthMetrics,
  getTuningHistory,
  init_confidence_tuner
};
