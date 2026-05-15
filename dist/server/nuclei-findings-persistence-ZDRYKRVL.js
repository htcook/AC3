import {
  getDb,
  init_db
} from "./chunk-TY7YEWON.js";
import "./chunk-NRYVRXXR.js";
import {
  init_schema,
  nucleiFindings,
  nucleiTemplateMappings
} from "./chunk-2DDCINQV.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/nuclei-findings-persistence.ts
import { eq, desc, and, sql } from "drizzle-orm";
import crypto from "crypto";
function generateFindingHash(target, templateId, matchedAt, severity) {
  const input = `${target}|${templateId}|${matchedAt}|${severity}`;
  return crypto.createHash("sha256").update(input).digest("hex").slice(0, 16);
}
async function persistNucleiFindings(params) {
  const { engagementId, target, port, parseResult, accessLevel, confidence, executionContext, nucleiCommand } = params;
  if (!parseResult.findings || parseResult.findings.length === 0) {
    return { inserted: 0, duplicates: 0 };
  }
  const db = await getDb();
  if (!db) {
    console.warn("[NucleiPersistence] DB not available \u2014 skipping persistence");
    return { inserted: 0, duplicates: 0 };
  }
  let inserted = 0;
  let duplicates = 0;
  for (const finding of parseResult.findings) {
    const hash = generateFindingHash(
      target,
      finding.info?.id || finding["template-id"] || "unknown",
      finding["matched-at"] || finding.host || target,
      finding.info?.severity || "unknown"
    );
    try {
      const existing = await db.select({ id: nucleiFindings.id }).from(nucleiFindings).where(eq(nucleiFindings.findingHash, hash)).limit(1);
      if (existing.length > 0) {
        duplicates++;
        continue;
      }
      const cveId = finding.info?.classification?.["cve-id"]?.[0] || null;
      const cweIds = finding.info?.classification?.["cwe-id"] || null;
      await db.insert(nucleiFindings).values({
        scanId: engagementId || 0,
        templateId: finding.info?.id || finding["template-id"] || "unknown",
        templateName: finding.info?.name || null,
        severity: finding.info?.severity || "unknown",
        findingType: finding.type || null,
        host: finding.host || target,
        matchedAt: finding["matched-at"] || null,
        extractedResults: finding["extracted-results"] ? JSON.stringify(finding["extracted-results"]) : null,
        curlCommand: finding["curl-command"] || null,
        description: finding.info?.description || null,
        reference: finding.info?.reference ? JSON.stringify(finding.info.reference) : null,
        tags: finding.info?.tags ? finding.info.tags.join(",") : null,
        cveId,
        cweId: cweIds?.[0] || null,
        engagementId: engagementId || null,
        // Enhanced columns
        accessLevel: accessLevel || null,
        confidence: confidence || null,
        executionContext,
        nucleiCommand: nucleiCommand || null,
        findingHash: hash,
        port: port || null,
        nucleiVerified: 1
      });
      inserted++;
    } catch (err) {
      console.warn(`[NucleiPersistence] Failed to insert finding: ${err.message}`);
    }
  }
  if (inserted > 0) {
    console.log(
      `[NucleiPersistence] Persisted ${inserted} findings (${duplicates} duplicates skipped) for ${target}:${port || "?"} [${executionContext}]`
    );
  }
  return { inserted, duplicates };
}
async function recordTemplateMapping(params) {
  const { cveId, templatePath, vulnClass, service, discoveredFrom } = params;
  const now = Date.now();
  const db = await getDb();
  if (!db) {
    console.warn("[NucleiPersistence] DB not available \u2014 skipping template mapping");
    return;
  }
  try {
    const existing = await db.select().from(nucleiTemplateMappings).where(and(
      eq(nucleiTemplateMappings.cveId, cveId),
      eq(nucleiTemplateMappings.templatePath, templatePath)
    )).limit(1);
    if (existing.length > 0) {
      await db.update(nucleiTemplateMappings).set({
        successCount: sql`${nucleiTemplateMappings.successCount} + 1`,
        lastUsedAt: now
      }).where(eq(nucleiTemplateMappings.id, existing[0].id));
    } else {
      await db.insert(nucleiTemplateMappings).values({
        cveId,
        templatePath,
        vulnClass: vulnClass || null,
        service: service || null,
        successCount: 1,
        lastUsedAt: now,
        discoveredFrom: discoveredFrom || "exploit_success",
        createdAt: now
      });
    }
    console.log(`[NucleiPersistence] Recorded template mapping: ${cveId} \u2192 ${templatePath}`);
  } catch (err) {
    console.warn(`[NucleiPersistence] Failed to record template mapping: ${err.message}`);
  }
}
async function getNucleiFindings(engagementId) {
  const db = await getDb();
  if (!db) return [];
  const rows = await db.select().from(nucleiFindings).where(eq(nucleiFindings.engagementId, engagementId)).orderBy(desc(nucleiFindings.id));
  return rows.map((r) => ({
    id: r.id,
    templateId: r.templateId,
    templateName: r.templateName,
    severity: r.severity,
    cveId: r.cveId,
    host: r.host,
    matchedAt: r.matchedAt,
    accessLevel: r.accessLevel,
    confidence: r.confidence,
    executionContext: r.executionContext,
    nucleiVerified: r.nucleiVerified,
    createdAt: r.createdAt
  }));
}
async function getNucleiStats(engagementId) {
  const db = await getDb();
  if (!db) return { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, verified: 0, uniqueCves: 0, uniqueTemplates: 0 };
  const rows = await db.select().from(nucleiFindings).where(eq(nucleiFindings.engagementId, engagementId));
  const cves = /* @__PURE__ */ new Set();
  const templates = /* @__PURE__ */ new Set();
  let critical = 0, high = 0, medium = 0, low = 0, info = 0, verified = 0;
  for (const r of rows) {
    if (r.cveId) cves.add(r.cveId);
    templates.add(r.templateId);
    if (r.nucleiVerified) verified++;
    switch (r.severity) {
      case "critical":
        critical++;
        break;
      case "high":
        high++;
        break;
      case "medium":
        medium++;
        break;
      case "low":
        low++;
        break;
      case "info":
        info++;
        break;
    }
  }
  return {
    total: rows.length,
    critical,
    high,
    medium,
    low,
    info,
    verified,
    uniqueCves: cves.size,
    uniqueTemplates: templates.size
  };
}
async function correlateByCV(cveId) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(nucleiFindings).where(eq(nucleiFindings.cveId, cveId));
  if (rows.length === 0) return null;
  const engagements = /* @__PURE__ */ new Set();
  const severities = /* @__PURE__ */ new Set();
  const targets = /* @__PURE__ */ new Set();
  let firstSeen = rows[0].createdAt;
  let lastSeen = rows[0].createdAt;
  for (const r of rows) {
    if (r.engagementId) engagements.add(r.engagementId);
    severities.add(r.severity);
    targets.add(r.host);
    if (r.createdAt < firstSeen) firstSeen = r.createdAt;
    if (r.createdAt > lastSeen) lastSeen = r.createdAt;
  }
  return {
    cveId,
    templateId: rows[0].templateId,
    totalFindings: rows.length,
    engagements: engagements.size,
    severities: [...severities],
    targets: [...targets],
    firstSeen,
    lastSeen
  };
}
async function correlateByTemplate(templateId) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(nucleiFindings).where(eq(nucleiFindings.templateId, templateId));
  if (rows.length === 0) return null;
  const engagements = /* @__PURE__ */ new Set();
  const severities = /* @__PURE__ */ new Set();
  const targets = /* @__PURE__ */ new Set();
  let firstSeen = rows[0].createdAt;
  let lastSeen = rows[0].createdAt;
  for (const r of rows) {
    if (r.engagementId) engagements.add(r.engagementId);
    severities.add(r.severity);
    targets.add(r.host);
    if (r.createdAt < firstSeen) firstSeen = r.createdAt;
    if (r.createdAt > lastSeen) lastSeen = r.createdAt;
  }
  return {
    cveId: rows[0].cveId || templateId,
    templateId,
    totalFindings: rows.length,
    engagements: engagements.size,
    severities: [...severities],
    targets: [...targets],
    firstSeen,
    lastSeen
  };
}
async function lookupDynamicTemplateMapping(cveId) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(nucleiTemplateMappings).where(eq(nucleiTemplateMappings.cveId, cveId)).orderBy(desc(nucleiTemplateMappings.successCount)).limit(1);
  return rows.length > 0 ? rows[0].templatePath : null;
}
async function getAllTemplateMappings() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(nucleiTemplateMappings).orderBy(desc(nucleiTemplateMappings.successCount));
}
async function getTemplateEffectiveness(limit = 20) {
  const db = await getDb();
  if (!db) return [];
  const rows = await db.select().from(nucleiTemplateMappings).orderBy(desc(nucleiTemplateMappings.successCount)).limit(limit);
  if (rows.length === 0) return [];
  const maxSuccess = Math.max(...rows.map((r) => r.successCount ?? 1));
  return rows.map((r) => ({
    templatePath: r.templatePath,
    cveId: r.cveId,
    vulnClass: r.vulnClass,
    service: r.service,
    successCount: r.successCount ?? 1,
    lastUsedAt: r.lastUsedAt ?? 0,
    discoveredFrom: r.discoveredFrom,
    hitRate: maxSuccess > 0 ? (r.successCount ?? 1) / maxSuccess : 1
  }));
}
async function getTopTemplates(n = 10) {
  return getTemplateEffectiveness(n);
}
async function getTemplateEffectivenessStats() {
  const all = await getTemplateEffectiveness(100);
  const byCveId = {};
  const byVulnClass = {};
  let totalSuccesses = 0;
  for (const t of all) {
    byCveId[t.cveId] = t;
    totalSuccesses += t.successCount;
    if (t.vulnClass) {
      if (!byVulnClass[t.vulnClass]) byVulnClass[t.vulnClass] = [];
      byVulnClass[t.vulnClass].push(t);
    }
  }
  return {
    totalMappings: all.length,
    totalSuccesses,
    topTemplates: all.slice(0, 10),
    byCveId,
    byVulnClass
  };
}
async function getTemplateHistory(templatePath) {
  const db = await getDb();
  if (!db) return [];
  const rows = await db.select().from(nucleiFindings).where(eq(nucleiFindings.templateId, templatePath)).orderBy(desc(nucleiFindings.id));
  return rows.map((r) => ({
    id: r.id,
    templateId: r.templateId,
    templateName: r.templateName,
    severity: r.severity,
    cveId: r.cveId,
    host: r.host,
    matchedAt: r.matchedAt,
    accessLevel: r.accessLevel,
    confidence: r.confidence,
    executionContext: r.executionContext,
    nucleiVerified: r.nucleiVerified,
    createdAt: r.createdAt
  }));
}
var init_nuclei_findings_persistence = __esm({
  "server/lib/nuclei-findings-persistence.ts"() {
    init_db();
    init_schema();
  }
});
init_nuclei_findings_persistence();
export {
  correlateByCV,
  correlateByTemplate,
  generateFindingHash,
  getAllTemplateMappings,
  getNucleiFindings,
  getNucleiStats,
  getTemplateEffectiveness,
  getTemplateEffectivenessStats,
  getTemplateHistory,
  getTopTemplates,
  lookupDynamicTemplateMapping,
  persistNucleiFindings,
  recordTemplateMapping
};
