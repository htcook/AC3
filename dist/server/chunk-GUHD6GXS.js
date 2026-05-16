import {
  getDb,
  init_db
} from "./chunk-RSFTEATL.js";
import {
  dnsSecurityAssessments,
  dnsSecurityFindings,
  dnsSecurityMonitoringConfig,
  init_schema
} from "./chunk-L4JENJ4Z.js";

// server/lib/dns-security-persistence.ts
init_db();
init_schema();
import { eq, desc, and, sql } from "drizzle-orm";
async function persistDnsSecurityAssessment(input) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const { domain, scanId, engagementId, report } = input;
  const previousAssessments = await db.select().from(dnsSecurityAssessments).where(eq(dnsSecurityAssessments.domain, domain)).orderBy(desc(dnsSecurityAssessments.assessedAt)).limit(1);
  const previous = previousAssessments[0] || null;
  let changes = null;
  if (previous) {
    changes = detectChanges(previous, report);
  }
  const insertResult = await db.insert(dnsSecurityAssessments).values({
    domain,
    engagementId: engagementId ?? null,
    scanId: scanId ?? null,
    context: report.context || "di_scan",
    overallRisk: report.summary.overallRisk,
    totalFindings: report.summary.totalFindings,
    criticalCount: report.summary.critical,
    highCount: report.summary.high,
    mediumCount: report.summary.medium,
    lowCount: report.summary.low,
    infoCount: report.summary.info,
    totalChecks: report.summary.totalChecks,
    passedChecks: report.summary.passedChecks,
    failedChecks: report.summary.failedChecks,
    dnssecEnabled: report.dnssec.enabled ? 1 : 0,
    dnssecChainValid: report.dnssec.chainOfTrustValid ? 1 : 0,
    responseTimeMs: report.metadata?.responseTimeMs ?? null,
    reportJson: report,
    previousAssessmentId: previous?.id ?? null,
    changesSinceLastJson: changes
  });
  const assessmentId = insertResult[0].insertId;
  if (report.findings.length > 0) {
    const findingValues = report.findings.map((f) => ({
      assessmentId,
      findingId: f.id,
      severity: f.severity,
      category: f.category,
      title: f.title,
      description: f.description || null,
      affectedRecord: f.affectedRecord || null,
      evidence: f.evidence || null,
      remediation: f.remediation || null,
      mitreAttackId: f.mitreAttackId || null,
      cvssScore: f.cvssScore?.toString() || null,
      cvssVector: f.cvssVector || null,
      cwe: f.cwe || null,
      references: f.references || null,
      status: "open"
    }));
    for (let i = 0; i < findingValues.length; i += 50) {
      const batch = findingValues.slice(i, i + 50);
      await db.insert(dnsSecurityFindings).values(batch);
    }
  }
  if (changes && changes.resolvedFindings.length > 0 && previous) {
    for (const findingId of changes.resolvedFindings) {
      await db.update(dnsSecurityFindings).set({ status: "resolved", resolvedAt: sql`NOW()` }).where(
        and(
          eq(dnsSecurityFindings.assessmentId, previous.id),
          eq(dnsSecurityFindings.findingId, findingId)
        )
      );
    }
  }
  return { assessmentId, changes };
}
function detectChanges(previous, current) {
  const prevReport = previous.reportJson;
  const prevFindings = prevReport?.findings || [];
  const currentFindings = current.findings;
  const prevFindingIds = new Set(prevFindings.map((f) => f.id));
  const currentFindingIds = new Set(currentFindings.map((f) => f.id));
  const newFindings = currentFindings.filter((f) => !prevFindingIds.has(f.id));
  const resolvedFindings = prevFindings.filter((f) => !currentFindingIds.has(f.id)).map((f) => f.id);
  const previousRisk = previous.overallRisk;
  const currentRisk = current.summary.overallRisk;
  const riskChanged = previousRisk !== currentRisk;
  const prevRecords = prevReport?.records || [];
  const currentRecords = current.records;
  const recordChanges = detectRecordChanges(prevRecords, currentRecords);
  return {
    newFindings,
    resolvedFindings,
    riskChanged,
    previousRisk,
    currentRisk,
    recordChanges
  };
}
function detectRecordChanges(prevRecords, currentRecords) {
  const prevKey = (r) => `${r.type}:${r.name}:${r.value}`;
  const prevSet = new Map(prevRecords.map((r) => [prevKey(r), r]));
  const currSet = new Map(currentRecords.map((r) => [prevKey(r), r]));
  const added = [];
  const removed = [];
  const modified = [];
  for (const [key, record] of currSet) {
    if (!prevSet.has(key)) {
      added.push({ type: record.type, name: record.name, value: record.value });
    }
  }
  for (const [key, record] of prevSet) {
    if (!currSet.has(key)) {
      removed.push({ type: record.type, name: record.name, value: record.value });
    }
  }
  const prevByTypeName = /* @__PURE__ */ new Map();
  const currByTypeName = /* @__PURE__ */ new Map();
  for (const r of prevRecords) {
    const k = `${r.type}:${r.name}`;
    if (!prevByTypeName.has(k)) prevByTypeName.set(k, []);
    prevByTypeName.get(k).push(r.value);
  }
  for (const r of currentRecords) {
    const k = `${r.type}:${r.name}`;
    if (!currByTypeName.has(k)) currByTypeName.set(k, []);
    currByTypeName.get(k).push(r.value);
  }
  for (const [key, prevValues] of prevByTypeName) {
    const currValues = currByTypeName.get(key);
    if (currValues && prevValues.length === 1 && currValues.length === 1 && prevValues[0] !== currValues[0]) {
      const [type, name] = key.split(":");
      modified.push({ type, name, oldValue: prevValues[0], newValue: currValues[0] });
    }
  }
  return { added, removed, modified };
}
async function getDnsAssessmentHistory(domain, limit = 20) {
  const db = await getDb();
  if (!db) return [];
  return db.select({
    id: dnsSecurityAssessments.id,
    domain: dnsSecurityAssessments.domain,
    overallRisk: dnsSecurityAssessments.overallRisk,
    totalFindings: dnsSecurityAssessments.totalFindings,
    criticalCount: dnsSecurityAssessments.criticalCount,
    highCount: dnsSecurityAssessments.highCount,
    mediumCount: dnsSecurityAssessments.mediumCount,
    lowCount: dnsSecurityAssessments.lowCount,
    dnssecEnabled: dnsSecurityAssessments.dnssecEnabled,
    responseTimeMs: dnsSecurityAssessments.responseTimeMs,
    changesSinceLastJson: dnsSecurityAssessments.changesSinceLastJson,
    assessedAt: dnsSecurityAssessments.assessedAt
  }).from(dnsSecurityAssessments).where(eq(dnsSecurityAssessments.domain, domain)).orderBy(desc(dnsSecurityAssessments.assessedAt)).limit(limit);
}
async function getLatestDnsAssessment(domain) {
  const db = await getDb();
  if (!db) return null;
  const results = await db.select().from(dnsSecurityAssessments).where(eq(dnsSecurityAssessments.domain, domain)).orderBy(desc(dnsSecurityAssessments.assessedAt)).limit(1);
  return results[0] || null;
}
async function getOpenDnsFindings(domain) {
  const db = await getDb();
  if (!db) return [];
  const latest = await getLatestDnsAssessment(domain);
  if (!latest) return [];
  return db.select().from(dnsSecurityFindings).where(
    and(
      eq(dnsSecurityFindings.assessmentId, latest.id),
      eq(dnsSecurityFindings.status, "open")
    )
  ).orderBy(desc(dnsSecurityFindings.createdAt));
}
async function getOrCreateMonitoringConfig(domain) {
  const db = await getDb();
  if (!db) return null;
  const existing = await db.select().from(dnsSecurityMonitoringConfig).where(eq(dnsSecurityMonitoringConfig.domain, domain)).limit(1);
  if (existing.length > 0) return existing[0];
  await db.insert(dnsSecurityMonitoringConfig).values({
    domain,
    enabled: 1,
    intervalHours: 24,
    alertOnNewCritical: 1,
    alertOnNewHigh: 1,
    alertOnDnsChange: 1
  });
  const created = await db.select().from(dnsSecurityMonitoringConfig).where(eq(dnsSecurityMonitoringConfig.domain, domain)).limit(1);
  return created[0] || null;
}
async function updateMonitoringConfig(domain, updates) {
  const db = await getDb();
  if (!db) return;
  const setValues = {};
  if (updates.enabled !== void 0) setValues.enabled = updates.enabled ? 1 : 0;
  if (updates.intervalHours !== void 0) setValues.intervalHours = updates.intervalHours;
  if (updates.alertOnNewCritical !== void 0) setValues.alertOnNewCritical = updates.alertOnNewCritical ? 1 : 0;
  if (updates.alertOnNewHigh !== void 0) setValues.alertOnNewHigh = updates.alertOnNewHigh ? 1 : 0;
  if (updates.alertOnDnsChange !== void 0) setValues.alertOnDnsChange = updates.alertOnDnsChange ? 1 : 0;
  await db.update(dnsSecurityMonitoringConfig).set(setValues).where(eq(dnsSecurityMonitoringConfig.domain, domain));
}
async function getMonitoredDomains() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(dnsSecurityMonitoringConfig).where(eq(dnsSecurityMonitoringConfig.enabled, 1));
}
async function markDomainChecked(domain) {
  const db = await getDb();
  if (!db) return;
  await db.update(dnsSecurityMonitoringConfig).set({ lastCheckedAt: sql`NOW()` }).where(eq(dnsSecurityMonitoringConfig.domain, domain));
}

export {
  persistDnsSecurityAssessment,
  getDnsAssessmentHistory,
  getLatestDnsAssessment,
  getOpenDnsFindings,
  getOrCreateMonitoringConfig,
  updateMonitoringConfig,
  getMonitoredDomains,
  markDomainChecked
};
