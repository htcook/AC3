/**
 * DNS Security Persistence Module
 * 
 * Persists DNS security assessment results to dedicated database tables,
 * enabling historical tracking, change detection, and monitoring.
 */
import { eq, desc, and, sql } from "drizzle-orm";
import { getDb } from "../db";
import { dnsSecurityAssessments, dnsSecurityFindings, dnsSecurityMonitoringConfig } from "../../drizzle/schema";
import type { DnsSecurityReport, DnsFinding } from "./dns-security-validator";

export interface PersistDnsAssessmentInput {
  domain: string;
  scanId?: number;
  engagementId?: number;
  report: DnsSecurityReport;
}

export interface DnsChangeDetection {
  newFindings: DnsFinding[];
  resolvedFindings: string[]; // finding IDs that were in previous but not current
  riskChanged: boolean;
  previousRisk: string | null;
  currentRisk: string;
  recordChanges: {
    added: Array<{ type: string; name: string; value: string }>;
    removed: Array<{ type: string; name: string; value: string }>;
    modified: Array<{ type: string; name: string; oldValue: string; newValue: string }>;
  };
}

/**
 * Persist a DNS security assessment to the database.
 * Automatically detects changes from the previous assessment for the same domain.
 */
export async function persistDnsSecurityAssessment(input: PersistDnsAssessmentInput): Promise<{
  assessmentId: number;
  changes: DnsChangeDetection | null;
}> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const { domain, scanId, engagementId, report } = input;

  // Fetch previous assessment for change detection
  const previousAssessments = await db.select()
    .from(dnsSecurityAssessments)
    .where(eq(dnsSecurityAssessments.domain, domain))
    .orderBy(desc(dnsSecurityAssessments.assessedAt))
    .limit(1);

  const previous = previousAssessments[0] || null;
  let changes: DnsChangeDetection | null = null;

  if (previous) {
    changes = detectChanges(previous, report);
  }

  // Insert the assessment record
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
    changesSinceLastJson: changes,
  });

  const assessmentId = insertResult[0].insertId;

  // Insert individual findings
  if (report.findings.length > 0) {
    const findingValues = report.findings.map(f => ({
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
      status: "open",
    }));

    // Batch insert in chunks of 50
    for (let i = 0; i < findingValues.length; i += 50) {
      const batch = findingValues.slice(i, i + 50);
      await db.insert(dnsSecurityFindings).values(batch);
    }
  }

  // Mark resolved findings from previous assessment
  if (changes && changes.resolvedFindings.length > 0 && previous) {
    for (const findingId of changes.resolvedFindings) {
      await db.update(dnsSecurityFindings)
        .set({ status: "resolved", resolvedAt: sql`NOW()` })
        .where(
          and(
            eq(dnsSecurityFindings.assessmentId, previous.id),
            eq(dnsSecurityFindings.findingId, findingId)
          )
        );
    }
  }

  return { assessmentId, changes };
}

/**
 * Detect changes between the previous assessment and the current report.
 */
function detectChanges(previous: any, current: DnsSecurityReport): DnsChangeDetection {
  const prevReport = previous.reportJson as DnsSecurityReport | null;
  const prevFindings = prevReport?.findings || [];
  const currentFindings = current.findings;

  // Find new findings (in current but not in previous)
  const prevFindingIds = new Set(prevFindings.map(f => f.id));
  const currentFindingIds = new Set(currentFindings.map(f => f.id));
  
  const newFindings = currentFindings.filter(f => !prevFindingIds.has(f.id));
  const resolvedFindings = prevFindings
    .filter(f => !currentFindingIds.has(f.id))
    .map(f => f.id);

  // Detect risk level change
  const previousRisk = previous.overallRisk;
  const currentRisk = current.summary.overallRisk;
  const riskChanged = previousRisk !== currentRisk;

  // Detect DNS record changes
  const prevRecords = prevReport?.records || [];
  const currentRecords = current.records;
  const recordChanges = detectRecordChanges(prevRecords, currentRecords);

  return {
    newFindings,
    resolvedFindings,
    riskChanged,
    previousRisk,
    currentRisk,
    recordChanges,
  };
}

/**
 * Compare DNS records between two assessments to detect additions, removals, and modifications.
 */
function detectRecordChanges(
  prevRecords: Array<{ type: string; name: string; value: string; ttl?: number }>,
  currentRecords: Array<{ type: string; name: string; value: string; ttl?: number }>
): DnsChangeDetection["recordChanges"] {
  const prevKey = (r: { type: string; name: string; value: string }) => `${r.type}:${r.name}:${r.value}`;
  const prevSet = new Map(prevRecords.map(r => [prevKey(r), r]));
  const currSet = new Map(currentRecords.map(r => [prevKey(r), r]));

  const added: Array<{ type: string; name: string; value: string }> = [];
  const removed: Array<{ type: string; name: string; value: string }> = [];
  const modified: Array<{ type: string; name: string; oldValue: string; newValue: string }> = [];

  // Find added records
  for (const [key, record] of currSet) {
    if (!prevSet.has(key)) {
      added.push({ type: record.type, name: record.name, value: record.value });
    }
  }

  // Find removed records
  for (const [key, record] of prevSet) {
    if (!currSet.has(key)) {
      removed.push({ type: record.type, name: record.name, value: record.value });
    }
  }

  // Detect value changes for same type+name combinations
  const prevByTypeName = new Map<string, string[]>();
  const currByTypeName = new Map<string, string[]>();
  
  for (const r of prevRecords) {
    const k = `${r.type}:${r.name}`;
    if (!prevByTypeName.has(k)) prevByTypeName.set(k, []);
    prevByTypeName.get(k)!.push(r.value);
  }
  for (const r of currentRecords) {
    const k = `${r.type}:${r.name}`;
    if (!currByTypeName.has(k)) currByTypeName.set(k, []);
    currByTypeName.get(k)!.push(r.value);
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

/**
 * Get the assessment history for a domain.
 */
export async function getDnsAssessmentHistory(domain: string, limit = 20): Promise<any[]> {
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
    assessedAt: dnsSecurityAssessments.assessedAt,
  })
    .from(dnsSecurityAssessments)
    .where(eq(dnsSecurityAssessments.domain, domain))
    .orderBy(desc(dnsSecurityAssessments.assessedAt))
    .limit(limit);
}

/**
 * Get the latest assessment for a domain (full report JSON).
 */
export async function getLatestDnsAssessment(domain: string): Promise<any | null> {
  const db = await getDb();
  if (!db) return null;
  const results = await db.select()
    .from(dnsSecurityAssessments)
    .where(eq(dnsSecurityAssessments.domain, domain))
    .orderBy(desc(dnsSecurityAssessments.assessedAt))
    .limit(1);
  return results[0] || null;
}

/**
 * Get all open findings for a domain across all assessments.
 */
export async function getOpenDnsFindings(domain: string): Promise<any[]> {
  const db = await getDb();
  if (!db) return [];
  
  // Get latest assessment ID for this domain
  const latest = await getLatestDnsAssessment(domain);
  if (!latest) return [];

  return db.select()
    .from(dnsSecurityFindings)
    .where(
      and(
        eq(dnsSecurityFindings.assessmentId, latest.id),
        eq(dnsSecurityFindings.status, "open")
      )
    )
    .orderBy(desc(dnsSecurityFindings.createdAt));
}

/**
 * Get or create monitoring config for a domain.
 */
export async function getOrCreateMonitoringConfig(domain: string): Promise<any> {
  const db = await getDb();
  if (!db) return null;

  const existing = await db.select()
    .from(dnsSecurityMonitoringConfig)
    .where(eq(dnsSecurityMonitoringConfig.domain, domain))
    .limit(1);

  if (existing.length > 0) return existing[0];

  // Create default config
  await db.insert(dnsSecurityMonitoringConfig).values({
    domain,
    enabled: 1,
    intervalHours: 24,
    alertOnNewCritical: 1,
    alertOnNewHigh: 1,
    alertOnDnsChange: 1,
  });

  const created = await db.select()
    .from(dnsSecurityMonitoringConfig)
    .where(eq(dnsSecurityMonitoringConfig.domain, domain))
    .limit(1);
  return created[0] || null;
}

/**
 * Update monitoring config for a domain.
 */
export async function updateMonitoringConfig(domain: string, updates: {
  enabled?: boolean;
  intervalHours?: number;
  alertOnNewCritical?: boolean;
  alertOnNewHigh?: boolean;
  alertOnDnsChange?: boolean;
}): Promise<void> {
  const db = await getDb();
  if (!db) return;

  const setValues: any = {};
  if (updates.enabled !== undefined) setValues.enabled = updates.enabled ? 1 : 0;
  if (updates.intervalHours !== undefined) setValues.intervalHours = updates.intervalHours;
  if (updates.alertOnNewCritical !== undefined) setValues.alertOnNewCritical = updates.alertOnNewCritical ? 1 : 0;
  if (updates.alertOnNewHigh !== undefined) setValues.alertOnNewHigh = updates.alertOnNewHigh ? 1 : 0;
  if (updates.alertOnDnsChange !== undefined) setValues.alertOnDnsChange = updates.alertOnDnsChange ? 1 : 0;

  await db.update(dnsSecurityMonitoringConfig)
    .set(setValues)
    .where(eq(dnsSecurityMonitoringConfig.domain, domain));
}

/**
 * Get all domains configured for monitoring.
 */
export async function getMonitoredDomains(): Promise<any[]> {
  const db = await getDb();
  if (!db) return [];
  return db.select()
    .from(dnsSecurityMonitoringConfig)
    .where(eq(dnsSecurityMonitoringConfig.enabled, 1));
}

/**
 * Mark a domain's monitoring as checked (update lastCheckedAt).
 */
export async function markDomainChecked(domain: string): Promise<void> {
  const db = await getDb();
  if (!db) return;
  await db.update(dnsSecurityMonitoringConfig)
    .set({ lastCheckedAt: sql`NOW()` })
    .where(eq(dnsSecurityMonitoringConfig.domain, domain));
}
