/**
 * CSPM Database Persistence Layer
 *
 * Stores Prowler, ScoutSuite, and Trivy scan results in the database
 * for historical tracking, trend analysis, and compliance reporting.
 */

import { getDb } from "../db";
import { cspmScanRuns, cspmFindings, containerVulnerabilities } from "../../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";
import type { ProwlerFinding, ProwlerScanResult } from "../routers/prowler-integration";

// ── Types ──────────────────────────────────────────────────────────────────

export interface CreateScanRunParams {
  credentialId?: number;
  engagementId?: number;
  scanTool: "prowler" | "scoutsuite" | "trivy";
  scanProvider: string;
  scanScope?: any;
  triggeredBy?: string;
  complianceFramework?: string;
}

export interface StoreFindingsParams {
  scanRunId: number;
  scanTool: "prowler" | "scoutsuite" | "trivy";
  findings: ProwlerFinding[];
  provider: string;
}

export interface StoreContainerVulnsParams {
  scanRunId: number;
  imageName: string;
  imageTag?: string;
  imageDigest?: string;
  vulnerabilities: Array<{
    vulnId: string;
    severity: string;
    pkgName: string;
    installedVersion?: string;
    fixedVersion?: string;
    title?: string;
    description?: string;
    primaryUrl?: string;
    dataSource?: string;
    publishedDate?: string;
    cvssScore?: string;
  }>;
}

// ── Scan Run CRUD ──────────────────────────────────────────────────────────

export async function createScanRun(params: CreateScanRunParams) {
  const db = await getDb();
  if (!db) return null;

  const now = Date.now();
  const result = await db.insert(cspmScanRuns).values({
    credentialId: params.credentialId ?? null,
    engagementId: params.engagementId ?? null,
    scanTool: params.scanTool,
    scanProvider: params.scanProvider as any,
    scanStatus: "running",
    scanScope: params.scanScope ?? null,
    complianceFramework: params.complianceFramework ?? null,
    triggeredBy: params.triggeredBy ?? null,
    scanStartedAt: now,
    createdAt: now,
  });

  const insertId = (result as any)[0]?.insertId;
  return insertId as number;
}

export async function completeScanRun(
  scanRunId: number,
  result: ProwlerScanResult,
  status: "completed" | "error" = "completed"
) {
  const db = await getDb();
  if (!db) return;

  const severityCounts = {
    criticalCount: result.findings.filter(f => f.severity === "critical").length,
    highCount: result.findings.filter(f => f.severity === "high").length,
    mediumCount: result.findings.filter(f => f.severity === "medium").length,
    lowCount: result.findings.filter(f => f.severity === "low").length,
    infoCount: result.findings.filter(f => f.severity === "informational").length,
  };

  const passCount = result.findings.filter(f => f.status === "PASS").length;
  const failCount = result.findings.filter(f => f.status === "FAIL").length;
  const total = passCount + failCount;
  const complianceScore = total > 0 ? Math.round((passCount / total) * 100) : null;

  await db.update(cspmScanRuns)
    .set({
      scanStatus: status,
      totalFindings: result.findings.length,
      ...severityCounts,
      passCount,
      failCount,
      complianceScore,
      scanDurationMs: result.durationMs,
      errorMessage: result.errors.length > 0 ? result.errors.join("\n") : null,
      scanCompletedAt: Date.now(),
    })
    .where(eq(cspmScanRuns.id, scanRunId));
}

export async function failScanRun(scanRunId: number, errorMessage: string) {
  const db = await getDb();
  if (!db) return;

  await db.update(cspmScanRuns)
    .set({
      scanStatus: "error",
      errorMessage,
      scanCompletedAt: Date.now(),
    })
    .where(eq(cspmScanRuns.id, scanRunId));
}

// ── Store Findings ─────────────────────────────────────────────────────────

function mapSeverityToDb(s: string): "critical" | "high" | "medium" | "low" | "info" {
  const lower = s.toLowerCase();
  if (lower === "critical") return "critical";
  if (lower === "high") return "high";
  if (lower === "medium") return "medium";
  if (lower === "low") return "low";
  return "info";
}

function mapStatusToDb(s: string): "fail" | "pass" | "warning" | "manual" | "not_available" {
  const upper = s.toUpperCase();
  if (upper === "PASS") return "pass";
  if (upper === "FAIL") return "fail";
  if (upper === "WARNING" || upper === "WARN") return "warning";
  return "not_available";
}

export async function storeFindings(params: StoreFindingsParams) {
  const db = await getDb();
  if (!db || params.findings.length === 0) return 0;

  const now = Date.now();
  const BATCH_SIZE = 100;
  let stored = 0;

  for (let i = 0; i < params.findings.length; i += BATCH_SIZE) {
    const batch = params.findings.slice(i, i + BATCH_SIZE);
    const values = batch.map(f => ({
      scanRunId: params.scanRunId,
      scanTool: params.scanTool,
      findingUid: f.checkId || null,
      severity: mapSeverityToDb(f.severity),
      status: mapStatusToDb(f.status),
      provider: params.provider,
      service: f.service || null,
      region: f.region || null,
      resourceArn: f.resourceArn || null,
      resourceName: f.resourceId || null,
      resourceType: null,
      checkId: f.checkId || null,
      checkTitle: f.checkTitle?.substring(0, 512) || null,
      description: f.description || null,
      riskDetails: f.risk || null,
      remediation: f.remediation || null,
      complianceFrameworks: f.complianceFrameworks.length > 0 ? f.complianceFrameworks : null,
      categories: null,
      rawFinding: null,
      createdAt: now,
    }));

    await db.insert(cspmFindings).values(values);
    stored += batch.length;
  }

  return stored;
}

// ── Store Container Vulnerabilities ────────────────────────────────────────

function mapContainerSeverity(s: string): "critical" | "high" | "medium" | "low" | "unknown" {
  const lower = s.toLowerCase();
  if (lower === "critical") return "critical";
  if (lower === "high") return "high";
  if (lower === "medium") return "medium";
  if (lower === "low") return "low";
  return "unknown";
}

export async function storeContainerVulnerabilities(params: StoreContainerVulnsParams) {
  const db = await getDb();
  if (!db || params.vulnerabilities.length === 0) return 0;

  const now = Date.now();
  const BATCH_SIZE = 100;
  let stored = 0;

  for (let i = 0; i < params.vulnerabilities.length; i += BATCH_SIZE) {
    const batch = params.vulnerabilities.slice(i, i + BATCH_SIZE);
    const values = batch.map(v => ({
      scanRunId: params.scanRunId,
      imageName: params.imageName,
      imageTag: params.imageTag ?? null,
      imageDigest: params.imageDigest ?? null,
      vulnId: v.vulnId,
      severity: mapContainerSeverity(v.severity),
      pkgName: v.pkgName,
      installedVersion: v.installedVersion ?? null,
      fixedVersion: v.fixedVersion ?? null,
      title: v.title ?? null,
      description: v.description ?? null,
      primaryUrl: v.primaryUrl ?? null,
      dataSource: v.dataSource ?? null,
      publishedDate: v.publishedDate ?? null,
      cvssScore: v.cvssScore ?? null,
      createdAt: now,
    }));

    await db.insert(containerVulnerabilities).values(values);
    stored += batch.length;
  }

  return stored;
}

// ── Query Helpers ──────────────────────────────────────────────────────────

export async function getScanRuns(opts: {
  tool?: "prowler" | "scoutsuite" | "trivy";
  provider?: string;
  limit?: number;
}) {
  const db = await getDb();
  if (!db) return [];

  const conditions = [];
  if (opts.tool) conditions.push(eq(cspmScanRuns.scanTool, opts.tool));
  if (opts.provider) conditions.push(eq(cspmScanRuns.scanProvider, opts.provider as any));

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  return db.select().from(cspmScanRuns)
    .where(where)
    .orderBy(desc(cspmScanRuns.createdAt))
    .limit(opts.limit ?? 50);
}

export async function getScanRunById(id: number) {
  const db = await getDb();
  if (!db) return null;

  const rows = await db.select().from(cspmScanRuns).where(eq(cspmScanRuns.id, id)).limit(1);
  return rows[0] ?? null;
}

export async function getFindingsForRun(scanRunId: number, opts?: {
  severity?: string;
  status?: string;
  limit?: number;
}) {
  const db = await getDb();
  if (!db) return [];

  const conditions = [eq(cspmFindings.scanRunId, scanRunId)];
  if (opts?.severity) conditions.push(eq(cspmFindings.severity, opts.severity as any));
  if (opts?.status) conditions.push(eq(cspmFindings.status, opts.status as any));

  return db.select().from(cspmFindings)
    .where(and(...conditions))
    .orderBy(desc(cspmFindings.severity))
    .limit(opts?.limit ?? 500);
}

export async function getContainerVulnsForRun(scanRunId: number, opts?: {
  severity?: string;
  limit?: number;
}) {
  const db = await getDb();
  if (!db) return [];

  const conditions = [eq(containerVulnerabilities.scanRunId, scanRunId)];
  if (opts?.severity) conditions.push(eq(containerVulnerabilities.severity, opts.severity as any));

  return db.select().from(containerVulnerabilities)
    .where(and(...conditions))
    .orderBy(desc(containerVulnerabilities.severity))
    .limit(opts?.limit ?? 500);
}

export async function getScanRunStats() {
  const db = await getDb();
  if (!db) return null;

  const [totals] = await db.select({
    totalRuns: sql<number>`COUNT(*)`,
    completedRuns: sql<number>`SUM(CASE WHEN scan_status = 'completed' THEN 1 ELSE 0 END)`,
    totalFindings: sql<number>`SUM(total_findings)`,
    totalCritical: sql<number>`SUM(critical_count)`,
    totalHigh: sql<number>`SUM(high_count)`,
    avgComplianceScore: sql<number>`AVG(compliance_score)`,
  }).from(cspmScanRuns);

  return totals;
}
