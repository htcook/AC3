/**
 * Nuclei Findings Persistence Layer
 * ──────────────────────────────────
 * Stores parsed Nuclei findings in the nuclei_findings DB table and
 * dynamic CVE→template mappings in nuclei_template_mappings.
 *
 * Three entry points:
 *   1. persistNucleiFindings()  — bulk-insert parsed findings after direct execution or verification
 *   2. recordTemplateMappings() — auto-map successful CVE exploits to Nuclei templates
 *   3. Query helpers for cross-engagement correlation
 */

import { getDb } from '../db';
import { nucleiFindings, nucleiTemplateMappings } from '../../drizzle/schema';
import { eq, desc, and, sql, inArray } from 'drizzle-orm';
import type { NucleiParseResult, NucleiJsonFinding } from './nuclei-output-parser';
import crypto from 'crypto';

// ─── Types ──────────────────────────────────────────────────────────────────

export type ExecutionContext = 'direct' | 'verification' | 're_verification';

export interface PersistNucleiFindingsParams {
  engagementId?: number;
  target: string;
  port?: number;
  parseResult: NucleiParseResult;
  accessLevel?: string;
  confidence?: number;
  executionContext: ExecutionContext;
  nucleiCommand?: string;
}

export interface NucleiFindingRecord {
  id: number;
  templateId: string;
  templateName: string | null;
  severity: string;
  cveId: string | null;
  host: string;
  matchedAt: string | null;
  accessLevel: string | null;
  confidence: number | null;
  executionContext: string | null;
  nucleiVerified: number | null;
  createdAt: string;
}

export interface NucleiCorrelationResult {
  cveId: string;
  templateId: string;
  totalFindings: number;
  engagements: number;
  severities: string[];
  targets: string[];
  firstSeen: string;
  lastSeen: string;
}

// ─── Finding Hash ───────────────────────────────────────────────────────────

/**
 * Generate a dedup hash for a Nuclei finding.
 * Hash is based on: target + templateId + matchedAt + severity
 */
export function generateFindingHash(
  target: string,
  templateId: string,
  matchedAt: string,
  severity: string,
): string {
  const input = `${target}|${templateId}|${matchedAt}|${severity}`;
  return crypto.createHash('sha256').update(input).digest('hex').slice(0, 16);
}

// ─── Persist Findings ───────────────────────────────────────────────────────

/**
 * Bulk-insert parsed Nuclei findings into the nuclei_findings table.
 * Deduplicates by finding_hash to avoid storing the same finding twice.
 * Returns the number of new findings inserted.
 */
export async function persistNucleiFindings(
  params: PersistNucleiFindingsParams,
): Promise<{ inserted: number; duplicates: number }> {
  const { engagementId, target, port, parseResult, accessLevel, confidence, executionContext, nucleiCommand } = params;

  if (!parseResult.findings || parseResult.findings.length === 0) {
    return { inserted: 0, duplicates: 0 };
  }

  const db = await getDb();
  if (!db) {
    console.warn('[NucleiPersistence] DB not available — skipping persistence');
    return { inserted: 0, duplicates: 0 };
  }

  let inserted = 0;
  let duplicates = 0;

  for (const finding of parseResult.findings) {
    const hash = generateFindingHash(
      target,
      finding.info?.id || finding['template-id'] || 'unknown',
      finding['matched-at'] || finding.host || target,
      finding.info?.severity || 'unknown',
    );

    // Check for existing finding with same hash
    try {
      const existing = await db.select({ id: nucleiFindings.id })
        .from(nucleiFindings)
        .where(eq(nucleiFindings.findingHash, hash))
        .limit(1);

      if (existing.length > 0) {
        duplicates++;
        continue;
      }

      const cveId = finding.info?.classification?.['cve-id']?.[0] || null;
      const cweIds = finding.info?.classification?.['cwe-id'] || null;

      await db.insert(nucleiFindings).values({
        scanId: engagementId || 0,
        templateId: finding.info?.id || finding['template-id'] || 'unknown',
        templateName: finding.info?.name || null,
        severity: finding.info?.severity || 'unknown',
        findingType: finding.type || null,
        host: finding.host || target,
        matchedAt: finding['matched-at'] || null,
        extractedResults: finding['extracted-results'] ? JSON.stringify(finding['extracted-results']) : null,
        curlCommand: finding['curl-command'] || null,
        description: finding.info?.description || null,
        reference: finding.info?.reference ? JSON.stringify(finding.info.reference) : null,
        tags: finding.info?.tags ? finding.info.tags.join(',') : null,
        cveId: cveId,
        cweId: cweIds?.[0] || null,
        engagementId: engagementId || null,
        // Enhanced columns
        accessLevel: accessLevel || null,
        confidence: confidence || null,
        executionContext: executionContext,
        nucleiCommand: nucleiCommand || null,
        findingHash: hash,
        port: port || null,
        nucleiVerified: 1,
      });
      inserted++;
    } catch (err: any) {
      console.warn(`[NucleiPersistence] Failed to insert finding: ${err.message}`);
    }
  }

  if (inserted > 0) {
    console.log(
      `[NucleiPersistence] Persisted ${inserted} findings (${duplicates} duplicates skipped) ` +
      `for ${target}:${port || '?'} [${executionContext}]`
    );
  }

  return { inserted, duplicates };
}

// ─── Template Mapping Persistence ───────────────────────────────────────────

/**
 * Record a successful CVE→Nuclei template mapping.
 * If the mapping already exists, increment successCount and update lastUsedAt.
 */
export async function recordTemplateMapping(params: {
  cveId: string;
  templatePath: string;
  vulnClass?: string;
  service?: string;
  discoveredFrom?: 'exploit_success' | 'manual' | 'knowledge_store';
}): Promise<void> {
  const { cveId, templatePath, vulnClass, service, discoveredFrom } = params;
  const now = Date.now();

  const db = await getDb();
  if (!db) {
    console.warn('[NucleiPersistence] DB not available — skipping template mapping');
    return;
  }

  try {
    // Check if mapping already exists
    const existing = await db.select()
      .from(nucleiTemplateMappings)
      .where(and(
        eq(nucleiTemplateMappings.cveId, cveId),
        eq(nucleiTemplateMappings.templatePath, templatePath),
      ))
      .limit(1);

    if (existing.length > 0) {
      // Update existing mapping
      await db.update(nucleiTemplateMappings)
        .set({
          successCount: sql`${nucleiTemplateMappings.successCount} + 1`,
          lastUsedAt: now,
        })
        .where(eq(nucleiTemplateMappings.id, existing[0].id));
    } else {
      // Insert new mapping
      await db.insert(nucleiTemplateMappings).values({
        cveId,
        templatePath,
        vulnClass: vulnClass || null,
        service: service || null,
        successCount: 1,
        lastUsedAt: now,
        discoveredFrom: discoveredFrom || 'exploit_success',
        createdAt: now,
      });
    }

    console.log(`[NucleiPersistence] Recorded template mapping: ${cveId} → ${templatePath}`);
  } catch (err: any) {
    console.warn(`[NucleiPersistence] Failed to record template mapping: ${err.message}`);
  }
}

// ─── Query Helpers ──────────────────────────────────────────────────────────

/**
 * Get Nuclei findings for an engagement, ordered by severity.
 */
export async function getNucleiFindings(engagementId: number): Promise<NucleiFindingRecord[]> {
  const db = await getDb();
  if (!db) return [];

  const rows = await db.select()
    .from(nucleiFindings)
    .where(eq(nucleiFindings.engagementId, engagementId))
    .orderBy(desc(nucleiFindings.id));

  return rows.map(r => ({
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
    createdAt: r.createdAt,
  }));
}

/**
 * Get Nuclei finding stats for an engagement.
 */
export async function getNucleiStats(engagementId: number): Promise<{
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  verified: number;
  uniqueCves: number;
  uniqueTemplates: number;
}> {
  const db = await getDb();
  if (!db) return { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, verified: 0, uniqueCves: 0, uniqueTemplates: 0 };

  const rows = await db.select()
    .from(nucleiFindings)
    .where(eq(nucleiFindings.engagementId, engagementId));

  const cves = new Set<string>();
  const templates = new Set<string>();
  let critical = 0, high = 0, medium = 0, low = 0, info = 0, verified = 0;

  for (const r of rows) {
    if (r.cveId) cves.add(r.cveId);
    templates.add(r.templateId);
    if (r.nucleiVerified) verified++;
    switch (r.severity) {
      case 'critical': critical++; break;
      case 'high': high++; break;
      case 'medium': medium++; break;
      case 'low': low++; break;
      case 'info': info++; break;
    }
  }

  return {
    total: rows.length,
    critical, high, medium, low, info,
    verified,
    uniqueCves: cves.size,
    uniqueTemplates: templates.size,
  };
}

/**
 * Cross-engagement correlation: find all findings for a given CVE across all engagements.
 */
export async function correlateByCV(cveId: string): Promise<NucleiCorrelationResult | null> {
  const db = await getDb();
  if (!db) return null;

  const rows = await db.select()
    .from(nucleiFindings)
    .where(eq(nucleiFindings.cveId, cveId));

  if (rows.length === 0) return null;

  const engagements = new Set<number>();
  const severities = new Set<string>();
  const targets = new Set<string>();
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
    lastSeen,
  };
}

/**
 * Cross-engagement correlation: find all findings for a given template across all engagements.
 */
export async function correlateByTemplate(templateId: string): Promise<NucleiCorrelationResult | null> {
  const db = await getDb();
  if (!db) return null;

  const rows = await db.select()
    .from(nucleiFindings)
    .where(eq(nucleiFindings.templateId, templateId));

  if (rows.length === 0) return null;

  const engagements = new Set<number>();
  const severities = new Set<string>();
  const targets = new Set<string>();
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
    lastSeen,
  };
}

/**
 * Look up dynamic CVE→template mappings from the DB.
 * Returns the most successful template path for a given CVE.
 */
export async function lookupDynamicTemplateMapping(cveId: string): Promise<string | null> {
  const db = await getDb();
  if (!db) return null;

  const rows = await db.select()
    .from(nucleiTemplateMappings)
    .where(eq(nucleiTemplateMappings.cveId, cveId))
    .orderBy(desc(nucleiTemplateMappings.successCount))
    .limit(1);

  return rows.length > 0 ? rows[0].templatePath : null;
}

/**
 * Get all dynamic template mappings, ordered by success count.
 */
export async function getAllTemplateMappings(): Promise<Array<{
  cveId: string;
  templatePath: string;
  vulnClass: string | null;
  service: string | null;
  successCount: number | null;
  lastUsedAt: number;
}>> {
  const db = await getDb();
  if (!db) return [];

  return db.select()
    .from(nucleiTemplateMappings)
    .orderBy(desc(nucleiTemplateMappings.successCount));
}

// ─── Template Effectiveness Tracking ────────────────────────────────────────

export interface TemplateEffectiveness {
  templatePath: string;
  cveId: string;
  vulnClass: string | null;
  service: string | null;
  successCount: number;
  lastUsedAt: number;
  discoveredFrom: string | null;
  hitRate: number; // successCount normalized against max
}

export interface TemplateEffectivenessStats {
  totalMappings: number;
  totalSuccesses: number;
  topTemplates: TemplateEffectiveness[];
  byCveId: Record<string, TemplateEffectiveness>;
  byVulnClass: Record<string, TemplateEffectiveness[]>;
}

/**
 * Get template effectiveness rankings — surfaces which templates have the
 * highest hit rate across engagements.
 */
export async function getTemplateEffectiveness(limit = 20): Promise<TemplateEffectiveness[]> {
  const db = await getDb();
  if (!db) return [];

  const rows = await db.select()
    .from(nucleiTemplateMappings)
    .orderBy(desc(nucleiTemplateMappings.successCount))
    .limit(limit);

  if (rows.length === 0) return [];

  const maxSuccess = Math.max(...rows.map(r => r.successCount ?? 1));

  return rows.map(r => ({
    templatePath: r.templatePath,
    cveId: r.cveId,
    vulnClass: r.vulnClass,
    service: r.service,
    successCount: r.successCount ?? 1,
    lastUsedAt: r.lastUsedAt ?? 0,
    discoveredFrom: r.discoveredFrom,
    hitRate: maxSuccess > 0 ? ((r.successCount ?? 1) / maxSuccess) : 1,
  }));
}

/**
 * Get top N templates by success count.
 */
export async function getTopTemplates(n = 10): Promise<TemplateEffectiveness[]> {
  return getTemplateEffectiveness(n);
}

/**
 * Get full template effectiveness stats including groupings.
 */
export async function getTemplateEffectivenessStats(): Promise<TemplateEffectivenessStats> {
  const all = await getTemplateEffectiveness(100);

  const byCveId: Record<string, TemplateEffectiveness> = {};
  const byVulnClass: Record<string, TemplateEffectiveness[]> = {};
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
    byVulnClass,
  };
}

/**
 * Get template usage history for a specific template path.
 * Returns all findings that used this template, ordered by time.
 */
export async function getTemplateHistory(templatePath: string): Promise<NucleiFindingRecord[]> {
  const db = await getDb();
  if (!db) return [];

  const rows = await db.select()
    .from(nucleiFindings)
    .where(eq(nucleiFindings.templateId, templatePath))
    .orderBy(desc(nucleiFindings.id));

  return rows.map(r => ({
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
    createdAt: r.createdAt,
  }));
}
