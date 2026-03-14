/**
 * Supplemental Scan Feeder
 * 
 * Feeds results from standalone scanning tools (Nuclei, ZAP, Nmap, etc.)
 * back into an engagement's findings and trackers. This allows pentesters
 * to run supplemental scans from the Scanning & Assessment module and have
 * results automatically appear in the engagement without manual entry.
 */

import { getDb } from "../db";
import { scanResults, engagements } from "../../drizzle/schema";
import { eq } from "drizzle-orm";

interface SupplementalFinding {
  name: string;
  severity: string;
  host: string;
  matched?: string;
  description?: string;
  tags?: string[];
  cveId?: string;
  cweId?: string;
  templateId?: string;
  extractedResults?: string[];
  curl?: string;
  port?: string;
  type?: string;
  evidence?: string;
}

/**
 * Feed scan results from a standalone tool into an engagement's scan_results table.
 * Results are stored as a new scan_result row linked to the engagement, which will
 * be picked up by the engagement's vuln synthesis and accuracy scoring.
 */
export async function feedScanResultsToEngagement(
  engagementId: number,
  scannerType: string,
  findings: SupplementalFinding[],
): Promise<{ inserted: number; engagementId: number }> {
  const db = await getDb();
  if (!db) {
    console.warn('[SupplementalScanFeeder] Database unavailable, skipping feed');
    return { inserted: 0, engagementId };
  }

  // Verify engagement exists
  const [engagement] = await db.select({ id: engagements.id })
    .from(engagements)
    .where(eq(engagements.id, engagementId))
    .limit(1);

  if (!engagement) {
    console.warn(`[SupplementalScanFeeder] Engagement #${engagementId} not found`);
    return { inserted: 0, engagementId };
  }

  // Convert findings to scan_result format
  const scanResultRows = findings.map(f => ({
    engagementId,
    scanTool: `supplemental_${scannerType}`,
    target: f.host,
    rawOutput: JSON.stringify({
      finding: f.name,
      severity: f.severity,
      matched: f.matched || f.host,
      description: f.description || '',
      cve: f.cveId,
      cwe: f.cweId,
      templateId: f.templateId,
      tags: f.tags || [],
      extractedResults: f.extractedResults || [],
      curl: f.curl,
      port: f.port,
      type: f.type,
      evidence: f.evidence || f.matched || '',
    }),
    parsedFindings: JSON.stringify([{
      title: f.name,
      severity: f.severity,
      description: f.description || f.name,
      evidence: f.evidence || f.matched || f.curl || '',
      cve: f.cveId,
      cwe: f.cweId,
      host: f.host,
      port: f.port,
      tags: f.tags,
      source: `supplemental_${scannerType}`,
      confidence: f.cveId ? 'high' : 'medium',
    }]),
    exitCode: 0,
    durationMs: 0,
    createdAt: Date.now(),
  }));

  let inserted = 0;
  for (const row of scanResultRows) {
    try {
      await db.insert(scanResults).values(row);
      inserted++;
    } catch (err: any) {
      console.warn(`[SupplementalScanFeeder] Failed to insert finding: ${err.message}`);
    }
  }

  console.log(
    `[SupplementalScanFeeder] Fed ${inserted}/${findings.length} findings from ${scannerType} ` +
    `into engagement #${engagementId}`
  );

  return { inserted, engagementId };
}

/**
 * Feed terminal command output as evidence into an engagement.
 * Used when a pentester runs manual commands in the EngagementTerminal.
 */
export async function feedTerminalEvidenceToEngagement(
  engagementId: number,
  command: string,
  output: string,
  target: string,
): Promise<{ success: boolean }> {
  const db = await getDb();
  if (!db) return { success: false };

  try {
    await db.insert(scanResults).values({
      engagementId,
      scanTool: 'manual_terminal',
      target,
      rawOutput: JSON.stringify({
        command,
        output: output.slice(0, 50000),
        timestamp: new Date().toISOString(),
      }),
      parsedFindings: JSON.stringify([{
        title: `Manual command: ${command.slice(0, 80)}`,
        severity: 'info',
        description: `Manual terminal command executed against ${target}`,
        evidence: output.slice(0, 10000),
        source: 'manual_terminal',
        confidence: 'manual',
      }]),
      exitCode: 0,
      durationMs: 0,
      createdAt: Date.now(),
    });
    return { success: true };
  } catch (err: any) {
    console.warn(`[SupplementalScanFeeder] Terminal evidence feed failed: ${err.message}`);
    return { success: false };
  }
}
