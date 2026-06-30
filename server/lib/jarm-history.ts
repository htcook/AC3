/**
 * JARM Historical Tracking Module
 *
 * Stores JARM fingerprints per scan in the database and detects TLS
 * configuration changes over time. When a host's JARM hash changes
 * between scans, the module classifies the change severity and flags
 * potential security events (e.g., a legitimate server suddenly matching
 * a C2 framework fingerprint).
 */

import { eq, and, desc, sql } from "drizzle-orm";
import { matchJarmFingerprint } from "./infrastructure-inference";
import type { JarmMatch } from "./infrastructure-inference";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface JarmHistoryRecord {
  id?: number;
  scanId: number;
  domain: string;
  host: string;
  port: number;
  jarmHash: string;
  matchedProvider: string | null;
  matchType: string | null;
  matchConfidence: number | null;
  source: string;
  certIssuer: string | null;
  certSubject: string | null;
  protocol: string | null;
  previousHash: string | null;
  changeDetected: boolean;
  changeType: string | null;
  changeSeverity: string | null;
  scannedAt: number;
}

export interface JarmChangeAlert {
  host: string;
  port: number;
  previousHash: string;
  currentHash: string;
  previousProvider: string | null;
  currentProvider: string | null;
  changeType: "provider_change" | "c2_appearance" | "c2_disappearance" | "server_change" | "new_fingerprint" | "hash_drift";
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  scannedAt: number;
}

export interface JarmTimeline {
  domain: string;
  totalRecords: number;
  uniqueHosts: number;
  changesDetected: number;
  criticalAlerts: number;
  records: JarmHistoryRecord[];
  alerts: JarmChangeAlert[];
}

// ─── Change Classification ──────────────────────────────────────────────────

function classifyChange(
  previousHash: string,
  currentHash: string,
  previousMatch: ReturnType<typeof matchJarmFingerprint>,
  currentMatch: ReturnType<typeof matchJarmFingerprint>,
): { changeType: JarmChangeAlert["changeType"]; severity: JarmChangeAlert["severity"]; description: string } {
  // C2 appearance: previous was not C2, current is C2
  if (currentMatch?.matchType === "c2" && previousMatch?.matchType !== "c2") {
    return {
      changeType: "c2_appearance",
      severity: "critical",
      description: `CRITICAL: TLS fingerprint changed from ${previousMatch?.provider || "unknown"} to ${currentMatch.provider} (C2 framework). This may indicate server compromise or unauthorized infrastructure.`,
    };
  }

  // C2 disappearance: previous was C2, current is not
  if (previousMatch?.matchType === "c2" && currentMatch?.matchType !== "c2") {
    return {
      changeType: "c2_disappearance",
      severity: "high",
      description: `C2 fingerprint (${previousMatch.provider}) no longer detected. Now matches ${currentMatch?.provider || "unknown"}. Verify remediation was intentional.`,
    };
  }

  // Provider change: different known providers
  if (previousMatch?.provider && currentMatch?.provider && previousMatch.provider !== currentMatch.provider) {
    return {
      changeType: "provider_change",
      severity: "medium",
      description: `TLS provider changed from ${previousMatch.provider} to ${currentMatch.provider}. This may indicate infrastructure migration or CDN change.`,
    };
  }

  // Server software change
  if (previousMatch?.matchType === "server" && currentMatch?.matchType === "server" && previousMatch.provider !== currentMatch.provider) {
    return {
      changeType: "server_change",
      severity: "medium",
      description: `Web server changed from ${previousMatch.provider} to ${currentMatch.provider}.`,
    };
  }

  // New fingerprint (previous was unknown, now matched)
  if (!previousMatch && currentMatch) {
    return {
      changeType: "new_fingerprint",
      severity: "low",
      description: `New TLS fingerprint identified as ${currentMatch.provider} (${currentMatch.matchType}). Previously unrecognized.`,
    };
  }

  // Generic hash drift
  return {
    changeType: "hash_drift",
    severity: "info",
    description: `JARM hash changed (${previousHash.substring(0, 16)}… → ${currentHash.substring(0, 16)}…). TLS configuration was modified.`,
  };
}

// ─── Core Functions ─────────────────────────────────────────────────────────

/**
 * Process JARM fingerprints from a completed scan and store them in history.
 * Compares against previous scan records for the same domain to detect changes.
 */
export async function processAndStoreJarmHistory(
  db: any,
  schema: any,
  scanId: number,
  domain: string,
  jarmMatches: JarmMatch[],
  scannedAt: number,
): Promise<{ records: JarmHistoryRecord[]; alerts: JarmChangeAlert[] }> {
  const records: JarmHistoryRecord[] = [];
  const alerts: JarmChangeAlert[] = [];

  if (jarmMatches.length === 0) {
    return { records, alerts };
  }

  // Get previous JARM records for this domain (most recent scan)
  const previousRecords = await db
    .select()
    .from(schema.jarmScanHistory)
    .where(
      and(
        eq(schema.jarmScanHistory.domain, domain),
        sql`${schema.jarmScanHistory.scanId} != ${scanId}`,
      ),
    )
    .orderBy(desc(schema.jarmScanHistory.scannedAt))
    .limit(100);

  // Build a map of previous hashes by host:port
  const previousByHostPort = new Map<string, typeof previousRecords[0]>();
  for (const prev of previousRecords) {
    const key = `${prev.host}:${prev.port}`;
    if (!previousByHostPort.has(key)) {
      previousByHostPort.set(key, prev);
    }
  }

  // Process each JARM match
  for (const match of jarmMatches) {
    const host = domain; // Use domain as host since JARM is per-domain
    const port = match.port || 443;
    const hostPortKey = `${host}:${port}`;

    // Look up previous record
    const prev = previousByHostPort.get(hostPortKey);
    const previousHash = prev?.jarmHash || null;
    const changeDetected = previousHash !== null && previousHash !== match.hash;

    // Classify change if detected
    let changeType: string | null = null;
    let changeSeverity: string | null = null;

    if (changeDetected && previousHash) {
      const prevMatch = matchJarmFingerprint(previousHash);
      const currMatch = matchJarmFingerprint(match.hash);
      const classification = classifyChange(previousHash, match.hash, prevMatch, currMatch);
      changeType = classification.changeType;
      changeSeverity = classification.severity;

      alerts.push({
        host,
        port,
        previousHash,
        currentHash: match.hash,
        previousProvider: prevMatch?.provider || null,
        currentProvider: currMatch?.provider || null,
        changeType: classification.changeType,
        severity: classification.severity,
        description: classification.description,
        scannedAt,
      });
    }

    const record: JarmHistoryRecord = {
      scanId,
      domain,
      host,
      port,
      jarmHash: match.hash,
      matchedProvider: match.matchedProvider,
      matchType: match.matchType,
      matchConfidence: match.confidence,
      source: match.source,
      certIssuer: null,
      certSubject: null,
      protocol: null,
      previousHash,
      changeDetected,
      changeType,
      changeSeverity,
      scannedAt,
    };

    records.push(record);

    // Insert into database
    try {
      await db.insert(schema.jarmScanHistory).values({
        scanId: record.scanId,
        domain: record.domain,
        host: record.host,
        port: record.port,
        jarmHash: record.jarmHash,
        matchedProvider: record.matchedProvider,
        matchType: record.matchType,
        matchConfidence: record.matchConfidence,
        source: record.source,
        certIssuer: record.certIssuer,
        certSubject: record.certSubject,
        protocol: record.protocol,
        previousHash: record.previousHash,
        changeDetected: record.changeDetected ? 1 : 0,
        changeType: record.changeType,
        changeSeverity: record.changeSeverity,
        scannedAt: record.scannedAt,
      });
    } catch (err) {
      console.error(`[JARM History] Failed to insert record for ${host}:${port}:`, err);
    }
  }

  return { records, alerts };
}

/**
 * Get the JARM fingerprint timeline for a domain.
 */
export async function getJarmTimeline(
  db: any,
  schema: any,
  domain: string,
  limit = 200,
): Promise<JarmTimeline> {
  const rows = await db
    .select()
    .from(schema.jarmScanHistory)
    .where(eq(schema.jarmScanHistory.domain, domain))
    .orderBy(desc(schema.jarmScanHistory.scannedAt))
    .limit(limit);

  const records: JarmHistoryRecord[] = rows.map((r: any) => ({
    id: r.id,
    scanId: r.scanId,
    domain: r.domain,
    host: r.host,
    port: r.port,
    jarmHash: r.jarmHash,
    matchedProvider: r.matchedProvider,
    matchType: r.matchType,
    matchConfidence: r.matchConfidence,
    source: r.source,
    certIssuer: r.certIssuer,
    certSubject: r.certSubject,
    protocol: r.protocol,
    previousHash: r.previousHash,
    changeDetected: r.changeDetected === 1,
    changeType: r.changeType,
    changeSeverity: r.changeSeverity,
    scannedAt: r.scannedAt,
  }));

  const uniqueHosts = new Set(records.map((r) => `${r.host}:${r.port}`)).size;
  const changesDetected = records.filter((r) => r.changeDetected).length;

  // Reconstruct alerts from change records
  const alerts: JarmChangeAlert[] = records
    .filter((r) => r.changeDetected && r.previousHash)
    .map((r) => {
      const prevMatch = r.previousHash ? matchJarmFingerprint(r.previousHash) : null;
      const currMatch = matchJarmFingerprint(r.jarmHash);
      return {
        host: r.host,
        port: r.port,
        previousHash: r.previousHash!,
        currentHash: r.jarmHash,
        previousProvider: prevMatch?.provider || r.matchedProvider,
        currentProvider: currMatch?.provider || r.matchedProvider,
        changeType: (r.changeType as JarmChangeAlert["changeType"]) || "hash_drift",
        severity: (r.changeSeverity as JarmChangeAlert["severity"]) || "info",
        description: `JARM hash changed on ${r.host}:${r.port}`,
        scannedAt: r.scannedAt,
      };
    });

  const criticalAlerts = alerts.filter((a) => a.severity === "critical").length;

  return {
    domain,
    totalRecords: records.length,
    uniqueHosts,
    changesDetected,
    criticalAlerts,
    records,
    alerts,
  };
}

/**
 * Get JARM history for a specific scan.
 */
export async function getJarmHistoryByScan(
  db: any,
  schema: any,
  scanId: number,
): Promise<JarmHistoryRecord[]> {
  const rows = await db
    .select()
    .from(schema.jarmScanHistory)
    .where(eq(schema.jarmScanHistory.scanId, scanId))
    .orderBy(desc(schema.jarmScanHistory.scannedAt));

  return rows.map((r: any) => ({
    id: r.id,
    scanId: r.scanId,
    domain: r.domain,
    host: r.host,
    port: r.port,
    jarmHash: r.jarmHash,
    matchedProvider: r.matchedProvider,
    matchType: r.matchType,
    matchConfidence: r.matchConfidence,
    source: r.source,
    certIssuer: r.certIssuer,
    certSubject: r.certSubject,
    protocol: r.protocol,
    previousHash: r.previousHash,
    changeDetected: r.changeDetected === 1,
    changeType: r.changeType,
    changeSeverity: r.changeSeverity,
    scannedAt: r.scannedAt,
  }));
}

/**
 * Get change alerts across all domains (for dashboard overview).
 */
export async function getRecentJarmAlerts(
  db: any,
  schema: any,
  limit = 50,
): Promise<JarmChangeAlert[]> {
  const rows = await db
    .select()
    .from(schema.jarmScanHistory)
    .where(eq(schema.jarmScanHistory.changeDetected, 1))
    .orderBy(desc(schema.jarmScanHistory.scannedAt))
    .limit(limit);

  return rows.map((r: any) => {
    const prevMatch = r.previousHash ? matchJarmFingerprint(r.previousHash) : null;
    const currMatch = matchJarmFingerprint(r.jarmHash);
    return {
      host: r.host,
      port: r.port,
      previousHash: r.previousHash || "",
      currentHash: r.jarmHash,
      previousProvider: prevMatch?.provider || null,
      currentProvider: currMatch?.provider || r.matchedProvider,
      changeType: (r.changeType as JarmChangeAlert["changeType"]) || "hash_drift",
      severity: (r.changeSeverity as JarmChangeAlert["severity"]) || "info",
      description: `JARM hash changed on ${r.host}:${r.port}`,
      scannedAt: r.scannedAt,
    };
  });
}
