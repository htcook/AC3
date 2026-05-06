import {
  matchJarmFingerprint
} from "./chunk-XGQW2UTM.js";
import "./chunk-KFQGP6VL.js";

// server/lib/jarm-history.ts
import { eq, and, desc, sql } from "drizzle-orm";
function classifyChange(previousHash, currentHash, previousMatch, currentMatch) {
  if (currentMatch?.matchType === "c2" && previousMatch?.matchType !== "c2") {
    return {
      changeType: "c2_appearance",
      severity: "critical",
      description: `CRITICAL: TLS fingerprint changed from ${previousMatch?.provider || "unknown"} to ${currentMatch.provider} (C2 framework). This may indicate server compromise or unauthorized infrastructure.`
    };
  }
  if (previousMatch?.matchType === "c2" && currentMatch?.matchType !== "c2") {
    return {
      changeType: "c2_disappearance",
      severity: "high",
      description: `C2 fingerprint (${previousMatch.provider}) no longer detected. Now matches ${currentMatch?.provider || "unknown"}. Verify remediation was intentional.`
    };
  }
  if (previousMatch?.provider && currentMatch?.provider && previousMatch.provider !== currentMatch.provider) {
    return {
      changeType: "provider_change",
      severity: "medium",
      description: `TLS provider changed from ${previousMatch.provider} to ${currentMatch.provider}. This may indicate infrastructure migration or CDN change.`
    };
  }
  if (previousMatch?.matchType === "server" && currentMatch?.matchType === "server" && previousMatch.provider !== currentMatch.provider) {
    return {
      changeType: "server_change",
      severity: "medium",
      description: `Web server changed from ${previousMatch.provider} to ${currentMatch.provider}.`
    };
  }
  if (!previousMatch && currentMatch) {
    return {
      changeType: "new_fingerprint",
      severity: "low",
      description: `New TLS fingerprint identified as ${currentMatch.provider} (${currentMatch.matchType}). Previously unrecognized.`
    };
  }
  return {
    changeType: "hash_drift",
    severity: "info",
    description: `JARM hash changed (${previousHash.substring(0, 16)}\u2026 \u2192 ${currentHash.substring(0, 16)}\u2026). TLS configuration was modified.`
  };
}
async function processAndStoreJarmHistory(db, schema, scanId, domain, jarmMatches, scannedAt) {
  const records = [];
  const alerts = [];
  if (jarmMatches.length === 0) {
    return { records, alerts };
  }
  const previousRecords = await db.select().from(schema.jarmScanHistory).where(
    and(
      eq(schema.jarmScanHistory.domain, domain),
      sql`${schema.jarmScanHistory.scanId} != ${scanId}`
    )
  ).orderBy(desc(schema.jarmScanHistory.scannedAt)).limit(100);
  const previousByHostPort = /* @__PURE__ */ new Map();
  for (const prev of previousRecords) {
    const key = `${prev.host}:${prev.port}`;
    if (!previousByHostPort.has(key)) {
      previousByHostPort.set(key, prev);
    }
  }
  for (const match of jarmMatches) {
    const host = domain;
    const port = match.port || 443;
    const hostPortKey = `${host}:${port}`;
    const prev = previousByHostPort.get(hostPortKey);
    const previousHash = prev?.jarmHash || null;
    const changeDetected = previousHash !== null && previousHash !== match.hash;
    let changeType = null;
    let changeSeverity = null;
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
        scannedAt
      });
    }
    const record = {
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
      scannedAt
    };
    records.push(record);
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
        scannedAt: record.scannedAt
      });
    } catch (err) {
      console.error(`[JARM History] Failed to insert record for ${host}:${port}:`, err);
    }
  }
  return { records, alerts };
}
async function getJarmTimeline(db, schema, domain, limit = 200) {
  const rows = await db.select().from(schema.jarmScanHistory).where(eq(schema.jarmScanHistory.domain, domain)).orderBy(desc(schema.jarmScanHistory.scannedAt)).limit(limit);
  const records = rows.map((r) => ({
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
    scannedAt: r.scannedAt
  }));
  const uniqueHosts = new Set(records.map((r) => `${r.host}:${r.port}`)).size;
  const changesDetected = records.filter((r) => r.changeDetected).length;
  const alerts = records.filter((r) => r.changeDetected && r.previousHash).map((r) => {
    const prevMatch = r.previousHash ? matchJarmFingerprint(r.previousHash) : null;
    const currMatch = matchJarmFingerprint(r.jarmHash);
    return {
      host: r.host,
      port: r.port,
      previousHash: r.previousHash,
      currentHash: r.jarmHash,
      previousProvider: prevMatch?.provider || r.matchedProvider,
      currentProvider: currMatch?.provider || r.matchedProvider,
      changeType: r.changeType || "hash_drift",
      severity: r.changeSeverity || "info",
      description: `JARM hash changed on ${r.host}:${r.port}`,
      scannedAt: r.scannedAt
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
    alerts
  };
}
async function getJarmHistoryByScan(db, schema, scanId) {
  const rows = await db.select().from(schema.jarmScanHistory).where(eq(schema.jarmScanHistory.scanId, scanId)).orderBy(desc(schema.jarmScanHistory.scannedAt));
  return rows.map((r) => ({
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
    scannedAt: r.scannedAt
  }));
}
async function getRecentJarmAlerts(db, schema, limit = 50) {
  const rows = await db.select().from(schema.jarmScanHistory).where(eq(schema.jarmScanHistory.changeDetected, 1)).orderBy(desc(schema.jarmScanHistory.scannedAt)).limit(limit);
  return rows.map((r) => {
    const prevMatch = r.previousHash ? matchJarmFingerprint(r.previousHash) : null;
    const currMatch = matchJarmFingerprint(r.jarmHash);
    return {
      host: r.host,
      port: r.port,
      previousHash: r.previousHash || "",
      currentHash: r.jarmHash,
      previousProvider: prevMatch?.provider || null,
      currentProvider: currMatch?.provider || r.matchedProvider,
      changeType: r.changeType || "hash_drift",
      severity: r.changeSeverity || "info",
      description: `JARM hash changed on ${r.host}:${r.port}`,
      scannedAt: r.scannedAt
    };
  });
}
export {
  getJarmHistoryByScan,
  getJarmTimeline,
  getRecentJarmAlerts,
  processAndStoreJarmHistory
};
