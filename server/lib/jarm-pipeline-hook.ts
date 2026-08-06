/**
 * JARM Pipeline Hook
 *
 * Fire-and-forget helper that extracts JARM fingerprints from passive recon
 * observations via the infrastructure inference engine, then stores them
 * in the JARM history table for TLS configuration change tracking.
 *
 * Called from the DI scan pipeline after both scan-only and full engagement
 * completion paths.
 */

export async function runJarmHistoryHook(
  scanId: number,
  primaryDomain: string,
  allObservations: any[],
  assets: any[],
): Promise<void> {
  try {
    const { inferInfrastructure } = await import('./infrastructure-inference');
    const { processAndStoreJarmHistory } = await import('./jarm-history');
    const { getDb } = await import('../db');
    const dbConn = getDb();
    const schema = await import('../../drizzle/schema');

    // Map observations to the shape expected by inferInfrastructure
    const observations = allObservations.map((o: any) => ({
      source: o.source || 'unknown',
      tags: o.tags || [],
      evidence: o.evidence || {},
      name: o.name || null,
    }));
    const mappedAssets = assets.map((a: any) => ({
      hostname: a.asset?.hostname || a.hostname || '',
      technologies: a.asset?.technologies || a.technologies || [],
      headers: a.asset?.headers || a.headers || {},
    }));

    const infraMap = inferInfrastructure(
      primaryDomain,
      observations,
      mappedAssets,
    );

    if (infraMap.jarmAnalysis && infraMap.jarmAnalysis.matches.length > 0) {
      const { records, alerts } = await processAndStoreJarmHistory(
        dbConn,
        schema,
        scanId,
        primaryDomain,
        infraMap.jarmAnalysis.matches,
        Date.now(),
      );
      console.log(`[JARM History] Stored ${records.length} fingerprints for scan ${scanId}, ${alerts.length} change alerts`);
      if (alerts.some(a => a.severity === 'critical')) {
        console.warn(`[JARM History] ⚠ CRITICAL: C2 framework fingerprint detected for ${primaryDomain}!`);
        // Emit a system notification for critical JARM alerts
        try {
          const { emitSystemNotification } = await import('./ws-event-hub');
          emitSystemNotification({
            title: '⚠ JARM C2 Alert',
            message: `C2 framework TLS fingerprint detected on ${primaryDomain} (scan ${scanId})`,
            severity: 'critical',
          });
        } catch {}
      }
    } else {
      console.log(`[JARM History] No JARM fingerprints found for scan ${scanId}`);
    }
  } catch (jarmErr: any) {
    console.warn(`[JARM History] Failed for scan ${scanId} (non-fatal):`, jarmErr.message);
  }
}
