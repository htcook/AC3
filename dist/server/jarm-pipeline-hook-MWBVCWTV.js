import "./chunk-KFQGP6VL.js";

// server/lib/jarm-pipeline-hook.ts
async function runJarmHistoryHook(scanId, primaryDomain, allObservations, assets) {
  try {
    const { inferInfrastructure } = await import("./infrastructure-inference-LSZQKY3R.js");
    const { processAndStoreJarmHistory } = await import("./jarm-history-LVTOF6AY.js");
    const { getDb } = await import("./db-QL5AIQ4A.js");
    const dbConn = getDb();
    const schema = await import("./schema-NFOE7JII.js");
    const observations = allObservations.map((o) => ({
      source: o.source || "unknown",
      tags: o.tags || [],
      evidence: o.evidence || {},
      name: o.name || null
    }));
    const mappedAssets = assets.map((a) => ({
      hostname: a.asset?.hostname || a.hostname || "",
      technologies: a.asset?.technologies || a.technologies || [],
      headers: a.asset?.headers || a.headers || {}
    }));
    const infraMap = inferInfrastructure(
      primaryDomain,
      observations,
      mappedAssets
    );
    if (infraMap.jarmAnalysis && infraMap.jarmAnalysis.matches.length > 0) {
      const { records, alerts } = await processAndStoreJarmHistory(
        dbConn,
        schema,
        scanId,
        primaryDomain,
        infraMap.jarmAnalysis.matches,
        Date.now()
      );
      console.log(`[JARM History] Stored ${records.length} fingerprints for scan ${scanId}, ${alerts.length} change alerts`);
      if (alerts.some((a) => a.severity === "critical")) {
        console.warn(`[JARM History] \u26A0 CRITICAL: C2 framework fingerprint detected for ${primaryDomain}!`);
        try {
          const { emitSystemNotification } = await import("./ws-event-hub-GYTLNKYI.js");
          emitSystemNotification({
            title: "\u26A0 JARM C2 Alert",
            message: `C2 framework TLS fingerprint detected on ${primaryDomain} (scan ${scanId})`,
            severity: "critical"
          });
        } catch {
        }
      }
    } else {
      console.log(`[JARM History] No JARM fingerprints found for scan ${scanId}`);
    }
  } catch (jarmErr) {
    console.warn(`[JARM History] Failed for scan ${scanId} (non-fatal):`, jarmErr.message);
  }
}
export {
  runJarmHistoryHook
};
