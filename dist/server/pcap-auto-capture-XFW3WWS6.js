import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/pcap-auto-capture.ts
function generateSessionId(engagementId, targetIp) {
  return `autocap-${engagementId}-${targetIp.replace(/\./g, "_")}-${Date.now()}`;
}
function getCaptureSessions(engagementId) {
  return completedSessions.get(engagementId) || [];
}
function getActiveSession(engagementId, targetIp) {
  for (const [, session] of activeSessions) {
    if (session.engagementId === engagementId && session.targetIp === targetIp) {
      return session;
    }
  }
  return void 0;
}
async function startAutoCapture(engagementId, targetIp, targetHostname, config = {}) {
  const cfg = { ...DEFAULT_AUTO_CAPTURE_CONFIG, ...config };
  if (!cfg.enabled) return null;
  const existing = getActiveSession(engagementId, targetIp);
  if (existing) {
    console.log(`[AutoCapture] Already capturing ${targetIp} for engagement ${engagementId}`);
    return existing;
  }
  const sessionId = generateSessionId(engagementId, targetIp);
  const pcapPath = `/tmp/autocap_${engagementId}_${targetIp.replace(/\./g, "_")}_${Date.now()}.pcap`;
  let bpfFilter = `host ${targetIp}`;
  if (cfg.additionalFilter) {
    bpfFilter = `(${bpfFilter}) and (${cfg.additionalFilter})`;
  }
  const tcpdumpCmd = [
    `nohup tcpdump`,
    `-i ${cfg.interface}`,
    `-w ${pcapPath}`,
    cfg.snapLen > 0 ? `-s ${cfg.snapLen}` : `-s 0`,
    `-c 1000000`,
    // Max 1M packets safety limit
    `'${bpfFilter}'`,
    `> /tmp/autocap_${sessionId}.log 2>&1 &`,
    `echo $!`
  ].join(" ");
  try {
    const { executeTool } = await import("./scan-server-executor-L5FGTKBI.js");
    const result = await executeTool({
      tool: "bash",
      args: `-c "${tcpdumpCmd.replace(/"/g, '\\"')}"`,
      timeoutSeconds: 10,
      sudo: true,
      engagementId
    });
    const pid = parseInt(result.stdout.trim());
    if (isNaN(pid) || pid <= 0) {
      console.error(`[AutoCapture] Failed to get PID for ${targetIp}: ${result.stdout} ${result.stderr}`);
      return null;
    }
    const session = {
      sessionId,
      engagementId,
      targetIp,
      targetHostname,
      pcapPath,
      pid,
      startedAt: Date.now()
    };
    activeSessions.set(sessionId, session);
    console.log(`[AutoCapture] Started capture for ${targetIp} (PID: ${pid}, PCAP: ${pcapPath})`);
    return session;
  } catch (err) {
    console.error(`[AutoCapture] Failed to start capture for ${targetIp}: ${err.message}`);
    return null;
  }
}
async function stopAutoCapture(sessionId, config = {}) {
  const cfg = { ...DEFAULT_AUTO_CAPTURE_CONFIG, ...config };
  const session = activeSessions.get(sessionId);
  if (!session) {
    console.warn(`[AutoCapture] No active session: ${sessionId}`);
    return null;
  }
  try {
    const { executeTool } = await import("./scan-server-executor-L5FGTKBI.js");
    await executeTool({
      tool: "bash",
      args: `-c "kill ${session.pid} 2>/dev/null; sleep 1; kill -9 ${session.pid} 2>/dev/null; true"`,
      timeoutSeconds: 10,
      sudo: true
    });
    session.stoppedAt = Date.now();
    const countResult = await executeTool({
      tool: "bash",
      args: `-c "capinfos -c '${session.pcapPath}' 2>/dev/null | grep 'Number of packets' | awk '{print \\$NF}'"`,
      timeoutSeconds: 10
    });
    session.packetsCaptured = parseInt(countResult.stdout.trim()) || 0;
    activeSessions.delete(sessionId);
    if (!completedSessions.has(session.engagementId)) {
      completedSessions.set(session.engagementId, []);
    }
    completedSessions.get(session.engagementId).push(session);
    console.log(`[AutoCapture] Stopped capture ${sessionId}: ${session.packetsCaptured} packets in ${session.stoppedAt - session.startedAt}ms`);
    if (cfg.autoAnalyze && session.packetsCaptured > 0) {
      await analyzeAutoCapture(session, cfg);
    }
    return session;
  } catch (err) {
    console.error(`[AutoCapture] Failed to stop capture ${sessionId}: ${err.message}`);
    activeSessions.delete(sessionId);
    session.stoppedAt = Date.now();
    if (!completedSessions.has(session.engagementId)) {
      completedSessions.set(session.engagementId, []);
    }
    completedSessions.get(session.engagementId).push(session);
    return session;
  }
}
async function analyzeAutoCapture(session, config = {}) {
  const cfg = { ...DEFAULT_AUTO_CAPTURE_CONFIG, ...config };
  try {
    const { analyzePcap, detectFindings, ingestPcapResults } = await import("./pcap-analyzer-SRCH3UTC.js");
    const analysis = await analyzePcap({
      pcapPath: session.pcapPath,
      maxPackets: 5e4,
      protocols: ["tcp", "udp", "http", "tls", "dns", "icmp"],
      extractStreams: true
    });
    const findings = detectFindings(analysis.packets);
    session.analysisSummary = {
      totalPackets: analysis.metadata.packetCount,
      protocols: analysis.protocolStats.map((p) => p.protocol),
      conversations: analysis.conversations.length,
      findings: findings.length,
      findingsBySeverity: findings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {})
    };
    session.analyzed = true;
    if (cfg.autoIngest && findings.length > 0) {
      await ingestPcapResults(findings, analysis.packets);
      console.log(`[AutoCapture] Ingested ${findings.length} findings from ${session.sessionId} into SSIL`);
    }
    console.log(`[AutoCapture] Analysis complete for ${session.sessionId}: ${analysis.metadata.packetCount} packets, ${findings.length} findings`);
    return session;
  } catch (err) {
    console.error(`[AutoCapture] Analysis failed for ${session.sessionId}: ${err.message}`);
    session.analyzed = false;
    return session;
  }
}
async function beforeScanForgeScan(engagementId, targetIp, targetHostname, config) {
  const session = await startAutoCapture(engagementId, targetIp, targetHostname, config);
  return session?.sessionId || null;
}
async function afterScanForgeScan(sessionId, config) {
  if (!sessionId) return null;
  return await stopAutoCapture(sessionId, config);
}
async function cleanupEngagementCaptures(engagementId) {
  const sessions = completedSessions.get(engagementId);
  if (!sessions || sessions.length === 0) return;
  try {
    const { executeTool } = await import("./scan-server-executor-L5FGTKBI.js");
    const paths = sessions.map((s) => s.pcapPath).join(" ");
    await executeTool({
      tool: "bash",
      args: `-c "rm -f ${paths} /tmp/autocap_${engagementId}_*.log 2>/dev/null; true"`,
      timeoutSeconds: 10
    });
    console.log(`[AutoCapture] Cleaned up ${sessions.length} PCAP files for engagement ${engagementId}`);
  } catch (err) {
    console.error(`[AutoCapture] Cleanup failed for engagement ${engagementId}: ${err.message}`);
  }
  completedSessions.delete(engagementId);
}
async function abortEngagementCaptures(engagementId) {
  const toAbort = [];
  for (const [id, session] of activeSessions) {
    if (session.engagementId === engagementId) {
      toAbort.push(id);
    }
  }
  for (const id of toAbort) {
    await stopAutoCapture(id, { autoAnalyze: false, autoIngest: false, enabled: true, maxDuration: 0, snapLen: 0, interface: "eth0" });
  }
}
var DEFAULT_AUTO_CAPTURE_CONFIG, activeSessions, completedSessions, beforeDiscoveryScan, afterDiscoveryScan;
var init_pcap_auto_capture = __esm({
  "server/lib/pcap-auto-capture.ts"() {
    DEFAULT_AUTO_CAPTURE_CONFIG = {
      enabled: true,
      maxDuration: 660,
      // ScanForge discovery timeout (600s) + 60s buffer
      autoAnalyze: true,
      autoIngest: true,
      snapLen: 0,
      interface: "eth0"
    };
    activeSessions = /* @__PURE__ */ new Map();
    completedSessions = /* @__PURE__ */ new Map();
    beforeDiscoveryScan = beforeScanForgeScan;
    afterDiscoveryScan = afterScanForgeScan;
  }
});
init_pcap_auto_capture();
export {
  DEFAULT_AUTO_CAPTURE_CONFIG,
  abortEngagementCaptures,
  afterDiscoveryScan,
  afterScanForgeScan,
  analyzeAutoCapture,
  beforeDiscoveryScan,
  beforeScanForgeScan,
  cleanupEngagementCaptures,
  getActiveSession,
  getCaptureSessions,
  startAutoCapture,
  stopAutoCapture
};
