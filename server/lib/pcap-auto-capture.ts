/**
 * PCAP Auto-Capture Hook — Automatic tcpdump During Active Scans
 * ═══════════════════════════════════════════════════════════════
 * Hooks into the engagement orchestrator's enumeration phase to
 * automatically start/stop tcpdump captures alongside nmap scans.
 *
 * Architecture:
 *   1. Before nmap starts → start background tcpdump on scan server
 *   2. nmap runs normally
 *   3. After nmap completes → stop tcpdump, analyze captured PCAP
 *   4. Feed findings into SSIL observation pipeline
 *
 * The capture runs as a background process on the scan server,
 * filtered to only the target IP to minimize noise.
 *
 * @module pcap-auto-capture
 */

// ═══════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════

export interface AutoCaptureSession {
  /** Unique session ID */
  sessionId: string;
  /** Engagement ID this capture belongs to */
  engagementId: number;
  /** Target IP being scanned */
  targetIp: string;
  /** Target hostname */
  targetHostname: string;
  /** PCAP file path on scan server */
  pcapPath: string;
  /** PID of the tcpdump process on scan server */
  pid: number;
  /** Timestamp when capture started */
  startedAt: number;
  /** Timestamp when capture stopped */
  stoppedAt?: number;
  /** Number of packets captured */
  packetsCaptured?: number;
  /** Whether the capture was analyzed */
  analyzed?: boolean;
  /** Analysis results summary */
  analysisSummary?: {
    totalPackets: number;
    protocols: string[];
    conversations: number;
    findings: number;
    findingsBySeverity: Record<string, number>;
  };
}

export interface AutoCaptureConfig {
  /** Enable auto-capture during scans (default: true) */
  enabled: boolean;
  /** Max capture duration in seconds (default: 660 = nmap timeout + buffer) */
  maxDuration: number;
  /** BPF filter additions beyond target IP */
  additionalFilter?: string;
  /** Whether to auto-analyze after capture (default: true) */
  autoAnalyze: boolean;
  /** Whether to ingest findings into SSIL pipeline (default: true) */
  autoIngest: boolean;
  /** Snap length — bytes per packet (default: 0 = full) */
  snapLen: number;
  /** Network interface on scan server (default: "eth0") */
  interface: string;
}

/** Default configuration for auto-capture */
export const DEFAULT_AUTO_CAPTURE_CONFIG: AutoCaptureConfig = {
  enabled: true,
  maxDuration: 660, // nmap timeout (600s) + 60s buffer
  autoAnalyze: true,
  autoIngest: true,
  snapLen: 0,
  interface: "eth0",
};

// ═══════════════════════════════════════════════════════════════
// §2 — SESSION REGISTRY
// ═══════════════════════════════════════════════════════════════

/** In-memory registry of active capture sessions */
const activeSessions = new Map<string, AutoCaptureSession>();

/** All completed sessions (kept for the engagement lifetime) */
const completedSessions = new Map<number, AutoCaptureSession[]>(); // engagementId → sessions

/**
 * Generate a unique session ID
 */
function generateSessionId(engagementId: number, targetIp: string): string {
  return `autocap-${engagementId}-${targetIp.replace(/\./g, "_")}-${Date.now()}`;
}

/**
 * Get all capture sessions for an engagement
 */
export function getCaptureSessions(engagementId: number): AutoCaptureSession[] {
  return completedSessions.get(engagementId) || [];
}

/**
 * Get active capture session for a target
 */
export function getActiveSession(engagementId: number, targetIp: string): AutoCaptureSession | undefined {
  for (const [, session] of activeSessions) {
    if (session.engagementId === engagementId && session.targetIp === targetIp) {
      return session;
    }
  }
  return undefined;
}

// ═══════════════════════════════════════════════════════════════
// §3 — START CAPTURE (before nmap)
// ═══════════════════════════════════════════════════════════════

/**
 * Start a background tcpdump capture on the scan server.
 * Called automatically before nmap begins scanning a target.
 *
 * @returns The session ID and PCAP path, or null if capture failed to start
 */
export async function startAutoCapture(
  engagementId: number,
  targetIp: string,
  targetHostname: string,
  config: Partial<AutoCaptureConfig> = {},
): Promise<AutoCaptureSession | null> {
  const cfg = { ...DEFAULT_AUTO_CAPTURE_CONFIG, ...config };

  if (!cfg.enabled) return null;

  // Check if there's already an active capture for this target
  const existing = getActiveSession(engagementId, targetIp);
  if (existing) {
    console.log(`[AutoCapture] Already capturing ${targetIp} for engagement ${engagementId}`);
    return existing;
  }

  const sessionId = generateSessionId(engagementId, targetIp);
  const pcapPath = `/tmp/autocap_${engagementId}_${targetIp.replace(/\./g, "_")}_${Date.now()}.pcap`;

  // Build BPF filter: capture all traffic to/from target IP
  let bpfFilter = `host ${targetIp}`;
  if (cfg.additionalFilter) {
    bpfFilter = `(${bpfFilter}) and (${cfg.additionalFilter})`;
  }

  // Build tcpdump command that runs in background and writes PID
  const tcpdumpCmd = [
    `nohup tcpdump`,
    `-i ${cfg.interface}`,
    `-w ${pcapPath}`,
    cfg.snapLen > 0 ? `-s ${cfg.snapLen}` : `-s 0`,
    `-c 1000000`, // Max 1M packets safety limit
    `'${bpfFilter}'`,
    `> /tmp/autocap_${sessionId}.log 2>&1 &`,
    `echo $!`,
  ].join(" ");

  try {
    const { executeTool } = await import("./scan-server-executor");
    const result = await executeTool({
      tool: "bash",
      args: `-c "${tcpdumpCmd.replace(/"/g, '\\"')}"`,
      timeoutSeconds: 10,
      sudo: true,
      engagementId,
    });

    const pid = parseInt(result.stdout.trim());
    if (isNaN(pid) || pid <= 0) {
      console.error(`[AutoCapture] Failed to get PID for ${targetIp}: ${result.stdout} ${result.stderr}`);
      return null;
    }

    const session: AutoCaptureSession = {
      sessionId,
      engagementId,
      targetIp,
      targetHostname,
      pcapPath,
      pid,
      startedAt: Date.now(),
    };

    activeSessions.set(sessionId, session);
    console.log(`[AutoCapture] Started capture for ${targetIp} (PID: ${pid}, PCAP: ${pcapPath})`);
    return session;
  } catch (err: any) {
    console.error(`[AutoCapture] Failed to start capture for ${targetIp}: ${err.message}`);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════
// §4 — STOP CAPTURE (after nmap)
// ═══════════════════════════════════════════════════════════════

/**
 * Stop a background tcpdump capture on the scan server.
 * Called automatically after nmap finishes scanning a target.
 *
 * @returns The completed session with packet count, or null if no active session
 */
export async function stopAutoCapture(
  sessionId: string,
  config: Partial<AutoCaptureConfig> = {},
): Promise<AutoCaptureSession | null> {
  const cfg = { ...DEFAULT_AUTO_CAPTURE_CONFIG, ...config };
  const session = activeSessions.get(sessionId);
  if (!session) {
    console.warn(`[AutoCapture] No active session: ${sessionId}`);
    return null;
  }

  try {
    const { executeTool } = await import("./scan-server-executor");

    // Kill the tcpdump process
    await executeTool({
      tool: "bash",
      args: `-c "kill ${session.pid} 2>/dev/null; sleep 1; kill -9 ${session.pid} 2>/dev/null; true"`,
      timeoutSeconds: 10,
      sudo: true,
    });

    session.stoppedAt = Date.now();

    // Get packet count from the PCAP file
    const countResult = await executeTool({
      tool: "bash",
      args: `-c "capinfos -c '${session.pcapPath}' 2>/dev/null | grep 'Number of packets' | awk '{print \\$NF}'"`,
      timeoutSeconds: 10,
    });
    session.packetsCaptured = parseInt(countResult.stdout.trim()) || 0;

    // Move from active to completed
    activeSessions.delete(sessionId);
    if (!completedSessions.has(session.engagementId)) {
      completedSessions.set(session.engagementId, []);
    }
    completedSessions.get(session.engagementId)!.push(session);

    console.log(`[AutoCapture] Stopped capture ${sessionId}: ${session.packetsCaptured} packets in ${session.stoppedAt - session.startedAt}ms`);

    // Auto-analyze if configured
    if (cfg.autoAnalyze && session.packetsCaptured > 0) {
      await analyzeAutoCapture(session, cfg);
    }

    return session;
  } catch (err: any) {
    console.error(`[AutoCapture] Failed to stop capture ${sessionId}: ${err.message}`);
    // Still move to completed even on error
    activeSessions.delete(sessionId);
    session.stoppedAt = Date.now();
    if (!completedSessions.has(session.engagementId)) {
      completedSessions.set(session.engagementId, []);
    }
    completedSessions.get(session.engagementId)!.push(session);
    return session;
  }
}

// ═══════════════════════════════════════════════════════════════
// §5 — ANALYZE CAPTURE (post-scan forensics)
// ═══════════════════════════════════════════════════════════════

/**
 * Analyze a completed auto-capture PCAP file.
 * Runs tshark analysis, detects findings, and optionally ingests into SSIL.
 */
export async function analyzeAutoCapture(
  session: AutoCaptureSession,
  config: Partial<AutoCaptureConfig> = {},
): Promise<AutoCaptureSession> {
  const cfg = { ...DEFAULT_AUTO_CAPTURE_CONFIG, ...config };

  try {
    const { analyzePcap, detectFindings, ingestPcapResults } = await import("./pcap-analyzer");

    // Run full tshark analysis
    const analysis = await analyzePcap({
      pcapPath: session.pcapPath,
      maxPackets: 50000,
      protocols: ["tcp", "udp", "http", "tls", "dns", "icmp"],
      extractStreams: true,
    });

    // Detect security findings
    const findings = detectFindings(analysis.packets);

    // Build summary
    session.analysisSummary = {
      totalPackets: analysis.metadata.packetCount,
      protocols: analysis.protocolStats.map(p => p.protocol),
      conversations: analysis.conversations.length,
      findings: findings.length,
      findingsBySeverity: findings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {} as Record<string, number>),
    };
    session.analyzed = true;

    // Auto-ingest into SSIL pipeline
    if (cfg.autoIngest && findings.length > 0) {
      await ingestPcapResults(findings, analysis.packets);
      console.log(`[AutoCapture] Ingested ${findings.length} findings from ${session.sessionId} into SSIL`);
    }

    console.log(`[AutoCapture] Analysis complete for ${session.sessionId}: ${analysis.metadata.packetCount} packets, ${findings.length} findings`);
    return session;
  } catch (err: any) {
    console.error(`[AutoCapture] Analysis failed for ${session.sessionId}: ${err.message}`);
    session.analyzed = false;
    return session;
  }
}

// ═══════════════════════════════════════════════════════════════
// §6 — ENGAGEMENT ORCHESTRATOR HOOKS
// ═══════════════════════════════════════════════════════════════

/**
 * Hook: Call before starting nmap scan on a target.
 * Returns the session ID to pass to the post-scan hook.
 */
export async function beforeNmapScan(
  engagementId: number,
  targetIp: string,
  targetHostname: string,
  config?: Partial<AutoCaptureConfig>,
): Promise<string | null> {
  const session = await startAutoCapture(engagementId, targetIp, targetHostname, config);
  return session?.sessionId || null;
}

/**
 * Hook: Call after nmap scan completes on a target.
 * Stops capture, analyzes PCAP, and returns findings summary.
 */
export async function afterNmapScan(
  sessionId: string | null,
  config?: Partial<AutoCaptureConfig>,
): Promise<AutoCaptureSession | null> {
  if (!sessionId) return null;
  return await stopAutoCapture(sessionId, config);
}

/**
 * Hook: Call when engagement completes to clean up PCAP files.
 */
export async function cleanupEngagementCaptures(engagementId: number): Promise<void> {
  const sessions = completedSessions.get(engagementId);
  if (!sessions || sessions.length === 0) return;

  try {
    const { executeTool } = await import("./scan-server-executor");
    const paths = sessions.map(s => s.pcapPath).join(" ");
    await executeTool({
      tool: "bash",
      args: `-c "rm -f ${paths} /tmp/autocap_${engagementId}_*.log 2>/dev/null; true"`,
      timeoutSeconds: 10,
    });
    console.log(`[AutoCapture] Cleaned up ${sessions.length} PCAP files for engagement ${engagementId}`);
  } catch (err: any) {
    console.error(`[AutoCapture] Cleanup failed for engagement ${engagementId}: ${err.message}`);
  }

  completedSessions.delete(engagementId);
}

/**
 * Kill all active captures for an engagement (e.g., on abort).
 */
export async function abortEngagementCaptures(engagementId: number): Promise<void> {
  const toAbort: string[] = [];
  for (const [id, session] of activeSessions) {
    if (session.engagementId === engagementId) {
      toAbort.push(id);
    }
  }

  for (const id of toAbort) {
    await stopAutoCapture(id, { autoAnalyze: false, autoIngest: false, enabled: true, maxDuration: 0, snapLen: 0, interface: "eth0" });
  }
}
