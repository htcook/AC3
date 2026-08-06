/**
 * PCAP Replay Module — Traffic Replay & Regression Testing
 * ═══════════════════════════════════════════════════════════════
 * Uses tcpreplay on the scan server to replay captured PCAP files
 * for regression testing against new detection rules, IDS tuning,
 * and forensic analysis.
 *
 * Capabilities:
 *   1. tcpreplay   — Replay PCAP at original or modified speed
 *   2. tcprewrite  — Modify packets before replay (rewrite IPs, MACs, ports)
 *   3. tcpprep     — Classify traffic for client/server splitting
 *   4. Replay scheduling — Queue replays with different configurations
 *   5. Detection comparison — Compare IDS/IPS alerts before/after rule changes
 *
 * Architecture:
 *   Dashboard → configure replay → SSH → scan server (tcpreplay) → capture results → compare
 *
 * @module pcap-replay
 */

// ═══════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════

export type ReplaySpeed = "original" | "topspeed" | "custom";
export type ReplayStatus = "queued" | "preparing" | "replaying" | "capturing" | "analyzing" | "completed" | "failed" | "cancelled";

export interface ReplayConfig {
  /** Path to PCAP file on scan server */
  pcapPath: string;
  /** Replay speed mode */
  speed: ReplaySpeed;
  /** Custom multiplier (e.g., 2.0 = 2x speed, 0.5 = half speed) */
  speedMultiplier?: number;
  /** Network interface to replay on */
  interface: string;
  /** Number of times to loop the replay */
  loopCount: number;
  /** Whether to rewrite destination IPs */
  rewriteDestIp?: string;
  /** Whether to rewrite source IPs */
  rewriteSrcIp?: string;
  /** Whether to rewrite destination MAC */
  rewriteDestMac?: string;
  /** Whether to rewrite source MAC */
  rewriteSrcMac?: string;
  /** Port remapping (e.g., "80:8080" remaps port 80 to 8080) */
  portRemap?: string[];
  /** Whether to capture responses during replay for comparison */
  captureResponses: boolean;
  /** BPF filter for response capture */
  captureFilter?: string;
  /** Max duration in seconds (safety limit) */
  maxDuration: number;
  /** Engagement ID for audit trail */
  engagementId?: number;
  /** Description / label for this replay */
  label?: string;
}

export interface ReplayResult {
  /** Unique replay ID */
  replayId: string;
  /** Configuration used */
  config: ReplayConfig;
  /** Current status */
  status: ReplayStatus;
  /** Timestamp when replay started */
  startedAt: number;
  /** Timestamp when replay completed */
  completedAt?: number;
  /** Duration in milliseconds */
  durationMs?: number;
  /** tcpreplay statistics */
  stats: ReplayStats;
  /** Response capture PCAP path (if captureResponses was true) */
  responsePcapPath?: string;
  /** Comparison results (if comparing against baseline) */
  comparison?: ReplayComparison;
  /** Error message if failed */
  error?: string;
}

export interface ReplayStats {
  /** Total packets sent */
  packetsSent: number;
  /** Total bytes sent */
  bytesSent: number;
  /** Packets that failed to send */
  packetsFailed: number;
  /** Actual replay duration in seconds */
  replayDurationSec: number;
  /** Average packets per second */
  avgPps: number;
  /** Average megabits per second */
  avgMbps: number;
  /** Number of loops completed */
  loopsCompleted: number;
}

export interface ReplayComparison {
  /** Baseline replay ID */
  baselineReplayId: string;
  /** Current replay ID */
  currentReplayId: string;
  /** Packets in baseline */
  baselinePackets: number;
  /** Packets in current */
  currentPackets: number;
  /** New conversations not in baseline */
  newConversations: number;
  /** Missing conversations from baseline */
  missingConversations: number;
  /** Protocol distribution changes */
  protocolDelta: Record<string, { baseline: number; current: number; delta: number }>;
  /** Summary verdict */
  verdict: "identical" | "minor_changes" | "significant_changes" | "major_divergence";
}

export interface RewriteRule {
  /** Type of rewrite */
  type: "src_ip" | "dst_ip" | "src_mac" | "dst_mac" | "port_remap" | "tos" | "ttl";
  /** Original value (for display) */
  original?: string;
  /** New value */
  value: string;
}

/** Default replay configuration */
export const DEFAULT_REPLAY_CONFIG: ReplayConfig = {
  pcapPath: "",
  speed: "original",
  interface: "eth0",
  loopCount: 1,
  captureResponses: true,
  maxDuration: 300,
};

// ═══════════════════════════════════════════════════════════════
// §2 — REPLAY SESSION REGISTRY
// ═══════════════════════════════════════════════════════════════

const replayHistory = new Map<number, ReplayResult[]>(); // engagementId → results
let replayCounter = 0;

function generateReplayId(): string {
  return `replay-${++replayCounter}-${Date.now()}`;
}

/**
 * Get all replay results for an engagement
 */
export function getReplayHistory(engagementId: number): ReplayResult[] {
  return replayHistory.get(engagementId) || [];
}

/**
 * Get all replay results across all engagements
 */
export function getAllReplays(): ReplayResult[] {
  const all: ReplayResult[] = [];
  for (const results of replayHistory.values()) {
    all.push(...results);
  }
  return all.sort((a, b) => b.startedAt - a.startedAt);
}

// ═══════════════════════════════════════════════════════════════
// §3 — COMMAND BUILDERS
// ═══════════════════════════════════════════════════════════════

/**
 * Build tcprewrite command for packet modification before replay
 */
export function buildRewriteCommand(pcapPath: string, outputPath: string, config: ReplayConfig): string | null {
  const rules: string[] = [];

  if (config.rewriteDestIp) {
    rules.push(`--dstipmap=0.0.0.0/0:${config.rewriteDestIp}/32`);
  }
  if (config.rewriteSrcIp) {
    rules.push(`--srcipmap=0.0.0.0/0:${config.rewriteSrcIp}/32`);
  }
  if (config.rewriteDestMac) {
    rules.push(`--enet-dmac=${config.rewriteDestMac}`);
  }
  if (config.rewriteSrcMac) {
    rules.push(`--enet-smac=${config.rewriteSrcMac}`);
  }
  if (config.portRemap && config.portRemap.length > 0) {
    for (const remap of config.portRemap) {
      rules.push(`--portmap=${remap}`);
    }
  }

  if (rules.length === 0) return null;

  return `tcprewrite --infile=${pcapPath} --outfile=${outputPath} ${rules.join(" ")}`;
}

/**
 * Build tcpreplay command
 */
export function buildReplayCommand(pcapPath: string, config: ReplayConfig): string {
  const parts = [`tcpreplay`];

  // Interface
  parts.push(`--intf1=${config.interface}`);

  // Speed control
  switch (config.speed) {
    case "topspeed":
      parts.push("--topspeed");
      break;
    case "custom":
      if (config.speedMultiplier) {
        parts.push(`--multiplier=${config.speedMultiplier}`);
      }
      break;
    case "original":
    default:
      // No flag = original timing
      break;
  }

  // Loop count
  if (config.loopCount > 1) {
    parts.push(`--loop=${config.loopCount}`);
  }

  // Stats output
  parts.push("--stats=1");

  // Input file
  parts.push(pcapPath);

  return parts.join(" ");
}

/**
 * Build tcpdump command for capturing responses during replay
 */
export function buildResponseCaptureCommand(
  outputPath: string,
  iface: string,
  filter?: string,
  durationSec: number = 300,
): string {
  const parts = [
    `tcpdump -i ${iface}`,
    `-w ${outputPath}`,
    `-s 0`,
    `-c 1000000`,
  ];

  if (filter) {
    parts.push(`'${filter}'`);
  }

  // Run with timeout
  return `timeout ${durationSec} ${parts.join(" ")} &`;
}

// ═══════════════════════════════════════════════════════════════
// §4 — STATS PARSER
// ═══════════════════════════════════════════════════════════════

/**
 * Parse tcpreplay output into structured stats
 */
export function parseReplayStats(output: string): ReplayStats {
  const stats: ReplayStats = {
    packetsSent: 0,
    bytesSent: 0,
    packetsFailed: 0,
    replayDurationSec: 0,
    avgPps: 0,
    avgMbps: 0,
    loopsCompleted: 0,
  };

  // Parse "Actual: X packets (Y bytes) sent in Z seconds"
  const actualMatch = output.match(/Actual:\s*(\d+)\s*packets?\s*\((\d+)\s*bytes?\)\s*sent\s*in\s*([\d.]+)\s*seconds?/i);
  if (actualMatch) {
    stats.packetsSent = parseInt(actualMatch[1]);
    stats.bytesSent = parseInt(actualMatch[2]);
    stats.replayDurationSec = parseFloat(actualMatch[3]);
  }

  // Parse "Failed to send X packets"
  const failedMatch = output.match(/Failed.*?(\d+)\s*packets?/i);
  if (failedMatch) {
    stats.packetsFailed = parseInt(failedMatch[1]);
  }

  // Parse "X.XX packets/s"
  const ppsMatch = output.match(/([\d.]+)\s*packets?\/s/i);
  if (ppsMatch) {
    stats.avgPps = parseFloat(ppsMatch[1]);
  }

  // Parse "X.XX Mbps"
  const mbpsMatch = output.match(/([\d.]+)\s*Mb(?:ps|it\/s)/i);
  if (mbpsMatch) {
    stats.avgMbps = parseFloat(mbpsMatch[1]);
  }

  // Calculate PPS from actual if not parsed
  if (stats.avgPps === 0 && stats.replayDurationSec > 0) {
    stats.avgPps = Math.round(stats.packetsSent / stats.replayDurationSec);
  }

  // Parse loop count
  const loopMatch = output.match(/Loop\s*(\d+)/i);
  if (loopMatch) {
    stats.loopsCompleted = parseInt(loopMatch[1]);
  } else if (stats.packetsSent > 0) {
    stats.loopsCompleted = 1;
  }

  return stats;
}

// ═══════════════════════════════════════════════════════════════
// §5 — REPLAY EXECUTION
// ═══════════════════════════════════════════════════════════════

/**
 * Execute a PCAP replay on the scan server.
 * Optionally captures responses for comparison.
 */
export async function executeReplay(config: ReplayConfig): Promise<ReplayResult> {
  const replayId = generateReplayId();
  const engagementId = config.engagementId || 0;

  const result: ReplayResult = {
    replayId,
    config,
    status: "preparing",
    startedAt: Date.now(),
    stats: {
      packetsSent: 0,
      bytesSent: 0,
      packetsFailed: 0,
      replayDurationSec: 0,
      avgPps: 0,
      avgMbps: 0,
      loopsCompleted: 0,
    },
  };

  // Store in history
  if (!replayHistory.has(engagementId)) {
    replayHistory.set(engagementId, []);
  }
  replayHistory.get(engagementId)!.push(result);

  try {
    const { executeTool } = await import("./scan-server-executor");

    // Step 1: Verify PCAP file exists
    const checkResult = await executeTool({
      tool: "bash",
      args: `-c "test -f '${config.pcapPath}' && capinfos -c '${config.pcapPath}' 2>/dev/null | grep 'Number of packets' | awk '{print \\$NF}'"`,
      timeoutSeconds: 10,
    });

    if (checkResult.exitCode !== 0) {
      result.status = "failed";
      result.error = `PCAP file not found: ${config.pcapPath}`;
      result.completedAt = Date.now();
      return result;
    }

    // Step 2: Rewrite packets if needed
    let replayPcapPath = config.pcapPath;
    const rewriteCmd = buildRewriteCommand(config.pcapPath, `/tmp/rewritten_${replayId}.pcap`, config);
    if (rewriteCmd) {
      result.status = "preparing";
      const rewriteResult = await executeTool({
        tool: "bash",
        args: `-c "${rewriteCmd}"`,
        timeoutSeconds: 60,
        sudo: true,
      });
      if (rewriteResult.exitCode === 0) {
        replayPcapPath = `/tmp/rewritten_${replayId}.pcap`;
      } else {
        console.warn(`[Replay] Rewrite failed, using original PCAP: ${rewriteResult.stderr}`);
      }
    }

    // Step 3: Start response capture if enabled
    let responsePcapPath: string | undefined;
    if (config.captureResponses) {
      responsePcapPath = `/tmp/replay_response_${replayId}.pcap`;
      const captureCmd = buildResponseCaptureCommand(
        responsePcapPath,
        config.interface,
        config.captureFilter,
        config.maxDuration,
      );
      await executeTool({
        tool: "bash",
        args: `-c "${captureCmd}"`,
        timeoutSeconds: 5,
        sudo: true,
      });
      result.responsePcapPath = responsePcapPath;
    }

    // Step 4: Execute replay
    result.status = "replaying";
    const replayCmd = buildReplayCommand(replayPcapPath, config);
    const replayExec = await executeTool({
      tool: "bash",
      args: `-c "timeout ${config.maxDuration} ${replayCmd} 2>&1"`,
      timeoutSeconds: config.maxDuration + 30,
      sudo: true,
      engagementId,
    });

    // Step 5: Parse results
    result.stats = parseReplayStats(replayExec.stdout + "\n" + replayExec.stderr);
    result.completedAt = Date.now();
    result.durationMs = result.completedAt - result.startedAt;

    // Step 6: Stop response capture
    if (config.captureResponses) {
      await executeTool({
        tool: "bash",
        args: `-c "pkill -f 'tcpdump.*${responsePcapPath}' 2>/dev/null; sleep 1; true"`,
        timeoutSeconds: 10,
        sudo: true,
      });
    }

    // Clean up rewritten PCAP if we created one
    if (replayPcapPath !== config.pcapPath) {
      await executeTool({
        tool: "bash",
        args: `-c "rm -f '${replayPcapPath}' 2>/dev/null; true"`,
        timeoutSeconds: 5,
      });
    }

    result.status = replayExec.exitCode === 0 || result.stats.packetsSent > 0 ? "completed" : "failed";
    if (result.status === "failed") {
      result.error = replayExec.stderr || "tcpreplay exited with non-zero status";
    }

    return result;
  } catch (err: any) {
    result.status = "failed";
    result.error = err.message;
    result.completedAt = Date.now();
    result.durationMs = result.completedAt - result.startedAt;
    return result;
  }
}

// ═══════════════════════════════════════════════════════════════
// §6 — COMPARISON ENGINE
// ═══════════════════════════════════════════════════════════════

/**
 * Compare two replay response captures.
 * Useful for regression testing: replay same traffic before/after rule changes.
 */
export async function compareReplays(
  baselineReplayId: string,
  currentReplayId: string,
  engagementId: number,
): Promise<ReplayComparison | null> {
  const history = replayHistory.get(engagementId) || [];
  const baseline = history.find(r => r.replayId === baselineReplayId);
  const current = history.find(r => r.replayId === currentReplayId);

  if (!baseline?.responsePcapPath || !current?.responsePcapPath) {
    return null;
  }

  try {
    const { executeTool } = await import("./scan-server-executor");
    const { parseConversations, parseProtocolStats } = await import("./pcap-analyzer");

    // Get conversation stats for both
    const [baseConvResult, currConvResult] = await Promise.all([
      executeTool({
        tool: "bash",
        args: `-c "tshark -r '${baseline.responsePcapPath}' -q -z conv,ip 2>/dev/null"`,
        timeoutSeconds: 30,
      }),
      executeTool({
        tool: "bash",
        args: `-c "tshark -r '${current.responsePcapPath}' -q -z conv,ip 2>/dev/null"`,
        timeoutSeconds: 30,
      }),
    ]);

    const baseConversations = parseConversations(baseConvResult.stdout);
    const currConversations = parseConversations(currConvResult.stdout);

    // Get protocol stats for both
    const [baseProtoResult, currProtoResult] = await Promise.all([
      executeTool({
        tool: "bash",
        args: `-c "tshark -r '${baseline.responsePcapPath}' -q -z io,phs 2>/dev/null"`,
        timeoutSeconds: 30,
      }),
      executeTool({
        tool: "bash",
        args: `-c "tshark -r '${current.responsePcapPath}' -q -z io,phs 2>/dev/null"`,
        timeoutSeconds: 30,
      }),
    ]);

    const baseProtos = parseProtocolStats(baseProtoResult.stdout);
    const currProtos = parseProtocolStats(currProtoResult.stdout);

    // Build protocol delta
    const protocolDelta: Record<string, { baseline: number; current: number; delta: number }> = {};
    const allProtocols = new Set([
      ...baseProtos.map(p => p.protocol),
      ...currProtos.map(p => p.protocol),
    ]);
    for (const proto of allProtocols) {
      const baseCount = baseProtos.find(p => p.protocol === proto)?.packets || 0;
      const currCount = currProtos.find(p => p.protocol === proto)?.packets || 0;
      protocolDelta[proto] = { baseline: baseCount, current: currCount, delta: currCount - baseCount };
    }

    // Determine new/missing conversations
    const baseConvKeys = new Set(baseConversations.map(c => `${c.srcAddr}-${c.dstAddr}`));
    const currConvKeys = new Set(currConversations.map(c => `${c.srcAddr}-${c.dstAddr}`));
    const newConversations = [...currConvKeys].filter(k => !baseConvKeys.has(k)).length;
    const missingConversations = [...baseConvKeys].filter(k => !currConvKeys.has(k)).length;

    // Determine verdict
    const totalDelta = Object.values(protocolDelta).reduce((sum, d) => sum + Math.abs(d.delta), 0);
    const totalBaseline = baseline.stats.packetsSent || 1;
    const changeRatio = totalDelta / totalBaseline;

    let verdict: ReplayComparison["verdict"];
    if (changeRatio < 0.01 && newConversations === 0 && missingConversations === 0) {
      verdict = "identical";
    } else if (changeRatio < 0.1 && newConversations + missingConversations <= 2) {
      verdict = "minor_changes";
    } else if (changeRatio < 0.3) {
      verdict = "significant_changes";
    } else {
      verdict = "major_divergence";
    }

    const comparison: ReplayComparison = {
      baselineReplayId,
      currentReplayId,
      baselinePackets: baseline.stats.packetsSent,
      currentPackets: current.stats.packetsSent,
      newConversations,
      missingConversations,
      protocolDelta,
      verdict,
    };

    // Store on current result
    current.comparison = comparison;
    return comparison;
  } catch (err: any) {
    console.error(`[Replay] Comparison failed: ${err.message}`);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════
// §7 — PCAP FILE MANAGEMENT
// ═══════════════════════════════════════════════════════════════

/**
 * List available PCAP files on the scan server
 */
export async function listPcapFiles(): Promise<Array<{
  path: string;
  filename: string;
  sizeBytes: number;
  modifiedAt: string;
  packetCount?: number;
}>> {
  try {
    const { executeTool } = await import("./scan-server-executor");
    const result = await executeTool({
      tool: "bash",
      args: `-c "find /tmp -name '*.pcap' -o -name '*.pcapng' 2>/dev/null | while read f; do stat --printf='%n|%s|%Y\\n' \\\"\\$f\\\" 2>/dev/null; done"`,
      timeoutSeconds: 15,
    });

    const files: Array<{ path: string; filename: string; sizeBytes: number; modifiedAt: string; packetCount?: number }> = [];
    for (const line of result.stdout.split("\n").filter(Boolean)) {
      const [path, size, mtime] = line.split("|");
      if (path && size) {
        files.push({
          path: path.trim(),
          filename: path.split("/").pop() || path,
          sizeBytes: parseInt(size) || 0,
          modifiedAt: new Date(parseInt(mtime || "0") * 1000).toISOString(),
        });
      }
    }

    return files.sort((a, b) => b.sizeBytes - a.sizeBytes);
  } catch (err: any) {
    console.error(`[Replay] Failed to list PCAP files: ${err.message}`);
    return [];
  }
}

/**
 * Upload a PCAP file to the scan server for replay
 */
export async function uploadPcapToScanServer(
  fileBuffer: Buffer,
  filename: string,
): Promise<string> {
  const { executeTool } = await import("./scan-server-executor");
  const remotePath = `/tmp/uploaded_${Date.now()}_${filename}`;

  // Base64 encode and decode on remote
  const b64 = fileBuffer.toString("base64");
  // Split into chunks to avoid command line length limits
  const chunkSize = 65000;
  const chunks = [];
  for (let i = 0; i < b64.length; i += chunkSize) {
    chunks.push(b64.slice(i, i + chunkSize));
  }

  // Write chunks
  await executeTool({
    tool: "bash",
    args: `-c "echo -n '' > ${remotePath}.b64"`,
    timeoutSeconds: 5,
  });
  for (const chunk of chunks) {
    await executeTool({
      tool: "bash",
      args: `-c "echo -n '${chunk}' >> ${remotePath}.b64"`,
      timeoutSeconds: 10,
    });
  }
  await executeTool({
    tool: "bash",
    args: `-c "base64 -d ${remotePath}.b64 > ${remotePath} && rm ${remotePath}.b64"`,
    timeoutSeconds: 30,
  });

  return remotePath;
}

/**
 * Provision tcpreplay tools on the scan server
 */
export async function provisionReplayTools(): Promise<{
  success: boolean;
  installed: string[];
  failed: string[];
}> {
  const { executeTool } = await import("./scan-server-executor");
  const installed: string[] = [];
  const failed: string[] = [];

  const installCmd = `DEBIAN_FRONTEND=noninteractive apt-get install -y tcpreplay 2>&1`;
  try {
    const result = await executeTool({
      tool: "bash",
      args: `-c "${installCmd}"`,
      timeoutSeconds: 120,
      sudo: true,
    });
    if (result.exitCode === 0) {
      installed.push("tcpreplay", "tcprewrite", "tcpprep");
    } else {
      failed.push("tcpreplay");
    }
  } catch {
    failed.push("tcpreplay");
  }

  return { success: failed.length === 0, installed, failed };
}
