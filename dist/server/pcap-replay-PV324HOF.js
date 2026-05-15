import "./chunk-KFQGP6VL.js";

// server/lib/pcap-replay.ts
var DEFAULT_REPLAY_CONFIG = {
  pcapPath: "",
  speed: "original",
  interface: "eth0",
  loopCount: 1,
  captureResponses: true,
  maxDuration: 300
};
var replayHistory = /* @__PURE__ */ new Map();
var replayCounter = 0;
function generateReplayId() {
  return `replay-${++replayCounter}-${Date.now()}`;
}
function getReplayHistory(engagementId) {
  return replayHistory.get(engagementId) || [];
}
function getAllReplays() {
  const all = [];
  for (const results of replayHistory.values()) {
    all.push(...results);
  }
  return all.sort((a, b) => b.startedAt - a.startedAt);
}
function buildRewriteCommand(pcapPath, outputPath, config) {
  const rules = [];
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
function buildReplayCommand(pcapPath, config) {
  const parts = [`tcpreplay`];
  parts.push(`--intf1=${config.interface}`);
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
      break;
  }
  if (config.loopCount > 1) {
    parts.push(`--loop=${config.loopCount}`);
  }
  parts.push("--stats=1");
  parts.push(pcapPath);
  return parts.join(" ");
}
function buildResponseCaptureCommand(outputPath, iface, filter, durationSec = 300) {
  const parts = [
    `tcpdump -i ${iface}`,
    `-w ${outputPath}`,
    `-s 0`,
    `-c 1000000`
  ];
  if (filter) {
    parts.push(`'${filter}'`);
  }
  return `timeout ${durationSec} ${parts.join(" ")} &`;
}
function parseReplayStats(output) {
  const stats = {
    packetsSent: 0,
    bytesSent: 0,
    packetsFailed: 0,
    replayDurationSec: 0,
    avgPps: 0,
    avgMbps: 0,
    loopsCompleted: 0
  };
  const actualMatch = output.match(/Actual:\s*(\d+)\s*packets?\s*\((\d+)\s*bytes?\)\s*sent\s*in\s*([\d.]+)\s*seconds?/i);
  if (actualMatch) {
    stats.packetsSent = parseInt(actualMatch[1]);
    stats.bytesSent = parseInt(actualMatch[2]);
    stats.replayDurationSec = parseFloat(actualMatch[3]);
  }
  const failedMatch = output.match(/Failed.*?(\d+)\s*packets?/i);
  if (failedMatch) {
    stats.packetsFailed = parseInt(failedMatch[1]);
  }
  const ppsMatch = output.match(/([\d.]+)\s*packets?\/s/i);
  if (ppsMatch) {
    stats.avgPps = parseFloat(ppsMatch[1]);
  }
  const mbpsMatch = output.match(/([\d.]+)\s*Mb(?:ps|it\/s)/i);
  if (mbpsMatch) {
    stats.avgMbps = parseFloat(mbpsMatch[1]);
  }
  if (stats.avgPps === 0 && stats.replayDurationSec > 0) {
    stats.avgPps = Math.round(stats.packetsSent / stats.replayDurationSec);
  }
  const loopMatch = output.match(/Loop\s*(\d+)/i);
  if (loopMatch) {
    stats.loopsCompleted = parseInt(loopMatch[1]);
  } else if (stats.packetsSent > 0) {
    stats.loopsCompleted = 1;
  }
  return stats;
}
async function executeReplay(config) {
  const replayId = generateReplayId();
  const engagementId = config.engagementId || 0;
  const result = {
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
      loopsCompleted: 0
    }
  };
  if (!replayHistory.has(engagementId)) {
    replayHistory.set(engagementId, []);
  }
  replayHistory.get(engagementId).push(result);
  try {
    const { executeTool } = await import("./scan-server-executor-F73PWIB5.js");
    const checkResult = await executeTool({
      tool: "bash",
      args: `-c "test -f '${config.pcapPath}' && capinfos -c '${config.pcapPath}' 2>/dev/null | grep 'Number of packets' | awk '{print \\$NF}'"`,
      timeoutSeconds: 10
    });
    if (checkResult.exitCode !== 0) {
      result.status = "failed";
      result.error = `PCAP file not found: ${config.pcapPath}`;
      result.completedAt = Date.now();
      return result;
    }
    let replayPcapPath = config.pcapPath;
    const rewriteCmd = buildRewriteCommand(config.pcapPath, `/tmp/rewritten_${replayId}.pcap`, config);
    if (rewriteCmd) {
      result.status = "preparing";
      const rewriteResult = await executeTool({
        tool: "bash",
        args: `-c "${rewriteCmd}"`,
        timeoutSeconds: 60,
        sudo: true
      });
      if (rewriteResult.exitCode === 0) {
        replayPcapPath = `/tmp/rewritten_${replayId}.pcap`;
      } else {
        console.warn(`[Replay] Rewrite failed, using original PCAP: ${rewriteResult.stderr}`);
      }
    }
    let responsePcapPath;
    if (config.captureResponses) {
      responsePcapPath = `/tmp/replay_response_${replayId}.pcap`;
      const captureCmd = buildResponseCaptureCommand(
        responsePcapPath,
        config.interface,
        config.captureFilter,
        config.maxDuration
      );
      await executeTool({
        tool: "bash",
        args: `-c "${captureCmd}"`,
        timeoutSeconds: 5,
        sudo: true
      });
      result.responsePcapPath = responsePcapPath;
    }
    result.status = "replaying";
    const replayCmd = buildReplayCommand(replayPcapPath, config);
    const replayExec = await executeTool({
      tool: "bash",
      args: `-c "timeout ${config.maxDuration} ${replayCmd} 2>&1"`,
      timeoutSeconds: config.maxDuration + 30,
      sudo: true,
      engagementId
    });
    result.stats = parseReplayStats(replayExec.stdout + "\n" + replayExec.stderr);
    result.completedAt = Date.now();
    result.durationMs = result.completedAt - result.startedAt;
    if (config.captureResponses) {
      await executeTool({
        tool: "bash",
        args: `-c "pkill -f 'tcpdump.*${responsePcapPath}' 2>/dev/null; sleep 1; true"`,
        timeoutSeconds: 10,
        sudo: true
      });
    }
    if (replayPcapPath !== config.pcapPath) {
      await executeTool({
        tool: "bash",
        args: `-c "rm -f '${replayPcapPath}' 2>/dev/null; true"`,
        timeoutSeconds: 5
      });
    }
    result.status = replayExec.exitCode === 0 || result.stats.packetsSent > 0 ? "completed" : "failed";
    if (result.status === "failed") {
      result.error = replayExec.stderr || "tcpreplay exited with non-zero status";
    }
    return result;
  } catch (err) {
    result.status = "failed";
    result.error = err.message;
    result.completedAt = Date.now();
    result.durationMs = result.completedAt - result.startedAt;
    return result;
  }
}
async function compareReplays(baselineReplayId, currentReplayId, engagementId) {
  const history = replayHistory.get(engagementId) || [];
  const baseline = history.find((r) => r.replayId === baselineReplayId);
  const current = history.find((r) => r.replayId === currentReplayId);
  if (!baseline?.responsePcapPath || !current?.responsePcapPath) {
    return null;
  }
  try {
    const { executeTool } = await import("./scan-server-executor-F73PWIB5.js");
    const { parseConversations, parseProtocolStats } = await import("./pcap-analyzer-JWTCZVPU.js");
    const [baseConvResult, currConvResult] = await Promise.all([
      executeTool({
        tool: "bash",
        args: `-c "tshark -r '${baseline.responsePcapPath}' -q -z conv,ip 2>/dev/null"`,
        timeoutSeconds: 30
      }),
      executeTool({
        tool: "bash",
        args: `-c "tshark -r '${current.responsePcapPath}' -q -z conv,ip 2>/dev/null"`,
        timeoutSeconds: 30
      })
    ]);
    const baseConversations = parseConversations(baseConvResult.stdout);
    const currConversations = parseConversations(currConvResult.stdout);
    const [baseProtoResult, currProtoResult] = await Promise.all([
      executeTool({
        tool: "bash",
        args: `-c "tshark -r '${baseline.responsePcapPath}' -q -z io,phs 2>/dev/null"`,
        timeoutSeconds: 30
      }),
      executeTool({
        tool: "bash",
        args: `-c "tshark -r '${current.responsePcapPath}' -q -z io,phs 2>/dev/null"`,
        timeoutSeconds: 30
      })
    ]);
    const baseProtos = parseProtocolStats(baseProtoResult.stdout);
    const currProtos = parseProtocolStats(currProtoResult.stdout);
    const protocolDelta = {};
    const allProtocols = /* @__PURE__ */ new Set([
      ...baseProtos.map((p) => p.protocol),
      ...currProtos.map((p) => p.protocol)
    ]);
    for (const proto of allProtocols) {
      const baseCount = baseProtos.find((p) => p.protocol === proto)?.packets || 0;
      const currCount = currProtos.find((p) => p.protocol === proto)?.packets || 0;
      protocolDelta[proto] = { baseline: baseCount, current: currCount, delta: currCount - baseCount };
    }
    const baseConvKeys = new Set(baseConversations.map((c) => `${c.srcAddr}-${c.dstAddr}`));
    const currConvKeys = new Set(currConversations.map((c) => `${c.srcAddr}-${c.dstAddr}`));
    const newConversations = [...currConvKeys].filter((k) => !baseConvKeys.has(k)).length;
    const missingConversations = [...baseConvKeys].filter((k) => !currConvKeys.has(k)).length;
    const totalDelta = Object.values(protocolDelta).reduce((sum, d) => sum + Math.abs(d.delta), 0);
    const totalBaseline = baseline.stats.packetsSent || 1;
    const changeRatio = totalDelta / totalBaseline;
    let verdict;
    if (changeRatio < 0.01 && newConversations === 0 && missingConversations === 0) {
      verdict = "identical";
    } else if (changeRatio < 0.1 && newConversations + missingConversations <= 2) {
      verdict = "minor_changes";
    } else if (changeRatio < 0.3) {
      verdict = "significant_changes";
    } else {
      verdict = "major_divergence";
    }
    const comparison = {
      baselineReplayId,
      currentReplayId,
      baselinePackets: baseline.stats.packetsSent,
      currentPackets: current.stats.packetsSent,
      newConversations,
      missingConversations,
      protocolDelta,
      verdict
    };
    current.comparison = comparison;
    return comparison;
  } catch (err) {
    console.error(`[Replay] Comparison failed: ${err.message}`);
    return null;
  }
}
async function listPcapFiles() {
  try {
    const { executeTool } = await import("./scan-server-executor-F73PWIB5.js");
    const result = await executeTool({
      tool: "bash",
      args: `-c "find /tmp -name '*.pcap' -o -name '*.pcapng' 2>/dev/null | while read f; do stat --printf='%n|%s|%Y\\n' \\"\\$f\\" 2>/dev/null; done"`,
      timeoutSeconds: 15
    });
    const files = [];
    for (const line of result.stdout.split("\n").filter(Boolean)) {
      const [path, size, mtime] = line.split("|");
      if (path && size) {
        files.push({
          path: path.trim(),
          filename: path.split("/").pop() || path,
          sizeBytes: parseInt(size) || 0,
          modifiedAt: new Date(parseInt(mtime || "0") * 1e3).toISOString()
        });
      }
    }
    return files.sort((a, b) => b.sizeBytes - a.sizeBytes);
  } catch (err) {
    console.error(`[Replay] Failed to list PCAP files: ${err.message}`);
    return [];
  }
}
async function uploadPcapToScanServer(fileBuffer, filename) {
  const { executeTool } = await import("./scan-server-executor-F73PWIB5.js");
  const remotePath = `/tmp/uploaded_${Date.now()}_${filename}`;
  const b64 = fileBuffer.toString("base64");
  const chunkSize = 65e3;
  const chunks = [];
  for (let i = 0; i < b64.length; i += chunkSize) {
    chunks.push(b64.slice(i, i + chunkSize));
  }
  await executeTool({
    tool: "bash",
    args: `-c "echo -n '' > ${remotePath}.b64"`,
    timeoutSeconds: 5
  });
  for (const chunk of chunks) {
    await executeTool({
      tool: "bash",
      args: `-c "echo -n '${chunk}' >> ${remotePath}.b64"`,
      timeoutSeconds: 10
    });
  }
  await executeTool({
    tool: "bash",
    args: `-c "base64 -d ${remotePath}.b64 > ${remotePath} && rm ${remotePath}.b64"`,
    timeoutSeconds: 30
  });
  return remotePath;
}
async function provisionReplayTools() {
  const { executeTool } = await import("./scan-server-executor-F73PWIB5.js");
  const installed = [];
  const failed = [];
  const installCmd = `DEBIAN_FRONTEND=noninteractive apt-get install -y tcpreplay 2>&1`;
  try {
    const result = await executeTool({
      tool: "bash",
      args: `-c "${installCmd}"`,
      timeoutSeconds: 120,
      sudo: true
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
export {
  DEFAULT_REPLAY_CONFIG,
  buildReplayCommand,
  buildResponseCaptureCommand,
  buildRewriteCommand,
  compareReplays,
  executeReplay,
  getAllReplays,
  getReplayHistory,
  listPcapFiles,
  parseReplayStats,
  provisionReplayTools,
  uploadPcapToScanServer
};
