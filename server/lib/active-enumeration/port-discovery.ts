/**
 * Phase 5 Sub-module: Port Discovery (Phase A Step 1)
 *
 * ScanForge multi-tool port scanning with:
 * - Auto-tool selection (Masscan/Naabu/RustScan)
 * - Evasion profile application
 * - Auto-retry on all-filtered results
 * - PCAP auto-capture hooks
 * - Passive recon port seeding fallback
 * - PARALLEL BATCH EXECUTION (up to MAX_CONCURRENT_TARGETS at once)
 */

import type { EnumerationHelpers, EngagementOpsState } from "./enumeration-context";

interface DiscoveredPort {
  port: number;
  protocol: string;
  service: string;
  product?: string;
  version?: string;
}

interface TargetEntry {
  scanTarget: string;
  assetHostname: string;
}

/** Max concurrent ScanForge scans per engagement (prevents scan server overload) */
const MAX_CONCURRENT_TARGETS = 3;

/**
 * Execute ScanForge discovery scan for all targets in parallel batches.
 * Returns after all assets have been scanned and enriched with port data.
 */
export async function executePortDiscovery(
  state: EngagementOpsState,
  targets: TargetEntry[],
  helpers: EnumerationHelpers
): Promise<void> {
  if (targets.length === 0) return;

  const ep = state.scanPlan?.discoveryEvasionProfile;
  const evasionDesc = ep
    ? `Timing: ${ep.timing}, Fragmentation: ${ep.fragmentation}, Decoys: ${ep.decoys}, Host Randomization: ${ep.randomizeHosts}, Data Padding: ${ep.dataLengthPadding}, Source Port Spoofing: ${ep.sourcePortSpoofing}`
    : "Default evasion profile";

  const parallelMode = targets.length > 1;
  helpers.addLog({
    phase: "enumeration",
    type: "scan_start",
    title: "🔍 Phase A: Discovery Scan with Evasion",
    detail: `Scanning ${targets.length} targets with full port sweep + service fingerprinting` +
      (parallelMode ? ` (parallel batches of ${Math.min(MAX_CONCURRENT_TARGETS, targets.length)})` : '') +
      `\nEvasion: ${evasionDesc}\n${state.scanPlan?.discoveryStrategy || "Comprehensive port discovery to enrich passive recon data"}`,
  });

  try {
    const { getScanServerConfigForScanForge } = await import("../scan-server-executor");
    const { autoSelectTool } = await import("../scanforge-discovery");
    const serverConfig = await getScanServerConfigForScanForge();

    // ═══ PARALLEL BATCH EXECUTION ═══
    // Process targets in batches of MAX_CONCURRENT_TARGETS to avoid overwhelming the scan server
    // while still achieving significant speedup over sequential execution.
    for (let batchStart = 0; batchStart < targets.length; batchStart += MAX_CONCURRENT_TARGETS) {
      const batch = targets.slice(batchStart, batchStart + MAX_CONCURRENT_TARGETS);

      if (batch.length > 1) {
        helpers.addLog({
          phase: "enumeration",
          type: "info",
          title: `🚀 Parallel Batch ${Math.floor(batchStart / MAX_CONCURRENT_TARGETS) + 1}/${Math.ceil(targets.length / MAX_CONCURRENT_TARGETS)}`,
          detail: `Scanning ${batch.length} targets concurrently: ${batch.map(t => t.assetHostname).join(', ')}`,
        });
      }

      // Execute all targets in this batch concurrently
      await Promise.allSettled(
        batch.map((targetEntry) =>
          scanSingleTarget(state, targetEntry, helpers, autoSelectTool)
        )
      );

      // Update progress proportionally
      const completedFraction = Math.min(batchStart + batch.length, targets.length) / targets.length;
      state.progress = Math.round(15 + completedFraction * 10); // 15-25 range for Phase A
      helpers.broadcastOpsUpdate({ type: "stats_update", stats: { ...state.stats } });
    }
  } catch (e: any) {
    helpers.addLog({
      phase: "enumeration",
      type: "error",
      title: "Discovery Scan Error",
      detail: e.message,
    });
  }
}

/**
 * Scan a single target — extracted from the original loop body for parallel execution.
 * This function is self-contained and safe to run concurrently.
 */
async function scanSingleTarget(
  state: EngagementOpsState,
  targetEntry: TargetEntry,
  helpers: EnumerationHelpers,
  autoSelectTool: (config: any) => string
): Promise<void> {
  const target = targetEntry.scanTarget;
  const asset = state.assets.find((a) => a.hostname === targetEntry.assetHostname);
  if (!asset) return;
  asset.status = "scanning";

  const assetPlan = state.scanPlan?.assetPlans.find(
    (ap) => ap.hostname === asset.hostname || ap.ip === target
  );
  const discoveryFlags =
    assetPlan?.discoveryFlags || "-Pn -sV -sC -O -f -T2 -D RND:5 --data-length 64";

  // ── ScanForge Discovery ──
  const discoveredPorts: DiscoveredPort[] = [];
  const sfTool = autoSelectTool({
    targets: [target],
    stealthLevel: assetPlan?.evasionTechniques?.length ? "medium" : "minimal",
  });
  const discoveryRationale = `ScanForge ${sfTool} — top ports discovery with service fingerprinting`;

  helpers.addLog({
    phase: "enumeration",
    type: "scan_start",
    title: `🔒 scanforge: ${helpers.fmtTarget(asset, target)}`,
    detail: `Phase A Step 1 — ${discoveryRationale}\nEvasion: ${assetPlan?.evasionTechniques?.join(", ") || "fragmentation, decoys, normal timing"}`,
  });

  const startTime = Date.now();

  // ═══ AUTO-CAPTURE: Start tcpdump ═══
  let autoCaptureSessionId: string | null = null;
  try {
    const { beforeDiscoveryScan } = await import("../pcap-auto-capture");
    autoCaptureSessionId = await beforeDiscoveryScan(
      state.engagementId,
      target,
      asset.hostname,
      { enabled: !!(state as any).autoCaptureEnabled }
    );
    if (autoCaptureSessionId) {
      helpers.addLog({
        phase: "enumeration",
        type: "info",
        title: `📡 Auto-Capture: ${helpers.fmtTarget(asset, target)}`,
        detail: `Background tcpdump started for forensic analysis during discovery scan`,
      });
    }
  } catch (capErr: any) {
    console.warn(`[AutoCapture] Hook failed: ${capErr.message}`);
  }

  try {
    // Build ScanForge command based on tool
    const sfArgs =
      sfTool === "naabu"
        ? `-host ${target} -top-ports 1000 -s s -no-stdin -rate 1000 -retries 1 -json`
        : sfTool === "masscan"
        ? `${target} -p1-1024,1720,2000,2427,3306,3389,5060,5061,5080,5432,5900,6379,8080,8443,9090,27017,41795 --rate 1000 -oJ -`
        : sfTool === "rustscan"
        ? `-a ${target} --range 1-65535 -b 4500 -g`
        : `-host ${target} -top-ports 1000 -s s -no-stdin -json`;

    helpers.addLog({
      phase: "enumeration",
      type: "tool_exec",
      title: `${sfTool} ${helpers.fmtTarget(asset, target)}`,
      detail: `${sfTool} ${sfArgs}`,
    });

    const discoveryResult = await helpers.executeTool({
      tool: sfTool,
      args: sfArgs,
      timeoutSeconds: 1200, // 20 minutes for full port range scans
      sudo: sfTool === "masscan" || sfTool === "zmap" || sfTool === "naabu",
    });

    // Parse output
    if (discoveryResult.stdout) {
      try {
        const discovery = await import("../scanforge-discovery");
        const parser =
          sfTool === "masscan"
            ? discovery.parseMasscanOutput
            : sfTool === "naabu"
            ? discovery.parseNaabuOutput
            : sfTool === "rustscan"
            ? discovery.parseRustScanOutput
            : discovery.parseNaabuOutput;
        const hosts = parser(discoveryResult.stdout);
        for (const host of hosts) {
          for (const p of host.ports) {
            discoveredPorts.push({
              port: p.port,
              protocol: p.protocol,
              service: p.service || "unknown",
              product: p.product,
              version: p.version,
            });
          }
        }
      } catch (parseErr: any) {
        // Fallback: line-based parsing
        const portRegex = /(\d+)\/(tcp|udp)\s+open\s+(\S+)/g;
        let match;
        while ((match = portRegex.exec(discoveryResult.stdout)) !== null) {
          discoveredPorts.push({
            port: parseInt(match[1]),
            protocol: match[2] as any,
            service: match[3] || "unknown",
          });
        }
      }
    }

    let durationMs = Date.now() - startTime;

    // ── AUTO-RETRY: If 0 ports and "filtered" output ──
    const allFiltered =
      discoveredPorts.length === 0 &&
      discoveryResult.stdout &&
      /All \d+ scanned ports.*filtered|\d+\/tcp\s+filtered/.test(discoveryResult.stdout);
    const hasEvasionFlags = /\-f\b|\-D\s|--data-length|--source-port|--mtu/.test(discoveryFlags);

    if (allFiltered && hasEvasionFlags) {
      helpers.addLog({
        phase: "enumeration",
        type: "info",
        title: `⚠️ scanforge Retry: ${helpers.fmtTarget(asset, target)} (removing evasion flags)`,
        detail: `First scan returned all-filtered (likely cloud WAF blocking evasion techniques). Retrying with naabu (most reliable fallback)`,
      });

      const retryArgs = `-host ${target} -top-ports 1000 -s s -no-stdin -rate 1000 -retries 1 -json`;
      const retryStart = Date.now();
      try {
        const retryResult = await helpers.executeTool({
          tool: sfTool || "naabu",
          args: retryArgs,
          timeoutSeconds: 600,
          sudo: true,
        });
        if (retryResult.stdout) {
          const tcpRegex2 = /(\d+)\/tcp\s+open\s+(\S+)(?:\s+(.*))?/g;
          let m2;
          while ((m2 = tcpRegex2.exec(retryResult.stdout)) !== null) {
            const pv = m2[3]?.trim() || "";
            const pts = pv.split(/\s+/);
            discoveredPorts.push({
              port: parseInt(m2[1]),
              protocol: "tcp",
              service: m2[2],
              product: pts.length > 0 ? pts.slice(0, -1).join(" ") || pts[0] : undefined,
              version: pts.length > 1 ? pts[pts.length - 1] : undefined,
            });
          }
        }
        durationMs += Date.now() - retryStart;
        helpers.addLog({
          phase: "enumeration",
          type: "scan_result",
          title: `scanforge Retry Complete: ${helpers.fmtTarget(asset, target)}`,
          detail: `Retry found ${discoveredPorts.length} services (simple flags worked)`,
        });
      } catch (retryErr: any) {
        helpers.addLog({
          phase: "enumeration",
          type: "error",
          title: `scanforge Retry Failed: ${helpers.fmtTarget(asset, target)}`,
          detail: retryErr.message,
        });
      }
    }

    // Merge discovery ports into asset
    asset.ports = discoveredPorts.map((p) => ({
      port: p.port,
      service: p.service || "unknown",
      version: p.product ? `${p.product}${p.version ? " " + p.version : ""}`.trim() : undefined,
    }));

    // Service resolution
    helpers.enrichPortServices(asset.ports, (asset.passiveRecon as any)?.services || []);

    // ── PASSIVE RECON PORT SEEDING ──
    if (discoveredPorts.length === 0) {
      const isWebAsset =
        asset.type === "web_app" ||
        (asset.passiveRecon as any)?.technologies?.some((t: string) =>
          /nginx|apache|iis|http|web|php|node|express|flask|django/i.test(t)
        ) ||
        (asset.passiveRecon as any)?.services?.some((s: any) => /http/i.test(s.service || ""));

      const passivePorts =
        (asset.passiveRecon as any)?.services?.map((s: any) => s.port).filter(Boolean) || [];

      if (isWebAsset || passivePorts.length > 0) {
        const seedPorts = passivePorts.length > 0 ? passivePorts : [80, 443];
        for (const port of seedPorts) {
          if (!asset.ports.some((p: any) => p.port === port)) {
            asset.ports.push({
              port,
              service: port === 443 ? "https" : "http",
              version: undefined,
            });
          }
        }
        helpers.addLog({
          phase: "enumeration",
          type: "info",
          title: `🌐 Port Seeding: ${helpers.fmtTarget(asset, target)}`,
          detail: `ScanForge found 0 open ports but passive recon indicates web services. Seeded ports: ${asset.ports.map((p: any) => `${p.port}/${p.service}`).join(", ")}. Pipeline will continue to credential testing and ZAP.`,
        });
        state.stats.portsFound += asset.ports.length;
      }
    }

    // Store tool result
    asset.toolResults.push({
      tool: sfTool || "naabu",
      command: `${sfTool} ${sfArgs}`,
      exitCode: discoveryResult.exitCode ?? 0,
      durationMs,
      timedOut: discoveryResult.timedOut || false,
      findingCount: discoveredPorts.length,
      findings: discoveredPorts.map((p) => ({
        severity: "info",
        title: `${p.port}/${p.protocol} ${p.service}${p.product ? ` (${p.product})` : ""}`,
      })),
      outputPreview: (discoveryResult.stdout || "").slice(0, 512),
      executedAt: Date.now(),
      phase: "discovery",
    });

    state.stats.portsFound += discoveredPorts.length;
    state.stats.hostsScanned++;
    asset.status = "enumerated";

    helpers.broadcastOpsUpdate({ type: "stats_update", stats: { ...state.stats } });
    helpers.addLog({
      phase: "enumeration",
      type: "scan_result",
      title: `scanforge Complete: ${helpers.fmtTarget(asset, target)}`,
      detail: `${discoveredPorts.length} services fingerprinted in ${Math.round(durationMs / 1000)}s\nPorts: ${discoveredPorts.map((p) => `${p.port}/${p.service}${p.product ? ` (${p.product})` : ""}`).join(", ")}`,
      data: { ports: asset.ports, discoveryFlags, evasion: assetPlan?.evasionTechniques },
    });
  } catch (e: any) {
    helpers.addLog({
      phase: "enumeration",
      type: "error",
      title: `scanforge Failed: ${helpers.fmtTarget(asset, target)}`,
      detail: e.message,
    });
    asset.status = "enumerated"; // Continue pipeline
  }

  // ═══ AUTO-CAPTURE: Stop tcpdump ═══
  if (autoCaptureSessionId) {
    try {
      const { afterDiscoveryScan } = await import("../pcap-auto-capture");
      const captureResult = await afterDiscoveryScan(autoCaptureSessionId);
      if (captureResult && captureResult.packetsCaptured) {
        helpers.addLog({
          phase: "enumeration",
          type: "info",
          title: `📡 Auto-Capture Complete: ${helpers.fmtTarget(asset, target)}`,
          detail: `Captured ${captureResult.packetsCaptured} packets during discovery scan (${Math.round((captureResult.stoppedAt! - captureResult.startedAt) / 1000)}s)${captureResult.analysisSummary ? `\nFindings: ${captureResult.analysisSummary.findings} security findings detected, ${captureResult.analysisSummary.conversations} conversations, protocols: ${captureResult.analysisSummary.protocols.join(", ")}` : ""}`,
          data: {
            pcapPath: captureResult.pcapPath,
            packetsCaptured: captureResult.packetsCaptured,
            analysisSummary: captureResult.analysisSummary,
          },
        });
        if (!(asset as any).pcapCaptures) (asset as any).pcapCaptures = [];
        (asset as any).pcapCaptures.push({
          sessionId: captureResult.sessionId,
          pcapPath: captureResult.pcapPath,
          packetsCaptured: captureResult.packetsCaptured,
          analysisSummary: captureResult.analysisSummary,
        });
      }
    } catch (capErr: any) {
      console.warn(`[AutoCapture] Stop hook failed: ${capErr.message}`);
    }
  }
}
