import {
  fmtTarget,
  init_orchestrator_types,
  isInRoeScope
} from "./chunk-M7Y3UOC3.js";
import {
  KNOWN_INFRA_IPS,
  addLog,
  broadcastOpsUpdate,
  broadcastReconFinding,
  enrichPortServices,
  getEffectiveTarget,
  getEngagementAbortSignal,
  init_engagement_orchestrator,
  init_service_resolver,
  init_tool_output_parsers,
  parseToolOutput,
  persistOpsStateDebounced,
  persistScanResult,
  pushVulnDeduped
} from "./chunk-7IV734JN.js";
import "./chunk-DACF3QRL.js";
import "./chunk-HPRQMQNG.js";
import "./chunk-2FSGQWVF.js";
import "./chunk-W537OLJR.js";
import {
  executeRawCommandViaQueue,
  executeToolViaQueue,
  init_job_queue_bridge
} from "./chunk-HRKZIZJ3.js";
import "./chunk-BCMKMV2T.js";
import "./chunk-LI545HOX.js";
import "./chunk-5DEWV7VV.js";
import "./chunk-TJBFPX34.js";
import "./chunk-MJGBFYEG.js";
import {
  buildGobusterCommand,
  getScanProfile,
  init_scan_profiles
} from "./chunk-IL4FZKPB.js";
import "./chunk-ROZQMJZL.js";
import "./chunk-R4LF5PWF.js";
import "./chunk-4SXJ2GAM.js";
import "./chunk-5BWO4Y3K.js";
import "./chunk-7DIV2VRB.js";
import "./chunk-PEKR4DSS.js";
import "./chunk-GCQGYOUO.js";
import "./chunk-QSC5SQUD.js";
import "./chunk-PUZE3GU2.js";
import "./chunk-DQAUMKMW.js";
import "./chunk-UOREPKTR.js";
import "./chunk-C4KWO5EH.js";
import "./chunk-SSYKZXNO.js";
import "./chunk-WP62CKNZ.js";
import "./chunk-G45ZFGC3.js";
import "./chunk-LPSC3SDV.js";
import "./chunk-J6EMIQSU.js";
import "./chunk-Q72HEY35.js";
import "./chunk-5TJ6FS74.js";
import "./chunk-UYX5D64U.js";
import "./chunk-YW5WVS53.js";
import "./chunk-PFTNS476.js";
import "./chunk-7ZNGVPYR.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-KUPDIQVG.js";
import "./chunk-CEPCIPS7.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-TAIMCRAB.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/active-enumeration/dns-resolver.ts
async function resolveAssetDns(state, scopedAssets, helpers) {
  const dns = await import("dns");
  const { promisify } = await import("util");
  const dnsResolve4 = promisify(dns.resolve4);
  const scanServerHost = process.env.SCAN_SERVER_HOST || "";
  helpers.addLog({
    phase: "enumeration",
    type: "info",
    title: `DNS Pre-Resolution: checking ${scopedAssets.length} assets`,
    detail: `Resolving hostnames to IPs before ScanForge scan`
  });
  for (const asset of scopedAssets) {
    if (asset.ip) continue;
    const hostname = asset.hostname;
    try {
      const ips = await dnsResolve4(hostname);
      if (ips.length > 0) {
        asset.ip = ips[0];
        helpers.addLog({
          phase: "enumeration",
          type: "info",
          title: `DNS Resolved: ${hostname}`,
          detail: `${hostname} \u2192 ${ips[0]}`
        });
      }
    } catch (_dnsErr) {
      const knownLabSubdomains = [
        "dvwa",
        "juice-shop",
        "juiceshop",
        "webgoat",
        "bwapp",
        "mutillidae",
        "vampi",
        "crapi",
        "hackazon"
      ];
      const hostnameBase = hostname.split(".")[0]?.toLowerCase() || "";
      const isLabOnScanServer = state.engagementType === "training_lab" || asset.passiveRecon?.liveInstanceUrl?.includes(SCAN_SERVER_DOMAIN) || asset.passiveRecon?.liveInstanceUrl?.includes(scanServerHost) || hostname.endsWith(".aceofcloud.io") && knownLabSubdomains.includes(hostnameBase) || hostname.includes(SCAN_SERVER_DOMAIN);
      if (isLabOnScanServer) {
        try {
          const scanIps = await dnsResolve4(SCAN_SERVER_DOMAIN);
          if (scanIps.length > 0) {
            asset.ip = scanIps[0];
            helpers.addLog({
              phase: "enumeration",
              type: "info",
              title: `DNS Fallback: ${hostname} \u2192 scan server IP`,
              detail: `${hostname} failed DNS resolution. Training lab detected \u2014 using scan server IP ${scanIps[0]} (${SCAN_SERVER_DOMAIN})`
            });
          }
        } catch {
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(scanServerHost)) {
            asset.ip = scanServerHost;
            helpers.addLog({
              phase: "enumeration",
              type: "info",
              title: `DNS Fallback: ${hostname} \u2192 scan server IP (env)`,
              detail: `Using SCAN_SERVER_HOST env IP: ${scanServerHost}`
            });
          }
        }
      }
      if (!asset.ip) {
        helpers.addLog({
          phase: "enumeration",
          type: "warning",
          title: `\u26A0\uFE0F DNS Resolution Failed: ${hostname}`,
          detail: `Could not resolve ${hostname} to an IP address. ScanForge discovery may fail for this target.`
        });
      }
    }
  }
}
var SCAN_SERVER_DOMAIN;
var init_dns_resolver = __esm({
  "server/lib/active-enumeration/dns-resolver.ts"() {
    "use strict";
    SCAN_SERVER_DOMAIN = "scan.aceofcloud.io";
  }
});

// server/lib/active-enumeration/port-discovery.ts
async function executePortDiscovery(state, targets, helpers) {
  if (targets.length === 0) return;
  const ep = state.scanPlan?.discoveryEvasionProfile;
  const evasionDesc = ep ? `Timing: ${ep.timing}, Fragmentation: ${ep.fragmentation}, Decoys: ${ep.decoys}, Host Randomization: ${ep.randomizeHosts}, Data Padding: ${ep.dataLengthPadding}, Source Port Spoofing: ${ep.sourcePortSpoofing}` : "Default evasion profile";
  const parallelMode = targets.length > 1;
  helpers.addLog({
    phase: "enumeration",
    type: "scan_start",
    title: "\u{1F50D} Phase A: Discovery Scan with Evasion",
    detail: `Scanning ${targets.length} targets with full port sweep + service fingerprinting` + (parallelMode ? ` (parallel batches of ${Math.min(MAX_CONCURRENT_TARGETS, targets.length)})` : "") + `
Evasion: ${evasionDesc}
${state.scanPlan?.discoveryStrategy || "Comprehensive port discovery to enrich passive recon data"}`
  });
  try {
    const { getScanServerConfigForScanForge } = await import("./scan-server-executor-EX3LSZL7.js");
    const { autoSelectTool } = await import("./scanforge-discovery-TRP7TB3H.js");
    const serverConfig = await getScanServerConfigForScanForge();
    for (let batchStart = 0; batchStart < targets.length; batchStart += MAX_CONCURRENT_TARGETS) {
      const batch = targets.slice(batchStart, batchStart + MAX_CONCURRENT_TARGETS);
      if (batch.length > 1) {
        helpers.addLog({
          phase: "enumeration",
          type: "info",
          title: `\u{1F680} Parallel Batch ${Math.floor(batchStart / MAX_CONCURRENT_TARGETS) + 1}/${Math.ceil(targets.length / MAX_CONCURRENT_TARGETS)}`,
          detail: `Scanning ${batch.length} targets concurrently: ${batch.map((t) => t.assetHostname).join(", ")}`
        });
      }
      await Promise.allSettled(
        batch.map(
          (targetEntry) => scanSingleTarget(state, targetEntry, helpers, autoSelectTool)
        )
      );
      const completedFraction = Math.min(batchStart + batch.length, targets.length) / targets.length;
      state.progress = Math.round(15 + completedFraction * 10);
      helpers.broadcastOpsUpdate({ type: "stats_update", stats: { ...state.stats } });
    }
  } catch (e) {
    helpers.addLog({
      phase: "enumeration",
      type: "error",
      title: "Discovery Scan Error",
      detail: e.message
    });
  }
}
async function scanSingleTarget(state, targetEntry, helpers, autoSelectTool) {
  const target = targetEntry.scanTarget;
  const asset = state.assets.find((a) => a.hostname === targetEntry.assetHostname);
  if (!asset) return;
  asset.status = "scanning";
  const assetPlan = state.scanPlan?.assetPlans.find(
    (ap) => ap.hostname === asset.hostname || ap.ip === target
  );
  const discoveryFlags = assetPlan?.discoveryFlags || "-Pn -sV -sC -O -f -T2 -D RND:5 --data-length 64";
  const discoveredPorts = [];
  const sfTool = autoSelectTool({
    targets: [target],
    stealthLevel: assetPlan?.evasionTechniques?.length ? "medium" : "minimal"
  });
  const discoveryRationale = `ScanForge ${sfTool} \u2014 top ports discovery with service fingerprinting`;
  helpers.addLog({
    phase: "enumeration",
    type: "scan_start",
    title: `\u{1F512} scanforge: ${helpers.fmtTarget(asset, target)}`,
    detail: `Phase A Step 1 \u2014 ${discoveryRationale}
Evasion: ${assetPlan?.evasionTechniques?.join(", ") || "fragmentation, decoys, normal timing"}`
  });
  const startTime = Date.now();
  let autoCaptureSessionId = null;
  try {
    const { beforeDiscoveryScan } = await import("./pcap-auto-capture-LXUVA2SW.js");
    autoCaptureSessionId = await beforeDiscoveryScan(
      state.engagementId,
      target,
      asset.hostname,
      { enabled: !!state.autoCaptureEnabled }
    );
    if (autoCaptureSessionId) {
      helpers.addLog({
        phase: "enumeration",
        type: "info",
        title: `\u{1F4E1} Auto-Capture: ${helpers.fmtTarget(asset, target)}`,
        detail: `Background tcpdump started for forensic analysis during discovery scan`
      });
    }
  } catch (capErr) {
    console.warn(`[AutoCapture] Hook failed: ${capErr.message}`);
  }
  try {
    const sfArgs = sfTool === "naabu" ? `-host ${target} -top-ports 1000 -s s -no-stdin -rate 1000 -retries 1 -json` : sfTool === "masscan" ? `${target} -p1-1024,1720,2000,2427,3306,3389,5060,5061,5080,5432,5900,6379,8080,8443,9090,27017,41795 --rate 1000 -oJ -` : sfTool === "rustscan" ? `-a ${target} --range 1-65535 -b 4500 -g` : `-host ${target} -top-ports 1000 -s s -no-stdin -json`;
    helpers.addLog({
      phase: "enumeration",
      type: "tool_exec",
      title: `${sfTool} ${helpers.fmtTarget(asset, target)}`,
      detail: `${sfTool} ${sfArgs}`
    });
    const discoveryResult = await helpers.executeTool({
      tool: sfTool,
      args: sfArgs,
      timeoutSeconds: 600,
      sudo: sfTool === "masscan" || sfTool === "zmap" || sfTool === "naabu"
    });
    if (discoveryResult.stdout) {
      try {
        const discovery = await import("./scanforge-discovery-TRP7TB3H.js");
        const parser = sfTool === "masscan" ? discovery.parseMasscanOutput : sfTool === "naabu" ? discovery.parseNaabuOutput : sfTool === "rustscan" ? discovery.parseRustScanOutput : discovery.parseNaabuOutput;
        const hosts = parser(discoveryResult.stdout);
        for (const host of hosts) {
          for (const p of host.ports) {
            discoveredPorts.push({
              port: p.port,
              protocol: p.protocol,
              service: p.service || "unknown",
              product: p.product,
              version: p.version
            });
          }
        }
      } catch (parseErr) {
        const portRegex = /(\d+)\/(tcp|udp)\s+open\s+(\S+)/g;
        let match;
        while ((match = portRegex.exec(discoveryResult.stdout)) !== null) {
          discoveredPorts.push({
            port: parseInt(match[1]),
            protocol: match[2],
            service: match[3] || "unknown"
          });
        }
      }
    }
    let durationMs = Date.now() - startTime;
    const allFiltered = discoveredPorts.length === 0 && discoveryResult.stdout && /All \d+ scanned ports.*filtered|\d+\/tcp\s+filtered/.test(discoveryResult.stdout);
    const hasEvasionFlags = /\-f\b|\-D\s|--data-length|--source-port|--mtu/.test(discoveryFlags);
    if (allFiltered && hasEvasionFlags) {
      helpers.addLog({
        phase: "enumeration",
        type: "info",
        title: `\u26A0\uFE0F scanforge Retry: ${helpers.fmtTarget(asset, target)} (removing evasion flags)`,
        detail: `First scan returned all-filtered (likely cloud WAF blocking evasion techniques). Retrying with naabu (most reliable fallback)`
      });
      const retryArgs = `-host ${target} -top-ports 1000 -s s -no-stdin -rate 1000 -retries 1 -json`;
      const retryStart = Date.now();
      try {
        const retryResult = await helpers.executeTool({
          tool: sfTool || "naabu",
          args: retryArgs,
          timeoutSeconds: 600,
          sudo: true
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
              product: pts.length > 0 ? pts.slice(0, -1).join(" ") || pts[0] : void 0,
              version: pts.length > 1 ? pts[pts.length - 1] : void 0
            });
          }
        }
        durationMs += Date.now() - retryStart;
        helpers.addLog({
          phase: "enumeration",
          type: "scan_result",
          title: `scanforge Retry Complete: ${helpers.fmtTarget(asset, target)}`,
          detail: `Retry found ${discoveredPorts.length} services (simple flags worked)`
        });
      } catch (retryErr) {
        helpers.addLog({
          phase: "enumeration",
          type: "error",
          title: `scanforge Retry Failed: ${helpers.fmtTarget(asset, target)}`,
          detail: retryErr.message
        });
      }
    }
    asset.ports = discoveredPorts.map((p) => ({
      port: p.port,
      service: p.service || "unknown",
      version: p.product ? `${p.product}${p.version ? " " + p.version : ""}`.trim() : void 0
    }));
    helpers.enrichPortServices(asset.ports, asset.passiveRecon?.services || []);
    if (discoveredPorts.length === 0) {
      const isWebAsset = asset.type === "web_app" || asset.passiveRecon?.technologies?.some(
        (t) => /nginx|apache|iis|http|web|php|node|express|flask|django/i.test(t)
      ) || asset.passiveRecon?.services?.some((s) => /http/i.test(s.service || ""));
      const passivePorts = asset.passiveRecon?.services?.map((s) => s.port).filter(Boolean) || [];
      if (isWebAsset || passivePorts.length > 0) {
        const seedPorts = passivePorts.length > 0 ? passivePorts : [80, 443];
        for (const port of seedPorts) {
          if (!asset.ports.some((p) => p.port === port)) {
            asset.ports.push({
              port,
              service: port === 443 ? "https" : "http",
              version: void 0
            });
          }
        }
        helpers.addLog({
          phase: "enumeration",
          type: "info",
          title: `\u{1F310} Port Seeding: ${helpers.fmtTarget(asset, target)}`,
          detail: `ScanForge found 0 open ports but passive recon indicates web services. Seeded ports: ${asset.ports.map((p) => `${p.port}/${p.service}`).join(", ")}. Pipeline will continue to credential testing and ZAP.`
        });
        state.stats.portsFound += asset.ports.length;
      }
    }
    asset.toolResults.push({
      tool: sfTool || "naabu",
      command: `${sfTool} ${sfArgs}`,
      exitCode: discoveryResult.exitCode ?? 0,
      durationMs,
      timedOut: discoveryResult.timedOut || false,
      findingCount: discoveredPorts.length,
      findings: discoveredPorts.map((p) => ({
        severity: "info",
        title: `${p.port}/${p.protocol} ${p.service}${p.product ? ` (${p.product})` : ""}`
      })),
      outputPreview: (discoveryResult.stdout || "").slice(0, 512),
      executedAt: Date.now(),
      phase: "discovery"
    });
    state.stats.portsFound += discoveredPorts.length;
    state.stats.hostsScanned++;
    asset.status = "enumerated";
    helpers.broadcastOpsUpdate({ type: "stats_update", stats: { ...state.stats } });
    helpers.addLog({
      phase: "enumeration",
      type: "scan_result",
      title: `scanforge Complete: ${helpers.fmtTarget(asset, target)}`,
      detail: `${discoveredPorts.length} services fingerprinted in ${Math.round(durationMs / 1e3)}s
Ports: ${discoveredPorts.map((p) => `${p.port}/${p.service}${p.product ? ` (${p.product})` : ""}`).join(", ")}`,
      data: { ports: asset.ports, discoveryFlags, evasion: assetPlan?.evasionTechniques }
    });
  } catch (e) {
    helpers.addLog({
      phase: "enumeration",
      type: "error",
      title: `scanforge Failed: ${helpers.fmtTarget(asset, target)}`,
      detail: e.message
    });
    asset.status = "enumerated";
  }
  if (autoCaptureSessionId) {
    try {
      const { afterDiscoveryScan } = await import("./pcap-auto-capture-LXUVA2SW.js");
      const captureResult = await afterDiscoveryScan(autoCaptureSessionId);
      if (captureResult && captureResult.packetsCaptured) {
        helpers.addLog({
          phase: "enumeration",
          type: "info",
          title: `\u{1F4E1} Auto-Capture Complete: ${helpers.fmtTarget(asset, target)}`,
          detail: `Captured ${captureResult.packetsCaptured} packets during discovery scan (${Math.round((captureResult.stoppedAt - captureResult.startedAt) / 1e3)}s)${captureResult.analysisSummary ? `
Findings: ${captureResult.analysisSummary.findings} security findings detected, ${captureResult.analysisSummary.conversations} conversations, protocols: ${captureResult.analysisSummary.protocols.join(", ")}` : ""}`,
          data: {
            pcapPath: captureResult.pcapPath,
            packetsCaptured: captureResult.packetsCaptured,
            analysisSummary: captureResult.analysisSummary
          }
        });
        if (!asset.pcapCaptures) asset.pcapCaptures = [];
        asset.pcapCaptures.push({
          sessionId: captureResult.sessionId,
          pcapPath: captureResult.pcapPath,
          packetsCaptured: captureResult.packetsCaptured,
          analysisSummary: captureResult.analysisSummary
        });
      }
    } catch (capErr) {
      console.warn(`[AutoCapture] Stop hook failed: ${capErr.message}`);
    }
  }
}
var MAX_CONCURRENT_TARGETS;
var init_port_discovery = __esm({
  "server/lib/active-enumeration/port-discovery.ts"() {
    "use strict";
    MAX_CONCURRENT_TARGETS = 3;
  }
});

// server/lib/active-enumeration/service-fingerprinter-runner.ts
var init_service_fingerprinter_runner = __esm({
  "server/lib/active-enumeration/service-fingerprinter-runner.ts"() {
    "use strict";
  }
});

// server/lib/active-enumeration/httpx-prober.ts
var init_httpx_prober = __esm({
  "server/lib/active-enumeration/httpx-prober.ts"() {
    "use strict";
  }
});

// server/lib/active-enumeration/enumeration-context.ts
function buildEnumerationHelpers(state) {
  const roeScope = [
    ...state.roeScopeGuard?.authorizedDomains || [],
    ...state.roeScopeGuard?.authorizedIps || []
  ];
  const engagementAbortSignal = getEngagementAbortSignal(state.engagementId);
  const executeTool = (config) => executeToolViaQueue(config, {
    engagementId: state.engagementId,
    roeScope,
    engagementAbortSignal
  });
  const executeRawCommand = (cmd, timeout, opts) => executeRawCommandViaQueue(cmd, timeout, {
    engagementId: state.engagementId,
    engagementAbortSignal,
    ...opts
  });
  return {
    addLog: (entry) => addLog(state, entry),
    broadcastOpsUpdate: (data) => broadcastOpsUpdate(state.engagementId, data),
    broadcastReconFinding: (finding) => broadcastReconFinding(state.engagementId, finding),
    getEffectiveTarget,
    isInRoeScope: (hostname, ip) => isInRoeScope(state, hostname, ip),
    fmtTarget,
    parseToolOutput,
    pushVulnDeduped,
    enrichPortServices,
    getScanProfile,
    buildGobusterCommand,
    executeTool,
    executeRawCommand,
    persistScanResult: (opts) => persistScanResult(opts),
    persistOpsStateDebounced: (delayMs) => persistOpsStateDebounced(state.engagementId, delayMs),
    KNOWN_INFRA_IPS,
    engagementAbortSignal,
    genId: () => Math.random().toString(36).substring(2, 10)
  };
}
var init_enumeration_context = __esm({
  "server/lib/active-enumeration/enumeration-context.ts"() {
    "use strict";
    init_orchestrator_types();
    init_engagement_orchestrator();
    init_tool_output_parsers();
    init_job_queue_bridge();
    init_service_resolver();
    init_scan_profiles();
  }
});

// server/lib/active-enumeration/cloud-scanner-runner.ts
async function runCloudAssetDetection(state, helpers) {
  try {
    const { detectCloudAsset, executeCloudStorageScan, getCloudDetectionPromptContext } = await import("./cloud-storage-scanner-IUT3SX4U.js");
    helpers.addLog({
      phase: "enumeration",
      type: "info",
      title: "\u2601\uFE0F Cloud Asset Detection",
      detail: "Analyzing discovery results for cloud-hosted infrastructure, storage endpoints, and misconfigured services"
    });
    let cloudAssetsFound = 0;
    let cloudStorageEndpoints = 0;
    let cloudFindings = [];
    for (const asset of state.assets) {
      const detection = detectCloudAsset({
        hostname: asset.hostname,
        ip: asset.ip,
        dnsRecords: asset.dnsRecords,
        headers: asset.headers,
        technologies: asset.technologies,
        cnames: asset.cnames,
        toolResults: asset.toolResults
      });
      if (detection.isCloudHosted) {
        cloudAssetsFound++;
        const providers = Array.from(new Set(detection.signatures.map((s) => s.provider)));
        asset.cloudProviders = providers;
        asset.cloudServices = detection.signatures.map(
          (s) => `${s.provider}:${s.service}`
        );
        helpers.addLog({
          phase: "enumeration",
          type: "finding",
          title: `\u2601\uFE0F Cloud Asset: ${asset.hostname}`,
          detail: `Providers: ${providers.join(", ")}
Services: ${detection.signatures.map((s) => `${s.provider} ${s.service} (${s.confidence})`).join(", ")}
Storage endpoints: ${detection.storageEndpoints.length}`,
          data: { cloudDetection: detection }
        });
        if (detection.storageEndpoints.length > 0 || detection.suggestedScans.length > 0) {
          cloudStorageEndpoints += detection.storageEndpoints.length;
          helpers.addLog({
            phase: "enumeration",
            type: "scan_start",
            title: `\u2601\uFE0F Cloud Storage Scan: ${asset.hostname}`,
            detail: `Running ${detection.suggestedScans.length} cloud-specific scans (${detection.storageEndpoints.join(", ")})`
          });
          try {
            const scanResult = await executeCloudStorageScan(
              asset.hostname,
              detection.suggestedScans,
              { maxScans: 5, timeoutSeconds: 120, engagementId: state.engagementId }
            );
            for (const finding of scanResult.findings) {
              cloudFindings.push({
                asset: asset.hostname,
                provider: finding.provider,
                service: finding.service || "storage",
                severity: finding.severity,
                title: finding.title
              });
              if (pushVulnDeduped(asset, {
                id: `cloud-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                severity: finding.severity,
                title: `[Cloud] ${finding.title}`,
                cve: finding.cve,
                description: finding.description,
                corroborationTier: "confirmed",
                evidenceDetail: `Confirmed by cloud security scan`
              })) {
                state.stats.vulnsFound++;
              }
            }
            for (const raw of scanResult.rawResults) {
              helpers.addLog({
                phase: "enumeration",
                type: "scan_result",
                title: `Cloud Scan Result: ${raw.tool}`,
                detail: `Exit: ${raw.exitCode} | Duration: ${Math.round(raw.durationMs / 1e3)}s
${raw.stdout.slice(0, 500)}`,
                data: raw
              });
            }
          } catch (cloudScanErr) {
            helpers.addLog({
              phase: "enumeration",
              type: "error",
              title: `Cloud Scan Error: ${asset.hostname}`,
              detail: cloudScanErr.message
            });
          }
        }
      }
    }
    state.cloudDetection = {
      assetsFound: cloudAssetsFound,
      storageEndpoints: cloudStorageEndpoints,
      findings: cloudFindings,
      promptContext: cloudAssetsFound > 0 ? getCloudDetectionPromptContext() : void 0
    };
    const severity_counts = cloudFindings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {});
    helpers.addLog({
      phase: "enumeration",
      type: cloudAssetsFound > 0 ? "phase_complete" : "info",
      title: cloudAssetsFound > 0 ? `\u2601\uFE0F Cloud Detection Complete \u2014 ${cloudAssetsFound} cloud assets, ${cloudFindings.length} findings` : "\u2601\uFE0F Cloud Detection \u2014 No cloud assets detected",
      detail: cloudAssetsFound > 0 ? `Providers: ${Array.from(new Set(cloudFindings.map((f) => f.provider))).join(", ")}
Findings: ${JSON.stringify(severity_counts)}
Storage endpoints scanned: ${cloudStorageEndpoints}` : "No cloud-hosted infrastructure identified in discovery results. Proceeding to Phase B."
    });
  } catch (cloudDetectErr) {
    console.error("[CloudDetection] Error:", cloudDetectErr.message);
    helpers.addLog({
      phase: "enumeration",
      type: "warning",
      title: "\u26A0\uFE0F Cloud Detection Skipped",
      detail: `Cloud asset detection encountered an error: ${cloudDetectErr.message}. Proceeding to Phase B.`
    });
  }
}
var init_cloud_scanner_runner = __esm({
  "server/lib/active-enumeration/cloud-scanner-runner.ts"() {
    "use strict";
    init_enumeration_context();
  }
});

// server/lib/active-enumeration/target-profiler.ts
async function runTargetProfiling(state, scopedAssets, helpers) {
  try {
    const {
      detectWAF,
      detectCDN,
      classifyAssetRole,
      selectEvasionProfile,
      generateScanStrategy,
      getDefaultScopeConstraints,
      buildTargetProfileContext
    } = await import("./context-aware-scanner-5TXY5Z56.js");
    helpers.addLog({
      phase: "enumeration",
      type: "info",
      title: "\u{1F50D} Phase A.6: Context-Aware Target Profiling",
      detail: "Building target profiles from discovery data \u2014 detecting WAF, CDN, firewall, topology, and generating adaptive scan strategies"
    });
    if (!state.targetProfiles) state.targetProfiles = {};
    const scopeTypeMap = {
      pentest: "pentest",
      red_team: "red_team",
      purple_team: "red_team",
      phishing: "vuln_assessment",
      tabletop: "vuln_assessment"
    };
    const scopeEngType = scopeTypeMap[state.engagementType] || "pentest";
    const baseScopeConstraints = getDefaultScopeConstraints(scopeEngType);
    for (const asset of scopedAssets) {
      try {
        const httpxResult = asset.toolResults.find((tr) => tr.tool === "httpx");
        const responseHeaders = {
          ...asset.httpxResponseHeaders || {},
          ...httpxResult?.fingerprints?.httpHeaders || {}
        };
        if (httpxResult?.fingerprints?.webServer && !responseHeaders["server"]) {
          responseHeaders["server"] = httpxResult.fingerprints.webServer;
        }
        const cookies = httpxResult?.fingerprints?.cookies || [];
        if (responseHeaders["set-cookie"]) {
          cookies.push(...responseHeaders["set-cookie"].split(/,\s*(?=[^;]*=)/));
        }
        let statusCode = 200;
        if (httpxResult?.rawOutput) {
          const scMatch = httpxResult.rawOutput.match(/"status.code":(\d+)|"status_code":(\d+)/);
          if (scMatch) statusCode = parseInt(scMatch[1] || scMatch[2]);
        }
        const technologies = asset.passiveRecon?.technologies || [];
        const webServerStr = httpxResult?.fingerprints?.webServer || responseHeaders["server"] || null;
        const poweredBy = httpxResult?.fingerprints?.poweredBy || responseHeaders["x-powered-by"] || null;
        let webServerParsed = null;
        if (webServerStr) {
          const wsMatch = webServerStr.match(/^([\w.-]+)\/?([\d.]+)?/);
          webServerParsed = { name: wsMatch?.[1] || webServerStr, version: wsMatch?.[2] || null, role: "unknown" };
        }
        let appFramework = null;
        if (poweredBy) {
          const fwMatch = poweredBy.match(/^([\w.-]+)\/?([\d.]+)?/);
          const lang = /PHP/i.test(poweredBy) ? "PHP" : /ASP/i.test(poweredBy) ? "C#" : /Express|Node/i.test(poweredBy) ? "JavaScript" : /JSF|Servlet/i.test(poweredBy) ? "Java" : "unknown";
          appFramework = { name: fwMatch?.[1] || poweredBy, version: fwMatch?.[2] || null, language: lang };
        }
        let cms = null;
        const cmsNames = ["WordPress", "Drupal", "Joomla", "Magento", "Shopify", "Wix", "Squarespace", "Ghost", "Typo3", "PrestaShop"];
        for (const cmsName of cmsNames) {
          const found = technologies.find((t) => t.toLowerCase().includes(cmsName.toLowerCase()));
          if (found) {
            const vMatch = found.match(/([\d.]+)/);
            cms = { name: cmsName, version: vMatch?.[1] || null };
            break;
          }
        }
        const langPatterns = {
          PHP: /php/i,
          Java: /java|jsp|servlet/i,
          Python: /python|django|flask/i,
          "C#": /asp\.net|c#/i,
          Ruby: /ruby|rails/i,
          JavaScript: /node|express|next|react|angular|vue/i,
          Go: /\bgo\b|golang/i,
          Rust: /\brust\b/i
        };
        const detectedLangs = [];
        for (const [lang, pat] of Object.entries(langPatterns)) {
          if (technologies.some((t) => pat.test(t)) || poweredBy && pat.test(poweredBy)) {
            detectedLangs.push(lang);
          }
        }
        let tlsData = null;
        if (httpxResult?.fingerprints?.tlsInfo) {
          const ti = httpxResult.fingerprints.tlsInfo;
          tlsData = {
            version: ti.protocol || "unknown",
            cipher: ti.cipherSuite || null,
            certIssuer: ti.issuerOrg || null,
            certExpiry: ti.notAfter || null,
            hsts: !!responseHeaders["strict-transport-security"],
            protocols: ti.protocol ? [ti.protocol] : []
          };
        }
        const serviceBanners = {};
        for (const p of asset.ports || []) {
          serviceBanners[p.port] = {
            service: p.service || "unknown",
            version: p.version || null,
            banner: null,
            protocol: "tcp"
          };
        }
        const fingerprint = {
          serverHeader: webServerStr,
          webServer: webServerParsed,
          appFramework,
          cms,
          os: null,
          tls: tlsData,
          languages: detectedLangs,
          jsFrameworks: technologies.filter((t) => /react|angular|vue|svelte|next|nuxt|gatsby/i.test(t)),
          databases: technologies.filter((t) => /mysql|postgres|mongo|redis|elastic|sqlite|mariadb|oracle|mssql/i.test(t)),
          techTags: technologies,
          serviceBanners
        };
        const wafProfile = detectWAF(responseHeaders, cookies, "", statusCode);
        if (wafProfile.detected) {
          asset.wafDetected = wafProfile.vendor || "unknown";
          addLog(state, {
            phase: "enumeration",
            type: "waf_detected",
            title: `\u{1F6E1}\uFE0F WAF Detected: ${fmtTarget(asset)} \u2192 ${wafProfile.vendor} (${wafProfile.type})`,
            detail: `Confidence: ${wafProfile.confidence}% | Detection: ${wafProfile.detectionMethod}
Bypass techniques: ${wafProfile.bypassTechniques.slice(0, 3).join(", ")}`
          });
        }
        const cnames = asset.cnames || (asset.passiveRecon?.dnsRecords?.["CNAME"] || []);
        const cdnProfile = detectCDN(responseHeaders, cnames);
        if (cdnProfile.detected) {
          addLog(state, {
            phase: "enumeration",
            type: "info",
            title: `\u{1F310} CDN Detected: ${fmtTarget(asset)} \u2192 ${cdnProfile.provider}`,
            detail: `Evidence: ${cdnProfile.evidence.join(", ")}${cdnProfile.originIp ? ` | Origin IP: ${cdnProfile.originIp}` : ""}${cdnProfile.hasBuiltInWAF ? " | Has built-in WAF" : ""}`
          });
        }
        const openPorts = (asset.ports || []).map((p) => p.port);
        const roleResult = classifyAssetRole(fingerprint, openPorts, responseHeaders);
        const topologyNode = {
          host: asset.hostname,
          role: roleResult.role,
          confidence: roleResult.confidence,
          backend: null,
          services: (asset.ports || []).map((p) => ({ port: p.port, service: p.service, version: p.version || null })),
          directlyReachable: true
        };
        const cloudProviders = asset.cloudProviders || [];
        const environment = cloudProviders.length > 0 ? "cloud" : technologies.some((t) => /docker|kubernetes|k8s|container/i.test(t)) ? "containerized" : technologies.some((t) => /lambda|serverless|cloud.function/i.test(t)) ? "serverless" : "traditional";
        const riskProfile = wafProfile.detected && cdnProfile.detected ? "high_security" : wafProfile.detected || cdnProfile.detected ? "standard" : (asset.ports || []).length > 20 ? "legacy" : "standard";
        const scopeConstraints = { ...baseScopeConstraints };
        if (cdnProfile.detected) scopeConstraints.sharedInfrastructure = true;
        if (wafProfile.detected)
          scopeConstraints.wafBypassAuthorized = scopeEngType === "pentest" || scopeEngType === "red_team";
        const partialProfile = {
          hostname: asset.hostname,
          ips: asset.ip ? [asset.ip] : [],
          fingerprint,
          waf: wafProfile,
          cdn: cdnProfile,
          firewall: {
            detected: false,
            type: "unknown",
            filteredPorts: [],
            rateLimiting: { detected: false, requestsPerSecond: null, burstLimit: null },
            geoBlocking: false,
            ipReputationBlocking: false
          },
          topology: topologyNode,
          environment,
          riskProfile,
          scopeConstraints,
          profiledAt: Date.now()
        };
        const strategy = generateScanStrategy(partialProfile);
        const fullProfile = { ...partialProfile, recommendedStrategy: strategy };
        state.targetProfiles[asset.hostname] = fullProfile;
        addLog(state, {
          phase: "enumeration",
          type: "info",
          title: `\u{1F4CB} Profile: ${fmtTarget(asset)} \u2192 ${roleResult.role} (${environment})`,
          detail: `Strategy: ${strategy.name} (${strategy.riskLevel} risk, ~${strategy.estimatedTimeMinutes}min)
Evasion: ${strategy.evasionProfile.name} (${strategy.evasionProfile.rateLimit} req/s)
Phases: ${strategy.phases.map((p) => p.name).join(" \u2192 ")}`
        });
      } catch (profileErr) {
        addLog(state, {
          phase: "enumeration",
          type: "warning",
          title: `\u26A0\uFE0F Profiling Failed: ${fmtTarget(asset)}`,
          detail: `Context-aware profiling error: ${profileErr.message}. Proceeding with default scan strategy.`
        });
      }
    }
    const profiledCount = Object.keys(state.targetProfiles).length;
    const wafCount = Object.values(state.targetProfiles).filter((p) => p.waf.detected).length;
    const cdnCount = Object.values(state.targetProfiles).filter((p) => p.cdn.detected).length;
    addLog(state, {
      phase: "enumeration",
      type: "phase_complete",
      title: `\u2705 Context-Aware Profiling Complete: ${profiledCount} targets profiled`,
      detail: `WAF detected: ${wafCount} | CDN detected: ${cdnCount}
Profiles stored for adaptive Phase B tool selection and downstream vuln scanning.`
    });
  } catch (profileEngineErr) {
    console.error("[ContextAwareScanner] Error:", profileEngineErr.message);
    addLog(state, {
      phase: "enumeration",
      type: "warning",
      title: "\u26A0\uFE0F Context-Aware Profiling Skipped",
      detail: `Profiling engine error: ${profileEngineErr.message}. Proceeding to Phase B with default strategies.`
    });
  }
}
var init_target_profiler = __esm({
  "server/lib/active-enumeration/target-profiler.ts"() {
    "use strict";
    init_enumeration_context();
  }
});

// server/lib/active-enumeration/targeted-tool-runner.ts
function genId() {
  return Math.random().toString(36).substring(2, 10);
}
async function executeTargetedToolDeployment(state, helpers) {
  addLog(state, {
    phase: "enumeration",
    type: "info",
    title: "\u{1F3AF} Phase B: Targeted Tool Deployment",
    detail: "Running targeted ScanForge discovery scripts and specialized tools per asset based on combined passive recon + discovery data"
  });
  const { suggestToolCommands } = await import("./scan-server-executor-EX3LSZL7.js");
  for (const asset of state.assets) {
    if ((asset.ports || []).length === 0) continue;
    if (!isInRoeScope(state, asset.hostname, asset.ip)) {
      addLog(state, {
        phase: "enumeration",
        type: "warning",
        title: `\u{1F6E1}\uFE0F Skipped: ${asset.hostname} (out of scope)`,
        detail: "Asset not in RoE authorized target list"
      });
      continue;
    }
    const webPorts = (asset.ports || []).filter(
      (p) => ["http", "https", "http-proxy", "http-alt"].includes(p.service) || [80, 443, 8080, 8443, 8e3, 3e3, 5e3].includes(p.port)
    );
    if (webPorts.length > 0) asset.type = "web_app";
    const target = getEffectiveTarget(asset, "discovery");
    const httpTarget = getEffectiveTarget(asset, "http");
    const assetPlan = state.scanPlan?.assetPlans.find(
      (ap) => ap.hostname === asset.hostname || ap.ip === target
    );
    const { autoSelectTool: autoSelectToolB } = await import("./scanforge-discovery-TRP7TB3H.js");
    const sfTool = autoSelectToolB({
      targets: [target],
      stealthLevel: assetPlan?.evasionTechniques?.length ? "medium" : "minimal"
    });
    await runTargetedDiscovery(state, asset, target, httpTarget, assetPlan, sfTool, helpers);
    let cmdsToRun = await buildToolCommandList(state, asset, target, httpTarget, assetPlan, helpers);
    cmdsToRun = mergeContextAwareTools(state, asset, httpTarget, cmdsToRun, helpers);
    const highPriorityCmds = filterAndSanitize(state, asset, target, httpTarget, cmdsToRun, helpers);
    await applyEvasionFlags(state, asset, highPriorityCmds);
    await executeToolsInParallel(state, asset, highPriorityCmds, helpers);
  }
  state.progress = 35;
  helpers.broadcastOpsUpdate({ type: "stats_update", stats: { ...state.stats } });
}
async function runTargetedDiscovery(state, asset, target, httpTarget, assetPlan, sfTool, helpers) {
  if (!assetPlan?.discoveryFlags) return;
  const discoveredPortList = (asset.ports || []).map((p) => p.port).join(",");
  let targetedFlags = assetPlan.discoveryFlags.replace(/(?:^|\s)-p\s*(?:\{[^}]+\}|[\d,\-]+)(?=\s|$)/g, "").replace(/\s*-p-/g, "").replace(/\{[^}]+\}/g, "").replace(/\s+/g, " ").trim();
  if (discoveredPortList) {
    targetedFlags = `${targetedFlags} -p ${discoveredPortList}`;
  } else {
    targetedFlags = `${targetedFlags} --top-ports 1000`;
  }
  addLog(state, {
    phase: "enumeration",
    type: "scan_start",
    title: `\u{1F3AF} Targeted ScanForge: ${fmtTarget(asset, target)}`,
    detail: `Phase B flags: ${targetedFlags}
Rationale: ${assetPlan.discoveryRationale}`
  });
  try {
    const startTime = Date.now();
    const discoveryArgs = `${targetedFlags} ${target}`;
    const discoveryResult = await helpers.executeTool({
      tool: sfTool || "naabu",
      args: discoveryArgs,
      timeoutSeconds: 300,
      sudo: true
    });
    const durationMs = Date.now() - startTime;
    const findings = parseToolOutput("scanforge-discovery", discoveryResult.stdout || "", asset);
    asset.toolResults.push({
      tool: sfTool || "naabu",
      command: `${sfTool} ${discoveryArgs}`,
      exitCode: discoveryResult.exitCode ?? 0,
      durationMs,
      timedOut: discoveryResult.timedOut || false,
      findingCount: findings.length,
      findings: findings.map((f) => ({
        severity: f.severity,
        title: f.title,
        cve: f.cve,
        evidence: f.evidence?.proofText || void 0
      })),
      outputPreview: (discoveryResult.stdout || "").slice(0, 1024),
      executedAt: Date.now(),
      phase: "targeted_enum"
    });
    addLog(state, {
      phase: "enumeration",
      type: "scan_result",
      title: `Targeted ScanForge Complete: ${fmtTarget(asset, target)}`,
      detail: `${findings.length} findings from targeted scripts in ${Math.round(durationMs / 1e3)}s`,
      data: { findings, outputPreview: (discoveryResult.stdout || "").slice(0, 500) }
    });
    for (const f of findings) {
      if (pushVulnDeduped(asset, {
        id: genId(),
        severity: f.severity,
        title: f.title,
        cve: f.cve,
        description: f.description,
        cvss: f.cvss,
        cwe: f.cwe,
        corroborationTier: "confirmed",
        evidenceDetail: "Confirmed by active scan tool output",
        rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4e3) : void 0,
        source: "active_scan"
      })) {
        state.stats.vulnsFound++;
      }
    }
  } catch (e) {
    addLog(state, {
      phase: "enumeration",
      type: "error",
      title: `Targeted ScanForge Failed: ${fmtTarget(asset, target)}`,
      detail: e.message
    });
  }
}
async function buildToolCommandList(state, asset, target, httpTarget, assetPlan, helpers) {
  const { suggestToolCommands } = await import("./scan-server-executor-EX3LSZL7.js");
  let cmdsToRun;
  if (assetPlan && assetPlan.activeTools.length > 0) {
    cmdsToRun = assetPlan.activeTools.map((t) => ({
      tool: t.tool,
      command: t.command.replace(/\{target\}/g, httpTarget).replace(/\{[^}]*host[^}]*\}/gi, httpTarget).replace(/\{[^}]*ip[^}]*\}/gi, httpTarget).replace(/\{[^}]*naabu[^}]*\}/gi, "").replace(/\s+/g, " ").trim(),
      purpose: t.rationale,
      priority: t.priority
    }));
    addLog(state, {
      phase: "enumeration",
      type: "tool_match",
      title: `Scan Plan Tools: ${fmtTarget(asset)}`,
      detail: `${cmdsToRun.length} tools from LLM scan plan: ${cmdsToRun.map((c) => c.tool).join(", ")}
Risk: ${assetPlan.riskNotes}`,
      data: {
        source: "scan_plan",
        tools: cmdsToRun.map((c) => c.tool),
        ports: (asset.ports || []).map((p) => `${p.port}/${p.service}`),
        assetType: asset.type,
        riskNotes: assetPlan.riskNotes
      }
    });
  } else {
    const suggestedCmds = await suggestToolCommands({
      hostname: asset.hostname,
      ip: asset.ip,
      type: asset.type,
      ports: asset.ports || []
    });
    cmdsToRun = suggestedCmds.map((c) => ({
      tool: c.tool,
      command: `${c.tool} ${c.args}`,
      purpose: c.purpose,
      priority: c.priority
    }));
    const toolNames = Array.from(new Set(cmdsToRun.map((c) => c.tool)));
    addLog(state, {
      phase: "enumeration",
      type: "tool_match",
      title: `Tool Match: ${fmtTarget(asset)}`,
      detail: `${cmdsToRun.length} commands queued using ${toolNames.length} tools: ${toolNames.join(", ")}`,
      data: {
        source: "auto_suggest",
        tools: toolNames,
        ports: (asset.ports || []).map((p) => `${p.port}/${p.service}`),
        assetType: asset.type
      }
    });
  }
  return cmdsToRun;
}
function mergeContextAwareTools(state, asset, httpTarget, cmdsToRun, helpers) {
  const targetProfile = state.targetProfiles?.[asset.hostname];
  if (!targetProfile?.recommendedStrategy) return cmdsToRun;
  const existingTools = new Set(cmdsToRun.map((c) => c.tool));
  const strategyPhases = targetProfile.recommendedStrategy.phases;
  let augmentedCount = 0;
  for (const phase of strategyPhases) {
    for (const tool of phase.tools) {
      if (!existingTools.has(tool.tool)) {
        const resolvedFlags = tool.flags.replace(/HOST|TARGET/g, httpTarget).replace(/DISCOVERED_PORTS/g, (asset.ports || []).map((p) => p.port).join(",")).replace(/TARGET_URL/g, `https://${asset.hostname}`).replace(/TARGET:PORT/g, `${asset.hostname}:443`);
        cmdsToRun.push({
          tool: tool.tool,
          command: `${tool.tool} ${resolvedFlags}`,
          purpose: `[Context-Aware] ${tool.purpose}`,
          priority: phase.requiresApproval ? 3 : 2
        });
        existingTools.add(tool.tool);
        augmentedCount++;
      }
    }
  }
  if (augmentedCount > 0) {
    addLog(state, {
      phase: "enumeration",
      type: "info",
      title: `\u{1F9E0} Context-Aware Augmentation: ${fmtTarget(asset)}`,
      detail: `Added ${augmentedCount} tools from ${targetProfile.recommendedStrategy.name} strategy (${targetProfile.recommendedStrategy.riskLevel} risk)
Evasion: ${targetProfile.recommendedStrategy.evasionProfile.name} (${targetProfile.recommendedStrategy.evasionProfile.rateLimit} req/s)`
    });
  }
  return cmdsToRun;
}
function filterAndSanitize(state, asset, target, httpTarget, cmdsToRun, helpers) {
  const isScoped = state.assets.length > 0;
  const highPriorityCmds = cmdsToRun.filter((c) => c.priority <= 2).filter((c) => {
    if (c.tool === "subfinder" && isScoped) {
      addLog(state, {
        phase: "enumeration",
        type: "info",
        title: "Skipped: subfinder (scoped engagement)",
        detail: "Subfinder skipped \u2014 targets are already defined in scope."
      });
      return false;
    }
    return true;
  });
  for (const cmd of highPriorityCmds) {
    if (cmd.tool === "nuclei") {
      sanitizeNucleiCommand(cmd, asset, httpTarget);
    }
    if (cmd.tool === "httpx") {
      sanitizeHttpxCommand(cmd);
    }
    if (cmd.tool === "gobuster") {
      sanitizeGobusterCommand(cmd, state, asset, httpTarget);
    }
    if (cmd.tool === "nikto") {
      sanitizeNiktoCommand(cmd, state, asset);
    }
  }
  return highPriorityCmds;
}
function sanitizeNucleiCommand(cmd, asset, httpTarget) {
  let nucleiCmd = cmd.command.replace(/\bnuclei\b/g, "").trim();
  const targetMatch = nucleiCmd.match(/-(?:target|u)\s+(\S+)/) || nucleiCmd.match(/(https?:\/\/\S+)/);
  let nucleiTarget = targetMatch?.[1] || httpTarget;
  if (nucleiTarget && !nucleiTarget.startsWith("http")) {
    const webPorts = (asset.ports || []).filter(
      (p) => ["http", "https", "http-proxy", "http-alt"].includes(p.service) || [80, 443, 8080, 8443, 8e3, 3e3, 5e3].includes(p.port)
    );
    if (webPorts.length > 0) {
      const scheme = webPorts[0].port === 443 || webPorts[0].port === 8443 ? "https" : "http";
      nucleiTarget = `${scheme}://${nucleiTarget}:${webPorts[0].port}`;
    }
  }
  nucleiCmd = nucleiCmd.replace(/-target\s+\S+/g, "").replace(/-u\s+\S+/g, "").trim();
  if (!nucleiCmd.includes("-severity")) nucleiCmd += " -severity critical,high,medium";
  if (!nucleiCmd.includes("-jsonl")) nucleiCmd += " -jsonl";
  if (!nucleiCmd.includes("-nc")) nucleiCmd += " -nc";
  if (!nucleiCmd.includes("-duc")) nucleiCmd += " -duc";
  if (!nucleiCmd.includes("-ni")) nucleiCmd += " -ni";
  if (!nucleiCmd.includes("-timeout")) nucleiCmd += " -timeout 10";
  if (!nucleiCmd.includes("-retries")) nucleiCmd += " -retries 1";
  const detectedTechs = asset.passiveRecon?.technologies || [];
  const techLower = detectedTechs.map((t) => t.toLowerCase());
  const techTags = [];
  if (techLower.some((t) => t.includes("wordpress"))) techTags.push("wordpress");
  if (techLower.some((t) => t.includes("nginx"))) techTags.push("nginx");
  if (techLower.some((t) => t.includes("apache"))) techTags.push("apache");
  if (techLower.some((t) => t.includes("php"))) techTags.push("php");
  if (techLower.some((t) => t.includes("node") || t.includes("next"))) techTags.push("nodejs");
  if (techLower.some((t) => t.includes("cloudfront") || t.includes("aws"))) techTags.push("aws");
  if (!nucleiCmd.includes("-tags") && techTags.length > 0) nucleiCmd += ` -tags ${techTags.join(",")}`;
  cmd.command = `nuclei -u ${nucleiTarget} ${nucleiCmd}`.replace(/\s+/g, " ").trim();
}
function sanitizeHttpxCommand(cmd) {
  let httpxCmd = cmd.command.replace(/\bhttpx\b/g, "").trim();
  const pipeMatch = httpxCmd.match(/^echo\s+(\S+)\s*\|\s*(.*)$/);
  if (pipeMatch) {
    const httpxUrl = pipeMatch[1];
    const httpxFlags = pipeMatch[2].replace(/\becho\b/g, "").replace(/\|/g, "").trim();
    cmd.command = `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, " ").trim();
  } else {
    const urlMatch = httpxCmd.match(/-u\s+(\S+)/);
    if (urlMatch) {
      const httpxUrl = urlMatch[1];
      const httpxFlags = httpxCmd.replace(/-u\s+\S+/, "").trim();
      cmd.command = `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, " ").trim();
    } else {
      const bareUrl = httpxCmd.match(/(https?:\/\/\S+)/);
      if (bareUrl) {
        const httpxUrl = bareUrl[1];
        const httpxFlags = httpxCmd.replace(/(https?:\/\/\S+)/, "").trim();
        cmd.command = `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, " ").trim();
      } else {
        cmd.command = `httpx ${httpxCmd}`.replace(/\s+/g, " ").trim();
      }
    }
  }
}
function sanitizeGobusterCommand(cmd, state, asset, httpTarget) {
  const gobUrlMatch = cmd.command.match(/-u\s+(\S+)/) || cmd.command.match(/(https?:\/\/\S+)/);
  const gobTargetUrl = gobUrlMatch?.[1] || httpTarget;
  const wafDetected = !!(asset.wafDetected && asset.wafDetected !== "none");
  const detectedTech = asset.passiveRecon?.technologies || [];
  const isApiTarget = asset.type === "api" || (asset.ports || []).some((p) => /api|graphql|rest/i.test(p.service || "")) || /\/api\/|\/v[0-9]+\//i.test(gobTargetUrl);
  let authCookie = "";
  const webCreds = (asset.confirmedCredentials || []).filter(
    (c) => ["http", "web", "form", "http-get", "http-post-form"].includes(c.service)
  );
  if (webCreds.length > 0 && webCreds[0].sessionCookie) {
    authCookie = webCreds[0].sessionCookie;
  } else if (asset.trainingLabCreds?.sessionCookie) {
    authCookie = asset.trainingLabCreds.sessionCookie;
  }
  const profile = getScanProfile(state.scanProfile || "standard");
  cmd.command = buildGobusterCommand(profile, gobTargetUrl, {
    wafDetected,
    authCookie: authCookie || void 0,
    detectedTech,
    isApiTarget
  });
}
function sanitizeNiktoCommand(cmd, state, asset) {
  const niktoUrlMatch = cmd.command.match(/-h\s+(https?:\/\/\S+)/);
  if (niktoUrlMatch) {
    const niktoUrl = niktoUrlMatch[1];
    const isNiktoHttps = niktoUrl.startsWith("https://") || /:(443|8443|8444|8445|8447|9443)\b/.test(niktoUrl);
    if (isNiktoHttps && !cmd.command.includes("-ssl")) {
      cmd.command = cmd.command.replace(/-h\s+\S+/, "$& -ssl");
    }
  }
  if (!cmd.command.includes("-vhost") && asset.hostname && asset.ip && asset.hostname !== asset.ip) {
    if (KNOWN_INFRA_IPS2.has(asset.ip)) {
      cmd.command += ` -vhost ${asset.hostname}`;
    }
  }
  if (!cmd.command.includes("-maxtime")) {
    cmd.command += " -maxtime 300";
  }
  if (!cmd.command.includes("Cookie:") && !cmd.command.includes("-id ")) {
    let niktoCookie = "";
    if (asset.trainingLabCreds?.sessionCookie) {
      niktoCookie = asset.trainingLabCreds.sessionCookie;
    } else {
      const niktoWebCreds = (asset.confirmedCredentials || []).filter(
        (c) => ["http", "web", "form", "http-get", "http-post-form"].includes(c.service)
      );
      if (niktoWebCreds.length > 0 && niktoWebCreds[0].sessionCookie) {
        niktoCookie = niktoWebCreds[0].sessionCookie;
      }
    }
    if (niktoCookie) {
      cmd.command += ` -H "Cookie: ${niktoCookie}"`;
    }
  }
  cmd.command = cmd.command.replace(/\s+/g, " ").trim();
}
async function applyEvasionFlags(state, asset, highPriorityCmds) {
  if (!state.targetProfiles) return;
  const targetProfile = state.targetProfiles[asset.hostname];
  if (!targetProfile) return;
  try {
    const { augmentCommandWithEvasion } = await import("./evasion-cli-adapter-OVRHDAK4.js");
    for (const cmd of highPriorityCmds) {
      const augmentation = augmentCommandWithEvasion(cmd.tool, cmd.command, targetProfile);
      if (augmentation.flagsAdded.length > 0) {
        cmd.command = augmentation.augmentedCommand;
      }
    }
  } catch {
  }
}
async function executeToolsInParallel(state, asset, highPriorityCmds, helpers) {
  const CONCURRENCY_LIMIT = 2;
  addLog(state, {
    phase: "enumeration",
    type: "info",
    title: `\u26A1 Parallel Execution: ${fmtTarget(asset)}`,
    detail: `Running ${highPriorityCmds.length} tools with concurrency=${CONCURRENCY_LIMIT} (${highPriorityCmds.map((c) => c.tool).join(", ")})`
  });
  async function executeToolCmd(cmd) {
    addLog(state, {
      phase: "enumeration",
      type: "scan_start",
      title: `Running: ${cmd.tool}`,
      detail: `${cmd.purpose} \u2014 ${cmd.command.slice(0, 120)}`,
      data: { tool: cmd.tool, fullCommand: cmd.command }
    });
    const toolTimeout = cmd.tool === "nuclei" ? 300 : 180;
    let result;
    const isPipeCommand = cmd.tool === "raw" || cmd.tool === "httpx" && cmd.command.includes("echo ") || cmd.tool === "nuclei" && cmd.command.includes("echo ");
    if (isPipeCommand) {
      const rawCmd = cmd.command.startsWith("raw ") ? cmd.command.slice(4) : cmd.command;
      const startTimeRaw = Date.now();
      result = await executeRawCommandViaQueue(rawCmd + " 2>&1", toolTimeout, {
        engagementId: state.engagementId
      });
      result.durationMs = Date.now() - startTimeRaw;
    } else {
      const cmdArgs = cmd.command.startsWith(cmd.tool) ? cmd.command.slice(cmd.tool.length).trim() : cmd.command;
      const startTime = Date.now();
      result = await helpers.executeTool({
        tool: cmd.tool,
        args: cmdArgs,
        timeoutSeconds: toolTimeout,
        engagementId: state.engagementId
      });
      if (!result.durationMs) result.durationMs = Date.now() - startTime;
    }
    if (result.stdout && result.stdout.length > 1e5) {
      result.stdout = result.stdout.slice(0, 1e5);
    }
    if (result.stderr && result.stderr.length > 5e4) {
      result.stderr = result.stderr.slice(0, 5e4);
    }
    const findings = parseToolOutput(cmd.tool, result.stdout || "", asset);
    asset.toolResults.push({
      tool: cmd.tool,
      command: cmd.command,
      exitCode: result.exitCode,
      durationMs: result.durationMs,
      timedOut: result.timedOut,
      findingCount: findings.length,
      findings: findings.map((f) => ({
        severity: f.severity,
        title: f.title,
        cve: f.cve,
        evidence: f.evidence?.proofText || void 0
      })),
      outputPreview: (result.stdout || "").slice(0, 512),
      executedAt: Date.now(),
      phase: "targeted_enum"
    });
    addLog(state, {
      phase: "enumeration",
      type: "scan_result",
      title: `${cmd.tool} Complete: ${fmtTarget(asset)}`,
      detail: `Exit code ${result.exitCode}, ${result.durationMs}ms, ${findings.length} findings${result.timedOut ? " (TIMED OUT)" : ""}`,
      data: { tool: cmd.tool, exitCode: result.exitCode, durationMs: result.durationMs, findings }
    });
    let newCount = 0;
    for (const f of findings) {
      if (pushVulnDeduped(asset, {
        id: genId(),
        severity: f.severity,
        title: f.title,
        cve: f.cve,
        description: f.description,
        cvss: f.cvss,
        cwe: f.cwe,
        corroborationTier: "confirmed",
        evidenceDetail: `Confirmed by ${cmd.tool} active scan`,
        rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4e3) : void 0,
        source: cmd.tool
      })) {
        state.stats.vulnsFound++;
        newCount++;
      }
    }
    return { tool: cmd.tool, findings: newCount, timedOut: result.timedOut };
  }
  const parallelStartTime = Date.now();
  for (let i = 0; i < highPriorityCmds.length; i += CONCURRENCY_LIMIT) {
    const batch = highPriorityCmds.slice(i, i + CONCURRENCY_LIMIT);
    const batchResults = await Promise.allSettled(
      batch.map(
        (cmd) => executeToolCmd(cmd).catch((e) => {
          addLog(state, { phase: "enumeration", type: "error", title: `${cmd.tool} Error`, detail: e.message });
          return null;
        })
      )
    );
    const succeeded = batchResults.filter((r) => r.status === "fulfilled" && r.value).length;
    const failed = batchResults.length - succeeded;
    if (batch.length > 1) {
      addLog(state, {
        phase: "enumeration",
        type: "info",
        title: `Batch ${Math.floor(i / CONCURRENCY_LIMIT) + 1} complete`,
        detail: `${succeeded}/${batch.length} tools finished (${failed} errors). Tools: ${batch.map((c) => c.tool).join(", ")}`
      });
    }
    try {
      const { midScanCleanup } = await import("./memory-manager-VARXZ63M.js");
      midScanCleanup(state);
    } catch {
      if (global.gc) global.gc();
    }
    if (failed > 0 && state.targetProfiles) {
      await autoEscalateEvasion(state, asset, batch.length);
    }
  }
  const parallelDuration = Date.now() - parallelStartTime;
  addLog(state, {
    phase: "enumeration",
    type: "info",
    title: `\u26A1 Parallel execution complete: ${fmtTarget(asset)}`,
    detail: `${highPriorityCmds.length} tools finished in ${Math.round(parallelDuration / 1e3)}s (parallel batches of ${CONCURRENCY_LIMIT})`
  });
}
async function autoEscalateEvasion(state, asset, batchSize) {
  try {
    const { escalateEvasionProfile: evaluateAndEscalate } = await import("./evasion-escalation-engine-IZY7LIBH.js");
    const profile = state.targetProfiles?.[asset.hostname];
    if (!profile) return;
    const recentResults = asset.toolResults.slice(-batchSize);
    for (const tr of recentResults) {
      const output = tr.outputPreview || "";
      const isBlocked = tr.exitCode !== 0 || tr.timedOut || /403|blocked|captcha|rate.limit|connection.reset|ip.ban/i.test(output);
      if (isBlocked) {
        const blockReason = tr.timedOut ? "rate_limit" : /403|blocked|waf/i.test(output) ? "waf_block" : /captcha/i.test(output) ? "captcha" : /rate.limit/i.test(output) ? "rate_limit" : /connection.reset|rst/i.test(output) ? "connection_reset" : /ban/i.test(output) ? "ip_ban" : "waf_block";
        const escalationResult = evaluateAndEscalate(profile, blockReason, { toolOutput: output });
        if (escalationResult.escalation.currentLevel > (profile.evasionEscalation?.currentLevel || 1)) {
          state.targetProfiles[asset.hostname] = {
            ...profile,
            evasionEscalation: escalationResult.escalation
          };
          addLog(state, {
            phase: "enumeration",
            type: "warning",
            title: `\u26A1 Evasion auto-escalated: ${asset.hostname}`,
            detail: `Level ${escalationResult.escalation.currentLevel}: ${escalationResult.escalation.action} (trigger: ${blockReason})`
          });
          break;
        }
      }
    }
  } catch {
  }
}
var KNOWN_INFRA_IPS2;
var init_targeted_tool_runner = __esm({
  "server/lib/active-enumeration/targeted-tool-runner.ts"() {
    "use strict";
    init_enumeration_context();
    KNOWN_INFRA_IPS2 = /* @__PURE__ */ new Set([
      // Add scan server IPs here
    ]);
  }
});

// server/lib/active-enumeration/index.ts
var init_active_enumeration = __esm({
  "server/lib/active-enumeration/index.ts"() {
    "use strict";
    init_dns_resolver();
    init_port_discovery();
    init_service_fingerprinter_runner();
    init_httpx_prober();
    init_cloud_scanner_runner();
    init_target_profiler();
    init_targeted_tool_runner();
    init_enumeration_context();
  }
});

// server/lib/engagement-phase-enumeration.ts
async function executeEnumeration(state, engagement, operatorCtx) {
  state.phase = "enumeration";
  state.currentAction = "Running enumeration & fingerprinting...";
  addLog(state, {
    phase: "enumeration",
    type: "info",
    title: "\u{1F50E} Phase 5: Active Discovery & Enumeration",
    detail: "Two-phase approach: Phase A discovery ScanForge discovery with evasion \u2192 Phase B targeted tool deployment"
  });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "enumeration" });
  const scopedAssets = state.assets.filter((a) => isInRoeScope(state, a.hostname, a.ip));
  const skippedAssets = state.assets.filter((a) => !isInRoeScope(state, a.hostname, a.ip));
  if (skippedAssets.length > 0) {
    addLog(state, {
      phase: "enumeration",
      type: "warning",
      title: `\u{1F6E1}\uFE0F Scope Guard: ${skippedAssets.length} assets excluded from active scanning`,
      detail: `Excluded: ${skippedAssets.map((a) => a.hostname).join(", ")}
Only RoE-authorized targets will be actively probed.`
    });
  }
  const helpers = buildEnumerationHelpers(state);
  await resolveAssetDns(state, scopedAssets, helpers);
  const targets = scopedAssets.map((a) => ({
    scanTarget: getEffectiveTarget(a, "discovery"),
    assetHostname: a.hostname
  }));
  await executePortDiscovery(state, targets, helpers);
  state.progress = 25;
  addLog(state, {
    phase: "enumeration",
    type: "phase_complete",
    title: "\u2705 Phase A Discovery Complete",
    detail: `${state.stats.hostsScanned} hosts scanned, ${state.stats.portsFound} ports discovered. Enriched data now available for Phase B targeted tool deployment.`
  });
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
  for (const asset of state.assets) {
    for (const p of asset.ports || []) {
      broadcastReconFinding(state.engagementId, {
        target: asset.hostname || asset.ip,
        port: typeof p.port === "number" ? p.port : parseInt(String(p.port)) || void 0,
        service: p.service || void 0,
        protocol: "tcp",
        tool: "scanforge_discovery"
      });
    }
  }
  await runCloudAssetDetection(state, helpers);
  await runTargetProfiling(state, scopedAssets, helpers);
  await executeTargetedToolDeployment(state, helpers);
  state.progress = 35;
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
}
var init_engagement_phase_enumeration = __esm({
  "server/lib/engagement-phase-enumeration.ts"() {
    init_orchestrator_types();
    init_engagement_orchestrator();
    init_active_enumeration();
  }
});
init_engagement_phase_enumeration();
export {
  executeEnumeration
};
