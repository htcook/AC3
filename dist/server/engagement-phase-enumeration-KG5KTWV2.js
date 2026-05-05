import {
  fmtTarget,
  init_orchestrator_types,
  isInRoeScope
} from "./chunk-M7Y3UOC3.js";
import {
  addLog,
  broadcastOpsUpdate,
  getEffectiveTarget,
  init_engagement_orchestrator,
  init_tool_output_parsers,
  parseToolOutput
} from "./chunk-VNE3HZVO.js";
import "./chunk-5U7VSFQX.js";
import "./chunk-HPRQMQNG.js";
import "./chunk-DOQ4XSAD.js";
import "./chunk-SG5FPEKQ.js";
import "./chunk-NYDLFO63.js";
import "./chunk-RDDOUXNN.js";
import "./chunk-4I5JHMN4.js";
import "./chunk-LI545HOX.js";
import "./chunk-5DEWV7VV.js";
import "./chunk-2Z3TQ745.js";
import "./chunk-MJGBFYEG.js";
import "./chunk-IL4FZKPB.js";
import "./chunk-HLPX2P35.js";
import "./chunk-R4LF5PWF.js";
import "./chunk-EBOA2OTZ.js";
import "./chunk-76MQOQX2.js";
import "./chunk-4SXJ2GAM.js";
import "./chunk-5BWO4Y3K.js";
import "./chunk-7DIV2VRB.js";
import "./chunk-D7O53KWC.js";
import "./chunk-SDB7RKKY.js";
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
import "./chunk-BRIFEITD.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-KUPDIQVG.js";
import "./chunk-SOJRLK5Z.js";
import "./chunk-AGW4B7XR.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-YB6W7YNA.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/engagement-phase-enumeration.ts
function genId() {
  return Math.random().toString(36).substring(2, 10);
}
async function executeEnumeration(state, engagement, operatorCtx) {
  state.phase = "enumeration";
  state.currentAction = "Running enumeration & fingerprinting...";
  addLog(state, { phase: "enumeration", type: "info", title: "\u{1F50E} Phase 5: Active Discovery & Enumeration", detail: "Two-phase approach: Phase A discovery ScanForge discovery with evasion \u2192 Phase B targeted tool deployment" });
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
  const dns = await import("dns");
  const { promisify } = await import("util");
  const dnsResolve4 = promisify(dns.resolve4);
  const scanServerHost = process.env.SCAN_SERVER_HOST || "";
  const SCAN_SERVER_DOMAIN = "scan.aceofcloud.io";
  addLog(state, { phase: "enumeration", type: "info", title: `DNS Pre-Resolution: checking ${scopedAssets.length} assets`, detail: `Resolving hostnames to IPs before ScanForge scan` });
  for (const asset of scopedAssets) {
    if (asset.ip) continue;
    const hostname = asset.hostname;
    try {
      const ips = await dnsResolve4(hostname);
      if (ips.length > 0) {
        asset.ip = ips[0];
        addLog(state, { phase: "enumeration", type: "info", title: `DNS Resolved: ${hostname}`, detail: `${hostname} \u2192 ${ips[0]}` });
      }
    } catch (_dnsErr) {
      const knownLabSubdomains = ["dvwa", "juice-shop", "juiceshop", "webgoat", "bwapp", "mutillidae", "vampi", "crapi", "hackazon"];
      const hostnameBase = hostname.split(".")[0]?.toLowerCase() || "";
      const isLabOnScanServer = state.engagementType === "training_lab" || asset.passiveRecon?.liveInstanceUrl?.includes(SCAN_SERVER_DOMAIN) || asset.passiveRecon?.liveInstanceUrl?.includes(scanServerHost) || hostname.endsWith(".aceofcloud.io") && knownLabSubdomains.includes(hostnameBase) || hostname.includes(SCAN_SERVER_DOMAIN);
      if (isLabOnScanServer) {
        try {
          const scanIps = await dnsResolve4(SCAN_SERVER_DOMAIN);
          if (scanIps.length > 0) {
            asset.ip = scanIps[0];
            addLog(state, {
              phase: "enumeration",
              type: "info",
              title: `DNS Fallback: ${hostname} \u2192 scan server IP`,
              detail: `${hostname} failed DNS resolution. Training lab detected \u2014 using scan server IP ${scanIps[0]} (${SCAN_SERVER_DOMAIN})`
            });
          }
        } catch {
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(scanServerHost)) {
            asset.ip = scanServerHost;
            addLog(state, {
              phase: "enumeration",
              type: "info",
              title: `DNS Fallback: ${hostname} \u2192 scan server IP (env)`,
              detail: `Using SCAN_SERVER_HOST env IP: ${scanServerHost}`
            });
          }
        }
      }
      if (!asset.ip) {
        addLog(state, {
          phase: "enumeration",
          type: "warning",
          title: `\u26A0\uFE0F DNS Resolution Failed: ${hostname}`,
          detail: `Could not resolve ${hostname} to an IP address. ScanForge discovery may fail for this target.`
        });
      }
    }
  }
  const targets = scopedAssets.map((a) => ({
    scanTarget: getEffectiveTarget(a, "discovery"),
    // Discovery: IP for port scans, hostname for vhosted targets
    assetHostname: a.hostname
    // Which asset this belongs to
  }));
  if (targets.length > 0) {
    const ep = state.scanPlan?.discoveryEvasionProfile;
    const evasionDesc = ep ? `Timing: ${ep.timing}, Fragmentation: ${ep.fragmentation}, Decoys: ${ep.decoys}, Host Randomization: ${ep.randomizeHosts}, Data Padding: ${ep.dataLengthPadding}, Source Port Spoofing: ${ep.sourcePortSpoofing}` : "Default evasion profile";
    addLog(state, {
      phase: "enumeration",
      type: "scan_start",
      title: "\u{1F50D} Phase A: Discovery Scan with Evasion",
      detail: `Scanning ${targets.length} targets with full port sweep + service fingerprinting
Evasion: ${evasionDesc}
${state.scanPlan?.discoveryStrategy || "Comprehensive port discovery to enrich passive recon data"}`
    });
    try {
      const { getScanServerConfigForScanForge } = await import("./scan-server-executor-RYJD5OAQ.js");
      const { executeScanforgeScan, autoSelectTool } = await import("./scanforge-discovery-E3DYLR5A.js");
      const roeScope = [...state.roeScopeGuard?.authorizedDomains || [], ...state.roeScopeGuard?.authorizedIps || []];
      const engagementAbortSig = getEngagementAbortSignal(state.engagementId);
      const executeTool2 = (config) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope, engagementAbortSignal: engagementAbortSig });
      const serverConfig = await getScanServerConfigForScanForge();
      for (const targetEntry of targets) {
        const target = targetEntry.scanTarget;
        const asset = state.assets.find((a) => a.hostname === targetEntry.assetHostname);
        if (!asset) continue;
        asset.status = "scanning";
        const assetPlan = state.scanPlan?.assetPlans.find(
          (ap) => ap.hostname === asset.hostname || ap.ip === target
        );
        const discoveryFlags = assetPlan?.discoveryFlags || "-Pn -sV -sC -O -f -T2 -D RND:5 --data-length 64";
        const discoveredPorts = [];
        const sfTool = autoSelectTool({ targets: [target], stealthLevel: assetPlan?.evasionTechniques?.length ? "medium" : "minimal" });
        const discoveryRationale = `ScanForge ${sfTool} \u2014 top ports discovery with service fingerprinting`;
        addLog(state, {
          phase: "enumeration",
          type: "scan_start",
          title: `\u{1F512} scanforge: ${fmtTarget(asset, target)}`,
          detail: `Phase A Step 1 \u2014 ${discoveryRationale}
Evasion: ${assetPlan?.evasionTechniques?.join(", ") || "fragmentation, decoys, normal timing"}`
        });
        const startTime = Date.now();
        let autoCaptureSessionId = null;
        try {
          const { beforeDiscoveryScan } = await import("./pcap-auto-capture-Z4K7TCTU.js");
          autoCaptureSessionId = await beforeDiscoveryScan(
            state.engagementId,
            target,
            asset.hostname,
            { enabled: !!state.autoCaptureEnabled }
          );
          if (autoCaptureSessionId) {
            addLog(state, {
              phase: "enumeration",
              type: "info",
              title: `\u{1F4E1} Auto-Capture: ${fmtTarget(asset, target)}`,
              detail: `Background tcpdump started for forensic analysis during discovery scan`
            });
          }
        } catch (capErr) {
          console.warn(`[AutoCapture] Hook failed: ${capErr.message}`);
        }
        try {
          const sfArgs = sfTool === "naabu" ? `-host ${target} -top-ports 1000 -s s -no-stdin -rate 1000 -retries 1 -json` : sfTool === "masscan" ? `${target} -p1-1024,1720,2000,2427,3306,3389,5060,5061,5080,5432,5900,6379,8080,8443,9090,27017,41795 --rate 1000 -oJ -` : sfTool === "rustscan" ? `-a ${target} --range 1-65535 -b 4500 -g` : `-host ${target} -top-ports 1000 -s s -no-stdin -json`;
          addLog(state, { phase: "enumeration", type: "tool_exec", title: `${sfTool} ${fmtTarget(asset, target)}`, detail: `${sfTool} ${sfArgs}` });
          const discoveryResult = await executeTool2({ tool: sfTool, args: sfArgs, timeoutSeconds: 600, sudo: sfTool === "masscan" || sfTool === "zmap" || sfTool === "naabu" });
          if (discoveryResult.stdout) {
            try {
              const discovery = await import("./scanforge-discovery-E3DYLR5A.js");
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
            addLog(state, {
              phase: "enumeration",
              type: "info",
              title: `\u26A0\uFE0F scanforge Retry: ${fmtTarget(asset, target)} (removing evasion flags)`,
              detail: `First scan returned all-filtered (likely cloud WAF blocking evasion techniques). Retrying with naabu (most reliable fallback)`
            });
            const retryFlags = `-host ${target} -top-ports 1000 -s s -no-stdin -rate 1000 -retries 1 -json`;
            const retryArgs = retryFlags;
            const retryStart = Date.now();
            try {
              const retryResult = await executeTool2({ tool: sfTool || "naabu", args: retryArgs, timeoutSeconds: 600, sudo: true });
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
              addLog(state, {
                phase: "enumeration",
                type: "scan_result",
                title: `scanforge Retry Complete: ${fmtTarget(asset, target)}`,
                detail: `Retry found ${discoveredPorts.length} services (simple flags worked)`
              });
              await persistScanResult({
                engagementId: state.engagementId,
                tool: sfTool || "naabu",
                target,
                command: `naabu ${retryArgs}`,
                stdout: retryResult.stdout || "",
                stderr: retryResult.stderr || "",
                exitCode: retryResult.exitCode ?? 0,
                durationMs: Date.now() - retryStart,
                timedOut: retryResult.timedOut || false,
                findings: discoveredPorts.map((p) => ({ type: "open_port", port: p.port, protocol: p.protocol, service: p.service, product: p.product, version: p.version })),
                phase: "discovery_retry"
              });
            } catch (retryErr) {
              addLog(state, { phase: "enumeration", type: "error", title: `scanforge Retry Failed: ${fmtTarget(asset, target)}`, detail: retryErr.message });
            }
          }
          asset.ports = discoveredPorts.map((p) => ({
            port: p.port,
            service: p.service || "unknown",
            version: p.product ? `${p.product}${p.version ? " " + p.version : ""}`.trim() : void 0
          }));
          enrichPortServices(asset.ports, asset.passiveRecon?.services || []);
          if (discoveredPorts.length === 0) {
            const isWebAsset = asset.type === "web_app" || asset.passiveRecon?.technologies?.some((t) => /nginx|apache|iis|http|web|php|node|express|flask|django/i.test(t)) || asset.passiveRecon?.services?.some((s) => /http/i.test(s.service || ""));
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
              addLog(state, {
                phase: "enumeration",
                type: "info",
                title: `\u{1F310} Port Seeding: ${fmtTarget(asset, target)}`,
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
          broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
          addLog(state, {
            phase: "enumeration",
            type: "scan_result",
            title: `scanforge Complete: ${fmtTarget(asset, target)}`,
            detail: `${discoveredPorts.length} services fingerprinted in ${Math.round(durationMs / 1e3)}s
Ports: ${discoveredPorts.map((p) => `${p.port}/${p.service}${p.product ? ` (${p.product})` : ""}`).join(", ")}`,
            data: { ports: asset.ports, discoveryFlags, evasion: assetPlan?.evasionTechniques }
          });
          await persistScanResult({
            engagementId: state.engagementId,
            tool: sfTool || "naabu",
            target,
            command: `${sfTool} ${sfArgs}`,
            stdout: discoveryResult.stdout || "",
            stderr: discoveryResult.stderr || "",
            exitCode: discoveryResult.exitCode ?? 0,
            durationMs,
            timedOut: discoveryResult.timedOut || false,
            findings: discoveredPorts.map((p) => ({ type: "open_port", port: p.port, protocol: p.protocol, service: p.service, product: p.product, version: p.version })),
            phase: "discovery"
          });
        } catch (e) {
          addLog(state, { phase: "enumeration", type: "error", title: `scanforge Failed: ${fmtTarget(asset, target)}`, detail: e.message });
          asset.status = "enumerated";
        }
        if (autoCaptureSessionId) {
          try {
            const { afterDiscoveryScan } = await import("./pcap-auto-capture-Z4K7TCTU.js");
            const captureResult = await afterDiscoveryScan(autoCaptureSessionId);
            if (captureResult && captureResult.packetsCaptured) {
              addLog(state, {
                phase: "enumeration",
                type: "info",
                title: `\u{1F4E1} Auto-Capture Complete: ${fmtTarget(asset, target)}`,
                detail: `Captured ${captureResult.packetsCaptured} packets during discovery scan (${Math.round((captureResult.stoppedAt - captureResult.startedAt) / 1e3)}s)${captureResult.analysisSummary ? `
Findings: ${captureResult.analysisSummary.findings} security findings detected, ${captureResult.analysisSummary.conversations} conversations, protocols: ${captureResult.analysisSummary.protocols.join(", ")}` : ""}`,
                data: { pcapPath: captureResult.pcapPath, packetsCaptured: captureResult.packetsCaptured, analysisSummary: captureResult.analysisSummary }
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
        try {
          const { autoFingerprint, summarizeFingerprints } = await import("./service-fingerprinter-PN56IYU6.js");
          const { getCachedFingerprints, cacheFingerprints } = await import("./fingerprint-cache-EAUC562M.js");
          const openPortNumbers = asset.ports.map((p) => p.port);
          if (openPortNumbers.length > 0) {
            const cacheLookup = await getCachedFingerprints(target, openPortNumbers);
            const cacheNote = cacheLookup.hitCount > 0 ? ` (\u2705 ${cacheLookup.hitCount} cached, ${cacheLookup.missCount} to probe)` : "";
            addLog(state, {
              phase: "enumeration",
              type: "info",
              title: `\u{1F50D} Service Fingerprinting: ${fmtTarget(asset, target)}`,
              detail: `Running protocol-specific probes on ${openPortNumbers.length} ports: ${openPortNumbers.join(", ")}${cacheNote}`
            });
            const fpStart = Date.now();
            let fpResults;
            if (cacheLookup.uncachedPorts.length > 0) {
              const freshResults = await autoFingerprint(target, cacheLookup.uncachedPorts, {
                engagementId: state.engagementId,
                operatorId: state.operatorId,
                timeoutMs: 1e4,
                tryDefaultCreds: (state.scanProfile || "standard") !== "stealth"
              });
              fpResults = [...cacheLookup.cached, ...freshResults];
              if (freshResults.length > 0) {
                const cacheResult = await cacheFingerprints(target, freshResults, state.engagementId);
                if (cacheResult.cached > 0) {
                  console.log(`[FingerprintCache] Cached ${cacheResult.cached} new results for ${target}`);
                }
              }
            } else {
              fpResults = cacheLookup.cached;
            }
            const fpDuration = Date.now() - fpStart;
            let upgraded = 0;
            for (const fp of fpResults) {
              if (fp.error) continue;
              const portEntry = asset.ports.find((p) => p.port === fp.port);
              if (portEntry) {
                if (fp.protocol) {
                  portEntry.service = fp.protocol;
                  portEntry.serviceSource = "fingerprinted";
                }
                if (fp.product || fp.version) {
                  portEntry.version = [fp.product, fp.version].filter(Boolean).join(" ");
                }
                portEntry.banner = fp.banner;
                portEntry.product = fp.product;
                portEntry.os = fp.os;
                portEntry.securityFlags = fp.securityFlags;
                portEntry.riskIndicators = fp.riskIndicators;
                portEntry.potentialCves = fp.potentialCves;
                upgraded++;
              }
            }
            const summary = summarizeFingerprints(fpResults);
            asset.fingerprintResults = fpResults;
            asset.fingerprintSummary = summary;
            addLog(state, {
              phase: "enumeration",
              type: "scan_result",
              title: `\u{1F50D} Fingerprinting Complete: ${fmtTarget(asset, target)}`,
              detail: `${summary.successfulProbes}/${summary.totalServices} services fingerprinted in ${Math.round(fpDuration / 1e3)}s \u2014 ${upgraded} ports upgraded
Products: ${fpResults.filter((f) => f.product).map((f) => `${f.port}/${f.product} ${f.version || ""}`).join(", ") || "none detected"}
Risks: ${summary.criticalRisks} critical, ${summary.highRisks} high, ${summary.mediumRisks} medium` + (summary.servicesWithAnonymousAccess.length > 0 ? `
\u26A0\uFE0F Anonymous access: ${summary.servicesWithAnonymousAccess.map((s) => `${s.port}/${s.protocol}`).join(", ")}` : "") + (summary.servicesWithDefaultCreds.length > 0 ? `
\u{1F511} Default credentials: ${summary.servicesWithDefaultCreds.map((s) => `${s.port}/${s.protocol}`).join(", ")}` : "") + (summary.allCves.length > 0 ? `
\u{1F6E1}\uFE0F Potential CVEs: ${summary.allCves.slice(0, 10).join(", ")}${summary.allCves.length > 10 ? ` (+${summary.allCves.length - 10} more)` : ""}` : ""),
              data: {
                fingerprintResults: fpResults.map((f) => ({
                  port: f.port,
                  protocol: f.protocol,
                  product: f.product,
                  version: f.version,
                  banner: f.banner,
                  os: f.os,
                  securityFlags: f.securityFlags,
                  riskIndicators: f.riskIndicators,
                  potentialCves: f.potentialCves
                })),
                summary: {
                  successfulProbes: summary.successfulProbes,
                  failedProbes: summary.failedProbes,
                  criticalRisks: summary.criticalRisks,
                  highRisks: summary.highRisks,
                  anonymousAccess: summary.servicesWithAnonymousAccess.length,
                  defaultCreds: summary.servicesWithDefaultCreds.length,
                  noTls: summary.servicesWithoutTls.length
                }
              }
            });
            try {
              const { enrichFingerprintsWithVulnFeeds } = await import("./fingerprint-cve-enrichment-TABS4WEJ.js");
              const { results: enrichedFps, summary: enrichSummary } = await enrichFingerprintsWithVulnFeeds(fpResults);
              asset.fingerprintResults = enrichedFps;
              asset.fingerprintCveEnrichment = enrichSummary;
              if (enrichSummary.enrichedCount > 0) {
                addLog(state, {
                  phase: "enumeration",
                  type: "finding",
                  title: `\u{1F6E1}\uFE0F CVE Enrichment: ${enrichSummary.totalCvesMatched} CVEs matched for ${fmtTarget(asset, target)}`,
                  detail: `Vuln feeds matched ${enrichSummary.totalCvesMatched} CVEs across ${enrichSummary.enrichedCount} services
Exploitable: ${enrichSummary.exploitableCveCount} | CISA KEV: ${enrichSummary.kevCveCount} | Active 0-day: ${enrichSummary.zeroDayCveCount}
Risk Score: ${enrichSummary.overallRiskScore}/100 | Max Severity: ${enrichSummary.maxSeverity.toUpperCase()}
Priority targets: ${enrichSummary.perService.filter((s) => s.matchedCves.length > 0).slice(0, 3).map((s) => `${s.port}/${s.product || s.protocol} (${s.matchedCves.length} CVEs)`).join(", ")}`,
                  data: { enrichSummary }
                });
              }
            } catch (enrichErr) {
              console.warn("[FP-CVE-Enrich] Non-blocking enrichment failed:", enrichErr.message);
            }
            try {
              const { diffFingerprints, fingerprintsToCacheEntries, buildDiffSummaryText } = await import("./fingerprint-diff-TAJYXW77.js");
              const { getCachedFingerprints: getPrevCached } = await import("./fingerprint-cache-EAUC562M.js");
              const allPrevPorts = Array.from({ length: 65535 }, (_, i) => i + 1);
              const prevCached = cacheLookup.cached.map((c) => ({
                host: c.host || target,
                port: c.port,
                protocol: c.protocol || null,
                product: c.product || null,
                version: c.version || null,
                banner: c.banner || null,
                os: c.os || null,
                securityFlags: c.securityFlags || null,
                riskIndicators: c.riskIndicators || [],
                potentialCves: c.potentialCves || [],
                confidence: c.confidence || 0,
                fingerprintedAt: c.fingerprintedAt || Date.now() - 864e5,
                engagementId: String(state.engagementId)
              }));
              if (prevCached.length > 0) {
                const diffReport = diffFingerprints(fpResults, prevCached, state.engagementId);
                asset.fingerprintDiff = diffReport;
                if (diffReport.totalChanges > 0) {
                  const diffSummary = buildDiffSummaryText(diffReport);
                  addLog(state, {
                    phase: "enumeration",
                    type: diffReport.postureChange === "degraded" ? "finding" : "info",
                    title: `\u{1F4CA} Fingerprint Diff: ${diffReport.totalChanges} changes for ${fmtTarget(asset, target)}`,
                    detail: `Posture: ${diffReport.postureChange.toUpperCase()} | Risk Delta: ${diffReport.riskScoreDelta > 0 ? "+" : ""}${diffReport.riskScoreDelta}
New services: +${diffReport.newServices.length} | Removed: -${diffReport.removedServices.length} | Version changes: ${diffReport.versionChanges.length}
CVE delta: +${diffReport.cveDelta.newCves.length} new, -${diffReport.cveDelta.resolvedCves.length} resolved, ${diffReport.cveDelta.persistentCves.length} persistent
` + (diffReport.changeBySeverity.critical > 0 ? `\u26A0\uFE0F ${diffReport.changeBySeverity.critical} CRITICAL changes detected!
` : "") + (diffReport.changeBySeverity.high > 0 ? `\u26A0\uFE0F ${diffReport.changeBySeverity.high} HIGH changes detected
` : ""),
                    data: { diffReport }
                  });
                }
              }
            } catch (diffErr) {
              console.warn("[FP-Diff] Non-blocking diff failed:", diffErr.message);
            }
            enrichPortServices(asset.ports, asset.passiveRecon?.services || []);
          }
        } catch (fpErr) {
          addLog(state, {
            phase: "enumeration",
            type: "info",
            title: `\u{1F50D} Fingerprinting Skipped: ${fmtTarget(asset, target)}`,
            detail: `Service fingerprinting failed (non-blocking): ${fpErr.message}`
          });
        }
        try {
          const { detectWafFromBanners, mergeBannerWafIntoAsset, generateEvasionProfile } = await import("./banner-waf-detector-MNWC2RNZ.js");
          const fpResults = asset.fingerprintResults;
          if (fpResults && fpResults.length > 0) {
            const bannerWafSummary = detectWafFromBanners(fpResults);
            if (bannerWafSummary.detections.length > 0) {
              const { wafVendor, newDetections } = mergeBannerWafIntoAsset(asset.wafDetected, bannerWafSummary.detections);
              if (newDetections && wafVendor) {
                asset.wafDetected = wafVendor;
                state.stats.wafDetections = (state.stats.wafDetections || 0) + bannerWafSummary.detections.length;
                const evasionProfile = generateEvasionProfile(bannerWafSummary);
                asset.bannerEvasionProfile = evasionProfile;
                asset.bannerWafSummary = bannerWafSummary;
                const categoryBreakdown = bannerWafSummary.detections.map(
                  (d) => `${d.port}/${d.protocol}: ${d.vendor} ${d.product} [${d.category}] (${d.confidence}% confidence)`
                ).join("\n");
                addLog(state, {
                  phase: "enumeration",
                  type: "waf_detected",
                  title: `\u{1F6E1}\uFE0F Banner WAF/IDS Detected: ${fmtTarget(asset, target)} \u2014 ${bannerWafSummary.uniqueVendors.join(", ")}`,
                  detail: `Security posture: ${bannerWafSummary.posture.replace("_", " ")}
Detections:
${categoryBreakdown}
Evasion: rate=${evasionProfile.rateMultiplier}x, fragment=${evasionProfile.useFragmentation}, encrypt=${evasionProfile.useEncryption}
Recommendations: ${bannerWafSummary.evasionRecommendations.slice(0, 3).join("; ")}`,
                  data: {
                    detections: bannerWafSummary.detections.map((d) => ({
                      vendor: d.vendor,
                      product: d.product,
                      category: d.category,
                      port: d.port,
                      confidence: d.confidence,
                      matchedPattern: d.matchedPattern
                    })),
                    posture: bannerWafSummary.posture,
                    evasionProfile
                  }
                });
              }
            }
          }
        } catch (bannerWafErr) {
        }
        try {
          const { isRdpVoipConferencingPort, getScanCommandsForService, getServiceForPort, buildExploitContextForLlm } = await import("./rdp-voip-conferencing-knowledge-6KMZOJ66.js");
          const CONFERENCING_WEB_PORTS = /* @__PURE__ */ new Set([443, 8443]);
          const CONFERENCING_FINGERPRINTS = ["polycom", "telepresence", "zoom room", "crestron", "webex", "lifesize", "tandberg", "cisco meeting", "realpresence"];
          const rdpVoipPorts = discoveredPorts.filter((p) => {
            if (["rdp", "sip", "sips", "h323", "sccp", "mgcp", "ms-wbt-server"].includes(p.service)) return true;
            if (CONFERENCING_WEB_PORTS.has(p.port)) {
              const banner = (p.banner || "").toLowerCase();
              const product = (p.product || "").toLowerCase();
              const version = (p.version || "").toLowerCase();
              const combined = `${banner} ${product} ${version}`;
              return CONFERENCING_FINGERPRINTS.some((fp) => combined.includes(fp));
            }
            return isRdpVoipConferencingPort(p.port);
          });
          if (rdpVoipPorts.length > 0) {
            addLog(state, { phase: "enumeration", type: "info", title: `\u{1F50C} RDP/VoIP/Conferencing Services Detected: ${fmtTarget(asset, target)}`, detail: `Found ${rdpVoipPorts.length} RDP/VoIP/conferencing services: ${rdpVoipPorts.map((p) => `${p.port}/${p.service}`).join(", ")}` });
            for (const svcPort of rdpVoipPorts.slice(0, 5)) {
              const svcName = getServiceForPort(svcPort.port) || svcPort.service;
              const scanCmds = getScanCommandsForService(svcName, target, svcPort.port);
              for (const cmd of scanCmds.slice(0, 2)) {
                try {
                  const svcResult = await executeTool2({ tool: cmd.tool, args: cmd.command.replace(cmd.tool + " ", ""), timeoutSeconds: cmd.timeout, sudo: cmd.tool === "masscan" || cmd.tool === "naabu" });
                  if (svcResult.stdout) {
                    addLog(state, { phase: "enumeration", type: "scan_result", title: `${cmd.tool} ${svcName} scan: ${target}:${svcPort.port}`, detail: `${cmd.purpose}
${(svcResult.stdout || "").slice(0, 1e3)}` });
                  }
                } catch (svcErr) {
                }
              }
              if (!asset.rdpVoipContext) asset.rdpVoipContext = [];
              asset.rdpVoipContext.push({ port: svcPort.port, service: svcName, exploitContext: buildExploitContextForLlm({ service: svcName, target, port: svcPort.port }) });
            }
          }
        } catch (rdpVoipErr) {
        }
        const webPorts = discoveredPorts.filter(
          (p) => ["http", "https", "http-proxy", "http-alt", "ssl"].includes(p.service) || [80, 443, 8080, 8443, 8e3, 3e3, 5e3, 9443].includes(p.port)
        );
        const commonWebPorts = [80, 443, 8080, 8443];
        for (const wp of commonWebPorts) {
          if (!webPorts.find((p) => p.port === wp)) {
            webPorts.push({ port: wp, protocol: "tcp", service: wp === 443 || wp === 8443 ? "https" : "http" });
          }
        }
        if (webPorts.length > 0) {
          asset.type = "web_app";
          const httpxFlags = assetPlan?.httpxFlags || "-json -tech-detect -status-code -title -cdn -tls-grab -follow-redirects -content-length -web-server -silent";
          const httpxTargets = webPorts.map((p) => {
            const scheme = [443, 8443, 9443].includes(p.port) || p.service === "https" || p.service === "ssl" ? "https" : "http";
            return `${scheme}://${asset.hostname || target}:${p.port}`;
          });
          addLog(state, {
            phase: "enumeration",
            type: "scan_start",
            title: `\u{1F310} httpx: ${fmtTarget(asset, target)}`,
            detail: `Phase A Step 2 \u2014 HTTP probing ${webPorts.length} web ports
Targets: ${httpxTargets.join(", ")}
Flags: ${httpxFlags}`
          });
          try {
            const httpxStart = Date.now();
            const httpxInput = httpxTargets.join("\\n");
            const httpxArgs = `${httpxFlags}`;
            const httpxCmd = `echo -e '${httpxInput}' | httpx ${httpxArgs}`;
            addLog(state, { phase: "enumeration", type: "tool_exec", title: `httpx ${fmtTarget(asset, target)}`, detail: httpxCmd });
            const httpxResult = await executeRawCommandViaQueue(httpxCmd, 120, { engagementId: state.engagementId, engagementAbortSignal: engagementAbortSig });
            const httpxDuration = Date.now() - httpxStart;
            const httpxFindings = [];
            const techDetected = [];
            const cdnDetected = [];
            const responseHeaders = {};
            let webServer = "";
            let tlsInfo = "";
            const httpxLivePorts = [];
            if (httpxResult.stdout) {
              for (const line of httpxResult.stdout.split("\n")) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                try {
                  const obj = JSON.parse(trimmed);
                  if (obj.status_code && obj.port) {
                    httpxLivePorts.push({ port: obj.port, statusCode: obj.status_code, title: obj.title || "" });
                  } else if (obj.status_code && obj.url) {
                    try {
                      const parsedUrl = new URL(obj.url);
                      const portNum = parsedUrl.port ? parseInt(parsedUrl.port) : parsedUrl.protocol === "https:" ? 443 : 80;
                      httpxLivePorts.push({ port: portNum, statusCode: obj.status_code, title: obj.title || "" });
                    } catch {
                    }
                  }
                  if (obj.tech && Array.isArray(obj.tech)) {
                    for (const tech of obj.tech) {
                      if (!techDetected.includes(tech)) techDetected.push(tech);
                      httpxFindings.push({ severity: "info", title: `[httpx] Technology: ${tech}` });
                    }
                  }
                  if (obj.cdn_name) {
                    if (!cdnDetected.includes(obj.cdn_name)) cdnDetected.push(obj.cdn_name);
                    httpxFindings.push({ severity: "info", title: `[httpx] CDN/WAF: ${obj.cdn_name}` });
                  }
                  if (obj.cdn === true) {
                    httpxFindings.push({ severity: "info", title: `[httpx] CDN detected` });
                  }
                  if (obj.webserver) {
                    webServer = obj.webserver;
                    httpxFindings.push({ severity: "info", title: `[httpx] Web Server: ${obj.webserver}` });
                  }
                  if (obj.tls) {
                    const tls = obj.tls;
                    tlsInfo = `${tls.version || ""} ${tls.cipher || ""}`.trim();
                    if (tls.subject_cn) httpxFindings.push({ severity: "info", title: `[httpx] TLS CN: ${tls.subject_cn}` });
                    if (tls.subject_org) httpxFindings.push({ severity: "info", title: `[httpx] TLS Org: ${tls.subject_org}` });
                    if (tls.not_after) httpxFindings.push({ severity: "info", title: `[httpx] TLS Expires: ${tls.not_after}` });
                  }
                  if (obj.status_code) {
                    httpxFindings.push({ severity: "info", title: `[httpx] ${obj.url || obj.input}: ${obj.status_code} ${obj.title || ""}`.trim() });
                  }
                  if (obj.content_length !== void 0) {
                    httpxFindings.push({ severity: "info", title: `[httpx] Content-Length: ${obj.content_length}` });
                  }
                  const headers = obj.header || obj.response_header || {};
                  if (typeof headers === "object" && !Array.isArray(headers)) {
                    for (const [key, val] of Object.entries(headers)) {
                      const lk = key.toLowerCase();
                      const headerVal = Array.isArray(val) ? val[0] : String(val);
                      if (lk === "x-powered-by") {
                        responseHeaders["x-powered-by"] = headerVal;
                        httpxFindings.push({ severity: "info", title: `[httpx] X-Powered-By: ${headerVal}` });
                        if (!techDetected.includes(headerVal)) techDetected.push(headerVal);
                      }
                      if (lk === "x-aspnet-version" || lk === "x-aspnetmvc-version") {
                        responseHeaders[lk] = headerVal;
                        httpxFindings.push({ severity: "info", title: `[httpx] ${key}: ${headerVal}` });
                        if (!techDetected.includes(`ASP.NET ${headerVal}`)) techDetected.push(`ASP.NET ${headerVal}`);
                      }
                      if (lk === "x-generator") {
                        responseHeaders["x-generator"] = headerVal;
                        httpxFindings.push({ severity: "info", title: `[httpx] X-Generator: ${headerVal}` });
                        if (!techDetected.includes(headerVal)) techDetected.push(headerVal);
                      }
                      if (lk === "set-cookie") {
                        responseHeaders["set-cookie"] = headerVal;
                        if (headerVal.includes("PHPSESSID") && !techDetected.includes("PHP")) techDetected.push("PHP");
                        if (headerVal.includes("JSESSIONID") && !techDetected.includes("Java")) techDetected.push("Java");
                        if (headerVal.includes("ASP.NET_SessionId") && !techDetected.includes("ASP.NET")) techDetected.push("ASP.NET");
                        if (headerVal.includes("connect.sid") && !techDetected.includes("Node.js/Express")) techDetected.push("Node.js/Express");
                        if (headerVal.includes("laravel_session") && !techDetected.includes("Laravel/PHP")) techDetected.push("Laravel/PHP");
                        if (headerVal.includes("_rails") && !techDetected.includes("Ruby on Rails")) techDetected.push("Ruby on Rails");
                        if (headerVal.includes("csrftoken") && !techDetected.includes("Django/Python")) techDetected.push("Django/Python");
                        if (headerVal.includes("wp-settings") && !techDetected.includes("WordPress")) techDetected.push("WordPress");
                      }
                      if (lk === "server" && !webServer) {
                        responseHeaders["server"] = headerVal;
                      }
                    }
                  }
                  if (typeof headers === "string") {
                    const headerLines = headers.split("\n");
                    for (const hl of headerLines) {
                      const colonIdx = hl.indexOf(":");
                      if (colonIdx === -1) continue;
                      const hName = hl.substring(0, colonIdx).trim().toLowerCase();
                      const hVal = hl.substring(colonIdx + 1).trim();
                      if (hName === "x-powered-by") {
                        responseHeaders["x-powered-by"] = hVal;
                        if (!techDetected.includes(hVal)) techDetected.push(hVal);
                        httpxFindings.push({ severity: "info", title: `[httpx] X-Powered-By: ${hVal}` });
                      }
                      if (hName === "set-cookie") {
                        responseHeaders["set-cookie"] = hVal;
                        if (hVal.includes("PHPSESSID") && !techDetected.includes("PHP")) techDetected.push("PHP");
                        if (hVal.includes("JSESSIONID") && !techDetected.includes("Java")) techDetected.push("Java");
                        if (hVal.includes("ASP.NET_SessionId") && !techDetected.includes("ASP.NET")) techDetected.push("ASP.NET");
                      }
                    }
                  }
                } catch {
                }
              }
            }
            if (asset.passiveRecon) {
              if (techDetected.length > 0) {
                asset.passiveRecon.technologies = [.../* @__PURE__ */ new Set([...asset.passiveRecon.technologies || [], ...techDetected])];
              }
              if (cdnDetected.length > 0) {
                asset.passiveRecon.riskSignals = [...asset.passiveRecon.riskSignals || [], ...cdnDetected.map((c) => ({ severity: "low", type: "cdn_waf", rationale: `CDN/WAF detected: ${c}` }))];
              }
              if (webServer) {
                asset.passiveRecon.technologies = [.../* @__PURE__ */ new Set([...asset.passiveRecon.technologies || [], webServer])];
              }
              if (Object.keys(responseHeaders).length > 0) {
                asset.httpxResponseHeaders = { ...asset.httpxResponseHeaders, ...responseHeaders };
              }
              if (httpxLivePorts.length > 0) {
                asset.httpxLivePorts = httpxLivePorts;
              }
            }
            asset.toolResults.push({
              tool: "httpx",
              command: httpxCmd,
              exitCode: httpxResult.exitCode ?? 0,
              durationMs: httpxDuration,
              timedOut: httpxResult.timedOut || false,
              findingCount: httpxFindings.length,
              findings: httpxFindings,
              outputPreview: (httpxResult.stdout || "").slice(0, 1024),
              rawOutput: (httpxResult.stdout || "").slice(0, 5e4),
              executedAt: Date.now(),
              phase: "discovery",
              fingerprints: {
                webServer: webServer || void 0,
                technologies: techDetected.length > 0 ? techDetected : void 0,
                httpHeaders: Object.keys(responseHeaders).length > 0 ? responseHeaders : void 0,
                tlsInfo: tlsInfo ? {
                  subjectCN: tlsInfo.subject_cn,
                  issuerOrg: tlsInfo.issuer_org,
                  notAfter: tlsInfo.not_after
                } : void 0,
                poweredBy: responseHeaders["x-powered-by"] || void 0,
                cookies: responseHeaders["set-cookie"] ? [responseHeaders["set-cookie"]] : void 0
              }
            });
            await persistScanResult({
              engagementId: state.engagementId,
              tool: "httpx",
              target,
              command: httpxCmd,
              stdout: httpxResult.stdout || "",
              stderr: httpxResult.stderr || "",
              exitCode: httpxResult.exitCode ?? 0,
              durationMs: httpxDuration,
              timedOut: httpxResult.timedOut || false,
              findings: httpxFindings,
              phase: "discovery"
            });
            addLog(state, {
              phase: "enumeration",
              type: "scan_result",
              title: `httpx Complete: ${fmtTarget(asset, target)}`,
              detail: `${httpxFindings.length} findings in ${Math.round(httpxDuration / 1e3)}s${techDetected.length > 0 ? `
Tech: ${techDetected.join(", ")}` : ""}${cdnDetected.length > 0 ? `
CDN/WAF: ${cdnDetected.join(", ")}` : ""}${webServer ? `
Server: ${webServer}` : ""}`,
              data: { tech: techDetected, cdn: cdnDetected, webServer, tls: tlsInfo }
            });
          } catch (e) {
            addLog(state, { phase: "enumeration", type: "error", title: `httpx Failed: ${fmtTarget(asset, target)}`, detail: e.message });
          }
        }
        if (asset.ports.length === 0 && webPorts.length > 0) {
          const httpxToolResult = asset.toolResults.find((tr) => tr.tool === "httpx");
          const confirmedPorts = [];
          if (httpxToolResult?.outputPreview) {
            for (const line of httpxToolResult.outputPreview.split("\n")) {
              try {
                const obj = JSON.parse(line.trim());
                if (obj.status_code && obj.port) {
                  const svc = obj.scheme === "https" ? "https" : "http";
                  if (!confirmedPorts.find((p) => p.port === obj.port)) {
                    confirmedPorts.push({
                      port: obj.port,
                      service: svc,
                      version: obj.webserver || void 0
                    });
                  }
                }
              } catch {
              }
            }
          }
          if (confirmedPorts.length === 0) {
            const httpxFindingCount = httpxToolResult?.findingCount || 0;
            if (httpxFindingCount > 0) {
              confirmedPorts.push({ port: 80, service: "http" });
              confirmedPorts.push({ port: 443, service: "https" });
            }
          }
          if (confirmedPorts.length > 0) {
            asset.ports = confirmedPorts;
            asset.type = "web_app";
            state.stats.portsFound += confirmedPorts.length;
            addLog(state, {
              phase: "enumeration",
              type: "info",
              title: `\u{1F310} httpx Port Backfill: ${fmtTarget(asset, target)}`,
              detail: `ScanForge found 0 open ports (cloud firewall), but httpx confirmed ${confirmedPorts.length} live web services: ${confirmedPorts.map((p) => `${p.port}/${p.service}`).join(", ")}. Pipeline will continue with httpx-discovered ports.`
            });
          }
        }
        addLog(state, {
          phase: "enumeration",
          type: "scan_result",
          title: `\u2705 Discovery Complete: ${fmtTarget(asset, target)}`,
          detail: `ScanForge: ${discoveredPorts.length} services | httpx: ${webPorts.length > 0 ? "probed" : "skipped (no web ports)"} | Final ports: ${asset.ports.length}`
        });
      }
    } catch (e) {
      addLog(state, { phase: "enumeration", type: "error", title: "Discovery Scan Error", detail: e.message });
    }
  }
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
  try {
    const { detectCloudAsset, executeCloudStorageScan, getCloudDetectionPromptContext } = await import("./cloud-storage-scanner-LBZRDQJJ.js");
    addLog(state, {
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
        asset.cloudProviders = detection.providers;
        asset.cloudServices = detection.signatures.map((s) => `${s.provider}:${s.service}`);
        addLog(state, {
          phase: "enumeration",
          type: "finding",
          title: `\u2601\uFE0F Cloud Asset: ${asset.hostname}`,
          detail: `Providers: ${detection.providers.join(", ")}
Services: ${detection.signatures.map((s) => `${s.provider} ${s.service} (${s.confidence})`).join(", ")}
Storage endpoints: ${detection.storageEndpoints.length}`,
          data: { cloudDetection: detection }
        });
        if (detection.storageEndpoints.length > 0 || detection.scanSuggestions.length > 0) {
          cloudStorageEndpoints += detection.storageEndpoints.length;
          addLog(state, {
            phase: "enumeration",
            type: "scan_start",
            title: `\u2601\uFE0F Cloud Storage Scan: ${asset.hostname}`,
            detail: `Running ${detection.scanSuggestions.length} cloud-specific scans (${detection.storageEndpoints.join(", ")})`
          });
          try {
            const scanResult = await executeCloudStorageScan(
              asset.hostname,
              detection.scanSuggestions,
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
              addLog(state, {
                phase: "enumeration",
                type: "scan_result",
                title: `Cloud Scan Result: ${raw.tool}`,
                detail: `Exit: ${raw.exitCode} | Duration: ${Math.round(raw.durationMs / 1e3)}s
${raw.stdout.slice(0, 500)}`,
                data: raw
              });
            }
          } catch (cloudScanErr) {
            addLog(state, {
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
    addLog(state, {
      phase: "enumeration",
      type: cloudAssetsFound > 0 ? "phase_complete" : "info",
      title: cloudAssetsFound > 0 ? `\u2601\uFE0F Cloud Detection Complete \u2014 ${cloudAssetsFound} cloud assets, ${cloudFindings.length} findings` : "\u2601\uFE0F Cloud Detection \u2014 No cloud assets detected",
      detail: cloudAssetsFound > 0 ? `Providers: ${[...new Set(cloudFindings.map((f) => f.provider))].join(", ")}
Findings: ${JSON.stringify(severity_counts)}
Storage endpoints scanned: ${cloudStorageEndpoints}` : "No cloud-hosted infrastructure identified in discovery results. Proceeding to Phase B."
    });
  } catch (cloudDetectErr) {
    console.error("[CloudDetection] Error:", cloudDetectErr.message);
    addLog(state, {
      phase: "enumeration",
      type: "warning",
      title: "\u26A0\uFE0F Cloud Detection Skipped",
      detail: `Cloud asset detection encountered an error: ${cloudDetectErr.message}. Proceeding to Phase B.`
    });
  }
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
    addLog(state, {
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
          webServerParsed = {
            name: wsMatch?.[1] || webServerStr,
            version: wsMatch?.[2] || null,
            role: "unknown"
          };
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
        for (const p of asset.ports) {
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
          // OS detection requires deeper probing
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
        const openPorts = asset.ports.map((p) => p.port);
        const roleResult = classifyAssetRole(fingerprint, openPorts, responseHeaders);
        const topologyNode = {
          host: asset.hostname,
          role: roleResult.role,
          confidence: roleResult.confidence,
          backend: null,
          services: asset.ports.map((p) => ({ port: p.port, service: p.service, version: p.version || null })),
          directlyReachable: true
        };
        const cloudProviders = asset.cloudProviders || [];
        const environment = cloudProviders.length > 0 ? "cloud" : technologies.some((t) => /docker|kubernetes|k8s|container/i.test(t)) ? "containerized" : technologies.some((t) => /lambda|serverless|cloud.function/i.test(t)) ? "serverless" : "traditional";
        const riskProfile = wafProfile.detected && cdnProfile.detected ? "high_security" : wafProfile.detected || cdnProfile.detected ? "standard" : asset.ports.length > 20 ? "legacy" : "standard";
        const scopeConstraints = { ...baseScopeConstraints };
        if (cdnProfile.detected) scopeConstraints.sharedInfrastructure = true;
        if (wafProfile.detected) scopeConstraints.wafBypassAuthorized = scopeEngType === "pentest" || scopeEngType === "red_team";
        const partialProfile = {
          hostname: asset.hostname,
          ips: asset.ip ? [asset.ip] : [],
          fingerprint,
          waf: wafProfile,
          cdn: cdnProfile,
          firewall: { detected: false, type: "unknown", filteredPorts: [], rateLimiting: { detected: false, requestsPerSecond: null, burstLimit: null }, geoBlocking: false, ipReputationBlocking: false },
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
  addLog(state, {
    phase: "enumeration",
    type: "info",
    title: "\u{1F3AF} Phase B: Targeted Tool Deployment",
    detail: "Running targeted ScanForge discovery scripts and specialized tools per asset based on combined passive recon + discovery data"
  });
  const hasScanPlan = !!state.scanPlan?.assetPlans?.length;
  const { suggestToolCommands } = await import("./scan-server-executor-RYJD5OAQ.js");
  const roeScope_B = [...state.roeScopeGuard?.authorizedDomains || [], ...state.roeScopeGuard?.authorizedIps || []];
  const engagementAbortSig_B = getEngagementAbortSignal(state.engagementId);
  const executeTool = (config) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope: roeScope_B, engagementAbortSignal: engagementAbortSig_B });
  for (const asset of state.assets) {
    if (asset.ports.length === 0) continue;
    if (!isInRoeScope(state, asset.hostname, asset.ip)) {
      addLog(state, { phase: "enumeration", type: "warning", title: `\u{1F6E1}\uFE0F Skipped: ${asset.hostname} (out of scope)`, detail: "Asset not in RoE authorized target list" });
      continue;
    }
    const webPorts = asset.ports.filter(
      (p) => ["http", "https", "http-proxy", "http-alt"].includes(p.service) || [80, 443, 8080, 8443, 8e3, 3e3, 5e3].includes(p.port)
    );
    if (webPorts.length > 0) asset.type = "web_app";
    const target = getEffectiveTarget(asset, "discovery");
    const httpTarget = getEffectiveTarget(asset, "http");
    const assetPlan = state.scanPlan?.assetPlans.find(
      (ap) => ap.hostname === asset.hostname || ap.ip === target
    );
    const { autoSelectTool: autoSelectToolB } = await import("./scanforge-discovery-E3DYLR5A.js");
    const sfTool = autoSelectToolB({ targets: [target], stealthLevel: assetPlan?.evasionTechniques?.length ? "medium" : "minimal" });
    if (assetPlan?.discoveryFlags) {
      const discoveredPortList = asset.ports.map((p) => p.port).join(",");
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
        const discoveryResult = await executeTool({ tool: sfTool || "naabu", args: discoveryArgs, timeoutSeconds: 300, sudo: true });
        const durationMs = Date.now() - startTime;
        const findings = parseToolOutput("scanforge-discovery", discoveryResult.stdout || "", asset);
        asset.toolResults.push({
          tool: sfTool || "naabu",
          command: `${sfTool} ${discoveryArgs}`,
          exitCode: discoveryResult.exitCode ?? 0,
          durationMs,
          timedOut: discoveryResult.timedOut || false,
          findingCount: findings.length,
          findings: findings.map((f) => ({ severity: f.severity, title: f.title, cve: f.cve, evidence: f.evidence?.proofText || void 0, attack: f.evidence?.attackPayload || void 0, method: f.evidence?.request?.method || void 0, url: f.evidence?.request?.url || void 0, param: f.evidence?.vulnerableParam || void 0, matchedPattern: f.evidence?.matchedPattern || void 0 })),
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
        await persistScanResult({
          engagementId: state.engagementId,
          tool: sfTool || "naabu",
          target,
          command: `${sfTool} ${discoveryArgs}`,
          stdout: discoveryResult.stdout || "",
          stderr: discoveryResult.stderr || "",
          exitCode: discoveryResult.exitCode ?? 0,
          durationMs,
          timedOut: discoveryResult.timedOut || false,
          findings,
          phase: "targeted_enum"
        });
        for (const f of findings) {
          if (pushVulnDeduped(asset, { id: genId(), severity: f.severity, title: f.title, cve: f.cve, description: f.description, cvss: f.cvss, cwe: f.cwe, corroborationTier: "confirmed", evidenceDetail: `Confirmed by active scan tool output`, rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4e3) : void 0, source: "active_scan" })) {
            state.stats.vulnsFound++;
          }
        }
      } catch (e) {
        addLog(state, { phase: "enumeration", type: "error", title: `Targeted ScanForge Failed: ${fmtTarget(asset, target)}`, detail: e.message });
      }
    }
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
          commands: cmdsToRun.map((c) => ({ tool: c.tool, purpose: c.purpose, priority: c.priority })),
          ports: asset.ports.map((p) => `${p.port}/${p.service}`),
          assetType: asset.type,
          riskNotes: assetPlan.riskNotes
        }
      });
    } else {
      const suggestedCmds = await suggestToolCommands({
        hostname: asset.hostname,
        ip: asset.ip,
        type: asset.type,
        ports: asset.ports
      });
      cmdsToRun = suggestedCmds.map((c) => ({
        tool: c.tool,
        command: `${c.tool} ${c.args}`,
        purpose: c.purpose,
        priority: c.priority
      }));
      const toolNames = [...new Set(cmdsToRun.map((c) => c.tool))];
      addLog(state, {
        phase: "enumeration",
        type: "tool_match",
        title: `Tool Match: ${fmtTarget(asset)}`,
        detail: `${cmdsToRun.length} commands queued using ${toolNames.length} tools: ${toolNames.join(", ")}`,
        data: {
          source: "auto_suggest",
          tools: toolNames,
          commands: cmdsToRun.map((c) => ({ tool: c.tool, purpose: c.purpose, priority: c.priority })),
          ports: asset.ports.map((p) => `${p.port}/${p.service}`),
          assetType: asset.type
        }
      });
    }
    const targetProfile = state.targetProfiles?.[asset.hostname];
    if (targetProfile?.recommendedStrategy) {
      const existingTools = new Set(cmdsToRun.map((c) => c.tool));
      const strategyPhases = targetProfile.recommendedStrategy.phases;
      let augmentedCount = 0;
      for (const phase of strategyPhases) {
        for (const tool of phase.tools) {
          if (!existingTools.has(tool.tool)) {
            const resolvedFlags = tool.flags.replace(/HOST|TARGET/g, httpTarget).replace(/DISCOVERED_PORTS/g, asset.ports.map((p) => p.port).join(",")).replace(/TARGET_URL/g, `https://${asset.hostname}`).replace(/TARGET:PORT/g, `${asset.hostname}:443`);
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
    }
    const isScoped = state.assets.length > 0;
    const highPriorityCmds = cmdsToRun.filter((c) => c.priority <= 2).filter((c) => {
      if (c.tool === "subfinder" && isScoped) {
        addLog(state, {
          phase: "enumeration",
          type: "info",
          title: `Skipped: subfinder (scoped engagement)`,
          detail: `Subfinder skipped \u2014 targets are already defined in scope. Subfinder is only used for domain intelligence / unscoped discovery.`
        });
        return false;
      }
      return true;
    });
    for (const cmd of highPriorityCmds) {
      if (cmd.tool === "nuclei") {
        let nucleiCmd = cmd.command;
        nucleiCmd = nucleiCmd.replace(/\bnuclei\b/g, "").trim();
        const targetMatch = nucleiCmd.match(/-(?:target|u)\s+(\S+)/) || nucleiCmd.match(/(https?:\/\/\S+)/);
        let nucleiTarget = targetMatch?.[1] || httpTarget;
        if (nucleiTarget && !nucleiTarget.startsWith("http")) {
          const webPorts2 = asset.ports.filter(
            (p) => ["http", "https", "http-proxy", "http-alt"].includes(p.service) || [80, 443, 8080, 8443, 8e3, 3e3, 5e3].includes(p.port)
          );
          if (webPorts2.length > 0) {
            const scheme = webPorts2[0].port === 443 || webPorts2[0].port === 8443 ? "https" : "http";
            nucleiTarget = `${scheme}://${nucleiTarget}:${webPorts2[0].port}`;
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
      if (cmd.tool === "httpx") {
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
      if (cmd.tool === "gobuster") {
        const gobUrlMatch = cmd.command.match(/-u\s+(\S+)/) || cmd.command.match(/(https?:\/\/\S+)/);
        const gobTargetUrl = gobUrlMatch?.[1] || httpTarget;
        const wafDetected = !!(asset.wafDetected && asset.wafDetected !== "none");
        const detectedTech = asset.passiveRecon?.technologies || [];
        const isApiTarget = asset.type === "api" || asset.ports.some((p) => /api|graphql|rest/i.test(p.service || "")) || /\/api\/|\/v[0-9]+\//i.test(gobTargetUrl);
        let authCookie = "";
        const webCreds = (asset.confirmedCredentials || []).filter(
          (c) => ["http", "web", "form", "http-get", "http-post-form"].includes(c.service)
        );
        if (webCreds.length > 0 && webCreds[0].sessionCookie) {
          authCookie = webCreds[0].sessionCookie;
        } else if (asset.trainingLabCreds?.sessionCookie) {
          authCookie = asset.trainingLabCreds.sessionCookie;
        }
        if (!authCookie && state.trainingLabMode) {
          const hostname = asset.hostname.toLowerCase();
          const GOBUSTER_LAB_CREDS = {
            "dvwa": { username: "admin", password: "password", loginPath: "/login.php", authType: "form-csrf" },
            "bwapp": { username: "bee", password: "bug", loginPath: "/login.php", authType: "form-simple" },
            "juiceshop": { username: "admin@juice-sh.op", password: "admin123", loginPath: "/rest/user/login", authType: "json-jwt" },
            "juice-shop": { username: "admin@juice-sh.op", password: "admin123", loginPath: "/rest/user/login", authType: "json-jwt" },
            "webgoat": { username: "guest", password: "guest", loginPath: "/WebGoat/login", authType: "form-simple" },
            "hackazon": { username: "test_user", password: "test_user", loginPath: "/user/login", authType: "form-simple" },
            "mutillidae": { username: "admin", password: "admin", loginPath: "/index.php?page=login.php", authType: "form-simple" },
            "bodgeit": { username: "test@test.com", password: "test", loginPath: "/bodgeit/login.jsp", authType: "form-simple" },
            "broken-crystals": { username: "john@mail.com", password: "Admin123!", loginPath: "/api/auth/login", authType: "json-jwt" },
            "brokencrystals": { username: "john@mail.com", password: "Admin123!", loginPath: "/api/auth/login", authType: "json-jwt" }
          };
          let matchedLab;
          for (const [labKey, creds] of Object.entries(GOBUSTER_LAB_CREDS)) {
            if (hostname.includes(labKey.replace("-", ""))) {
              matchedLab = { key: labKey, creds };
              break;
            }
          }
          if (matchedLab) {
            try {
              const { executeTool: executeTool2 } = await import("./scan-server-executor-RYJD5OAQ.js");
              const authBaseUrl = gobTargetUrl.replace(/\/[^/]*$/, "") || `http://${asset.hostname}`;
              if (matchedLab.creds.authType === "json-jwt") {
                const loginResult = await executeTool2({
                  tool: "curl",
                  args: `-s -X POST ${authBaseUrl}${matchedLab.creds.loginPath} -H "Content-Type: application/json" -d '{"email":"${matchedLab.creds.username}","password":"${matchedLab.creds.password}"}'`,
                  timeout: 15
                });
                if (loginResult.stdout) {
                  try {
                    const resp = JSON.parse(loginResult.stdout);
                    const token = resp.authentication?.token || resp.token || resp.access_token;
                    if (token) {
                      authCookie = `token=${token}`;
                      asset.trainingLabCreds = { ...matchedLab.creds, sessionCookie: authCookie };
                      addLog(state, {
                        phase: "enumeration",
                        type: "info",
                        title: `\u{1F511} Gobuster Auto-Auth: JWT acquired for ${matchedLab.key}`,
                        detail: `Logged in as ${matchedLab.creds.username} via ${matchedLab.creds.loginPath}. Gobuster will scan authenticated paths.`
                      });
                    }
                  } catch {
                  }
                }
              } else if (matchedLab.creds.authType === "form-csrf") {
                const getLogin = await executeTool2({
                  tool: "curl",
                  args: `-s -c /tmp/gobuster_auth_cookies.txt -b /tmp/gobuster_auth_cookies.txt ${authBaseUrl}${matchedLab.creds.loginPath}`,
                  timeout: 15
                });
                const csrfMatch = getLogin.stdout?.match(/user_token.*?value=['"]([^'"]+)['"]/i);
                const csrfToken = csrfMatch?.[1] || "";
                const postLogin = await executeTool2({
                  tool: "curl",
                  args: `-s -c /tmp/gobuster_auth_cookies.txt -b /tmp/gobuster_auth_cookies.txt -X POST ${authBaseUrl}${matchedLab.creds.loginPath} -d "username=${matchedLab.creds.username}&password=${matchedLab.creds.password}&Login=Login&user_token=${csrfToken}" -D -`,
                  timeout: 15
                });
                const sessionMatch = postLogin.stdout?.match(/PHPSESSID=([^;\s]+)/i);
                if (sessionMatch?.[1]) {
                  authCookie = `PHPSESSID=${sessionMatch[1]}; security=low`;
                  asset.trainingLabCreds = { ...matchedLab.creds, sessionCookie: authCookie };
                  addLog(state, {
                    phase: "enumeration",
                    type: "info",
                    title: `\u{1F511} Gobuster Auto-Auth: DVWA session acquired`,
                    detail: `Logged in as ${matchedLab.creds.username} with CSRF token handling. Gobuster will scan behind login wall.`
                  });
                }
              } else {
                const loginResult = await executeTool2({
                  tool: "curl",
                  args: `-s -X POST ${authBaseUrl}${matchedLab.creds.loginPath} -d "username=${matchedLab.creds.username}&password=${matchedLab.creds.password}" -D -`,
                  timeout: 15
                });
                const setCookie = loginResult.stdout?.match(/Set-Cookie:\s*([^\n]+)/i);
                if (setCookie?.[1]) {
                  authCookie = setCookie[1].split(";")[0].trim();
                  asset.trainingLabCreds = { ...matchedLab.creds, sessionCookie: authCookie };
                  addLog(state, {
                    phase: "enumeration",
                    type: "info",
                    title: `\u{1F511} Gobuster Auto-Auth: Session acquired for ${matchedLab.key}`,
                    detail: `Logged in as ${matchedLab.creds.username}. Gobuster will scan authenticated paths.`
                  });
                }
              }
            } catch (authErr) {
              addLog(state, {
                phase: "enumeration",
                type: "warning",
                title: `Gobuster Auto-Auth Failed: ${matchedLab.key}`,
                detail: `Could not acquire session cookie for authenticated Gobuster scan: ${authErr.message}. Continuing unauthenticated.`
              });
            }
          }
        }
        const profile = getScanProfile(state.scanProfile || "standard");
        cmd.command = buildGobusterCommand(profile, gobTargetUrl, {
          wafDetected,
          authCookie: authCookie || void 0,
          detectedTech,
          isApiTarget
        });
      }
      if (cmd.tool === "nikto") {
        const niktoUrlMatch = cmd.command.match(/-h\s+(https?:\/\/\S+)/);
        if (niktoUrlMatch) {
          const niktoUrl = niktoUrlMatch[1];
          const isNiktoHttps = niktoUrl.startsWith("https://") || /:(443|8443|8444|8445|8447|9443)\b/.test(niktoUrl);
          if (isNiktoHttps && !cmd.command.includes("-ssl")) {
            cmd.command = cmd.command.replace(/-h\s+\S+/, `$& -ssl`);
          }
        }
        if (!cmd.command.includes("-vhost") && asset.hostname && asset.ip && asset.hostname !== asset.ip) {
          if (KNOWN_INFRA_IPS.has(asset.ip)) {
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
            addLog(state, {
              phase: "enumeration",
              type: "info",
              title: `\u{1F510} Nikto Auth: Session cookie injected for ${asset.hostname}`,
              detail: `Nikto will scan authenticated paths using the session acquired during auto-auth.`
            });
          }
        }
        cmd.command = cmd.command.replace(/\s+/g, " ").trim();
      }
    }
    if (state.targetProfiles) {
      const targetProfile2 = state.targetProfiles[asset.hostname];
      if (targetProfile2) {
        const { augmentCommandWithEvasion } = await import("./evasion-cli-adapter-OVRHDAK4.js");
        for (const cmd of highPriorityCmds) {
          const augmentation = augmentCommandWithEvasion(cmd.tool, cmd.command, targetProfile2);
          if (augmentation.flagsAdded.length > 0) {
            cmd.command = augmentation.augmentedCommand;
          }
        }
        const escalation = targetProfile2.evasionEscalation;
        if (escalation && escalation.currentLevel > 1) {
          addLog(state, {
            phase: "enumeration",
            type: "info",
            title: `\u{1F6E1}\uFE0F Evasion flags applied: ${fmtTarget(asset)}`,
            detail: `Level ${escalation.currentLevel}: Rate limits, headers, and timing adjusted for ${highPriorityCmds.length} tools`
          });
        }
      }
    }
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
        result = await executeRawCommandViaQueue(rawCmd + " 2>&1", toolTimeout, { engagementId: state.engagementId });
        result.durationMs = Date.now() - startTimeRaw;
      } else {
        const cmdArgs = cmd.command.startsWith(cmd.tool) ? cmd.command.slice(cmd.tool.length).trim() : cmd.command;
        const startTime = Date.now();
        result = await executeTool({
          tool: cmd.tool,
          args: cmdArgs,
          timeoutSeconds: toolTimeout,
          engagementId: state.engagementId
        });
        if (!result.durationMs) result.durationMs = Date.now() - startTime;
      }
      if (result.stdout.length > 1e5) {
        result.stdout = result.stdout.slice(0, 1e5);
      }
      if (result.stderr && result.stderr.length > 5e4) {
        result.stderr = result.stderr.slice(0, 5e4);
      }
      const findings = parseToolOutput(cmd.tool, result.stdout, asset);
      asset.toolResults.push({
        tool: cmd.tool,
        command: cmd.command,
        exitCode: result.exitCode,
        durationMs: result.durationMs,
        timedOut: result.timedOut,
        findingCount: findings.length,
        findings: findings.map((f) => ({ severity: f.severity, title: f.title, cve: f.cve, evidence: f.evidence?.proofText || void 0, attack: f.evidence?.attackPayload || void 0, method: f.evidence?.request?.method || void 0, url: f.evidence?.request?.url || void 0, param: f.evidence?.vulnerableParam || void 0, matchedPattern: f.evidence?.matchedPattern || void 0 })),
        outputPreview: result.stdout.slice(0, 512),
        executedAt: Date.now(),
        phase: "targeted_enum"
      });
      addLog(state, {
        phase: "enumeration",
        type: "scan_result",
        title: `${cmd.tool} Complete: ${fmtTarget(asset)}`,
        detail: `Exit code ${result.exitCode}, ${result.durationMs}ms, ${findings.length} findings${result.timedOut ? " (TIMED OUT)" : ""}`,
        data: {
          tool: cmd.tool,
          exitCode: result.exitCode,
          durationMs: result.durationMs,
          findings,
          outputPreview: result.stdout.slice(0, 500)
        }
      });
      await persistScanResult({
        engagementId: state.engagementId,
        tool: cmd.tool,
        target: asset.hostname || asset.ip,
        command: cmd.command,
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.exitCode,
        durationMs: result.durationMs,
        timedOut: result.timedOut,
        findings,
        phase: "targeted_enum"
      });
      let newCount = 0;
      for (const f of findings) {
        if (pushVulnDeduped(asset, { id: genId(), severity: f.severity, title: f.title, cve: f.cve, description: f.description, cvss: f.cvss, cwe: f.cwe, corroborationTier: "confirmed", evidenceDetail: `Confirmed by ${cmd.tool} active scan`, rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4e3) : void 0, source: cmd.tool })) {
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
        batch.map((cmd) => executeToolCmd(cmd).catch((e) => {
          addLog(state, { phase: "enumeration", type: "error", title: `${cmd.tool} Error`, detail: e.message });
          return null;
        }))
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
      const enumBatchMem = process.memoryUsage();
      const enumBatchHeapMB = enumBatchMem.heapUsed / 1024 / 1024;
      const enumHeapLimit = global.__heapLimitMB || 768;
      if (enumBatchHeapMB > enumHeapLimit * 0.6) {
        console.warn(`[MemoryBackpressure] Enum batch: heap at ${enumBatchHeapMB.toFixed(0)}MB/${enumHeapLimit}MB \u2014 pausing 2s`);
        await new Promise((r) => setTimeout(r, 2e3));
        if (global.gc) global.gc();
      }
      if (failed > 0 && state.targetProfiles) {
        try {
          const { escalateEvasionProfile: evaluateAndEscalate } = await import("./evasion-escalation-engine-IZY7LIBH.js");
          const profile = state.targetProfiles[asset.hostname];
          if (profile) {
            const recentResults = asset.toolResults.slice(-batch.length);
            for (const tr of recentResults) {
              const output = tr.outputPreview || "";
              const isBlocked = tr.exitCode !== 0 || tr.timedOut || /403|blocked|captcha|rate.limit|connection.reset|ip.ban/i.test(output);
              if (isBlocked) {
                const blockReason = tr.timedOut ? "rate_limit" : /403|blocked|waf/i.test(output) ? "waf_block" : /captcha/i.test(output) ? "captcha" : /rate.limit/i.test(output) ? "rate_limit" : /connection.reset|rst/i.test(output) ? "connection_reset" : /ban/i.test(output) ? "ip_ban" : "waf_block";
                const escalationResult = evaluateAndEscalate(profile, blockReason, { toolOutput: output });
                if (escalationResult.escalation.currentLevel > (profile.evasionEscalation?.currentLevel || 1)) {
                  state.targetProfiles[asset.hostname] = { ...profile, evasionEscalation: escalationResult.escalation };
                  addLog(state, {
                    phase: "enumeration",
                    type: "warning",
                    title: `\u26A1 Evasion auto-escalated: ${asset.hostname}`,
                    detail: `Level ${escalationResult.escalation.currentLevel}: ${escalationResult.escalation.action} (trigger: ${blockReason})`,
                    riskTier: "yellow"
                  });
                  break;
                }
              }
            }
          }
        } catch (_e) {
        }
      }
    }
    const parallelDuration = Date.now() - parallelStartTime;
    addLog(state, {
      phase: "enumeration",
      type: "info",
      title: `\u26A1 Parallel execution complete: ${fmtTarget(asset)}`,
      detail: `${highPriorityCmds.length} tools finished in ${Math.round(parallelDuration / 1e3)}s (parallel batches of ${CONCURRENCY_LIMIT})`
    });
    persistOpsStateDebounced(state.engagementId, 500);
  }
  state.progress = 35;
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
}
var init_engagement_phase_enumeration = __esm({
  "server/lib/engagement-phase-enumeration.ts"() {
    init_orchestrator_types();
    init_engagement_orchestrator();
    init_tool_output_parsers();
  }
});
init_engagement_phase_enumeration();
export {
  executeEnumeration
};
