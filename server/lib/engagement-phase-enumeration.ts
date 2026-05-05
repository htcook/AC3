/**
 * Phase 5: Active Discovery & Enumeration
 *
 * Extracted from engagement-orchestrator.ts for maintainability.
 * This module handles the active enumeration phase:
 * - ScanForge discovery scans with evasion profiles
 * - Service fingerprinting and diff detection
 * - Cloud asset detection and storage scanning
 * - Context-aware tool selection and deployment
 * - Banner/WAF detection and evasion adaptation
 * - RDP/VoIP/Conferencing service enumeration
 * - DNS enumeration and zone transfer attempts
 * - PCAP auto-capture for network analysis
 */

// ─── Types from shared module (breaks circular import) ──────────────────────
import { type EngagementOpsState, isInRoeScope, fmtTarget } from "../../shared/orchestrator-types";
// ─── Runtime helpers from orchestrator ──────────────────────────────────────
import {
  addLog,
  broadcastOpsUpdate,
  getEffectiveTarget,
} from "./engagement-orchestrator";
// ─── Tool output parsing (already extracted) ────────────────────────────────
import { parseToolOutput } from "./tool-output-parsers";

// ─── Local utility ──────────────────────────────────────────────────────────
function genId(): string {
  return Math.random().toString(36).substring(2, 10);
}

export async function executeEnumeration(state: EngagementOpsState, engagement: any, operatorCtx: { id: string; name?: string }) {
  state.phase = "enumeration";
  state.currentAction = "Running enumeration & fingerprinting...";
  addLog(state, { phase: "enumeration", type: "info", title: "🔎 Phase 5: Active Discovery & Enumeration", detail: "Two-phase approach: Phase A discovery ScanForge discovery with evasion → Phase B targeted tool deployment" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "enumeration" });

  // ═══ RoE SCOPE GUARD: Filter active scan targets to only authorized assets ═══
  const scopedAssets = state.assets.filter(a => isInRoeScope(state, a.hostname, a.ip));
  const skippedAssets = state.assets.filter(a => !isInRoeScope(state, a.hostname, a.ip));
  if (skippedAssets.length > 0) {
    addLog(state, {
      phase: "enumeration", type: "warning",
      title: `🛡️ Scope Guard: ${skippedAssets.length} assets excluded from active scanning`,
      detail: `Excluded: ${skippedAssets.map(a => a.hostname).join(", ")}\nOnly RoE-authorized targets will be actively probed.`,
    });
  }
  // ═══ DNS PRE-RESOLUTION: Resolve hostnames to IPs before ScanForge discovery ═══
  // ScanForge on the scan server may fail to resolve hostnames (e.g., training labs
  // hosted via path-based routing on scan.aceofcloud.io). Pre-resolve here and
  // fall back to scan server IP for known self-hosted labs.
  const dns = await import('dns');
  const { promisify } = await import('util');
  const dnsResolve4 = promisify(dns.resolve4);
  const scanServerHost = process.env.SCAN_SERVER_HOST || '';
  const SCAN_SERVER_DOMAIN = 'scan.aceofcloud.io';

  addLog(state, { phase: 'enumeration', type: 'info', title: `DNS Pre-Resolution: checking ${scopedAssets.length} assets`, detail: `Resolving hostnames to IPs before ScanForge scan` });
  for (const asset of scopedAssets) {
    if (asset.ip) continue; // Already has an IP
    const hostname = asset.hostname;
    try {
      const ips = await dnsResolve4(hostname);
      if (ips.length > 0) {
        asset.ip = ips[0];
        addLog(state, { phase: 'enumeration', type: 'info', title: `DNS Resolved: ${hostname}`, detail: `${hostname} → ${ips[0]}` });
      }
    } catch (_dnsErr: any) {
      // DNS failed — check if this is a training lab hosted on the scan server
      // Detection heuristics: engagement type, liveInstanceUrl, hostname pattern, or scan server domain match
      const knownLabSubdomains = ['dvwa', 'juice-shop', 'juiceshop', 'webgoat', 'bwapp', 'mutillidae', 'vampi', 'crapi', 'hackazon'];
      const hostnameBase = hostname.split('.')[0]?.toLowerCase() || '';
      const isLabOnScanServer = state.engagementType === 'training_lab' ||
        (asset.passiveRecon as any)?.liveInstanceUrl?.includes(SCAN_SERVER_DOMAIN) ||
        (asset.passiveRecon as any)?.liveInstanceUrl?.includes(scanServerHost) ||
        (hostname.endsWith('.aceofcloud.io') && knownLabSubdomains.includes(hostnameBase)) ||
        (hostname.includes(SCAN_SERVER_DOMAIN));

      if (isLabOnScanServer) {
        // Resolve scan server domain to get the IP
        try {
          const scanIps = await dnsResolve4(SCAN_SERVER_DOMAIN);
          if (scanIps.length > 0) {
            asset.ip = scanIps[0];
            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `DNS Fallback: ${hostname} → scan server IP`,
              detail: `${hostname} failed DNS resolution. Training lab detected — using scan server IP ${scanIps[0]} (${SCAN_SERVER_DOMAIN})`,
            });
          }
        } catch {
          // Even scan server domain failed — try raw IP from env
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(scanServerHost)) {
            asset.ip = scanServerHost;
            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `DNS Fallback: ${hostname} → scan server IP (env)`,
              detail: `Using SCAN_SERVER_HOST env IP: ${scanServerHost}`,
            });
          }
        }
      }

      if (!asset.ip) {
        addLog(state, {
          phase: 'enumeration', type: 'warning',
          title: `⚠️ DNS Resolution Failed: ${hostname}`,
          detail: `Could not resolve ${hostname} to an IP address. ScanForge discovery may fail for this target.`,
        });
      }
    }
  }

  // Build target list preserving asset identity (avoid IP dedup when multiple assets share an IP)
  // Each entry maps to a unique asset by hostname, using IP only for ScanForge discovery execution
  const targets = scopedAssets.map(a => ({
    scanTarget: getEffectiveTarget(a, 'discovery'),  // Discovery: IP for port scans, hostname for vhosted targets
    assetHostname: a.hostname,       // Which asset this belongs to
  }));

  // ═══════════════════════════════════════════════════════════════════════════
  // PHASE A: Discovery ScanForge with Evasion Tactics
  // ═══════════════════════════════════════════════════════════════════════════
  if (targets.length > 0) {
    const ep = state.scanPlan?.discoveryEvasionProfile;
    const evasionDesc = ep
      ? `Timing: ${ep.timing}, Fragmentation: ${ep.fragmentation}, Decoys: ${ep.decoys}, Host Randomization: ${ep.randomizeHosts}, Data Padding: ${ep.dataLengthPadding}, Source Port Spoofing: ${ep.sourcePortSpoofing}`
      : 'Default evasion profile';

    addLog(state, {
      phase: "enumeration", type: "scan_start",
      title: "🔍 Phase A: Discovery Scan with Evasion",
      detail: `Scanning ${targets.length} targets with full port sweep + service fingerprinting\nEvasion: ${evasionDesc}\n${state.scanPlan?.discoveryStrategy || 'Comprehensive port discovery to enrich passive recon data'}`,
    });

    try {
      // Job Queue Bridge: route scan execution through Redis queue when DO workers are available
      const { getScanServerConfigForScanForge } = await import("./scan-server-executor");
      const { executeScanforgeScan, autoSelectTool } = await import("./scanforge-discovery");
      const roeScope = [...(state.roeScopeGuard?.authorizedDomains || []), ...(state.roeScopeGuard?.authorizedIps || [])];
      const engagementAbortSig = getEngagementAbortSignal(state.engagementId);
      const executeTool = (config: any) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope, engagementAbortSignal: engagementAbortSig });
      const serverConfig = await getScanServerConfigForScanForge();

      for (const targetEntry of targets) {
        const target = targetEntry.scanTarget;
        const asset = state.assets.find(a => a.hostname === targetEntry.assetHostname);
        if (!asset) continue;
        asset.status = "scanning";

        // Get Phase A discovery flags from scan plan
        const assetPlan = state.scanPlan?.assetPlans.find(
          ap => ap.hostname === asset.hostname || ap.ip === target
        );
        // Extract discoveryFlags from the asset plan (used by auto-retry logic and logging)
        const discoveryFlags = assetPlan?.discoveryFlags || '-Pn -sV -sC -O -f -T2 -D RND:5 --data-length 64';

        // ── Step 1: ScanForge Discovery (multi-tool port scanning) ──────────
        const discoveredPorts: Array<{ port: number; protocol: string; service: string; product?: string; version?: string }> = [];
        // ScanForge auto-selects the best tool (Masscan/Naabu/RustScan) based on target context
        const sfTool = autoSelectTool({ targets: [target], stealthLevel: assetPlan?.evasionTechniques?.length ? 'medium' : 'minimal' });
        const discoveryRationale = `ScanForge ${sfTool} — top ports discovery with service fingerprinting`;

        addLog(state, {
          phase: 'enumeration', type: 'scan_start',
          title: `🔒 scanforge: ${fmtTarget(asset, target)}`,
          detail: `Phase A Step 1 — ${discoveryRationale}\nEvasion: ${assetPlan?.evasionTechniques?.join(', ') || 'fragmentation, decoys, normal timing'}`,
        });

        const startTime = Date.now();
        // ═══ AUTO-CAPTURE: Start tcpdump before ScanForge discovery ═══
        let autoCaptureSessionId: string | null = null;
        try {
          const { beforeDiscoveryScan } = await import('./pcap-auto-capture');
          autoCaptureSessionId = await beforeDiscoveryScan(
            state.engagementId, target, asset.hostname,
            { enabled: !!(state as any).autoCaptureEnabled }
          );
          if (autoCaptureSessionId) {
            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `📡 Auto-Capture: ${fmtTarget(asset, target)}`,
              detail: `Background tcpdump started for forensic analysis during discovery scan`,
            });
          }
        } catch (capErr: any) {
          console.warn(`[AutoCapture] Hook failed: ${capErr.message}`);
        }
        try {
          // Naabu v2.5.0: MUST use SYN scan (-s s) with -no-stdin to avoid CONNECT scan hang bug
          const sfArgs = sfTool === 'naabu' ? `-host ${target} -top-ports 1000 -s s -no-stdin -rate 1000 -retries 1 -json` : sfTool === 'masscan' ? `${target} -p1-1024,1720,2000,2427,3306,3389,5060,5061,5080,5432,5900,6379,8080,8443,9090,27017,41795 --rate 1000 -oJ -` : sfTool === 'rustscan' ? `-a ${target} --range 1-65535 -b 4500 -g` : `-host ${target} -top-ports 1000 -s s -no-stdin -json`;
          addLog(state, { phase: 'enumeration', type: 'tool_exec', title: `${sfTool} ${fmtTarget(asset, target)}`, detail: `${sfTool} ${sfArgs}` });
          const discoveryResult = await executeTool({ tool: sfTool, args: sfArgs, timeoutSeconds: 600, sudo: sfTool === 'masscan' || sfTool === 'zmap' || sfTool === 'naabu' });

          // Parse ScanForge JSON output into structured port data
          if (discoveryResult.stdout) {
            try {
              // Import the appropriate parser based on tool
              const discovery = await import("./scanforge-discovery");
              const parser = sfTool === 'masscan' ? discovery.parseMasscanOutput
                : sfTool === 'naabu' ? discovery.parseNaabuOutput
                : sfTool === 'rustscan' ? discovery.parseRustScanOutput
                : discovery.parseNaabuOutput;
              const hosts = parser(discoveryResult.stdout);
              for (const host of hosts) {
                for (const p of host.ports) {
                  discoveredPorts.push({
                    port: p.port,
                    protocol: p.protocol,
                    service: p.service || 'unknown',
                    product: p.product,
                    version: p.version,
                  });
                }
              }
            } catch (parseErr: any) {
              // Fallback: try line-based parsing for greppable output
              const portRegex = /(\d+)\/(tcp|udp)\s+open\s+(\S+)/g;
              let match;
              while ((match = portRegex.exec(discoveryResult.stdout)) !== null) {
                discoveredPorts.push({
                  port: parseInt(match[1]),
                  protocol: match[2] as any,
                  service: match[3] || 'unknown',
                });
              }
            }
          }

          let durationMs = Date.now() - startTime;

          // ── AUTO-RETRY: If ScanForge found 0 ports and output shows "filtered", retry without evasion flags ──
          // Cloud firewalls (CloudFront, AWS, etc.) DROP fragmented/spoofed packets, causing all ports to show as "filtered"
          const allFiltered = discoveredPorts.length === 0 && discoveryResult.stdout && /All \d+ scanned ports.*filtered|\d+\/tcp\s+filtered/.test(discoveryResult.stdout);
          const hasEvasionFlags = /\-f\b|\-D\s|--data-length|--source-port|--mtu/.test(discoveryFlags);

          if (allFiltered && hasEvasionFlags) {
            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `⚠️ scanforge Retry: ${fmtTarget(asset, target)} (removing evasion flags)`,
              detail: `First scan returned all-filtered (likely cloud WAF blocking evasion techniques). Retrying with naabu (most reliable fallback)`,
            });

            const retryFlags = `-host ${target} -top-ports 1000 -s s -no-stdin -rate 1000 -retries 1 -json`;
            const retryArgs = retryFlags;
            const retryStart = Date.now();
            try {
              const retryResult = await executeTool({ tool: sfTool || 'naabu', args: retryArgs, timeoutSeconds: 600, sudo: true });
              if (retryResult.stdout) {
                const tcpRegex2 = /(\d+)\/tcp\s+open\s+(\S+)(?:\s+(.*))?/g;
                let m2;
                while ((m2 = tcpRegex2.exec(retryResult.stdout)) !== null) {
                  const pv = m2[3]?.trim() || '';
                  const pts = pv.split(/\s+/);
                  discoveredPorts.push({
                    port: parseInt(m2[1]), protocol: 'tcp', service: m2[2],
                    product: pts.length > 0 ? pts.slice(0, -1).join(' ') || pts[0] : undefined,
                    version: pts.length > 1 ? pts[pts.length - 1] : undefined,
                  });
                }
              }
              durationMs += (Date.now() - retryStart);
              addLog(state, {
                phase: 'enumeration', type: 'scan_result',
                title: `scanforge Retry Complete: ${fmtTarget(asset, target)}`,
                detail: `Retry found ${discoveredPorts.length} services (simple flags worked)`,
              });

              // Persist retry result too
              await persistScanResult({
                engagementId: state.engagementId, tool: sfTool || 'naabu', target,
                command: `naabu ${retryArgs}`, stdout: retryResult.stdout || '',
                stderr: retryResult.stderr || '', exitCode: retryResult.exitCode ?? 0,
                durationMs: Date.now() - retryStart, timedOut: retryResult.timedOut || false,
                findings: discoveredPorts.map(p => ({ type: 'open_port', port: p.port, protocol: p.protocol, service: p.service, product: p.product, version: p.version })),
                phase: 'discovery_retry',
              });
            } catch (retryErr: any) {
              addLog(state, { phase: 'enumeration', type: 'error', title: `scanforge Retry Failed: ${fmtTarget(asset, target)}`, detail: retryErr.message });
            }
          }

          // Merge discovery ports into asset
          asset.ports = discoveredPorts.map(p => ({
            port: p.port,
            service: p.service || 'unknown',
            version: p.product ? `${p.product}${p.version ? ' ' + p.version : ''}`.trim() : undefined,
          }));

          // ── SERVICE RESOLUTION ──
          // Replace "unknown" service labels using passive recon + well-known port mapping
          enrichPortServices(asset.ports, (asset.passiveRecon as any)?.services || []);

          // ── PASSIVE RECON PORT SEEDING ──────────────────────────────────────
          // If ScanForge found 0 ports but passive recon detected web services,
          // seed standard web ports (80/443) so the pipeline continues to
          // credential testing and ZAP scanning. This handles training labs
          // behind nginx reverse proxies and CDN-fronted targets.
          if (discoveredPorts.length === 0) {
            const isWebAsset = asset.type === 'web_app' ||
              (asset.passiveRecon as any)?.technologies?.some((t: string) => /nginx|apache|iis|http|web|php|node|express|flask|django/i.test(t)) ||
              (asset.passiveRecon as any)?.services?.some((s: any) => /http/i.test(s.service || ''));

            // Also check if passive recon already found ports
            const passivePorts = (asset.passiveRecon as any)?.services?.map((s: any) => s.port).filter(Boolean) || [];

            if (isWebAsset || passivePorts.length > 0) {
              const seedPorts = passivePorts.length > 0
                ? passivePorts
                : [80, 443]; // Default web ports

              for (const port of seedPorts) {
                if (!asset.ports.some(p => p.port === port)) {
                  asset.ports.push({
                    port,
                    service: port === 443 ? 'https' : 'http',
                    version: undefined,
                  });
                }
              }

              addLog(state, {
                phase: 'enumeration', type: 'info',
                title: `🌐 Port Seeding: ${fmtTarget(asset, target)}`,
                detail: `ScanForge found 0 open ports but passive recon indicates web services. Seeded ports: ${asset.ports.map(p => `${p.port}/${p.service}`).join(', ')}. Pipeline will continue to credential testing and ZAP.`,
              });

              state.stats.portsFound += asset.ports.length;
            }
          }

          // Store ScanForge discovery discovery result
          asset.toolResults.push({
            tool: sfTool || 'naabu',
            command: `${sfTool} ${sfArgs}`,
            exitCode: discoveryResult.exitCode ?? 0,
            durationMs,
            timedOut: discoveryResult.timedOut || false,
            findingCount: discoveredPorts.length,
            findings: discoveredPorts.map(p => ({
              severity: 'info',
              title: `${p.port}/${p.protocol} ${p.service}${p.product ? ` (${p.product})` : ''}`,
            })),
            outputPreview: (discoveryResult.stdout || '').slice(0, 512),
            executedAt: Date.now(),
            phase: 'discovery',
          });

          state.stats.portsFound += discoveredPorts.length;
          state.stats.hostsScanned++;
          asset.status = 'enumerated';

          broadcastOpsUpdate(state.engagementId, { type: 'stats_update', stats: { ...state.stats } });
          addLog(state, {
            phase: 'enumeration', type: 'scan_result',
            title: `scanforge Complete: ${fmtTarget(asset, target)}`,
            detail: `${discoveredPorts.length} services fingerprinted in ${Math.round(durationMs / 1000)}s\nPorts: ${discoveredPorts.map(p => `${p.port}/${p.service}${p.product ? ` (${p.product})` : ''}`).join(', ')}`,
            data: { ports: asset.ports, discoveryFlags, evasion: assetPlan?.evasionTechniques },
          });

          await persistScanResult({
            engagementId: state.engagementId,
            tool: sfTool || 'naabu',
            target,
            command: `${sfTool} ${sfArgs}`,
            stdout: discoveryResult.stdout || '',
            stderr: discoveryResult.stderr || '',
            exitCode: discoveryResult.exitCode ?? 0,
            durationMs,
            timedOut: discoveryResult.timedOut || false,
            findings: discoveredPorts.map(p => ({ type: 'open_port', port: p.port, protocol: p.protocol, service: p.service, product: p.product, version: p.version })),
            phase: 'discovery',
          });
        } catch (e: any) {
          addLog(state, { phase: 'enumeration', type: 'error', title: `scanforge Failed: ${fmtTarget(asset, target)}`, detail: e.message });
          asset.status = 'enumerated'; // Continue pipeline
        }

        // ═══ AUTO-CAPTURE: Stop tcpdump after ScanForge discovery ═══
        if (autoCaptureSessionId) {
          try {
            const { afterDiscoveryScan } = await import('./pcap-auto-capture');
            const captureResult = await afterDiscoveryScan(autoCaptureSessionId);
            if (captureResult && captureResult.packetsCaptured) {
              addLog(state, {
                phase: 'enumeration', type: 'info',
                title: `📡 Auto-Capture Complete: ${fmtTarget(asset, target)}`,
                detail: `Captured ${captureResult.packetsCaptured} packets during discovery scan (${Math.round((captureResult.stoppedAt! - captureResult.startedAt) / 1000)}s)${
                  captureResult.analysisSummary ? `\nFindings: ${captureResult.analysisSummary.findings} security findings detected, ${captureResult.analysisSummary.conversations} conversations, protocols: ${captureResult.analysisSummary.protocols.join(', ')}` : ''
                }`,
                data: { pcapPath: captureResult.pcapPath, packetsCaptured: captureResult.packetsCaptured, analysisSummary: captureResult.analysisSummary },
              });
              // Store capture reference on asset for topology builder
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

        // ── Step 2a: Active Service Fingerprinting ──────────────────────
        // Run protocol-specific probes on all discovered ports to upgrade
        // "inferred" service labels to "fingerprinted" with product/version/banner.
        try {
          const { autoFingerprint, summarizeFingerprints } = await import('./service-fingerprinter');
          const { getCachedFingerprints, cacheFingerprints } = await import('./fingerprint-cache');
          const openPortNumbers = asset.ports.map(p => p.port);
          if (openPortNumbers.length > 0) {
            // ── Check fingerprint cache first ──
            const cacheLookup = await getCachedFingerprints(target, openPortNumbers);
            const cacheNote = cacheLookup.hitCount > 0
              ? ` (✅ ${cacheLookup.hitCount} cached, ${cacheLookup.missCount} to probe)`
              : '';

            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `🔍 Service Fingerprinting: ${fmtTarget(asset, target)}`,
              detail: `Running protocol-specific probes on ${openPortNumbers.length} ports: ${openPortNumbers.join(', ')}${cacheNote}`,
            });

            const fpStart = Date.now();
            let fpResults: any[];

            if (cacheLookup.uncachedPorts.length > 0) {
              // Probe only uncached ports
              const freshResults = await autoFingerprint(target, cacheLookup.uncachedPorts, {
                engagementId: state.engagementId,
                operatorId: state.operatorId,
                timeoutMs: 10000,
                tryDefaultCreds: (state.scanProfile || 'standard') !== 'stealth',
              });
              // Merge cached + fresh results
              fpResults = [...cacheLookup.cached, ...freshResults];
              // Cache the fresh results for future runs
              if (freshResults.length > 0) {
                const cacheResult = await cacheFingerprints(target, freshResults, state.engagementId);
                if (cacheResult.cached > 0) {
                  console.log(`[FingerprintCache] Cached ${cacheResult.cached} new results for ${target}`);
                }
              }
            } else {
              // All ports were cached — no probing needed
              fpResults = cacheLookup.cached;
            }
            const fpDuration = Date.now() - fpStart;

            // Merge fingerprint results into asset port data
            let upgraded = 0;
            for (const fp of fpResults) {
              if (fp.error) continue;
              const portEntry = asset.ports.find(p => p.port === fp.port);
              if (portEntry) {
                // Upgrade service name if we got a real fingerprint
                if (fp.protocol) {
                  portEntry.service = fp.protocol;
                  (portEntry as any).serviceSource = 'fingerprinted';
                }
                // Upgrade version with product + version info
                if (fp.product || fp.version) {
                  portEntry.version = [fp.product, fp.version].filter(Boolean).join(' ');
                }
                // Store banner and security metadata
                (portEntry as any).banner = fp.banner;
                (portEntry as any).product = fp.product;
                (portEntry as any).os = fp.os;
                (portEntry as any).securityFlags = fp.securityFlags;
                (portEntry as any).riskIndicators = fp.riskIndicators;
                (portEntry as any).potentialCves = fp.potentialCves;
                upgraded++;
              }
            }

            const summary = summarizeFingerprints(fpResults);

            // Store fingerprint results on asset for downstream use
            (asset as any).fingerprintResults = fpResults;
            (asset as any).fingerprintSummary = summary;

            addLog(state, {
              phase: 'enumeration', type: 'scan_result',
              title: `🔍 Fingerprinting Complete: ${fmtTarget(asset, target)}`,
              detail: `${summary.successfulProbes}/${summary.totalServices} services fingerprinted in ${Math.round(fpDuration / 1000)}s — ${upgraded} ports upgraded\n` +
                `Products: ${fpResults.filter(f => f.product).map(f => `${f.port}/${f.product} ${f.version || ''}`).join(', ') || 'none detected'}\n` +
                `Risks: ${summary.criticalRisks} critical, ${summary.highRisks} high, ${summary.mediumRisks} medium` +
                (summary.servicesWithAnonymousAccess.length > 0 ? `\n⚠️ Anonymous access: ${summary.servicesWithAnonymousAccess.map(s => `${s.port}/${s.protocol}`).join(', ')}` : '') +
                (summary.servicesWithDefaultCreds.length > 0 ? `\n🔑 Default credentials: ${summary.servicesWithDefaultCreds.map(s => `${s.port}/${s.protocol}`).join(', ')}` : '') +
                (summary.allCves.length > 0 ? `\n🛡️ Potential CVEs: ${summary.allCves.slice(0, 10).join(', ')}${summary.allCves.length > 10 ? ` (+${summary.allCves.length - 10} more)` : ''}` : ''),
              data: {
                fingerprintResults: fpResults.map(f => ({
                  port: f.port,
                  protocol: f.protocol,
                  product: f.product,
                  version: f.version,
                  banner: f.banner,
                  os: f.os,
                  securityFlags: f.securityFlags,
                  riskIndicators: f.riskIndicators,
                  potentialCves: f.potentialCves,
                })),
                summary: {
                  successfulProbes: summary.successfulProbes,
                  failedProbes: summary.failedProbes,
                  criticalRisks: summary.criticalRisks,
                  highRisks: summary.highRisks,
                  anonymousAccess: summary.servicesWithAnonymousAccess.length,
                  defaultCreds: summary.servicesWithDefaultCreds.length,
                  noTls: summary.servicesWithoutTls.length,
                },
              },
            });

            // ── Enrich fingerprints with vuln feed CVE data ──
            // Query NVD/CIRCL/KEV/ExploitDB for product+version matches
            try {
              const { enrichFingerprintsWithVulnFeeds } = await import('./fingerprint-cve-enrichment');
              const { results: enrichedFps, summary: enrichSummary } = await enrichFingerprintsWithVulnFeeds(fpResults);
              (asset as any).fingerprintResults = enrichedFps;
              (asset as any).fingerprintCveEnrichment = enrichSummary;
              if (enrichSummary.enrichedCount > 0) {
                addLog(state, {
                  phase: 'enumeration', type: 'finding',
                  title: `🛡️ CVE Enrichment: ${enrichSummary.totalCvesMatched} CVEs matched for ${fmtTarget(asset, target)}`,
                  detail: `Vuln feeds matched ${enrichSummary.totalCvesMatched} CVEs across ${enrichSummary.enrichedCount} services\n` +
                    `Exploitable: ${enrichSummary.exploitableCveCount} | CISA KEV: ${enrichSummary.kevCveCount} | Active 0-day: ${enrichSummary.zeroDayCveCount}\n` +
                    `Risk Score: ${enrichSummary.overallRiskScore}/100 | Max Severity: ${enrichSummary.maxSeverity.toUpperCase()}\n` +
                    `Priority targets: ${enrichSummary.perService.filter(s => s.matchedCves.length > 0).slice(0, 3).map(s => `${s.port}/${s.product || s.protocol} (${s.matchedCves.length} CVEs)`).join(', ')}`,
                  data: { enrichSummary },
                });
              }
            } catch (enrichErr: any) {
              console.warn('[FP-CVE-Enrich] Non-blocking enrichment failed:', enrichErr.message);
            }

            // ── Fingerprint Diff: compare against previous scan ──
            try {
              const { diffFingerprints, fingerprintsToCacheEntries, buildDiffSummaryText } = await import('./fingerprint-diff');
              const { getCachedFingerprints: getPrevCached } = await import('./fingerprint-cache');
              
              // Get ALL previously cached fingerprints for this target (not just current ports)
              const allPrevPorts = Array.from({ length: 65535 }, (_, i) => i + 1); // We'll filter by engagement
              // Actually, use the cache entries we already have from the initial lookup
              const prevCached = cacheLookup.cached.map(c => ({
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
                fingerprintedAt: c.fingerprintedAt || (Date.now() - 86400000),
                engagementId: String(state.engagementId),
              }));

              if (prevCached.length > 0) {
                const diffReport = diffFingerprints(fpResults, prevCached, state.engagementId);
                (asset as any).fingerprintDiff = diffReport;

                if (diffReport.totalChanges > 0) {
                  const diffSummary = buildDiffSummaryText(diffReport);
                  addLog(state, {
                    phase: 'enumeration', type: diffReport.postureChange === 'degraded' ? 'finding' : 'info',
                    title: `📊 Fingerprint Diff: ${diffReport.totalChanges} changes for ${fmtTarget(asset, target)}`,
                    detail: `Posture: ${diffReport.postureChange.toUpperCase()} | Risk Delta: ${diffReport.riskScoreDelta > 0 ? '+' : ''}${diffReport.riskScoreDelta}\n` +
                      `New services: +${diffReport.newServices.length} | Removed: -${diffReport.removedServices.length} | Version changes: ${diffReport.versionChanges.length}\n` +
                      `CVE delta: +${diffReport.cveDelta.newCves.length} new, -${diffReport.cveDelta.resolvedCves.length} resolved, ${diffReport.cveDelta.persistentCves.length} persistent\n` +
                      (diffReport.changeBySeverity.critical > 0 ? `⚠️ ${diffReport.changeBySeverity.critical} CRITICAL changes detected!\n` : '') +
                      (diffReport.changeBySeverity.high > 0 ? `⚠️ ${diffReport.changeBySeverity.high} HIGH changes detected\n` : ''),
                    data: { diffReport },
                  });
                }
              }
            } catch (diffErr: any) {
              console.warn('[FP-Diff] Non-blocking diff failed:', diffErr.message);
            }

            // Re-run service resolution with enriched data
            enrichPortServices(asset.ports, (asset.passiveRecon as any)?.services || []);
          }
        } catch (fpErr: any) {
          addLog(state, {
            phase: 'enumeration', type: 'info',
            title: `🔍 Fingerprinting Skipped: ${fmtTarget(asset, target)}`,
            detail: `Service fingerprinting failed (non-blocking): ${fpErr.message}`,
          });
        }

        // ── Step 2a.1: Banner-Based WAF/IDS Detection ─────────────────────
        // Detect WAF/IDS/firewall signatures from TCP-level fingerprint banners.
        // This complements HTTP-based WAF detection by catching network-level appliances.
        try {
          const { detectWafFromBanners, mergeBannerWafIntoAsset, generateEvasionProfile } = await import('./banner-waf-detector');
          const fpResults = (asset as any).fingerprintResults;
          if (fpResults && fpResults.length > 0) {
            const bannerWafSummary = detectWafFromBanners(fpResults);
            if (bannerWafSummary.detections.length > 0) {
              const { wafVendor, newDetections } = mergeBannerWafIntoAsset(asset.wafDetected, bannerWafSummary.detections);
              if (newDetections && wafVendor) {
                asset.wafDetected = wafVendor;
                state.stats.wafDetections = (state.stats.wafDetections || 0) + bannerWafSummary.detections.length;

                // Generate evasion profile for downstream scanning
                const evasionProfile = generateEvasionProfile(bannerWafSummary);
                (asset as any).bannerEvasionProfile = evasionProfile;
                (asset as any).bannerWafSummary = bannerWafSummary;

                const categoryBreakdown = bannerWafSummary.detections.map(d =>
                  `${d.port}/${d.protocol}: ${d.vendor} ${d.product} [${d.category}] (${d.confidence}% confidence)`
                ).join('\n');

                addLog(state, {
                  phase: 'enumeration', type: 'waf_detected',
                  title: `\ud83d\udee1\ufe0f Banner WAF/IDS Detected: ${fmtTarget(asset, target)} \u2014 ${bannerWafSummary.uniqueVendors.join(', ')}`,
                  detail: `Security posture: ${bannerWafSummary.posture.replace('_', ' ')}\n` +
                    `Detections:\n${categoryBreakdown}\n` +
                    `Evasion: rate=${evasionProfile.rateMultiplier}x, fragment=${evasionProfile.useFragmentation}, encrypt=${evasionProfile.useEncryption}\n` +
                    `Recommendations: ${bannerWafSummary.evasionRecommendations.slice(0, 3).join('; ')}`,
                  data: {
                    detections: bannerWafSummary.detections.map(d => ({
                      vendor: d.vendor, product: d.product, category: d.category,
                      port: d.port, confidence: d.confidence, matchedPattern: d.matchedPattern,
                    })),
                    posture: bannerWafSummary.posture,
                    evasionProfile,
                  },
                });
              }
            }
          }
        } catch (bannerWafErr: any) {
          /* Banner WAF detection is best-effort — don't block pipeline */
        }

        // ── Step 2b: RDP/VoIP/Conferencing service-specific scanning ──────────
        try {
          const { isRdpVoipConferencingPort, getScanCommandsForService, getServiceForPort, buildExploitContextForLlm } = await import('./knowledge/rdp-voip-conferencing-knowledge');
          // Filter for RDP/VoIP/conferencing ports, but exclude generic HTTPS ports (443, 8443)
          // unless the service fingerprint or banner actually indicates conferencing equipment
          const CONFERENCING_WEB_PORTS = new Set([443, 8443]);
          const CONFERENCING_FINGERPRINTS = ['polycom', 'telepresence', 'zoom room', 'crestron', 'webex', 'lifesize', 'tandberg', 'cisco meeting', 'realpresence'];
          const rdpVoipPorts = discoveredPorts.filter(p => {
            // Always include known RDP/VoIP service names
            if (['rdp', 'sip', 'sips', 'h323', 'sccp', 'mgcp', 'ms-wbt-server'].includes(p.service)) return true;
            // For 443/8443 — only include if banner/product indicates conferencing equipment
            if (CONFERENCING_WEB_PORTS.has(p.port)) {
              const banner = ((p as any).banner || '').toLowerCase();
              const product = ((p as any).product || '').toLowerCase();
              const version = (p.version || '').toLowerCase();
              const combined = `${banner} ${product} ${version}`;
              return CONFERENCING_FINGERPRINTS.some(fp => combined.includes(fp));
            }
            // For all other ports, use the standard port-based check
            return isRdpVoipConferencingPort(p.port);
          });
          if (rdpVoipPorts.length > 0) {
            addLog(state, { phase: 'enumeration', type: 'info', title: `🔌 RDP/VoIP/Conferencing Services Detected: ${fmtTarget(asset, target)}`, detail: `Found ${rdpVoipPorts.length} RDP/VoIP/conferencing services: ${rdpVoipPorts.map(p => `${p.port}/${p.service}`).join(', ')}` });
            for (const svcPort of rdpVoipPorts.slice(0, 5)) {
              const svcName = getServiceForPort(svcPort.port) || svcPort.service;
              const scanCmds = getScanCommandsForService(svcName, target, svcPort.port);
              for (const cmd of scanCmds.slice(0, 2)) {
                try {
                  const svcResult = await executeTool({ tool: cmd.tool, args: cmd.command.replace(cmd.tool + ' ', ''), timeoutSeconds: cmd.timeout, sudo: cmd.tool === 'masscan' || cmd.tool === 'naabu' });
                  if (svcResult.stdout) {
                    addLog(state, { phase: 'enumeration', type: 'scan_result', title: `${cmd.tool} ${svcName} scan: ${target}:${svcPort.port}`, detail: `${cmd.purpose}\n${(svcResult.stdout || '').slice(0, 1000)}` });
                  }
                } catch (svcErr: any) {
                  /* best effort — continue scanning */
                }
              }
              // Store RDP/VoIP context on asset for exploitation phase
              if (!(asset as any).rdpVoipContext) (asset as any).rdpVoipContext = [];
              (asset as any).rdpVoipContext.push({ port: svcPort.port, service: svcName, exploitContext: buildExploitContextForLlm({ service: svcName, target, port: svcPort.port }) });
            }
          }
        } catch (rdpVoipErr: any) {
          /* RDP/VoIP scanning is best-effort — don't block pipeline */
        }

        // ── Step 3: httpx (HTTP probing on web ports) ────────────────────
        const webPorts = discoveredPorts.filter(p =>
          ['http', 'https', 'http-proxy', 'http-alt', 'ssl'].includes(p.service) ||
          [80, 443, 8080, 8443, 8000, 3000, 5000, 9443].includes(p.port)
        );
        // Also probe common web ports even if ScanForge didn't detect them as open
        const commonWebPorts = [80, 443, 8080, 8443];
        for (const wp of commonWebPorts) {
          if (!webPorts.find(p => p.port === wp)) {
            // Always try common web ports — httpx will quickly determine if they're actually open
            webPorts.push({ port: wp, protocol: 'tcp', service: wp === 443 || wp === 8443 ? 'https' : 'http' });
          }
        }

        if (webPorts.length > 0) {
          asset.type = 'web_app';
          const httpxFlags = assetPlan?.httpxFlags || '-json -tech-detect -status-code -title -cdn -tls-grab -follow-redirects -content-length -web-server -silent';
          // Build target URLs for httpx
          const httpxTargets = webPorts.map(p => {
            const scheme = [443, 8443, 9443].includes(p.port) || p.service === 'https' || p.service === 'ssl' ? 'https' : 'http';
            return `${scheme}://${asset.hostname || target}:${p.port}`;
          });

          addLog(state, {
            phase: 'enumeration', type: 'scan_start',
            title: `🌐 httpx: ${fmtTarget(asset, target)}`,
            detail: `Phase A Step 2 — HTTP probing ${webPorts.length} web ports\nTargets: ${httpxTargets.join(', ')}\nFlags: ${httpxFlags}`,
          });

          try {
            const httpxStart = Date.now();
            // Pipe targets to httpx via raw command (not tool='bash' which may not be whitelisted)
            const httpxInput = httpxTargets.join('\\n');
            const httpxArgs = `${httpxFlags}`;
            const httpxCmd = `echo -e '${httpxInput}' | httpx ${httpxArgs}`;
            addLog(state, { phase: 'enumeration', type: 'tool_exec', title: `httpx ${fmtTarget(asset, target)}`, detail: httpxCmd });
            const httpxResult = await executeRawCommandViaQueue(httpxCmd, 120, { engagementId: state.engagementId, engagementAbortSignal: engagementAbortSig });
            const httpxDuration = Date.now() - httpxStart;

            // Parse httpx JSON output — each line is a JSON object with real data
            const httpxFindings: Array<{ severity: string; title: string }> = [];
            const techDetected: string[] = [];
            const cdnDetected: string[] = [];
            const responseHeaders: Record<string, string> = {};
            let webServer = '';
            let tlsInfo = '';

            // Track which ports returned 200 (live web app) vs 404/error
            const httpxLivePorts: Array<{ port: number; statusCode: number; title: string }> = [];

            if (httpxResult.stdout) {
              for (const line of httpxResult.stdout.split('\n')) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                try {
                  const obj = JSON.parse(trimmed);
                  // Track per-port status codes for downstream ZAP/SQLMap port filtering
                  if (obj.status_code && obj.port) {
                    httpxLivePorts.push({ port: obj.port, statusCode: obj.status_code, title: obj.title || '' });
                  } else if (obj.status_code && obj.url) {
                    try {
                      const parsedUrl = new URL(obj.url);
                      const portNum = parsedUrl.port ? parseInt(parsedUrl.port) : (parsedUrl.protocol === 'https:' ? 443 : 80);
                      httpxLivePorts.push({ port: portNum, statusCode: obj.status_code, title: obj.title || '' });
                    } catch {}
                  }
                  // Technology detection
                  if (obj.tech && Array.isArray(obj.tech)) {
                    for (const tech of obj.tech) {
                      if (!techDetected.includes(tech)) techDetected.push(tech);
                      httpxFindings.push({ severity: 'info', title: `[httpx] Technology: ${tech}` });
                    }
                  }
                  // CDN/WAF detection
                  if (obj.cdn_name) {
                    if (!cdnDetected.includes(obj.cdn_name)) cdnDetected.push(obj.cdn_name);
                    httpxFindings.push({ severity: 'info', title: `[httpx] CDN/WAF: ${obj.cdn_name}` });
                  }
                  if (obj.cdn === true) {
                    httpxFindings.push({ severity: 'info', title: `[httpx] CDN detected` });
                  }
                  // Web server
                  if (obj.webserver) {
                    webServer = obj.webserver;
                    httpxFindings.push({ severity: 'info', title: `[httpx] Web Server: ${obj.webserver}` });
                  }
                  // TLS info
                  if (obj.tls) {
                    const tls = obj.tls;
                    tlsInfo = `${tls.version || ''} ${tls.cipher || ''}`.trim();
                    if (tls.subject_cn) httpxFindings.push({ severity: 'info', title: `[httpx] TLS CN: ${tls.subject_cn}` });
                    if (tls.subject_org) httpxFindings.push({ severity: 'info', title: `[httpx] TLS Org: ${tls.subject_org}` });
                    if (tls.not_after) httpxFindings.push({ severity: 'info', title: `[httpx] TLS Expires: ${tls.not_after}` });
                  }
                  // Status code + title
                  if (obj.status_code) {
                    httpxFindings.push({ severity: 'info', title: `[httpx] ${obj.url || obj.input}: ${obj.status_code} ${obj.title || ''}`.trim() });
                  }
                  // Content length
                  if (obj.content_length !== undefined) {
                    httpxFindings.push({ severity: 'info', title: `[httpx] Content-Length: ${obj.content_length}` });
                  }
                  // ── Response Header Extraction for Tech Stack Detection ──
                  // httpx -json includes response headers in the 'header' field (object of header arrays)
                  // and also in 'a' (raw response), 'response_header' (string), etc.
                  const headers = obj.header || obj.response_header || {};
                  if (typeof headers === 'object' && !Array.isArray(headers)) {
                    // httpx returns headers as { "header-name": ["value1", "value2"] }
                    for (const [key, val] of Object.entries(headers)) {
                      const lk = key.toLowerCase();
                      const headerVal = Array.isArray(val) ? val[0] : String(val);
                      if (lk === 'x-powered-by') {
                        responseHeaders['x-powered-by'] = headerVal;
                        httpxFindings.push({ severity: 'info', title: `[httpx] X-Powered-By: ${headerVal}` });
                        // Extract tech from X-Powered-By (e.g., "PHP/8.1.2", "ASP.NET", "Express")
                        if (!techDetected.includes(headerVal)) techDetected.push(headerVal);
                      }
                      if (lk === 'x-aspnet-version' || lk === 'x-aspnetmvc-version') {
                        responseHeaders[lk] = headerVal;
                        httpxFindings.push({ severity: 'info', title: `[httpx] ${key}: ${headerVal}` });
                        if (!techDetected.includes(`ASP.NET ${headerVal}`)) techDetected.push(`ASP.NET ${headerVal}`);
                      }
                      if (lk === 'x-generator') {
                        responseHeaders['x-generator'] = headerVal;
                        httpxFindings.push({ severity: 'info', title: `[httpx] X-Generator: ${headerVal}` });
                        if (!techDetected.includes(headerVal)) techDetected.push(headerVal);
                      }
                      if (lk === 'set-cookie') {
                        responseHeaders['set-cookie'] = headerVal;
                        // Detect tech from cookie names
                        if (headerVal.includes('PHPSESSID') && !techDetected.includes('PHP')) techDetected.push('PHP');
                        if (headerVal.includes('JSESSIONID') && !techDetected.includes('Java')) techDetected.push('Java');
                        if (headerVal.includes('ASP.NET_SessionId') && !techDetected.includes('ASP.NET')) techDetected.push('ASP.NET');
                        if (headerVal.includes('connect.sid') && !techDetected.includes('Node.js/Express')) techDetected.push('Node.js/Express');
                        if (headerVal.includes('laravel_session') && !techDetected.includes('Laravel/PHP')) techDetected.push('Laravel/PHP');
                        if (headerVal.includes('_rails') && !techDetected.includes('Ruby on Rails')) techDetected.push('Ruby on Rails');
                        if (headerVal.includes('csrftoken') && !techDetected.includes('Django/Python')) techDetected.push('Django/Python');
                        if (headerVal.includes('wp-settings') && !techDetected.includes('WordPress')) techDetected.push('WordPress');
                      }
                      if (lk === 'server' && !webServer) {
                        responseHeaders['server'] = headerVal;
                        // Already captured via obj.webserver above, but ensure it's in responseHeaders
                      }
                    }
                  }
                  // Also check raw response string for headers if 'header' field is a string
                  if (typeof headers === 'string') {
                    const headerLines = headers.split('\n');
                    for (const hl of headerLines) {
                      const colonIdx = hl.indexOf(':');
                      if (colonIdx === -1) continue;
                      const hName = hl.substring(0, colonIdx).trim().toLowerCase();
                      const hVal = hl.substring(colonIdx + 1).trim();
                      if (hName === 'x-powered-by') {
                        responseHeaders['x-powered-by'] = hVal;
                        if (!techDetected.includes(hVal)) techDetected.push(hVal);
                        httpxFindings.push({ severity: 'info', title: `[httpx] X-Powered-By: ${hVal}` });
                      }
                      if (hName === 'set-cookie') {
                        responseHeaders['set-cookie'] = hVal;
                        if (hVal.includes('PHPSESSID') && !techDetected.includes('PHP')) techDetected.push('PHP');
                        if (hVal.includes('JSESSIONID') && !techDetected.includes('Java')) techDetected.push('Java');
                        if (hVal.includes('ASP.NET_SessionId') && !techDetected.includes('ASP.NET')) techDetected.push('ASP.NET');
                      }
                    }
                  }
                } catch { /* not JSON line — skip */ }
              }
            }

            // Enrich asset passiveRecon with httpx data
            if (asset.passiveRecon) {
              if (techDetected.length > 0) {
                asset.passiveRecon.technologies = [...new Set([...(asset.passiveRecon.technologies || []), ...techDetected])];
              }
              if (cdnDetected.length > 0) {
                asset.passiveRecon.riskSignals = [...(asset.passiveRecon.riskSignals || []), ...cdnDetected.map(c => ({ severity: 'low', type: 'cdn_waf', rationale: `CDN/WAF detected: ${c}` }))];
              }
              if (webServer) {
                asset.passiveRecon.technologies = [...new Set([...(asset.passiveRecon.technologies || []), webServer])];
              }
              // Store extracted response headers for downstream ZAP config
              if (Object.keys(responseHeaders).length > 0) {
                (asset as any).httpxResponseHeaders = { ...(asset as any).httpxResponseHeaders, ...responseHeaders };
              }
              // Store per-port httpx status codes for downstream ZAP/SQLMap filtering
              if (httpxLivePorts.length > 0) {
                (asset as any).httpxLivePorts = httpxLivePorts;
              }
            }

            // Store httpx result with fingerprints and raw output
            asset.toolResults.push({
              tool: 'httpx',
              command: httpxCmd,
              exitCode: httpxResult.exitCode ?? 0,
              durationMs: httpxDuration,
              timedOut: httpxResult.timedOut || false,
              findingCount: httpxFindings.length,
              findings: httpxFindings,
              outputPreview: (httpxResult.stdout || '').slice(0, 1024),
              rawOutput: (httpxResult.stdout || '').slice(0, 50_000),
              executedAt: Date.now(),
              phase: 'discovery',
              fingerprints: {
                webServer: webServer || undefined,
                technologies: techDetected.length > 0 ? techDetected : undefined,
                httpHeaders: Object.keys(responseHeaders).length > 0 ? responseHeaders : undefined,
                tlsInfo: tlsInfo ? {
                  subjectCN: tlsInfo.subject_cn,
                  issuerOrg: tlsInfo.issuer_org,
                  notAfter: tlsInfo.not_after,
                } : undefined,
                poweredBy: responseHeaders['x-powered-by'] || undefined,
                cookies: responseHeaders['set-cookie'] ? [responseHeaders['set-cookie']] : undefined,
              },
            });

            await persistScanResult({
              engagementId: state.engagementId,
              tool: 'httpx',
              target,
              command: httpxCmd,
              stdout: httpxResult.stdout || '',
              stderr: httpxResult.stderr || '',
              exitCode: httpxResult.exitCode ?? 0,
              durationMs: httpxDuration,
              timedOut: httpxResult.timedOut || false,
              findings: httpxFindings,
              phase: 'discovery',
            });

            addLog(state, {
              phase: 'enumeration', type: 'scan_result',
              title: `httpx Complete: ${fmtTarget(asset, target)}`,
              detail: `${httpxFindings.length} findings in ${Math.round(httpxDuration / 1000)}s${techDetected.length > 0 ? `\nTech: ${techDetected.join(', ')}` : ''}${cdnDetected.length > 0 ? `\nCDN/WAF: ${cdnDetected.join(', ')}` : ''}${webServer ? `\nServer: ${webServer}` : ''}`,
              data: { tech: techDetected, cdn: cdnDetected, webServer, tls: tlsInfo },
            });
          } catch (e: any) {
            addLog(state, { phase: 'enumeration', type: 'error', title: `httpx Failed: ${fmtTarget(asset, target)}`, detail: e.message });
          }
        }

         // ── httpx Port Backfill: if ScanForge found 0 ports but httpx confirmed live services ──
        // This is critical for cloud-hosted targets where ScanForge discovery may show all ports as "filtered"
        // but httpx successfully connects to web services on 80/443
        if (asset.ports.length === 0 && webPorts.length > 0) {
          // Check which web ports httpx actually confirmed as live (got a status code response)
          const httpxToolResult = asset.toolResults.find(tr => tr.tool === 'httpx');
          const confirmedPorts: Array<{ port: number; service: string; version?: string }> = [];

          if (httpxToolResult?.outputPreview) {
            for (const line of httpxToolResult.outputPreview.split('\n')) {
              try {
                const obj = JSON.parse(line.trim());
                if (obj.status_code && obj.port) {
                  const svc = obj.scheme === 'https' ? 'https' : 'http';
                  if (!confirmedPorts.find(p => p.port === obj.port)) {
                    confirmedPorts.push({
                      port: obj.port,
                      service: svc,
                      version: obj.webserver || undefined,
                    });
                  }
                }
              } catch { /* not JSON */ }
            }
          }

          // Fallback: if httpx output didn't have port info, use the common web ports we probed
          if (confirmedPorts.length === 0) {
            // httpx found findings but we can't parse port info — assume standard web ports
            const httpxFindingCount = httpxToolResult?.findingCount || 0;
            if (httpxFindingCount > 0) {
              confirmedPorts.push({ port: 80, service: 'http' });
              confirmedPorts.push({ port: 443, service: 'https' });
            }
          }

          if (confirmedPorts.length > 0) {
            asset.ports = confirmedPorts;
            asset.type = 'web_app';
            state.stats.portsFound += confirmedPorts.length;

            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `🌐 httpx Port Backfill: ${fmtTarget(asset, target)}`,
              detail: `ScanForge found 0 open ports (cloud firewall), but httpx confirmed ${confirmedPorts.length} live web services: ${confirmedPorts.map(p => `${p.port}/${p.service}`).join(', ')}. Pipeline will continue with httpx-discovered ports.`,
            });
          }
        }

        // ── Discovery complete for this asset ────────────────────────
        addLog(state, {
          phase: 'enumeration', type: 'scan_result',
          title: `✅ Discovery Complete: ${fmtTarget(asset, target)}`,
          detail: `ScanForge: ${discoveredPorts.length} services | httpx: ${webPorts.length > 0 ? 'probed' : 'skipped (no web ports)'} | Final ports: ${asset.ports.length}`,
        });
      }
    } catch (e: any) {
      addLog(state, { phase: "enumeration", type: "error", title: "Discovery Scan Error", detail: e.message });
    }
  }

  state.progress = 25;
  addLog(state, {
    phase: "enumeration", type: "phase_complete",
    title: "\u2705 Phase A Discovery Complete",
    detail: `${state.stats.hostsScanned} hosts scanned, ${state.stats.portsFound} ports discovered. Enriched data now available for Phase B targeted tool deployment.`,
  });
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });

  // ═══ EMIT recon:finding EVENTS FOR PORT DISCOVERY RESULTS ═══
  for (const asset of state.assets) {
    for (const p of (asset.ports || [])) {
      broadcastReconFinding(state.engagementId, {
        target: asset.hostname || asset.ip,
        port: typeof p.port === "number" ? p.port : parseInt(String(p.port)) || undefined,
        service: p.service || undefined,
        protocol: "tcp",
        tool: "scanforge_discovery",
      });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PHASE A.5: Cloud Asset Detection & Storage Enumeration
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const { detectCloudAsset, executeCloudStorageScan, getCloudDetectionPromptContext } = await import("./cloud-storage-scanner");
    addLog(state, {
      phase: "enumeration", type: "info",
      title: "☁️ Cloud Asset Detection",
      detail: "Analyzing discovery results for cloud-hosted infrastructure, storage endpoints, and misconfigured services",
    });
    let cloudAssetsFound = 0;
    let cloudStorageEndpoints = 0;
    let cloudFindings: Array<{ asset: string; provider: string; service: string; severity: string; title: string }> = [];
    for (const asset of state.assets) {
      const detection = detectCloudAsset({
        hostname: asset.hostname,
        ip: asset.ip,
        dnsRecords: (asset as any).dnsRecords,
        headers: (asset as any).headers,
        technologies: (asset as any).technologies,
        cnames: (asset as any).cnames,
        toolResults: (asset as any).toolResults,
      });
      if (detection.isCloudHosted) {
        cloudAssetsFound++;
        // Tag the asset with cloud metadata
        (asset as any).cloudProviders = detection.providers;
        (asset as any).cloudServices = detection.signatures.map(s => `${s.provider}:${s.service}`);
        addLog(state, {
          phase: "enumeration", type: "finding",
          title: `☁️ Cloud Asset: ${asset.hostname}`,
          detail: `Providers: ${detection.providers.join(", ")}\nServices: ${detection.signatures.map(s => `${s.provider} ${s.service} (${s.confidence})`).join(", ")}\nStorage endpoints: ${detection.storageEndpoints.length}`,
          data: { cloudDetection: detection },
        });
        // If storage endpoints found, run cloud storage scans
        if (detection.storageEndpoints.length > 0 || detection.scanSuggestions.length > 0) {
          cloudStorageEndpoints += detection.storageEndpoints.length;
          addLog(state, {
            phase: "enumeration", type: "scan_start",
            title: `☁️ Cloud Storage Scan: ${asset.hostname}`,
            detail: `Running ${detection.scanSuggestions.length} cloud-specific scans (${detection.storageEndpoints.join(", ")})`,
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
                title: finding.title,
              });
              // Add to asset vulns for downstream correlation (deduplicated)
              if (pushVulnDeduped(asset, {
                id: `cloud-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                severity: finding.severity,
                title: `[Cloud] ${finding.title}`,
                cve: finding.cve,
                description: finding.description,
                corroborationTier: 'confirmed',
                evidenceDetail: `Confirmed by cloud security scan`,
              })) {
                state.stats.vulnsFound++;
              }
            }
            // Store raw results for the engagement log
            for (const raw of scanResult.rawResults) {
              addLog(state, {
                phase: "enumeration", type: "scan_result",
                title: `Cloud Scan Result: ${raw.tool}`,
                detail: `Exit: ${raw.exitCode} | Duration: ${Math.round(raw.durationMs / 1000)}s\n${raw.stdout.slice(0, 500)}`,
                data: raw,
              });
            }
          } catch (cloudScanErr: any) {
            addLog(state, {
              phase: "enumeration", type: "error",
              title: `Cloud Scan Error: ${asset.hostname}`,
              detail: cloudScanErr.message,
            });
          }
        }
      }
    }
    // Store cloud detection summary in state for LLM attack planner
    (state as any).cloudDetection = {
      assetsFound: cloudAssetsFound,
      storageEndpoints: cloudStorageEndpoints,
      findings: cloudFindings,
      promptContext: cloudAssetsFound > 0 ? getCloudDetectionPromptContext() : undefined,
    };
    const severity_counts = cloudFindings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    addLog(state, {
      phase: "enumeration", type: cloudAssetsFound > 0 ? "phase_complete" : "info",
      title: cloudAssetsFound > 0
        ? `☁️ Cloud Detection Complete — ${cloudAssetsFound} cloud assets, ${cloudFindings.length} findings`
        : "☁️ Cloud Detection — No cloud assets detected",
      detail: cloudAssetsFound > 0
        ? `Providers: ${[...new Set(cloudFindings.map(f => f.provider))].join(", ")}\nFindings: ${JSON.stringify(severity_counts)}\nStorage endpoints scanned: ${cloudStorageEndpoints}`
        : "No cloud-hosted infrastructure identified in discovery results. Proceeding to Phase B.",
    });
  } catch (cloudDetectErr: any) {
    console.error("[CloudDetection] Error:", cloudDetectErr.message);
    addLog(state, {
      phase: "enumeration", type: "warning",
      title: "⚠️ Cloud Detection Skipped",
      detail: `Cloud asset detection encountered an error: ${cloudDetectErr.message}. Proceeding to Phase B.`,
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PHASE A.6: Context-Aware Target Profiling (WAF/CDN/topology detection)
  // ═══════════════════════════════════════════════════════════════════════════
  try {
    const {
      detectWAF, detectCDN, classifyAssetRole, selectEvasionProfile,
      generateScanStrategy, getDefaultScopeConstraints, buildTargetProfileContext,
    } = await import('./context-aware-scanner');
    type TargetProfile = import('./context-aware-scanner').TargetProfile;
    type TargetFingerprint = import('./context-aware-scanner').TargetFingerprint;
    type TopologyNode = import('./context-aware-scanner').TopologyNode;

    addLog(state, {
      phase: 'enumeration', type: 'info',
      title: '🔍 Phase A.6: Context-Aware Target Profiling',
      detail: 'Building target profiles from discovery data — detecting WAF, CDN, firewall, topology, and generating adaptive scan strategies',
    });

    if (!state.targetProfiles) state.targetProfiles = {};

    // Map orchestrator engagement type to context-aware scanner scope type
    const scopeTypeMap: Record<string, 'pentest' | 'red_team' | 'vuln_assessment' | 'bug_bounty'> = {
      pentest: 'pentest', red_team: 'red_team', purple_team: 'red_team',
      phishing: 'vuln_assessment', tabletop: 'vuln_assessment',
    };
    const scopeEngType = scopeTypeMap[state.engagementType] || 'pentest';
    const baseScopeConstraints = getDefaultScopeConstraints(scopeEngType);

    for (const asset of scopedAssets) {
      try {
        // ── Collect httpx response headers from tool results ──
        const httpxResult = asset.toolResults.find(tr => tr.tool === 'httpx');
        const responseHeaders: Record<string, string> = {
          ...((asset as any).httpxResponseHeaders || {}),
          ...(httpxResult?.fingerprints?.httpHeaders || {}),
        };
        if (httpxResult?.fingerprints?.webServer && !responseHeaders['server']) {
          responseHeaders['server'] = httpxResult.fingerprints.webServer;
        }

        // ── Extract cookies from response headers ──
        const cookies: string[] = httpxResult?.fingerprints?.cookies || [];
        if (responseHeaders['set-cookie']) {
          cookies.push(...responseHeaders['set-cookie'].split(/,\s*(?=[^;]*=)/));
        }

        // ── Extract status code from httpx output ──
        let statusCode = 200;
        if (httpxResult?.rawOutput) {
          const scMatch = httpxResult.rawOutput.match(/"status.code":(\d+)|"status_code":(\d+)/);
          if (scMatch) statusCode = parseInt(scMatch[1] || scMatch[2]);
        }

        // ── Build TargetFingerprint from all available data ──
        const technologies = asset.passiveRecon?.technologies || [];
        const webServerStr = httpxResult?.fingerprints?.webServer || responseHeaders['server'] || null;
        const poweredBy = httpxResult?.fingerprints?.poweredBy || responseHeaders['x-powered-by'] || null;

        // Parse web server name/version
        let webServerParsed: TargetFingerprint['webServer'] = null;
        if (webServerStr) {
          const wsMatch = webServerStr.match(/^([\w.-]+)\/?([\d.]+)?/);
          webServerParsed = {
            name: wsMatch?.[1] || webServerStr,
            version: wsMatch?.[2] || null,
            role: 'unknown',
          };
        }

        // Parse app framework from x-powered-by and technologies
        let appFramework: TargetFingerprint['appFramework'] = null;
        if (poweredBy) {
          const fwMatch = poweredBy.match(/^([\w.-]+)\/?([\d.]+)?/);
          const lang = /PHP/i.test(poweredBy) ? 'PHP'
            : /ASP/i.test(poweredBy) ? 'C#'
            : /Express|Node/i.test(poweredBy) ? 'JavaScript'
            : /JSF|Servlet/i.test(poweredBy) ? 'Java'
            : 'unknown';
          appFramework = { name: fwMatch?.[1] || poweredBy, version: fwMatch?.[2] || null, language: lang };
        }

        // Detect CMS from technologies
        let cms: TargetFingerprint['cms'] = null;
        const cmsNames = ['WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify', 'Wix', 'Squarespace', 'Ghost', 'Typo3', 'PrestaShop'];
        for (const cmsName of cmsNames) {
          const found = technologies.find(t => t.toLowerCase().includes(cmsName.toLowerCase()));
          if (found) {
            const vMatch = found.match(/([\d.]+)/);
            cms = { name: cmsName, version: vMatch?.[1] || null };
            break;
          }
        }

        // Detect languages from technologies
        const langPatterns: Record<string, RegExp> = {
          PHP: /php/i, Java: /java|jsp|servlet/i, Python: /python|django|flask/i,
          'C#': /asp\.net|c#/i, Ruby: /ruby|rails/i, JavaScript: /node|express|next|react|angular|vue/i,
          Go: /\bgo\b|golang/i, Rust: /\brust\b/i,
        };
        const detectedLangs: string[] = [];
        for (const [lang, pat] of Object.entries(langPatterns)) {
          if (technologies.some(t => pat.test(t)) || (poweredBy && pat.test(poweredBy))) {
            detectedLangs.push(lang);
          }
        }

        // Build TLS info from httpx fingerprints
        let tlsData: TargetFingerprint['tls'] = null;
        if (httpxResult?.fingerprints?.tlsInfo) {
          const ti = httpxResult.fingerprints.tlsInfo;
          tlsData = {
            version: ti.protocol || 'unknown',
            cipher: ti.cipherSuite || null,
            certIssuer: ti.issuerOrg || null,
            certExpiry: ti.notAfter || null,
            hsts: !!responseHeaders['strict-transport-security'],
            protocols: ti.protocol ? [ti.protocol] : [],
          };
        }

        // Build service banners from ScanForge discovery ports
        const serviceBanners: TargetFingerprint['serviceBanners'] = {};
        for (const p of asset.ports) {
          serviceBanners[p.port] = {
            service: p.service || 'unknown',
            version: p.version || null,
            banner: null,
            protocol: 'tcp',
          };
        }

        const fingerprint: TargetFingerprint = {
          serverHeader: webServerStr,
          webServer: webServerParsed,
          appFramework,
          cms,
          os: null, // OS detection requires deeper probing
          tls: tlsData,
          languages: detectedLangs,
          jsFrameworks: technologies.filter(t => /react|angular|vue|svelte|next|nuxt|gatsby/i.test(t)),
          databases: technologies.filter(t => /mysql|postgres|mongo|redis|elastic|sqlite|mariadb|oracle|mssql/i.test(t)),
          techTags: technologies,
          serviceBanners,
        };

        // ── Run WAF detection ──
        const wafProfile = detectWAF(responseHeaders, cookies, '', statusCode);
        if (wafProfile.detected) {
          asset.wafDetected = wafProfile.vendor || 'unknown';
          addLog(state, {
            phase: 'enumeration', type: 'waf_detected',
            title: `🛡️ WAF Detected: ${fmtTarget(asset)} → ${wafProfile.vendor} (${wafProfile.type})`,
            detail: `Confidence: ${wafProfile.confidence}% | Detection: ${wafProfile.detectionMethod}\nBypass techniques: ${wafProfile.bypassTechniques.slice(0, 3).join(', ')}`,
          });
        }

        // ── Run CDN detection ──
        const cnames = (asset as any).cnames || (asset.passiveRecon?.dnsRecords?.['CNAME'] || []);
        const cdnProfile = detectCDN(responseHeaders, cnames);
        if (cdnProfile.detected) {
          addLog(state, {
            phase: 'enumeration', type: 'info',
            title: `🌐 CDN Detected: ${fmtTarget(asset)} → ${cdnProfile.provider}`,
            detail: `Evidence: ${cdnProfile.evidence.join(', ')}${cdnProfile.originIp ? ` | Origin IP: ${cdnProfile.originIp}` : ''}${cdnProfile.hasBuiltInWAF ? ' | Has built-in WAF' : ''}`,
          });
        }

        // ── Classify asset role ──
        const openPorts = asset.ports.map(p => p.port);
        const roleResult = classifyAssetRole(fingerprint, openPorts, responseHeaders);

        // ── Build topology node ──
        const topologyNode: TopologyNode = {
          host: asset.hostname,
          role: roleResult.role,
          confidence: roleResult.confidence,
          backend: null,
          services: asset.ports.map(p => ({ port: p.port, service: p.service, version: p.version || null })),
          directlyReachable: true,
        };

        // ── Determine environment ──
        const cloudProviders = (asset as any).cloudProviders || [];
        const environment: TargetProfile['environment'] = cloudProviders.length > 0 ? 'cloud'
          : technologies.some(t => /docker|kubernetes|k8s|container/i.test(t)) ? 'containerized'
          : technologies.some(t => /lambda|serverless|cloud.function/i.test(t)) ? 'serverless'
          : 'traditional';

        // ── Determine risk profile ──
        const riskProfile: TargetProfile['riskProfile'] = wafProfile.detected && cdnProfile.detected ? 'high_security'
          : wafProfile.detected || cdnProfile.detected ? 'standard'
          : asset.ports.length > 20 ? 'legacy'
          : 'standard';

        // ── Build scope constraints ──
        const scopeConstraints = { ...baseScopeConstraints };
        if (cdnProfile.detected) scopeConstraints.sharedInfrastructure = true;
        if (wafProfile.detected) scopeConstraints.wafBypassAuthorized = scopeEngType === 'pentest' || scopeEngType === 'red_team';

        // ── Build partial profile (without strategy) ──
        const partialProfile: Omit<TargetProfile, 'recommendedStrategy'> = {
          hostname: asset.hostname,
          ips: asset.ip ? [asset.ip] : [],
          fingerprint,
          waf: wafProfile,
          cdn: cdnProfile,
          firewall: { detected: false, type: 'unknown', filteredPorts: [], rateLimiting: { detected: false, requestsPerSecond: null, burstLimit: null }, geoBlocking: false, ipReputationBlocking: false },
          topology: topologyNode,
          environment,
          riskProfile,
          scopeConstraints,
          profiledAt: Date.now(),
        };

        // ── Generate scan strategy ──
        const strategy = generateScanStrategy(partialProfile);

        // ── Store complete profile ──
        const fullProfile: TargetProfile = { ...partialProfile, recommendedStrategy: strategy };
        state.targetProfiles[asset.hostname] = fullProfile;

        addLog(state, {
          phase: 'enumeration', type: 'info',
          title: `📋 Profile: ${fmtTarget(asset)} → ${roleResult.role} (${environment})`,
          detail: `Strategy: ${strategy.name} (${strategy.riskLevel} risk, ~${strategy.estimatedTimeMinutes}min)\nEvasion: ${strategy.evasionProfile.name} (${strategy.evasionProfile.rateLimit} req/s)\nPhases: ${strategy.phases.map(p => p.name).join(' → ')}`,
        });
      } catch (profileErr: any) {
        addLog(state, {
          phase: 'enumeration', type: 'warning',
          title: `⚠️ Profiling Failed: ${fmtTarget(asset)}`,
          detail: `Context-aware profiling error: ${profileErr.message}. Proceeding with default scan strategy.`,
        });
      }
    }

    const profiledCount = Object.keys(state.targetProfiles).length;
    const wafCount = Object.values(state.targetProfiles).filter(p => p.waf.detected).length;
    const cdnCount = Object.values(state.targetProfiles).filter(p => p.cdn.detected).length;

    addLog(state, {
      phase: 'enumeration', type: 'phase_complete',
      title: `✅ Context-Aware Profiling Complete: ${profiledCount} targets profiled`,
      detail: `WAF detected: ${wafCount} | CDN detected: ${cdnCount}\nProfiles stored for adaptive Phase B tool selection and downstream vuln scanning.`,
    });
  } catch (profileEngineErr: any) {
    console.error('[ContextAwareScanner] Error:', profileEngineErr.message);
    addLog(state, {
      phase: 'enumeration', type: 'warning',
      title: '⚠️ Context-Aware Profiling Skipped',
      detail: `Profiling engine error: ${profileEngineErr.message}. Proceeding to Phase B with default strategies.`,
    });
  }
  // ═══════════════════════════════════════════════════════════════════════════
  // PHASE B: Targeted ScanForge + Tool Deployment (using enriched data)
  // ═══════════════════════════════════════════════════════════════════════════
  addLog(state, {
    phase: "enumeration", type: "info",
    title: "🎯 Phase B: Targeted Tool Deployment",
    detail: "Running targeted ScanForge discovery scripts and specialized tools per asset based on combined passive recon + discovery data",
  });

  const hasScanPlan = !!state.scanPlan?.assetPlans?.length;
  // Job Queue Bridge: route Phase B tool execution through Redis queue
  const { suggestToolCommands } = await import("./scan-server-executor");
  const roeScope_B = [...(state.roeScopeGuard?.authorizedDomains || []), ...(state.roeScopeGuard?.authorizedIps || [])];
  const engagementAbortSig_B = getEngagementAbortSignal(state.engagementId);
  const executeTool = (config: any) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope: roeScope_B, engagementAbortSignal: engagementAbortSig_B });

  for (const asset of state.assets) {
    if (asset.ports.length === 0) continue;
    // ═══ RoE SCOPE GUARD: Skip out-of-scope assets in Phase B ═══
    if (!isInRoeScope(state, asset.hostname, asset.ip)) {
      addLog(state, { phase: "enumeration", type: "warning", title: `🛡️ Skipped: ${asset.hostname} (out of scope)`, detail: "Asset not in RoE authorized target list" });
      continue;
    }
    // Classify asset type based on discovered portss
    const webPorts = asset.ports.filter(p =>
      ["http", "https", "http-proxy", "http-alt"].includes(p.service) ||
      [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port)
    );
    if (webPorts.length > 0) asset.type = "web_app";

    const target = getEffectiveTarget(asset, 'discovery');
    const httpTarget = getEffectiveTarget(asset, 'http');
    const assetPlan = state.scanPlan?.assetPlans.find(
      ap => ap.hostname === asset.hostname || ap.ip === target
    );
    // Auto-select the best scan tool for this asset in Phase B
    const { autoSelectTool: autoSelectToolB } = await import("./scanforge-discovery");
    const sfTool = autoSelectToolB({ targets: [target], stealthLevel: assetPlan?.evasionTechniques?.length ? 'medium' : 'minimal' });

    // Phase B targeted discovery: run deeper scripts on discovered ports
    if (assetPlan?.discoveryFlags) {
      // Sanitize LLM-generated flags: replace any -p port specs with actual discovered ports
      const discoveredPortList = asset.ports.map(p => p.port).join(',');
      let targetedFlags = assetPlan.discoveryFlags
        .replace(/(?:^|\s)-p\s*(?:\{[^}]+\}|[\d,\-]+)(?=\s|$)/g, '')  // Remove -p with any value (numeric or placeholder)
        .replace(/\s*-p-/g, '')           // Remove -p- (all ports)
        .replace(/\{[^}]+\}/g, '')        // Remove ALL {placeholder} strings
        .replace(/\s+/g, ' ')
        .trim();
      // Add discovered ports if any were found, otherwise use --top-ports 1000
      if (discoveredPortList) {
        targetedFlags = `${targetedFlags} -p ${discoveredPortList}`;
      } else {
        targetedFlags = `${targetedFlags} --top-ports 1000`;
      }
      addLog(state, {
        phase: 'enumeration', type: 'scan_start',
        title: `🎯 Targeted ScanForge: ${fmtTarget(asset, target)}`,
        detail: `Phase B flags: ${targetedFlags}\nRationale: ${assetPlan.discoveryRationale}`,
      });

      try {
        const startTime = Date.now();
        const discoveryArgs = `${targetedFlags} ${target}`;
        const discoveryResult = await executeTool({ tool: sfTool || 'naabu', args: discoveryArgs, timeoutSeconds: 300, sudo: true });
        const durationMs = Date.now() - startTime;

        // Parse targeted scan findings (vuln scripts, etc.)
        const findings = parseToolOutput('scanforge-discovery', discoveryResult.stdout || '', asset);

        // Store as toolResult
        asset.toolResults.push({
          tool: sfTool || 'naabu',
          command: `${sfTool} ${discoveryArgs}`,
          exitCode: discoveryResult.exitCode ?? 0,
          durationMs,
          timedOut: discoveryResult.timedOut || false,
          findingCount: findings.length,
          findings: findings.map(f => ({ severity: f.severity, title: f.title, cve: f.cve, evidence: f.evidence?.proofText || undefined, attack: f.evidence?.attackPayload || undefined, method: f.evidence?.request?.method || undefined, url: f.evidence?.request?.url || undefined, param: f.evidence?.vulnerableParam || undefined, matchedPattern: f.evidence?.matchedPattern || undefined })),
          outputPreview: (discoveryResult.stdout || '').slice(0, 1024),
          executedAt: Date.now(),
          phase: 'targeted_enum',
        });

        addLog(state, {
          phase: 'enumeration', type: 'scan_result',
          title: `Targeted ScanForge Complete: ${fmtTarget(asset, target)}`,
          detail: `${findings.length} findings from targeted scripts in ${Math.round(durationMs / 1000)}s`,
          data: { findings, outputPreview: (discoveryResult.stdout || '').slice(0, 500) },
        });

        // Persist targeted ScanForge discovery to database
        await persistScanResult({
          engagementId: state.engagementId,
          tool: sfTool || 'naabu',
          target,
          command: `${sfTool} ${discoveryArgs}`,
          stdout: discoveryResult.stdout || '',
          stderr: discoveryResult.stderr || '',
          exitCode: discoveryResult.exitCode ?? 0,
          durationMs,
          timedOut: discoveryResult.timedOut || false,
          findings,
          phase: 'targeted_enum',
        });

        // Add findings to asset vulns (deduplicated)
        for (const f of findings) {
          if (pushVulnDeduped(asset, { id: genId(), severity: f.severity, title: f.title, cve: f.cve, description: f.description, cvss: f.cvss, cwe: f.cwe, corroborationTier: 'confirmed', evidenceDetail: `Confirmed by active scan tool output`, rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4000) : undefined, source: 'active_scan' })) {
            state.stats.vulnsFound++;
          }
        }
      } catch (e: any) {
        addLog(state, { phase: 'enumeration', type: 'error', title: `Targeted ScanForge Failed: ${fmtTarget(asset, target)}`, detail: e.message });
      }
    }

    // Build unified tool command list: prefer scan plan, fallback to suggestToolCommands
    let cmdsToRun: Array<{ tool: string; command: string; purpose: string; priority: number }>;

    if (assetPlan && assetPlan.activeTools.length > 0) {
      cmdsToRun = assetPlan.activeTools.map(t => ({
        tool: t.tool,
        command: t.command
          .replace(/\{target\}/g, httpTarget)
          .replace(/\{[^}]*host[^}]*\}/gi, httpTarget)
          .replace(/\{[^}]*ip[^}]*\}/gi, httpTarget)
          .replace(/\{[^}]*naabu[^}]*\}/gi, '')  // Remove any naabu placeholders
          .replace(/\s+/g, ' ').trim(),
        purpose: t.rationale,
        priority: t.priority,
      }));
      addLog(state, {
        phase: "enumeration", type: "tool_match",
        title: `Scan Plan Tools: ${fmtTarget(asset)}`,
        detail: `${cmdsToRun.length} tools from LLM scan plan: ${cmdsToRun.map(c => c.tool).join(", ")}\nRisk: ${assetPlan.riskNotes}`,
        data: {
          source: 'scan_plan',
          tools: cmdsToRun.map(c => c.tool),
          commands: cmdsToRun.map(c => ({ tool: c.tool, purpose: c.purpose, priority: c.priority })),
          ports: asset.ports.map(p => `${p.port}/${p.service}`),
          assetType: asset.type,
          riskNotes: assetPlan.riskNotes,
        },
      });
    } else {
      const suggestedCmds = await suggestToolCommands({
        hostname: asset.hostname, ip: asset.ip, type: asset.type, ports: asset.ports,
      });
      cmdsToRun = suggestedCmds.map(c => ({
        tool: c.tool,
        command: `${c.tool} ${c.args}`,
        purpose: c.purpose,
        priority: c.priority,
      }));
      const toolNames = [...new Set(cmdsToRun.map(c => c.tool))];
      addLog(state, {
        phase: "enumeration", type: "tool_match",
        title: `Tool Match: ${fmtTarget(asset)}`,
        detail: `${cmdsToRun.length} commands queued using ${toolNames.length} tools: ${toolNames.join(", ")}`,
        data: {
          source: 'auto_suggest',
          tools: toolNames,
          commands: cmdsToRun.map(c => ({ tool: c.tool, purpose: c.purpose, priority: c.priority })),
          ports: asset.ports.map(p => `${p.port}/${p.service}`),
          assetType: asset.type,
        },
      });
    }

    // ── Merge context-aware strategy tools into command list ──
    const targetProfile = state.targetProfiles?.[asset.hostname];
    if (targetProfile?.recommendedStrategy) {
      const existingTools = new Set(cmdsToRun.map(c => c.tool));
      const strategyPhases = targetProfile.recommendedStrategy.phases;
      let augmentedCount = 0;
      for (const phase of strategyPhases) {
        for (const tool of phase.tools) {
          // Only add tools that aren't already in the command list
          if (!existingTools.has(tool.tool)) {
            const resolvedFlags = tool.flags
              .replace(/HOST|TARGET/g, httpTarget)
              .replace(/DISCOVERED_PORTS/g, asset.ports.map(p => p.port).join(','))
              .replace(/TARGET_URL/g, `https://${asset.hostname}`)
              .replace(/TARGET:PORT/g, `${asset.hostname}:443`);
            cmdsToRun.push({
              tool: tool.tool,
              command: `${tool.tool} ${resolvedFlags}`,
              purpose: `[Context-Aware] ${tool.purpose}`,
              priority: phase.requiresApproval ? 3 : 2,
            });
            existingTools.add(tool.tool);
            augmentedCount++;
          }
        }
      }
      if (augmentedCount > 0) {
        addLog(state, {
          phase: 'enumeration', type: 'info',
          title: `🧠 Context-Aware Augmentation: ${fmtTarget(asset)}`,
          detail: `Added ${augmentedCount} tools from ${targetProfile.recommendedStrategy.name} strategy (${targetProfile.recommendedStrategy.riskLevel} risk)\nEvasion: ${targetProfile.recommendedStrategy.evasionProfile.name} (${targetProfile.recommendedStrategy.evasionProfile.rateLimit} req/s)`,
        });
      }
    }
    // Execute priority 1 and 2 tool commands on the scan server
    // Skip subfinder for scoped engagements — targets are already defined, subfinder
    // discovers new subdomains outside scope. Keep it only for domain intelligence scans.
    const isScoped = state.assets.length > 0; // Scoped = operator defined targets
    const highPriorityCmds = cmdsToRun
      .filter(c => c.priority <= 2)
      .filter(c => {
        if (c.tool === 'subfinder' && isScoped) {
          addLog(state, {
            phase: 'enumeration', type: 'info',
            title: `Skipped: subfinder (scoped engagement)`,
            detail: `Subfinder skipped — targets are already defined in scope. Subfinder is only used for domain intelligence / unscoped discovery.`,
          });
          return false;
        }
        return true;
      });
    // ── Phase B command sanitization (applied to all commands before execution) ──
    for (const cmd of highPriorityCmds) {
      // Fix LLM-generated nuclei commands: ensure -u URL format with severity/tag filters
      if (cmd.tool === 'nuclei') {
        let nucleiCmd = cmd.command;
        // Strip ALL occurrences of 'nuclei' keyword — we'll re-add it once at the end
        // The LLM sometimes generates 'nuclei -u URL nuclei -severity...' (doubled)
        nucleiCmd = nucleiCmd.replace(/\bnuclei\b/g, '').trim();
        const targetMatch = nucleiCmd.match(/-(?:target|u)\s+(\S+)/) || nucleiCmd.match(/(https?:\/\/\S+)/);
        let nucleiTarget = targetMatch?.[1] || httpTarget;
        if (nucleiTarget && !nucleiTarget.startsWith('http')) {
          const webPorts = asset.ports.filter(p =>
            ['http', 'https', 'http-proxy', 'http-alt'].includes(p.service) ||
            [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port)
          );
          if (webPorts.length > 0) {
            const scheme = webPorts[0].port === 443 || webPorts[0].port === 8443 ? 'https' : 'http';
            nucleiTarget = `${scheme}://${nucleiTarget}:${webPorts[0].port}`;
          }
        }
        nucleiCmd = nucleiCmd.replace(/-target\s+\S+/g, '').replace(/-u\s+\S+/g, '').trim();
        if (!nucleiCmd.includes('-severity')) nucleiCmd += ' -severity critical,high,medium';
        if (!nucleiCmd.includes('-jsonl')) nucleiCmd += ' -jsonl';
        if (!nucleiCmd.includes('-nc')) nucleiCmd += ' -nc';
        if (!nucleiCmd.includes('-duc')) nucleiCmd += ' -duc';
        if (!nucleiCmd.includes('-ni')) nucleiCmd += ' -ni';
        if (!nucleiCmd.includes('-timeout')) nucleiCmd += ' -timeout 10';
        if (!nucleiCmd.includes('-retries')) nucleiCmd += ' -retries 1';
        const detectedTechs = asset.passiveRecon?.technologies || [];
        const techLower = detectedTechs.map((t: string) => t.toLowerCase());
        const techTags: string[] = [];
        if (techLower.some((t: string) => t.includes('wordpress'))) techTags.push('wordpress');
        if (techLower.some((t: string) => t.includes('nginx'))) techTags.push('nginx');
        if (techLower.some((t: string) => t.includes('apache'))) techTags.push('apache');
        if (techLower.some((t: string) => t.includes('php'))) techTags.push('php');
        if (techLower.some((t: string) => t.includes('node') || t.includes('next'))) techTags.push('nodejs');
        if (techLower.some((t: string) => t.includes('cloudfront') || t.includes('aws'))) techTags.push('aws');
        if (!nucleiCmd.includes('-tags') && techTags.length > 0) nucleiCmd += ` -tags ${techTags.join(',')}`;
        cmd.command = `nuclei -u ${nucleiTarget} ${nucleiCmd}`.replace(/\s+/g, ' ').trim();
      }

      // Fix LLM-generated httpx commands: convert -u single-URL mode to pipe mode
      if (cmd.tool === 'httpx') {
        // Normalize: strip ALL 'httpx' keywords, then detect if LLM included a pipe
        let httpxCmd = cmd.command.replace(/\bhttpx\b/g, '').trim();
        // If LLM already included a pipe (echo URL | flags), extract URL and flags separately
        const pipeMatch = httpxCmd.match(/^echo\s+(\S+)\s*\|\s*(.*)$/);
        if (pipeMatch) {
          const httpxUrl = pipeMatch[1];
          const httpxFlags = pipeMatch[2].replace(/\becho\b/g, '').replace(/\|/g, '').trim();
          cmd.command = `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, ' ').trim();
        } else {
          // No pipe — extract URL from -u flag or bare URL
          const urlMatch = httpxCmd.match(/-u\s+(\S+)/);
          if (urlMatch) {
            const httpxUrl = urlMatch[1];
            const httpxFlags = httpxCmd.replace(/-u\s+\S+/, '').trim();
            cmd.command = `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, ' ').trim();
          } else {
            const bareUrl = httpxCmd.match(/(https?:\/\/\S+)/);
            if (bareUrl) {
              const httpxUrl = bareUrl[1];
              const httpxFlags = httpxCmd.replace(/(https?:\/\/\S+)/, '').trim();
              cmd.command = `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, ' ').trim();
            } else {
              cmd.command = `httpx ${httpxCmd}`.replace(/\s+/g, ' ').trim();
            }
          }
        }
      }

      // Fix LLM-generated gobuster commands: use buildGobusterCommand() for profile-aware command generation
      if (cmd.tool === 'gobuster') {
        // Extract target URL from the LLM-generated command
        const gobUrlMatch = cmd.command.match(/-u\s+(\S+)/) || cmd.command.match(/(https?:\/\/\S+)/);
        const gobTargetUrl = gobUrlMatch?.[1] || httpTarget;

        // Gather runtime context for adaptive command building
        const wafDetected = !!(asset.wafDetected && asset.wafDetected !== 'none');
        const detectedTech = asset.passiveRecon?.technologies || [];
        const isApiTarget = asset.type === 'api' ||
          asset.ports.some(p => /api|graphql|rest/i.test(p.service || '')) ||
          /\/api\/|\/v[0-9]+\//i.test(gobTargetUrl);

        // Get auth cookie from confirmed credentials or training lab creds
        let authCookie = '';
        const webCreds = (asset.confirmedCredentials || []).filter((c: any) =>
          ['http', 'web', 'form', 'http-get', 'http-post-form'].includes(c.service)
        );
        if (webCreds.length > 0 && (webCreds[0] as any).sessionCookie) {
          authCookie = (webCreds[0] as any).sessionCookie;
        } else if ((asset as any).trainingLabCreds?.sessionCookie) {
          authCookie = (asset as any).trainingLabCreds.sessionCookie;
        }

        // ═══ TRAINING LAB AUTO-AUTH FOR GOBUSTER ═══
        // If no session cookie exists yet but this is a known training lab,
        // acquire one now so Gobuster can enumerate authenticated paths.
        // This runs during the enumeration phase (before vuln_detection acquires cookies for ZAP).
        if (!authCookie && state.trainingLabMode) {
          const hostname = asset.hostname.toLowerCase();
          const GOBUSTER_LAB_CREDS: Record<string, { username: string; password: string; loginPath: string; authType: 'form-csrf' | 'json-jwt' | 'form-simple' }> = {
            'dvwa': { username: 'admin', password: 'password', loginPath: '/login.php', authType: 'form-csrf' },
            'bwapp': { username: 'bee', password: 'bug', loginPath: '/login.php', authType: 'form-simple' },
            'juiceshop': { username: 'admin@juice-sh.op', password: 'admin123', loginPath: '/rest/user/login', authType: 'json-jwt' },
            'juice-shop': { username: 'admin@juice-sh.op', password: 'admin123', loginPath: '/rest/user/login', authType: 'json-jwt' },
            'webgoat': { username: 'guest', password: 'guest', loginPath: '/WebGoat/login', authType: 'form-simple' },
            'hackazon': { username: 'test_user', password: 'test_user', loginPath: '/user/login', authType: 'form-simple' },
            'mutillidae': { username: 'admin', password: 'admin', loginPath: '/index.php?page=login.php', authType: 'form-simple' },
            'bodgeit': { username: 'test@test.com', password: 'test', loginPath: '/bodgeit/login.jsp', authType: 'form-simple' },
            'broken-crystals': { username: 'john@mail.com', password: 'Admin123!', loginPath: '/api/auth/login', authType: 'json-jwt' },
            'brokencrystals': { username: 'john@mail.com', password: 'Admin123!', loginPath: '/api/auth/login', authType: 'json-jwt' },
          };

          let matchedLab: { key: string; creds: typeof GOBUSTER_LAB_CREDS[string] } | undefined;
          for (const [labKey, creds] of Object.entries(GOBUSTER_LAB_CREDS)) {
            if (hostname.includes(labKey.replace('-', ''))) {
              matchedLab = { key: labKey, creds };
              break;
            }
          }

          if (matchedLab) {
            try {
              const { executeTool } = await import('./scan-server-executor');
              const authBaseUrl = gobTargetUrl.replace(/\/[^/]*$/, '') || `http://${asset.hostname}`;

              if (matchedLab.creds.authType === 'json-jwt') {
                // JSON API login (Juice Shop, Broken Crystals)
                const loginResult = await executeTool({
                  tool: 'curl',
                  args: `-s -X POST ${authBaseUrl}${matchedLab.creds.loginPath} -H "Content-Type: application/json" -d '{"email":"${matchedLab.creds.username}","password":"${matchedLab.creds.password}"}'`,
                  timeout: 15,
                });
                if (loginResult.stdout) {
                  try {
                    const resp = JSON.parse(loginResult.stdout);
                    const token = resp.authentication?.token || resp.token || resp.access_token;
                    if (token) {
                      authCookie = `token=${token}`;
                      (asset as any).trainingLabCreds = { ...matchedLab.creds, sessionCookie: authCookie };
                      addLog(state, {
                        phase: 'enumeration', type: 'info',
                        title: `\u{1F511} Gobuster Auto-Auth: JWT acquired for ${matchedLab.key}`,
                        detail: `Logged in as ${matchedLab.creds.username} via ${matchedLab.creds.loginPath}. Gobuster will scan authenticated paths.`,
                      });
                    }
                  } catch { /* JSON parse failed */ }
                }
              } else if (matchedLab.creds.authType === 'form-csrf') {
                // DVWA-style: GET login page for CSRF token, then POST with cookie jar
                const getLogin = await executeTool({
                  tool: 'curl',
                  args: `-s -c /tmp/gobuster_auth_cookies.txt -b /tmp/gobuster_auth_cookies.txt ${authBaseUrl}${matchedLab.creds.loginPath}`,
                  timeout: 15,
                });
                const csrfMatch = getLogin.stdout?.match(/user_token.*?value=['"]([^'"]+)['"]/i);
                const csrfToken = csrfMatch?.[1] || '';
                const postLogin = await executeTool({
                  tool: 'curl',
                  args: `-s -c /tmp/gobuster_auth_cookies.txt -b /tmp/gobuster_auth_cookies.txt -X POST ${authBaseUrl}${matchedLab.creds.loginPath} -d "username=${matchedLab.creds.username}&password=${matchedLab.creds.password}&Login=Login&user_token=${csrfToken}" -D -`,
                  timeout: 15,
                });
                const sessionMatch = postLogin.stdout?.match(/PHPSESSID=([^;\s]+)/i);
                if (sessionMatch?.[1]) {
                  authCookie = `PHPSESSID=${sessionMatch[1]}; security=low`;
                  (asset as any).trainingLabCreds = { ...matchedLab.creds, sessionCookie: authCookie };
                  addLog(state, {
                    phase: 'enumeration', type: 'info',
                    title: `\u{1F511} Gobuster Auto-Auth: DVWA session acquired`,
                    detail: `Logged in as ${matchedLab.creds.username} with CSRF token handling. Gobuster will scan behind login wall.`,
                  });
                }
              } else {
                // Generic form POST login
                const loginResult = await executeTool({
                  tool: 'curl',
                  args: `-s -X POST ${authBaseUrl}${matchedLab.creds.loginPath} -d "username=${matchedLab.creds.username}&password=${matchedLab.creds.password}" -D -`,
                  timeout: 15,
                });
                const setCookie = loginResult.stdout?.match(/Set-Cookie:\s*([^\n]+)/i);
                if (setCookie?.[1]) {
                  authCookie = setCookie[1].split(';')[0].trim();
                  (asset as any).trainingLabCreds = { ...matchedLab.creds, sessionCookie: authCookie };
                  addLog(state, {
                    phase: 'enumeration', type: 'info',
                    title: `\u{1F511} Gobuster Auto-Auth: Session acquired for ${matchedLab.key}`,
                    detail: `Logged in as ${matchedLab.creds.username}. Gobuster will scan authenticated paths.`,
                  });
                }
              }
            } catch (authErr: any) {
              addLog(state, {
                phase: 'enumeration', type: 'warning',
                title: `Gobuster Auto-Auth Failed: ${matchedLab.key}`,
                detail: `Could not acquire session cookie for authenticated Gobuster scan: ${authErr.message}. Continuing unauthenticated.`,
              });
            }
          }
        }

        // Build the command using the scan profile helper
        const profile = getScanProfile(state.scanProfile || 'standard');
        cmd.command = buildGobusterCommand(profile, gobTargetUrl, {
          wafDetected,
          authCookie: authCookie || undefined,
          detectedTech,
          isApiTarget,
        });
      }

      // Fix LLM-generated nikto commands: ensure -ssl flag for HTTPS targets
      if (cmd.tool === 'nikto') {
        const niktoUrlMatch = cmd.command.match(/-h\s+(https?:\/\/\S+)/);
        if (niktoUrlMatch) {
          const niktoUrl = niktoUrlMatch[1];
          const isNiktoHttps = niktoUrl.startsWith('https://') || /:(443|8443|8444|8445|8447|9443)\b/.test(niktoUrl);
          if (isNiktoHttps && !cmd.command.includes('-ssl')) {
            cmd.command = cmd.command.replace(/-h\s+\S+/, `$& -ssl`);
          }
        }
        // ── Reverse-proxy vhost fix ──
        // When the asset is behind nginx virtual hosting (IP resolves to infra),
        // nikto needs -vhost to send the correct Host header. Without it, nginx
        // routes to the default server block (ScanForge dashboard) instead of
        // the intended target (e.g., Broken Crystals).
        if (!cmd.command.includes('-vhost') && asset.hostname && asset.ip && asset.hostname !== asset.ip) {
          if (KNOWN_INFRA_IPS.has(asset.ip)) {
            cmd.command += ` -vhost ${asset.hostname}`;
          }
        }
        // Ensure maxtime is set to prevent hanging
        if (!cmd.command.includes('-maxtime')) {
          cmd.command += ' -maxtime 300';
        }

        // ═══ TRAINING LAB AUTO-AUTH FOR NIKTO ═══
        // Inject session cookie from training lab auto-auth (acquired by Gobuster or earlier phase)
        // so Nikto scans authenticated paths behind the login wall.
        if (!cmd.command.includes('Cookie:') && !cmd.command.includes('-id ')) {
          let niktoCookie = '';
          // Check if Gobuster already acquired a session cookie for this asset
          if ((asset as any).trainingLabCreds?.sessionCookie) {
            niktoCookie = (asset as any).trainingLabCreds.sessionCookie;
          } else {
            // Check confirmed credentials for web session cookies
            const niktoWebCreds = (asset.confirmedCredentials || []).filter((c: any) =>
              ['http', 'web', 'form', 'http-get', 'http-post-form'].includes(c.service)
            );
            if (niktoWebCreds.length > 0 && (niktoWebCreds[0] as any).sessionCookie) {
              niktoCookie = (niktoWebCreds[0] as any).sessionCookie;
            }
          }
          if (niktoCookie) {
            // Nikto custom header injection for cookie-based auth
            cmd.command += ` -H "Cookie: ${niktoCookie}"`;
            addLog(state, {
              phase: 'enumeration', type: 'info',
              title: `\u{1F510} Nikto Auth: Session cookie injected for ${asset.hostname}`,
              detail: `Nikto will scan authenticated paths using the session acquired during auto-auth.`,
            });
          }
        }

        cmd.command = cmd.command.replace(/\s+/g, ' ').trim();
      }
    }

    // ── Apply evasion profile flags to all tool commands ──
    if (state.targetProfiles) {
      const targetProfile = state.targetProfiles[asset.hostname];
      if (targetProfile) {
        const { augmentCommandWithEvasion } = await import('./evasion-cli-adapter.js');
        for (const cmd of highPriorityCmds) {
          const augmentation = augmentCommandWithEvasion(cmd.tool, cmd.command, targetProfile);
          if (augmentation.flagsAdded.length > 0) {
            cmd.command = augmentation.augmentedCommand;
          }
        }
        const escalation = (targetProfile as any).evasionEscalation;
        if (escalation && escalation.currentLevel > 1) {
          addLog(state, {
            phase: 'enumeration', type: 'info',
            title: `🛡️ Evasion flags applied: ${fmtTarget(asset)}`,
            detail: `Level ${escalation.currentLevel}: Rate limits, headers, and timing adjusted for ${highPriorityCmds.length} tools`,
          });
        }
      }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PARALLEL TOOL EXECUTION — Run tools concurrently with concurrency limit
    // Shannon-inspired: run up to 3 tools in parallel per asset (SSH connection limit)
    // ═══════════════════════════════════════════════════════════════════════════
    const CONCURRENCY_LIMIT = 2;
    addLog(state, {
      phase: 'enumeration', type: 'info',
      title: `⚡ Parallel Execution: ${fmtTarget(asset)}`,
      detail: `Running ${highPriorityCmds.length} tools with concurrency=${CONCURRENCY_LIMIT} (${highPriorityCmds.map(c => c.tool).join(', ')})`,
    });

    // Execute a single tool command and return results
    async function executeToolCmd(cmd: { tool: string; command: string; purpose: string; priority: number }) {
      addLog(state, {
        phase: "enumeration", type: "scan_start",
        title: `Running: ${cmd.tool}`,
        detail: `${cmd.purpose} — ${cmd.command.slice(0, 120)}`,
        data: { tool: cmd.tool, fullCommand: cmd.command },
      });

      const toolTimeout = cmd.tool === 'nuclei' ? 300 : 180;
      let result: any;

      // Route pipe/raw commands through executeRawCommandViaQueue (not executeTool)
      // "raw" tool commands from suggestToolCommands use stdin piping (echo URL | tool)
      // and would be blocked by ALLOWED_TOOLS whitelist in executeTool.
      const isPipeCommand = (cmd.tool === 'raw') ||
        (cmd.tool === 'httpx' && cmd.command.includes('echo ')) ||
        (cmd.tool === 'nuclei' && cmd.command.includes('echo '));
      if (isPipeCommand) {
        // Strip the "raw " prefix if present — the shell command is the args, not "raw <args>"
        const rawCmd = cmd.command.startsWith('raw ') ? cmd.command.slice(4) : cmd.command;
        const startTimeRaw = Date.now();
        result = await executeRawCommandViaQueue(rawCmd + ' 2>&1', toolTimeout, { engagementId: state.engagementId });
        result.durationMs = Date.now() - startTimeRaw;
      } else {
        const cmdArgs = cmd.command.startsWith(cmd.tool)
          ? cmd.command.slice(cmd.tool.length).trim()
          : cmd.command;
        const startTime = Date.now();
        result = await executeTool({
          tool: cmd.tool,
          args: cmdArgs,
          timeoutSeconds: toolTimeout,
          engagementId: state.engagementId,
        });
        if (!result.durationMs) result.durationMs = Date.now() - startTime;
      }

      // Truncate stdout early to prevent holding multi-MB strings in memory
      // parseToolOutput only needs the structured lines, not raw bulk output
      if (result.stdout.length > 100_000) {
        result.stdout = result.stdout.slice(0, 100_000);
      }
      if (result.stderr && result.stderr.length > 50_000) {
        result.stderr = result.stderr.slice(0, 50_000);
      }
      // Parse tool output for findings
      const findings = parseToolOutput(cmd.tool, result.stdout, asset);

      // Store as toolResult on the asset
      asset.toolResults.push({
        tool: cmd.tool,
        command: cmd.command,
        exitCode: result.exitCode,
        durationMs: result.durationMs,
        timedOut: result.timedOut,
        findingCount: findings.length,
        findings: findings.map(f => ({ severity: f.severity, title: f.title, cve: f.cve, evidence: f.evidence?.proofText || undefined, attack: f.evidence?.attackPayload || undefined, method: f.evidence?.request?.method || undefined, url: f.evidence?.request?.url || undefined, param: f.evidence?.vulnerableParam || undefined, matchedPattern: f.evidence?.matchedPattern || undefined })),
        outputPreview: result.stdout.slice(0, 512),
        executedAt: Date.now(),
        phase: 'targeted_enum',
      });

      addLog(state, {
        phase: "enumeration", type: "scan_result",
        title: `${cmd.tool} Complete: ${fmtTarget(asset)}`,
        detail: `Exit code ${result.exitCode}, ${result.durationMs}ms, ${findings.length} findings${result.timedOut ? " (TIMED OUT)" : ""}`,
        data: {
          tool: cmd.tool, exitCode: result.exitCode, durationMs: result.durationMs,
          findings, outputPreview: result.stdout.slice(0, 500),
        },
      });

      // Persist to database
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
        phase: "targeted_enum",
      });

      // Add findings to asset vulns (deduplicated)
      let newCount = 0;
      for (const f of findings) {
        if (pushVulnDeduped(asset, { id: genId(), severity: f.severity, title: f.title, cve: f.cve, description: f.description, cvss: f.cvss, cwe: f.cwe, corroborationTier: 'confirmed', evidenceDetail: `Confirmed by ${cmd.tool} active scan`, rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4000) : undefined, source: cmd.tool })) {
          state.stats.vulnsFound++;
          newCount++;
        }
      }

      return { tool: cmd.tool, findings: newCount, timedOut: result.timedOut };
    }

    // Run tools in batches with concurrency limit
    const parallelStartTime = Date.now();
    for (let i = 0; i < highPriorityCmds.length; i += CONCURRENCY_LIMIT) {
      const batch = highPriorityCmds.slice(i, i + CONCURRENCY_LIMIT);
      const batchResults = await Promise.allSettled(
        batch.map(cmd => executeToolCmd(cmd).catch(e => {
          addLog(state, { phase: "enumeration", type: "error", title: `${cmd.tool} Error`, detail: e.message });
          return null;
        }))
      );
      // Log batch completion
      const succeeded = batchResults.filter(r => r.status === 'fulfilled' && r.value).length;
      const failed = batchResults.length - succeeded;
      if (batch.length > 1) {
        addLog(state, {
          phase: 'enumeration', type: 'info',
          title: `Batch ${Math.floor(i / CONCURRENCY_LIMIT) + 1} complete`,
          detail: `${succeeded}/${batch.length} tools finished (${failed} errors). Tools: ${batch.map(c => c.tool).join(', ')}`,
        });
      }
      // ── Memory relief between enumeration batches ──
      try {
        const { midScanCleanup } = await import('./memory-manager');
        midScanCleanup(state);
      } catch { if (global.gc) global.gc(); }
      const enumBatchMem = process.memoryUsage();
      const enumBatchHeapMB = enumBatchMem.heapUsed / 1024 / 1024;
      const enumHeapLimit = (global as any).__heapLimitMB || 768;
      if (enumBatchHeapMB > enumHeapLimit * 0.6) {
        console.warn(`[MemoryBackpressure] Enum batch: heap at ${enumBatchHeapMB.toFixed(0)}MB/${enumHeapLimit}MB — pausing 2s`);
        await new Promise(r => setTimeout(r, 2000));
        if (global.gc) global.gc();
      }
      // ── Auto-escalate evasion if tools are being blocked ──
      if (failed > 0 && state.targetProfiles) {
        try {
          const { escalateEvasionProfile: evaluateAndEscalate } = await import('./evasion-escalation-engine.js');
          const profile = state.targetProfiles[asset.hostname];
          if (profile) {
            // Check latest tool results for block indicators
            const recentResults = asset.toolResults.slice(-batch.length);
            for (const tr of recentResults) {
              const output = tr.outputPreview || '';
              const isBlocked = tr.exitCode !== 0 || tr.timedOut ||
                /403|blocked|captcha|rate.limit|connection.reset|ip.ban/i.test(output);
              if (isBlocked) {
                const blockReason = tr.timedOut ? 'rate_limit' as const :
                  /403|blocked|waf/i.test(output) ? 'waf_block' as const :
                  /captcha/i.test(output) ? 'captcha' as const :
                  /rate.limit/i.test(output) ? 'rate_limit' as const :
                  /connection.reset|rst/i.test(output) ? 'connection_reset' as const :
                  /ban/i.test(output) ? 'ip_ban' as const : 'waf_block' as const;
                const escalationResult = evaluateAndEscalate(profile, blockReason, { toolOutput: output });
                if (escalationResult.escalation.currentLevel > (profile.evasionEscalation?.currentLevel || 1)) {
                  state.targetProfiles[asset.hostname] = { ...profile, evasionEscalation: escalationResult.escalation };
                  addLog(state, {
                    phase: 'enumeration', type: 'warning',
                    title: `⚡ Evasion auto-escalated: ${asset.hostname}`,
                    detail: `Level ${escalationResult.escalation.currentLevel}: ${escalationResult.escalation.action} (trigger: ${blockReason})`,
                    riskTier: 'yellow',
                  });
                  break; // One escalation per batch is enough
                }
              }
            }
          }
        } catch (_e) { /* Non-critical — log and continue */ }
      }
    }
    const parallelDuration = Date.now() - parallelStartTime;
    addLog(state, {
      phase: 'enumeration', type: 'info',
      title: `⚡ Parallel execution complete: ${fmtTarget(asset)}`,
      detail: `${highPriorityCmds.length} tools finished in ${Math.round(parallelDuration / 1000)}s (parallel batches of ${CONCURRENCY_LIMIT})`,
    });

    // Persist state after each asset completes
    persistOpsStateDebounced(state.engagementId, 500);
  }

  state.progress = 35;
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
}

