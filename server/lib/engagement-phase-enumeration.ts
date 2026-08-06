/**
 * Phase 5: Active Discovery & Enumeration — Thin Orchestrator
 *
 * Delegates all heavy lifting to sub-modules under ./active-enumeration/.
 * This file coordinates the execution order and handles inter-phase transitions.
 *
 * Sub-modules:
 * - dns-resolver — DNS pre-resolution with training lab fallback
 * - port-discovery — ScanForge multi-tool port scanning + PCAP capture
 * - service-fingerprinter-runner — Protocol probing + CVE enrichment
 * - httpx-prober — HTTP probing + tech detection
 * - cloud-scanner-runner — Cloud asset detection & storage scanning
 * - target-profiler — Context-aware WAF/CDN/topology profiling
 * - targeted-tool-runner — Phase B tool deployment + parallel execution
 */

// ─── Types from shared module ──────────────────────────────────────────────
import { type EngagementOpsState, isInRoeScope } from "../../shared/orchestrator-types";
// ─── Runtime helpers from orchestrator ──────────────────────────────────────
import {
  addLog,
  broadcastOpsUpdate,
  broadcastReconFinding,
  getEffectiveTarget,
} from "./engagement-orchestrator";
// ─── Sub-modules ────────────────────────────────────────────────────────────
import {
  buildEnumerationHelpers,
  resolveAssetDns,
  executePortDiscovery,
  runCloudAssetDetection,
  runTargetProfiling,
  executeTargetedToolDeployment,
} from "./active-enumeration";

export async function executeEnumeration(
  state: EngagementOpsState,
  engagement: any,
  operatorCtx: { id: string; name?: string }
) {
  state.phase = "enumeration";
  state.currentAction = "Running enumeration & fingerprinting...";
  addLog(state, {
    phase: "enumeration",
    type: "info",
    title: "🔎 Phase 5: Active Discovery & Enumeration",
    detail:
      "Two-phase approach: Phase A discovery ScanForge discovery with evasion → Phase B targeted tool deployment",
  });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "enumeration" });

  // ═══ RoE SCOPE GUARD: Filter active scan targets to only authorized assets ═══
  const scopedAssets = state.assets.filter((a) => isInRoeScope(state, a.hostname, a.ip));
  const skippedAssets = state.assets.filter((a) => !isInRoeScope(state, a.hostname, a.ip));
  if (skippedAssets.length > 0) {
    addLog(state, {
      phase: "enumeration",
      type: "warning",
      title: `🛡️ Scope Guard: ${skippedAssets.length} assets excluded from active scanning`,
      detail: `Excluded: ${skippedAssets.map((a) => a.hostname).join(", ")}\nOnly RoE-authorized targets will be actively probed.`,
    });
  }

  // Build shared helpers object for sub-modules
  const helpers = buildEnumerationHelpers(state);

  // ═══════════════════════════════════════════════════════════════════════════
  // PHASE A: Discovery with Evasion Tactics
  // ═══════════════════════════════════════════════════════════════════════════

  // Step 0: DNS Pre-Resolution
  await resolveAssetDns(state, scopedAssets, helpers);

  // Build target list preserving asset identity
  const targets = scopedAssets.map((a) => ({
    scanTarget: getEffectiveTarget(a, "discovery"),
    assetHostname: a.hostname,
  }));

  // Step 1-3: Port Discovery + Service Fingerprinting + httpx Probing
  // (port-discovery internally handles fingerprinting and httpx per-asset)
  await executePortDiscovery(state, targets, helpers);

  // Phase A completion
  state.progress = 25;
  addLog(state, {
    phase: "enumeration",
    type: "phase_complete",
    title: "✅ Phase A Discovery Complete",
    detail: `${state.stats.hostsScanned} hosts scanned, ${state.stats.portsFound} ports discovered. Enriched data now available for Phase B targeted tool deployment.`,
  });
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });

  // Emit recon:finding events for port discovery results
  for (const asset of state.assets) {
    for (const p of asset.ports || []) {
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
  await runCloudAssetDetection(state, helpers);

  // ═══════════════════════════════════════════════════════════════════════════
  // PHASE A.6: Context-Aware Target Profiling (WAF/CDN/topology detection)
  // ═══════════════════════════════════════════════════════════════════════════
  await runTargetProfiling(state, scopedAssets, helpers);

  // ═══════════════════════════════════════════════════════════════════════════
  // PHASE B: Targeted Tool Deployment + FIRST BLOOD (parallel)
  // First Blood runs 4 fast-path attack lanes in parallel with Phase B tools
  // to deliver immediate findings while deeper enumeration continues.
  // ═══════════════════════════════════════════════════════════════════════════
  const firstBloodPromise = executeFirstBlood(state);
  await executeTargetedToolDeployment(state, helpers);

  // Await First Blood results (should already be done since it's fast-path)
  const firstBloodResults = await firstBloodPromise;
  if (firstBloodResults && firstBloodResults.findings.length > 0) {
    addLog(state, {
      phase: "enumeration",
      type: "phase_complete",
      title: `⚡ First Blood: ${firstBloodResults.findings.length} immediate findings`,
      detail: `Fast-path parallel scan found ${firstBloodResults.findings.filter((f: any) => f.severity === 'critical').length} critical, ` +
        `${firstBloodResults.findings.filter((f: any) => f.severity === 'high').length} high severity issues in ${firstBloodResults.durationMs}ms. ` +
        `Lanes: ${firstBloodResults.completedLanes.join(', ')}`,
    });
    broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
  }

  // Final progress update
  state.progress = 35;
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
}

/**
 * First Blood: Parallel fast-path pipeline that runs during active scanning.
 * Executes 4 attack lanes simultaneously to deliver immediate wins:
 * 1. Nuclei critical templates (top-100 CVEs)
 * 2. KEV exploit matching (known-exploited vulns)
 * 3. Credential spraying (default/weak creds)
 * 4. Cloud misconfig checks (S3, Azure blobs, GCP buckets)
 */
async function executeFirstBlood(state: EngagementOpsState) {
  const startTime = Date.now();
  try {
    const { executeFirstBlood: runFirstBlood } = await import('./first-blood-engine');
    const targets = state.assets
      .filter(a => a.hostname || a.ip)
      .map(a => a.hostname || a.ip);
    if (targets.length === 0) return null;

    addLog(state, {
      phase: "enumeration",
      type: "info",
      title: "⚡ First Blood: Fast-Path Attack Lanes Launched",
      detail: `Running 4 parallel attack lanes against ${targets.length} targets: Nuclei Critical, KEV Exploits, Credential Spray, Cloud Misconfig`,
    });

    const result = await runFirstBlood({
      targets,
      engagementId: state.engagementId,
      enabledLanes: ['nuclei_critical', 'kev_exploits', 'credential_spray', 'cloud_misconfig'],
    });

    // Merge First Blood findings into engagement state vulns
    for (const finding of result.findings) {
      const matchingAsset = state.assets.find(a =>
        a.hostname === finding.target || a.ip === finding.target
      );
      if (matchingAsset) {
        matchingAsset.vulns = matchingAsset.vulns || [];
        matchingAsset.vulns.push({
          id: finding.id,
          title: finding.title,
          severity: finding.severity,
          cve: finding.cve || undefined,
          source: `first_blood:${finding.lane}`,
          detail: finding.detail,
          remediation: finding.remediation,
        } as any);
        state.stats.vulnsFound = (state.stats.vulnsFound || 0) + 1;
      }
    }

    return {
      findings: result.findings,
      completedLanes: result.completedLanes,
      durationMs: Date.now() - startTime,
    };
  } catch (err: any) {
    console.warn(`[FirstBlood] Non-fatal error: ${err.message}`);
    addLog(state, {
      phase: "enumeration",
      type: "warning",
      title: "⚡ First Blood: Partial Failure",
      detail: `Some fast-path lanes failed: ${err.message}. Continuing with standard enumeration.`,
    });
    return null;
  }
}
