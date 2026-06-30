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
  // PHASE B: Targeted Tool Deployment (using enriched data)
  // ═══════════════════════════════════════════════════════════════════════════
  await executeTargetedToolDeployment(state, helpers);

  // Final progress update
  state.progress = 35;
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
}
