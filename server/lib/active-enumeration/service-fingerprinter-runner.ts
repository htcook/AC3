/**
 * Phase 5 Sub-module: Service Fingerprinting Runner (Phase A Step 2a)
 *
 * Runs protocol-specific probes on discovered ports:
 * - Fingerprint cache lookup
 * - Protocol probing for uncached ports
 * - CVE enrichment from vuln feeds
 * - Fingerprint diff against previous scans
 * - Banner-based WAF/IDS detection
 * - RDP/VoIP/Conferencing service scanning
 */

import type { EnumerationHelpers, EngagementOpsState } from "./enumeration-context";

/**
 * Run service fingerprinting on all discovered ports for an asset.
 * Includes CVE enrichment, diff detection, and banner WAF analysis.
 */
export async function runServiceFingerprinting(
  state: EngagementOpsState,
  asset: any,
  target: string,
  helpers: EnumerationHelpers
): Promise<void> {
  try {
    const { autoFingerprint, summarizeFingerprints } = await import("../service-fingerprinter");
    const { getCachedFingerprints, cacheFingerprints } = await import("../fingerprint-cache");
    const openPortNumbers = (asset.ports || []).map((p: any) => p.port);
    if (openPortNumbers.length === 0) return;

    // ── Check fingerprint cache first ──
    const cacheLookup = await getCachedFingerprints(target, openPortNumbers);
    const cacheNote =
      cacheLookup.hitCount > 0
        ? ` (✅ ${cacheLookup.hitCount} cached, ${cacheLookup.missCount} to probe)`
        : "";

    helpers.addLog({
      phase: "enumeration",
      type: "info",
      title: `🔍 Service Fingerprinting: ${helpers.fmtTarget(asset, target)}`,
      detail: `Running protocol-specific probes on ${openPortNumbers.length} ports: ${openPortNumbers.join(", ")}${cacheNote}`,
    });

    const fpStart = Date.now();
    let fpResults: any[];

    if (cacheLookup.uncachedPorts.length > 0) {
      const freshResults = await autoFingerprint(target, cacheLookup.uncachedPorts, {
        engagementId: state.engagementId,
        operatorId: state.operatorId,
        timeoutMs: 10000,
        tryDefaultCreds: (state.scanProfile || "standard") !== "stealth",
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

    // Merge fingerprint results into asset port data
    let upgraded = 0;
    for (const fp of fpResults) {
      if (fp.error) continue;
      const portEntry = asset.ports.find((p: any) => p.port === fp.port);
      if (portEntry) {
        if (fp.protocol) {
          portEntry.service = fp.protocol;
          (portEntry as any).serviceSource = "fingerprinted";
        }
        if (fp.product || fp.version) {
          portEntry.version = [fp.product, fp.version].filter(Boolean).join(" ");
        }
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
    (asset as any).fingerprintResults = fpResults;
    (asset as any).fingerprintSummary = summary;

    helpers.addLog({
      phase: "enumeration",
      type: "scan_result",
      title: `🔍 Fingerprinting Complete: ${helpers.fmtTarget(asset, target)}`,
      detail:
        `${summary.successfulProbes}/${summary.totalServices} services fingerprinted in ${Math.round(fpDuration / 1000)}s — ${upgraded} ports upgraded\n` +
        `Products: ${fpResults.filter((f: any) => f.product).map((f: any) => `${f.port}/${f.product} ${f.version || ""}`).join(", ") || "none detected"}\n` +
        `Risks: ${summary.criticalRisks} critical, ${summary.highRisks} high, ${summary.mediumRisks} medium` +
        (summary.servicesWithAnonymousAccess.length > 0
          ? `\n⚠️ Anonymous access: ${summary.servicesWithAnonymousAccess.map((s: any) => `${s.port}/${s.protocol}`).join(", ")}`
          : "") +
        (summary.servicesWithDefaultCreds.length > 0
          ? `\n🔑 Default credentials: ${summary.servicesWithDefaultCreds.map((s: any) => `${s.port}/${s.protocol}`).join(", ")}`
          : "") +
        (summary.allCves.length > 0
          ? `\n🛡️ Potential CVEs: ${summary.allCves.slice(0, 10).join(", ")}${summary.allCves.length > 10 ? ` (+${summary.allCves.length - 10} more)` : ""}`
          : ""),
      data: {
        fingerprintResults: fpResults.map((f: any) => ({
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

    // ── CVE Enrichment ──
    await enrichWithVulnFeeds(asset, target, fpResults, helpers);

    // ── Fingerprint Diff ──
    await computeFingerprintDiff(state, asset, target, fpResults, cacheLookup, helpers);

    // Re-run service resolution with enriched data
    helpers.enrichPortServices(asset.ports, (asset.passiveRecon as any)?.services || []);
  } catch (fpErr: any) {
    helpers.addLog({
      phase: "enumeration",
      type: "info",
      title: `🔍 Fingerprinting Skipped: ${helpers.fmtTarget(asset, target)}`,
      detail: `Service fingerprinting failed (non-blocking): ${fpErr.message}`,
    });
  }

  // ── Banner WAF/IDS Detection ──
  await detectBannerWaf(state, asset, target, helpers);

  // ── RDP/VoIP/Conferencing Scanning ──
  await scanRdpVoipServices(state, asset, target, helpers);
}

// ─── Internal helpers ───────────────────────────────────────────────────────

async function enrichWithVulnFeeds(
  asset: any,
  target: string,
  fpResults: any[],
  helpers: EnumerationHelpers
): Promise<void> {
  try {
    const { enrichFingerprintsWithVulnFeeds } = await import("../fingerprint-cve-enrichment");
    const { results: enrichedFps, summary: enrichSummary } =
      await enrichFingerprintsWithVulnFeeds(fpResults);
    (asset as any).fingerprintResults = enrichedFps;
    (asset as any).fingerprintCveEnrichment = enrichSummary;
    if (enrichSummary.enrichedCount > 0) {
      helpers.addLog({
        phase: "enumeration",
        type: "finding",
        title: `🛡️ CVE Enrichment: ${enrichSummary.totalCvesMatched} CVEs matched for ${helpers.fmtTarget(asset, target)}`,
        detail:
          `Vuln feeds matched ${enrichSummary.totalCvesMatched} CVEs across ${enrichSummary.enrichedCount} services\n` +
          `Exploitable: ${enrichSummary.exploitableCveCount} | CISA KEV: ${enrichSummary.kevCveCount} | Active 0-day: ${enrichSummary.zeroDayCveCount}\n` +
          `Risk Score: ${enrichSummary.overallRiskScore}/100 | Max Severity: ${enrichSummary.maxSeverity.toUpperCase()}\n` +
          `Priority targets: ${enrichSummary.perService.filter((s: any) => s.matchedCves.length > 0).slice(0, 3).map((s: any) => `${s.port}/${s.product || s.protocol} (${s.matchedCves.length} CVEs)`).join(", ")}`,
        data: { enrichSummary },
      });
    }
  } catch (enrichErr: any) {
    console.warn("[FP-CVE-Enrich] Non-blocking enrichment failed:", enrichErr.message);
  }
}

async function computeFingerprintDiff(
  state: EngagementOpsState,
  asset: any,
  target: string,
  fpResults: any[],
  cacheLookup: any,
  helpers: EnumerationHelpers
): Promise<void> {
  try {
    const { diffFingerprints, buildDiffSummaryText } = await import("../fingerprint-diff");

    const prevCached = cacheLookup.cached.map((c: any) => ({
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
      fingerprintedAt: c.fingerprintedAt || Date.now() - 86400000,
      engagementId: String(state.engagementId),
    }));

    if (prevCached.length > 0) {
      const diffReport = diffFingerprints(fpResults, prevCached, state.engagementId);
      (asset as any).fingerprintDiff = diffReport;

      if (diffReport.totalChanges > 0) {
        helpers.addLog({
          phase: "enumeration",
          type: diffReport.postureChange === "degraded" ? "finding" : "info",
          title: `📊 Fingerprint Diff: ${diffReport.totalChanges} changes for ${helpers.fmtTarget(asset, target)}`,
          detail:
            `Posture: ${diffReport.postureChange.toUpperCase()} | Risk Delta: ${diffReport.riskScoreDelta > 0 ? "+" : ""}${diffReport.riskScoreDelta}\n` +
            `New services: +${diffReport.newServices.length} | Removed: -${diffReport.removedServices.length} | Version changes: ${diffReport.versionChanges.length}\n` +
            `CVE delta: +${diffReport.cveDelta.newCves.length} new, -${diffReport.cveDelta.resolvedCves.length} resolved, ${diffReport.cveDelta.persistentCves.length} persistent\n` +
            (diffReport.changeBySeverity.critical > 0
              ? `⚠️ ${diffReport.changeBySeverity.critical} CRITICAL changes detected!\n`
              : "") +
            (diffReport.changeBySeverity.high > 0
              ? `⚠️ ${diffReport.changeBySeverity.high} HIGH changes detected\n`
              : ""),
          data: { diffReport },
        });
      }
    }
  } catch (diffErr: any) {
    console.warn("[FP-Diff] Non-blocking diff failed:", diffErr.message);
  }
}

async function detectBannerWaf(
  state: EngagementOpsState,
  asset: any,
  target: string,
  helpers: EnumerationHelpers
): Promise<void> {
  try {
    const { detectWafFromBanners, mergeBannerWafIntoAsset, generateEvasionProfile } = await import(
      "../banner-waf-detector"
    );
    const fpResults = (asset as any).fingerprintResults;
    if (!fpResults || fpResults.length === 0) return;

    const bannerWafSummary = detectWafFromBanners(fpResults);
    if (bannerWafSummary.detections.length > 0) {
      const { wafVendor, newDetections } = mergeBannerWafIntoAsset(
        asset.wafDetected,
        bannerWafSummary.detections
      );
      if (newDetections && wafVendor) {
        asset.wafDetected = wafVendor;
        state.stats.wafDetections = (state.stats.wafDetections || 0) + bannerWafSummary.detections.length;

        const evasionProfile = generateEvasionProfile(bannerWafSummary);
        (asset as any).bannerEvasionProfile = evasionProfile;
        (asset as any).bannerWafSummary = bannerWafSummary;

        const categoryBreakdown = bannerWafSummary.detections
          .map(
            (d: any) =>
              `${d.port}/${d.protocol}: ${d.vendor} ${d.product} [${d.category}] (${d.confidence}% confidence)`
          )
          .join("\n");

        helpers.addLog({
          phase: "enumeration",
          type: "waf_detected",
          title: `🛡️ Banner WAF/IDS Detected: ${helpers.fmtTarget(asset, target)} — ${bannerWafSummary.uniqueVendors.join(", ")}`,
          detail:
            `Security posture: ${bannerWafSummary.posture.replace("_", " ")}\n` +
            `Detections:\n${categoryBreakdown}\n` +
            `Evasion: rate=${evasionProfile.rateMultiplier}x, fragment=${evasionProfile.useFragmentation}, encrypt=${evasionProfile.useEncryption}\n` +
            `Recommendations: ${bannerWafSummary.evasionRecommendations.slice(0, 3).join("; ")}`,
          data: {
            detections: bannerWafSummary.detections.map((d: any) => ({
              vendor: d.vendor,
              product: d.product,
              category: d.category,
              port: d.port,
              confidence: d.confidence,
              matchedPattern: d.matchedPattern,
            })),
            posture: bannerWafSummary.posture,
            evasionProfile,
          },
        });
      }
    }
  } catch (bannerWafErr: any) {
    /* Banner WAF detection is best-effort */
  }
}

async function scanRdpVoipServices(
  state: EngagementOpsState,
  asset: any,
  target: string,
  helpers: EnumerationHelpers
): Promise<void> {
  try {
    const {
      isRdpVoipConferencingPort,
      getScanCommandsForService,
      getServiceForPort,
      buildExploitContextForLlm,
    } = await import("../knowledge/rdp-voip-conferencing-knowledge");

    const discoveredPorts = asset.ports || [];
    const CONFERENCING_WEB_PORTS = new Set([443, 8443]);
    const CONFERENCING_FINGERPRINTS = [
      "polycom", "telepresence", "zoom room", "crestron", "webex",
      "lifesize", "tandberg", "cisco meeting", "realpresence",
    ];

    const rdpVoipPorts = discoveredPorts.filter((p: any) => {
      if (["rdp", "sip", "sips", "h323", "sccp", "mgcp", "ms-wbt-server"].includes(p.service))
        return true;
      if (CONFERENCING_WEB_PORTS.has(p.port)) {
        const banner = ((p as any).banner || "").toLowerCase();
        const product = ((p as any).product || "").toLowerCase();
        const version = (p.version || "").toLowerCase();
        const combined = `${banner} ${product} ${version}`;
        return CONFERENCING_FINGERPRINTS.some((fp) => combined.includes(fp));
      }
      return isRdpVoipConferencingPort(p.port);
    });

    if (rdpVoipPorts.length > 0) {
      helpers.addLog({
        phase: "enumeration",
        type: "info",
        title: `🔌 RDP/VoIP/Conferencing Services Detected: ${helpers.fmtTarget(asset, target)}`,
        detail: `Found ${rdpVoipPorts.length} RDP/VoIP/conferencing services: ${rdpVoipPorts.map((p: any) => `${p.port}/${p.service}`).join(", ")}`,
      });

      for (const svcPort of rdpVoipPorts.slice(0, 5)) {
        const svcName = getServiceForPort(svcPort.port) || svcPort.service;
        const scanCmds = getScanCommandsForService(svcName, target, svcPort.port);
        for (const cmd of scanCmds.slice(0, 2)) {
          try {
            const svcResult = await helpers.executeTool({
              tool: cmd.tool,
              args: cmd.command.replace(cmd.tool + " ", ""),
              timeoutSeconds: cmd.timeout,
              sudo: cmd.tool === "masscan" || cmd.tool === "naabu",
            });
            if (svcResult.stdout) {
              helpers.addLog({
                phase: "enumeration",
                type: "scan_result",
                title: `${cmd.tool} ${svcName} scan: ${target}:${svcPort.port}`,
                detail: `${cmd.purpose}\n${(svcResult.stdout || "").slice(0, 1000)}`,
              });
            }
          } catch (svcErr: any) {
            /* best effort */
          }
        }
        if (!(asset as any).rdpVoipContext) (asset as any).rdpVoipContext = [];
        (asset as any).rdpVoipContext.push({
          port: svcPort.port,
          service: svcName,
          exploitContext: buildExploitContextForLlm({
            service: svcName,
            target,
            port: svcPort.port,
          }),
        });
      }
    }
  } catch (rdpVoipErr: any) {
    /* RDP/VoIP scanning is best-effort */
  }
}
