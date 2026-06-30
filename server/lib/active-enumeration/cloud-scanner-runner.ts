/**
 * Phase 5 Sub-module: Cloud Asset Detection (Phase A.5)
 *
 * Detects cloud-hosted infrastructure and runs cloud storage scans:
 * - AWS/GCP/Azure provider detection
 * - S3/GCS/Blob storage enumeration
 * - Misconfigured cloud service detection
 */

import type { EnumerationHelpers, EngagementOpsState } from "./enumeration-context";
import { pushVulnDeduped } from "./enumeration-context";

/**
 * Detect cloud assets and run cloud storage scans on all assets.
 */
export async function runCloudAssetDetection(
  state: EngagementOpsState,
  helpers: EnumerationHelpers
): Promise<void> {
  try {
    const { detectCloudAsset, executeCloudStorageScan, getCloudDetectionPromptContext } =
      await import("../cloud-storage-scanner");

    helpers.addLog({
      phase: "enumeration",
      type: "info",
      title: "☁️ Cloud Asset Detection",
      detail: "Analyzing discovery results for cloud-hosted infrastructure, storage endpoints, and misconfigured services",
    });

    let cloudAssetsFound = 0;
    let cloudStorageEndpoints = 0;
    let cloudFindings: Array<{
      asset: string;
      provider: string;
      service: string;
      severity: string;
      title: string;
    }> = [];

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
        const providers = Array.from(new Set(detection.signatures.map((s: any) => s.provider)));
        (asset as any).cloudProviders = providers;
        (asset as any).cloudServices = detection.signatures.map(
          (s: any) => `${s.provider}:${s.service}`
        );

        helpers.addLog({
          phase: "enumeration",
          type: "finding",
          title: `☁️ Cloud Asset: ${asset.hostname}`,
          detail: `Providers: ${providers.join(", ")}\nServices: ${detection.signatures.map((s: any) => `${s.provider} ${s.service} (${s.confidence})`).join(", ")}\nStorage endpoints: ${detection.storageEndpoints.length}`,
          data: { cloudDetection: detection },
        });

        // Run cloud storage scans if endpoints found
        if (detection.storageEndpoints.length > 0 || detection.suggestedScans.length > 0) {
          cloudStorageEndpoints += detection.storageEndpoints.length;
          helpers.addLog({
            phase: "enumeration",
            type: "scan_start",
            title: `☁️ Cloud Storage Scan: ${asset.hostname}`,
            detail: `Running ${detection.suggestedScans.length} cloud-specific scans (${detection.storageEndpoints.join(", ")})`,
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
                title: finding.title,
              });
              if (
                pushVulnDeduped(asset, {
                  id: `cloud-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                  severity: finding.severity,
                  title: `[Cloud] ${finding.title}`,
                  cve: (finding as any).cve,
                  description: finding.description,
                  corroborationTier: "confirmed",
                  evidenceDetail: `Confirmed by cloud security scan`,
                })
              ) {
                state.stats.vulnsFound++;
              }
            }

            for (const raw of scanResult.rawResults) {
              helpers.addLog({
                phase: "enumeration",
                type: "scan_result",
                title: `Cloud Scan Result: ${raw.tool}`,
                detail: `Exit: ${raw.exitCode} | Duration: ${Math.round(raw.durationMs / 1000)}s\n${raw.stdout.slice(0, 500)}`,
                data: raw,
              });
            }
          } catch (cloudScanErr: any) {
            helpers.addLog({
              phase: "enumeration",
              type: "error",
              title: `Cloud Scan Error: ${asset.hostname}`,
              detail: cloudScanErr.message,
            });
          }
        }
      }
    }

    // Store cloud detection summary
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

    helpers.addLog({
      phase: "enumeration",
      type: cloudAssetsFound > 0 ? "phase_complete" : "info",
      title: cloudAssetsFound > 0
        ? `☁️ Cloud Detection Complete — ${cloudAssetsFound} cloud assets, ${cloudFindings.length} findings`
        : "☁️ Cloud Detection — No cloud assets detected",
      detail: cloudAssetsFound > 0
        ? `Providers: ${Array.from(new Set(cloudFindings.map((f) => f.provider))).join(", ")}\nFindings: ${JSON.stringify(severity_counts)}\nStorage endpoints scanned: ${cloudStorageEndpoints}`
        : "No cloud-hosted infrastructure identified in discovery results. Proceeding to Phase B.",
    });
  } catch (cloudDetectErr: any) {
    console.error("[CloudDetection] Error:", cloudDetectErr.message);
    helpers.addLog({
      phase: "enumeration",
      type: "warning",
      title: "⚠️ Cloud Detection Skipped",
      detail: `Cloud asset detection encountered an error: ${cloudDetectErr.message}. Proceeding to Phase B.`,
    });
  }
}
