/**
 * Phase 5: Active Enumeration — Sub-module barrel export
 *
 * This module decomposes the monolithic engagement-phase-enumeration.ts (2,087 lines)
 * into focused, testable sub-modules following the Phase 6/7/8 pattern.
 *
 * Sub-modules:
 * - dns-resolver.ts — DNS pre-resolution with training lab fallback
 * - port-discovery.ts — ScanForge multi-tool port scanning
 * - service-fingerprinter-runner.ts — Protocol probing + CVE enrichment
 * - httpx-prober.ts — HTTP probing + tech detection
 * - cloud-scanner-runner.ts — Cloud asset detection
 * - target-profiler.ts — Context-aware WAF/CDN/topology profiling
 * - targeted-tool-runner.ts — Phase B tool deployment + parallel execution
 */

export { resolveAssetDns } from "./dns-resolver";
export { executePortDiscovery } from "./port-discovery";
export { runServiceFingerprinting } from "./service-fingerprinter-runner";
export { runHttpxProbing } from "./httpx-prober";
export { runCloudAssetDetection } from "./cloud-scanner-runner";
export { runTargetProfiling } from "./target-profiler";
export { executeTargetedToolDeployment } from "./targeted-tool-runner";
export { buildEnumerationHelpers, type EnumerationHelpers, type EnumerationContext } from "./enumeration-context";
