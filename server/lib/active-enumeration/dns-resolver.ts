/**
 * Phase 5 Sub-module: DNS Pre-Resolution
 *
 * Resolves hostnames to IPs before ScanForge discovery.
 * Handles training lab fallback (scan server domain resolution).
 */

import type { EnumerationHelpers, EngagementOpsState } from "./enumeration-context";

const SCAN_SERVER_DOMAIN = "scan.aceofcloud.io";

/**
 * Pre-resolve hostnames to IPs for all scoped assets.
 * ScanForge on the scan server may fail to resolve hostnames (e.g., training labs
 * hosted via path-based routing). Pre-resolve here and fall back to scan server IP.
 */
export async function resolveAssetDns(
  state: EngagementOpsState,
  scopedAssets: any[],
  helpers: EnumerationHelpers
): Promise<void> {
  const dns = await import("dns");
  const { promisify } = await import("util");
  const dnsResolve4 = promisify(dns.resolve4);
  const scanServerHost = process.env.SCAN_SERVER_HOST || "";

  helpers.addLog({
    phase: "enumeration",
    type: "info",
    title: `DNS Pre-Resolution: checking ${scopedAssets.length} assets`,
    detail: `Resolving hostnames to IPs before ScanForge scan`,
  });

  for (const asset of scopedAssets) {
    if (asset.ip) continue; // Already has an IP
    const hostname = asset.hostname;
    try {
      const ips = await dnsResolve4(hostname);
      if (ips.length > 0) {
        asset.ip = ips[0];
        helpers.addLog({
          phase: "enumeration",
          type: "info",
          title: `DNS Resolved: ${hostname}`,
          detail: `${hostname} → ${ips[0]}`,
        });
      }
    } catch (_dnsErr: any) {
      // DNS failed — check if this is a training lab hosted on the scan server
      const knownLabSubdomains = [
        "dvwa", "juice-shop", "juiceshop", "webgoat", "bwapp",
        "mutillidae", "vampi", "crapi", "hackazon",
      ];
      const hostnameBase = hostname.split(".")[0]?.toLowerCase() || "";
      const isLabOnScanServer =
        state.engagementType === "training_lab" ||
        (asset.passiveRecon as any)?.liveInstanceUrl?.includes(SCAN_SERVER_DOMAIN) ||
        (asset.passiveRecon as any)?.liveInstanceUrl?.includes(scanServerHost) ||
        (hostname.endsWith(".aceofcloud.io") && knownLabSubdomains.includes(hostnameBase)) ||
        hostname.includes(SCAN_SERVER_DOMAIN);

      if (isLabOnScanServer) {
        // Resolve scan server domain to get the IP
        try {
          const scanIps = await dnsResolve4(SCAN_SERVER_DOMAIN);
          if (scanIps.length > 0) {
            asset.ip = scanIps[0];
            helpers.addLog({
              phase: "enumeration",
              type: "info",
              title: `DNS Fallback: ${hostname} → scan server IP`,
              detail: `${hostname} failed DNS resolution. Training lab detected — using scan server IP ${scanIps[0]} (${SCAN_SERVER_DOMAIN})`,
            });
          }
        } catch {
          // Even scan server domain failed — try raw IP from env
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(scanServerHost)) {
            asset.ip = scanServerHost;
            helpers.addLog({
              phase: "enumeration",
              type: "info",
              title: `DNS Fallback: ${hostname} → scan server IP (env)`,
              detail: `Using SCAN_SERVER_HOST env IP: ${scanServerHost}`,
            });
          }
        }
      }

      if (!asset.ip) {
        helpers.addLog({
          phase: "enumeration",
          type: "warning",
          title: `⚠️ DNS Resolution Failed: ${hostname}`,
          detail: `Could not resolve ${hostname} to an IP address. ScanForge discovery may fail for this target.`,
        });
      }
    }
  }
}
