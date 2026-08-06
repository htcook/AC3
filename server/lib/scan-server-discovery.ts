/**
 * Scan Server Auto-Discovery
 * ─────────────────────────────────────────────────────────────────────────────
 * Dynamically discovers the ScanForge EC2 instance's current public IP using
 * the AWS EC2 DescribeInstances API. Eliminates the need to manually update
 * SCANFORGE_URL / SCAN_SERVER_HOST env vars when the instance IP changes.
 *
 * Discovery Strategy:
 *   1. If SCANFORGE_INSTANCE_ID env is set → query by instance ID (fastest)
 *   2. If SCANFORGE_TAG_NAME env is set → query by Name tag
 *   3. Fallback: query by Name tag "ac3-scanforge" (default convention)
 *
 * Results are cached with a 5-minute TTL. Health checks validate the cached IP.
 * If discovery fails, falls back to the static SCANFORGE_URL env var.
 */

import { ENV } from "../_core/env";

// ─── Configuration ──────────────────────────────────────────────────────────

const SCANFORGE_INSTANCE_ID = process.env.SCANFORGE_INSTANCE_ID || "";
const SCANFORGE_TAG_NAME = process.env.SCANFORGE_TAG_NAME || "ac3-scanforge";
const DISCOVERY_TTL_MS = 5 * 60 * 1000; // 5 minutes
const HEALTH_TIMEOUT_MS = 8_000;
const SCAN_PORT = 4443;

// ─── Cache ──────────────────────────────────────────────────────────────────

interface DiscoveryCache {
  ip: string;
  url: string;
  discoveredAt: number;
  healthy: boolean;
  lastHealthCheck: number;
  instanceId: string;
  instanceName: string;
  region: string;
}

let _cache: DiscoveryCache | null = null;
let _discoveryInProgress: Promise<DiscoveryCache | null> | null = null;

// ─── EC2 Discovery ──────────────────────────────────────────────────────────

async function discoverScanServerFromEC2(): Promise<DiscoveryCache | null> {
  try {
    const { EC2Client, DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");

    const accessKeyId = ENV.AWS_ACCESS_KEY_ID;
    const secretAccessKey = ENV.AWS_SECRET_ACCESS_KEY;
    const sessionToken = process.env.AWS_SESSION_TOKEN || "";
    if (!accessKeyId || !secretAccessKey) {
      console.warn("[ScanDiscovery] AWS credentials not configured — skipping EC2 discovery");
      return null;
    }

    const region = ENV.AWS_REGION || "us-east-1";
    const credentials: any = { accessKeyId, secretAccessKey };
    if (sessionToken) credentials.sessionToken = sessionToken;
    const ec2 = new EC2Client({ region, credentials });

    // Build filters based on available identifiers
    const filters: Array<{ Name: string; Values: string[] }> = [
      { Name: "instance-state-name", Values: ["running"] },
    ];

    let instanceIds: string[] | undefined;

    if (SCANFORGE_INSTANCE_ID) {
      // Direct instance ID lookup (fastest)
      instanceIds = [SCANFORGE_INSTANCE_ID];
    } else {
      // Tag-based lookup
      filters.push({ Name: "tag:Name", Values: [SCANFORGE_TAG_NAME] });
    }

    const result = await ec2.send(new DescribeInstancesCommand({
      Filters: filters,
      InstanceIds: instanceIds,
      MaxResults: instanceIds ? undefined : 5,
    }));

    // Find the first running instance with a public IP
    for (const reservation of result.Reservations || []) {
      for (const inst of reservation.Instances || []) {
        if (inst.PublicIpAddress && inst.State?.Name === "running") {
          const tags: Record<string, string> = {};
          for (const t of inst.Tags || []) {
            if (t.Key && t.Value) tags[t.Key] = t.Value;
          }

          const ip = inst.PublicIpAddress;
          const url = `https://${ip}:${SCAN_PORT}`;

          const cache: DiscoveryCache = {
            ip,
            url,
            discoveredAt: Date.now(),
            healthy: true, // Assume healthy until proven otherwise
            lastHealthCheck: 0,
            instanceId: inst.InstanceId || "",
            instanceName: tags["Name"] || inst.InstanceId || "",
            region,
          };

          console.log(`[ScanDiscovery] Discovered ScanForge at ${ip} (${cache.instanceName}, ${cache.instanceId})`);
          return cache;
        }
      }
    }

    console.warn("[ScanDiscovery] No running ScanForge instance found with public IP");
    return null;
  } catch (err: any) {
    console.error(`[ScanDiscovery] EC2 discovery failed: ${err.message}`);
    return null;
  }
}

// ─── Health Check ───────────────────────────────────────────────────────────

async function checkHealth(url: string): Promise<boolean> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), HEALTH_TIMEOUT_MS);
    // Use Node's native fetch with rejectUnauthorized disabled for self-signed certs
    const resp = await fetch(`${url}/health`, {
      signal: ctrl.signal,
      // @ts-ignore — Node fetch supports this
      dispatcher: undefined,
    });
    clearTimeout(timer);
    return resp.ok;
  } catch {
    return false;
  }
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Get the current ScanForge URL via auto-discovery.
 * Returns the discovered HTTPS URL (e.g., https://54.159.118.192:4443).
 * Falls back to SCANFORGE_URL env var if discovery fails.
 */
export async function getDiscoveredScanUrl(): Promise<string> {
  const now = Date.now();

  // Return cached result if still fresh
  if (_cache && (now - _cache.discoveredAt) < DISCOVERY_TTL_MS) {
    return _cache.url;
  }

  // Prevent concurrent discovery calls
  if (_discoveryInProgress) {
    const result = await _discoveryInProgress;
    return result?.url || getFallbackUrl();
  }

  _discoveryInProgress = (async () => {
    const discovered = await discoverScanServerFromEC2();
    if (discovered) {
      // Validate with health check
      const healthy = await checkHealth(discovered.url);
      discovered.healthy = healthy;
      discovered.lastHealthCheck = Date.now();

      if (!healthy) {
        console.warn(`[ScanDiscovery] Discovered IP ${discovered.ip} is unhealthy — will still use it (may recover)`);
      }

      _cache = discovered;
      return discovered;
    }
    return null;
  })();

  try {
    const result = await _discoveryInProgress;
    return result?.url || getFallbackUrl();
  } finally {
    _discoveryInProgress = null;
  }
}

/**
 * Get the discovered scan server IP address (just the IP, no protocol/port).
 */
export async function getDiscoveredScanIp(): Promise<string> {
  const now = Date.now();
  if (_cache && (now - _cache.discoveredAt) < DISCOVERY_TTL_MS) {
    return _cache.ip;
  }
  await getDiscoveredScanUrl(); // Triggers discovery
  return _cache?.ip || process.env.SCAN_SERVER_HOST || "";
}

/**
 * Get full infrastructure details for the scan server (for client whitelisting panel).
 */
export async function getScanServerInfo(): Promise<{
  ip: string;
  url: string;
  instanceId: string;
  instanceName: string;
  region: string;
  healthy: boolean;
  lastDiscovered: number;
  source: "ec2-discovery" | "env-fallback";
}> {
  await getDiscoveredScanUrl(); // Ensure discovery has run

  if (_cache) {
    // Refresh health if stale
    const now = Date.now();
    if (now - _cache.lastHealthCheck > 30_000) {
      _cache.healthy = await checkHealth(_cache.url);
      _cache.lastHealthCheck = now;
    }

    return {
      ip: _cache.ip,
      url: _cache.url,
      instanceId: _cache.instanceId,
      instanceName: _cache.instanceName,
      region: _cache.region,
      healthy: _cache.healthy,
      lastDiscovered: _cache.discoveredAt,
      source: "ec2-discovery",
    };
  }

  // Fallback
  const fallbackUrl = getFallbackUrl();
  const fallbackIp = extractIpFromUrl(fallbackUrl);
  return {
    ip: fallbackIp,
    url: fallbackUrl,
    instanceId: "",
    instanceName: "static-env-config",
    region: ENV.AWS_REGION || "us-east-1",
    healthy: false,
    lastDiscovered: 0,
    source: "env-fallback",
  };
}

/**
 * Force a fresh discovery (bypasses cache).
 * Use after instance replacement or when health checks fail repeatedly.
 */
export async function forceRediscovery(): Promise<string> {
  _cache = null;
  return getDiscoveredScanUrl();
}

/**
 * Get all platform infrastructure IPs for client whitelisting.
 * Returns EXTERNAL (public) IPs that targets will see during a pentest.
 * Internal/private IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x) are excluded
 * since they are not visible to targets.
 */
export async function getPlatformInfraIps(): Promise<Array<{
  role: string;
  ip: string;
  port: number | string;
  protocol: string;
  description: string;
  healthy: boolean | null;
  source: string;
}>> {
  const ips: Array<{
    role: string;
    ip: string;
    port: number | string;
    protocol: string;
    description: string;
    healthy: boolean | null;
    source: string;
  }> = [];

  // 1. Scan Server (auto-discovered via EC2 — uses Elastic IP)
  const scanInfo = await getScanServerInfo();
  if (scanInfo.ip && isPublicIp(scanInfo.ip)) {
    ips.push({
      role: "Scan Server (ScanForge)",
      ip: scanInfo.ip,
      port: SCAN_PORT,
      protocol: "HTTPS",
      description: "Primary scanning infrastructure — nmap, nuclei, ZAP, hydra, msfconsole, etc. All scan tools execute from this IP.",
      healthy: scanInfo.healthy,
      source: scanInfo.source,
    });
  }

  // 2. Platform NAT Gateway (ECS outbound traffic)
  // The ECS tasks run in a private subnet and exit via NAT gateway.
  // This is the IP targets see for platform-initiated connections (webhooks, API checks).
  const platformNatIp = process.env.PLATFORM_NAT_IP || "52.23.137.98";
  if (platformNatIp && isPublicIp(platformNatIp)) {
    ips.push({
      role: "AC3 Platform (ECS NAT)",
      ip: platformNatIp,
      port: "*",
      protocol: "TCP",
      description: "Platform outbound traffic (orchestration callbacks, API health checks, webhook deliveries)",
      healthy: true,
      source: "nat-gateway",
    });
  }

  // 3. C2 NAT Gateway (offensive infrastructure subnet)
  // C2 tools (Caldera, Metasploit listeners) in the isolated C2 subnet exit via this NAT.
  const c2NatIp = process.env.C2_NAT_IP || "98.91.65.223";
  if (c2NatIp && isPublicIp(c2NatIp)) {
    ips.push({
      role: "C2 Infrastructure (NAT)",
      ip: c2NatIp,
      port: "*",
      protocol: "TCP",
      description: "C2 subnet outbound — Caldera agents, Metasploit reverse shells, post-exploitation traffic",
      healthy: null,
      source: "nat-gateway",
    });
  }

  // 4. Caldera C2 (from env — use external IP only)
  const calderaUrl = process.env.CALDERA_BASE_URL || "";
  if (calderaUrl) {
    const calderaIp = extractIpFromUrl(calderaUrl);
    if (calderaIp && isPublicIp(calderaIp)) {
      ips.push({
        role: "MITRE Caldera C2",
        ip: calderaIp,
        port: extractPortFromUrl(calderaUrl) || 8888,
        protocol: "HTTP/HTTPS",
        description: "MITRE Caldera adversary emulation platform",
        healthy: null,
        source: "env",
      });
    }
  }

  // 5. Evilginx / Phishing Infrastructure
  const evilginxUrl = process.env.EVILGINX_BASE_URL || "";
  if (evilginxUrl) {
    const evilginxIp = extractIpFromUrl(evilginxUrl);
    if (evilginxIp && isPublicIp(evilginxIp)) {
      ips.push({
        role: "Evilginx (Phishing)",
        ip: evilginxIp,
        port: "443",
        protocol: "HTTPS",
        description: "Evilginx reverse proxy for credential harvesting (red team)",
        healthy: null,
        source: "env",
      });
    }
  }

  // 6. GoPhish
  const gophishUrl = process.env.GOPHISH_BASE_URL || "";
  if (gophishUrl) {
    const gophishIp = extractIpFromUrl(gophishUrl);
    if (gophishIp && isPublicIp(gophishIp)) {
      ips.push({
        role: "GoPhish (Phishing)",
        ip: gophishIp,
        port: extractPortFromUrl(gophishUrl) || 3333,
        protocol: "HTTPS",
        description: "GoPhish phishing campaign server",
        healthy: null,
        source: "env",
      });
    }
  }

  // 7. ZAP Proxy — runs ON the scan server, so same IP as scan bridge.
  // Only add separately if it's a different host.
  const zapUrl = process.env.ZAP_BASE_URL || "";
  if (zapUrl) {
    const zapIp = extractIpFromUrl(zapUrl);
    if (zapIp && isPublicIp(zapIp) && zapIp !== scanInfo.ip) {
      ips.push({
        role: "OWASP ZAP",
        ip: zapIp,
        port: extractPortFromUrl(zapUrl) || 8092,
        protocol: "HTTP",
        description: "OWASP ZAP web application scanner (DAST)",
        healthy: null,
        source: "env",
      });
    }
  }

  // 8. Wazuh SIEM (if configured)
  const wazuhIp = process.env.WAZUH_EXTERNAL_IP || "13.216.71.182";
  if (wazuhIp && isPublicIp(wazuhIp)) {
    ips.push({
      role: "Wazuh SIEM",
      ip: wazuhIp,
      port: "1514/1515",
      protocol: "TCP",
      description: "Wazuh manager — agent enrollment and event collection (monitoring, not scanning)",
      healthy: null,
      source: "env",
    });
  }

  return ips;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Returns true if the IP is a public (non-RFC1918, non-loopback) address.
 * Filters out 10.x.x.x, 172.16-31.x.x, 192.168.x.x, and 127.x.x.x.
 */
function isPublicIp(ip: string): boolean {
  if (!ip) return false;
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  // 10.0.0.0/8
  if (parts[0] === 10) return false;
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return false;
  // 127.0.0.0/8
  if (parts[0] === 127) return false;
  // 169.254.0.0/16 (link-local)
  if (parts[0] === 169 && parts[1] === 254) return false;
  return true;
}

function getFallbackUrl(): string {
  return process.env.SCANFORGE_URL
    || (process.env.SCAN_SERVER_HOST ? `https://${process.env.SCAN_SERVER_HOST}:${SCAN_PORT}` : "")
    || "https://scanforge.aceofcloud.io:4443";
}

function extractIpFromUrl(url: string): string {
  try {
    // Handle bare IPs
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url)) return url;
    // Handle URLs
    const match = url.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    return match ? match[1] : "";
  } catch {
    return "";
  }
}

function extractPortFromUrl(url: string): number | null {
  try {
    const u = new URL(url);
    return u.port ? parseInt(u.port, 10) : null;
  } catch {
    const match = url.match(/:(\d+)/);
    return match ? parseInt(match[1], 10) : null;
  }
}
