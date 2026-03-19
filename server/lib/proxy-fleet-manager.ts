/**
 * Proxy Fleet Manager
 * 
 * Manages DigitalOcean droplet-based proxy fleets for IP rotation during
 * red team engagements. Each engagement gets its own fleet of lightweight
 * SOCKS5 proxy nodes across configurable regions.
 * 
 * Features:
 * - Auto-provision DO droplets with microsocks SOCKS5 proxy via cloud-init
 * - Multi-region deployment (NYC, LON, SFO, AMS, SGP, BLR)
 * - Proxy health checking (connectivity, latency, IP reputation)
 * - Burned IP detection (connection resets, rate limits, WAF blocks)
 * - Auto-rotation when IPs get burned
 * - Fleet teardown on engagement completion
 * - Stealth scan profiles (slow/moderate/aggressive)
 * - Per-tool, per-phase proxy assignment
 */

import {
  createDroplet,
  deleteDroplet,
  getDroplet,
  listDroplets,
  listSshKeys,
  type DODroplet,
} from "./digitalocean-infra";

// ─── Types ───────────────────────────────────────────────────────────────────

export type ProxyRegion = "nyc1" | "nyc3" | "lon1" | "sfo3" | "ams3" | "sgp1" | "blr1" | "fra1" | "tor1" | "syd1";

export type FleetStatus = "provisioning" | "ready" | "active" | "degraded" | "tearing_down" | "destroyed";

export type ProxyNodeStatus = "provisioning" | "healthy" | "degraded" | "burned" | "destroyed";

export type StealthProfile = "slow" | "moderate" | "aggressive";

export type EngagementPhase = "recon" | "enumeration" | "vuln_detection" | "exploitation" | "post_exploit";

export interface ProxyNode {
  id: string;                    // Internal node ID
  dropletId: number;             // DigitalOcean droplet ID
  region: ProxyRegion;
  ip: string;                    // Public IPv4
  socksPort: number;             // SOCKS5 port (default 1080)
  status: ProxyNodeStatus;
  provisionedAt: number;         // UTC timestamp
  lastHealthCheck: number | null;
  latencyMs: number | null;
  requestsRouted: number;
  burnedAt: number | null;
  burnReason: string | null;
  assignedPhase: EngagementPhase | null;
  assignedTool: string | null;
}

export interface ProxyFleet {
  id: string;                    // Fleet ID
  engagementId: number;
  status: FleetStatus;
  stealthProfile: StealthProfile;
  nodes: ProxyNode[];
  createdAt: number;
  destroyedAt: number | null;
  totalCostEstimate: number;     // USD estimate
  burnedIps: BurnedIpRecord[];
  rotationLog: RotationLogEntry[];
}

export interface BurnedIpRecord {
  ip: string;
  region: ProxyRegion;
  burnedAt: number;
  reason: string;
  detectionMethod: "connection_reset" | "rate_limit" | "waf_block" | "timeout" | "manual";
  replacementIp: string | null;
}

export interface RotationLogEntry {
  timestamp: number;
  oldIp: string;
  newIp: string;
  reason: string;
  phase: EngagementPhase;
  tool: string;
}

export interface StealthConfig {
  requestsPerSecond: number;
  delayBetweenToolsMs: number;
  maxConcurrentScans: number;
  userAgentRotation: boolean;
  headerRandomization: boolean;
  requestFragmentation: boolean;
  jitterMs: [number, number];    // [min, max] random delay added per request
  description: string;
}

export interface FleetProvisionOptions {
  engagementId: number;
  regions: ProxyRegion[];
  nodesPerRegion: number;
  stealthProfile: StealthProfile;
  dropletSize?: string;
  sshKeyIds?: number[];
}

export interface ProxyAssignment {
  proxyUrl: string;              // socks5://ip:port
  nodeId: string;
  ip: string;
  region: ProxyRegion;
}

// ─── Stealth Profiles ────────────────────────────────────────────────────────

export const STEALTH_PROFILES: Record<StealthProfile, StealthConfig> = {
  slow: {
    requestsPerSecond: 1,
    delayBetweenToolsMs: 30000,
    maxConcurrentScans: 1,
    userAgentRotation: true,
    headerRandomization: true,
    requestFragmentation: true,
    jitterMs: [500, 3000],
    description: "Maximum stealth — 1 req/s, single concurrent scan, full evasion. Use for initial recon against hardened targets with active SOC monitoring.",
  },
  moderate: {
    requestsPerSecond: 10,
    delayBetweenToolsMs: 5000,
    maxConcurrentScans: 3,
    userAgentRotation: true,
    headerRandomization: true,
    requestFragmentation: false,
    jitterMs: [100, 1000],
    description: "Balanced — 10 req/s, 3 concurrent scans, UA rotation. Standard profile for most engagements.",
  },
  aggressive: {
    requestsPerSecond: 50,
    delayBetweenToolsMs: 1000,
    maxConcurrentScans: 10,
    userAgentRotation: false,
    headerRandomization: false,
    requestFragmentation: false,
    jitterMs: [0, 100],
    description: "Full speed — 50 req/s, 10 concurrent scans, minimal evasion. Use for lab environments or when speed > stealth.",
  },
};

// ─── In-Memory Fleet Registry ────────────────────────────────────────────────

const activeFleets = new Map<number, ProxyFleet>();

// ─── Cloud-Init User Data ────────────────────────────────────────────────────

function generateProxyUserData(socksPort: number = 1080): string {
  return `#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# System hardening
apt-get update -qq && apt-get upgrade -y -qq
apt-get install -y -qq ufw fail2ban build-essential git curl

# Disable password auth
sed -i 's/#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl restart sshd

# Install microsocks (lightweight SOCKS5 proxy)
cd /tmp
git clone https://github.com/rofl0r/microsocks.git
cd microsocks
make && make install

# Create systemd service for microsocks
cat > /etc/systemd/system/microsocks.service <<EOF
[Unit]
Description=MicroSOCKS5 Proxy
After=network.target
[Service]
ExecStart=/usr/local/bin/microsocks -p ${socksPort}
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now microsocks

# Firewall — only allow SSH and SOCKS5
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow ${socksPort}/tcp
ufw --force enable

# Health check endpoint via socat
apt-get install -y -qq socat
cat > /etc/systemd/system/health-check.service <<EOF
[Unit]
Description=Health Check HTTP
After=network.target
[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:8080,reuseaddr,fork EXEC:'/bin/echo -e "HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\n\\r\\nok"'
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now health-check

echo "Proxy node ready — SOCKS5 on port ${socksPort}, health on 8080"
`;
}

// ─── Fleet Lifecycle ─────────────────────────────────────────────────────────

/**
 * Provision a new proxy fleet for an engagement.
 * Creates droplets across specified regions with SOCKS5 proxies.
 */
export async function provisionFleet(opts: FleetProvisionOptions): Promise<ProxyFleet> {
  const fleetId = `fleet-${opts.engagementId}-${Date.now().toString(36)}`;
  const socksPort = 1080;
  const dropletSize = opts.dropletSize || "s-1vcpu-512mb-10gb"; // $4/month — smallest

  // Get SSH keys if not provided
  let sshKeyIds = opts.sshKeyIds;
  if (!sshKeyIds || sshKeyIds.length === 0) {
    const keys = await listSshKeys();
    sshKeyIds = keys.map(k => k.id);
  }

  const fleet: ProxyFleet = {
    id: fleetId,
    engagementId: opts.engagementId,
    status: "provisioning",
    stealthProfile: opts.stealthProfile,
    nodes: [],
    createdAt: Date.now(),
    destroyedAt: null,
    totalCostEstimate: 0,
    burnedIps: [],
    rotationLog: [],
  };

  activeFleets.set(opts.engagementId, fleet);

  // Provision droplets across regions
  const provisionPromises: Promise<void>[] = [];

  for (const region of opts.regions) {
    for (let i = 0; i < opts.nodesPerRegion; i++) {
      const nodeName = `proxy-${opts.engagementId}-${region}-${i}`;
      const nodeId = `node-${region}-${i}-${Date.now().toString(36)}`;

      const promise = (async () => {
        try {
          const droplet = await createDroplet({
            name: nodeName,
            region,
            size: dropletSize,
            image: "ubuntu-22-04-x64",
            sshKeys: sshKeyIds,
            tags: [`fleet:${fleetId}`, `engagement:${opts.engagementId}`, "proxy-fleet"],
            userData: generateProxyUserData(socksPort),
            monitoring: true,
          });

          const node: ProxyNode = {
            id: nodeId,
            dropletId: droplet.id,
            region,
            ip: droplet.ipv4Public || "",
            socksPort,
            status: "provisioning",
            provisionedAt: Date.now(),
            lastHealthCheck: null,
            latencyMs: null,
            requestsRouted: 0,
            burnedAt: null,
            burnReason: null,
            assignedPhase: null,
            assignedTool: null,
          };

          fleet.nodes.push(node);
        } catch (err: any) {
          console.error(`[ProxyFleet] Failed to provision ${nodeName}: ${err.message}`);
        }
      })();

      provisionPromises.push(promise);
    }
  }

  await Promise.all(provisionPromises);

  // Estimate cost: $4/month per droplet ≈ $0.006/hour
  fleet.totalCostEstimate = fleet.nodes.length * 0.006;

  // Start health check polling to wait for nodes to come online
  pollFleetHealth(fleet).catch(err =>
    console.error(`[ProxyFleet] Health poll error: ${err.message}`)
  );

  return fleet;
}

/**
 * Poll droplet status until all nodes have public IPs and SOCKS5 is reachable.
 */
async function pollFleetHealth(fleet: ProxyFleet, maxWaitMs: number = 300000): Promise<void> {
  const start = Date.now();
  const pollInterval = 15000; // 15 seconds

  while (Date.now() - start < maxWaitMs) {
    let allReady = true;

    for (const node of fleet.nodes) {
      if (node.status === "burned" || node.status === "destroyed") continue;

      try {
        const droplet = await getDroplet(node.dropletId);

        // Update IP if we don't have it yet
        if (!node.ip && droplet.ipv4Public) {
          node.ip = droplet.ipv4Public;
        }

        if (droplet.status === "active" && node.ip) {
          // Check SOCKS5 health
          const healthy = await checkProxyHealth(node);
          if (healthy) {
            node.status = "healthy";
            node.lastHealthCheck = Date.now();
          } else {
            allReady = false;
          }
        } else {
          allReady = false;
        }
      } catch {
        allReady = false;
      }
    }

    if (allReady && fleet.nodes.length > 0) {
      fleet.status = "ready";
      return;
    }

    await new Promise(r => setTimeout(r, pollInterval));
  }

  // Partial readiness
  const healthyCount = fleet.nodes.filter(n => n.status === "healthy").length;
  fleet.status = healthyCount > 0 ? "degraded" : "provisioning";
}

/**
 * Check if a proxy node's SOCKS5 service is reachable.
 */
async function checkProxyHealth(node: ProxyNode): Promise<boolean> {
  if (!node.ip) return false;

  try {
    // Check the health endpoint first (faster than SOCKS5 handshake)
    const start = Date.now();
    const res = await fetch(`http://${node.ip}:8080/`, {
      signal: AbortSignal.timeout(5000),
    });
    node.latencyMs = Date.now() - start;
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Get the active fleet for an engagement.
 */
export function getFleet(engagementId: number): ProxyFleet | null {
  return activeFleets.get(engagementId) || null;
}

/**
 * Get all active fleets.
 */
export function getAllFleets(): ProxyFleet[] {
  return Array.from(activeFleets.values());
}

/**
 * Destroy a fleet — delete all droplets and clean up.
 */
export async function destroyFleet(engagementId: number): Promise<{ destroyed: number; errors: string[] }> {
  const fleet = activeFleets.get(engagementId);
  if (!fleet) return { destroyed: 0, errors: ["No fleet found for this engagement"] };

  fleet.status = "tearing_down";
  const errors: string[] = [];
  let destroyed = 0;

  for (const node of fleet.nodes) {
    if (node.status === "destroyed") continue;
    try {
      await deleteDroplet(node.dropletId);
      node.status = "destroyed";
      destroyed++;
    } catch (err: any) {
      errors.push(`Failed to destroy ${node.id} (droplet ${node.dropletId}): ${err.message}`);
    }
  }

  fleet.status = "destroyed";
  fleet.destroyedAt = Date.now();

  return { destroyed, errors };
}

// ─── IP Rotation ─────────────────────────────────────────────────────────────

/**
 * Mark an IP as burned and auto-rotate to a replacement.
 */
export async function burnAndRotate(
  engagementId: number,
  nodeId: string,
  reason: string,
  detectionMethod: BurnedIpRecord["detectionMethod"],
  phase: EngagementPhase,
  tool: string,
): Promise<{ success: boolean; newNode?: ProxyNode; error?: string }> {
  const fleet = activeFleets.get(engagementId);
  if (!fleet) return { success: false, error: "No fleet found" };

  const node = fleet.nodes.find(n => n.id === nodeId);
  if (!node) return { success: false, error: "Node not found" };

  // Mark as burned
  node.status = "burned";
  node.burnedAt = Date.now();
  node.burnReason = reason;

  const burnRecord: BurnedIpRecord = {
    ip: node.ip,
    region: node.region,
    burnedAt: Date.now(),
    reason,
    detectionMethod,
    replacementIp: null,
  };

  // Provision a replacement in the same region
  try {
    const sshKeys = await listSshKeys();
    const replacement = await createDroplet({
      name: `proxy-${engagementId}-${node.region}-replacement-${Date.now().toString(36)}`,
      region: node.region,
      size: "s-1vcpu-512mb-10gb",
      image: "ubuntu-22-04-x64",
      sshKeys: sshKeys.map(k => k.id),
      tags: [`fleet:${fleet.id}`, `engagement:${engagementId}`, "proxy-fleet", "replacement"],
      userData: generateProxyUserData(node.socksPort),
      monitoring: true,
    });

    const newNode: ProxyNode = {
      id: `node-${node.region}-repl-${Date.now().toString(36)}`,
      dropletId: replacement.id,
      region: node.region,
      ip: replacement.ipv4Public || "",
      socksPort: node.socksPort,
      status: "provisioning",
      provisionedAt: Date.now(),
      lastHealthCheck: null,
      latencyMs: null,
      requestsRouted: 0,
      burnedAt: null,
      burnReason: null,
      assignedPhase: node.assignedPhase,
      assignedTool: node.assignedTool,
    };

    fleet.nodes.push(newNode);
    burnRecord.replacementIp = newNode.ip;

    fleet.burnedIps.push(burnRecord);
    fleet.rotationLog.push({
      timestamp: Date.now(),
      oldIp: node.ip,
      newIp: newNode.ip || "(provisioning)",
      reason,
      phase,
      tool,
    });

    // Destroy the burned droplet
    try {
      await deleteDroplet(node.dropletId);
      node.status = "destroyed";
    } catch {}

    return { success: true, newNode };
  } catch (err: any) {
    fleet.burnedIps.push(burnRecord);
    return { success: false, error: `Replacement failed: ${err.message}` };
  }
}

/**
 * Get the next available proxy for a given phase and tool.
 * Implements round-robin across healthy nodes, preferring nodes in different regions.
 */
let rotationIndex = 0;

export function getNextProxy(
  engagementId: number,
  phase: EngagementPhase,
  tool: string,
): ProxyAssignment | null {
  const fleet = activeFleets.get(engagementId);
  if (!fleet) return null;

  const healthyNodes = fleet.nodes.filter(n => n.status === "healthy");
  if (healthyNodes.length === 0) return null;

  // Round-robin selection
  const node = healthyNodes[rotationIndex % healthyNodes.length];
  rotationIndex++;

  // Track assignment
  node.assignedPhase = phase;
  node.assignedTool = tool;
  node.requestsRouted++;

  return {
    proxyUrl: `socks5://${node.ip}:${node.socksPort}`,
    nodeId: node.id,
    ip: node.ip,
    region: node.region,
  };
}

/**
 * Get all proxy URLs for a fleet (for tools that accept proxy lists).
 */
export function getAllProxyUrls(engagementId: number): string[] {
  const fleet = activeFleets.get(engagementId);
  if (!fleet) return [];

  return fleet.nodes
    .filter(n => n.status === "healthy")
    .map(n => `socks5://${n.ip}:${n.socksPort}`);
}

// ─── Burned IP Detection ─────────────────────────────────────────────────────

export interface BurnDetectionResult {
  burned: boolean;
  reason: string;
  detectionMethod: BurnedIpRecord["detectionMethod"];
  confidence: "high" | "medium" | "low";
}

/**
 * Analyze a scan/exploit response to detect if the source IP has been burned.
 */
export function detectBurnedIp(response: {
  statusCode?: number;
  body?: string;
  error?: string;
  responseTimeMs?: number;
  consecutiveFailures?: number;
}): BurnDetectionResult {
  // Connection reset — high confidence burn
  if (response.error?.includes("ECONNRESET") || response.error?.includes("ECONNREFUSED")) {
    return {
      burned: true,
      reason: "Connection reset/refused — likely IP-blocked by firewall or IDS",
      detectionMethod: "connection_reset",
      confidence: "high",
    };
  }

  // WAF block responses
  if (response.statusCode === 403 && response.body?.match(/blocked|denied|firewall|waf|cloudflare|akamai/i)) {
    return {
      burned: true,
      reason: `WAF block detected (HTTP 403): ${response.body?.slice(0, 100)}`,
      detectionMethod: "waf_block",
      confidence: "high",
    };
  }

  // Rate limiting
  if (response.statusCode === 429) {
    return {
      burned: true,
      reason: "Rate limited (HTTP 429) — IP throttled",
      detectionMethod: "rate_limit",
      confidence: "high",
    };
  }

  // Captcha challenges
  if (response.body?.match(/captcha|challenge|verify.*human|recaptcha/i)) {
    return {
      burned: true,
      reason: "CAPTCHA/challenge detected — IP flagged as suspicious",
      detectionMethod: "waf_block",
      confidence: "medium",
    };
  }

  // Timeout pattern (3+ consecutive timeouts)
  if (response.error?.includes("ETIMEDOUT") && (response.consecutiveFailures || 0) >= 3) {
    return {
      burned: true,
      reason: "Consecutive timeouts (3+) — possible blackholing",
      detectionMethod: "timeout",
      confidence: "medium",
    };
  }

  return {
    burned: false,
    reason: "No burn indicators detected",
    detectionMethod: "manual",
    confidence: "low",
  };
}

// ─── Fleet Summary ───────────────────────────────────────────────────────────

export interface FleetSummary {
  fleetId: string;
  engagementId: number;
  status: FleetStatus;
  stealthProfile: StealthProfile;
  stealthConfig: StealthConfig;
  totalNodes: number;
  healthyNodes: number;
  burnedNodes: number;
  destroyedNodes: number;
  regions: { region: ProxyRegion; nodeCount: number; healthyCount: number }[];
  totalRequestsRouted: number;
  totalBurnedIps: number;
  costEstimatePerHour: number;
  uptime: number;
  allIps: { ip: string; region: ProxyRegion; status: ProxyNodeStatus; purpose: string }[];
}

export function getFleetSummary(engagementId: number): FleetSummary | null {
  const fleet = activeFleets.get(engagementId);
  if (!fleet) return null;

  const regionMap = new Map<ProxyRegion, { total: number; healthy: number }>();
  for (const node of fleet.nodes) {
    const entry = regionMap.get(node.region) || { total: 0, healthy: 0 };
    entry.total++;
    if (node.status === "healthy") entry.healthy++;
    regionMap.set(node.region, entry);
  }

  return {
    fleetId: fleet.id,
    engagementId: fleet.engagementId,
    status: fleet.status,
    stealthProfile: fleet.stealthProfile,
    stealthConfig: STEALTH_PROFILES[fleet.stealthProfile],
    totalNodes: fleet.nodes.length,
    healthyNodes: fleet.nodes.filter(n => n.status === "healthy").length,
    burnedNodes: fleet.nodes.filter(n => n.status === "burned").length,
    destroyedNodes: fleet.nodes.filter(n => n.status === "destroyed").length,
    regions: Array.from(regionMap.entries()).map(([region, counts]) => ({
      region,
      nodeCount: counts.total,
      healthyCount: counts.healthy,
    })),
    totalRequestsRouted: fleet.nodes.reduce((sum, n) => sum + n.requestsRouted, 0),
    totalBurnedIps: fleet.burnedIps.length,
    costEstimatePerHour: fleet.nodes.filter(n => n.status !== "destroyed").length * 0.006,
    uptime: Date.now() - fleet.createdAt,
    allIps: fleet.nodes
      .filter(n => n.ip && n.status !== "destroyed")
      .map(n => ({
        ip: n.ip,
        region: n.region,
        status: n.status,
        purpose: n.assignedPhase ? `${n.assignedPhase}/${n.assignedTool || "general"}` : "standby",
      })),
  };
}

// ─── IP Disclosure Document Data ─────────────────────────────────────────────

export interface IpDisclosureData {
  engagementId: number;
  engagementName: string;
  fleetId: string;
  generatedAt: number;
  sourceIps: {
    ip: string;
    region: ProxyRegion;
    purpose: string;
    expectedTraffic: string;
    ports: string;
  }[];
  scanServerIp: string | null;
  calderaServerIp: string | null;
  expectedTrafficPatterns: string[];
  whitelistInstructions: string;
}

/**
 * Generate IP disclosure data for client notification.
 */
export function generateIpDisclosureData(
  engagementId: number,
  engagementName: string,
): IpDisclosureData | null {
  const fleet = activeFleets.get(engagementId);
  if (!fleet) return null;

  const scanServerIp = process.env.SCAN_SERVER_HOST || null;
  const calderaBaseUrl = process.env.CALDERA_BASE_URL || "";
  let calderaServerIp: string | null = null;
  try {
    calderaServerIp = new URL(calderaBaseUrl).hostname;
  } catch {}

  const sourceIps = fleet.nodes
    .filter(n => n.ip && n.status !== "destroyed")
    .map(n => ({
      ip: n.ip,
      region: n.region,
      purpose: getPurposeForPhase(n.assignedPhase),
      expectedTraffic: getTrafficDescription(n.assignedPhase, fleet.stealthProfile),
      ports: "80, 443, 8080, 8443 (HTTP/HTTPS scanning)",
    }));

  // Add scan server and C2 server IPs
  if (scanServerIp) {
    sourceIps.push({
      ip: scanServerIp,
      region: "nyc1" as ProxyRegion,
      purpose: "Vulnerability scanning (Nuclei, Nmap, ZAP)",
      expectedTraffic: "High-volume scan traffic across all target ports",
      ports: "All TCP ports (1-65535)",
    });
  }

  if (calderaServerIp && calderaServerIp !== scanServerIp) {
    sourceIps.push({
      ip: calderaServerIp,
      region: "nyc1" as ProxyRegion,
      purpose: "C2 framework (Caldera) — post-exploitation callbacks",
      expectedTraffic: "HTTPS callbacks on port 443/8443",
      ports: "443, 8443, 8888",
    });
  }

  return {
    engagementId,
    engagementName,
    fleetId: fleet.id,
    generatedAt: Date.now(),
    sourceIps,
    scanServerIp,
    calderaServerIp,
    expectedTrafficPatterns: [
      "DNS resolution queries for target domains",
      "HTTP/HTTPS requests to target web applications",
      "TCP SYN scans across common ports (nmap)",
      "Nuclei vulnerability template probes",
      "ZAP active/passive scan requests",
      "SSH connection attempts (credential testing)",
      "Caldera C2 agent callbacks (HTTPS)",
    ],
    whitelistInstructions: [
      "Add the following source IPs to your WAF/IDS/IPS whitelist for the duration of the engagement.",
      "Configure rate limiting exceptions for these IPs on all in-scope targets.",
      "Notify your SOC/NOC team that traffic from these IPs is authorized penetration testing.",
      "If any IP is rotated mid-engagement, you will receive an updated notification.",
      "After the engagement concludes, remove all whitelist entries for these IPs.",
    ].join("\n"),
  };
}

function getPurposeForPhase(phase: EngagementPhase | null): string {
  switch (phase) {
    case "recon": return "Passive/active reconnaissance";
    case "enumeration": return "Port scanning and service enumeration";
    case "vuln_detection": return "Vulnerability scanning (Nuclei, ZAP)";
    case "exploitation": return "Exploit delivery and validation";
    case "post_exploit": return "Post-exploitation and C2 operations";
    default: return "General scanning and testing";
  }
}

function getTrafficDescription(phase: EngagementPhase | null, profile: StealthProfile): string {
  const config = STEALTH_PROFILES[profile];
  return `~${config.requestsPerSecond} req/s, ${config.maxConcurrentScans} concurrent streams`;
}
