/**
 * @deprecated — Nmap has been removed from the platform. Use scanforge-discovery
 * (naabu + masscan + Nerva) for port discovery and service fingerprinting.
 * This module is retained for backward compatibility only.
 *
 * Nmap Orchestrator (DEPRECATED)
 *
 * Previously executed Nmap scans on the operator's remote servers via SSH.
 *
 * Architecture:
 *   Dashboard → SSH → operator's scan server (nmap installed) → XML output → parse → SSIL
 *
 * This does NOT embed or redistribute Nmap. The operator installs Nmap
 * on their own infrastructure. We call it as an external CLI tool via SSH
 * (same pattern as the payload-generator uses for msfvenom).
 *
 * Licensing: Nmap NPSL allows end-user execution. We only parse output.
 *
 * Scan profiles:
 *   - quick:    Top 100 ports, no scripts, SYN scan (-sS -T4 --top-ports 100)
 *   - standard: Top 1000 ports, default scripts (-sS -sV -sC -T3 --top-ports 1000)
 *   - deep:     All 65535 ports, aggressive scripts (-sS -sV -sC -A -T2 -p-)
 *   - stealth:  SYN scan, randomised, low rate (-sS -T1 --randomize-hosts --max-rate 50)
 *   - service:  Service version + OS detection on specific ports (-sV -O -p <ports>)
 *   - udp:      UDP scan on common ports (-sU --top-ports 50)
 *   - vuln:     Vulnerability scripts (--script vuln -sV)
 *
 * Author: Harrison Cook — AceofCloud
 */
import { Client as SSHClient } from "ssh2";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { FIPS_SSH_ALGORITHMS } from "./fips-ssh";

// ─── Types ──────────────────────────────────────────────────────────────────

export type NmapScanProfile = "quick" | "standard" | "deep" | "stealth" | "service" | "udp" | "vuln" | "custom";

export interface NmapScanConfig {
  /** Target IPs, CIDRs, or hostnames (must be pre-validated by scope-guard) */
  targets: string[];
  /** Scan profile */
  profile: NmapScanProfile;
  /** Specific ports (for "service" profile or custom) */
  ports?: string;
  /** Custom Nmap arguments (for "custom" profile) */
  customArgs?: string;
  /** Engagement ID for scope enforcement */
  engagementId: number;
  /** Operator info */
  operatorId: string;
  operatorName?: string;
  /** Scan server connection */
  server: ScanServerConfig;
  /** Timeout in seconds (default 600 = 10 min) */
  timeoutSeconds?: number;
  /** NSE scripts to include */
  scripts?: string[];
  /** Exclude specific hosts */
  excludeHosts?: string[];
}

export interface ScanServerConfig {
  host: string;
  port?: number;
  username: string;
  privateKeyPath?: string;
  privateKey?: string;
  /** Path to nmap binary on the remote server (default: "nmap") */
  nmapPath?: string;
}

export interface NmapScanResult {
  scanId: string;
  status: "completed" | "failed" | "timeout";
  startedAt: number;
  completedAt: number;
  durationMs: number;
  command: string;
  hosts: NmapHost[];
  summary: NmapSummary;
  rawXml?: string;
  error?: string;
}

export interface NmapHost {
  ip: string;
  hostnames: string[];
  status: "up" | "down" | "unknown";
  os?: NmapOSMatch;
  ports: NmapPort[];
  scripts?: NmapScript[];
  /** MAC address if on same subnet */
  mac?: string;
  /** Vendor from MAC OUI */
  vendor?: string;
  /** Hop count */
  distance?: number;
  /** Uptime estimate */
  uptime?: { seconds: number; lastBoot?: string };
}

export interface NmapPort {
  port: number;
  protocol: "tcp" | "udp" | "sctp";
  state: "open" | "closed" | "filtered" | "open|filtered" | "closed|filtered";
  service: string;
  product?: string;
  version?: string;
  extraInfo?: string;
  cpe?: string[];
  banner?: string;
  scripts?: NmapScript[];
  /** Service detection confidence (0-10) */
  serviceConf?: number;
  /** Service detection method */
  method?: string;
}

export interface NmapScript {
  id: string;
  output: string;
  elements?: Record<string, string>;
}

export interface NmapOSMatch {
  name: string;
  accuracy: number;
  family?: string;
  generation?: string;
  cpe?: string;
}

export interface NmapSummary {
  totalHosts: number;
  hostsUp: number;
  hostsDown: number;
  totalPorts: number;
  openPorts: number;
  filteredPorts: number;
  closedPorts: number;
  uniqueServices: string[];
  uniqueProducts: string[];
  scanType: string;
  nmapVersion?: string;
  elapsed?: number;
}

// ─── Scan Profile Definitions ───────────────────────────────────────────────

const SCAN_PROFILES: Record<NmapScanProfile, (config: NmapScanConfig) => string[]> = {
  quick: () => [
    "-sS", "-T4", "--top-ports", "100",
    "-sV", "--version-intensity", "2",
    "--open", "-oX", "-",
  ],
  standard: () => [
    "-sS", "-sV", "-sC", "-T3",
    "--top-ports", "1000",
    "-O", "--osscan-limit",
    "--open", "-oX", "-",
  ],
  deep: () => [
    "-sS", "-sV", "-sC", "-A", "-T2",
    "-p-",
    "--open", "-oX", "-",
  ],
  stealth: () => [
    "-sS", "-T1",
    "--randomize-hosts",
    "--max-rate", "50",
    "--top-ports", "1000",
    "-sV", "--version-intensity", "1",
    "--open", "-oX", "-",
  ],
  service: (config) => [
    "-sV", "-O",
    "-p", config.ports || "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017",
    "-sC",
    "--open", "-oX", "-",
  ],
  udp: () => [
    "-sU", "--top-ports", "50",
    "-sV", "--version-intensity", "2",
    "--open", "-oX", "-",
  ],
  vuln: () => [
    "--script", "vuln",
    "-sV", "-T3",
    "--top-ports", "1000",
    "--open", "-oX", "-",
  ],
  custom: (config) => {
    const args = config.customArgs ? config.customArgs.split(/\s+/) : [];
    // Always force XML output to stdout
    if (!args.includes("-oX")) {
      args.push("-oX", "-");
    }
    return args;
  },
};

/** Admin/service ports for targeted fingerprinting */
export const ADMIN_SERVICE_PORTS: Record<string, number[]> = {
  ssh: [22, 2222, 22222],
  ftp: [20, 21, 990],
  sftp: [22, 115],
  smtp: [25, 465, 587, 2525],
  dns: [53],
  http: [80, 8080, 8000, 8888],
  https: [443, 8443, 4443],
  pop3: [110, 995],
  imap: [143, 993],
  smb: [139, 445],
  rdp: [3389],
  vnc: [5900, 5901, 5902],
  telnet: [23, 992],
  snmp: [161, 162],
  ldap: [389, 636],
  mysql: [3306],
  mssql: [1433, 1434],
  postgresql: [5432],
  oracle: [1521, 1630],
  redis: [6379],
  mongodb: [27017, 27018],
  elasticsearch: [9200, 9300],
  docker: [2375, 2376],
  kubernetes: [6443, 10250],
  winrm: [5985, 5986],
  nfs: [111, 2049],
  kerberos: [88, 464],
};

/** Get all unique admin ports as a comma-separated string */
export function getAllAdminPorts(): string {
  const ports = new Set<number>();
  for (const group of Object.values(ADMIN_SERVICE_PORTS)) {
    for (const port of group) ports.add(port);
  }
  return Array.from(ports).sort((a, b) => a - b).join(",");
}

// ─── SSH Command Execution ──────────────────────────────────────────────────

function executeSSHCommand(
  server: ScanServerConfig,
  command: string,
  timeoutMs: number
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      conn.end();
      reject(new Error(`SSH command timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);

    // Read private key
    let privateKey: string | Buffer | undefined;
    if (server.privateKey) {
      privateKey = server.privateKey;
    } else if (server.privateKeyPath) {
      try {
        privateKey = fs.readFileSync(server.privateKeyPath);
      } catch (err: any) {
        clearTimeout(timer);
        reject(new Error(`Cannot read SSH key: ${err.message}`));
        return;
      }
    }

    conn
      .on("ready", () => {
        conn.exec(command, (err, stream) => {
          if (err) {
            clearTimeout(timer);
            conn.end();
            return reject(err);
          }
          stream.on("close", (code: number) => {
            clearTimeout(timer);
            conn.end();
            if (!timedOut) {
              resolve({ stdout, stderr, exitCode: code || 0 });
            }
          });
          stream.on("data", (data: Buffer) => {
            stdout += data.toString();
          });
          stream.stderr.on("data", (data: Buffer) => {
            stderr += data.toString();
          });
        });
      })
      .on("error", (err) => {
        clearTimeout(timer);
        reject(new Error(`SSH connection error: ${err.message}`));
      })
      .connect({
        host: server.host,
        port: server.port || 22,
        username: server.username,
        privateKey,
        readyTimeout: 15000,
        keepaliveInterval: 10000,
        // FIPS 140-3: Restrict to NIST-approved SSH algorithms only
        algorithms: FIPS_SSH_ALGORITHMS,
      });
  });
}

// ─── Nmap XML Parser ────────────────────────────────────────────────────────

/**
 * Parse Nmap XML output into structured NmapHost[] results.
 * Uses regex-based parsing to avoid XML library dependencies.
 */
export function parseNmapXml(xml: string): { hosts: NmapHost[]; summary: Partial<NmapSummary> } {
  const hosts: NmapHost[] = [];
  const summary: Partial<NmapSummary> = {};

  // Extract Nmap version
  const nmapVerMatch = xml.match(/scanner="nmap"[^>]*version="([^"]+)"/);
  if (nmapVerMatch) summary.nmapVersion = nmapVerMatch[1];

  // Extract scan type
  const scanTypeMatch = xml.match(/type="([^"]+)"/);
  if (scanTypeMatch) summary.scanType = scanTypeMatch[1];

  // Extract elapsed time
  const elapsedMatch = xml.match(/elapsed="([^"]+)"/);
  if (elapsedMatch) summary.elapsed = parseFloat(elapsedMatch[1]);

  // Extract hosts
  const hostBlocks = xml.match(/<host[\s>][\s\S]*?<\/host>/g) || [];

  for (const hostBlock of hostBlocks) {
    const host: NmapHost = {
      ip: "",
      hostnames: [],
      status: "unknown",
      ports: [],
    };

    // Status
    const statusMatch = hostBlock.match(/<status\s+state="(\w+)"/);
    if (statusMatch) host.status = statusMatch[1] as any;

    // IP address
    const addrMatch = hostBlock.match(/<address\s+addr="([^"]+)"\s+addrtype="ipv4"/);
    if (addrMatch) host.ip = addrMatch[1];
    if (!host.ip) {
      const addr6Match = hostBlock.match(/<address\s+addr="([^"]+)"\s+addrtype="ipv6"/);
      if (addr6Match) host.ip = addr6Match[1];
    }

    // MAC address
    const macMatch = hostBlock.match(/<address\s+addr="([^"]+)"\s+addrtype="mac"(?:\s+vendor="([^"]+)")?/);
    if (macMatch) {
      host.mac = macMatch[1];
      if (macMatch[2]) host.vendor = macMatch[2];
    }

    // Hostnames
    const hostnameMatches = hostBlock.matchAll(/<hostname\s+name="([^"]+)"/g);
    for (const m of hostnameMatches) {
      host.hostnames.push(m[1]);
    }

    // Distance (hop count)
    const distMatch = hostBlock.match(/<distance\s+value="(\d+)"/);
    if (distMatch) host.distance = parseInt(distMatch[1], 10);

    // Uptime
    const uptimeMatch = hostBlock.match(/<uptime\s+seconds="(\d+)"(?:\s+lastboot="([^"]+)")?/);
    if (uptimeMatch) {
      host.uptime = {
        seconds: parseInt(uptimeMatch[1], 10),
        lastBoot: uptimeMatch[2],
      };
    }

    // OS detection
    const osMatchBlock = hostBlock.match(/<osmatch\s+name="([^"]+)"\s+accuracy="(\d+)"[^>]*(?:>[\s\S]*?<\/osmatch>|\/?>)/);
    if (osMatchBlock) {
      host.os = {
        name: osMatchBlock[1],
        accuracy: parseInt(osMatchBlock[2], 10),
      };
      // Extract OS CPE
      const osCpeMatch = osMatchBlock[0].match(/<cpe>([^<]+)<\/cpe>/);
      if (osCpeMatch) host.os.cpe = osCpeMatch[1];
    }

    // Ports
    const portBlocks = hostBlock.match(/<port[\s>][\s\S]*?<\/port>/g) || [];
    for (const portBlock of portBlocks) {
      const portMatch = portBlock.match(/<port\s+protocol="(\w+)"\s+portid="(\d+)"/);
      if (!portMatch) continue;

      const port: NmapPort = {
        port: parseInt(portMatch[2], 10),
        protocol: portMatch[1] as any,
        state: "open",
        service: "unknown",
      };

      // State
      const stateMatch = portBlock.match(/<state\s+state="([^"]+)"/);
      if (stateMatch) port.state = stateMatch[1] as any;

      // Service
      const svcMatch = portBlock.match(/<service\s+([^>]+)/);
      if (svcMatch) {
        const svcAttrs = svcMatch[1];
        const nameMatch = svcAttrs.match(/name="([^"]+)"/);
        if (nameMatch) port.service = nameMatch[1];
        const productMatch = svcAttrs.match(/product="([^"]+)"/);
        if (productMatch) port.product = productMatch[1];
        const versionMatch = svcAttrs.match(/version="([^"]+)"/);
        if (versionMatch) port.version = versionMatch[1];
        const extraMatch = svcAttrs.match(/extrainfo="([^"]+)"/);
        if (extraMatch) port.extraInfo = extraMatch[1];
        const confMatch = svcAttrs.match(/conf="(\d+)"/);
        if (confMatch) port.serviceConf = parseInt(confMatch[1], 10);
        const methodMatch = svcAttrs.match(/method="([^"]+)"/);
        if (methodMatch) port.method = methodMatch[1];
      }

      // CPEs
      const cpeMatches = portBlock.matchAll(/<cpe>([^<]+)<\/cpe>/g);
      const cpes: string[] = [];
      for (const cm of cpeMatches) cpes.push(cm[1]);
      if (cpes.length > 0) port.cpe = cpes;

      // NSE scripts
      const scriptBlocks = portBlock.match(/<script\s+id="([^"]+)"[^>]*output="([^"]*)"[^>]*\/?>/g) || [];
      if (scriptBlocks.length > 0) {
        port.scripts = [];
        for (const sb of scriptBlocks) {
          const idMatch = sb.match(/id="([^"]+)"/);
          const outMatch = sb.match(/output="([^"]*)"/);
          if (idMatch) {
            port.scripts.push({
              id: idMatch[1],
              output: outMatch ? outMatch[1].replace(/&#xa;/g, "\n").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&") : "",
            });
          }
        }
      }

      // Banner (from banner-plus or other scripts)
      const bannerScript = port.scripts?.find(s => s.id === "banner" || s.id === "banner-plus");
      if (bannerScript) port.banner = bannerScript.output;

      host.ports.push(port);
    }

    // Host-level scripts
    const hostScriptBlock = hostBlock.match(/<hostscript>([\s\S]*?)<\/hostscript>/);
    if (hostScriptBlock) {
      const hostScripts = hostScriptBlock[1].match(/<script\s+id="([^"]+)"[^>]*output="([^"]*)"[^>]*\/?>/g) || [];
      if (hostScripts.length > 0) {
        host.scripts = [];
        for (const sb of hostScripts) {
          const idMatch = sb.match(/id="([^"]+)"/);
          const outMatch = sb.match(/output="([^"]*)"/);
          if (idMatch) {
            host.scripts.push({
              id: idMatch[1],
              output: outMatch ? outMatch[1].replace(/&#xa;/g, "\n") : "",
            });
          }
        }
      }
    }

    if (host.ip) hosts.push(host);
  }

  return { hosts, summary };
}

// ─── Scan Execution ─────────────────────────────────────────────────────────

/**
 * Execute an Nmap scan on a remote server via SSH.
 *
 * IMPORTANT: Targets MUST be pre-validated by scope-guard before calling this.
 * This function does NOT perform scope validation — that is the caller's responsibility.
 */
export async function executeNmapScan(config: NmapScanConfig): Promise<NmapScanResult> {
  const scanId = `nmap-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  const startedAt = Date.now();
  const timeoutMs = (config.timeoutSeconds || 600) * 1000;
  const nmapPath = config.server.nmapPath || "nmap";

  // Build Nmap arguments
  const profileArgs = SCAN_PROFILES[config.profile](config);

  // Add scripts if specified
  if (config.scripts && config.scripts.length > 0 && config.profile !== "custom") {
    const scriptIdx = profileArgs.indexOf("--script");
    if (scriptIdx >= 0) {
      profileArgs[scriptIdx + 1] += `,${config.scripts.join(",")}`;
    } else {
      profileArgs.push("--script", config.scripts.join(","));
    }
  }

  // Add exclude hosts
  if (config.excludeHosts && config.excludeHosts.length > 0) {
    profileArgs.push("--exclude", config.excludeHosts.join(","));
  }

  // Build full command
  const targetStr = config.targets.join(" ");
  // Sanitise targets to prevent command injection
  const safeTargets = config.targets.map(t => t.replace(/[;&|`$(){}]/g, "")).join(" ");
  const command = `sudo ${nmapPath} ${profileArgs.join(" ")} ${safeTargets} 2>/dev/null`;

  try {
    const { stdout, stderr, exitCode } = await executeSSHCommand(config.server, command, timeoutMs);

    if (exitCode !== 0 && !stdout.includes("</nmaprun>")) {
      return {
        scanId,
        status: "failed",
        startedAt,
        completedAt: Date.now(),
        durationMs: Date.now() - startedAt,
        command: `${nmapPath} ${profileArgs.join(" ")} ${targetStr}`,
        hosts: [],
        summary: {
          totalHosts: 0, hostsUp: 0, hostsDown: 0,
          totalPorts: 0, openPorts: 0, filteredPorts: 0, closedPorts: 0,
          uniqueServices: [], uniqueProducts: [],
          scanType: config.profile,
        },
        error: stderr || `Nmap exited with code ${exitCode}`,
      };
    }

    // Parse XML output
    const { hosts, summary: parsedSummary } = parseNmapXml(stdout);

    // Build summary
    const allPorts = hosts.flatMap(h => h.ports);
    const summary: NmapSummary = {
      totalHosts: hosts.length,
      hostsUp: hosts.filter(h => h.status === "up").length,
      hostsDown: hosts.filter(h => h.status === "down").length,
      totalPorts: allPorts.length,
      openPorts: allPorts.filter(p => p.state === "open").length,
      filteredPorts: allPorts.filter(p => p.state === "filtered" || p.state === "open|filtered").length,
      closedPorts: allPorts.filter(p => p.state === "closed").length,
      uniqueServices: [...new Set(allPorts.map(p => p.service).filter(Boolean))],
      uniqueProducts: [...new Set(allPorts.map(p => p.product).filter((p): p is string => !!p))],
      scanType: config.profile,
      nmapVersion: parsedSummary.nmapVersion,
      elapsed: parsedSummary.elapsed,
    };

    return {
      scanId,
      status: "completed",
      startedAt,
      completedAt: Date.now(),
      durationMs: Date.now() - startedAt,
      command: `${nmapPath} ${profileArgs.join(" ")} ${targetStr}`,
      hosts,
      summary,
      rawXml: stdout.length < 5_000_000 ? stdout : undefined, // Don't store huge XML
    };
  } catch (err: any) {
    return {
      scanId,
      status: err.message.includes("timed out") ? "timeout" : "failed",
      startedAt,
      completedAt: Date.now(),
      durationMs: Date.now() - startedAt,
      command: `${nmapPath} ${profileArgs.join(" ")} ${targetStr}`,
      hosts: [],
      summary: {
        totalHosts: 0, hostsUp: 0, hostsDown: 0,
        totalPorts: 0, openPorts: 0, filteredPorts: 0, closedPorts: 0,
        uniqueServices: [], uniqueProducts: [],
        scanType: config.profile,
      },
      error: err.message,
    };
  }
}

// ─── Nmap Result → SSIL Observation Adapter ─────────────────────────────────

/**
 * Convert Nmap scan results into the format expected by the observation normalizer.
 * This bridges the gap between our NmapScanResult and the adaptNmapResults() function
 * in observation-normalizer.ts.
 */
export function toNmapRawResults(scanResult: NmapScanResult, policyProfile?: string): Array<{
  host: string;
  ports: Array<{
    port: number;
    protocol: string;
    service: string | null;
    version: string | null;
    banner: string | null;
    serviceConfidence: number;
    scripts: Array<{ id: string; output: string }>;
  }>;
  os: string | null;
  tags: string[];
  nmapVersion: string;
  scanRunId: string;
  policyProfile: string;
}> {
  return scanResult.hosts.map(host => ({
    host: host.ip,
    ports: host.ports.map(p => ({
      port: p.port,
      protocol: p.protocol,
      service: p.service || null,
      version: p.version ? `${p.product || ""} ${p.version}`.trim() : (p.product || null),
      banner: p.banner || p.scripts?.find(s => s.id === "banner")?.output || null,
      serviceConfidence: (p.serviceConf || 5) / 10,
      scripts: p.scripts || [],
    })),
    os: host.os?.name || null,
    tags: [
      `profile:${scanResult.summary.scanType}`,
      ...(host.os ? [`os:${host.os.name}`] : []),
      ...(host.vendor ? [`vendor:${host.vendor}`] : []),
    ],
    nmapVersion: scanResult.summary.nmapVersion || "7.94",
    scanRunId: scanResult.scanId,
    policyProfile: policyProfile || "active-standard",
  }));
}

// ─── Convenience: Scan with scope enforcement ───────────────────────────────

/**
 * Execute an Nmap scan with automatic ROE scope enforcement.
 * This is the recommended entry point for all Nmap scans.
 */
export async function scanWithScopeEnforcement(config: NmapScanConfig): Promise<NmapScanResult> {
  const { enforceScope } = await import("./scope-guard");

  // Enforce scope on all targets
  await enforceScope({
    engagementId: config.engagementId,
    targets: config.targets.map(t => ({ value: t })),
    tool: `nmap:${config.profile}`,
    operatorId: config.operatorId,
    operatorName: config.operatorName,
  });

  // Scope validated — execute scan
  return executeNmapScan(config);
}

// ─── Pre-flight Check ───────────────────────────────────────────────────────

/**
 * Verify that the remote server has Nmap installed and accessible.
 */
export async function preflightCheck(server: ScanServerConfig): Promise<{
  available: boolean;
  version?: string;
  error?: string;
  hasSudo?: boolean;
}> {
  try {
    const nmapPath = server.nmapPath || "nmap";
    const { stdout, exitCode } = await executeSSHCommand(server, `${nmapPath} --version 2>&1`, 10000);

    if (exitCode !== 0 && !stdout.includes("Nmap")) {
      return { available: false, error: "Nmap not found on remote server" };
    }

    const versionMatch = stdout.match(/Nmap version (\S+)/);

    // Check sudo access for SYN scans
    let hasSudo = false;
    try {
      const sudoResult = await executeSSHCommand(server, "sudo -n true 2>&1", 5000);
      hasSudo = sudoResult.exitCode === 0;
    } catch {
      hasSudo = false;
    }

    return {
      available: true,
      version: versionMatch ? versionMatch[1] : "unknown",
      hasSudo,
    };
  } catch (err: any) {
    return { available: false, error: err.message };
  }
}
