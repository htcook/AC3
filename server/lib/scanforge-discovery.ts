/**
 * scanforge-discovery.ts — ScanForge Multi-Tool Discovery Engine
 *
 * ScanForge-native multi-tool discovery engine. Executes port discovery scans on the
 * operator's remote ScanForge server via SSH using Masscan, Naabu,
 * RustScan, or ZMap. Parses JSON/text output and feeds results into
 * the SSIL observation pipeline.
 *
 * Architecture:
 *   Dashboard → SSH → ScanForge droplet (tools installed) → JSON output → parse → SSIL
 *
 * Supported tools:
 *   - Masscan: High-speed TCP SYN scanner (large ranges)
 *   - Naabu:   ProjectDiscovery port scanner (pipeline integration)
 *   - RustScan: Ultra-fast Rust port scanner (single hosts)
 *   - ZMap:    Internet-wide single-port scanner (massive ranges)
 *
 * Author: Harrison Cook — AceofCloud
 */
import { Client as SSHClient } from "ssh2";
import * as fs from "fs";
import * as crypto from "crypto";
import { FIPS_SSH_ALGORITHMS } from "./fips-ssh";

// ─── Types ──────────────────────────────────────────────────────────────────

export type ScanforgeTool = "masscan" | "naabu" | "rustscan" | "zmap";
export type ScanforgeProfile = "quick" | "standard" | "deep" | "stealth" | "service" | "udp" | "full-pipeline" | "custom";

export interface ScanforgeConfig {
  /** Target IPs, CIDRs, or hostnames (must be pre-validated by scope-guard) */
  targets: string[];
  /** Scan profile */
  profile: ScanforgeProfile;
  /** Preferred tool (auto-selected if not specified) */
  tool?: ScanforgeTool;
  /** Specific ports (comma-separated or range like 1-1024) */
  ports?: string;
  /** Custom arguments (for "custom" profile) */
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
  /** Rate limit (packets/sec for masscan, requests/sec for naabu) */
  rate?: number;
  /** Stealth level affects tool selection and rate */
  stealthLevel?: 'minimal' | 'low' | 'medium' | 'high' | 'maximum';
  /** Exclude specific hosts */
  excludeHosts?: string[];
  /** Whether to chain httpx for fingerprinting */
  chainHttpx?: boolean;
  /** Whether to chain nuclei for vuln detection */
  chainNuclei?: boolean;
  /** Nuclei tags for targeted scanning */
  nucleiTags?: string[];
  /** Nuclei severity filter */
  nucleiSeverity?: string[];
}

export interface ScanServerConfig {
  host: string;
  port?: number;
  username: string;
  privateKeyPath?: string;
  privateKey?: string;
}

export interface ScanforgeResult {
  scanId: string;
  status: "completed" | "failed" | "timeout";
  tool: ScanforgeTool;
  startedAt: number;
  completedAt: number;
  durationMs: number;
  command: string;
  hosts: DiscoveredHost[];
  summary: ScanforgeSummary;
  /** httpx results if chained */
  httpxResults?: HttpxResult[];
  /** nuclei results if chained */
  nucleiResults?: NucleiResult[];
  rawOutput?: string;
  error?: string;
}

export interface DiscoveredHost {
  ip: string;
  hostnames: string[];
  status: "up" | "down" | "unknown";
  ports: DiscoveredPort[];
  /** Source tool that discovered this host */
  discoveredBy: ScanforgeTool;
}

export interface DiscoveredPort {
  port: number;
  protocol: "tcp" | "udp";
  state: "open" | "closed" | "filtered" | "open|filtered";
  service: string;
  product?: string;
  version?: string;
  banner?: string;
  /** Service detection confidence (0-1) */
  serviceConf?: number;
}

export interface HttpxResult {
  url: string;
  host: string;
  port: number;
  statusCode: number;
  title: string;
  server?: string;
  technologies?: string[];
  contentLength?: number;
  contentType?: string;
  cdn?: string;
  tls?: { version: string; cipher: string; issuer: string };
}

export interface NucleiResult {
  templateId: string;
  name: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  host: string;
  matchedAt: string;
  description?: string;
  reference?: string[];
  tags?: string[];
  cve?: string;
}

export interface ScanforgeSummary {
  totalHosts: number;
  hostsUp: number;
  totalPorts: number;
  openPorts: number;
  filteredPorts: number;
  uniqueServices: string[];
  uniqueProducts: string[];
  tool: ScanforgeTool;
  profile: string;
  /** httpx summary */
  webServicesFound?: number;
  technologiesDetected?: string[];
  /** nuclei summary */
  vulnsFound?: number;
  criticalVulns?: number;
  highVulns?: number;
}

// ─── Tool Auto-Selection ──────────────────────────────────────────────────

/**
 * Auto-select the best discovery tool based on target context.
 */
export function autoSelectTool(config: {
  targets: string[];
  stealthLevel?: string;
  profile?: ScanforgeProfile;
}): ScanforgeTool {
  const { targets, stealthLevel, profile } = config;

  // UDP scanning → only Naabu supports it
  if (profile === 'udp') return 'naabu';

  // Pipeline integration → Naabu
  if (profile === 'full-pipeline') return 'naabu';

  // Stealth → Naabu (best rate control)
  if (stealthLevel === 'high' || stealthLevel === 'maximum') return 'naabu';

  // Single host → RustScan (fastest for single targets)
  if (targets.length === 1 && !targets[0].includes('/')) return 'rustscan';

  // Small CIDR (/24 or smaller) → RustScan or Naabu
  if (targets.length === 1 && targets[0].includes('/')) {
    const cidr = parseInt(targets[0].split('/')[1], 10);
    if (cidr >= 24) return 'naabu';
    if (cidr >= 16) return 'masscan';
    return 'masscan'; // Large ranges → Masscan
  }

  // Multiple targets → Masscan
  if (targets.length > 5) return 'masscan';

  // Default → Naabu (most versatile)
  return 'naabu';
}

// ─── Scan Profile Definitions ─────────────────────────────────────────────

function buildMasscanArgs(config: ScanforgeConfig): string[] {
  const ports = config.ports || '1-1024,3306,3389,5432,5900,6379,8080,8443,27017';
  const rate = config.rate || 1000;
  const args = [`-p${ports}`, `--rate`, `${rate}`, `-oJ`, `-`];

  if (config.stealthLevel === 'high' || config.stealthLevel === 'maximum') {
    args.push('--source-port', '53', '--randomize-hosts');
  }
  if (config.excludeHosts?.length) {
    args.push('--excludefile', '/dev/stdin'); // We'll handle this differently
  }
  return args;
}

function buildNaabuArgs(config: ScanforgeConfig): string[] {
  const args: string[] = [];

  if (config.ports) {
    args.push('-p', config.ports);
  } else if (config.profile === 'deep' || config.profile === 'service') {
    args.push('-p', '-'); // All ports
  } else {
    args.push('-top-ports', '1000');
  }

  const rate = config.rate || 500;
  args.push('-rate', `${rate}`);

  if (config.profile === 'udp') {
    args.push('-scan-type', 'udp');
  } else if (config.stealthLevel === 'high' || config.stealthLevel === 'maximum') {
    args.push('-scan-type', 's'); // SYN scan
  }

  args.push('-json');

  if (config.excludeHosts?.length) {
    args.push('-exclude-hosts', config.excludeHosts.join(','));
  }

  return args;
}

function buildRustScanArgs(config: ScanforgeConfig): string[] {
  const args: string[] = [];

  // Port range
  if (config.ports) {
    args.push('--range', config.ports);
  } else {
    args.push('--range', '1-65535');
  }

  // Batch size (controls speed/stealth)
  let batchSize = 4500;
  switch (config.stealthLevel) {
    case 'maximum': batchSize = 64; break;
    case 'high': batchSize = 128; break;
    case 'medium': batchSize = 500; break;
    case 'low': batchSize = 1000; break;
    case 'minimal': batchSize = 4500; break;
  }
  args.push('-b', `${batchSize}`);

  // Timeout
  const timeout = config.stealthLevel === 'maximum' || config.stealthLevel === 'high' ? 5000 : 2000;
  args.push('-t', `${timeout}`);

  // Greppable output
  args.push('-g');

  return args;
}

function buildZmapArgs(config: ScanforgeConfig): string[] {
  const port = config.ports?.split(',')[0]?.split('-')[0] || '80'; // ZMap = single port
  const bandwidth = config.stealthLevel === 'high' || config.stealthLevel === 'maximum' ? '1M' : '10M';
  return ['-p', port, '-B', bandwidth, '-O', 'json', '--output-fields=saddr,sport'];
}

const PROFILE_CONFIGS: Record<ScanforgeProfile, (config: ScanforgeConfig) => { tool: ScanforgeTool; args: string[] }> = {
  quick: (config) => ({
    tool: config.tool || autoSelectTool(config),
    args: config.tool === 'masscan' ? buildMasscanArgs({ ...config, ports: config.ports || '1-1024', rate: config.rate || 5000 })
      : config.tool === 'rustscan' ? buildRustScanArgs({ ...config, ports: '1-1024' })
      : buildNaabuArgs({ ...config, ports: undefined }), // top-ports 1000 default
  }),
  standard: (config) => ({
    tool: config.tool || autoSelectTool(config),
    args: config.tool === 'masscan' ? buildMasscanArgs(config)
      : config.tool === 'rustscan' ? buildRustScanArgs(config)
      : buildNaabuArgs(config),
  }),
  deep: (config) => ({
    tool: config.tool || 'masscan',
    args: config.tool === 'masscan' ? buildMasscanArgs({ ...config, ports: '0-65535', rate: config.rate || 5000 })
      : config.tool === 'rustscan' ? buildRustScanArgs({ ...config, ports: '1-65535' })
      : buildNaabuArgs({ ...config, ports: '-' }),
  }),
  stealth: (config) => ({
    tool: 'naabu',
    args: buildNaabuArgs({ ...config, rate: config.rate || 50, stealthLevel: 'high' }),
  }),
  service: (config) => ({
    tool: config.tool || 'naabu',
    args: buildNaabuArgs({ ...config, ports: config.ports || '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017' }),
  }),
  udp: (config) => ({
    tool: 'naabu',
    args: buildNaabuArgs({ ...config, profile: 'udp' }),
  }),
  'full-pipeline': (config) => ({
    tool: config.tool || 'naabu',
    args: buildNaabuArgs(config),
  }),
  custom: (config) => ({
    tool: config.tool || 'naabu',
    args: config.customArgs ? config.customArgs.split(/\s+/) : buildNaabuArgs(config),
  }),
};

// ─── SSH Command Execution ────────────────────────────────────────────────

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
        algorithms: FIPS_SSH_ALGORITHMS,
      });
  });
}

// ─── Output Parsers ───────────────────────────────────────────────────────

/**
 * Parse Masscan JSON output into DiscoveredHost[].
 * Masscan JSON format: [{"ip":"1.2.3.4","timestamp":"1234","ports":[{"port":80,"proto":"tcp","status":"open"}]}, ...]
 */
export function parseMasscanOutput(output: string): DiscoveredHost[] {
  const hostMap = new Map<string, DiscoveredHost>();

  try {
    // Masscan outputs JSON array, but may have trailing comma issues
    const cleaned = output.trim().replace(/,\s*\]/, ']').replace(/,\s*$/, '');
    let records: any[];

    // Try parsing as JSON array first
    try {
      records = JSON.parse(cleaned.startsWith('[') ? cleaned : `[${cleaned}]`);
    } catch {
      // Masscan sometimes outputs one JSON object per line
      records = cleaned.split('\n')
        .filter(line => line.trim().startsWith('{'))
        .map(line => {
          try { return JSON.parse(line.replace(/,$/, '')); } catch { return null; }
        })
        .filter(Boolean);
    }

    for (const record of records) {
      if (!record.ip) continue;

      if (!hostMap.has(record.ip)) {
        hostMap.set(record.ip, {
          ip: record.ip,
          hostnames: [],
          status: 'up',
          ports: [],
          discoveredBy: 'masscan',
        });
      }

      const host = hostMap.get(record.ip)!;

      if (record.ports && Array.isArray(record.ports)) {
        for (const p of record.ports) {
          host.ports.push({
            port: p.port,
            protocol: p.proto || 'tcp',
            state: p.status || 'open',
            service: p.service?.name || 'unknown',
            banner: p.service?.banner,
          });
        }
      }
    }
  } catch (err) {
    // If JSON parsing fails completely, try line-based parsing
    const lines = output.split('\n');
    for (const line of lines) {
      const match = line.match(/Discovered open port (\d+)\/(tcp|udp) on ([\d.]+)/);
      if (match) {
        const [, portStr, proto, ip] = match;
        if (!hostMap.has(ip)) {
          hostMap.set(ip, {
            ip,
            hostnames: [],
            status: 'up',
            ports: [],
            discoveredBy: 'masscan',
          });
        }
        hostMap.get(ip)!.ports.push({
          port: parseInt(portStr, 10),
          protocol: proto as 'tcp' | 'udp',
          state: 'open',
          service: 'unknown',
        });
      }
    }
  }

  return Array.from(hostMap.values());
}

/**
 * Parse Naabu JSON output into DiscoveredHost[].
 * Naabu JSON format: {"host":"1.2.3.4","ip":"1.2.3.4","port":80,"protocol":"tcp"}
 */
export function parseNaabuOutput(output: string): DiscoveredHost[] {
  const hostMap = new Map<string, DiscoveredHost>();

  const lines = output.split('\n').filter(line => line.trim().startsWith('{'));

  for (const line of lines) {
    try {
      const record = JSON.parse(line);
      const ip = record.ip || record.host;
      if (!ip) continue;

      if (!hostMap.has(ip)) {
        hostMap.set(ip, {
          ip,
          hostnames: record.host && record.host !== ip ? [record.host] : [],
          status: 'up',
          ports: [],
          discoveredBy: 'naabu',
        });
      }

      const host = hostMap.get(ip)!;
      if (record.port) {
        host.ports.push({
          port: record.port,
          protocol: record.protocol || 'tcp',
          state: 'open',
          service: 'unknown',
        });
      }
    } catch {
      // Skip unparseable lines
    }
  }

  return Array.from(hostMap.values());
}

/**
 * Parse RustScan greppable output into DiscoveredHost[].
 * RustScan -g format: 1.2.3.4 -> [80,443,8080]
 */
export function parseRustScanOutput(output: string): DiscoveredHost[] {
  const hostMap = new Map<string, DiscoveredHost>();

  const lines = output.split('\n');
  for (const line of lines) {
    // Format: IP -> [port1,port2,port3]
    const match = line.match(/([\d.]+)\s*->\s*\[([^\]]+)\]/);
    if (match) {
      const [, ip, portsStr] = match;
      const ports = portsStr.split(',').map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p));

      if (!hostMap.has(ip)) {
        hostMap.set(ip, {
          ip,
          hostnames: [],
          status: 'up',
          ports: [],
          discoveredBy: 'rustscan',
        });
      }

      const host = hostMap.get(ip)!;
      for (const port of ports) {
        host.ports.push({
          port,
          protocol: 'tcp',
          state: 'open',
          service: 'unknown',
        });
      }
    }
  }

  return Array.from(hostMap.values());
}

/**
 * Parse ZMap JSON output into DiscoveredHost[].
 * ZMap JSON format: {"saddr":"1.2.3.4","sport":80}
 */
export function parseZmapOutput(output: string): DiscoveredHost[] {
  const hostMap = new Map<string, DiscoveredHost>();

  const lines = output.split('\n').filter(line => line.trim().startsWith('{'));

  for (const line of lines) {
    try {
      const record = JSON.parse(line);
      const ip = record.saddr;
      if (!ip) continue;

      if (!hostMap.has(ip)) {
        hostMap.set(ip, {
          ip,
          hostnames: [],
          status: 'up',
          ports: [],
          discoveredBy: 'zmap',
        });
      }

      const host = hostMap.get(ip)!;
      if (record.sport) {
        host.ports.push({
          port: record.sport,
          protocol: 'tcp',
          state: 'open',
          service: 'unknown',
        });
      }
    } catch {
      // Skip unparseable lines
    }
  }

  return Array.from(hostMap.values());
}

/**
 * Parse httpx JSON output into HttpxResult[].
 */
export function parseHttpxOutput(output: string): HttpxResult[] {
  const results: HttpxResult[] = [];

  const lines = output.split('\n').filter(line => line.trim().startsWith('{'));

  for (const line of lines) {
    try {
      const record = JSON.parse(line);
      results.push({
        url: record.url || record.input,
        host: record.host || '',
        port: record.port || (record.url?.includes(':443') ? 443 : 80),
        statusCode: record['status-code'] || record.status_code || 0,
        title: record.title || '',
        server: record.webserver || record.server,
        technologies: record.tech || record.technologies,
        contentLength: record['content-length'] || record.content_length,
        contentType: record['content-type'] || record.content_type,
        cdn: record.cdn_name || record.cdn,
      });
    } catch {
      // Skip unparseable lines
    }
  }

  return results;
}

/**
 * Parse Nuclei JSON output into NucleiResult[].
 */
export function parseNucleiOutput(output: string): NucleiResult[] {
  const results: NucleiResult[] = [];

  const lines = output.split('\n').filter(line => line.trim().startsWith('{'));

  for (const line of lines) {
    try {
      const record = JSON.parse(line);
      results.push({
        templateId: record['template-id'] || record.templateID || '',
        name: record.info?.name || record.name || '',
        severity: record.info?.severity || record.severity || 'info',
        host: record.host || '',
        matchedAt: record['matched-at'] || record.matched || '',
        description: record.info?.description,
        reference: record.info?.reference,
        tags: record.info?.tags ? (typeof record.info.tags === 'string' ? record.info.tags.split(',') : record.info.tags) : undefined,
        cve: record.info?.classification?.['cve-id']?.[0],
      });
    } catch {
      // Skip unparseable lines
    }
  }

  return results;
}

// ─── Tool-Specific Parsers Map ────────────────────────────────────────────

const OUTPUT_PARSERS: Record<ScanforgeTool, (output: string) => DiscoveredHost[]> = {
  masscan: parseMasscanOutput,
  naabu: parseNaabuOutput,
  rustscan: parseRustScanOutput,
  zmap: parseZmapOutput,
};

// ─── Scan Execution ───────────────────────────────────────────────────────

/**
 * Execute a ScanForge discovery scan on a remote server via SSH.
 *
 * IMPORTANT: Targets MUST be pre-validated by scope-guard before calling this.
 */
export async function executeScanforgeScan(config: ScanforgeConfig): Promise<ScanforgeResult> {
  const scanId = `sf-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  const startedAt = Date.now();
  const timeoutMs = (config.timeoutSeconds || 600) * 1000;

  // Resolve tool and args
  const profileConfig = PROFILE_CONFIGS[config.profile](config);
  const tool = config.tool || profileConfig.tool;
  const args = config.profile === 'custom' && config.customArgs
    ? config.customArgs.split(/\s+/)
    : profileConfig.args;

  // Sanitise targets
  const safeTargets = config.targets.map(t => t.replace(/[;&|`$(){}]/g, ""));

  // Build command based on tool
  let command: string;
  switch (tool) {
    case 'masscan':
      command = `sudo masscan ${safeTargets.join(' ')} ${args.join(' ')} 2>/dev/null`;
      break;
    case 'naabu':
      command = `naabu -host ${safeTargets.join(',')} ${args.join(' ')} 2>/dev/null`;
      break;
    case 'rustscan':
      command = `rustscan -a ${safeTargets.join(',')} ${args.join(' ')} 2>/dev/null`;
      break;
    case 'zmap':
      command = `sudo zmap ${safeTargets.join(' ')} ${args.join(' ')} 2>/dev/null`;
      break;
    default:
      command = `naabu -host ${safeTargets.join(',')} ${args.join(' ')} 2>/dev/null`;
  }

  // Chain httpx if requested
  if (config.chainHttpx) {
    const httpxRate = config.stealthLevel === 'high' || config.stealthLevel === 'maximum' ? '-rate-limit 10' : '';
    // For tools that output host:port, pipe to httpx
    if (tool === 'naabu') {
      // Naabu can pipe directly via -silent
      command = command.replace('-json', '-silent');
      command += ` | httpx -json -title -tech-detect -status-code -server -follow-redirects ${httpxRate}`;
    }
  }

  // Chain nuclei if requested
  if (config.chainNuclei && config.chainHttpx) {
    const nucleiRate = config.stealthLevel === 'high' || config.stealthLevel === 'maximum' ? '-rate-limit 10' : '';
    const tags = config.nucleiTags?.length ? `-tags ${config.nucleiTags.join(',')}` : '-tags cve,misconfig';
    const severity = config.nucleiSeverity?.length ? `-severity ${config.nucleiSeverity.join(',')}` : '-severity medium,high,critical';
    command += ` | nuclei -json ${tags} ${severity} ${nucleiRate}`;
  }

  try {
    const { stdout, stderr, exitCode } = await executeSSHCommand(config.server, command, timeoutMs);

    if (exitCode !== 0 && !stdout.trim()) {
      return {
        scanId,
        status: "failed",
        tool,
        startedAt,
        completedAt: Date.now(),
        durationMs: Date.now() - startedAt,
        command,
        hosts: [],
        summary: emptySummary(tool, config.profile),
        error: stderr || `${tool} exited with code ${exitCode}`,
      };
    }

    // Parse output based on tool
    let hosts: DiscoveredHost[];
    let httpxResults: HttpxResult[] | undefined;
    let nucleiResults: NucleiResult[] | undefined;

    if (config.chainHttpx && !config.chainNuclei) {
      // Output is httpx JSON
      httpxResults = parseHttpxOutput(stdout);
      hosts = httpxResultsToHosts(httpxResults, tool);
    } else if (config.chainNuclei) {
      // Output is nuclei JSON
      nucleiResults = parseNucleiOutput(stdout);
      hosts = nucleiResultsToHosts(nucleiResults, tool);
    } else {
      // Output is raw tool output
      const parser = OUTPUT_PARSERS[tool];
      hosts = parser(stdout);
    }

    // Build summary
    const allPorts = hosts.flatMap(h => h.ports);
    const summary: ScanforgeSummary = {
      totalHosts: hosts.length,
      hostsUp: hosts.filter(h => h.status === 'up').length,
      totalPorts: allPorts.length,
      openPorts: allPorts.filter(p => p.state === 'open').length,
      filteredPorts: allPorts.filter(p => p.state === 'filtered' || p.state === 'open|filtered').length,
      uniqueServices: [...new Set(allPorts.map(p => p.service).filter(s => s !== 'unknown'))],
      uniqueProducts: [...new Set(allPorts.map(p => p.product).filter((p): p is string => !!p))],
      tool,
      profile: config.profile,
    };

    if (httpxResults) {
      summary.webServicesFound = httpxResults.length;
      summary.technologiesDetected = [...new Set(httpxResults.flatMap(r => r.technologies || []))];
    }

    if (nucleiResults) {
      summary.vulnsFound = nucleiResults.length;
      summary.criticalVulns = nucleiResults.filter(r => r.severity === 'critical').length;
      summary.highVulns = nucleiResults.filter(r => r.severity === 'high').length;
    }

    return {
      scanId,
      status: "completed",
      tool,
      startedAt,
      completedAt: Date.now(),
      durationMs: Date.now() - startedAt,
      command,
      hosts,
      summary,
      httpxResults,
      nucleiResults,
      rawOutput: stdout.length < 5_000_000 ? stdout : undefined,
    };
  } catch (err: any) {
    return {
      scanId,
      status: err.message.includes("timed out") ? "timeout" : "failed",
      tool,
      startedAt,
      completedAt: Date.now(),
      durationMs: Date.now() - startedAt,
      command,
      hosts: [],
      summary: emptySummary(tool, config.profile),
      error: err.message,
    };
  }
}

// ─── Helper: Convert httpx/nuclei results to hosts ────────────────────────

function httpxResultsToHosts(results: HttpxResult[], tool: ScanforgeTool): DiscoveredHost[] {
  const hostMap = new Map<string, DiscoveredHost>();

  for (const r of results) {
    const ip = r.host || new URL(r.url).hostname;
    if (!hostMap.has(ip)) {
      hostMap.set(ip, {
        ip,
        hostnames: [],
        status: 'up',
        ports: [],
        discoveredBy: tool,
      });
    }
    const host = hostMap.get(ip)!;
    host.ports.push({
      port: r.port,
      protocol: 'tcp',
      state: 'open',
      service: r.port === 443 ? 'https' : 'http',
      product: r.server,
      banner: r.title,
    });
  }

  return Array.from(hostMap.values());
}

function nucleiResultsToHosts(results: NucleiResult[], tool: ScanforgeTool): DiscoveredHost[] {
  const hostMap = new Map<string, DiscoveredHost>();

  for (const r of results) {
    const ip = r.host;
    if (!ip) continue;
    if (!hostMap.has(ip)) {
      hostMap.set(ip, {
        ip,
        hostnames: [],
        status: 'up',
        ports: [],
        discoveredBy: tool,
      });
    }
  }

  return Array.from(hostMap.values());
}

function emptySummary(tool: ScanforgeTool, profile: string): ScanforgeSummary {
  return {
    totalHosts: 0, hostsUp: 0, totalPorts: 0, openPorts: 0, filteredPorts: 0,
    uniqueServices: [], uniqueProducts: [], tool, profile,
  };
}

// ─── ScanForge Result → SSIL Observation Adapter ──────────────────────────

/**
 * Convert ScanForge results into the format expected by the observation normalizer.
 * This bridges the gap between ScanforgeResult and the SSIL pipeline.
 * Compatible with the existing adaptScanForgeResults() interface.
 */
export function toScanforgeRawResults(scanResult: ScanforgeResult, policyProfile?: string): Array<{
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
  serviceVersion: string;
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
      banner: p.banner || null,
      serviceConfidence: p.serviceConf || 0.5,
      scripts: [], // ScanForge tools don't have NSE-style scripts
    })),
    os: null, // ScanForge discovery tools don't do OS detection
    tags: [
      `tool:${scanResult.tool}`,
      `profile:${scanResult.summary.profile}`,
    ],
    // Keep field name as serviceVersion for backward compatibility with SSIL adapter
    serviceVersion: `scanforge:${scanResult.tool}`,
    scanRunId: scanResult.scanId,
    policyProfile: policyProfile || "active-standard",
  }));
}

// ─── Convenience: Scan with scope enforcement ─────────────────────────────

/**
 * Execute a ScanForge scan with automatic ROE scope enforcement.
 * This is the recommended entry point for all discovery scans.
 */
export async function scanWithScopeEnforcement(config: ScanforgeConfig): Promise<ScanforgeResult> {
  const { enforceScope } = await import("./scope-guard");

  await enforceScope({
    engagementId: config.engagementId,
    targets: config.targets.map(t => ({ value: t })),
    tool: `scanforge:${config.tool || autoSelectTool(config)}:${config.profile}`,
    operatorId: config.operatorId,
    operatorName: config.operatorName,
  });

  return executeScanforgeScan(config);
}

// ─── Pre-flight Check ─────────────────────────────────────────────────────

/**
 * Verify that the remote server has ScanForge tools installed and accessible.
 */
export async function preflightCheck(server: ScanServerConfig): Promise<{
  available: boolean;
  tools: Record<string, { installed: boolean; version?: string }>;
  error?: string;
  hasSudo?: boolean;
}> {
  const tools: Record<string, { installed: boolean; version?: string }> = {};

  try {
    // Check each tool
    const checks = [
      { name: 'masscan', cmd: 'masscan --version 2>&1 | head -1' },
      { name: 'naabu', cmd: 'naabu -version 2>&1 | head -1' },
      { name: 'rustscan', cmd: 'rustscan --version 2>&1 | head -1' },
      { name: 'zmap', cmd: 'zmap --version 2>&1 | head -1' },
      { name: 'httpx', cmd: 'httpx -version 2>&1 | head -1' },
      { name: 'nuclei', cmd: 'nuclei -version 2>&1 | head -1' },
    ];

    for (const check of checks) {
      try {
        const { stdout, exitCode } = await executeSSHCommand(server, check.cmd, 10000);
        const version = stdout.trim().match(/[\d.]+/)?.[0];
        tools[check.name] = {
          installed: exitCode === 0 || stdout.includes(check.name) || !!version,
          version: version || 'unknown',
        };
      } catch {
        tools[check.name] = { installed: false };
      }
    }

    // Check sudo access
    let hasSudo = false;
    try {
      const sudoResult = await executeSSHCommand(server, "sudo -n true 2>&1", 5000);
      hasSudo = sudoResult.exitCode === 0;
    } catch {
      hasSudo = false;
    }

    const anyInstalled = Object.values(tools).some(t => t.installed);

    return {
      available: anyInstalled,
      tools,
      hasSudo,
    };
  } catch (err: any) {
    return {
      available: false,
      tools,
      error: err.message,
    };
  }
}
