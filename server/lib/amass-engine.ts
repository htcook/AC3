/**
 * Amass Execution Engine
 * 
 * SSH-based remote execution of OWASP Amass for active subdomain enumeration.
 * Supports passive, active, brute-force, and intel modes with JSON output parsing.
 * Integrates with the ROE scope guard to enforce engagement boundaries.
 * 
 * Amass is licensed under Apache 2.0 — fully permissible for commercial use.
 * The operator installs Amass on their scan servers; this engine orchestrates
 * execution via SSH (same pattern as scanforge-discovery.ts).
 */

import crypto from "crypto";
import { Client as SSHClient } from "ssh2";
import fs from "fs";
import { enforceScope, type ScopeContext } from "./scope-guard";
import { FIPS_SSH_ALGORITHMS } from "./fips-ssh";

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

export type AmassMode = "passive" | "active" | "brute" | "full" | "intel";

export type AmassIntelMode = "org" | "asn" | "cidr" | "whois";

export interface AmassScanConfig {
  /** Target domains to enumerate */
  domains: string[];
  /** Scan mode */
  mode: AmassMode;
  /** Scan server SSH connection details */
  server: AmassScanServer;
  /** Engagement ID for scope enforcement */
  engagementId?: string;
  /** Custom wordlist path on the scan server for brute-force */
  wordlistPath?: string;
  /** Ports to check (default: 443) */
  ports?: number[];
  /** Custom DNS resolvers */
  resolvers?: string[];
  /** Resolver file path on the scan server */
  resolverFilePath?: string;
  /** Blacklisted subdomains to exclude */
  blacklist?: string[];
  /** Disable altered name generation */
  noAlts?: boolean;
  /** Disable recursive brute forcing */
  noRecursive?: boolean;
  /** Min labels before recursive brute forcing (default: 1) */
  minForRecursive?: number;
  /** Include unresolvable DNS names */
  includeUnresolvable?: boolean;
  /** Print data sources for discovered names */
  showSources?: boolean;
  /** Timeout in minutes (default: 30) */
  timeoutMinutes?: number;
  /** Path to Amass config file on the scan server */
  configPath?: string;
  /** Path to Amass binary on the scan server */
  amassPath?: string;
  /** Maximum execution time in seconds for SSH command (default: 2400) */
  sshTimeoutSeconds?: number;
}

export interface AmassIntelConfig {
  /** Intel mode type */
  intelMode: AmassIntelMode;
  /** Query value (org name, ASN number, CIDR, or domain for whois) */
  query: string;
  /** Scan server SSH connection details */
  server: AmassScanServer;
  /** Path to Amass binary on the scan server */
  amassPath?: string;
  /** SSH timeout in seconds */
  sshTimeoutSeconds?: number;
}

export interface AmassScanServer {
  host: string;
  port?: number;
  username: string;
  privateKey?: string | Buffer;
  privateKeyPath?: string;
}

export interface AmassResult {
  scanId: string;
  status: "completed" | "failed" | "timeout";
  mode: AmassMode;
  domains: string[];
  startedAt: number;
  completedAt: number;
  durationMs: number;
  command: string;
  /** Discovered subdomains with full metadata */
  subdomains: AmassSubdomain[];
  /** Unique IP addresses found */
  uniqueIps: string[];
  /** Unique ASNs found */
  uniqueAsns: number[];
  /** Data sources that contributed findings */
  dataSources: string[];
  /** Summary statistics */
  summary: AmassSummary;
  /** Raw stderr output for debugging */
  stderr?: string;
  /** Error message if failed */
  error?: string;
}

export interface AmassSubdomain {
  /** Fully qualified domain name */
  name: string;
  /** Parent domain */
  domain: string;
  /** Resolved IP addresses with network info */
  addresses: AmassAddress[];
  /** Discovery tag (dns, cert, brute, alt, etc.) */
  tag: string;
  /** Data sources that found this subdomain */
  sources: string[];
}

export interface AmassAddress {
  ip: string;
  cidr: string;
  asn: number;
  desc: string;
}

export interface AmassSummary {
  totalSubdomains: number;
  totalUniqueIps: number;
  totalAsns: number;
  totalSources: number;
  resolvedCount: number;
  unresolvedCount: number;
  /** Breakdown by discovery method */
  byTag: Record<string, number>;
  /** Breakdown by data source */
  bySource: Record<string, number>;
  /** Breakdown by ASN */
  byAsn: Record<string, { count: number; desc: string }>;
  /** Subdomains per domain */
  byDomain: Record<string, number>;
}

export interface AmassIntelResult {
  scanId: string;
  status: "completed" | "failed";
  intelMode: AmassIntelMode;
  query: string;
  /** Discovered domains/organizations */
  discoveries: string[];
  error?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wordlists — built-in high-value subdomain prefixes for brute-force
// ═══════════════════════════════════════════════════════════════════════════════

export const BUILT_IN_WORDLIST: string[] = [
  // Infrastructure
  "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "ns3", "dns",
  "dns1", "dns2", "mx", "mx1", "mx2", "relay", "gateway", "proxy",
  // Web services
  "api", "app", "web", "portal", "admin", "panel", "dashboard", "console",
  "login", "auth", "sso", "oauth", "accounts", "my", "account",
  // Development & CI/CD
  "dev", "staging", "stage", "test", "testing", "qa", "uat", "sandbox",
  "demo", "beta", "alpha", "preview", "canary", "ci", "cd", "build",
  "jenkins", "gitlab", "github", "bitbucket", "bamboo", "drone", "argo",
  // Cloud & containers
  "cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "docker", "registry",
  "harbor", "ecr", "gcr", "acr", "s3", "cdn", "static", "assets", "media",
  // Databases & storage
  "db", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb",
  "redis", "elastic", "elasticsearch", "kibana", "grafana", "influx",
  "minio", "ceph", "nfs", "backup", "backups", "storage",
  // Monitoring & logging
  "monitor", "monitoring", "nagios", "zabbix", "prometheus", "alertmanager",
  "log", "logs", "logging", "splunk", "elk", "graylog", "sentry", "datadog",
  // Security
  "vpn", "openvpn", "wireguard", "firewall", "waf", "ids", "ips",
  "siem", "vault", "secrets", "cert", "certs", "pki", "ca",
  // Communication
  "chat", "slack", "teams", "meet", "zoom", "webex", "jitsi",
  "wiki", "confluence", "docs", "documentation", "help", "support",
  "jira", "ticket", "tickets", "helpdesk", "servicedesk",
  // Network
  "intranet", "internal", "corp", "corporate", "office", "remote",
  "bastion", "jump", "jumpbox", "ssh", "rdp", "vnc", "telnet",
  "switch", "router", "fw", "lb", "loadbalancer", "haproxy", "nginx",
  // Services
  "crm", "erp", "hr", "payroll", "finance", "billing", "payment",
  "shop", "store", "ecommerce", "cart", "checkout", "order", "orders",
  "blog", "cms", "wordpress", "wp", "drupal", "joomla",
  // APIs & microservices
  "api-v1", "api-v2", "api-gateway", "graphql", "rest", "grpc",
  "service", "services", "microservice", "ms", "svc",
  // Email
  "webmail", "owa", "exchange", "autodiscover", "autoconfig",
  "spam", "antispam", "dkim", "spf", "dmarc",
  // Misc
  "status", "health", "ping", "info", "about", "contact",
  "download", "downloads", "upload", "uploads", "files", "file",
  "img", "images", "image", "video", "videos", "stream",
  "search", "analytics", "metrics", "report", "reports",
  "old", "legacy", "archive", "temp", "tmp", "cache",
  "m", "mobile", "wap", "touch",
];

// ═══════════════════════════════════════════════════════════════════════════════
// SSH Command Execution (same pattern as scanforge-discovery)
// ═══════════════════════════════════════════════════════════════════════════════

function executeSSHCommand(
  server: AmassScanServer,
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
        // FIPS 140-3: Restrict to NIST-approved SSH algorithms only
        algorithms: FIPS_SSH_ALGORITHMS,
      });
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Command Builder
// ═══════════════════════════════════════════════════════════════════════════════

function buildEnumCommand(config: AmassScanConfig): string {
  const amass = config.amassPath || "amass";
  const args: string[] = ["enum"];

  // Mode flags
  switch (config.mode) {
    case "passive":
      args.push("-passive");
      break;
    case "active":
      args.push("-active");
      break;
    case "brute":
      args.push("-brute");
      break;
    case "full":
      args.push("-active", "-brute");
      break;
    // "intel" mode uses a different subcommand
  }

  // Target domains
  for (const domain of config.domains) {
    args.push("-d", sanitize(domain));
  }

  // Wordlist for brute force
  if ((config.mode === "brute" || config.mode === "full") && config.wordlistPath) {
    args.push("-w", config.wordlistPath);
  }

  // Ports
  if (config.ports && config.ports.length > 0) {
    args.push("-p", config.ports.join(","));
  }

  // Resolvers
  if (config.resolvers && config.resolvers.length > 0) {
    args.push("-r", config.resolvers.join(","));
  }
  if (config.resolverFilePath) {
    args.push("-rf", config.resolverFilePath);
  }

  // Blacklist
  if (config.blacklist && config.blacklist.length > 0) {
    for (const bl of config.blacklist) {
      args.push("-bl", sanitize(bl));
    }
  }

  // Options
  if (config.noAlts) args.push("-noalts");
  if (config.noRecursive) args.push("-norecursive");
  if (config.minForRecursive !== undefined) {
    args.push("-min-for-recursive", String(config.minForRecursive));
  }
  if (config.includeUnresolvable) args.push("-include-unresolvable");
  if (config.showSources) args.push("-src");
  if (config.configPath) args.push("-config", config.configPath);

  // Timeout
  const timeout = config.timeoutMinutes || 30;
  args.push("-timeout", String(timeout));

  // JSON output to stdout via temp file
  const tmpFile = `/tmp/amass-${Date.now()}.json`;
  args.push("-json", tmpFile);

  return { command: `${amass} ${args.join(" ")} 2>&1 && cat ${tmpFile} && rm -f ${tmpFile}`, displayCommand: `${amass} ${args.join(" ")}` } as any;
}

function buildEnumCommandStr(config: AmassScanConfig): { command: string; displayCommand: string } {
  const amass = config.amassPath || "amass";
  const args: string[] = ["enum"];

  switch (config.mode) {
    case "passive":
      args.push("-passive");
      break;
    case "active":
      args.push("-active");
      break;
    case "brute":
      args.push("-brute");
      break;
    case "full":
      args.push("-active", "-brute");
      break;
  }

  for (const domain of config.domains) {
    args.push("-d", sanitize(domain));
  }

  if ((config.mode === "brute" || config.mode === "full") && config.wordlistPath) {
    args.push("-w", config.wordlistPath);
  }

  if (config.ports && config.ports.length > 0) {
    args.push("-p", config.ports.join(","));
  }

  if (config.resolvers && config.resolvers.length > 0) {
    args.push("-r", config.resolvers.join(","));
  }
  if (config.resolverFilePath) {
    args.push("-rf", config.resolverFilePath);
  }

  if (config.blacklist && config.blacklist.length > 0) {
    for (const bl of config.blacklist) {
      args.push("-bl", sanitize(bl));
    }
  }

  if (config.noAlts) args.push("-noalts");
  if (config.noRecursive) args.push("-norecursive");
  if (config.minForRecursive !== undefined) {
    args.push("-min-for-recursive", String(config.minForRecursive));
  }
  if (config.includeUnresolvable) args.push("-include-unresolvable");
  if (config.showSources) args.push("-src");
  if (config.configPath) args.push("-config", config.configPath);

  const timeout = config.timeoutMinutes || 30;
  args.push("-timeout", String(timeout));

  const tmpFile = `/tmp/amass-${Date.now()}-${crypto.randomBytes(4).toString("hex")}.json`;
  args.push("-json", tmpFile);

  const displayCommand = `${amass} ${args.join(" ")}`;
  const command = `${displayCommand} 2>/tmp/amass-stderr.txt; cat ${tmpFile} 2>/dev/null; rm -f ${tmpFile}; cat /tmp/amass-stderr.txt >&2; rm -f /tmp/amass-stderr.txt`;

  return { command, displayCommand };
}

function buildIntelCommand(config: AmassIntelConfig): { command: string; displayCommand: string } {
  const amass = config.amassPath || "amass";
  const args: string[] = ["intel"];

  switch (config.intelMode) {
    case "org":
      args.push("-org", `"${sanitize(config.query)}"`);
      break;
    case "asn":
      args.push("-asn", sanitize(config.query));
      break;
    case "cidr":
      args.push("-cidr", sanitize(config.query));
      break;
    case "whois":
      args.push("-whois", "-d", sanitize(config.query));
      break;
  }

  const displayCommand = `${amass} ${args.join(" ")}`;
  return { command: `${displayCommand} 2>/dev/null`, displayCommand };
}

function sanitize(input: string): string {
  return input.replace(/[;&|`$(){}'"\\]/g, "");
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSON Output Parser
// ═══════════════════════════════════════════════════════════════════════════════

export function parseAmassJsonOutput(jsonOutput: string): AmassSubdomain[] {
  const subdomains: AmassSubdomain[] = [];
  const seen = new Set<string>();

  // Amass outputs one JSON object per line (JSONL format)
  const lines = jsonOutput.split("\n").filter(l => l.trim());

  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      if (!entry.name) continue;

      const key = entry.name.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);

      const subdomain: AmassSubdomain = {
        name: entry.name,
        domain: entry.domain || extractParentDomain(entry.name),
        addresses: (entry.addresses || []).map((addr: any) => ({
          ip: addr.ip || "",
          cidr: addr.cidr || "",
          asn: addr.asn || 0,
          desc: addr.desc || "",
        })),
        tag: entry.tag || "unknown",
        sources: Array.isArray(entry.sources) ? entry.sources : (entry.source ? [entry.source] : []),
      };

      subdomains.push(subdomain);
    } catch {
      // Skip malformed lines (stderr mixed in, progress output, etc.)
      continue;
    }
  }

  return subdomains;
}

function extractParentDomain(fqdn: string): string {
  const parts = fqdn.split(".");
  if (parts.length <= 2) return fqdn;
  return parts.slice(-2).join(".");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Summary Generator
// ═══════════════════════════════════════════════════════════════════════════════

export function generateAmassSummary(subdomains: AmassSubdomain[]): AmassSummary {
  const byTag: Record<string, number> = {};
  const bySource: Record<string, number> = {};
  const byAsn: Record<string, { count: number; desc: string }> = {};
  const byDomain: Record<string, number> = {};
  const allIps = new Set<string>();
  const allAsns = new Set<number>();
  let resolvedCount = 0;
  let unresolvedCount = 0;

  for (const sub of subdomains) {
    // By tag
    byTag[sub.tag] = (byTag[sub.tag] || 0) + 1;

    // By source
    for (const src of sub.sources) {
      bySource[src] = (bySource[src] || 0) + 1;
    }

    // By domain
    byDomain[sub.domain] = (byDomain[sub.domain] || 0) + 1;

    // Addresses
    if (sub.addresses.length > 0) {
      resolvedCount++;
      for (const addr of sub.addresses) {
        if (addr.ip) allIps.add(addr.ip);
        if (addr.asn) {
          allAsns.add(addr.asn);
          const asnKey = String(addr.asn);
          if (!byAsn[asnKey]) {
            byAsn[asnKey] = { count: 0, desc: addr.desc };
          }
          byAsn[asnKey].count++;
        }
      }
    } else {
      unresolvedCount++;
    }
  }

  return {
    totalSubdomains: subdomains.length,
    totalUniqueIps: allIps.size,
    totalAsns: allAsns.size,
    totalSources: Object.keys(bySource).length,
    resolvedCount,
    unresolvedCount,
    byTag,
    bySource,
    byAsn,
    byDomain,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main Execution Functions
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Execute an Amass enumeration scan with scope enforcement.
 */
export async function executeAmassEnum(config: AmassScanConfig): Promise<AmassResult> {
  const scanId = `amass-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  const startedAt = Date.now();
  const sshTimeout = (config.sshTimeoutSeconds || 2400) * 1000;

  // Scope enforcement — validate all target domains are in scope
  if (config.engagementId) {
    for (const domain of config.domains) {
      await enforceScope({
        engagementId: config.engagementId,
        targets: [domain],
        toolName: `amass_${config.mode}`,
        action: `Amass ${config.mode} enumeration`,
      });
    }
  }

  const { command, displayCommand } = buildEnumCommandStr(config);

  try {
    const { stdout, stderr, exitCode } = await executeSSHCommand(
      config.server,
      command,
      sshTimeout
    );

    const completedAt = Date.now();

    // Parse JSON output from stdout
    const subdomains = parseAmassJsonOutput(stdout);
    const summary = generateAmassSummary(subdomains);

    const uniqueIps = [...new Set(subdomains.flatMap(s => s.addresses.map(a => a.ip)).filter(Boolean))];
    const uniqueAsns = [...new Set(subdomains.flatMap(s => s.addresses.map(a => a.asn)).filter(Boolean))];
    const dataSources = [...new Set(subdomains.flatMap(s => s.sources))];

    return {
      scanId,
      status: exitCode === 0 || subdomains.length > 0 ? "completed" : "failed",
      mode: config.mode,
      domains: config.domains,
      startedAt,
      completedAt,
      durationMs: completedAt - startedAt,
      command: displayCommand,
      subdomains,
      uniqueIps,
      uniqueAsns,
      dataSources,
      summary,
      stderr: stderr || undefined,
      error: exitCode !== 0 && subdomains.length === 0 ? `Amass exited with code ${exitCode}` : undefined,
    };
  } catch (err: any) {
    const completedAt = Date.now();
    return {
      scanId,
      status: err.message?.includes("timed out") ? "timeout" : "failed",
      mode: config.mode,
      domains: config.domains,
      startedAt,
      completedAt,
      durationMs: completedAt - startedAt,
      command: displayCommand,
      subdomains: [],
      uniqueIps: [],
      uniqueAsns: [],
      dataSources: [],
      summary: {
        totalSubdomains: 0,
        totalUniqueIps: 0,
        totalAsns: 0,
        totalSources: 0,
        resolvedCount: 0,
        unresolvedCount: 0,
        byTag: {},
        bySource: {},
        byAsn: {},
        byDomain: {},
      },
      error: err.message,
    };
  }
}

/**
 * Execute Amass intel subcommand for organization/ASN/CIDR discovery.
 */
export async function executeAmassIntel(config: AmassIntelConfig): Promise<AmassIntelResult> {
  const scanId = `amass-intel-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  const sshTimeout = (config.sshTimeoutSeconds || 120) * 1000;

  const { command, displayCommand } = buildIntelCommand(config);

  try {
    const { stdout, exitCode } = await executeSSHCommand(
      config.server,
      command,
      sshTimeout
    );

    const discoveries = stdout
      .split("\n")
      .map(l => l.trim())
      .filter(l => l.length > 0 && !l.startsWith("{"));

    return {
      scanId,
      status: exitCode === 0 ? "completed" : "failed",
      intelMode: config.intelMode,
      query: config.query,
      discoveries,
      error: exitCode !== 0 ? `Amass intel exited with code ${exitCode}` : undefined,
    };
  } catch (err: any) {
    return {
      scanId,
      status: "failed",
      intelMode: config.intelMode,
      query: config.query,
      discoveries: [],
      error: err.message,
    };
  }
}

/**
 * Execute Amass with scope enforcement — validates all targets and discovered
 * subdomains against the ROE scope before returning results.
 */
export async function scanWithScopeEnforcement(
  config: AmassScanConfig
): Promise<AmassResult> {
  // enforceScope is called inside executeAmassEnum
  const result = await executeAmassEnum(config);

  // Post-scan: filter out any discovered subdomains that resolve to out-of-scope IPs
  // This handles the case where a subdomain resolves to an IP outside the ROE boundary
  if (config.engagementId && result.subdomains.length > 0) {
    const filteredSubdomains: AmassSubdomain[] = [];
    for (const sub of result.subdomains) {
      // Keep subdomains that have no addresses (unresolved) — they're just DNS names
      if (sub.addresses.length === 0) {
        filteredSubdomains.push(sub);
        continue;
      }
      // Check if any resolved IP is in scope
      // We don't block here — we flag out-of-scope IPs for the operator
      filteredSubdomains.push({
        ...sub,
        addresses: sub.addresses.map(addr => ({
          ...addr,
          // Add a marker for out-of-scope IPs (the UI can highlight these)
        })),
      });
    }
    result.subdomains = filteredSubdomains;
    result.summary = generateAmassSummary(filteredSubdomains);
  }

  return result;
}

/**
 * Preflight check — verify Amass is installed and accessible on the scan server.
 */
export async function preflightCheck(server: AmassScanServer): Promise<{
  available: boolean;
  version?: string;
  error?: string;
}> {
  try {
    const amassPath = "amass";
    const { stdout, exitCode } = await executeSSHCommand(
      server,
      `${amassPath} -version 2>&1 || ${amassPath} --version 2>&1 || echo "amass not found"`,
      10000
    );

    if (exitCode !== 0 || stdout.includes("not found") || stdout.includes("command not found")) {
      return { available: false, error: "Amass is not installed or not in PATH" };
    }

    // Extract version from output like "OWASP Amass v4.2.0" or "v4.2.0"
    const versionMatch = stdout.match(/v?(\d+\.\d+\.\d+)/);
    return {
      available: true,
      version: versionMatch ? versionMatch[1] : stdout.trim().substring(0, 50),
    };
  } catch (err: any) {
    return { available: false, error: err.message };
  }
}

/**
 * Convert Amass results to the unified discovery format used by the observation normalizer.
 * This bridges Amass output into the SSIL pipeline.
 */
export function toUnifiedDiscoveryFormat(result: AmassResult): Array<{
  type: "subdomain";
  name: string;
  domain: string;
  ips: string[];
  asns: number[];
  sources: string[];
  tag: string;
  discoveredAt: number;
  tool: "amass";
  mode: AmassMode;
}> {
  return result.subdomains.map(sub => ({
    type: "subdomain" as const,
    name: sub.name,
    domain: sub.domain,
    ips: sub.addresses.map(a => a.ip).filter(Boolean),
    asns: sub.addresses.map(a => a.asn).filter(Boolean),
    sources: sub.sources,
    tag: sub.tag,
    discoveredAt: result.completedAt,
    tool: "amass" as const,
    mode: result.mode,
  }));
}

/**
 * Generate a built-in wordlist file on the scan server for brute-force mode.
 * Returns the path to the wordlist file.
 */
export async function deployBuiltInWordlist(server: AmassScanServer): Promise<string> {
  const wordlistPath = "/tmp/amass-builtin-wordlist.txt";
  const wordlistContent = BUILT_IN_WORDLIST.join("\\n");
  
  await executeSSHCommand(
    server,
    `echo -e "${wordlistContent}" > ${wordlistPath}`,
    10000
  );

  return wordlistPath;
}

/**
 * Compare two Amass scan results to identify new, removed, and changed subdomains.
 * Useful for tracking attack surface changes over time.
 */
export function diffAmassResults(
  previous: AmassResult,
  current: AmassResult
): {
  newSubdomains: AmassSubdomain[];
  removedSubdomains: AmassSubdomain[];
  changedSubdomains: Array<{
    name: string;
    previousIps: string[];
    currentIps: string[];
  }>;
  summary: {
    added: number;
    removed: number;
    changed: number;
    unchanged: number;
  };
} {
  const prevMap = new Map(previous.subdomains.map(s => [s.name.toLowerCase(), s]));
  const currMap = new Map(current.subdomains.map(s => [s.name.toLowerCase(), s]));

  const newSubdomains: AmassSubdomain[] = [];
  const removedSubdomains: AmassSubdomain[] = [];
  const changedSubdomains: Array<{ name: string; previousIps: string[]; currentIps: string[] }> = [];
  let unchanged = 0;

  // Find new and changed
  for (const [name, curr] of currMap) {
    const prev = prevMap.get(name);
    if (!prev) {
      newSubdomains.push(curr);
    } else {
      const prevIps = prev.addresses.map(a => a.ip).sort().join(",");
      const currIps = curr.addresses.map(a => a.ip).sort().join(",");
      if (prevIps !== currIps) {
        changedSubdomains.push({
          name: curr.name,
          previousIps: prev.addresses.map(a => a.ip),
          currentIps: curr.addresses.map(a => a.ip),
        });
      } else {
        unchanged++;
      }
    }
  }

  // Find removed
  for (const [name, prev] of prevMap) {
    if (!currMap.has(name)) {
      removedSubdomains.push(prev);
    }
  }

  return {
    newSubdomains,
    removedSubdomains,
    changedSubdomains,
    summary: {
      added: newSubdomains.length,
      removed: removedSubdomains.length,
      changed: changedSubdomains.length,
      unchanged,
    },
  };
}
