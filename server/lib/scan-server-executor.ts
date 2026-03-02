/**
 * Scan Server Executor
 *
 * Generic SSH tool executor for the remote scan server. The LLM orchestrator
 * calls this to run any tool (nmap, nuclei, nikto, hydra, gobuster, etc.)
 * on the DigitalOcean droplet and get structured results back.
 *
 * Architecture:
 *   Dashboard LLM → decides tool + args → this executor → SSH → scan server → parse output
 *
 * The executor:
 *   1. Validates the command against a whitelist of allowed tools
 *   2. Connects to the scan server via SSH using env credentials
 *   3. Executes the command with a timeout
 *   4. Returns stdout/stderr/exitCode
 *   5. Optionally parses output (JSON, XML, or text)
 */
import { Client as SSHClient } from "ssh2";
import { ENV } from "../_core/env";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ToolExecConfig {
  /** The tool to run (must be in ALLOWED_TOOLS) */
  tool: string;
  /** Command-line arguments */
  args: string;
  /** Target (for logging and scope enforcement) */
  target?: string;
  /** Timeout in seconds (default 300 = 5 min) */
  timeoutSeconds?: number;
  /** Engagement ID for audit trail */
  engagementId?: number;
  /** Whether to run with sudo */
  sudo?: boolean;
}

export interface ToolExecResult {
  tool: string;
  command: string;
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  timedOut: boolean;
  error?: string;
}

export interface ScanServerStatus {
  connected: boolean;
  tools: Record<string, { installed: boolean; path?: string }>;
  uptime?: string;
  diskFree?: string;
  memoryFree?: string;
  error?: string;
}

// ─── Allowed Tools (whitelist) ──────────────────────────────────────────────

const ALLOWED_TOOLS = new Set([
  "nmap", "nuclei", "nikto", "gobuster", "hydra", "httpx", "naabu", "subfinder",
  "enum4linux", "smbclient", "ldapsearch", "snmpwalk", "nbtscan",
  "onesixtyone", "dig", "whois", "sqlmap", "wfuzz", "crackmapexec",
  "masscan", "curl", "wget", "cat", "head", "tail", "grep",
  // Allow reading tool manifest and health check
  "bash", "sh",
]);

// Characters that could indicate command injection
const DANGEROUS_CHARS = /[;&|`$(){}]/;

// ─── SSH Connection Helper ──────────────────────────────────────────────────

// Cache the downloaded SSH key so we only fetch once
let cachedSshKey: string | null = null;

// Fallback RSA key URL stored in S3 (uploaded during provisioning)
const SCAN_SERVER_KEY_URL = "https://files.manuscdn.com/user_upload_by_module/session_file/310419663028432609/hHJfIBSNDxDiefRC";

async function getScanServerConfig() {
  const host = ENV.SCAN_SERVER_HOST;
  const user = ENV.SCAN_SERVER_USER || "root";
  const sshKey = ENV.SCAN_SERVER_SSH_KEY;

  if (!host) throw new Error("SCAN_SERVER_HOST not configured");

  // Return cached key if available
  if (cachedSshKey) return { host, username: user, privateKey: cachedSshKey };

  let fixedKey: string | null = null;

  if (sshKey) {
    if (sshKey.startsWith('http://') || sshKey.startsWith('https://')) {
      // URL to the key file — download it
      try {
        const resp = await fetch(sshKey);
        if (resp.ok) fixedKey = await resp.text();
      } catch { /* fall through to fallback */ }
    } else if (!sshKey.startsWith('-----')) {
      // Base64 encoded
      fixedKey = Buffer.from(sshKey, 'base64').toString('utf8');
    } else if (sshKey.includes('\\n')) {
      // Literal \n sequences
      fixedKey = sshKey.split('\\n').join('\n');
    } else {
      fixedKey = sshKey;
    }
  }

  // Validate the key — if it's in OpenSSH format (not RSA PEM), ssh2 may not parse it correctly
  // In that case, fall back to downloading the RSA PEM key from S3
  if (!fixedKey || fixedKey.includes('OPENSSH')) {
    console.log('[ScanServer] Downloading RSA key from S3 fallback...');
    try {
      const resp = await fetch(SCAN_SERVER_KEY_URL);
      if (resp.ok) {
        fixedKey = await resp.text();
        console.log('[ScanServer] RSA key downloaded successfully');
      }
    } catch (e) {
      console.error('[ScanServer] Failed to download RSA key:', e);
    }
  }

  if (!fixedKey) throw new Error("SCAN_SERVER_SSH_KEY not configured and fallback download failed");

  cachedSshKey = fixedKey;
  return { host, username: user, privateKey: fixedKey };
}

async function executeSSH(
  command: string,
  timeoutMs: number
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const config = await getScanServerConfig();

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
        host: config.host,
        port: 22,
        username: config.username,
        privateKey: config.privateKey,
        readyTimeout: 15000,
        keepaliveInterval: 10000,
      });
  });
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Execute a tool on the remote scan server.
 * The tool must be in the ALLOWED_TOOLS whitelist.
 */
export async function executeTool(config: ToolExecConfig): Promise<ToolExecResult> {
  const { tool, args, timeoutSeconds = 300, sudo = false } = config;
  const startTime = Date.now();

  // Validate tool is allowed
  if (!ALLOWED_TOOLS.has(tool)) {
    return {
      tool,
      command: `${tool} ${args}`,
      stdout: "",
      stderr: `Tool "${tool}" is not in the allowed tools whitelist`,
      exitCode: -1,
      durationMs: 0,
      timedOut: false,
      error: `Tool "${tool}" not allowed`,
    };
  }

  // Build command
  const prefix = sudo ? "sudo " : "";
  const command = `${prefix}${tool} ${args} 2>&1`;

  try {
    const { stdout, stderr, exitCode } = await executeSSH(command, timeoutSeconds * 1000);
    return {
      tool,
      command: `${tool} ${args}`,
      stdout: stdout.slice(0, 500_000), // Cap at 500KB
      stderr: stderr.slice(0, 50_000),
      exitCode,
      durationMs: Date.now() - startTime,
      timedOut: false,
    };
  } catch (err: any) {
    const timedOut = err.message.includes("timed out");
    return {
      tool,
      command: `${tool} ${args}`,
      stdout: "",
      stderr: err.message,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      timedOut,
      error: err.message,
    };
  }
}

/**
 * Execute a raw command on the scan server (for advanced use cases).
 * Use with caution — prefer executeTool for standard operations.
 */
export async function executeRawCommand(
  command: string,
  timeoutSeconds: number = 300
): Promise<ToolExecResult> {
  const startTime = Date.now();
  try {
    const { stdout, stderr, exitCode } = await executeSSH(command, timeoutSeconds * 1000);
    return {
      tool: "raw",
      command,
      stdout: stdout.slice(0, 500_000),
      stderr: stderr.slice(0, 50_000),
      exitCode,
      durationMs: Date.now() - startTime,
      timedOut: false,
    };
  } catch (err: any) {
    return {
      tool: "raw",
      command,
      stdout: "",
      stderr: err.message,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      timedOut: err.message.includes("timed out"),
      error: err.message,
    };
  }
}

/**
 * Check the scan server status and available tools.
 */
export async function checkScanServerStatus(): Promise<ScanServerStatus> {
  try {
    const result = await executeSSH("cat /opt/tool-manifest.json 2>/dev/null && echo '---HEALTH---' && bash /opt/health-check.sh 2>/dev/null", 15000);
    const parts = result.stdout.split("---HEALTH---");
    let tools: Record<string, { installed: boolean; path?: string }> = {};

    try {
      const manifest = JSON.parse(parts[0].trim());
      for (const [name, info] of Object.entries(manifest.tools || {})) {
        tools[name] = { installed: true, path: (info as any).path };
      }
    } catch {}

    let health: any = {};
    try {
      health = JSON.parse((parts[1] || "").trim());
    } catch {}

    return {
      connected: true,
      tools,
      uptime: health.uptime,
      diskFree: health.disk_free,
      memoryFree: health.memory_free,
    };
  } catch (err: any) {
    return {
      connected: false,
      tools: {},
      error: err.message,
    };
  }
}

/**
 * Get the scan server config for the nmap-orchestrator (backwards compatibility).
 */
export async function getScanServerConfigForNmap() {
  const config = await getScanServerConfig();
  return {
    host: config.host,
    port: 22,
    username: config.username,
    privateKey: config.privateKey,
  };
}

/**
 * Generate tool commands based on asset type and discovered services.
 * This is used by the LLM to get suggested commands, which it can then
 * modify or execute directly.
 */
export function suggestToolCommands(asset: {
  hostname?: string;
  ip?: string;
  type?: string;
  ports: Array<{ port: number; service: string; version?: string }>;
}): Array<{ tool: string; args: string; purpose: string; priority: number }> {
  const target = asset.ip || asset.hostname || "";
  const commands: Array<{ tool: string; args: string; purpose: string; priority: number }> = [];

  // Always start with nmap service detection
  const portList = asset.ports.map(p => p.port).join(",");

  // Web services
  const webPorts = asset.ports.filter(p =>
    ["http", "https", "http-proxy", "http-alt"].includes(p.service) ||
    [80, 443, 8080, 8443, 8000, 3000, 5000, 9090].includes(p.port)
  );

  if (webPorts.length > 0) {
    for (const wp of webPorts) {
      const scheme = wp.port === 443 || wp.port === 8443 ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;

      commands.push({
        tool: "nikto",
        args: `-h ${url} -Tuning 1234567890 -maxtime 300`,
        purpose: `Web vulnerability scan on ${url}`,
        priority: 1,
      });

      commands.push({
        tool: "nuclei",
        args: `-u ${url} -severity low,medium,high,critical -json -timeout 5 -retries 1`,
        purpose: `CVE/vulnerability template scan on ${url}`,
        priority: 1,
      });

      commands.push({
        tool: "gobuster",
        args: `dir -u ${url} -w /opt/SecLists/Discovery/Web-Content/common.txt -t 20 -q --no-error`,
        purpose: `Directory brute-force on ${url}`,
        priority: 2,
      });

      commands.push({
        tool: "httpx",
        args: `-u ${url} -json -title -status-code -tech-detect -follow-redirects`,
        purpose: `HTTP probe and tech detection on ${url}`,
        priority: 1,
      });
    }
  }

  // SSH
  const sshPorts = asset.ports.filter(p => p.service === "ssh" || p.port === 22);
  if (sshPorts.length > 0) {
    for (const sp of sshPorts) {
      commands.push({
        tool: "hydra",
        args: `-l admin -P /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt -s ${sp.port} -t 4 -f ${target} ssh`,
        purpose: `SSH credential testing on port ${sp.port}`,
        priority: 3,
      });
    }
  }

  // SMB
  const smbPorts = asset.ports.filter(p =>
    ["microsoft-ds", "netbios-ssn", "smb"].includes(p.service) ||
    [139, 445].includes(p.port)
  );
  if (smbPorts.length > 0) {
    commands.push({
      tool: "enum4linux",
      args: `-a ${target}`,
      purpose: `SMB/NetBIOS enumeration`,
      priority: 2,
    });
    commands.push({
      tool: "smbclient",
      args: `-L //${target} -N`,
      purpose: `List SMB shares (anonymous)`,
      priority: 2,
    });
  }

  // LDAP
  const ldapPorts = asset.ports.filter(p =>
    ["ldap", "ldaps"].includes(p.service) || [389, 636].includes(p.port)
  );
  if (ldapPorts.length > 0) {
    commands.push({
      tool: "ldapsearch",
      args: `-x -H ldap://${target} -b "" -s base namingContexts`,
      purpose: `LDAP anonymous enumeration`,
      priority: 2,
    });
  }

  // SNMP
  const snmpPorts = asset.ports.filter(p =>
    p.service === "snmp" || p.port === 161
  );
  if (snmpPorts.length > 0) {
    commands.push({
      tool: "onesixtyone",
      args: `${target} public private`,
      purpose: `SNMP community string brute-force`,
      priority: 2,
    });
  }

  // DNS
  const dnsPorts = asset.ports.filter(p =>
    p.service === "domain" || p.port === 53
  );
  if (dnsPorts.length > 0 && asset.hostname) {
    commands.push({
      tool: "dig",
      args: `@${target} ${asset.hostname} any +noall +answer`,
      purpose: `DNS enumeration`,
      priority: 2,
    });
    commands.push({
      tool: "dig",
      args: `@${target} ${asset.hostname} axfr`,
      purpose: `DNS zone transfer attempt`,
      priority: 3,
    });
  }

  // FTP
  const ftpPorts = asset.ports.filter(p =>
    p.service === "ftp" || p.port === 21
  );
  if (ftpPorts.length > 0) {
    commands.push({
      tool: "hydra",
      args: `-l anonymous -p anonymous -s 21 -t 4 -f ${target} ftp`,
      purpose: `FTP anonymous login test`,
      priority: 2,
    });
  }

  // MySQL/PostgreSQL
  const dbPorts = asset.ports.filter(p =>
    ["mysql", "postgresql"].includes(p.service) || [3306, 5432].includes(p.port)
  );
  if (dbPorts.length > 0) {
    for (const dp of dbPorts) {
      const proto = dp.port === 5432 ? "postgres" : "mysql";
      commands.push({
        tool: "hydra",
        args: `-l root -P /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt -s ${dp.port} -t 4 -f ${target} ${proto}`,
        purpose: `${proto} credential testing on port ${dp.port}`,
        priority: 3,
      });
    }
  }

  // RDP
  const rdpPorts = asset.ports.filter(p =>
    p.service === "ms-wbt-server" || p.port === 3389
  );
  if (rdpPorts.length > 0) {
    commands.push({
      tool: "hydra",
      args: `-l administrator -P /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt -s 3389 -t 4 -f ${target} rdp`,
      purpose: `RDP credential testing`,
      priority: 3,
    });
  }

  // Sort by priority
  commands.sort((a, b) => a.priority - b.priority);
  return commands;
}
