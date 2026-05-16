/**
 * Scan Server Executor
 *
 * Generic SSH tool executor for the remote scan server. The LLM orchestrator
 * calls this to run any tool (ScanForge discovery, nuclei, nikto, hydra, gobuster, etc.)
 * on the AWS EC2 scan instance and get structured results back.
 *
 * Architecture:
 *   Dashboard LLM → decides tool + args → this executor → SSH → AWS EC2 scan server → parse output
 *
 * The executor:
 *   1. Validates the command against a whitelist of allowed tools
 *   2. Connects to the scan server via SSH using env credentials
 *   3. Executes the command with a timeout
 *   4. Returns stdout/stderr/exitCode
 *   5. Optionally parses output (JSON, XML, or text)
 */
import { Client as SSHClient } from "ssh2";
import { createRequire } from "module";
const _require = createRequire(import.meta.url);
const sshUtils = _require("ssh2").utils;
import { ENV } from "../_core/env";
import { matchCredentialsForAsset } from "./oem-default-creds";
import { FIPS_SSH_ALGORITHMS } from "./fips-ssh";

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
  "scanforge-discovery", "nuclei", "nikto", "gobuster", "hydra", "httpx", "naabu", "subfinder",
  "enum4linux", "smbclient", "ldapsearch", "snmpwalk", "nbtscan",
  "onesixtyone", "dig", "whois", "sqlmap", "wfuzz", "crackmapexec",
  "masscan", "curl", "wget", "cat", "head", "tail", "grep",
  // Web application & SSL scanning tools
  "ffuf", "sslscan", "whatweb", "testssl", "wpscan", "zap-cli", "zap.sh",
  // OWASP ZAP (via Docker or direct install)
  "zap", "docker", "zaproxy",
  // Cloud storage & misconfiguration enumeration tools
  "cloud_enum", "s3scanner", "trufflehog", "aws",
  // Packet capture, analysis & manipulation tools
  "tcpdump", "tshark", "editcap", "mergecap", "capinfos",
  // Scapy packet crafting (via Python)
  "python3", "scapy",
  // Advanced injection & XSS testing tools
  "xsstrike", "dalfox",
  // Command injection & template injection tools
  "commix", "tplmap",
  // Service fingerprinting, SSH audit, and web crawling
  "nerva", "ssh-audit", "katana",
  // Recursive content discovery & web fuzzing (Audit R4, R12)
  "feroxbuster", "dirb", "dirsearch",
  // Parameter discovery (Audit R7)
  "arjun", "paramspider",
  // WAF fingerprinting (Audit R15)
  "wafw00f",
  // TLS vulnerability testing (Audit R8)
  "testssl.sh",
  // Screenshot capture
  "chromium", "chromium-browser", "google-chrome", "puppeteer",
  // Allow reading tool manifest and health check
  "bash", "sh", "uptime", "df", "free",
]);

// Characters that could indicate command injection
const DANGEROUS_CHARS = /[;&|`$(){}]/;

// ─── SSH Connection Helper ──────────────────────────────────────────────────

// Cache the downloaded SSH key so we only fetch once
let cachedSshKey: string | null = null;

// Fallback RSA key URL — prefer SCAN_SERVER_KEY_URL env var for DO/self-hosted deployments.
// Falls back to Manus CDN URL only when env var is not set (Manus sandbox).
const SCAN_SERVER_KEY_URL = process.env.SCAN_SERVER_KEY_URL
  || "https://files.manuscdn.com/user_upload_by_module/session_file/310419663028432609/hHJfIBSNDxDiefRC";

export async function getScanServerConfig() {
  // Route SSH scan execution to the dedicated ScanForge EC2 instance.
  // Configured via SCANFORGE_HOST or SCAN_SERVER_HOST environment variable.
  const host = process.env.SCANFORGE_HOST || process.env.SCAN_SERVER_HOST || ENV.SCAN_SERVER_HOST || "";
  const user = ENV.SCAN_SERVER_USER || "root";
  // Read SSH key directly from process.env (removed from ENV object to prevent
  // deployment system from injecting multi-line PEM into Docker build command)
  const sshKey = process.env.SCAN_SERVER_SSH_KEY ?? "";

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

  // Validate the key using ssh2's parseKey — supports RSA PEM, OpenSSH ed25519, etc.
  // Only fall back to the S3 RSA key if the env key is missing or truly unparseable.
  if (fixedKey) {
    const parsed = sshUtils.parseKey(fixedKey);
    if (parsed instanceof Error) {
      console.log(`[ScanServer] Env SSH key parse failed (${parsed.message}), trying S3 RSA fallback...`);
      fixedKey = null; // Clear so we fall through to fallback
    } else {
      console.log(`[ScanServer] Using env SSH key (type: ${parsed.type}, comment: ${parsed.comment || 'none'})`);
    }
  }

  // Fallback: download the RSA PEM key from S3 if env key was missing or unparseable
  if (!fixedKey) {
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

// ─── SSH Connection Pool ────────────────────────────────────────────────────
// Reuse a persistent SSH connection across sequential scans to avoid
// rapid connect/disconnect cycles that cause connection failures.
let pooledConn: InstanceType<typeof SSHClient> | null = null;
let pooledConnReady = false;
let poolIdleTimer: NodeJS.Timeout | null = null;
const POOL_IDLE_TIMEOUT = 60_000; // Close idle connection after 60s

function resetPoolIdleTimer() {
  if (poolIdleTimer) clearTimeout(poolIdleTimer);
  poolIdleTimer = setTimeout(() => {
    if (pooledConn) {
      pooledConn.end();
      pooledConn = null;
      pooledConnReady = false;
    }
  }, POOL_IDLE_TIMEOUT);
}

/**
 * Clean up the SSH connection pool.
 * Call during graceful shutdown to prevent connection leaks.
 */
export function cleanupSSHPool(): void {
  if (poolIdleTimer) {
    clearTimeout(poolIdleTimer);
    poolIdleTimer = null;
  }
  if (pooledConn) {
    try {
      pooledConn.end();
      console.log('[ScanServer] SSH pool connection closed (graceful shutdown)');
    } catch { /* ignore */ }
    pooledConn = null;
    pooledConnReady = false;
  }
}

async function getPooledConnection(): Promise<InstanceType<typeof SSHClient>> {
  if (pooledConn && pooledConnReady) {
    resetPoolIdleTimer();
    return pooledConn;
  }
  // Close stale connection if exists
  if (pooledConn) {
    try { pooledConn.end(); } catch { /* ignore */ }
    pooledConn = null;
    pooledConnReady = false;
  }
  const config = await getScanServerConfig();
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    const readyTimer = setTimeout(() => {
      conn.end();
      reject(new Error('SSH pool connection timed out after 20s'));
    }, 20000);
    conn
      .on('ready', () => {
        clearTimeout(readyTimer);
        pooledConn = conn;
        pooledConnReady = true;
        resetPoolIdleTimer();
        resolve(conn);
      })
      .on('error', (err) => {
        clearTimeout(readyTimer);
        pooledConn = null;
        pooledConnReady = false;
        reject(new Error(`SSH pool connection error: ${err.message}`));
      })
      .on('close', () => {
        pooledConn = null;
        pooledConnReady = false;
      })
      .connect({
        host: config.host,
        port: 22,
        username: config.username,
        privateKey: config.privateKey,
        readyTimeout: 20000,
        keepaliveInterval: 10000,
        algorithms: FIPS_SSH_ALGORITHMS,
      });
  });
}

/** Execute a command on a pooled SSH connection (reuses connection across calls) */
async function executeSSHPooled(
  command: string,
  timeoutMs: number
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const conn = await getPooledConnection();
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      reject(new Error(`SSH command timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);
    conn.exec(command, (err, stream) => {
      if (err) {
        clearTimeout(timer);
        return reject(err);
      }
      stream.on('close', (code: number) => {
        clearTimeout(timer);
        resetPoolIdleTimer();
        if (!timedOut) {
          resolve({ stdout, stderr, exitCode: code || 0 });
        }
      });
      stream.on('data', (data: Buffer) => {
        stdout += data.toString();
      });
      stream.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });
    });
  });
}

/** Execute a command with a fresh SSH connection (original behavior) */
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
        // FIPS 140-3: Restrict to NIST-approved SSH algorithms only
        algorithms: FIPS_SSH_ALGORITHMS,
      });
  });
}

// ─── P6: SSH Retry with Exponential Backoff ────────────────────────────────
// Wraps SSH execution functions with automatic retry on connection failures.
// Only retries on transient SSH errors (connection reset, timeout, ECONNREFUSED);
// does NOT retry on tool-level errors (non-zero exit code from the scan tool).

const SSH_RETRY_CONFIG = {
  maxRetries: 3,
  baseDelayMs: 2000,  // 2s → 4s → 8s exponential backoff
  backoffMultiplier: 2,
  /** Error patterns that indicate a transient SSH/network issue worth retrying */
  retryablePatterns: [
    'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EHOSTUNREACH', 'ENETUNREACH',
    'SSH connection error', 'SSH pool connection error', 'SSH pool connection timed out',
    'SSH command timed out', 'socket hang up', 'Connection reset',
    'read ECONNRESET', 'connect ECONNREFUSED', 'Channel open failure',
    'Keepalive timeout', 'Client-side network socket disconnected',
  ],
};

interface SSHRetryMetrics {
  totalRetries: number;
  successAfterRetry: number;
  exhaustedRetries: number;
}

const sshRetryMetrics: SSHRetryMetrics = {
  totalRetries: 0,
  successAfterRetry: 0,
  exhaustedRetries: 0,
};

export function getSSHRetryMetrics(): SSHRetryMetrics {
  return { ...sshRetryMetrics };
}

function isRetryableSSHError(error: Error | string): boolean {
  const msg = typeof error === 'string' ? error : error.message;
  return SSH_RETRY_CONFIG.retryablePatterns.some(pattern => msg.includes(pattern));
}

async function sshSleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Execute an SSH command with automatic retry on transient connection failures.
 * Invalidates the pooled connection on failure so the next attempt gets a fresh one.
 */
async function executeSSHWithRetry(
  command: string,
  timeoutSeconds: number,
  usePool: boolean = true
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= SSH_RETRY_CONFIG.maxRetries; attempt++) {
    try {
      if (usePool) {
        return await executeSSHPooled(command, timeoutSeconds * 1000);
      } else {
        return await executeViaChildProcessSSH(command, timeoutSeconds);
      }
    } catch (err: any) {
      lastError = err;

      if (attempt < SSH_RETRY_CONFIG.maxRetries && isRetryableSSHError(err)) {
        sshRetryMetrics.totalRetries++;
        const delay = SSH_RETRY_CONFIG.baseDelayMs * Math.pow(SSH_RETRY_CONFIG.backoffMultiplier, attempt);
        console.warn(`[ScanServer] SSH attempt ${attempt + 1}/${SSH_RETRY_CONFIG.maxRetries + 1} failed: ${err.message}. Retrying in ${delay}ms...`);

        // Invalidate the pooled connection so next attempt gets a fresh one
        if (pooledConn) {
          try { pooledConn.end(); } catch { /* ignore */ }
          pooledConn = null;
          pooledConnReady = false;
        }

        await sshSleep(delay);
        continue;
      }

      // Non-retryable error or retries exhausted
      if (attempt >= SSH_RETRY_CONFIG.maxRetries) {
        sshRetryMetrics.exhaustedRetries++;
        console.error(`[ScanServer] SSH retries exhausted after ${attempt + 1} attempts: ${err.message}`);
      }
      throw err;
    }
  }

  // Should never reach here, but TypeScript needs it
  sshRetryMetrics.successAfterRetry++;
  throw lastError || new Error('SSH retry logic error');
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Execute a tool on the remote scan server.
 * The tool must be in the ALLOWED_TOOLS whitelist.
 *
 * Execution strategy:
 *   1. Try HTTP API (do-scan-api) — non-blocking, better error handling
 *   2. Fall back to child_process SSH with P6 retry (exponential backoff)
 *
 * The HTTP API path is preferred because it:
 *   - Eliminates SSH connection overhead and key management
 *   - Runs in a separate OS process on the scan server (no event loop blocking)
 *   - Provides built-in metrics and health monitoring
 *   - Has automatic SSH fallback built into the do-scan-api module
 */
export async function executeTool(config: ToolExecConfig): Promise<ToolExecResult> {
  const { tool, args, timeoutSeconds = 300, sudo = false } = config;
  const startTime = Date.now();

  // Validate tool is allowed
  if (!ALLOWED_TOOLS.has(tool)) {
    console.warn(`[ScanServer] Tool "${tool}" blocked by whitelist. Allowed: ${[...ALLOWED_TOOLS].join(', ')}`);
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

  console.log(`[ScanServer] executeTool: tool=${tool}, timeout=${timeoutSeconds}s, target=${config.target || 'N/A'}, args=${String(args).substring(0, 150)}`);

  // Primary path: HTTP API (includes its own SSH fallback)
  try {
    const { executeToolViaHttp } = await import("./do-scan-api");
    const httpResult = await executeToolViaHttp(config);
    console.log(`[ScanServer] HTTP API result: tool=${tool}, exitCode=${httpResult.exitCode}, timedOut=${httpResult.timedOut}, duration=${httpResult.durationMs}ms, stdout=${httpResult.stdout?.substring(0, 100) || '(empty)'}`);
    return httpResult;
  } catch (httpImportErr: any) {
    // do-scan-api module failed to load — fall through to direct SSH
    console.warn(`[ScanServer] HTTP API module unavailable (${httpImportErr.message}), using direct SSH with retry`);
  }

  // Fallback: direct child_process SSH with P6 retry
  const prefix = sudo ? "sudo " : "";
  const command = `${prefix}${tool} ${args} 2>&1`;
  console.log(`[ScanServer] SSH fallback: ${command.substring(0, 150)}`);

  try {
    const result = await executeSSHWithRetry(command, timeoutSeconds, false);
    if (sshRetryMetrics.totalRetries > 0) sshRetryMetrics.successAfterRetry++;
    console.log(`[ScanServer] SSH result: tool=${tool}, exitCode=${result.exitCode}, duration=${Date.now() - startTime}ms, stdout=${result.stdout?.substring(0, 100) || '(empty)'}`);
    return {
      tool,
      command: `${tool} ${args}`,
      stdout: result.stdout.slice(0, 500_000),
      stderr: result.stderr.slice(0, 50_000),
      exitCode: result.exitCode,
      durationMs: Date.now() - startTime,
      timedOut: false,
    };
  } catch (err: any) {
    const timedOut = err.message.includes("timed out");
    console.error(`[ScanServer] SSH error: tool=${tool}, timedOut=${timedOut}, error=${err.message.substring(0, 200)}`);
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
 * Execute a raw command on the scan server.
 * Primary path: HTTP API (non-blocking, with SSH fallback built in).
 * Fallback: direct child_process SSH if HTTP module is unavailable.
 */
export async function executeRawCommand(
  command: string,
  timeoutSeconds: number = 300
): Promise<ToolExecResult> {
  const startTime = Date.now();

  // Primary path: HTTP API
  try {
    const { executeRawCommandViaHttp } = await import("./do-scan-api");
    return await executeRawCommandViaHttp(command, timeoutSeconds);
  } catch (httpImportErr: any) {
    console.warn(`[ScanServer] HTTP API module unavailable for raw command, using direct SSH`);
  }

  // Fallback: direct child_process SSH with P6 retry
  try {
    const result = await executeSSHWithRetry(command, timeoutSeconds, false);
    if (sshRetryMetrics.totalRetries > 0) sshRetryMetrics.successAfterRetry++;
    return {
      tool: "raw",
      command,
      stdout: result.stdout.slice(0, 500_000),
      stderr: result.stderr.slice(0, 50_000),
      exitCode: result.exitCode,
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
 * Execute a command on the scan server using the system ssh binary.
 * This runs in a child process so SSH crypto doesn't block the Node.js event loop.
 * Used by the training lab for long-running scans (nuclei, nikto, etc.).
 */
export async function executeViaChildProcessSSH(
  command: string,
  timeoutSeconds: number
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  console.log(`[ChildProcessSSH] START: timeout=${timeoutSeconds}s cmd=${command.slice(0, 80)}...`);
  const { spawn } = await import('child_process');
  const { writeFile, unlink } = await import('fs/promises');
  const config = await getScanServerConfig();

  // Write the SSH key to a temp file (child_process ssh needs a file path)
  const keyPath = `/tmp/.scan_key_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  await writeFile(keyPath, config.privateKey, { mode: 0o600 });

  const MAX_OUTPUT = 512 * 1024; // 512KB max per stream

  return new Promise((resolve, reject) => {
    const args = [
      '-o', 'StrictHostKeyChecking=no',
      '-o', 'UserKnownHostsFile=/dev/null',
      '-o', 'LogLevel=ERROR',
      '-o', `ConnectTimeout=15`,
      '-o', 'ServerAliveInterval=15',
      '-o', 'ServerAliveCountMax=3',
      '-i', keyPath,
      `${config.username}@${config.host}`,
      command,
    ];

    const child = spawn('ssh', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdoutBuf = '';
    let stderrBuf = '';
    let stdoutCapped = false;
    let stderrCapped = false;
    let resolved = false;

    // Stream stdout with cap — pause stream when limit reached
    child.stdout.on('data', (chunk: Buffer) => {
      if (stdoutCapped) return;
      const str = chunk.toString('utf8');
      if (stdoutBuf.length + str.length > MAX_OUTPUT) {
        stdoutBuf += str.slice(0, MAX_OUTPUT - stdoutBuf.length);
        stdoutBuf += '\n[OUTPUT TRUNCATED]';
        stdoutCapped = true;
        // Don't kill the process — let it finish naturally
      } else {
        stdoutBuf += str;
      }
    });

    child.stderr.on('data', (chunk: Buffer) => {
      if (stderrCapped) return;
      const str = chunk.toString('utf8');
      if (stderrBuf.length + str.length > MAX_OUTPUT) {
        stderrBuf += str.slice(0, MAX_OUTPUT - stderrBuf.length);
        stderrCapped = true;
      } else {
        stderrBuf += str;
      }
    });

    // Timeout handler
    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        child.kill('SIGTERM');
        setTimeout(() => child.kill('SIGKILL'), 5000);
        unlink(keyPath).catch(() => {});
        // Resolve with whatever output we have instead of rejecting
        resolve({
          stdout: stdoutBuf,
          stderr: stderrBuf + '\n[TIMED OUT]',
          exitCode: -1,
        });
      }
    }, timeoutSeconds * 1000);

    child.on('close', (code) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        unlink(keyPath).catch(() => {});
        console.log(`[ChildProcessSSH] DONE: exit=${code} stdout=${stdoutBuf.length}b stderr=${stderrBuf.length}b`);
        resolve({
          stdout: stdoutBuf,
          stderr: stderrBuf,
          exitCode: code ?? -1,
        });
      }
    });

    child.on('error', (err) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        unlink(keyPath).catch(() => {});
        resolve({
          stdout: stdoutBuf,
          stderr: err.message,
          exitCode: -1,
        });
      }
    });
  });
}

/**
 * Check the scan server status and available tools.
 */
export async function checkScanServerStatus(): Promise<ScanServerStatus> {
  try {
    const result = await executeSSHWithRetry("cat /opt/tool-manifest.json 2>/dev/null && echo '---HEALTH---' && bash /opt/health-check.sh 2>/dev/null", 15, true);
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
 * Get the scan server config for the scanforge-discovery engine.
 */
export async function getScanServerConfigForScanForge() {
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
 *
 * When `technologies` are provided, OEM/vendor default credentials are
 * looked up and injected as high-priority credential tests BEFORE the
 * generic wordlist fallback.
 */
export async function suggestToolCommands(asset: {
  hostname?: string;
  ip?: string;
  type?: string;
  ports: Array<{ port: number; service: string; version?: string }>;
  technologies?: Array<{ name?: string; vendor?: string; version?: string; cpe?: string; port?: number; protocol?: string }>;
}): Promise<Array<{ tool: string; args: string; purpose: string; priority: number }>> {
  const target = asset.ip || asset.hostname || "";
  // For HTTPS targets behind ALBs/CDNs, Hydra must use the hostname (not raw IP)
  // so TLS SNI sends the correct Host header. Without this, ALBs return 421.
  const hydraTarget = asset.hostname || asset.ip || "";
  const commands: Array<{ tool: string; args: string; purpose: string; priority: number }> = [];

  // Always start with ScanForge discovery service detection
  const portList = asset.ports.map(p => p.port).join(",");

  // Web services
  const webPorts = asset.ports.filter(p =>
    ["http", "https", "http-proxy", "http-alt"].includes(p.service) ||
    [80, 443, 8080, 8443, 8000, 3000, 5000, 9090].includes(p.port)
  );

  if (webPorts.length > 0) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.port === 8444 || wp.port === 8445 || wp.port === 8447 || wp.port === 9443 || wp.service === 'https' || wp.service === 'ssl';
      const scheme = isHttps ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;

      // NOTE: httpx and nuclei MUST use raw commands with stdin piping
      // because the -u flag hangs without a TTY / PDCP auth prompt
      commands.push({
        tool: "raw",
        args: `echo '${url}' | httpx -silent -nc -json -follow-redirects -tech-detect -status-code -title -web-server -content-length -content-type`,
        purpose: `HTTP probe and tech detection on ${url}`,
        priority: 1,
      });

      commands.push({
        tool: "raw",
        args: `echo '${url}' | nuclei -jsonl -nc -timeout 10 -retries 1 -rate-limit 100 -silent -tags exposure,misconfig,tech,xss,sqli,lfi,ssrf,cve,rce,traversal -severity info,low,medium,high,critical -concurrency 5`,
        purpose: `CVE/vulnerability template scan on ${url}`,
        priority: 1,
      });

      // Nikto: add -ssl flag for HTTPS targets to ensure proper TLS handshake
      const niktoSslFlag = isHttps ? ' -ssl' : '';
      commands.push({
        tool: "nikto",
        args: `-h ${url}${niktoSslFlag} -Tuning 1234567890abc -maxtime 300`,
        purpose: `Web vulnerability scan on ${url}`,
        priority: 1,
      });

      commands.push({
        tool: "gobuster",
        args: `dir -u ${url} -w /opt/SecLists/Discovery/Web-Content/common.txt -t 20 -q --no-error`,
        purpose: `Directory brute-force on ${url}`,
        priority: 2,
      });
    }
  }

  // ── Vendor/OEM Default Credential Testing (priority 3, before generic wordlists) ──
  // Look up known default credentials based on detected technologies
  if (asset.technologies && asset.technologies.length > 0) {
    try {
      const oemMatches = await matchCredentialsForAsset(asset.technologies);
      for (const svc of oemMatches) {
        // Build per-service hydra commands with vendor-specific user:pass pairs
        const credPairs = svc.credentials;
        if (credPairs.length === 0) continue;

        // Find the matching port on the asset
        const matchingPort = svc.port
          ? asset.ports.find(p => p.port === svc.port)
          : null;
        if (svc.port && !matchingPort) continue; // Port not open, skip

        // Map OEM protocol to hydra module
        // NOTE: http/https/web_admin now use http-form-post instead of http-get
        // because http-get tests HTTP Basic Auth which produces false positives
        // against modern web apps that serve SPAs (always return HTTP 200).
        // For actual HTTP Basic Auth targets, the OEM credential DB should
        // specify protocol as 'http_basic' explicitly.
        const protocolToHydra: Record<string, string> = {
          ssh: "ssh", telnet: "telnet", ftp: "ftp", mysql: "mysql",
          postgres: "postgres", mssql: "mssql", rdp: "rdp",
          http: "http-form-post", https: "https-form-post", web_admin: "http-form-post",
          http_basic: "http-get", https_basic: "https-get",
          snmp: "snmp", ldap: "ldap2", oracle: "oracle-listener",
        };
        const hydraModule = protocolToHydra[credPairs[0].protocol] || credPairs[0].protocol;
        const port = svc.port || matchingPort?.port;
        if (!port) continue;

        // Create a targeted credential file approach: test each vendor default pair
        for (const cred of credPairs) {
          const passArg = cred.password === "" ? `-e n` : `-p '${cred.password}'`;

          // For http-form-post/https-form-post, we need a form data string
          // Use a common login form pattern with failure string detection
          if (hydraModule === 'http-form-post' || hydraModule === 'https-form-post') {
            // Try common login paths with standard form field names
            const loginPaths = ['/login', '/admin/login', '/auth/login', '/api/auth/login', '/signin'];
            const formVariants = [
              { fields: 'username=^USER^&password=^PASS^', failStr: 'invalid|incorrect|failed|error|denied|wrong' },
              { fields: 'email=^USER^&password=^PASS^', failStr: 'invalid|incorrect|failed|error|denied|wrong' },
              { fields: 'user=^USER^&pass=^PASS^', failStr: 'invalid|incorrect|failed|error|denied|wrong' },
            ];
            // Use first login path + first form variant as primary, others as fallback
            commands.push({
              tool: 'hydra',
              args: `-l '${cred.username}' ${passArg} -s ${port} -t 4 -f -V ${hydraTarget} ${hydraModule} '${loginPaths[0]}:${formVariants[0].fields}:F=${formVariants[0].failStr}'`,
              purpose: `[OEM Default] ${cred.vendor} ${cred.product} — ${cred.username}:${cred.password || "(empty)"} via HTTP form on port ${port}`,
              priority: 3,
            });
          } else {
            commands.push({
              tool: "hydra",
              args: `-l '${cred.username}' ${passArg} -s ${port} -t 4 -f -V ${hydraTarget} ${hydraModule}`,
              purpose: `[OEM Default] ${cred.vendor} ${cred.product} — ${cred.username}:${cred.password || "(empty)"} on port ${port}`,
              priority: 3,
            });
          }
        }
      }
    } catch (e) {
      // OEM module not available, fall through to generic testing
    }
  }

  // ── HTTP Form-Based Credential Testing for Web Applications ──
  // Training labs (DVWA, Juice Shop, WebGoat, bWAPP, etc.) use HTTP form login
  // Generate hydra http-form-post commands for common web app login patterns
  if (webPorts.length > 0) {
    // Known training lab credential patterns (deterministic, no LLM needed)
    const KNOWN_WEB_APP_CREDS: Array<{
      pattern: RegExp; // Match against hostname, URL, or technology name
      loginPath: string;
      formData: string; // Hydra http-form-post format: path:POST_DATA:FAIL_STRING
      username: string;
      password: string;
      appName: string;
    }> = [
      {
        pattern: /dvwa/i,
        loginPath: '/login.php',
        formData: '/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed',
        username: 'admin', password: 'password', appName: 'DVWA',
      },
      {
        pattern: /juice.?shop/i,
        loginPath: '/rest/user/login',
        formData: '/rest/user/login:{"email"\:"^USER^","password"\:"^PASS^"}:Invalid',
        username: 'admin@juice-sh.op', password: 'admin123', appName: 'Juice Shop',
      },
      {
        pattern: /webgoat/i,
        loginPath: '/WebGoat/login',
        formData: '/WebGoat/login:username=^USER^&password=^PASS^:Invalid',
        username: 'guest', password: 'guest', appName: 'WebGoat',
      },
      {
        pattern: /bwapp/i,
        loginPath: '/login.php',
        formData: '/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid',
        username: 'bee', password: 'bug', appName: 'bWAPP',
      },
      {
        pattern: /mutillidae/i,
        loginPath: '/index.php?page=login.php',
        formData: '/index.php?page=login.php:username=^USER^&password=^PASS^&login-php-submit-button=Login:Authentication Error',
        username: 'admin', password: 'admin', appName: 'Mutillidae',
      },
      {
        pattern: /crapi/i,
        loginPath: '/identity/api/auth/login',
        formData: '/identity/api/auth/login:{"email"\:"^USER^","password"\:"^PASS^"}:Invalid',
        username: 'victim@example.com', password: 'Cr4p1!', appName: 'crAPI',
      },
    ];

    const hostLower = (asset.hostname || '').toLowerCase();
    const techNames = (asset.technologies || []).map(t => (t.name || '').toLowerCase()).join(' ');
    const matchStr = `${hostLower} ${techNames}`;

    for (const wp of webPorts) {
      const scheme = wp.port === 443 || wp.port === 8443 ? 'https' : 'http';

      for (const app of KNOWN_WEB_APP_CREDS) {
        if (app.pattern.test(matchStr)) {
          const hydraModule = scheme === 'https' ? 'https-form-post' : 'http-form-post';
          commands.push({
            tool: 'hydra',
            args: `-l '${app.username}' -p '${app.password}' -s ${wp.port} -t 4 -f -V ${hydraTarget} ${hydraModule} '${app.formData}'`,
            purpose: `[Known App] ${app.appName} HTTP form login — ${app.username}:${app.password} on port ${wp.port}`,
            priority: 3,
          });
        }
      }

      // Generic HTTP form credential testing with common defaults
      commands.push({
        tool: 'hydra',
        args: `-l admin -P /opt/SecLists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt -s ${wp.port} -t 4 -f -V ${hydraTarget} ${scheme === 'https' ? 'https-form-post' : 'http-form-post'} '/login:username=^USER^&password=^PASS^:incorrect'`,
        purpose: `HTTP form credential testing (common passwords) on port ${wp.port}`,
        priority: 3,
      });
    }
  }

  // SSH (multi-user credential testing with lab-aware weak pairs)
  const sshPorts = asset.ports.filter(p => p.service === "ssh" || p.port === 22);
  if (sshPorts.length > 0) {
    for (const sp of sshPorts) {
      // Priority 2: Test common weak credential pairs first (fast, high-yield)
      // These cover lab environments, default installs, and lazy admin passwords
      const WEAK_CRED_PAIRS = [
        'root:root', 'root:toor', 'root:password', 'root:123456',
        'admin:admin', 'admin:password', 'admin:admin123',
        'user:user', 'user:password', 'test:test', 'test:password',
        'ubuntu:ubuntu', 'vagrant:vagrant', 'pi:raspberry',
        'ms3user:ms3password', 'msfadmin:msfadmin', 'postgres:postgres',
        'ftp:ftp', 'guest:guest', 'operator:operator',
      ];
      // Write credential pairs to a temp file for hydra -C flag
      const credPairsStr = WEAK_CRED_PAIRS.join('\\n');
      commands.push({
        tool: "raw",
        args: `printf '${credPairsStr}' > /tmp/ssh-weak-creds-${sp.port}.txt && hydra -C /tmp/ssh-weak-creds-${sp.port}.txt -s ${sp.port} -t 4 -f -V ${hydraTarget} ssh`,
        purpose: `SSH weak credential pairs testing (${WEAK_CRED_PAIRS.length} pairs including lab defaults) on port ${sp.port}`,
        priority: 2,
      });

      // Priority 3: Broader username + wordlist testing as fallback
      commands.push({
        tool: "raw",
        args: `hydra -L <(printf 'root\\nadmin\\nuser\\nubuntu\\ntest\\nms3user\\ndeploy\\nwww-data\\n') -P /opt/SecLists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt -s ${sp.port} -t 4 -f -V ${hydraTarget} ssh`,
        purpose: `SSH credential testing (8 users × top-20 passwords) on port ${sp.port}`,
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

  // MySQL/PostgreSQL (generic wordlist fallback)
  const dbPorts = asset.ports.filter(p =>
    ["mysql", "postgresql"].includes(p.service) || [3306, 5432].includes(p.port)
  );
  if (dbPorts.length > 0) {
    for (const dp of dbPorts) {
      const proto = dp.port === 5432 ? "postgres" : "mysql";
      commands.push({
        tool: "hydra",
        args: `-l root -P /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt -s ${dp.port} -t 4 -f ${target} ${proto}`,
        purpose: `${proto} credential testing (generic wordlist) on port ${dp.port}`,
        priority: 3,
      });
    }
  }

  // RDP (generic wordlist fallback)
  const rdpPorts = asset.ports.filter(p =>
    p.service === "ms-wbt-server" || p.port === 3389
  );
  if (rdpPorts.length > 0) {
    commands.push({
      tool: "hydra",
      args: `-l administrator -P /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt -s 3389 -t 4 -f ${target} rdp`,
      purpose: `RDP credential testing (generic wordlist)`,
      priority: 3,
    });
  }

  // ── Audit R1: Katana JS-Aware Web Crawling ──────────────────────────────
  // Crawls with headless browser to discover JS-rendered endpoints, forms, and API calls
  if (webPorts.length > 0) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.service === 'https' || wp.service === 'ssl';
      const scheme = isHttps ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;

      commands.push({
        tool: "katana",
        args: `-u ${url} -d 3 -jc -kf -json -silent -headless -timeout 15 -rate-limit 10 -crawl-duration 300s`,
        purpose: `JS-aware web crawling on ${url} — discovers endpoints hidden behind JavaScript rendering`,
        priority: 1,
      });
    }
  }

  // ── Audit R4: Feroxbuster Recursive Content Discovery ──────────────────
  // Replaces gobuster with recursive directory brute-force + auto-calibration
  if (webPorts.length > 0) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.service === 'https' || wp.service === 'ssl';
      const scheme = isHttps ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;

      commands.push({
        tool: "feroxbuster",
        args: `-u ${url} -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -t 50 --depth 3 --timeout 10 --status-codes 200,204,301,302,307,308,401,403,405 -x php,asp,aspx,jsp,html,js --json --quiet --no-state --auto-calibration --dont-scan /logout`,
        purpose: `Recursive content discovery on ${url} — finds hidden directories, files, and endpoints`,
        priority: 2,
      });
    }
  }

  // ── Audit R5: API Specification Discovery ──────────────────────────────
  // Probes for exposed Swagger, OpenAPI, GraphQL, and WSDL endpoints
  if (webPorts.length > 0) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.service === 'https' || wp.service === 'ssl';
      const scheme = isHttps ? "https" : "http";
      const baseUrl = `${scheme}://${target}:${wp.port}`;

      // Probe common API spec locations
      const apiPaths = [
        '/swagger.json', '/openapi.json', '/api-docs', '/api-docs.json',
        '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
        '/swagger-ui.html', '/swagger-ui/', '/redoc',
        '/graphql', '/graphiql', '/playground',
        '?wsdl', '/service?wsdl',
        '/actuator', '/actuator/info', '/actuator/env', '/actuator/health',
        '/.well-known/openapi',
      ];
      const probeUrls = apiPaths.map(p => `${baseUrl}${p}`).join(' ');

      commands.push({
        tool: "raw",
        args: `for url in ${probeUrls}; do code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$url"); if [ "$code" != "000" ] && [ "$code" != "404" ] && [ "$code" != "503" ]; then echo "$code $url"; fi; done`,
        purpose: `API specification discovery on ${baseUrl} — probes for Swagger, OpenAPI, GraphQL, WSDL, and Spring Actuator endpoints`,
        priority: 2,
      });

      // GraphQL introspection probe
      commands.push({
        tool: "raw",
        args: `curl -s -m 10 -X POST ${baseUrl}/graphql -H 'Content-Type: application/json' -d '{"query":"{__schema{queryType{name}types{name kind}}}"}'`,
        purpose: `GraphQL introspection probe on ${baseUrl}/graphql`,
        priority: 2,
      });
    }
  }

  // ── Audit R7: Parameter Discovery (Arjun + ParamSpider) ───────────────
  if (webPorts.length > 0 && asset.hostname) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.service === 'https' || wp.service === 'ssl';
      const scheme = isHttps ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;

      commands.push({
        tool: "arjun",
        args: `-u ${url} -m GET -t 10 --timeout 15 -oJ /dev/stdout --passive`,
        purpose: `Hidden parameter discovery on ${url} — finds unlinked GET parameters`,
        priority: 2,
      });

      commands.push({
        tool: "arjun",
        args: `-u ${url} -m POST -t 10 --timeout 15 -oJ /dev/stdout --passive`,
        purpose: `Hidden parameter discovery on ${url} — finds unlinked POST parameters`,
        priority: 2,
      });
    }

    // ParamSpider mines parameters from web archives
    commands.push({
      tool: "paramspider",
      args: `-d ${asset.hostname} --exclude css,js,png,jpg,gif,svg,woff,ttf,ico,pdf --level high -o /dev/stdout`,
      purpose: `Web archive parameter mining for ${asset.hostname} — discovers historical URL parameters`,
      priority: 2,
    });
  }

  // ── Audit R8: TLS Vulnerability Testing (testssl.sh) ──────────────────
  const tlsPorts = asset.ports.filter(p =>
    p.service === 'https' || p.service === 'ssl' ||
    [443, 8443, 993, 995, 465, 636].includes(p.port)
  );
  if (tlsPorts.length > 0) {
    for (const tp of tlsPorts) {
      commands.push({
        tool: "testssl.sh",
        args: `--jsonfile - --quiet --color 0 --sneaky -U -p -S ${target}:${tp.port}`,
        purpose: `TLS vulnerability testing on ${target}:${tp.port} — checks for Heartbleed, POODLE, ROBOT, DROWN, FREAK, BEAST, weak ciphers`,
        priority: 2,
      });
    }
  }

  // ── Audit R12: Virtual Host Enumeration (ffuf) ────────────────────────
  if (webPorts.length > 0 && asset.hostname) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.service === 'https' || wp.service === 'ssl';
      const scheme = isHttps ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;

      commands.push({
        tool: "ffuf",
        args: `-w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u ${url} -H "Host: FUZZ.${asset.hostname}" -mc 200,204,301,302,307,308,401,403 -json -s -ac`,
        purpose: `Virtual host enumeration on ${url} — discovers hidden vhosts sharing the same IP`,
        priority: 3,
      });
    }
  }

  // ── Audit R15: WAF Fingerprinting (wafw00f) ───────────────────────────
  if (webPorts.length > 0) {
    for (const wp of webPorts) {
      const isHttps = wp.port === 443 || wp.port === 8443 || wp.service === 'https' || wp.service === 'ssl';
      const scheme = isHttps ? "https" : "http";
      const url = `${scheme}://${target}:${wp.port}`;

      commands.push({
        tool: "wafw00f",
        args: `${url} -o - -a`,
        purpose: `WAF fingerprinting on ${url} — identifies web application firewalls for evasion planning`,
        priority: 3,
      });
    }
  }

  // Sort by priority
  commands.sort((a, b) => a.priority - b.priority);
  return commands;
}
