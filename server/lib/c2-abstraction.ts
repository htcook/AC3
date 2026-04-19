/**
 * Unified C2 Abstraction Layer
 *
 * Provides a common interface across Caldera, Metasploit, and Sliver C2 frameworks.
 * Each adapter normalizes agents, sessions, module dispatch, and result collection
 * into a unified schema so the Ability Graph Engine, Learning Engine, and Exploit
 * Matcher can operate framework-agnostically.
 *
 * Architecture:
 *   C2Registry → [CalderaAdapter, MetasploitAdapter, SliverAdapter]
 *     ↓ dispatch(target, module)
 *     ↓ pollResult(taskId)
 *     ↓ listAgents()
 *     ↓ healthCheck()
 *
 * Author: Harrison Cook — AceofCloud
 */

import { ENV } from "../_core/env";
import { getDb } from "../db";
import { metasploitServers } from "../../drizzle/schema";
import { eq, desc } from "drizzle-orm";
import { CobaltStrikeAdapter } from "./cobalt-strike-adapter";

// ─── Unified Types ──────────────────────────────────────────────────────────

export type C2FrameworkType = "caldera" | "metasploit" | "sliver" | "empire" | "cobaltstrike" | "manjusaka";

export type C2AgentStatus = "active" | "dormant" | "dead" | "unknown";

export interface C2Agent {
  id: string;                    // Framework-specific agent/session ID
  framework: C2FrameworkType;
  hostname: string;
  username: string;
  platform: string;              // windows, linux, macos
  architecture: string;          // x64, x86, arm64
  ipAddress: string;
  status: C2AgentStatus;
  lastSeen: string;              // ISO timestamp
  privileges: string;            // user, admin, system/root
  processId?: number;
  processName?: string;
  transport?: string;            // http, https, mtls, dns, tcp
  metadata?: Record<string, any>;
}

export interface C2Module {
  id: string;                    // Module identifier (ability ID, MSF module path, Sliver command)
  framework: C2FrameworkType;
  name: string;
  description: string;
  type: string;                  // exploit, post, auxiliary, payload, ability, command
  platform: string[];
  techniqueId?: string;          // MITRE ATT&CK mapping
  tactic?: string;
  rank?: number;                 // Reliability ranking (0-600 for MSF, 0-100 for others)
  options?: Record<string, C2ModuleOption>;
}

export interface C2ModuleOption {
  name: string;
  type: string;
  required: boolean;
  default?: any;
  description: string;
  values?: string[];
}

export interface C2TaskRequest {
  agentId: string;
  moduleId: string;
  options?: Record<string, any>;
  timeout?: number;              // Seconds
}

export interface C2TaskResult {
  taskId: string;
  framework: C2FrameworkType;
  agentId: string;
  moduleId: string;
  status: "pending" | "running" | "success" | "failed" | "timeout" | "error";
  exitCode: number;
  stdout: string;
  stderr: string;
  startedAt: string;
  completedAt?: string;
  metadata?: Record<string, any>;
}

export interface C2HealthStatus {
  framework: C2FrameworkType;
  connected: boolean;
  version?: string;
  agentCount: number;
  activeJobs: number;
  lastChecked: string;
  error?: string;
  details?: Record<string, any>;
}

export interface C2ConnectionConfig {
  framework: C2FrameworkType;
  name: string;
  host: string;
  port: number;
  apiKey?: string;
  username?: string;
  password?: string;
  ssl: boolean;
  enabled: boolean;
}

// ─── C2 Adapter Interface ──────────────────────────────────────────────────

export interface IC2Adapter {
  readonly framework: C2FrameworkType;

  /** Test connectivity and return health status */
  healthCheck(): Promise<C2HealthStatus>;

  /** List all agents/sessions/implants */
  listAgents(): Promise<C2Agent[]>;

  /** Get a specific agent by ID */
  getAgent(agentId: string): Promise<C2Agent | null>;

  /** Search for modules by keyword, CVE, or technique ID */
  searchModules(query: string): Promise<C2Module[]>;

  /** Get module details */
  getModule(moduleId: string): Promise<C2Module | null>;

  /** Dispatch a task to an agent */
  dispatch(request: C2TaskRequest): Promise<C2TaskResult>;

  /** Poll for task completion */
  pollResult(taskId: string, agentId: string): Promise<C2TaskResult>;

  /** Kill/terminate an agent */
  killAgent(agentId: string): Promise<boolean>;
}

// ─── Caldera Adapter ────────────────────────────────────────────────────────

const CALDERA_BASE = ENV.calderaBaseUrl || "";
const CALDERA_KEY = ENV.calderaApiKey || "";

async function calderaFetch(endpoint: string, options: RequestInit = {}): Promise<any> {
  if (!CALDERA_BASE) throw new Error("CALDERA_BASE_URL not configured");
  const url = `${CALDERA_BASE}/api/v2${endpoint}`;
  const resp = await fetch(url, {
    ...options,
    headers: {
      "KEY": CALDERA_KEY,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  if (!resp.ok) throw new Error(`Caldera API ${resp.status}: ${await resp.text()}`);
  return resp.json();
}

export class CalderaAdapter implements IC2Adapter {
  readonly framework: C2FrameworkType = "caldera";

  async healthCheck(): Promise<C2HealthStatus> {
    try {
      const [health, agents] = await Promise.all([
        calderaFetch("/health").catch(() => null),
        calderaFetch("/agents").catch(() => []),
      ]);
      return {
        framework: "caldera",
        connected: true,
        version: health?.version || "unknown",
        agentCount: Array.isArray(agents) ? agents.length : 0,
        activeJobs: 0,
        lastChecked: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        framework: "caldera",
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
      const agents = await calderaFetch("/agents");
      if (!Array.isArray(agents)) return [];
      return agents.map((a: any) => ({
        id: a.paw,
        framework: "caldera" as C2FrameworkType,
        hostname: a.host || "unknown",
        username: a.username || "unknown",
        platform: a.platform || "unknown",
        architecture: a.architecture || "unknown",
        ipAddress: a.host_ip_addrs?.[0] || a.host || "",
        status: this.mapAgentStatus(a),
        lastSeen: a.last_seen || new Date().toISOString(),
        privileges: a.privilege || "user",
        processId: a.pid,
        processName: a.exe_name,
        transport: a.contact || "http",
        metadata: { group: a.group, trusted: a.trusted, executors: a.executors },
      }));
    } catch {
      return [];
    }
  }

  private mapAgentStatus(a: any): C2AgentStatus {
    if (!a.last_seen) return "unknown";
    const lastSeen = new Date(a.last_seen).getTime();
    const now = Date.now();
    const diffMin = (now - lastSeen) / 60000;
    if (diffMin < 5) return "active";
    if (diffMin < 60) return "dormant";
    return "dead";
  }

  async getAgent(agentId: string): Promise<C2Agent | null> {
    const agents = await this.listAgents();
    return agents.find(a => a.id === agentId) || null;
  }

  async searchModules(query: string): Promise<C2Module[]> {
    try {
      const abilities = await calderaFetch("/abilities");
      if (!Array.isArray(abilities)) return [];
      const q = query.toLowerCase();
      return abilities
        .filter((a: any) =>
          a.name?.toLowerCase().includes(q) ||
          a.technique_id?.toLowerCase().includes(q) ||
          a.description?.toLowerCase().includes(q) ||
          a.tactic?.toLowerCase().includes(q)
        )
        .slice(0, 50)
        .map((a: any) => ({
          id: a.ability_id,
          framework: "caldera" as C2FrameworkType,
          name: a.name,
          description: a.description || "",
          type: "ability",
          platform: a.executors?.map((e: any) => e.platform) || [],
          techniqueId: a.technique_id,
          tactic: a.tactic,
          rank: 300,
        }));
    } catch {
      return [];
    }
  }

  async getModule(moduleId: string): Promise<C2Module | null> {
    try {
      const abilities = await calderaFetch("/abilities");
      const ability = abilities?.find((a: any) => a.ability_id === moduleId);
      if (!ability) return null;
      return {
        id: ability.ability_id,
        framework: "caldera",
        name: ability.name,
        description: ability.description || "",
        type: "ability",
        platform: ability.executors?.map((e: any) => e.platform) || [],
        techniqueId: ability.technique_id,
        tactic: ability.tactic,
        rank: 300,
      };
    } catch {
      return null;
    }
  }

  async dispatch(request: C2TaskRequest): Promise<C2TaskResult> {
    const startedAt = new Date().toISOString();
    try {
      // Create or use existing operation, then add ability link
      const op = await calderaFetch("/operations", {
        method: "POST",
        body: JSON.stringify({
          name: `c2-dispatch-${Date.now()}`,
          adversary: { adversary_id: "", name: "", description: "" },
          source: { id: "" },
          auto_close: true,
          jitter: "0/0",
        }),
      });

      // Potential link to add ability to the operation
      await calderaFetch(`/operations/${op.id}/potential-links`, {
        method: "POST",
        body: JSON.stringify({
          paw: request.agentId,
          ability_id: request.moduleId,
          facts: Object.entries(request.options || {}).map(([k, v]) => ({
            trait: k, value: v,
          })),
        }),
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
        metadata: { operationId: op.id },
      };
    } catch (err: any) {
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
        completedAt: new Date().toISOString(),
      };
    }
  }

  async pollResult(taskId: string, agentId: string): Promise<C2TaskResult> {
    const parts = taskId.split("-");
    const operationId = parts[1];
    try {
      const links = await calderaFetch(`/operations/${operationId}/links`);
      const link = links?.find((l: any) => l.paw === agentId);
      if (!link) {
        return {
          taskId, framework: "caldera", agentId, moduleId: "",
          status: "pending", exitCode: -1, stdout: "", stderr: "",
          startedAt: new Date().toISOString(),
        };
      }
      const finished = link.finish !== null && link.finish !== undefined && link.finish !== "";
      return {
        taskId,
        framework: "caldera",
        agentId,
        moduleId: link.ability?.ability_id || "",
        status: finished ? (link.status === 0 ? "success" : "failed") : "running",
        exitCode: link.status ?? -1,
        stdout: link.output ? Buffer.from(link.output, "base64").toString("utf-8") : "",
        stderr: "",
        startedAt: link.decide || new Date().toISOString(),
        completedAt: link.finish || undefined,
      };
    } catch (err: any) {
      return {
        taskId, framework: "caldera", agentId, moduleId: "",
        status: "error", exitCode: -1, stdout: "", stderr: err.message,
        startedAt: new Date().toISOString(),
      };
    }
  }

  async killAgent(agentId: string): Promise<boolean> {
    try {
      await calderaFetch(`/agents/${agentId}`, { method: "DELETE" });
      return true;
    } catch {
      return false;
    }
  }
}

// ─── Metasploit Adapter ─────────────────────────────────────────────────────

/**
 * Wraps the existing MsfClient to conform to the unified C2 interface.
 * Connects via MSGRPC (MessagePack RPC) to msfrpcd.
 */
export class MetasploitAdapter implements IC2Adapter {
  readonly framework: C2FrameworkType = "metasploit";
  private clientPromise: Promise<any> | null = null;

  private async getClient(): Promise<any> {
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        const { MsfClient } = await import("./msf-client");
        // Try DB-configured servers first, then ENV fallback
        const db = await getDb();
        if (db) {
          const servers = await db.select().from(metasploitServers)
            .where(eq(metasploitServers.msfStatus, "online"))
            .orderBy(desc(metasploitServers.msfCreatedAt))
            .limit(1);
          if (servers.length > 0) {
            const s = servers[0];
            const client = s.sshTunnelEnabled
              ? await MsfClient.fromServerWithTunnel({
                  ipAddress: s.ipAddress || "",
                  rpcPort: s.rpcPort || 55553,
                  rpcUser: s.rpcUser || "msf",
                  rpcPass: s.rpcPass || "",
                  rpcSsl: s.rpcSsl || false,
                  sshUser: s.sshUser || "root",
                  sshKeyPath: s.sshKeyPath || undefined,
                } as any)
              : new MsfClient({
                  host: s.ipAddress || "127.0.0.1",
                  port: s.rpcPort || 55553,
                  user: s.rpcUser || "msf",
                  pass: s.rpcPass || "",
                  ssl: s.rpcSsl || false,
                });
            if (client) {
              await client.login();
              return client;
            }
          }
        }
        // ENV fallback
        if (ENV.MSF_RPC_HOST) {
          const { MsfClient: MC } = await import("./msf-client");
          const client = new MC({
            host: ENV.MSF_RPC_HOST,
            port: ENV.MSF_RPC_PORT,
            user: ENV.MSF_RPC_USER,
            pass: ENV.MSF_RPC_PASS,
            ssl: ENV.MSF_RPC_SSL,
          });
          await client.login();
          return client;
        }
        return null;
      })();
    }
    return this.clientPromise;
  }

  async healthCheck(): Promise<C2HealthStatus> {
    try {
      const client = await this.getClient();
      if (!client) {
        return {
          framework: "metasploit", connected: false, agentCount: 0,
          activeJobs: 0, lastChecked: new Date().toISOString(),
          error: "No Metasploit server configured",
        };
      }
      const health = await client.healthCheck();
      return {
        framework: "metasploit",
        connected: health.connected,
        version: health.version,
        agentCount: health.sessions,
        activeJobs: health.jobs,
        lastChecked: new Date().toISOString(),
        details: { modules: health.modules },
      };
    } catch (err: any) {
      this.clientPromise = null; // Reset on failure
      return {
        framework: "metasploit", connected: false, agentCount: 0,
        activeJobs: 0, lastChecked: new Date().toISOString(),
        error: err.message,
      };
    }
  }

  async listAgents(): Promise<C2Agent[]> {
    try {
      const client = await this.getClient();
      if (!client) return [];
      const sessions = await client.listSessions();
      return Object.entries(sessions).map(([id, s]: [string, any]) => ({
        id,
        framework: "metasploit" as C2FrameworkType,
        hostname: s.info || "unknown",
        username: s.username || "unknown",
        platform: s.platform || "unknown",
        architecture: s.arch || "unknown",
        ipAddress: s.target_host || s.tunnel_peer?.split(":")[0] || "",
        status: "active" as C2AgentStatus,
        lastSeen: new Date().toISOString(),
        privileges: s.username?.includes("SYSTEM") || s.username === "root" ? "system" : "user",
        transport: s.type || "shell",
        metadata: {
          sessionType: s.type,
          viaExploit: s.via_exploit,
          viaPayload: s.via_payload,
          tunnelLocal: s.tunnel_local,
          tunnelPeer: s.tunnel_peer,
          routes: s.routes,
        },
      }));
    } catch {
      return [];
    }
  }

  async getAgent(agentId: string): Promise<C2Agent | null> {
    const agents = await this.listAgents();
    return agents.find(a => a.id === agentId) || null;
  }

  async searchModules(query: string): Promise<C2Module[]> {
    try {
      const client = await this.getClient();
      if (!client) return [];
      const modules = await client.searchModules(query);
      return modules.slice(0, 50).map((m: any) => ({
        id: m.fullname,
        framework: "metasploit" as C2FrameworkType,
        name: m.name,
        description: m.description || "",
        type: m.type || "exploit",
        platform: [m.platform || "multi"],
        rank: this.mapRank(m.rank),
        options: {},
      }));
    } catch {
      return [];
    }
  }

  private mapRank(rank: string | number): number {
    const rankMap: Record<string, number> = {
      manual: 0, low: 100, average: 200, normal: 300,
      good: 400, great: 500, excellent: 600,
    };
    if (typeof rank === "string") return rankMap[rank] || 300;
    return typeof rank === "number" ? rank : 300;
  }

  async getModule(moduleId: string): Promise<C2Module | null> {
    try {
      const client = await this.getClient();
      if (!client) return null;
      const parts = moduleId.split("/");
      const moduleType = parts[0]; // exploit, post, auxiliary, etc.
      const info = await client.getModuleInfo(moduleType, moduleId);
      const options = await client.getModuleOptions(moduleType, moduleId);
      return {
        id: moduleId,
        framework: "metasploit",
        name: info.name,
        description: info.description || "",
        type: moduleType,
        platform: info.targets?.map((t: any) => t.name) || ["multi"],
        rank: info.rank,
        options: Object.fromEntries(
          Object.entries(options || {}).map(([k, v]: [string, any]) => [k, {
            name: k, type: v.type, required: v.required,
            default: v.default, description: v.desc,
            values: v.enums,
          }])
        ),
      };
    } catch {
      return null;
    }
  }

  async dispatch(request: C2TaskRequest): Promise<C2TaskResult> {
    const startedAt = new Date().toISOString();
    try {
      const client = await this.getClient();
      if (!client) throw new Error("No Metasploit connection");

      const sessionId = request.agentId;
      const session = (await client.listSessions())[sessionId];
      if (!session) throw new Error(`Session ${sessionId} not found`);

      if (session.type === "meterpreter") {
        // Meterpreter command execution
        const command = request.options?.command || request.moduleId;
        await client.meterpreterWrite(sessionId, command);
        // Poll for output
        await new Promise(r => setTimeout(r, 2000));
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
          completedAt: new Date().toISOString(),
        };
      } else {
        // Shell command execution
        const command = request.options?.command || request.moduleId;
        await client.shellWrite(sessionId, command + "\n");
        await new Promise(r => setTimeout(r, 2000));
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
          completedAt: new Date().toISOString(),
        };
      }
    } catch (err: any) {
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
        completedAt: new Date().toISOString(),
      };
    }
  }

  /**
   * Execute a Metasploit module (exploit/post/auxiliary) against a target.
   * This is separate from session-based dispatch — it launches a new module job.
   */
  async executeModule(params: {
    moduleType: string;
    modulePath: string;
    options: Record<string, any>;
    payload?: string;
  }): Promise<C2TaskResult> {
    const startedAt = new Date().toISOString();
    try {
      const client = await this.getClient();
      if (!client) throw new Error("No Metasploit connection");

      const result = await client.executeModule(
        params.moduleType,
        params.modulePath,
        params.options,
        params.payload,
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
        metadata: { jobId: result.job_id, uuid: result.uuid },
      };
    } catch (err: any) {
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
        completedAt: new Date().toISOString(),
      };
    }
  }

  async pollResult(taskId: string, agentId: string): Promise<C2TaskResult> {
    try {
      const client = await this.getClient();
      if (!client) throw new Error("No Metasploit connection");

      if (taskId.startsWith("msf-job-")) {
        const jobId = taskId.replace("msf-job-", "");
        const jobs = await client.listJobs();
        const isRunning = jobId in jobs;
        return {
          taskId, framework: "metasploit", agentId, moduleId: "",
          status: isRunning ? "running" : "success",
          exitCode: isRunning ? -1 : 0,
          stdout: isRunning ? "Job still running" : "Job completed",
          stderr: "", startedAt: new Date().toISOString(),
          completedAt: isRunning ? undefined : new Date().toISOString(),
        };
      }

      // Session-based task — already completed inline
      return {
        taskId, framework: "metasploit", agentId, moduleId: "",
        status: "success", exitCode: 0, stdout: "", stderr: "",
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
      };
    } catch (err: any) {
      return {
        taskId, framework: "metasploit", agentId, moduleId: "",
        status: "error", exitCode: -1, stdout: "", stderr: err.message,
        startedAt: new Date().toISOString(),
      };
    }
  }

  async killAgent(agentId: string): Promise<boolean> {
    try {
      const client = await this.getClient();
      if (!client) return false;
      await client.stopSession(agentId);
      return true;
    } catch {
      return false;
    }
  }
}

// ─── Sliver Adapter ─────────────────────────────────────────────────────────

/**
 * Sliver C2 adapter using the Sliver REST API.
 * Sliver exposes a gRPC API natively, but also supports REST via sliver-server.
 * We use REST for broader compatibility.
 *
 * Required ENV:
 *   SLIVER_API_URL — e.g. https://sliver-server:31337
 *   SLIVER_API_TOKEN — operator token from `sliver-server operator`
 */
export class SliverAdapter implements IC2Adapter {
  readonly framework: C2FrameworkType = "sliver";

  private get baseUrl(): string {
    return process.env.SLIVER_API_URL || "";
  }

  private get token(): string {
    return process.env.SLIVER_API_TOKEN || "";
  }

  private async sliverFetch(endpoint: string, options: RequestInit = {}): Promise<any> {
    if (!this.baseUrl) throw new Error("SLIVER_API_URL not configured");
    const url = `${this.baseUrl}${endpoint}`;
    const resp = await fetch(url, {
      ...options,
      headers: {
        "Authorization": `Bearer ${this.token}`,
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });
    if (!resp.ok) throw new Error(`Sliver API ${resp.status}: ${await resp.text()}`);
    return resp.json().catch(() => null);
  }

  async healthCheck(): Promise<C2HealthStatus> {
    try {
      const [version, sessions, beacons] = await Promise.all([
        this.sliverFetch("/version").catch(() => null),
        this.sliverFetch("/sessions").catch(() => []),
        this.sliverFetch("/beacons").catch(() => []),
      ]);
      const sessionCount = Array.isArray(sessions) ? sessions.length : 0;
      const beaconCount = Array.isArray(beacons) ? beacons.length : 0;
      return {
        framework: "sliver",
        connected: true,
        version: version?.version || "unknown",
        agentCount: sessionCount + beaconCount,
        activeJobs: 0,
        lastChecked: new Date().toISOString(),
        details: { sessions: sessionCount, beacons: beaconCount },
      };
    } catch (err: any) {
      return {
        framework: "sliver",
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
      const [sessions, beacons] = await Promise.all([
        this.sliverFetch("/sessions").catch(() => []),
        this.sliverFetch("/beacons").catch(() => []),
      ]);

      const agents: C2Agent[] = [];

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
            lastSeen: s.LastCheckin || new Date().toISOString(),
            privileges: (s.Username || "").includes("root") || (s.Username || "").includes("SYSTEM") ? "system" : "user",
            transport: s.Transport || s.transport || "mtls",
            metadata: { type: "session", pid: s.PID || s.pid, name: s.Name || s.name },
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
            lastSeen: b.LastCheckin || new Date().toISOString(),
            privileges: (b.Username || "").includes("root") || (b.Username || "").includes("SYSTEM") ? "system" : "user",
            transport: b.Transport || b.transport || "https",
            metadata: { type: "beacon", interval: b.Interval, jitter: b.Jitter, pid: b.PID },
          });
        }
      }

      return agents;
    } catch {
      return [];
    }
  }

  private beaconStatus(b: any): C2AgentStatus {
    const lastCheckin = new Date(b.LastCheckin || b.last_checkin || 0).getTime();
    const interval = (b.Interval || 60) * 1000;
    const missedCheckins = (Date.now() - lastCheckin) / interval;
    if (missedCheckins < 3) return "active";
    if (missedCheckins < 10) return "dormant";
    return "dead";
  }

  async getAgent(agentId: string): Promise<C2Agent | null> {
    const agents = await this.listAgents();
    return agents.find(a => a.id === agentId) || null;
  }

  async searchModules(query: string): Promise<C2Module[]> {
    // Sliver uses built-in commands rather than modules
    // Map common commands to C2Module format
    const sliverCommands: C2Module[] = [
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
      { id: "wmi", framework: "sliver", name: "WMI", description: "Execute via WMI", type: "command", platform: ["windows"], techniqueId: "T1047" },
    ];

    const q = query.toLowerCase();
    return sliverCommands.filter(c =>
      c.name.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q) ||
      c.id.includes(q) ||
      c.techniqueId?.toLowerCase().includes(q)
    );
  }

  async getModule(moduleId: string): Promise<C2Module | null> {
    const modules = await this.searchModules(moduleId);
    return modules.find(m => m.id === moduleId) || null;
  }

  async dispatch(request: C2TaskRequest): Promise<C2TaskResult> {
    const startedAt = new Date().toISOString();
    try {
      // Determine if this is a session or beacon
      const agent = await this.getAgent(request.agentId);
      if (!agent) throw new Error(`Agent ${request.agentId} not found`);

      const isBeacon = agent.metadata?.type === "beacon";
      const endpoint = isBeacon
        ? `/beacons/${request.agentId}/tasks`
        : `/sessions/${request.agentId}/commands`;

      const result = await this.sliverFetch(endpoint, {
        method: "POST",
        body: JSON.stringify({
          command: request.moduleId,
          args: request.options?.args || [],
          data: request.options?.data,
          timeout: request.timeout || 300,
        }),
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
        metadata: { isBeacon, response: result },
      };
    } catch (err: any) {
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
        completedAt: new Date().toISOString(),
      };
    }
  }

  async pollResult(taskId: string, agentId: string): Promise<C2TaskResult> {
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
        startedAt: result?.CreatedAt || new Date().toISOString(),
        completedAt: result?.Completed ? new Date().toISOString() : undefined,
      };
    } catch (err: any) {
      return {
        taskId, framework: "sliver", agentId, moduleId: "",
        status: "error", exitCode: -1, stdout: "", stderr: err.message,
        startedAt: new Date().toISOString(),
      };
    }
  }

  async killAgent(agentId: string): Promise<boolean> {
    try {
      // Try session kill first, then beacon
      await this.sliverFetch(`/sessions/${agentId}/kill`, { method: "POST" })
        .catch(() => this.sliverFetch(`/beacons/${agentId}/kill`, { method: "POST" }));
      return true;
    } catch {
      return false;
    }
  }
}

// ─── Empire Adapter ────────────────────────────────────────────────────────

/**
 * Empire C2 adapter using the Empire REST API (Starkiller / Empire v5+).
 * Empire exposes a REST API on port 1337 by default.
 *
 * Required ENV:
 *   EMPIRE_BASE_URL — e.g. https://empire-server:1337
 *   EMPIRE_API_KEY  — API token from Empire (or use username/password auth)
 *
 * Empire concepts mapped to unified interface:
 *   - Agents → C2Agent
 *   - Modules (powershell, python, csharp) → C2Module
 *   - Tasks → C2TaskResult
 *   - Stagers → used for initial access generation
 *   - Listeners → required for agent callbacks
 */
export class EmpireAdapter implements IC2Adapter {
  readonly framework: C2FrameworkType = "empire";

  private get baseUrl(): string {
    return process.env.EMPIRE_BASE_URL || "";
  }

  private get apiKey(): string {
    return process.env.EMPIRE_API_KEY || "";
  }

  private tokenCache: { token: string; expiresAt: number } | null = null;

  private async getToken(): Promise<string> {
    // If we have a static API key, use it directly
    if (this.apiKey) return this.apiKey;

    // Otherwise try username/password auth
    if (this.tokenCache && this.tokenCache.expiresAt > Date.now()) {
      return this.tokenCache.token;
    }

    const username = process.env.EMPIRE_USERNAME || "empireadmin";
    const password = process.env.EMPIRE_PASSWORD || "password123!";

    const resp = await fetch(`${this.baseUrl}/api/v2/admin/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!resp.ok) throw new Error(`Empire auth failed: ${resp.status}`);
    const data = await resp.json();
    const token = data.token || data.access_token;
    this.tokenCache = { token, expiresAt: Date.now() + 3500 * 1000 }; // ~1hr
    return token;
  }

  private async empireFetch(endpoint: string, options: RequestInit = {}): Promise<any> {
    if (!this.baseUrl) throw new Error("EMPIRE_BASE_URL not configured");
    const token = await this.getToken();
    const url = `${this.baseUrl}/api/v2${endpoint}`;
    const resp = await fetch(url, {
      ...options,
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });
    if (!resp.ok) throw new Error(`Empire API ${resp.status}: ${await resp.text()}`);
    return resp.json().catch(() => null);
  }

  async healthCheck(): Promise<C2HealthStatus> {
    try {
      const [version, agents, listeners] = await Promise.all([
        this.empireFetch("/meta/version").catch(() => null),
        this.empireFetch("/agents").catch(() => ({ records: [] })),
        this.empireFetch("/listeners").catch(() => ({ records: [] })),
      ]);
      const agentList = agents?.records || agents || [];
      const listenerList = listeners?.records || listeners || [];
      return {
        framework: "empire",
        connected: true,
        version: version?.version || "5.x",
        agentCount: Array.isArray(agentList) ? agentList.length : 0,
        activeJobs: Array.isArray(listenerList) ? listenerList.length : 0,
        lastChecked: new Date().toISOString(),
        details: { listeners: Array.isArray(listenerList) ? listenerList.length : 0 },
      };
    } catch (err: any) {
      return {
        framework: "empire",
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
      const data = await this.empireFetch("/agents");
      const agents = data?.records || data || [];
      if (!Array.isArray(agents)) return [];
      return agents.map((a: any) => ({
        id: a.session_id || a.name || a.id?.toString() || "unknown",
        framework: "empire" as C2FrameworkType,
        hostname: a.hostname || a.host || "unknown",
        username: a.username || "unknown",
        platform: this.mapPlatform(a.os_details || a.language || ""),
        architecture: a.architecture || this.inferArch(a.os_details || ""),
        ipAddress: a.external_ip || a.internal_ip || a.host || "",
        status: this.mapAgentStatus(a),
        lastSeen: a.lastseen_time || a.checkin_time || new Date().toISOString(),
        privileges: this.inferPrivileges(a),
        processId: a.process_id,
        processName: a.process_name,
        transport: a.listener || "http",
        metadata: {
          language: a.language,           // powershell, python, csharp
          listener: a.listener,
          high_integrity: a.high_integrity,
          stale: a.stale,
          delay: a.delay,
          jitter: a.jitter,
          nonce: a.nonce,
        },
      }));
    } catch {
      return [];
    }
  }

  private mapPlatform(osDetails: string): string {
    const os = osDetails.toLowerCase();
    if (os.includes("windows")) return "windows";
    if (os.includes("linux") || os.includes("ubuntu") || os.includes("centos")) return "linux";
    if (os.includes("macos") || os.includes("darwin")) return "macos";
    return "multi";
  }

  private inferArch(osDetails: string): string {
    const os = osDetails.toLowerCase();
    if (os.includes("x64") || os.includes("amd64") || os.includes("64-bit")) return "x64";
    if (os.includes("x86") || os.includes("32-bit")) return "x86";
    if (os.includes("arm")) return "arm64";
    return "x64";
  }

  private mapAgentStatus(a: any): C2AgentStatus {
    if (a.stale === true) return "dormant";
    if (a.archived === true) return "dead";
    const lastSeen = new Date(a.lastseen_time || a.checkin_time || 0).getTime();
    const diffMin = (Date.now() - lastSeen) / 60000;
    if (diffMin < 5) return "active";
    if (diffMin < 60) return "dormant";
    return "dead";
  }

  private inferPrivileges(a: any): string {
    if (a.high_integrity === true) return "admin";
    const username = (a.username || "").toLowerCase();
    if (username.includes("system") || username.includes("root") || username === "nt authority\\system") return "system";
    if (username.includes("admin")) return "admin";
    return "user";
  }

  async getAgent(agentId: string): Promise<C2Agent | null> {
    try {
      const data = await this.empireFetch(`/agents/${agentId}`);
      if (!data) return null;
      const agents = await this.listAgents();
      return agents.find(a => a.id === agentId) || null;
    } catch {
      return null;
    }
  }

  async searchModules(query: string): Promise<C2Module[]> {
    try {
      const data = await this.empireFetch(`/modules?query=${encodeURIComponent(query)}`);
      const modules = data?.records || data || [];
      if (!Array.isArray(modules)) return [];
      return modules.slice(0, 50).map((m: any) => ({
        id: m.id || m.name,
        framework: "empire" as C2FrameworkType,
        name: m.name,
        description: m.description || "",
        type: this.mapModuleType(m),
        platform: this.mapModulePlatforms(m),
        techniqueId: this.extractTechniqueId(m),
        tactic: this.extractTactic(m),
        rank: m.opsec_safe ? 400 : 300,
        options: m.options ? Object.fromEntries(
          Object.entries(m.options).map(([k, v]: [string, any]) => [k, {
            name: k,
            type: typeof v.Value === "boolean" ? "boolean" : "string",
            required: v.Required || false,
            default: v.Value,
            description: v.Description || "",
          }])
        ) : undefined,
      }));
    } catch {
      // Fallback: return common Empire modules
      return this.getBuiltinModules(query);
    }
  }

  private mapModuleType(m: any): string {
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

  private mapModulePlatforms(m: any): string[] {
    const lang = (m.language || "").toLowerCase();
    if (lang === "powershell" || lang === "csharp") return ["windows"];
    if (lang === "python") return ["linux", "macos"];
    return ["windows", "linux", "macos"];
  }

  private extractTechniqueId(m: any): string | undefined {
    if (m.techniques) {
      const techniques = Array.isArray(m.techniques) ? m.techniques : [m.techniques];
      return techniques[0] || undefined;
    }
    // Map common Empire modules to MITRE techniques
    const name = (m.name || "").toLowerCase();
    const techniqueMap: Record<string, string> = {
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
      "wmi_persistence": "T1546.003",
    };
    for (const [key, tech] of Object.entries(techniqueMap)) {
      if (name.includes(key)) return tech;
    }
    return undefined;
  }

  private extractTactic(m: any): string | undefined {
    if (m.tactics) {
      const tactics = Array.isArray(m.tactics) ? m.tactics : [m.tactics];
      return tactics[0] || undefined;
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
    return undefined;
  }

  /**
   * Fallback built-in module list for when the API is unreachable.
   * Covers the most commonly used Empire modules.
   */
  private getBuiltinModules(query: string): C2Module[] {
    const modules: C2Module[] = [
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
      { id: "csharp/lateral_movement/sharpwmi", framework: "empire", name: "SharpWMI", description: "C# WMI lateral movement", type: "exploit", platform: ["windows"], techniqueId: "T1047", tactic: "lateral-movement" },
    ];

    const q = query.toLowerCase();
    return modules.filter(m =>
      m.name.toLowerCase().includes(q) ||
      m.description.toLowerCase().includes(q) ||
      m.id.toLowerCase().includes(q) ||
      m.techniqueId?.toLowerCase().includes(q) ||
      m.tactic?.toLowerCase().includes(q)
    );
  }

  async getModule(moduleId: string): Promise<C2Module | null> {
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
          Object.entries(data.options).map(([k, v]: [string, any]) => [k, {
            name: k,
            type: typeof v.Value === "boolean" ? "boolean" : "string",
            required: v.Required || false,
            default: v.Value,
            description: v.Description || "",
          }])
        ) : undefined,
      };
    } catch {
      // Try built-in modules
      const builtins = this.getBuiltinModules(moduleId);
      return builtins.find(m => m.id === moduleId) || null;
    }
  }

  async dispatch(request: C2TaskRequest): Promise<C2TaskResult> {
    const startedAt = new Date().toISOString();
    try {
      // Build task payload
      const taskPayload: any = {
        module: request.moduleId,
      };

      // Add module options
      if (request.options) {
        taskPayload.options = request.options;
      }

      // Post task to agent
      const result = await this.empireFetch(`/agents/${request.agentId}/tasks/module`, {
        method: "POST",
        body: JSON.stringify(taskPayload),
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
        metadata: { taskData: result },
      };
    } catch (err: any) {
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
        completedAt: new Date().toISOString(),
      };
    }
  }

  /**
   * Execute a shell command on an Empire agent.
   */
  async shellCommand(agentId: string, command: string): Promise<C2TaskResult> {
    const startedAt = new Date().toISOString();
    try {
      const result = await this.empireFetch(`/agents/${agentId}/tasks/shell`, {
        method: "POST",
        body: JSON.stringify({ command }),
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
        metadata: { command },
      };
    } catch (err: any) {
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
        completedAt: new Date().toISOString(),
      };
    }
  }

  async pollResult(taskId: string, agentId: string): Promise<C2TaskResult> {
    try {
      // Empire v5 task results endpoint
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
        startedAt: data?.created_at || new Date().toISOString(),
        completedAt: completed ? (data?.updated_at || new Date().toISOString()) : undefined,
      };
    } catch (err: any) {
      return {
        taskId,
        framework: "empire",
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
      await this.empireFetch(`/agents/${agentId}`, { method: "DELETE" });
      return true;
    } catch {
      return false;
    }
  }

  // ─── Empire-Specific Operations ──────────────────────────────────────────

  /** List all active listeners */
  async listListeners(): Promise<any[]> {
    try {
      const data = await this.empireFetch("/listeners");
      return data?.records || data || [];
    } catch {
      return [];
    }
  }

  /** Create a new listener */
  async createListener(params: {
    name: string;
    template: string;   // http, http_com, http_hop, http_foreign, http_mapi, onedrive, dbx, etc.
    host: string;
    port: number;
    options?: Record<string, any>;
  }): Promise<any> {
    return this.empireFetch("/listeners", {
      method: "POST",
      body: JSON.stringify({
        name: params.name,
        template: params.template,
        options: {
          Host: params.host,
          Port: params.port.toString(),
          ...params.options,
        },
      }),
    });
  }

  /** List available stagers */
  async listStagers(): Promise<any[]> {
    try {
      const data = await this.empireFetch("/stagers");
      return data?.records || data || [];
    } catch {
      return [];
    }
  }

  /** Generate a stager for agent deployment */
  async generateStager(params: {
    template: string;   // multi/launcher, windows/launcher_bat, multi/bash, etc.
    listener: string;
    options?: Record<string, any>;
  }): Promise<{ output: string; filename?: string }> {
    const result = await this.empireFetch("/stagers", {
      method: "POST",
      body: JSON.stringify({
        StagerName: params.template,
        Listener: params.listener,
        ...params.options,
      }),
    });
    return {
      output: result?.output || result?.Output || "",
      filename: result?.OutFile || undefined,
    };
  }

  /** Get agent task results history */
  async getAgentResults(agentId: string): Promise<any[]> {
    try {
      const data = await this.empireFetch(`/agents/${agentId}/tasks`);
      return data?.records || data || [];
    } catch {
      return [];
    }
  }
}

// ─── Manjusaka Adapter ──────────────────────────────────────────────────────

/**
 * Manjusaka C2 adapter using the NPS REST API (Poem + OpenAPI).
 * Manjusaka is a Rust-based C2 framework with staged implants (NPC1/NPC2),
 * VNC remote desktop, file management, tunneling, and BOF plugin support.
 * NPS server exposes an HTTP/HTTPS API on port 33000 by default.
 *
 * Manjusaka concepts mapped to unified interface:
 *   - NPC1 (stage 1 basic agent) + NPC2 (stage 2 enhanced agent) → C2Agent
 *   - Built-in commands + plugins (BOF, getpass) → C2Module
 *   - Tasks → C2TaskResult
 *   - Listeners → required for agent callbacks
 *   - Tunnels → network pivoting capability
 */
export class ManjusakaAdapter implements IC2Adapter {
  readonly framework: C2FrameworkType = "manjusaka";

  private get baseUrl(): string {
    return process.env.MANJUSAKA_API_URL || process.env.MANJUSAKA_BASE_URL || "";
  }

  private get token(): string {
    return process.env.MANJUSAKA_API_KEY || process.env.MANJUSAKA_TOKEN || "";
  }

  private async manjusakaFetch(endpoint: string, options: RequestInit = {}): Promise<any> {
    if (!this.baseUrl) throw new Error("MANJUSAKA_API_URL not configured");
    const url = `${this.baseUrl}${endpoint}`;
    const resp = await fetch(url, {
      ...options,
      headers: {
        "Authorization": `Bearer ${this.token}`,
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });
    if (!resp.ok) throw new Error(`Manjusaka API ${resp.status}: ${await resp.text()}`);
    return resp.json().catch(() => null);
  }

  async healthCheck(): Promise<C2HealthStatus> {
    try {
      const [health, agents] = await Promise.all([
        this.manjusakaFetch("/api/health").catch(() => null),
        this.manjusakaFetch("/api/agents").catch(() => []),
      ]);
      const agentCount = Array.isArray(agents) ? agents.length : (agents?.data?.length || 0);
      return {
        framework: "manjusaka",
        connected: true,
        version: health?.version || "unknown",
        agentCount,
        activeJobs: health?.active_tasks || 0,
        lastChecked: new Date().toISOString(),
        details: {
          npc1Agents: Array.isArray(agents) ? agents.filter((a: any) => a.type === "npc1").length : 0,
          npc2Agents: Array.isArray(agents) ? agents.filter((a: any) => a.type === "npc2").length : 0,
          listeners: health?.listeners || 0,
          tunnels: health?.tunnels || 0,
        },
      };
    } catch (err: any) {
      return {
        framework: "manjusaka",
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
      const data = await this.manjusakaFetch("/api/agents");
      const agentList = Array.isArray(data) ? data : (data?.data || []);

      return agentList.map((a: any) => ({
        id: a.id?.toString() || a.agent_id || `mjsk-${Date.now()}`,
        framework: "manjusaka" as C2FrameworkType,
        hostname: a.hostname || a.computer_name || "unknown",
        username: a.username || a.user || "unknown",
        platform: (a.platform || a.os || "unknown").toLowerCase(),
        architecture: a.architecture || a.arch || "x64",
        ipAddress: a.ip_address || a.remote_addr || a.external_ip || "",
        status: this.mapAgentStatus(a),
        lastSeen: a.last_checkin || a.last_seen || new Date().toISOString(),
        privileges: this.inferPrivileges(a),
        transport: a.transport || a.protocol || "https",
        metadata: {
          type: a.type || (a.has_npc2 ? "npc2" : "npc1"),
          pid: a.pid,
          npc2Loaded: a.has_npc2 || a.type === "npc2",
          listenerId: a.listener_id,
          projectId: a.project_id,
          vncActive: a.vnc_active || false,
          tunnelCount: a.tunnel_count || 0,
        },
      }));
    } catch {
      return [];
    }
  }

  private mapAgentStatus(a: any): C2AgentStatus {
    if (a.status === "active" || a.status === "online") return "active";
    if (a.status === "dormant" || a.status === "sleeping") return "dormant";
    if (a.status === "dead" || a.status === "offline") return "dead";
    // Infer from last checkin
    const lastCheckin = new Date(a.last_checkin || a.last_seen || 0).getTime();
    const elapsed = Date.now() - lastCheckin;
    if (elapsed < 5 * 60 * 1000) return "active";      // < 5 min
    if (elapsed < 30 * 60 * 1000) return "dormant";     // < 30 min
    return "dead";
  }

  private inferPrivileges(a: any): string {
    const user = (a.username || a.user || "").toLowerCase();
    if (user === "root" || user === "system" || user.includes("nt authority")) return "system";
    if (a.is_admin || a.elevated) return "admin";
    return "user";
  }

  async getAgent(agentId: string): Promise<C2Agent | null> {
    try {
      const data = await this.manjusakaFetch(`/api/agents/${agentId}`);
      if (!data) return null;
      const agents = await this.listAgents();
      return agents.find(a => a.id === agentId) || null;
    } catch {
      // Fallback: search in full list
      const agents = await this.listAgents();
      return agents.find(a => a.id === agentId) || null;
    }
  }

  async searchModules(query: string): Promise<C2Module[]> {
    // Manjusaka uses built-in commands + plugins (BOF, CRL, getpass)
    const manjusakaModules: C2Module[] = [
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
      { id: "self-destruct", framework: "manjusaka", name: "Self Destruct", description: "Remove agent from target and clean up artifacts", type: "command", platform: ["windows", "linux"], techniqueId: "T1070.004", tactic: "defense-evasion" },
    ];

    const q = query.toLowerCase();
    return manjusakaModules.filter(c =>
      c.name.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q) ||
      c.id.includes(q) ||
      c.techniqueId?.toLowerCase().includes(q) ||
      c.tactic?.toLowerCase().includes(q)
    );
  }

  async getModule(moduleId: string): Promise<C2Module | null> {
    const modules = await this.searchModules(moduleId);
    return modules.find(m => m.id === moduleId) || null;
  }

  async dispatch(request: C2TaskRequest): Promise<C2TaskResult> {
    const startedAt = new Date().toISOString();
    try {
      const agent = await this.getAgent(request.agentId);
      if (!agent) throw new Error(`Agent ${request.agentId} not found`);

      const result = await this.manjusakaFetch(`/api/agents/${request.agentId}/task`, {
        method: "POST",
        body: JSON.stringify({
          command: request.moduleId,
          args: request.options?.args || [],
          options: request.options || {},
          timeout: request.timeout || 300,
        }),
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
        metadata: { agentType: agent.metadata?.type, response: result },
      };
    } catch (err: any) {
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
        completedAt: new Date().toISOString(),
      };
    }
  }

  async pollResult(taskId: string, agentId: string): Promise<C2TaskResult> {
    try {
      const result = await this.manjusakaFetch(`/api/agents/${agentId}/task/${taskId}`);
      const completed = result?.status === "completed" || result?.status === "success";
      return {
        taskId,
        framework: "manjusaka",
        agentId,
        moduleId: result?.command || "",
        status: completed ? "success" : (result?.status === "failed" ? "failed" : "running"),
        exitCode: completed ? 0 : (result?.status === "failed" ? 1 : -1),
        stdout: result?.output || result?.stdout || "",
        stderr: result?.error || result?.stderr || "",
        startedAt: result?.started_at || new Date().toISOString(),
        completedAt: completed ? (result?.completed_at || new Date().toISOString()) : undefined,
      };
    } catch (err: any) {
      return {
        taskId, framework: "manjusaka", agentId, moduleId: "",
        status: "error", exitCode: -1, stdout: "", stderr: err.message,
        startedAt: new Date().toISOString(),
      };
    }
  }

  async killAgent(agentId: string): Promise<boolean> {
    try {
      await this.manjusakaFetch(`/api/agents/${agentId}`, { method: "DELETE" });
      return true;
    } catch {
      return false;
    }
  }

  // ─── Manjusaka-Specific Operations ──────────────────────────────────────────

  /** List all active listeners */
  async listListeners(): Promise<any[]> {
    try {
      const data = await this.manjusakaFetch("/api/listeners");
      return Array.isArray(data) ? data : (data?.data || []);
    } catch {
      return [];
    }
  }

  /** Create a new listener */
  async createListener(params: {
    name: string;
    protocol: "tcp" | "http" | "https" | "websocket" | "kcp" | "ssh";
    host: string;
    port: number;
    options?: Record<string, any>;
  }): Promise<any> {
    return this.manjusakaFetch("/api/listeners", {
      method: "POST",
      body: JSON.stringify(params),
    });
  }

  /** Stop a listener */
  async stopListener(listenerId: string): Promise<boolean> {
    try {
      await this.manjusakaFetch(`/api/listeners/${listenerId}`, { method: "DELETE" });
      return true;
    } catch {
      return false;
    }
  }

  /** Generate NPC1 implant */
  async generateImplant(params: {
    platform: "windows" | "linux";
    architecture: "x64" | "x86";
    listenerId: string;
    callbackHost: string;
    callbackPort: number;
    transport: "tcp" | "http" | "https" | "websocket" | "kcp";
    options?: Record<string, any>;
  }): Promise<any> {
    return this.manjusakaFetch("/api/payloads/generate", {
      method: "POST",
      body: JSON.stringify(params),
    });
  }

  /** Load NPC2 on an existing NPC1 agent */
  async loadNpc2(agentId: string): Promise<any> {
    return this.manjusakaFetch(`/api/agents/${agentId}/load-npc2`, {
      method: "POST",
    });
  }

  /** Unload NPC2 from an agent */
  async unloadNpc2(agentId: string): Promise<any> {
    return this.manjusakaFetch(`/api/agents/${agentId}/unload-npc2`, {
      method: "POST",
    });
  }

  /** Start VNC session on agent */
  async startVnc(agentId: string): Promise<any> {
    return this.manjusakaFetch(`/api/agents/${agentId}/vnc/start`, {
      method: "POST",
    });
  }

  /** Stop VNC session on agent */
  async stopVnc(agentId: string): Promise<any> {
    return this.manjusakaFetch(`/api/agents/${agentId}/vnc/stop`, {
      method: "POST",
    });
  }

  /** List active tunnels */
  async listTunnels(): Promise<any[]> {
    try {
      const data = await this.manjusakaFetch("/api/tunnels");
      return Array.isArray(data) ? data : (data?.data || []);
    } catch {
      return [];
    }
  }

  /** Create a tunnel through an agent */
  async createTunnel(params: {
    agentId: string;
    localPort: number;
    remoteHost: string;
    remotePort: number;
    type?: "tcp" | "socks5";
  }): Promise<any> {
    return this.manjusakaFetch("/api/tunnels", {
      method: "POST",
      body: JSON.stringify(params),
    });
  }

  /** Stop a tunnel */
  async stopTunnel(tunnelId: string): Promise<boolean> {
    try {
      await this.manjusakaFetch(`/api/tunnels/${tunnelId}`, { method: "DELETE" });
      return true;
    } catch {
      return false;
    }
  }

  /** Execute BOF on agent */
  async executeBof(agentId: string, bofPath: string, args?: string[]): Promise<C2TaskResult> {
    return this.dispatch({
      agentId,
      moduleId: "bof-execute",
      options: { bofPath, args: args || [] },
    });
  }

  /** Get aggregate stats */
  async getStats(): Promise<any> {
    try {
      return await this.manjusakaFetch("/api/stats");
    } catch {
      return { agents: 0, listeners: 0, tunnels: 0 };
    }
  }
}

// ─── C2 Registry ────────────────────────────────────────────────────────────

/**
 * Central registry that manages all C2 adapter instances.
 * Provides unified access to agents, modules, and dispatch across frameworks.
 */
export class C2Registry {
  private adapters = new Map<C2FrameworkType, IC2Adapter>();
  private static instance: C2Registry | null = null;

  static getInstance(): C2Registry {
    if (!C2Registry.instance) {
      C2Registry.instance = new C2Registry();
      // Auto-register available adapters
      C2Registry.instance.register(new CalderaAdapter());
      C2Registry.instance.register(new MetasploitAdapter());
      C2Registry.instance.register(new SliverAdapter());
      C2Registry.instance.register(new EmpireAdapter());
      C2Registry.instance.register(new CobaltStrikeAdapter());
      C2Registry.instance.register(new ManjusakaAdapter());
    }
    return C2Registry.instance;
  }

  register(adapter: IC2Adapter): void {
    this.adapters.set(adapter.framework, adapter);
  }

  get(framework: C2FrameworkType): IC2Adapter | undefined {
    return this.adapters.get(framework);
  }

  getAll(): IC2Adapter[] {
    return Array.from(this.adapters.values());
  }

  /** Health check all registered C2 frameworks */
  async healthCheckAll(): Promise<C2HealthStatus[]> {
    const results = await Promise.allSettled(
      this.getAll().map(a => a.healthCheck())
    );
    return results.map((r, i) =>
      r.status === "fulfilled" ? r.value : {
        framework: this.getAll()[i].framework,
        connected: false,
        agentCount: 0,
        activeJobs: 0,
        lastChecked: new Date().toISOString(),
        error: (r as PromiseRejectedResult).reason?.message || "Unknown error",
      }
    );
  }

  /** List all agents across all C2 frameworks */
  async listAllAgents(): Promise<C2Agent[]> {
    const results = await Promise.allSettled(
      this.getAll().map(a => a.listAgents())
    );
    return results.flatMap(r =>
      r.status === "fulfilled" ? r.value : []
    );
  }

  /** Search modules across all C2 frameworks */
  async searchAllModules(query: string): Promise<C2Module[]> {
    const results = await Promise.allSettled(
      this.getAll().map(a => a.searchModules(query))
    );
    return results.flatMap(r =>
      r.status === "fulfilled" ? r.value : []
    );
  }

  /** Dispatch to the correct C2 framework based on agent ID lookup */
  async dispatch(request: C2TaskRequest & { framework: C2FrameworkType }): Promise<C2TaskResult> {
    const adapter = this.get(request.framework);
    if (!adapter) throw new Error(`No adapter registered for ${request.framework}`);
    return adapter.dispatch(request);
  }

  /** Find which framework owns an agent */
  async resolveAgentFramework(agentId: string): Promise<C2FrameworkType | null> {
    for (const adapter of this.getAll()) {
      const agent = await adapter.getAgent(agentId);
      if (agent) return adapter.framework;
    }
    return null;
  }

  /** Get aggregate stats across all C2 frameworks */
  async getAggregateStats(): Promise<{
    totalAgents: number;
    activeAgents: number;
    frameworkStats: C2HealthStatus[];
    agentsByFramework: Record<C2FrameworkType, number>;
    agentsByPlatform: Record<string, number>;
    agentsByStatus: Record<C2AgentStatus, number>;
  }> {
    const [health, agents] = await Promise.all([
      this.healthCheckAll(),
      this.listAllAgents(),
    ]);

    const agentsByFramework: Record<string, number> = {};
    const agentsByPlatform: Record<string, number> = {};
    const agentsByStatus: Record<string, number> = {};

    for (const agent of agents) {
      agentsByFramework[agent.framework] = (agentsByFramework[agent.framework] || 0) + 1;
      agentsByPlatform[agent.platform] = (agentsByPlatform[agent.platform] || 0) + 1;
      agentsByStatus[agent.status] = (agentsByStatus[agent.status] || 0) + 1;
    }

    return {
      totalAgents: agents.length,
      activeAgents: agents.filter(a => a.status === "active").length,
      frameworkStats: health,
      agentsByFramework: agentsByFramework as Record<C2FrameworkType, number>,
      agentsByPlatform,
      agentsByStatus: agentsByStatus as Record<C2AgentStatus, number>,
    };
  }
}

// ─── Convenience Exports ────────────────────────────────────────────────────

export function getC2Registry(): C2Registry {
  return C2Registry.getInstance();
}

export function getCalderaAdapter(): CalderaAdapter {
  return C2Registry.getInstance().get("caldera") as CalderaAdapter;
}

export function getMetasploitAdapter(): MetasploitAdapter {
  return C2Registry.getInstance().get("metasploit") as MetasploitAdapter;
}

export function getSliverAdapter(): SliverAdapter {
  return C2Registry.getInstance().get("sliver") as SliverAdapter;
}

export function getEmpireAdapter(): EmpireAdapter {
  return C2Registry.getInstance().get("empire") as EmpireAdapter;
}

export function getCobaltStrikeAdapter(): CobaltStrikeAdapter {
  return C2Registry.getInstance().get("cobaltstrike") as CobaltStrikeAdapter;
}

export function getManjusakaAdapter(): ManjusakaAdapter {
  return C2Registry.getInstance().get("manjusaka") as ManjusakaAdapter;
}
