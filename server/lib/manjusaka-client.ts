/**
 * Manjusaka C2 API Client
 *
 * Connects to a Manjusaka C2 server via its REST API.
 * Manjusaka is a Rust-based C2 framework with Go/Rust implants.
 * The control server exposes an HTTP API for agent management,
 * listener control, and implant generation.
 *
 * Default port: 8443 (HTTPS) or 8080 (HTTP)
 * Auth: Token-based or admin password
 */
import { ENV } from "../_core/env";
import { getFIPSHttpsAgent } from "./fips-tls";

// ─── Types ─────────────────────────────────────────────────────────────────

export interface ManjusakaAgent {
  id: string;
  hostname: string;
  username: string;
  os: string;
  arch: string;
  ip: string;
  pid: number;
  processName: string;
  implantType: "rust" | "go";
  transport: string;
  lastSeen: number;
  isAlive: boolean;
  privileges: string;
  integrity: string;
}

export interface ManjusakaListener {
  id: string;
  name: string;
  type: "tcp" | "http" | "https" | "websocket";
  bindHost: string;
  bindPort: number;
  isActive: boolean;
  connectedAgents: number;
}

export interface ManjusakaImplant {
  id: string;
  name: string;
  os: string;
  arch: string;
  implantType: "rust" | "go";
  transport: string;
  format: string;
  size: number;
  createdAt: number;
  sha256: string;
}

export interface ManjusakaTunnel {
  id: string;
  agentId: string;
  type: "socks5" | "portforward" | "reverse";
  localHost: string;
  localPort: number;
  remoteHost: string;
  remotePort: number;
  isActive: boolean;
}

export interface ManjusakaVncSession {
  id: string;
  agentId: string;
  hostname: string;
  resolution: string;
  isActive: boolean;
  startedAt: number;
}

// ─── Client ────────────────────────────────────────────────────────────────

export class ManjusakaClient {
  private baseUrl: string;
  private token: string;
  private adminPassword: string;

  constructor(baseUrl?: string, token?: string, password?: string) {
    this.baseUrl = (baseUrl || ENV.MANJUSAKA_SERVER_URL).replace(/\/$/, "");
    this.token = token || ENV.MANJUSAKA_API_TOKEN;
    this.adminPassword = password || ENV.MANJUSAKA_ADMIN_PASSWORD;
  }

  get isConfigured(): boolean {
    return !!(this.baseUrl && (this.token || this.adminPassword));
  }

  // ─── Auth ──────────────────────────────────────────────────────────────

  private async authenticate(): Promise<void> {
    if (this.token) return; // already have a token
    if (!this.adminPassword) throw new Error("No Manjusaka token or password configured");

    const resp = await fetch(`${this.baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: this.adminPassword }),
      signal: AbortSignal.timeout(10000),
    });

    if (!resp.ok) throw new Error(`Manjusaka auth failed: ${resp.status}`);
    const data = await resp.json();
    this.token = data.token || data.access_token || "";
  }

  // ─── HTTP Helper ───────────────────────────────────────────────────────

  private async request<T = any>(
    method: string,
    path: string,
    body?: any,
    timeoutMs = 10000
  ): Promise<T> {
    if (!this.token) await this.authenticate();

    const url = `${this.baseUrl}/api${path}`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${this.token}`,
    };

    const options: RequestInit = {
      method,
      headers,
      signal: AbortSignal.timeout(timeoutMs),
    };

    if (body) options.body = JSON.stringify(body);

    if (url.startsWith("https://")) {
      const { getUndiciDispatcher } = require('./gophish-client');
      const dispatcher = getUndiciDispatcher();
      if (dispatcher) (options as any).dispatcher = dispatcher;
    }

    const response = await fetch(url, options);

    if (response.status === 401) {
      // Token expired, re-authenticate
      this.token = "";
      await this.authenticate();
      headers["Authorization"] = `Bearer ${this.token}`;
      const retryResp = await fetch(url, { ...options, headers });
      if (!retryResp.ok) throw new Error(`Manjusaka API ${method} ${path} failed: ${retryResp.status}`);
      return retryResp.json() as Promise<T>;
    }

    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`Manjusaka API ${method} ${path} failed: ${response.status} ${text}`);
    }

    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      return response.json() as Promise<T>;
    }
    return response.text() as unknown as T;
  }

  // ─── Health Check ──────────────────────────────────────────────────────

  async healthCheck(): Promise<{
    status: "online" | "offline" | "unconfigured" | "error";
    version?: string;
    error?: string;
    latencyMs?: number;
  }> {
    if (!this.isConfigured) return { status: "unconfigured" };

    const start = Date.now();
    try {
      const info = await this.request<{ version?: string }>("GET", "/info", undefined, 5000);
      return {
        status: "online",
        version: info?.version || "unknown",
        latencyMs: Date.now() - start,
      };
    } catch (err: any) {
      return {
        status: "error",
        error: err.message,
        latencyMs: Date.now() - start,
      };
    }
  }

  // ─── Listeners ─────────────────────────────────────────────────────────

  async listListeners(): Promise<ManjusakaListener[]> {
    const data = await this.request<{ listeners?: ManjusakaListener[] }>("GET", "/listeners");
    return data?.listeners || [];
  }

  async createListener(config: {
    name: string;
    type: "tcp" | "http" | "https" | "websocket";
    bindHost: string;
    bindPort: number;
  }): Promise<ManjusakaListener> {
    return this.request("POST", "/listeners", config);
  }

  async stopListener(listenerId: string): Promise<void> {
    await this.request("DELETE", `/listeners/${listenerId}`);
  }

  // ─── Agents ────────────────────────────────────────────────────────────

  async listAgents(): Promise<ManjusakaAgent[]> {
    const data = await this.request<{ agents?: ManjusakaAgent[] }>("GET", "/agents");
    return data?.agents || [];
  }

  async killAgent(agentId: string): Promise<void> {
    await this.request("DELETE", `/agents/${agentId}`);
  }

  async executeTask(agentId: string, command: string, args?: string[]): Promise<{
    taskId: string;
    output?: string;
  }> {
    return this.request("POST", `/agents/${agentId}/tasks`, {
      type: "shell",
      command,
      args: args || [],
    }, 30000);
  }

  // ─── Implants ──────────────────────────────────────────────────────────

  async listImplants(): Promise<ManjusakaImplant[]> {
    const data = await this.request<{ implants?: ManjusakaImplant[] }>("GET", "/implants");
    return data?.implants || [];
  }

  async generateImplant(config: {
    name: string;
    os: string;
    arch: string;
    implantType: "rust" | "go";
    transport: string;
    format: string;
    c2Url: string;
  }): Promise<ManjusakaImplant> {
    return this.request("POST", "/implants/generate", config, 120000);
  }

  // ─── NPC2 Modules ─────────────────────────────────────────────────────

  async loadNpc2(agentId: string, moduleId: string): Promise<{ success: boolean }> {
    return this.request("POST", `/agents/${agentId}/npc2/load`, { moduleId });
  }

  async unloadNpc2(agentId: string, moduleId: string): Promise<{ success: boolean }> {
    return this.request("POST", `/agents/${agentId}/npc2/unload`, { moduleId });
  }

  // ─── VNC ───────────────────────────────────────────────────────────────

  async startVnc(agentId: string): Promise<ManjusakaVncSession> {
    return this.request("POST", `/agents/${agentId}/vnc/start`);
  }

  async stopVnc(agentId: string, sessionId: string): Promise<void> {
    await this.request("POST", `/agents/${agentId}/vnc/stop`, { sessionId });
  }

  async listVncSessions(): Promise<ManjusakaVncSession[]> {
    const data = await this.request<{ sessions?: ManjusakaVncSession[] }>("GET", "/vnc/sessions");
    return data?.sessions || [];
  }

  // ─── Tunnels ───────────────────────────────────────────────────────────

  async listTunnels(): Promise<ManjusakaTunnel[]> {
    const data = await this.request<{ tunnels?: ManjusakaTunnel[] }>("GET", "/tunnels");
    return data?.tunnels || [];
  }

  async createTunnel(config: {
    agentId: string;
    type: "socks5" | "portforward" | "reverse";
    localHost: string;
    localPort: number;
    remoteHost?: string;
    remotePort?: number;
  }): Promise<ManjusakaTunnel> {
    return this.request("POST", "/tunnels", config);
  }

  async stopTunnel(tunnelId: string): Promise<void> {
    await this.request("DELETE", `/tunnels/${tunnelId}`);
  }
}

// ─── Singleton ─────────────────────────────────────────────────────────────

let _manjusakaClient: ManjusakaClient | null = null;

export function getManjusakaClient(): ManjusakaClient {
  if (!_manjusakaClient) {
    _manjusakaClient = new ManjusakaClient();
  }
  return _manjusakaClient;
}
