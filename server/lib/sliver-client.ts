/**
 * Sliver C2 API Client
 *
 * Connects to a Sliver C2 server via its gRPC-over-HTTP API.
 * Sliver exposes a multiplayer operator API that uses mTLS for auth.
 * Since gRPC from Node.js requires protobuf compilation, we use the
 * Sliver REST API wrapper (available when --rest-api flag is used)
 * or fall back to SSH + CLI execution for servers without REST.
 *
 * Connection modes:
 * 1. REST API (preferred): Direct HTTPS calls to Sliver's REST endpoint
 * 2. SSH + CLI: Execute sliver-client commands over SSH tunnel
 * 3. Operator Config: Parse .cfg file for mTLS credentials
 */
import { ENV } from "../_core/env";
import { getFIPSHttpsAgent } from "./fips-tls";

// ─── Types ─────────────────────────────────────────────────────────────────

export interface SliverImplant {
  id: string;
  name: string;
  os: string;
  arch: string;
  transport: string;
  remoteAddress: string;
  hostname: string;
  username: string;
  uid: string;
  gid: string;
  pid: number;
  filename: string;
  activeC2: string;
  reconnectInterval: number;
  proxyUrl: string;
  lastCheckin: number;
  isDead: boolean;
  burntAt?: number;
}

export interface SliverSession {
  id: string;
  name: string;
  remoteAddress: string;
  hostname: string;
  username: string;
  os: string;
  arch: string;
  transport: string;
  pid: number;
  filename: string;
  activeC2: string;
  lastCheckin: number;
  isDead: boolean;
}

export interface SliverBeacon {
  id: string;
  name: string;
  hostname: string;
  username: string;
  os: string;
  arch: string;
  transport: string;
  remoteAddress: string;
  pid: number;
  filename: string;
  activeC2: string;
  lastCheckin: number;
  interval: number;
  jitter: number;
  isDead: boolean;
  nextCheckin: number;
  tasksPending: number;
}

export interface SliverListener {
  id: string;
  type: string; // mtls, https, dns, wg
  bindAddress: string;
  port: number;
  domains?: string[];
  isActive: boolean;
}

export interface SliverJob {
  id: number;
  name: string;
  description: string;
  protocol: string;
  port: number;
}

export interface SliverOperatorConfig {
  operator: string;
  lhost: string;
  lport: number;
  token: string;
  caCertificate: string;
  certificate: string;
  privateKey: string;
}

// ─── Client ────────────────────────────────────────────────────────────────

export class SliverClient {
  private baseUrl: string;
  private token: string;
  private operatorConfig: SliverOperatorConfig | null = null;
  private connected: boolean = false;

  constructor(baseUrl?: string, token?: string) {
    this.baseUrl = (baseUrl || ENV.SLIVER_SERVER_URL).replace(/\/$/, "");
    this.token = token || ENV.SLIVER_OPERATOR_TOKEN;

    // Parse operator config if provided
    if (ENV.SLIVER_OPERATOR_CONFIG) {
      try {
        const decoded = Buffer.from(ENV.SLIVER_OPERATOR_CONFIG, "base64").toString("utf-8");
        this.operatorConfig = JSON.parse(decoded);
        if (this.operatorConfig && !this.baseUrl) {
          this.baseUrl = `https://${this.operatorConfig.lhost}:${this.operatorConfig.lport}`;
        }
        if (this.operatorConfig && !this.token) {
          this.token = this.operatorConfig.token;
        }
      } catch {
        console.warn("[SliverClient] Failed to parse operator config");
      }
    }
  }

  get isConfigured(): boolean {
    return !!(this.baseUrl && this.token);
  }

  // ─── HTTP Helper ───────────────────────────────────────────────────────

  private async request<T = any>(
    method: string,
    path: string,
    body?: any,
    timeoutMs = 10000
  ): Promise<T> {
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

    if (body) {
      options.body = JSON.stringify(body);
    }

    // Use FIPS agent for HTTPS
    if (url.startsWith("https://")) {
      (options as any).agent = getFIPSHttpsAgent();
    }

    const response = await fetch(url, options);

    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`Sliver API ${method} ${path} failed: ${response.status} ${text}`);
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
    if (!this.isConfigured) {
      return { status: "unconfigured" };
    }

    const start = Date.now();
    try {
      const info = await this.request<{ version?: string }>("GET", "/version", undefined, 5000);
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

  // ─── Sessions ──────────────────────────────────────────────────────────

  async listSessions(): Promise<SliverSession[]> {
    const data = await this.request<{ sessions?: SliverSession[] }>("GET", "/sessions");
    return data?.sessions || [];
  }

  async killSession(sessionId: string): Promise<void> {
    await this.request("DELETE", `/sessions/${sessionId}`);
  }

  // ─── Beacons ───────────────────────────────────────────────────────────

  async listBeacons(): Promise<SliverBeacon[]> {
    const data = await this.request<{ beacons?: SliverBeacon[] }>("GET", "/beacons");
    return data?.beacons || [];
  }

  async getBeaconTasks(beaconId: string): Promise<any[]> {
    const data = await this.request<{ tasks?: any[] }>("GET", `/beacons/${beaconId}/tasks`);
    return data?.tasks || [];
  }

  // ─── Implants (Builds) ────────────────────────────────────────────────

  async listImplants(): Promise<SliverImplant[]> {
    const data = await this.request<{ implants?: SliverImplant[] }>("GET", "/implants");
    return data?.implants || [];
  }

  async generateImplant(config: {
    name: string;
    os: string;
    arch: string;
    transport: string;
    format: string;
    c2Urls: string[];
    obfuscation?: boolean;
    evasion?: {
      canaryDomains?: string[];
      limitDatetime?: string;
      limitHostname?: string;
      limitUsername?: string;
    };
  }): Promise<{ id: string; name: string; filepath: string }> {
    return this.request("POST", "/implants/generate", {
      config: {
        IsBeacon: config.transport === "https" || config.transport === "dns",
        GOOS: config.os,
        GOARCH: config.arch,
        Name: config.name,
        Format: config.format === "exe" ? 1 : config.format === "shared" ? 2 : config.format === "shellcode" ? 3 : 4,
        ObfuscateSymbols: config.obfuscation ?? false,
        C2: config.c2Urls.map((url) => ({
          Priority: 0,
          URL: url,
        })),
        CanaryDomains: config.evasion?.canaryDomains || [],
        LimitDatetime: config.evasion?.limitDatetime || "",
        LimitHostname: config.evasion?.limitHostname || "",
        LimitUsername: config.evasion?.limitUsername || "",
      },
    }, 120000); // implant generation can take a while
  }

  // ─── Jobs (Listeners) ─────────────────────────────────────────────────

  async listJobs(): Promise<SliverJob[]> {
    const data = await this.request<{ active?: SliverJob[] }>("GET", "/jobs");
    return data?.active || [];
  }

  async startMTLSListener(host: string, port: number): Promise<SliverJob> {
    return this.request("POST", "/jobs/mtls", { host, port });
  }

  async startHTTPSListener(domain: string, host: string, port: number): Promise<SliverJob> {
    return this.request("POST", "/jobs/https", { domain, host, port });
  }

  async startDNSListener(domains: string[], host: string, port: number): Promise<SliverJob> {
    return this.request("POST", "/jobs/dns", { domains, host, port });
  }

  async startWGListener(host: string, port: number): Promise<SliverJob> {
    return this.request("POST", "/jobs/wg", { host, port });
  }

  async killJob(jobId: number): Promise<void> {
    await this.request("DELETE", `/jobs/${jobId}`);
  }

  // ─── Task Execution ────────────────────────────────────────────────────

  async executeCommand(
    sessionId: string,
    command: string,
    args: string[] = []
  ): Promise<{ stdout: string; stderr: string; status: number }> {
    return this.request("POST", `/sessions/${sessionId}/exec`, {
      path: command,
      args,
      output: true,
    }, 30000);
  }

  async executeShellcode(
    sessionId: string,
    shellcode: Buffer,
    pid?: number
  ): Promise<{ taskId: string }> {
    return this.request("POST", `/sessions/${sessionId}/shellcode`, {
      data: shellcode.toString("base64"),
      pid,
      rwxPages: false,
    });
  }

  // ─── Operators ─────────────────────────────────────────────────────────

  async listOperators(): Promise<Array<{ name: string; online: boolean }>> {
    const data = await this.request<{ operators?: Array<{ name: string; online: boolean }> }>("GET", "/operators");
    return data?.operators || [];
  }

  // ─── Server Info ───────────────────────────────────────────────────────

  async getVersion(): Promise<{ major: number; minor: number; patch: number; commit: string }> {
    return this.request("GET", "/version");
  }

  // ─── Websites (for staging) ────────────────────────────────────────────

  async listWebsites(): Promise<any[]> {
    const data = await this.request<{ websites?: any[] }>("GET", "/websites");
    return data?.websites || [];
  }
}

// ─── Singleton ─────────────────────────────────────────────────────────────

let _sliverClient: SliverClient | null = null;

export function getSliverClient(): SliverClient {
  if (!_sliverClient) {
    _sliverClient = new SliverClient();
  }
  return _sliverClient;
}
