/**
 * SSH Tunnel Manager for Metasploit RPC Connectivity
 *
 * Establishes and maintains SSH tunnels to exploit servers, providing:
 * - Encrypted port forwarding (local → remote msfrpcd)
 * - Health monitoring with TCP probes every 30s
 * - Auto-reconnect with exponential backoff
 * - SSH keepalive to prevent idle timeouts
 * - Event system for tunnel state changes
 *
 * Architecture:
 *   Platform → SSH Tunnel (localhost:random → remote:55553) → msfrpcd
 *   No SSL needed — SSH provides the encryption layer
 */

import { Client as SshClient, type ConnectConfig } from "ssh2";
import * as net from "net";
import * as fs from "fs";
import * as path from "path";
import { EventEmitter } from "events";

// ─── Constants ────────────────────────────────────────────────────────────

export const DEFAULT_SSH_KEY_PATH = path.join(
  process.env.HOME || "/home/ubuntu",
  ".ssh",
  "msf_deploy_key"
);

const HEALTH_CHECK_INTERVAL = 30_000;
const KEEPALIVE_INTERVAL = 10_000;
const MAX_KEEPALIVE_MISSES = 3;
const DEFAULT_RECONNECT_MAX = 10;
const RECONNECT_BASE_DELAY = 1_000;
const RECONNECT_MAX_DELAY = 30_000;

// ─── Types ────────────────────────────────────────────────────────────────

export type TunnelState =
  | "connected"
  | "connecting"
  | "disconnected"
  | "reconnecting"
  | "error";

export interface TunnelConfig {
  tunnelId: string;
  sshHost: string;
  sshPort?: number;
  sshUser: string;
  sshKeyPath?: string;
  sshPassword?: string;
  remoteHost: string;
  remotePort: number;
  localPort?: number;
  maxReconnectAttempts?: number;
}

export interface TunnelStatus {
  tunnelId: string;
  state: TunnelState;
  localPort: number | null;
  remoteHost: string;
  remotePort: number;
  connectedAt: Date | null;
  reconnectAttempts: number;
  bytesTransferred: number;
  lastError: string | null;
}

export interface HealthCheckResult {
  healthy: boolean;
  latencyMs: number;
  error?: string;
}

// ─── SSH Tunnel Instance ──────────────────────────────────────────────────

class SshTunnel extends EventEmitter {
  private config: TunnelConfig;
  private sshClient: SshClient | null = null;
  private tcpServer: net.Server | null = null;
  private state: TunnelState = "disconnected";
  private localPort: number | null = null;
  private connectedAt: Date | null = null;
  private reconnectAttempts = 0;
  private bytesTransferred = 0;
  private lastError: string | null = null;
  private healthTimer: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private destroyed = false;

  constructor(config: TunnelConfig) {
    super();
    this.config = {
      sshPort: 22,
      localPort: 0,
      maxReconnectAttempts: DEFAULT_RECONNECT_MAX,
      ...config,
    };
  }

  async connect(): Promise<number> {
    if (this.destroyed) throw new Error("Tunnel has been destroyed");
    if (this.state === "connected") return this.localPort!;

    this.setState("connecting");

    try {
      const sshClient = await this.createSshConnection();
      this.sshClient = sshClient;

      const port = await this.startLocalServer(sshClient);
      this.localPort = port;
      this.connectedAt = new Date();
      this.reconnectAttempts = 0;
      this.setState("connected");
      this.startHealthMonitoring();

      return port;
    } catch (err: any) {
      this.lastError = err.message;
      this.setState("error");
      throw err;
    }
  }

  async close(): Promise<void> {
    this.destroyed = true;
    this.stopHealthMonitoring();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.tcpServer) {
      this.tcpServer.close();
      this.tcpServer = null;
    }
    if (this.sshClient) {
      this.sshClient.end();
      this.sshClient = null;
    }
    this.localPort = null;
    this.setState("disconnected");
  }

  getStatus(): TunnelStatus {
    return {
      tunnelId: this.config.tunnelId,
      state: this.state,
      localPort: this.localPort,
      remoteHost: this.config.remoteHost,
      remotePort: this.config.remotePort,
      connectedAt: this.connectedAt,
      reconnectAttempts: this.reconnectAttempts,
      bytesTransferred: this.bytesTransferred,
      lastError: this.lastError,
    };
  }

  get isConnected(): boolean {
    return this.state === "connected";
  }

  get port(): number | null {
    return this.localPort;
  }

  async healthCheck(): Promise<HealthCheckResult> {
    if (!this.localPort || this.state !== "connected") {
      return { healthy: false, latencyMs: 0, error: "Tunnel not connected" };
    }

    const start = Date.now();
    return new Promise((resolve) => {
      const sock = net.createConnection(
        { host: "127.0.0.1", port: this.localPort!, timeout: 5000 },
        () => {
          const latency = Date.now() - start;
          sock.destroy();
          resolve({ healthy: true, latencyMs: latency });
        }
      );
      sock.on("error", (err) => {
        resolve({
          healthy: false,
          latencyMs: Date.now() - start,
          error: err.message,
        });
      });
      sock.on("timeout", () => {
        sock.destroy();
        resolve({ healthy: false, latencyMs: 5000, error: "TCP probe timeout" });
      });
    });
  }

  private setState(state: TunnelState) {
    const prev = this.state;
    this.state = state;
    if (prev !== state) {
      this.emit(state, this.getStatus());
    }
  }

  private async createSshConnection(): Promise<SshClient> {
    return new Promise((resolve, reject) => {
      const client = new SshClient();
      const connectConfig: ConnectConfig = {
        host: this.config.sshHost,
        port: this.config.sshPort || 22,
        username: this.config.sshUser,
        keepaliveInterval: KEEPALIVE_INTERVAL,
        keepaliveCountMax: MAX_KEEPALIVE_MISSES,
        readyTimeout: 30000,
      };

      if (this.config.sshKeyPath && fs.existsSync(this.config.sshKeyPath)) {
        connectConfig.privateKey = fs.readFileSync(this.config.sshKeyPath);
      } else if (this.config.sshPassword) {
        connectConfig.password = this.config.sshPassword;
      } else if (fs.existsSync(DEFAULT_SSH_KEY_PATH)) {
        connectConfig.privateKey = fs.readFileSync(DEFAULT_SSH_KEY_PATH);
      } else {
        reject(new Error("No SSH key or password available"));
        return;
      }

      client.on("ready", () => resolve(client));
      client.on("error", (err) => reject(err));
      client.on("close", () => {
        if (!this.destroyed && this.state === "connected") {
          this.handleDisconnect();
        }
      });

      client.connect(connectConfig);
    });
  }

  private async startLocalServer(sshClient: SshClient): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = net.createServer((localSocket) => {
        sshClient.forwardOut(
          "127.0.0.1",
          localSocket.localPort || 0,
          this.config.remoteHost,
          this.config.remotePort,
          (err, stream) => {
            if (err) {
              localSocket.destroy();
              return;
            }
            localSocket.pipe(stream).pipe(localSocket);
            stream.on("data", (chunk: Buffer) => {
              this.bytesTransferred += chunk.length;
            });
            localSocket.on("data", (chunk: Buffer) => {
              this.bytesTransferred += chunk.length;
            });
          }
        );
      });

      server.on("error", reject);
      server.listen(this.config.localPort || 0, "127.0.0.1", () => {
        const addr = server.address() as net.AddressInfo;
        this.tcpServer = server;
        resolve(addr.port);
      });
    });
  }

  private handleDisconnect() {
    this.stopHealthMonitoring();
    if (this.tcpServer) {
      this.tcpServer.close();
      this.tcpServer = null;
    }
    this.sshClient = null;

    const maxAttempts =
      this.config.maxReconnectAttempts ?? DEFAULT_RECONNECT_MAX;
    if (this.reconnectAttempts < maxAttempts) {
      this.scheduleReconnect();
    } else {
      this.lastError = `Max reconnect attempts (${maxAttempts}) reached`;
      this.setState("error");
    }
  }

  private scheduleReconnect() {
    this.setState("reconnecting");
    const delay = Math.min(
      RECONNECT_BASE_DELAY * Math.pow(2, this.reconnectAttempts),
      RECONNECT_MAX_DELAY
    );
    this.reconnectAttempts++;

    this.reconnectTimer = setTimeout(async () => {
      try {
        await this.connect();
      } catch {
        // connect() handles error state
      }
    }, delay);
  }

  private startHealthMonitoring() {
    this.stopHealthMonitoring();
    this.healthTimer = setInterval(async () => {
      const result = await this.healthCheck();
      this.emit("health", result);
      if (!result.healthy && this.state === "connected") {
        this.handleDisconnect();
      }
    }, HEALTH_CHECK_INTERVAL);
  }

  private stopHealthMonitoring() {
    if (this.healthTimer) {
      clearInterval(this.healthTimer);
      this.healthTimer = null;
    }
  }
}

// ─── Tunnel Manager (Singleton) ───────────────────────────────────────────

class TunnelManager {
  private tunnels = new Map<string, SshTunnel>();

  async createTunnel(config: TunnelConfig): Promise<number> {
    if (this.tunnels.has(config.tunnelId)) {
      await this.closeTunnel(config.tunnelId);
    }

    const tunnel = new SshTunnel(config);
    this.tunnels.set(config.tunnelId, tunnel);

    const port = await tunnel.connect();
    return port;
  }

  async closeTunnel(tunnelId: string): Promise<void> {
    const tunnel = this.tunnels.get(tunnelId);
    if (tunnel) {
      await tunnel.close();
      this.tunnels.delete(tunnelId);
    }
  }

  getTunnelStatus(tunnelId: string): TunnelStatus | null {
    const tunnel = this.tunnels.get(tunnelId);
    return tunnel ? tunnel.getStatus() : null;
  }

  getAllTunnelStatuses(): TunnelStatus[] {
    return Array.from(this.tunnels.values()).map((t) => t.getStatus());
  }

  getLocalPort(tunnelId: string): number | null {
    const tunnel = this.tunnels.get(tunnelId);
    return tunnel?.port ?? null;
  }

  isConnected(tunnelId: string): boolean {
    const tunnel = this.tunnels.get(tunnelId);
    return tunnel?.isConnected ?? false;
  }

  async healthCheck(tunnelId: string): Promise<HealthCheckResult> {
    const tunnel = this.tunnels.get(tunnelId);
    if (!tunnel) return { healthy: false, latencyMs: 0, error: "Tunnel not found" };
    return tunnel.healthCheck();
  }

  async healthCheckAll(): Promise<Record<string, HealthCheckResult>> {
    const results: Record<string, HealthCheckResult> = {};
    const entries = Array.from(this.tunnels.entries());
    for (let i = 0; i < entries.length; i++) {
      const [id, tunnel] = entries[i];
      results[id] = await tunnel.healthCheck();
    }
    return results;
  }

  async closeAll(): Promise<void> {
    const promises = Array.from(this.tunnels.keys()).map((id) =>
      this.closeTunnel(id)
    );
    await Promise.all(promises);
  }

  get activeTunnelCount(): number {
    return Array.from(this.tunnels.values()).filter((t) => t.isConnected).length;
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────

export const tunnelManager = new TunnelManager();

export async function createTunnelForServer(server: {
  id: number;
  ipAddress: string | null;
  rpcPort?: number | null;
  sshUser?: string | null;
  sshKeyPath?: string | null;
}): Promise<{ tunnelId: string; localPort: number }> {
  if (!server.ipAddress) throw new Error("Server has no IP address");

  const tunnelId = `msf-tunnel-${server.id}`;
  const localPort = await tunnelManager.createTunnel({
    tunnelId,
    sshHost: server.ipAddress,
    sshUser: server.sshUser || "root",
    sshKeyPath: server.sshKeyPath || DEFAULT_SSH_KEY_PATH,
    remoteHost: "127.0.0.1",
    remotePort: server.rpcPort || 55553,
  });

  return { tunnelId, localPort };
}

export function hasDefaultSshKey(): boolean {
  return fs.existsSync(DEFAULT_SSH_KEY_PATH);
}

export function getDefaultSshPublicKey(): string | null {
  const pubPath = DEFAULT_SSH_KEY_PATH + ".pub";
  if (!fs.existsSync(pubPath)) return null;
  return fs.readFileSync(pubPath, "utf8").trim();
}
