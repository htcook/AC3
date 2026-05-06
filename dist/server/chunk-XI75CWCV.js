import {
  FIPS_SSH_ALGORITHMS,
  init_fips_ssh
} from "./chunk-SD56WPOS.js";

// server/lib/ssh-tunnel-manager.ts
init_fips_ssh();
import { Client as SshClient } from "ssh2";
import * as net from "net";
import * as fs from "fs";
import * as path from "path";
import { EventEmitter } from "events";
var DEFAULT_SSH_KEY_PATH = path.join(
  process.env.HOME || "/home/ubuntu",
  ".ssh",
  "msf_deploy_key"
);
var HEALTH_CHECK_INTERVAL = 3e4;
var KEEPALIVE_INTERVAL = 1e4;
var MAX_KEEPALIVE_MISSES = 3;
var DEFAULT_RECONNECT_MAX = 10;
var RECONNECT_BASE_DELAY = 1e3;
var RECONNECT_MAX_DELAY = 3e4;
var SshTunnel = class extends EventEmitter {
  constructor(config) {
    super();
    this.sshClient = null;
    this.tcpServer = null;
    this.state = "disconnected";
    this.localPort = null;
    this.connectedAt = null;
    this.reconnectAttempts = 0;
    this.bytesTransferred = 0;
    this.lastError = null;
    this.healthTimer = null;
    this.reconnectTimer = null;
    this.destroyed = false;
    this.config = {
      sshPort: 22,
      localPort: 0,
      maxReconnectAttempts: DEFAULT_RECONNECT_MAX,
      ...config
    };
  }
  async connect() {
    if (this.destroyed) throw new Error("Tunnel has been destroyed");
    if (this.state === "connected") return this.localPort;
    this.setState("connecting");
    try {
      const sshClient = await this.createSshConnection();
      this.sshClient = sshClient;
      const port = await this.startLocalServer(sshClient);
      this.localPort = port;
      this.connectedAt = /* @__PURE__ */ new Date();
      this.reconnectAttempts = 0;
      this.setState("connected");
      this.startHealthMonitoring();
      return port;
    } catch (err) {
      this.lastError = err.message;
      this.setState("error");
      throw err;
    }
  }
  async close() {
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
  getStatus() {
    return {
      tunnelId: this.config.tunnelId,
      state: this.state,
      localPort: this.localPort,
      remoteHost: this.config.remoteHost,
      remotePort: this.config.remotePort,
      connectedAt: this.connectedAt,
      reconnectAttempts: this.reconnectAttempts,
      bytesTransferred: this.bytesTransferred,
      lastError: this.lastError
    };
  }
  get isConnected() {
    return this.state === "connected";
  }
  get port() {
    return this.localPort;
  }
  async healthCheck() {
    if (!this.localPort || this.state !== "connected") {
      return { healthy: false, latencyMs: 0, error: "Tunnel not connected" };
    }
    const start = Date.now();
    return new Promise((resolve) => {
      const sock = net.createConnection(
        { host: "127.0.0.1", port: this.localPort, timeout: 5e3 },
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
          error: err.message
        });
      });
      sock.on("timeout", () => {
        sock.destroy();
        resolve({ healthy: false, latencyMs: 5e3, error: "TCP probe timeout" });
      });
    });
  }
  setState(state) {
    const prev = this.state;
    this.state = state;
    if (prev !== state) {
      this.emit(state, this.getStatus());
    }
  }
  async createSshConnection() {
    return new Promise((resolve, reject) => {
      const client = new SshClient();
      const connectConfig = {
        host: this.config.sshHost,
        port: this.config.sshPort || 22,
        username: this.config.sshUser,
        keepaliveInterval: KEEPALIVE_INTERVAL,
        keepaliveCountMax: MAX_KEEPALIVE_MISSES,
        readyTimeout: 3e4,
        // FIPS 140-3: Restrict to NIST-approved algorithms only
        algorithms: FIPS_SSH_ALGORITHMS
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
  async startLocalServer(sshClient) {
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
            stream.on("data", (chunk) => {
              this.bytesTransferred += chunk.length;
            });
            localSocket.on("data", (chunk) => {
              this.bytesTransferred += chunk.length;
            });
          }
        );
      });
      server.on("error", reject);
      server.listen(this.config.localPort || 0, "127.0.0.1", () => {
        const addr = server.address();
        this.tcpServer = server;
        resolve(addr.port);
      });
    });
  }
  handleDisconnect() {
    this.stopHealthMonitoring();
    if (this.tcpServer) {
      this.tcpServer.close();
      this.tcpServer = null;
    }
    this.sshClient = null;
    const maxAttempts = this.config.maxReconnectAttempts ?? DEFAULT_RECONNECT_MAX;
    if (this.reconnectAttempts < maxAttempts) {
      this.scheduleReconnect();
    } else {
      this.lastError = `Max reconnect attempts (${maxAttempts}) reached`;
      this.setState("error");
    }
  }
  scheduleReconnect() {
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
      }
    }, delay);
  }
  startHealthMonitoring() {
    this.stopHealthMonitoring();
    this.healthTimer = setInterval(async () => {
      const result = await this.healthCheck();
      this.emit("health", result);
      if (!result.healthy && this.state === "connected") {
        this.handleDisconnect();
      }
    }, HEALTH_CHECK_INTERVAL);
  }
  stopHealthMonitoring() {
    if (this.healthTimer) {
      clearInterval(this.healthTimer);
      this.healthTimer = null;
    }
  }
};
var TunnelManager = class {
  constructor() {
    this.tunnels = /* @__PURE__ */ new Map();
  }
  async createTunnel(config) {
    if (this.tunnels.has(config.tunnelId)) {
      await this.closeTunnel(config.tunnelId);
    }
    const tunnel = new SshTunnel(config);
    this.tunnels.set(config.tunnelId, tunnel);
    const port = await tunnel.connect();
    return port;
  }
  async closeTunnel(tunnelId) {
    const tunnel = this.tunnels.get(tunnelId);
    if (tunnel) {
      await tunnel.close();
      this.tunnels.delete(tunnelId);
    }
  }
  getTunnelStatus(tunnelId) {
    const tunnel = this.tunnels.get(tunnelId);
    return tunnel ? tunnel.getStatus() : null;
  }
  getAllTunnelStatuses() {
    return Array.from(this.tunnels.values()).map((t) => t.getStatus());
  }
  getLocalPort(tunnelId) {
    const tunnel = this.tunnels.get(tunnelId);
    return tunnel?.port ?? null;
  }
  isConnected(tunnelId) {
    const tunnel = this.tunnels.get(tunnelId);
    return tunnel?.isConnected ?? false;
  }
  async healthCheck(tunnelId) {
    const tunnel = this.tunnels.get(tunnelId);
    if (!tunnel) return { healthy: false, latencyMs: 0, error: "Tunnel not found" };
    return tunnel.healthCheck();
  }
  async healthCheckAll() {
    const results = {};
    const entries = Array.from(this.tunnels.entries());
    for (let i = 0; i < entries.length; i++) {
      const [id, tunnel] = entries[i];
      results[id] = await tunnel.healthCheck();
    }
    return results;
  }
  async closeAll() {
    const promises = Array.from(this.tunnels.keys()).map(
      (id) => this.closeTunnel(id)
    );
    await Promise.all(promises);
  }
  get activeTunnelCount() {
    return Array.from(this.tunnels.values()).filter((t) => t.isConnected).length;
  }
};
var tunnelManager = new TunnelManager();
async function createTunnelForServer(server) {
  if (!server.ipAddress) throw new Error("Server has no IP address");
  const tunnelId = `msf-tunnel-${server.id}`;
  const localPort = await tunnelManager.createTunnel({
    tunnelId,
    sshHost: server.ipAddress,
    sshUser: server.sshUser || "root",
    sshKeyPath: server.sshKeyPath || DEFAULT_SSH_KEY_PATH,
    remoteHost: "127.0.0.1",
    remotePort: server.rpcPort || 55553
  });
  return { tunnelId, localPort };
}
function hasDefaultSshKey() {
  return fs.existsSync(DEFAULT_SSH_KEY_PATH);
}
function getDefaultSshPublicKey() {
  const pubPath = DEFAULT_SSH_KEY_PATH + ".pub";
  if (!fs.existsSync(pubPath)) return null;
  return fs.readFileSync(pubPath, "utf8").trim();
}

export {
  DEFAULT_SSH_KEY_PATH,
  tunnelManager,
  createTunnelForServer,
  hasDefaultSshKey,
  getDefaultSshPublicKey
};
