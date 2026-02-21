/**
 * Session Alerter — Background service that polls all online MSF servers
 * for new sessions and triggers notifyOwner + in-app notifications.
 */
import { notifyOwner } from "../_core/notification";
import { MsfClient } from "./msf-client";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface SessionAlert {
  serverId: number;
  serverName: string;
  sessionId: string;
  sessionType: string;
  targetHost: string;
  platform: string;
  arch: string;
  username: string;
  viaExploit: string;
  viaPayload: string;
  tunnelPeer: string;
  detectedAt: number; // unix ms
}

export interface AlerterConfig {
  pollIntervalMs: number;
  enabled: boolean;
  notifyOwnerEnabled: boolean;
}

type ServerConfig = {
  id: number;
  name: string;
  host: string;
  port: number;
  rpcUser: string;
  rpcPass: string;
  rpcSsl: boolean;
  sshTunnelEnabled?: boolean;
  sshHost?: string;
  sshPort?: number;
  sshUser?: string;
  sshKeyPath?: string;
};

// ─── Session Alerter Singleton ──────────────────────────────────────────────

class SessionAlerter {
  private knownSessions = new Map<string, Set<string>>(); // serverId -> Set<sessionId>
  private alerts: SessionAlert[] = [];
  private maxAlerts = 500;
  private timer: ReturnType<typeof setInterval> | null = null;
  private config: AlerterConfig = {
    pollIntervalMs: 30_000, // 30 seconds
    enabled: false,
    notifyOwnerEnabled: true,
  };
  private serverProvider: (() => Promise<ServerConfig[]>) | null = null;
  private onAlertCallbacks: ((alert: SessionAlert) => void)[] = [];

  /** Register a function that provides the list of online MSF servers */
  setServerProvider(fn: () => Promise<ServerConfig[]>) {
    this.serverProvider = fn;
  }

  /** Register a callback for new alerts (e.g., push to notification bell) */
  onAlert(cb: (alert: SessionAlert) => void) {
    this.onAlertCallbacks.push(cb);
  }

  /** Start the polling loop */
  start(config?: Partial<AlerterConfig>) {
    if (config) {
      this.config = { ...this.config, ...config };
    }
    this.config.enabled = true;

    if (this.timer) {
      clearInterval(this.timer);
    }

    console.log(`[SessionAlerter] Started (poll every ${this.config.pollIntervalMs / 1000}s)`);

    // Run immediately, then on interval
    this.poll().catch(err => console.error("[SessionAlerter] Initial poll error:", err));
    this.timer = setInterval(() => {
      this.poll().catch(err => console.error("[SessionAlerter] Poll error:", err));
    }, this.config.pollIntervalMs);
  }

  /** Stop the polling loop */
  stop() {
    this.config.enabled = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    console.log("[SessionAlerter] Stopped");
  }

  /** Get current config */
  getConfig(): AlerterConfig {
    return { ...this.config };
  }

  /** Update config */
  updateConfig(config: Partial<AlerterConfig>) {
    const wasEnabled = this.config.enabled;
    this.config = { ...this.config, ...config };

    // Restart if interval changed while running
    if (this.config.enabled && wasEnabled && this.timer) {
      this.stop();
      this.start();
    } else if (this.config.enabled && !wasEnabled) {
      this.start();
    } else if (!this.config.enabled && wasEnabled) {
      this.stop();
    }
  }

  /** Get all alerts (most recent first) */
  getAlerts(limit = 50): SessionAlert[] {
    return this.alerts.slice(-limit).reverse();
  }

  /** Get unread count (alerts in last hour) */
  getUnreadCount(): number {
    const oneHourAgo = Date.now() - 3600_000;
    return this.alerts.filter(a => a.detectedAt > oneHourAgo).length;
  }

  /** Clear all alerts */
  clearAlerts() {
    this.alerts = [];
  }

  /** Dismiss a specific alert */
  dismissAlert(serverId: number, sessionId: string) {
    this.alerts = this.alerts.filter(
      a => !(a.serverId === serverId && a.sessionId === sessionId)
    );
  }

  /** Mark a session as known (pre-seed on startup) */
  markKnown(serverId: number, sessionId: string) {
    const key = String(serverId);
    if (!this.knownSessions.has(key)) {
      this.knownSessions.set(key, new Set());
    }
    this.knownSessions.get(key)!.add(sessionId);
  }

  /** The main poll cycle */
  private async poll() {
    if (!this.serverProvider) {
      return;
    }

    let servers: ServerConfig[];
    try {
      servers = await this.serverProvider();
    } catch (err) {
      console.error("[SessionAlerter] Failed to get servers:", err);
      return;
    }

    for (const server of servers) {
      try {
        await this.checkServer(server);
      } catch (err: any) {
        // Don't log connection failures for every poll — too noisy
        if (!err.message?.includes("ECONNREFUSED")) {
          console.warn(`[SessionAlerter] Error checking ${server.name}:`, err.message);
        }
      }
    }
  }

  private async checkServer(server: ServerConfig) {
    const client = await MsfClient.fromServerWithTunnel({
      id: server.id,
      ipAddress: server.host,
      rpcPort: server.port,
      rpcUser: server.rpcUser,
      rpcPass: server.rpcPass,
      rpcSsl: server.rpcSsl,
      sshTunnelEnabled: server.sshTunnelEnabled ?? false,
      sshHost: server.sshHost ?? server.host,
      sshPort: server.sshPort ?? 22,
      sshUser: server.sshUser ?? "root",
      sshKeyPath: server.sshKeyPath ?? "",
    } as any);

    if (!client) return;

    const sessions = await client.listSessions();
    const serverKey = String(server.id);

    if (!this.knownSessions.has(serverKey)) {
      // First time seeing this server — seed all current sessions as known
      const known = new Set<string>();
      for (const sid of Object.keys(sessions)) {
        known.add(sid);
      }
      this.knownSessions.set(serverKey, known);
      console.log(`[SessionAlerter] Seeded ${known.size} existing sessions for ${server.name}`);
      return;
    }

    const known = this.knownSessions.get(serverKey)!;

    for (const [sessionId, session] of Object.entries(sessions)) {
      if (!known.has(sessionId)) {
        // New session detected!
        known.add(sessionId);

        const alert: SessionAlert = {
          serverId: server.id,
          serverName: server.name,
          sessionId,
          sessionType: (session as any).type || "unknown",
          targetHost: (session as any).target_host || (session as any).session_host || "",
          platform: (session as any).platform || "",
          arch: (session as any).arch || "",
          username: (session as any).username || "",
          viaExploit: (session as any).via_exploit || "",
          viaPayload: (session as any).via_payload || "",
          tunnelPeer: (session as any).tunnel_peer || "",
          detectedAt: Date.now(),
        };

        this.alerts.push(alert);
        if (this.alerts.length > this.maxAlerts) {
          this.alerts = this.alerts.slice(-this.maxAlerts);
        }

        console.log(
          `[SessionAlerter] 🔔 NEW SESSION on ${server.name}: ` +
          `${alert.sessionType} #${sessionId} → ${alert.targetHost} (${alert.platform}/${alert.arch}) via ${alert.viaExploit}`
        );

        // Fire callbacks
        for (const cb of this.onAlertCallbacks) {
          try { cb(alert); } catch {}
        }

        // Send push notification
        if (this.config.notifyOwnerEnabled) {
          this.sendNotification(alert).catch(err =>
            console.warn("[SessionAlerter] Notification failed:", err.message)
          );
        }
      }
    }

    // Clean up sessions that no longer exist
    for (const sid of Array.from(known)) {
      if (!sessions[sid]) {
        known.delete(sid);
      }
    }
  }

  private async sendNotification(alert: SessionAlert) {
    const typeEmoji = alert.sessionType === "meterpreter" ? "⚡" : "🐚";
    const title = `${typeEmoji} New ${alert.sessionType} session on ${alert.serverName}`;
    const content = [
      `**Session #${alert.sessionId}** established`,
      `**Target:** ${alert.targetHost || "unknown"}`,
      `**Platform:** ${alert.platform || "unknown"} / ${alert.arch || "unknown"}`,
      `**User:** ${alert.username || "unknown"}`,
      `**Exploit:** ${alert.viaExploit || "unknown"}`,
      `**Payload:** ${alert.viaPayload || "unknown"}`,
      `**Peer:** ${alert.tunnelPeer || "unknown"}`,
      `**Time:** ${new Date(alert.detectedAt).toISOString()}`,
    ].join("\n");

    await notifyOwner({ title, content });
  }
}

// Export singleton
export const sessionAlerter = new SessionAlerter();
