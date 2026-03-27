/**
 * ScanForge Out-of-Band (OOB) Detection Server
 *
 * Provides a callback server for detecting blind vulnerabilities:
 *   - Blind SQL Injection (via DNS/HTTP exfiltration)
 *   - Blind SSRF (via HTTP callback)
 *   - Blind XXE (via HTTP/FTP callback)
 *   - Blind Command Injection (via DNS/HTTP callback)
 *   - Blind SSTI (via HTTP callback)
 *
 * Architecture:
 *   - Registers unique canary tokens per proof attempt
 *   - Listens for HTTP callbacks on a dedicated path
 *   - Correlates callbacks to findings via canary token
 *   - Supports DNS-based OOB via subdomain canary matching
 *
 * In production, this would run on a dedicated domain (e.g., oob.scanforge.io)
 * with wildcard DNS. For now, it integrates into the Express app.
 */

import { Router, type Request, type Response } from "express";
import { randomUUID } from "crypto";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface OOBToken {
  /** Unique canary token */
  token: string;
  /** Finding ID this token is associated with */
  findingId: string;
  /** Scan ID */
  scanId: string;
  /** Vulnerability class being tested */
  vulnClass: string;
  /** When the token was registered */
  registeredAt: number;
  /** When the callback was received (null if pending) */
  receivedAt: number | null;
  /** Callback metadata */
  callbackData?: OOBCallbackData;
  /** Token expiry (ms since epoch) */
  expiresAt: number;
}

export interface OOBCallbackData {
  /** Source IP of the callback */
  sourceIp: string;
  /** HTTP method used */
  method: string;
  /** Full URL path */
  path: string;
  /** Request headers */
  headers: Record<string, string>;
  /** Request body (if any) */
  body?: string;
  /** DNS query type (if DNS-based) */
  dnsQueryType?: string;
  /** Timestamp */
  timestamp: number;
}

export interface OOBInteraction {
  /** Token that was triggered */
  token: string;
  /** Type of interaction */
  type: "http" | "dns" | "ftp" | "smtp";
  /** Callback data */
  data: OOBCallbackData;
}

// ─── OOB Server ─────────────────────────────────────────────────────────────

export class OOBServer {
  private tokens: Map<string, OOBToken> = new Map();
  private interactions: OOBInteraction[] = [];
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  /** Default token TTL: 10 minutes */
  private readonly TOKEN_TTL_MS = 10 * 60 * 1000;
  /** Max interactions to keep in memory */
  private readonly MAX_INTERACTIONS = 1000;

  constructor() {
    // Start cleanup interval to expire old tokens
    this.cleanupInterval = setInterval(() => this.cleanup(), 60_000);
  }

  /**
   * Register a new OOB canary token for a proof attempt.
   */
  registerToken(findingId: string, scanId: string, vulnClass: string): OOBToken {
    const token: OOBToken = {
      token: `sf-${randomUUID().replace(/-/g, "").slice(0, 16)}`,
      findingId,
      scanId,
      vulnClass,
      registeredAt: Date.now(),
      receivedAt: null,
      expiresAt: Date.now() + this.TOKEN_TTL_MS,
    };

    this.tokens.set(token.token, token);
    console.log(`[OOB] Registered token ${token.token} for finding ${findingId} (${vulnClass})`);
    return token;
  }

  /**
   * Check if a token has received a callback.
   */
  checkToken(token: string): OOBToken | null {
    return this.tokens.get(token) || null;
  }

  /**
   * Wait for a token callback with timeout.
   */
  async waitForCallback(token: string, timeoutMs: number = 5000): Promise<OOBToken | null> {
    const deadline = Date.now() + timeoutMs;
    const pollInterval = 250;

    while (Date.now() < deadline) {
      const entry = this.tokens.get(token);
      if (entry?.receivedAt) return entry;
      await new Promise(r => setTimeout(r, pollInterval));
    }

    return this.tokens.get(token) || null;
  }

  /**
   * Record an incoming callback for a token.
   */
  recordCallback(token: string, data: OOBCallbackData): boolean {
    const entry = this.tokens.get(token);
    if (!entry) {
      console.debug(`[OOB] Callback for unknown token: ${token}`);
      return false;
    }

    if (entry.expiresAt < Date.now()) {
      console.debug(`[OOB] Callback for expired token: ${token}`);
      this.tokens.delete(token);
      return false;
    }

    entry.receivedAt = Date.now();
    entry.callbackData = data;

    const interaction: OOBInteraction = {
      token,
      type: "http",
      data,
    };
    this.interactions.push(interaction);

    // Trim interactions if too many
    if (this.interactions.length > this.MAX_INTERACTIONS) {
      this.interactions = this.interactions.slice(-this.MAX_INTERACTIONS);
    }

    console.log(`[OOB] Callback received for token ${token} (finding: ${entry.findingId}, vuln: ${entry.vulnClass}) from ${data.sourceIp}`);
    return true;
  }

  /**
   * Get all interactions for a scan.
   */
  getInteractionsForScan(scanId: string): OOBInteraction[] {
    const scanTokens = new Set(
      Array.from(this.tokens.values())
        .filter(t => t.scanId === scanId)
        .map(t => t.token)
    );
    return this.interactions.filter(i => scanTokens.has(i.token));
  }

  /**
   * Get all confirmed (callback-received) tokens for a scan.
   */
  getConfirmedTokens(scanId: string): OOBToken[] {
    return Array.from(this.tokens.values())
      .filter(t => t.scanId === scanId && t.receivedAt !== null);
  }

  /**
   * Get pending (no callback yet) tokens for a scan.
   */
  getPendingTokens(scanId: string): OOBToken[] {
    return Array.from(this.tokens.values())
      .filter(t => t.scanId === scanId && t.receivedAt === null && t.expiresAt > Date.now());
  }

  /**
   * Generate OOB payload URLs for different vulnerability classes.
   */
  generatePayloads(token: string, baseUrl: string): Record<string, string> {
    return {
      // HTTP callback URL
      http: `${baseUrl}/api/scanforge/oob/${token}`,
      // DNS subdomain callback
      dns: `${token}.oob.scanforge.local`,
      // XXE entity payload
      xxe_entity: `<!ENTITY xxe SYSTEM "${baseUrl}/api/scanforge/oob/${token}">`,
      // SSRF target URL
      ssrf: `${baseUrl}/api/scanforge/oob/${token}?type=ssrf`,
      // Blind SQLi via LOAD_FILE/INTO OUTFILE
      sqli_oob: `' UNION SELECT LOAD_FILE('${baseUrl}/api/scanforge/oob/${token}') -- `,
    };
  }

  /**
   * Cleanup expired tokens.
   */
  private cleanup(): void {
    const now = Date.now();
    let cleaned = 0;
    for (const [key, token] of this.tokens) {
      if (token.expiresAt < now && !token.receivedAt) {
        this.tokens.delete(key);
        cleaned++;
      }
    }
    if (cleaned > 0) {
      console.debug(`[OOB] Cleaned up ${cleaned} expired tokens`);
    }
  }

  /**
   * Get server statistics.
   */
  getStats(): { activeTokens: number; confirmedTokens: number; totalInteractions: number } {
    const now = Date.now();
    const active = Array.from(this.tokens.values()).filter(t => t.expiresAt > now);
    const confirmed = active.filter(t => t.receivedAt !== null);
    return {
      activeTokens: active.length,
      confirmedTokens: confirmed.length,
      totalInteractions: this.interactions.length,
    };
  }

  /**
   * Shutdown the OOB server.
   */
  shutdown(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.tokens.clear();
    this.interactions = [];
  }
}

// ─── Express Router ─────────────────────────────────────────────────────────

/**
 * Create the OOB callback Express router.
 * Mount at /api/scanforge/oob
 */
export function createOOBRouter(server: OOBServer): Router {
  const router = Router();

  // Catch-all callback endpoint: /api/scanforge/oob/:token
  router.all("/:token", (req: Request, res: Response) => {
    const { token } = req.params;

    const callbackData: OOBCallbackData = {
      sourceIp: req.ip || req.socket.remoteAddress || "unknown",
      method: req.method,
      path: req.originalUrl,
      headers: Object.fromEntries(
        Object.entries(req.headers)
          .filter(([, v]) => typeof v === "string")
          .map(([k, v]) => [k, v as string])
      ),
      body: typeof req.body === "string" ? req.body : JSON.stringify(req.body),
      timestamp: Date.now(),
    };

    const recorded = server.recordCallback(token, callbackData);

    if (recorded) {
      // Return a minimal response — don't reveal anything about the system
      res.status(200).send("");
    } else {
      res.status(404).send("");
    }
  });

  // Stats endpoint (protected, for internal use)
  router.get("/_stats", (_req: Request, res: Response) => {
    res.json(server.getStats());
  });

  return router;
}

// ─── Singleton ──────────────────────────────────────────────────────────────

let oobServer: OOBServer | null = null;

export function getOOBServer(): OOBServer {
  if (!oobServer) {
    oobServer = new OOBServer();
  }
  return oobServer;
}
