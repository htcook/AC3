/**
 * C2 Health Check Service
 *
 * Performs real HTTP health probes against configured C2 servers:
 *   - CALDERA: GET /api/v2/health (expects 200 + JSON body)
 *   - Sliver:  GET /health or POST /rpc (gRPC-web style health probe)
 *   - Metasploit: POST /api/v1/auth/login (MSFRPC token validation)
 *
 * Each probe measures latency, extracts version info when available,
 * and returns a structured HealthCheckResult.
 */

import { getFIPSCrypto, type EncryptedPayload } from "./fips-crypto";

// ─── Types ──────────────────────────────────────────────────────────────

export interface HealthCheckResult {
  status: "connected" | "disconnected" | "error";
  latencyMs: number;
  message: string;
  version?: string;
  capabilities?: string[];
  serverTime?: string;
}

export interface C2ServerRecord {
  id: string;
  name: string;
  type: "caldera" | "sliver" | "metasploit";
  baseUrl: string;
  authConfigEncrypted: string;
}

// ─── Auth Config Decryption ─────────────────────────────────────────────

function decryptAuthConfig(serverId: string, encrypted: string): Record<string, unknown> {
  try {
    const fips = getFIPSCrypto();
    const payload: EncryptedPayload = JSON.parse(encrypted);
    const decrypted = fips.decrypt(payload, `c2-auth-${serverId}`);
    return JSON.parse(decrypted.toString("utf-8"));
  } catch {
    return {};
  }
}

// ─── CALDERA Health Check ───────────────────────────────────────────────

async function checkCaldera(baseUrl: string, authConfig: Record<string, unknown>): Promise<HealthCheckResult> {
  const startTime = Date.now();
  const apiKey = (authConfig.apiKey as string) || "";

  try {
    // Primary: /api/v2/health
    const healthUrl = new URL("/api/v2/health", baseUrl).toString();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    const response = await fetch(healthUrl, {
      method: "GET",
      headers: {
        "KEY": apiKey,
        "Accept": "application/json",
      },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const latencyMs = Date.now() - startTime;

    if (response.ok) {
      let version: string | undefined;
      let capabilities: string[] | undefined;
      let serverTime: string | undefined;

      try {
        const body = await response.json();
        version = body.version || body.caldera_version;
        if (body.plugins && Array.isArray(body.plugins)) {
          capabilities = body.plugins.map((p: any) => p.name || p);
        }
        serverTime = body.server_time || body.timestamp;
      } catch {
        // Body parse failure is non-fatal
      }

      return {
        status: "connected",
        latencyMs,
        message: `CALDERA server responding at ${new URL(baseUrl).hostname} (${latencyMs}ms)`,
        version,
        capabilities,
        serverTime,
      };
    }

    // 401/403 means server is reachable but auth failed
    if (response.status === 401 || response.status === 403) {
      return {
        status: "error",
        latencyMs,
        message: `CALDERA authentication failed (HTTP ${response.status}). Check API key.`,
      };
    }

    return {
      status: "error",
      latencyMs,
      message: `CALDERA returned HTTP ${response.status}`,
    };
  } catch (e: any) {
    const latencyMs = Date.now() - startTime;
    if (e.name === "AbortError") {
      return { status: "disconnected", latencyMs, message: "CALDERA health check timed out (10s)" };
    }
    return {
      status: "disconnected",
      latencyMs,
      message: `Cannot reach CALDERA server: ${e.code || e.message}`,
    };
  }
}

// ─── Sliver Health Check ────────────────────────────────────────────────

async function checkSliver(baseUrl: string, authConfig: Record<string, unknown>): Promise<HealthCheckResult> {
  const startTime = Date.now();
  const token = (authConfig.token as string) || (authConfig.apiKey as string) || "";

  try {
    // Sliver multiplayer uses gRPC-web; try a basic HTTP probe first
    const healthUrl = new URL("/health", baseUrl).toString();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    const response = await fetch(healthUrl, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Accept": "application/json",
      },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const latencyMs = Date.now() - startTime;

    if (response.ok) {
      let version: string | undefined;
      try {
        const body = await response.json();
        version = body.version || body.server_version;
      } catch {}

      return {
        status: "connected",
        latencyMs,
        message: `Sliver server responding at ${new URL(baseUrl).hostname} (${latencyMs}ms)`,
        version,
      };
    }

    // Sliver may not have a /health endpoint; try root
    if (response.status === 404) {
      const rootUrl = new URL("/", baseUrl).toString();
      const rootController = new AbortController();
      const rootTimeout = setTimeout(() => rootController.abort(), 5_000);

      try {
        const rootResp = await fetch(rootUrl, {
          method: "GET",
          signal: rootController.signal,
        });
        clearTimeout(rootTimeout);
        const rootLatency = Date.now() - startTime;

        // Any response means the server is reachable
        return {
          status: "connected",
          latencyMs: rootLatency,
          message: `Sliver server reachable at ${new URL(baseUrl).hostname} (no health endpoint; root responded ${rootResp.status})`,
        };
      } catch {
        clearTimeout(rootTimeout);
      }
    }

    if (response.status === 401 || response.status === 403) {
      return {
        status: "error",
        latencyMs,
        message: `Sliver authentication failed (HTTP ${response.status}). Check operator token.`,
      };
    }

    return {
      status: "error",
      latencyMs,
      message: `Sliver returned HTTP ${response.status}`,
    };
  } catch (e: any) {
    const latencyMs = Date.now() - startTime;
    if (e.name === "AbortError") {
      return { status: "disconnected", latencyMs, message: "Sliver health check timed out (10s)" };
    }
    return {
      status: "disconnected",
      latencyMs,
      message: `Cannot reach Sliver server: ${e.code || e.message}`,
    };
  }
}

// ─── Metasploit Health Check ────────────────────────────────────────────

async function checkMetasploit(baseUrl: string, authConfig: Record<string, unknown>): Promise<HealthCheckResult> {
  const startTime = Date.now();
  const apiKey = (authConfig.apiKey as string) || (authConfig.token as string) || "";
  const username = (authConfig.username as string) || "";
  const password = (authConfig.password as string) || "";

  try {
    // MSFRPC: POST /api/v1/auth/login or try /api/v1/msf/version
    const versionUrl = new URL("/api/v1/msf/version", baseUrl).toString();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    const headers: Record<string, string> = {
      "Accept": "application/json",
      "Content-Type": "application/json",
    };

    if (apiKey) {
      headers["Authorization"] = `Bearer ${apiKey}`;
    }

    const response = await fetch(versionUrl, {
      method: "GET",
      headers,
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const latencyMs = Date.now() - startTime;

    if (response.ok) {
      let version: string | undefined;
      let capabilities: string[] | undefined;
      try {
        const body = await response.json();
        version = body.version || body.metasploit_version;
        if (body.modules) {
          capabilities = Object.keys(body.modules);
        }
      } catch {}

      return {
        status: "connected",
        latencyMs,
        message: `Metasploit RPC responding at ${new URL(baseUrl).hostname} (${latencyMs}ms)`,
        version,
        capabilities,
      };
    }

    // Try auth endpoint as fallback
    if (response.status === 401 && (username || password)) {
      const authUrl = new URL("/api/v1/auth/login", baseUrl).toString();
      const authController = new AbortController();
      const authTimeout = setTimeout(() => authController.abort(), 5_000);

      try {
        const authResp = await fetch(authUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
          signal: authController.signal,
        });
        clearTimeout(authTimeout);
        const authLatency = Date.now() - startTime;

        if (authResp.ok) {
          return {
            status: "connected",
            latencyMs: authLatency,
            message: `Metasploit RPC authenticated at ${new URL(baseUrl).hostname} (${authLatency}ms)`,
          };
        }
      } catch {
        clearTimeout(authTimeout);
      }
    }

    if (response.status === 401 || response.status === 403) {
      return {
        status: "error",
        latencyMs,
        message: `Metasploit authentication failed (HTTP ${response.status}). Check API key or credentials.`,
      };
    }

    return {
      status: "error",
      latencyMs,
      message: `Metasploit returned HTTP ${response.status}`,
    };
  } catch (e: any) {
    const latencyMs = Date.now() - startTime;
    if (e.name === "AbortError") {
      return { status: "disconnected", latencyMs, message: "Metasploit health check timed out (10s)" };
    }
    return {
      status: "disconnected",
      latencyMs,
      message: `Cannot reach Metasploit server: ${e.code || e.message}`,
    };
  }
}

// ─── Unified Health Check ───────────────────────────────────────────────

/**
 * Perform a real HTTP health check against a C2 server.
 * Dispatches to the appropriate protocol-specific checker.
 */
export async function checkC2Health(server: C2ServerRecord): Promise<HealthCheckResult> {
  const authConfig = decryptAuthConfig(server.id, server.authConfigEncrypted);

  switch (server.type) {
    case "caldera":
      return checkCaldera(server.baseUrl, authConfig);
    case "sliver":
      return checkSliver(server.baseUrl, authConfig);
    case "metasploit":
      return checkMetasploit(server.baseUrl, authConfig);
    default:
      return {
        status: "error",
        latencyMs: 0,
        message: `Unknown C2 server type: ${server.type}`,
      };
  }
}
