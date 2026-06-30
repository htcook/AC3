/**
 * Caldera Preflight — Connectivity validation before payload builds,
 * campaign exports, and operation provisioning.
 *
 * Checks:
 *  1. Caldera base URL is configured
 *  2. HTTP health endpoint responds within timeout
 *  3. API key is accepted (not 401/403)
 *  4. Returns server version, latency, and agent callback URL
 *
 * Usage:
 *   const info = await validateCalderaConnection();
 *   // info.baseUrl, info.ip, info.port, info.latencyMs, info.version, info.agentCallbackUrl
 *
 * Throws a descriptive error if the server is unreachable or misconfigured.
 */

import { ENV } from "../_core/env";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface CalderaPreflightResult {
  ok: true;
  baseUrl: string;
  ip: string;
  port: number;
  latencyMs: number;
  version: string;
  agentCallbackUrl: string;
  capabilities: string[];
}

export interface CalderaPreflightError {
  ok: false;
  baseUrl: string;
  ip: string;
  port: number;
  error: string;
  latencyMs: number;
}

export type CalderaPreflightOutcome = CalderaPreflightResult | CalderaPreflightError;

// ─── URL Parsing ────────────────────────────────────────────────────────────

function parseCalderaUrl(baseUrl: string): { ip: string; port: number } {
  try {
    const url = new URL(baseUrl);
    const ip = url.hostname;
    let port = url.port ? parseInt(url.port, 10) : (url.protocol === "https:" ? 443 : 80);
    return { ip, port };
  } catch {
    return { ip: "unknown", port: 0 };
  }
}

// ─── Quick TCP Reachability Check ───────────────────────────────────────────

async function tcpReachable(host: string, port: number, timeoutMs = 5000): Promise<boolean> {
  // Use a simple HTTP HEAD as a TCP-level reachability probe
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const protocol = port === 443 ? "https" : "http";
    await fetch(`${protocol}://${host}:${port}/`, {
      method: "HEAD",
      signal: controller.signal,
    }).catch(() => {});
    clearTimeout(timer);
    return true;
  } catch {
    return false;
  }
}

// ─── Main Preflight Check ───────────────────────────────────────────────────

/**
 * Validate that the Cyber C2 server is reachable and authenticated.
 * Call this before any payload build, campaign export, or operation creation.
 *
 * @param options.timeout - Max wait in ms (default 10000)
 * @param options.baseUrl - Override the default Caldera URL
 * @param options.apiKey  - Override the default API key
 * @returns CalderaPreflightResult on success
 * @throws Error with descriptive message on failure
 */
export async function validateCalderaConnection(options?: {
  timeout?: number;
  baseUrl?: string;
  apiKey?: string;
}): Promise<CalderaPreflightResult> {
  const baseUrl = options?.baseUrl || ENV.calderaBaseUrl;
  const apiKey = options?.apiKey || ENV.calderaApiKey;
  const timeout = options?.timeout || 10_000;

  if (!baseUrl) {
    throw new Error(
      "Cyber C2 server URL is not configured. Set CALDERA_BASE_URL in environment variables."
    );
  }

  if (!apiKey) {
    throw new Error(
      "Caldera API key is not configured. Set CALDERA_API_KEY in environment variables."
    );
  }

  const { ip, port } = parseCalderaUrl(baseUrl);
  const startTime = Date.now();

  // Step 1: Health endpoint probe
  try {
    const healthUrl = `${baseUrl}/api/v2/health`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(healthUrl, {
      method: "GET",
      headers: {
        KEY: apiKey,
        Accept: "application/json",
      },
      signal: controller.signal,
    });
    clearTimeout(timer);

    const latencyMs = Date.now() - startTime;

    // Step 2: Check authentication
    if (response.status === 401 || response.status === 403) {
      throw new Error(
        `Caldera server at ${ip}:${port} rejected the API key (HTTP ${response.status}). ` +
        `Verify CALDERA_API_KEY is correct. Latency: ${latencyMs}ms.`
      );
    }

    if (!response.ok) {
      throw new Error(
        `Caldera server at ${ip}:${port} returned HTTP ${response.status}. Latency: ${latencyMs}ms.`
      );
    }

    // Step 3: Parse response for version and capabilities
    let version = "unknown";
    let capabilities: string[] = [];
    try {
      const body = await response.json();
      version = body.version || body.caldera_version || "unknown";
      if (body.plugins && Array.isArray(body.plugins)) {
        capabilities = body.plugins.map((p: any) => (typeof p === "string" ? p : p.name || ""));
      }
    } catch {
      // Non-fatal — we confirmed connectivity
    }

    // Step 4: Derive the agent callback URL
    // Caldera agents call back to the server's HTTP contact endpoint
    // Default: http://<ip>:8888 for direct, or the baseUrl for proxied setups
    const agentCallbackUrl = baseUrl;

    return {
      ok: true,
      baseUrl,
      ip,
      port,
      latencyMs,
      version,
      agentCallbackUrl,
      capabilities,
    };
  } catch (err: any) {
    const latencyMs = Date.now() - startTime;

    if (err.name === "AbortError") {
      throw new Error(
        `Caldera server at ${ip}:${port} did not respond within ${timeout / 1000}s. ` +
        `Verify the server is running and the IP/port is correct.`
      );
    }

    // Re-throw our own descriptive errors
    if (err.message?.includes("Cyber C2")) {
      throw err;
    }

    throw new Error(
      `Cannot reach Caldera server at ${ip}:${port}: ${err.code || err.message}. ` +
      `Latency: ${latencyMs}ms. Check network connectivity and firewall rules.`
    );
  }
}

/**
 * Non-throwing version — returns a result object instead of throwing.
 * Useful for UI status indicators.
 */
export async function checkCalderaStatus(options?: {
  timeout?: number;
  baseUrl?: string;
  apiKey?: string;
}): Promise<CalderaPreflightOutcome> {
  const baseUrl = options?.baseUrl || ENV.calderaBaseUrl;
  const { ip, port } = parseCalderaUrl(baseUrl);

  try {
    return await validateCalderaConnection(options);
  } catch (err: any) {
    return {
      ok: false,
      baseUrl,
      ip,
      port,
      error: err.message || "Unknown error",
      latencyMs: 0,
    };
  }
}

/**
 * Get the default Cyber C2 listener address for payload generation.
 * Returns { lhost, lport } suitable for msfvenom LHOST/LPORT.
 *
 * The idea: MSF payloads should call back to the Caldera server,
 * where a Sandcat agent stager is served. This way, successful
 * exploits automatically deploy a Caldera agent.
 */
export function getCalderaListenerDefaults(): {
  lhost: string;
  lport: number;
  agentCallbackUrl: string;
  c2Framework: "caldera";
} {
  const baseUrl = ENV.calderaBaseUrl;
  const { ip, port } = parseCalderaUrl(baseUrl);

  // For Caldera, the agent callback typically goes to the HTTP contact on port 8888
  // But if proxied through HTTPS, use the proxy hostname
  // The actual agent stager endpoint is at /file/download (Sandcat)
  return {
    lhost: ip,
    lport: port === 443 ? 8888 : port, // If proxied via 443, agents use direct 8888
    agentCallbackUrl: baseUrl,
    c2Framework: "caldera",
  };
}
