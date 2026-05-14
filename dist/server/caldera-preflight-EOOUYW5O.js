import {
  ENV,
  init_env
} from "./chunk-NRYVRXXR.js";
import "./chunk-KFQGP6VL.js";

// server/lib/caldera-preflight.ts
init_env();
function parseCalderaUrl(baseUrl) {
  try {
    const url = new URL(baseUrl);
    const ip = url.hostname;
    let port = url.port ? parseInt(url.port, 10) : url.protocol === "https:" ? 443 : 80;
    return { ip, port };
  } catch {
    return { ip: "unknown", port: 0 };
  }
}
async function validateCalderaConnection(options) {
  const baseUrl = options?.baseUrl || ENV.calderaBaseUrl;
  const apiKey = options?.apiKey || ENV.calderaApiKey;
  const timeout = options?.timeout || 1e4;
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
  try {
    const healthUrl = `${baseUrl}/api/v2/health`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const response = await fetch(healthUrl, {
      method: "GET",
      headers: {
        KEY: apiKey,
        Accept: "application/json"
      },
      signal: controller.signal
    });
    clearTimeout(timer);
    const latencyMs = Date.now() - startTime;
    if (response.status === 401 || response.status === 403) {
      throw new Error(
        `Caldera server at ${ip}:${port} rejected the API key (HTTP ${response.status}). Verify CALDERA_API_KEY is correct. Latency: ${latencyMs}ms.`
      );
    }
    if (!response.ok) {
      throw new Error(
        `Caldera server at ${ip}:${port} returned HTTP ${response.status}. Latency: ${latencyMs}ms.`
      );
    }
    let version = "unknown";
    let capabilities = [];
    try {
      const body = await response.json();
      version = body.version || body.caldera_version || "unknown";
      if (body.plugins && Array.isArray(body.plugins)) {
        capabilities = body.plugins.map((p) => typeof p === "string" ? p : p.name || "");
      }
    } catch {
    }
    const agentCallbackUrl = baseUrl;
    return {
      ok: true,
      baseUrl,
      ip,
      port,
      latencyMs,
      version,
      agentCallbackUrl,
      capabilities
    };
  } catch (err) {
    const latencyMs = Date.now() - startTime;
    if (err.name === "AbortError") {
      throw new Error(
        `Caldera server at ${ip}:${port} did not respond within ${timeout / 1e3}s. Verify the server is running and the IP/port is correct.`
      );
    }
    if (err.message?.includes("Cyber C2")) {
      throw err;
    }
    throw new Error(
      `Cannot reach Caldera server at ${ip}:${port}: ${err.code || err.message}. Latency: ${latencyMs}ms. Check network connectivity and firewall rules.`
    );
  }
}
async function checkCalderaStatus(options) {
  const baseUrl = options?.baseUrl || ENV.calderaBaseUrl;
  const { ip, port } = parseCalderaUrl(baseUrl);
  try {
    return await validateCalderaConnection(options);
  } catch (err) {
    return {
      ok: false,
      baseUrl,
      ip,
      port,
      error: err.message || "Unknown error",
      latencyMs: 0
    };
  }
}
function getCalderaListenerDefaults() {
  const baseUrl = ENV.calderaBaseUrl;
  const { ip, port } = parseCalderaUrl(baseUrl);
  return {
    lhost: ip,
    lport: port === 443 ? 8888 : port,
    // If proxied via 443, agents use direct 8888
    agentCallbackUrl: baseUrl,
    c2Framework: "caldera"
  };
}
export {
  checkCalderaStatus,
  getCalderaListenerDefaults,
  validateCalderaConnection
};
