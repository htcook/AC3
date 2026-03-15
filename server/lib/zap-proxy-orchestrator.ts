/**
 * ZAP Proxy Orchestration Engine
 *
 * Manages the full ZAP proxy lifecycle for web application penetration testing:
 *   1. Proxy deployment & configuration (listener address, port, upstream chains)
 *   2. Browser proxy integration (PAC file generation, CA cert management)
 *   3. Authenticated crawling (form-based, JSON API, bearer token, HTTP basic)
 *   4. Session management (logged-in/out indicators, forced user, session tokens)
 *   5. WAF-aware scan tuning (rate limiting, evasion, header rotation)
 *   6. Interactive proxy sessions (request/response interception, manual browse)
 *   7. Context & scope management for multi-target engagements
 *
 * Requires ZAP running in daemon mode with API enabled.
 * Environment: ZAP_BASE_URL, ZAP_API_KEY
 *
 * @module zap-proxy-orchestrator
 */

import { DEFAULT_ZAP_CONFIG, type ZapConfig } from "./zap-scanner";

// ─── Types ─────────────────────────────────────────────────────────────────

export interface ProxyConfig {
  /** ZAP proxy listener address (default: 0.0.0.0) */
  listenAddress: string;
  /** ZAP proxy listener port (default: 8080) */
  listenPort: number;
  /** Upstream proxy for chaining (e.g., Burp, corporate proxy) */
  upstreamProxy?: {
    host: string;
    port: number;
    username?: string;
    password?: string;
    /** Hosts to bypass upstream proxy */
    noProxyHosts?: string[];
  };
  /** Whether to intercept HTTPS traffic (requires CA cert install) */
  httpsInterception: boolean;
  /** Custom User-Agent for all proxied requests */
  userAgent?: string;
  /** Request delay in ms to avoid WAF rate limiting */
  requestDelayMs?: number;
  /** Max concurrent connections through proxy */
  maxConcurrentConnections?: number;
}

export interface AuthConfig {
  /** Authentication method type */
  type: "form_based" | "json_api" | "http_basic" | "bearer_token" | "script_based" | "manual_browse";
  /** Login page URL */
  loginUrl: string;
  /** Login request URL (form action / API endpoint) */
  loginRequestUrl?: string;
  /** POST data template with {%username%} and {%password%} placeholders */
  loginRequestData?: string;
  /** Content-Type for login request */
  contentType?: "application/x-www-form-urlencoded" | "application/json";
  /** Username field name in form */
  usernameField?: string;
  /** Password field name in form */
  passwordField?: string;
  /** Credentials to use */
  credentials: Array<{
    username: string;
    password: string;
    role?: string;
  }>;
  /** Regex pattern that indicates user is logged IN */
  loggedInIndicator?: string;
  /** Regex pattern that indicates user is logged OUT */
  loggedOutIndicator?: string;
  /** Bearer token (for bearer_token type) */
  bearerToken?: string;
  /** Header name for token (default: Authorization) */
  tokenHeaderName?: string;
  /** Token prefix (default: Bearer) */
  tokenPrefix?: string;
  /** CSRF token field name */
  csrfTokenName?: string;
  /** CSRF token extraction regex from page */
  csrfTokenRegex?: string;
  /** Anti-CSRF token parameter name in ZAP */
  antiCsrfTokenName?: string;
}

export interface SessionConfig {
  /** Session token names to track (e.g., JSESSIONID, PHPSESSID) */
  sessionTokenNames: string[];
  /** Whether to regenerate session on each spider request */
  regenerateSession: boolean;
  /** Session timeout in seconds */
  sessionTimeoutSec?: number;
  /** Cookie domain scope */
  cookieDomain?: string;
}

export interface WafEvasionConfig {
  /** Detected WAF vendor (from waf-ngfw-detection module) */
  detectedWaf?: string;
  /** Request delay between probes (ms) */
  requestDelayMs: number;
  /** Max requests per second */
  maxRequestsPerSecond: number;
  /** Rotate User-Agent headers */
  rotateUserAgents: boolean;
  /** Custom User-Agent pool */
  userAgentPool?: string[];
  /** Add random query parameters to avoid caching */
  randomizeQueryParams: boolean;
  /** Use HTTP/1.1 chunked encoding for payload delivery */
  useChunkedEncoding: boolean;
  /** URL-encode payloads to bypass WAF pattern matching */
  doubleUrlEncode: boolean;
  /** Add random delays between requests (jitter) */
  jitterMs: number;
  /** Use case variation in payloads */
  caseVariation: boolean;
  /** Comment insertion in SQL/XSS payloads */
  commentInsertion: boolean;
}

export interface ProxySession {
  id: string;
  contextId: string;
  contextName: string;
  targetUrl: string;
  proxyConfig: ProxyConfig;
  authConfig?: AuthConfig;
  sessionConfig?: SessionConfig;
  wafEvasion?: WafEvasionConfig;
  status: "initializing" | "ready" | "intercepting" | "crawling" | "scanning" | "completed" | "error";
  startedAt: number;
  urlsIntercepted: number;
  requestsProxied: number;
  error?: string;
}

export interface ProxySessionStatus {
  session: ProxySession;
  proxyAddress: string;
  proxyPort: number;
  caCertUrl: string;
  pacFileUrl: string;
  browserConfigInstructions: BrowserProxyInstructions;
  interceptedHosts: string[];
  activeUsers: string[];
}

export interface BrowserProxyInstructions {
  chrome: string;
  firefox: string;
  systemWide: string;
  curlCommand: string;
  pythonRequests: string;
}

// ─── ZAP API Helper ────────────────────────────────────────────────────────

async function zapApi(
  endpoint: string,
  params: Record<string, string> = {},
  config: ZapConfig = DEFAULT_ZAP_CONFIG,
  method: "GET" | "POST" = "GET",
): Promise<any> {
  const url = new URL(`${config.baseUrl}${endpoint}`);
  url.searchParams.set("apikey", config.apiKey);
  if (method === "GET") {
    for (const [k, v] of Object.entries(params)) {
      url.searchParams.set(k, v);
    }
  }

  const fetchOpts: RequestInit = {
    method,
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(30000),
  };

  if (method === "POST") {
    fetchOpts.headers = {
      ...fetchOpts.headers,
      "Content-Type": "application/x-www-form-urlencoded",
    };
    const body = new URLSearchParams(params);
    body.set("apikey", config.apiKey);
    fetchOpts.body = body.toString();
  }

  const response = await fetch(url.toString(), fetchOpts);
  if (!response.ok) {
    throw new Error(`ZAP API error: ${response.status} ${response.statusText} at ${endpoint}`);
  }
  return response.json();
}

// ─── User-Agent Pool for WAF Evasion ───────────────────────────────────────

const DEFAULT_USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
];

// ─── WAF-Specific Evasion Presets ──────────────────────────────────────────

const WAF_EVASION_PRESETS: Record<string, Partial<WafEvasionConfig>> = {
  cloudflare: {
    requestDelayMs: 2000,
    maxRequestsPerSecond: 2,
    rotateUserAgents: true,
    randomizeQueryParams: true,
    jitterMs: 1500,
    doubleUrlEncode: false,
    caseVariation: true,
    commentInsertion: true,
  },
  akamai: {
    requestDelayMs: 3000,
    maxRequestsPerSecond: 1,
    rotateUserAgents: true,
    randomizeQueryParams: true,
    jitterMs: 2000,
    doubleUrlEncode: true,
    caseVariation: true,
    commentInsertion: true,
  },
  aws_waf: {
    requestDelayMs: 1500,
    maxRequestsPerSecond: 3,
    rotateUserAgents: true,
    randomizeQueryParams: false,
    jitterMs: 1000,
    doubleUrlEncode: true,
    caseVariation: false,
    commentInsertion: true,
  },
  imperva: {
    requestDelayMs: 2500,
    maxRequestsPerSecond: 2,
    rotateUserAgents: true,
    randomizeQueryParams: true,
    jitterMs: 2000,
    doubleUrlEncode: true,
    caseVariation: true,
    commentInsertion: true,
  },
  f5_big_ip: {
    requestDelayMs: 1000,
    maxRequestsPerSecond: 5,
    rotateUserAgents: false,
    randomizeQueryParams: false,
    jitterMs: 500,
    doubleUrlEncode: false,
    caseVariation: false,
    commentInsertion: false,
  },
  modsecurity: {
    requestDelayMs: 500,
    maxRequestsPerSecond: 10,
    rotateUserAgents: false,
    randomizeQueryParams: false,
    jitterMs: 300,
    doubleUrlEncode: true,
    caseVariation: true,
    commentInsertion: true,
  },
  fortinet: {
    requestDelayMs: 2000,
    maxRequestsPerSecond: 2,
    rotateUserAgents: true,
    randomizeQueryParams: true,
    jitterMs: 1500,
    doubleUrlEncode: true,
    caseVariation: true,
    commentInsertion: false,
  },
  palo_alto: {
    requestDelayMs: 1500,
    maxRequestsPerSecond: 3,
    rotateUserAgents: true,
    randomizeQueryParams: false,
    jitterMs: 1000,
    doubleUrlEncode: false,
    caseVariation: true,
    commentInsertion: true,
  },
  default: {
    requestDelayMs: 500,
    maxRequestsPerSecond: 10,
    rotateUserAgents: false,
    randomizeQueryParams: false,
    jitterMs: 200,
    doubleUrlEncode: false,
    caseVariation: false,
    commentInsertion: false,
  },
};

// ─── Active Sessions Store ─────────────────────────────────────────────────

const activeSessions = new Map<string, ProxySession>();

// ─── Core Orchestration Functions ──────────────────────────────────────────

/**
 * Initialize a new ZAP proxy session with full configuration.
 * Creates a ZAP context, configures proxy settings, sets up auth if provided,
 * and applies WAF evasion settings.
 */
export async function initializeProxySession(params: {
  targetUrl: string;
  contextName?: string;
  proxyConfig?: Partial<ProxyConfig>;
  authConfig?: AuthConfig;
  sessionConfig?: SessionConfig;
  wafVendor?: string;
  wafEvasionOverrides?: Partial<WafEvasionConfig>;
  zapConfig?: Partial<ZapConfig>;
}): Promise<ProxySessionStatus> {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...params.zapConfig };
  const sessionId = `proxy-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const contextName = params.contextName || `ctx-${new URL(params.targetUrl).hostname}`;

  console.log(`[ZAP Proxy] Initializing session ${sessionId} for ${params.targetUrl}`);

  // Step 1: Create ZAP context
  const contextResult = await zapApi("/JSON/context/action/newContext/", {
    contextName,
  }, cfg);
  const contextId = String(contextResult.contextId);

  // Step 2: Add target URL to context scope
  const targetHost = new URL(params.targetUrl).hostname;
  const includeRegex = `${params.targetUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}.*`;
  await zapApi("/JSON/context/action/includeInContext/", {
    contextName,
    regex: includeRegex,
  }, cfg);

  // Also include subdomains
  await zapApi("/JSON/context/action/includeInContext/", {
    contextName,
    regex: `https?://.*\\.${targetHost.replace(/\./g, "\\.")}.*`,
  }, cfg).catch(() => {}); // Non-fatal if regex is invalid

  // Step 3: Configure proxy settings
  const proxyConfig: ProxyConfig = {
    listenAddress: params.proxyConfig?.listenAddress || "0.0.0.0",
    listenPort: params.proxyConfig?.listenPort || 8080,
    httpsInterception: params.proxyConfig?.httpsInterception ?? true,
    requestDelayMs: params.proxyConfig?.requestDelayMs || 20,
    maxConcurrentConnections: params.proxyConfig?.maxConcurrentConnections || 10,
    ...params.proxyConfig,
  };

  // Configure proxy address/port
  await zapApi("/JSON/core/action/setOptionProxyChainPort/", {
    Integer: String(proxyConfig.listenPort),
  }, cfg).catch(() => {});

  // Configure upstream proxy if provided
  if (proxyConfig.upstreamProxy) {
    await zapApi("/JSON/core/action/setOptionUseProxyChain/", {
      Boolean: "true",
    }, cfg);
    await zapApi("/JSON/core/action/setOptionProxyChainName/", {
      String: proxyConfig.upstreamProxy.host,
    }, cfg);
    await zapApi("/JSON/core/action/setOptionProxyChainPort/", {
      Integer: String(proxyConfig.upstreamProxy.port),
    }, cfg);
    if (proxyConfig.upstreamProxy.username) {
      await zapApi("/JSON/core/action/setOptionProxyChainUserName/", {
        String: proxyConfig.upstreamProxy.username,
      }, cfg);
    }
    if (proxyConfig.upstreamProxy.password) {
      await zapApi("/JSON/core/action/setOptionProxyChainPassword/", {
        String: proxyConfig.upstreamProxy.password,
      }, cfg);
    }
    if (proxyConfig.upstreamProxy.noProxyHosts?.length) {
      await zapApi("/JSON/core/action/setOptionProxyChainSkipName/", {
        String: proxyConfig.upstreamProxy.noProxyHosts.join(";"),
      }, cfg);
    }
  }

  // Step 4: Configure request delay for WAF evasion
  const wafPreset = WAF_EVASION_PRESETS[params.wafVendor?.toLowerCase() || "default"] || WAF_EVASION_PRESETS.default;
  const wafEvasion: WafEvasionConfig = {
    detectedWaf: params.wafVendor,
    requestDelayMs: wafPreset.requestDelayMs || 500,
    maxRequestsPerSecond: wafPreset.maxRequestsPerSecond || 10,
    rotateUserAgents: wafPreset.rotateUserAgents || false,
    randomizeQueryParams: wafPreset.randomizeQueryParams || false,
    useChunkedEncoding: false,
    doubleUrlEncode: wafPreset.doubleUrlEncode || false,
    jitterMs: wafPreset.jitterMs || 200,
    caseVariation: wafPreset.caseVariation || false,
    commentInsertion: wafPreset.commentInsertion || false,
    ...params.wafEvasionOverrides,
  };

  // Apply request delay to ZAP
  await zapApi("/JSON/core/action/setOptionDefaultUserAgent/", {
    String: proxyConfig.userAgent || DEFAULT_USER_AGENTS[0],
  }, cfg).catch(() => {});

  // Set scan delay
  if (wafEvasion.requestDelayMs > 0) {
    await zapApi("/JSON/spider/action/setOptionRequestWaitTime/", {
      Integer: String(wafEvasion.requestDelayMs),
    }, cfg).catch(() => {});
    await zapApi("/JSON/ascan/action/setOptionDelayInMs/", {
      Integer: String(wafEvasion.requestDelayMs),
    }, cfg).catch(() => {});
  }

  // Set max scan threads based on rate limit
  const maxThreads = Math.max(1, Math.min(5, Math.floor(wafEvasion.maxRequestsPerSecond / 2)));
  await zapApi("/JSON/ascan/action/setOptionThreadPerHost/", {
    Integer: String(maxThreads),
  }, cfg).catch(() => {});

  // Step 5: Configure authentication if provided
  if (params.authConfig) {
    await configureAuthentication(contextId, contextName, params.authConfig, cfg);
  }

  // Step 6: Configure session management
  const sessionConfig: SessionConfig = params.sessionConfig || {
    sessionTokenNames: ["JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "connect.sid", "session", "sid"],
    regenerateSession: false,
  };

  await zapApi("/JSON/sessionManagement/action/setSessionManagementMethod/", {
    contextId,
    methodName: "cookieBasedSessionManagement",
  }, cfg).catch(() => {});

  // Add session token names for tracking
  for (const tokenName of sessionConfig.sessionTokenNames) {
    await zapApi("/JSON/httpsessions/action/addSessionToken/", {
      site: targetHost,
      sessionToken: tokenName,
    }, cfg).catch(() => {});
  }

  // Step 7: Build session object
  const session: ProxySession = {
    id: sessionId,
    contextId,
    contextName,
    targetUrl: params.targetUrl,
    proxyConfig,
    authConfig: params.authConfig,
    sessionConfig,
    wafEvasion,
    status: "ready",
    startedAt: Date.now(),
    urlsIntercepted: 0,
    requestsProxied: 0,
  };

  activeSessions.set(sessionId, session);

  // Build browser configuration instructions
  const proxyAddress = proxyConfig.listenAddress === "0.0.0.0"
    ? cfg.baseUrl.replace(/https?:\/\//, "").replace(/:\d+$/, "")
    : proxyConfig.listenAddress;
  const proxyPort = proxyConfig.listenPort;

  const browserInstructions = generateBrowserInstructions(proxyAddress, proxyPort, cfg.baseUrl);

  console.log(`[ZAP Proxy] Session ${sessionId} ready — proxy at ${proxyAddress}:${proxyPort}`);

  return {
    session,
    proxyAddress,
    proxyPort,
    caCertUrl: `${cfg.baseUrl}/OTHER/core/other/rootcert/`,
    pacFileUrl: `${cfg.baseUrl}/OTHER/core/other/proxy.pac/`,
    browserConfigInstructions: browserInstructions,
    interceptedHosts: [targetHost],
    activeUsers: params.authConfig?.credentials.map(c => c.username) || [],
  };
}

/**
 * Configure ZAP authentication for a context.
 * Supports form-based, JSON API, HTTP basic, bearer token, and script-based auth.
 */
async function configureAuthentication(
  contextId: string,
  contextName: string,
  auth: AuthConfig,
  cfg: ZapConfig,
): Promise<void> {
  console.log(`[ZAP Auth] Configuring ${auth.type} authentication for context ${contextName}`);

  switch (auth.type) {
    case "form_based": {
      // Build login request data with placeholders
      const loginData = auth.loginRequestData ||
        `${auth.usernameField || "username"}={%username%}&${auth.passwordField || "password"}={%password%}`;

      const authMethodParams = [
        `loginUrl=${encodeURIComponent(auth.loginUrl)}`,
        `loginRequestData=${encodeURIComponent(loginData)}`,
      ];

      if (auth.loginRequestUrl) {
        authMethodParams.push(`loginPageUrl=${encodeURIComponent(auth.loginRequestUrl)}`);
      }

      await zapApi("/JSON/authentication/action/setAuthenticationMethod/", {
        contextId,
        authMethodName: "formBasedAuthentication",
        authMethodConfigParams: authMethodParams.join("&"),
      }, cfg);
      break;
    }

    case "json_api": {
      // JSON-based authentication (REST APIs)
      const loginData = auth.loginRequestData ||
        JSON.stringify({
          [auth.usernameField || "username"]: "{%username%}",
          [auth.passwordField || "password"]: "{%password%}",
        });

      await zapApi("/JSON/authentication/action/setAuthenticationMethod/", {
        contextId,
        authMethodName: "jsonBasedAuthentication",
        authMethodConfigParams: [
          `loginUrl=${encodeURIComponent(auth.loginRequestUrl || auth.loginUrl)}`,
          `loginRequestData=${encodeURIComponent(loginData)}`,
        ].join("&"),
      }, cfg);
      break;
    }

    case "http_basic": {
      await zapApi("/JSON/authentication/action/setAuthenticationMethod/", {
        contextId,
        authMethodName: "httpAuthentication",
        authMethodConfigParams: [
          `hostname=${encodeURIComponent(new URL(auth.loginUrl).hostname)}`,
          `port=${new URL(auth.loginUrl).port || "443"}`,
          `realm=`,
        ].join("&"),
      }, cfg);
      break;
    }

    case "bearer_token": {
      // For bearer token auth, we use a script or header-based approach
      // Add the token as a replacer rule
      if (auth.bearerToken) {
        const headerName = auth.tokenHeaderName || "Authorization";
        const headerValue = `${auth.tokenPrefix || "Bearer"} ${auth.bearerToken}`;
        await zapApi("/JSON/replacer/action/addRule/", {
          description: "Bearer Token Auth",
          enabled: "true",
          matchType: "REQ_HEADER",
          matchRegex: "false",
          matchString: headerName,
          replacement: headerValue,
          initiators: "",
        }, cfg);
      }
      break;
    }

    case "manual_browse": {
      // Manual authentication — user browses through proxy and logs in manually
      // ZAP will capture the session automatically
      await zapApi("/JSON/authentication/action/setAuthenticationMethod/", {
        contextId,
        authMethodName: "manualAuthentication",
      }, cfg);
      break;
    }
  }

  // Set logged-in/logged-out indicators
  if (auth.loggedInIndicator) {
    await zapApi("/JSON/authentication/action/setLoggedInIndicator/", {
      contextId,
      loggedInIndicatorRegex: auth.loggedInIndicator,
    }, cfg);
  }

  if (auth.loggedOutIndicator) {
    await zapApi("/JSON/authentication/action/setLoggedOutIndicator/", {
      contextId,
      loggedOutIndicatorRegex: auth.loggedOutIndicator,
    }, cfg);
  }

  // Add users with credentials
  for (const cred of auth.credentials) {
    try {
      const userResult = await zapApi("/JSON/users/action/newUser/", {
        contextId,
        name: cred.username,
      }, cfg);
      const userId = String(userResult.userId);

      // Set credentials based on auth type
      if (auth.type === "form_based" || auth.type === "json_api") {
        await zapApi("/JSON/users/action/setAuthenticationCredentials/", {
          contextId,
          userId,
          authCredentialsConfigParams: `username=${encodeURIComponent(cred.username)}&password=${encodeURIComponent(cred.password)}`,
        }, cfg);
      } else if (auth.type === "http_basic") {
        await zapApi("/JSON/users/action/setAuthenticationCredentials/", {
          contextId,
          userId,
          authCredentialsConfigParams: `username=${encodeURIComponent(cred.username)}&password=${encodeURIComponent(cred.password)}`,
        }, cfg);
      }

      // Enable the user
      await zapApi("/JSON/users/action/setUserEnabled/", {
        contextId,
        userId,
        enabled: "true",
      }, cfg);

      // Set as forced user for authenticated crawling
      await zapApi("/JSON/forcedUser/action/setForcedUser/", {
        contextId,
        userId,
      }, cfg);

      console.log(`[ZAP Auth] Added user ${cred.username} (role: ${cred.role || "default"}) to context`);
    } catch (err: any) {
      console.warn(`[ZAP Auth] Failed to add user ${cred.username}: ${err.message}`);
    }
  }

  // Enable forced user mode for authenticated crawling
  await zapApi("/JSON/forcedUser/action/setForcedUserModeEnabled/", {
    boolean: "true",
  }, cfg).catch(() => {});

  // Configure anti-CSRF tokens if specified
  if (auth.antiCsrfTokenName) {
    await zapApi("/JSON/acsrf/action/addOptionToken/", {
      String: auth.antiCsrfTokenName,
    }, cfg).catch(() => {});
  }

  console.log(`[ZAP Auth] Authentication configured for context ${contextName}`);
}

/**
 * Generate browser proxy configuration instructions for all major browsers.
 */
function generateBrowserInstructions(
  proxyHost: string,
  proxyPort: number,
  zapBaseUrl: string,
): BrowserProxyInstructions {
  return {
    chrome: [
      `1. Open Chrome with proxy flag:`,
      `   google-chrome --proxy-server="${proxyHost}:${proxyPort}" --ignore-certificate-errors`,
      ``,
      `   Or configure manually:`,
      `   Settings → System → Open proxy settings`,
      `   Set HTTP/HTTPS proxy to ${proxyHost}:${proxyPort}`,
      ``,
      `2. Install ZAP CA Certificate for HTTPS interception:`,
      `   Navigate to ${zapBaseUrl}/OTHER/core/other/rootcert/`,
      `   Save the certificate, then import in:`,
      `   Settings → Privacy and Security → Manage Certificates → Authorities → Import`,
      `   Check "Trust this certificate for identifying websites"`,
    ].join("\n"),

    firefox: [
      `1. Open Firefox Preferences → Network Settings → Settings`,
      `   Select "Manual proxy configuration"`,
      `   HTTP Proxy: ${proxyHost}  Port: ${proxyPort}`,
      `   Check "Also use this proxy for HTTPS"`,
      ``,
      `2. Install ZAP CA Certificate:`,
      `   Navigate to ${zapBaseUrl}/OTHER/core/other/rootcert/`,
      `   Firefox will prompt to trust — check "Trust this CA to identify websites"`,
      `   Or: Preferences → Privacy & Security → View Certificates → Import`,
    ].join("\n"),

    systemWide: [
      `Linux:`,
      `  export http_proxy=http://${proxyHost}:${proxyPort}`,
      `  export https_proxy=http://${proxyHost}:${proxyPort}`,
      `  export HTTP_PROXY=http://${proxyHost}:${proxyPort}`,
      `  export HTTPS_PROXY=http://${proxyHost}:${proxyPort}`,
      ``,
      `macOS:`,
      `  networksetup -setwebproxy "Wi-Fi" ${proxyHost} ${proxyPort}`,
      `  networksetup -setsecurewebproxy "Wi-Fi" ${proxyHost} ${proxyPort}`,
      ``,
      `Windows:`,
      `  netsh winhttp set proxy ${proxyHost}:${proxyPort}`,
    ].join("\n"),

    curlCommand: `curl -x http://${proxyHost}:${proxyPort} -k https://target.example.com`,

    pythonRequests: [
      `import requests`,
      `proxies = {`,
      `    "http": "http://${proxyHost}:${proxyPort}",`,
      `    "https": "http://${proxyHost}:${proxyPort}",`,
      `}`,
      `response = requests.get("https://target.example.com", proxies=proxies, verify=False)`,
    ].join("\n"),
  };
}

/**
 * Start an authenticated spider crawl through the ZAP proxy.
 * Uses the configured auth context to crawl as an authenticated user.
 */
export async function startAuthenticatedCrawl(
  sessionId: string,
  options?: {
    useAjaxSpider?: boolean;
    maxDepth?: number;
    maxChildren?: number;
    subtreeOnly?: boolean;
    zapConfig?: Partial<ZapConfig>;
  },
): Promise<{
  spiderScanId: string;
  ajaxSpiderStarted: boolean;
  contextId: string;
}> {
  const session = activeSessions.get(sessionId);
  if (!session) throw new Error(`Proxy session ${sessionId} not found`);

  const cfg = { ...DEFAULT_ZAP_CONFIG, ...options?.zapConfig };

  session.status = "crawling";

  // Start traditional spider with context
  const spiderResult = await zapApi("/JSON/spider/action/scan/", {
    url: session.targetUrl,
    maxChildren: String(options?.maxChildren || 20),
    recurse: "true",
    contextName: session.contextName,
    subtreeOnly: String(options?.subtreeOnly || false),
  }, cfg);

  const spiderScanId = String(spiderResult.scan);

  // Optionally start AJAX spider for SPAs
  let ajaxSpiderStarted = false;
  if (options?.useAjaxSpider) {
    try {
      await zapApi("/JSON/ajaxSpider/action/scan/", {
        url: session.targetUrl,
        inScope: "true",
        contextName: session.contextName,
        subtreeOnly: String(options?.subtreeOnly || false),
      }, cfg);
      ajaxSpiderStarted = true;
    } catch (err: any) {
      console.warn(`[ZAP Proxy] AJAX spider failed to start: ${err.message}`);
    }
  }

  console.log(`[ZAP Proxy] Authenticated crawl started — spider ${spiderScanId}, AJAX: ${ajaxSpiderStarted}`);

  return {
    spiderScanId,
    ajaxSpiderStarted,
    contextId: session.contextId,
  };
}

/**
 * Get the proxy history — all requests/responses that passed through ZAP.
 */
export async function getProxyHistory(
  options?: {
    start?: number;
    count?: number;
    zapConfig?: Partial<ZapConfig>;
  },
): Promise<{
  messages: Array<{
    id: string;
    timestamp: string;
    method: string;
    url: string;
    statusCode: number;
    responseLength: number;
    rtt: number;
    tags: string[];
    note: string;
  }>;
  totalCount: number;
}> {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...options?.zapConfig };

  const result = await zapApi("/JSON/core/view/messages/", {
    baseurl: "",
    start: String(options?.start || 0),
    count: String(options?.count || 100),
  }, cfg);

  const messages = (result.messages || []).map((msg: any) => ({
    id: msg.id,
    timestamp: msg.timestamp,
    method: msg.requestHeader?.split(" ")[0] || "GET",
    url: msg.requestHeader?.split(" ")[1] || "",
    statusCode: parseInt(msg.responseHeader?.split(" ")[1] || "0", 10),
    responseLength: parseInt(msg.responseBody?.length || "0", 10),
    rtt: parseInt(msg.rtt || "0", 10),
    tags: msg.tags || [],
    note: msg.note || "",
  }));

  return {
    messages,
    totalCount: messages.length,
  };
}

/**
 * Get the ZAP root CA certificate for HTTPS interception.
 */
export async function getCaCertificate(
  zapConfig?: Partial<ZapConfig>,
): Promise<{ certPem: string; downloadUrl: string }> {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...zapConfig };

  try {
    const response = await fetch(`${cfg.baseUrl}/OTHER/core/other/rootcert/?apikey=${cfg.apiKey}`, {
      signal: AbortSignal.timeout(10000),
    });
    const certPem = await response.text();
    return {
      certPem,
      downloadUrl: `${cfg.baseUrl}/OTHER/core/other/rootcert/`,
    };
  } catch {
    return {
      certPem: "",
      downloadUrl: `${cfg.baseUrl}/OTHER/core/other/rootcert/`,
    };
  }
}

/**
 * Apply WAF evasion settings to an active ZAP scan based on detected WAF vendor.
 * Integrates with the waf-ngfw-detection module output.
 */
export async function applyWafEvasionSettings(
  wafAssessment: {
    wafDetected: boolean;
    wafVendor?: string;
    wafConfidence?: number;
    ngfwDetected?: boolean;
    ngfwVendor?: string;
  },
  zapConfig?: Partial<ZapConfig>,
): Promise<{
  applied: boolean;
  preset: string;
  settings: WafEvasionConfig;
  scanTuning: {
    threadCount: number;
    delayMs: number;
    maxRps: number;
    evasionTechniques: string[];
  };
}> {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...zapConfig };

  if (!wafAssessment.wafDetected) {
    return {
      applied: false,
      preset: "none",
      settings: WAF_EVASION_PRESETS.default as WafEvasionConfig,
      scanTuning: {
        threadCount: 5,
        delayMs: 20,
        maxRps: 50,
        evasionTechniques: [],
      },
    };
  }

  // Normalize WAF vendor name to match presets
  const vendorKey = (wafAssessment.wafVendor || "").toLowerCase()
    .replace(/\s+/g, "_")
    .replace(/[^a-z0-9_]/g, "");

  const preset = WAF_EVASION_PRESETS[vendorKey] || WAF_EVASION_PRESETS.default;
  const settings: WafEvasionConfig = {
    detectedWaf: wafAssessment.wafVendor,
    requestDelayMs: preset.requestDelayMs || 500,
    maxRequestsPerSecond: preset.maxRequestsPerSecond || 10,
    rotateUserAgents: preset.rotateUserAgents || false,
    randomizeQueryParams: preset.randomizeQueryParams || false,
    useChunkedEncoding: false,
    doubleUrlEncode: preset.doubleUrlEncode || false,
    jitterMs: preset.jitterMs || 200,
    caseVariation: preset.caseVariation || false,
    commentInsertion: preset.commentInsertion || false,
  };

  // Apply to ZAP
  const threadCount = Math.max(1, Math.min(5, Math.floor(settings.maxRequestsPerSecond / 2)));

  await zapApi("/JSON/ascan/action/setOptionDelayInMs/", {
    Integer: String(settings.requestDelayMs),
  }, cfg).catch(() => {});

  await zapApi("/JSON/ascan/action/setOptionThreadPerHost/", {
    Integer: String(threadCount),
  }, cfg).catch(() => {});

  await zapApi("/JSON/spider/action/setOptionRequestWaitTime/", {
    Integer: String(settings.requestDelayMs),
  }, cfg).catch(() => {});

  // Rotate user agents if needed
  if (settings.rotateUserAgents) {
    const randomUA = DEFAULT_USER_AGENTS[Math.floor(Math.random() * DEFAULT_USER_AGENTS.length)];
    await zapApi("/JSON/core/action/setOptionDefaultUserAgent/", {
      String: randomUA,
    }, cfg).catch(() => {});
  }

  // Build list of active evasion techniques
  const evasionTechniques: string[] = [];
  if (settings.rotateUserAgents) evasionTechniques.push("User-Agent rotation");
  if (settings.randomizeQueryParams) evasionTechniques.push("Query parameter randomization");
  if (settings.doubleUrlEncode) evasionTechniques.push("Double URL encoding");
  if (settings.caseVariation) evasionTechniques.push("Case variation in payloads");
  if (settings.commentInsertion) evasionTechniques.push("Comment insertion in payloads");
  if (settings.jitterMs > 0) evasionTechniques.push(`Request jitter (${settings.jitterMs}ms)`);
  if (settings.requestDelayMs > 100) evasionTechniques.push(`Rate limiting (${settings.requestDelayMs}ms delay)`);

  console.log(`[ZAP WAF Evasion] Applied ${vendorKey} preset: ${threadCount} threads, ${settings.requestDelayMs}ms delay, ${evasionTechniques.length} evasion techniques`);

  return {
    applied: true,
    preset: vendorKey,
    settings,
    scanTuning: {
      threadCount,
      delayMs: settings.requestDelayMs,
      maxRps: settings.maxRequestsPerSecond,
      evasionTechniques,
    },
  };
}

/**
 * Get the status of an active proxy session.
 */
export async function getProxySessionStatus(
  sessionId: string,
  zapConfig?: Partial<ZapConfig>,
): Promise<ProxySessionStatus | null> {
  const session = activeSessions.get(sessionId);
  if (!session) return null;

  const cfg = { ...DEFAULT_ZAP_CONFIG, ...zapConfig };
  const proxyAddress = session.proxyConfig.listenAddress === "0.0.0.0"
    ? cfg.baseUrl.replace(/https?:\/\//, "").replace(/:\d+$/, "")
    : session.proxyConfig.listenAddress;

  // Get intercepted hosts from ZAP
  let interceptedHosts: string[] = [];
  try {
    const sites = await zapApi("/JSON/core/view/sites/", {}, cfg);
    interceptedHosts = sites.sites || [];
  } catch {}

  // Get active users
  let activeUsers: string[] = [];
  try {
    const users = await zapApi("/JSON/users/view/usersList/", { contextId: session.contextId }, cfg);
    activeUsers = (users.usersList || []).map((u: any) => u.name);
  } catch {}

  // Update request count
  try {
    const stats = await zapApi("/JSON/core/view/numberOfMessages/", {}, cfg);
    session.requestsProxied = parseInt(stats.numberOfMessages || "0", 10);
  } catch {}

  return {
    session,
    proxyAddress,
    proxyPort: session.proxyConfig.listenPort,
    caCertUrl: `${cfg.baseUrl}/OTHER/core/other/rootcert/`,
    pacFileUrl: `${cfg.baseUrl}/OTHER/core/other/proxy.pac/`,
    browserConfigInstructions: generateBrowserInstructions(proxyAddress, session.proxyConfig.listenPort, cfg.baseUrl),
    interceptedHosts,
    activeUsers,
  };
}

/**
 * Stop a proxy session and clean up.
 */
export async function stopProxySession(
  sessionId: string,
  zapConfig?: Partial<ZapConfig>,
): Promise<{ success: boolean; requestsProxied: number; urlsIntercepted: number }> {
  const session = activeSessions.get(sessionId);
  if (!session) return { success: false, requestsProxied: 0, urlsIntercepted: 0 };

  const cfg = { ...DEFAULT_ZAP_CONFIG, ...zapConfig };

  // Disable forced user mode
  await zapApi("/JSON/forcedUser/action/setForcedUserModeEnabled/", {
    boolean: "false",
  }, cfg).catch(() => {});

  session.status = "completed";

  const result = {
    success: true,
    requestsProxied: session.requestsProxied,
    urlsIntercepted: session.urlsIntercepted,
  };

  activeSessions.delete(sessionId);
  console.log(`[ZAP Proxy] Session ${sessionId} stopped — ${result.requestsProxied} requests proxied`);

  return result;
}

/**
 * List all active proxy sessions.
 */
export function listActiveSessions(): ProxySession[] {
  return Array.from(activeSessions.values());
}

/**
 * Use LLM to analyze a login page and generate authentication configuration.
 * Detects form fields, CSRF tokens, login endpoints, and session indicators.
 */
export async function detectLoginConfiguration(
  loginPageUrl: string,
  zapConfig?: Partial<ZapConfig>,
): Promise<{
  detected: boolean;
  authConfig: AuthConfig | null;
  analysis: string;
  confidence: number;
}> {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...zapConfig };

  try {
    // Fetch the login page through ZAP to capture it
    const response = await fetch(loginPageUrl, {
      headers: {
        "User-Agent": DEFAULT_USER_AGENTS[0],
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      signal: AbortSignal.timeout(15000),
    });

    const html = await response.text();
    const headers = Object.fromEntries(response.headers.entries());

    // Use LLM to analyze the login page
    const { invokeLLM } = await import("../_core/llm");
    const llmResponse = await invokeLLM({
    _caller: "zap-proxy-orchestrator.analyze",
      messages: [
        {
          role: "system",
          content: `You are a web application security expert analyzing login pages for automated authentication configuration.
Analyze the provided HTML and HTTP headers to determine:
1. Authentication type (form_based, json_api, http_basic, bearer_token)
2. Login form action URL
3. Username field name and ID
4. Password field name and ID
5. CSRF token field name and value pattern
6. Any anti-bot mechanisms (CAPTCHA, rate limiting)
7. Logged-in indicator patterns (text/regex that appears when authenticated)
8. Logged-out indicator patterns (text/regex that appears when not authenticated)
9. Session cookie names

Respond in JSON format with these fields:
{
  "authType": "form_based|json_api|http_basic|bearer_token",
  "loginFormAction": "/login",
  "usernameField": "username",
  "passwordField": "password",
  "csrfTokenName": "_csrf",
  "csrfTokenRegex": "name=\\"_csrf\\" value=\\"([^\"]+)\\"",
  "loggedInIndicator": "\\\\QDashboard\\\\E|\\\\QLogout\\\\E|\\\\QMy Account\\\\E",
  "loggedOutIndicator": "\\\\QLogin\\\\E|\\\\QSign In\\\\E",
  "sessionCookies": ["JSESSIONID"],
  "hasAntiBot": false,
  "antiBotType": null,
  "confidence": 0.85,
  "analysis": "Brief analysis of the login mechanism"
}`,
        },
        {
          role: "user",
          content: `Analyze this login page at ${loginPageUrl}:\n\nHTTP Headers:\n${JSON.stringify(headers, null, 2)}\n\nHTML (first 5000 chars):\n${html.substring(0, 5000)}`,
        },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "login_analysis",
          strict: true,
          schema: {
            type: "object",
            properties: {
              authType: { type: "string" },
              loginFormAction: { type: "string" },
              usernameField: { type: "string" },
              passwordField: { type: "string" },
              csrfTokenName: { type: "string" },
              csrfTokenRegex: { type: "string" },
              loggedInIndicator: { type: "string" },
              loggedOutIndicator: { type: "string" },
              sessionCookies: { type: "array", items: { type: "string" } },
              hasAntiBot: { type: "boolean" },
              antiBotType: { type: "string" },
              confidence: { type: "number" },
              analysis: { type: "string" },
            },
            required: ["authType", "loginFormAction", "usernameField", "passwordField",
              "csrfTokenName", "csrfTokenRegex", "loggedInIndicator", "loggedOutIndicator",
              "sessionCookies", "hasAntiBot", "antiBotType", "confidence", "analysis"],
            additionalProperties: false,
          },
        },
      },
    });

    const parsed = JSON.parse(llmResponse.choices[0].message.content || "{}");

    const authConfig: AuthConfig = {
      type: parsed.authType as AuthConfig["type"] || "form_based",
      loginUrl: loginPageUrl,
      loginRequestUrl: parsed.loginFormAction
        ? new URL(parsed.loginFormAction, loginPageUrl).toString()
        : loginPageUrl,
      usernameField: parsed.usernameField || "username",
      passwordField: parsed.passwordField || "password",
      credentials: [], // To be filled by the operator
      loggedInIndicator: parsed.loggedInIndicator || undefined,
      loggedOutIndicator: parsed.loggedOutIndicator || undefined,
      csrfTokenName: parsed.csrfTokenName || undefined,
      csrfTokenRegex: parsed.csrfTokenRegex || undefined,
      antiCsrfTokenName: parsed.csrfTokenName || undefined,
    };

    return {
      detected: true,
      authConfig,
      analysis: parsed.analysis || "Login page analyzed successfully",
      confidence: parsed.confidence || 0.5,
    };
  } catch (err: any) {
    return {
      detected: false,
      authConfig: null,
      analysis: `Failed to analyze login page: ${err.message}`,
      confidence: 0,
    };
  }
}

/**
 * Get WAF evasion preset names and descriptions for UI display.
 */
export function getWafEvasionPresets(): Array<{
  vendor: string;
  requestDelay: number;
  maxRps: number;
  techniques: string[];
}> {
  return Object.entries(WAF_EVASION_PRESETS).map(([vendor, preset]) => {
    const techniques: string[] = [];
    if (preset.rotateUserAgents) techniques.push("UA rotation");
    if (preset.randomizeQueryParams) techniques.push("Query randomization");
    if (preset.doubleUrlEncode) techniques.push("Double URL encoding");
    if (preset.caseVariation) techniques.push("Case variation");
    if (preset.commentInsertion) techniques.push("Comment insertion");
    return {
      vendor,
      requestDelay: preset.requestDelayMs || 500,
      maxRps: preset.maxRequestsPerSecond || 10,
      techniques,
    };
  });
}
