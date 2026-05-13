import {
  DEFAULT_ZAP_CONFIG,
  init_zap_scanner
} from "./chunk-ZDGAPNZV.js";
import "./chunk-UK4O2S6Y.js";
import "./chunk-IU7QQ35X.js";
import "./chunk-UJVJACSD.js";
import "./chunk-EG77VATD.js";
import "./chunk-ENQ6TOJL.js";
import "./chunk-V7U4LYHE.js";
import "./chunk-4BQS7LEI.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-VL2KRLTM.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-IG2G4XDA.js";
import "./chunk-KFQGP6VL.js";

// server/lib/zap-proxy-orchestrator.ts
init_zap_scanner();
async function zapApi(endpoint, params = {}, config = DEFAULT_ZAP_CONFIG, method = "GET") {
  const url = new URL(`${config.baseUrl}${endpoint}`);
  url.searchParams.set("apikey", config.apiKey);
  if (method === "GET") {
    for (const [k, v] of Object.entries(params)) {
      url.searchParams.set(k, v);
    }
  }
  const fetchOpts = {
    method,
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(3e4)
  };
  if (method === "POST") {
    fetchOpts.headers = {
      ...fetchOpts.headers,
      "Content-Type": "application/x-www-form-urlencoded"
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
var DEFAULT_USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
];
var WAF_EVASION_PRESETS = {
  cloudflare: {
    requestDelayMs: 2e3,
    maxRequestsPerSecond: 2,
    rotateUserAgents: true,
    randomizeQueryParams: true,
    jitterMs: 1500,
    doubleUrlEncode: false,
    caseVariation: true,
    commentInsertion: true
  },
  akamai: {
    requestDelayMs: 3e3,
    maxRequestsPerSecond: 1,
    rotateUserAgents: true,
    randomizeQueryParams: true,
    jitterMs: 2e3,
    doubleUrlEncode: true,
    caseVariation: true,
    commentInsertion: true
  },
  aws_waf: {
    requestDelayMs: 1500,
    maxRequestsPerSecond: 3,
    rotateUserAgents: true,
    randomizeQueryParams: false,
    jitterMs: 1e3,
    doubleUrlEncode: true,
    caseVariation: false,
    commentInsertion: true
  },
  imperva: {
    requestDelayMs: 2500,
    maxRequestsPerSecond: 2,
    rotateUserAgents: true,
    randomizeQueryParams: true,
    jitterMs: 2e3,
    doubleUrlEncode: true,
    caseVariation: true,
    commentInsertion: true
  },
  f5_big_ip: {
    requestDelayMs: 1e3,
    maxRequestsPerSecond: 5,
    rotateUserAgents: false,
    randomizeQueryParams: false,
    jitterMs: 500,
    doubleUrlEncode: false,
    caseVariation: false,
    commentInsertion: false
  },
  modsecurity: {
    requestDelayMs: 500,
    maxRequestsPerSecond: 10,
    rotateUserAgents: false,
    randomizeQueryParams: false,
    jitterMs: 300,
    doubleUrlEncode: true,
    caseVariation: true,
    commentInsertion: true
  },
  fortinet: {
    requestDelayMs: 2e3,
    maxRequestsPerSecond: 2,
    rotateUserAgents: true,
    randomizeQueryParams: true,
    jitterMs: 1500,
    doubleUrlEncode: true,
    caseVariation: true,
    commentInsertion: false
  },
  palo_alto: {
    requestDelayMs: 1500,
    maxRequestsPerSecond: 3,
    rotateUserAgents: true,
    randomizeQueryParams: false,
    jitterMs: 1e3,
    doubleUrlEncode: false,
    caseVariation: true,
    commentInsertion: true
  },
  default: {
    requestDelayMs: 500,
    maxRequestsPerSecond: 10,
    rotateUserAgents: false,
    randomizeQueryParams: false,
    jitterMs: 200,
    doubleUrlEncode: false,
    caseVariation: false,
    commentInsertion: false
  }
};
var activeSessions = /* @__PURE__ */ new Map();
async function initializeProxySession(params) {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...params.zapConfig };
  const sessionId = `proxy-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const contextName = params.contextName || `ctx-${new URL(params.targetUrl).hostname}`;
  console.log(`[ZAP Proxy] Initializing session ${sessionId} for ${params.targetUrl}`);
  const contextResult = await zapApi("/JSON/context/action/newContext/", {
    contextName
  }, cfg);
  const contextId = String(contextResult.contextId);
  const targetHost = new URL(params.targetUrl).hostname;
  const includeRegex = `${params.targetUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}.*`;
  await zapApi("/JSON/context/action/includeInContext/", {
    contextName,
    regex: includeRegex
  }, cfg);
  await zapApi("/JSON/context/action/includeInContext/", {
    contextName,
    regex: `https?://.*\\.${targetHost.replace(/\./g, "\\.")}.*`
  }, cfg).catch(() => {
  });
  const proxyConfig = {
    listenAddress: params.proxyConfig?.listenAddress || "0.0.0.0",
    listenPort: params.proxyConfig?.listenPort || 8080,
    httpsInterception: params.proxyConfig?.httpsInterception ?? true,
    requestDelayMs: params.proxyConfig?.requestDelayMs || 20,
    maxConcurrentConnections: params.proxyConfig?.maxConcurrentConnections || 10,
    ...params.proxyConfig
  };
  await zapApi("/JSON/core/action/setOptionProxyChainPort/", {
    Integer: String(proxyConfig.listenPort)
  }, cfg).catch(() => {
  });
  if (proxyConfig.upstreamProxy) {
    await zapApi("/JSON/core/action/setOptionUseProxyChain/", {
      Boolean: "true"
    }, cfg);
    await zapApi("/JSON/core/action/setOptionProxyChainName/", {
      String: proxyConfig.upstreamProxy.host
    }, cfg);
    await zapApi("/JSON/core/action/setOptionProxyChainPort/", {
      Integer: String(proxyConfig.upstreamProxy.port)
    }, cfg);
    if (proxyConfig.upstreamProxy.username) {
      await zapApi("/JSON/core/action/setOptionProxyChainUserName/", {
        String: proxyConfig.upstreamProxy.username
      }, cfg);
    }
    if (proxyConfig.upstreamProxy.password) {
      await zapApi("/JSON/core/action/setOptionProxyChainPassword/", {
        String: proxyConfig.upstreamProxy.password
      }, cfg);
    }
    if (proxyConfig.upstreamProxy.noProxyHosts?.length) {
      await zapApi("/JSON/core/action/setOptionProxyChainSkipName/", {
        String: proxyConfig.upstreamProxy.noProxyHosts.join(";")
      }, cfg);
    }
  }
  const wafPreset = WAF_EVASION_PRESETS[params.wafVendor?.toLowerCase() || "default"] || WAF_EVASION_PRESETS.default;
  const wafEvasion = {
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
    ...params.wafEvasionOverrides
  };
  await zapApi("/JSON/core/action/setOptionDefaultUserAgent/", {
    String: proxyConfig.userAgent || DEFAULT_USER_AGENTS[0]
  }, cfg).catch(() => {
  });
  if (wafEvasion.requestDelayMs > 0) {
    await zapApi("/JSON/spider/action/setOptionRequestWaitTime/", {
      Integer: String(wafEvasion.requestDelayMs)
    }, cfg).catch(() => {
    });
    await zapApi("/JSON/ascan/action/setOptionDelayInMs/", {
      Integer: String(wafEvasion.requestDelayMs)
    }, cfg).catch(() => {
    });
  }
  const maxThreads = Math.max(1, Math.min(5, Math.floor(wafEvasion.maxRequestsPerSecond / 2)));
  await zapApi("/JSON/ascan/action/setOptionThreadPerHost/", {
    Integer: String(maxThreads)
  }, cfg).catch(() => {
  });
  if (params.authConfig) {
    await configureAuthentication(contextId, contextName, params.authConfig, cfg);
  }
  const sessionConfig = params.sessionConfig || {
    sessionTokenNames: ["JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "connect.sid", "session", "sid"],
    regenerateSession: false
  };
  await zapApi("/JSON/sessionManagement/action/setSessionManagementMethod/", {
    contextId,
    methodName: "cookieBasedSessionManagement"
  }, cfg).catch(() => {
  });
  for (const tokenName of sessionConfig.sessionTokenNames) {
    await zapApi("/JSON/httpsessions/action/addSessionToken/", {
      site: targetHost,
      sessionToken: tokenName
    }, cfg).catch(() => {
    });
  }
  const session = {
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
    requestsProxied: 0
  };
  activeSessions.set(sessionId, session);
  const proxyAddress = proxyConfig.listenAddress === "0.0.0.0" ? cfg.baseUrl.replace(/https?:\/\//, "").replace(/:\d+$/, "") : proxyConfig.listenAddress;
  const proxyPort = proxyConfig.listenPort;
  const browserInstructions = generateBrowserInstructions(proxyAddress, proxyPort, cfg.baseUrl);
  console.log(`[ZAP Proxy] Session ${sessionId} ready \u2014 proxy at ${proxyAddress}:${proxyPort}`);
  return {
    session,
    proxyAddress,
    proxyPort,
    caCertUrl: `${cfg.baseUrl}/OTHER/core/other/rootcert/`,
    pacFileUrl: `${cfg.baseUrl}/OTHER/core/other/proxy.pac/`,
    browserConfigInstructions: browserInstructions,
    interceptedHosts: [targetHost],
    activeUsers: params.authConfig?.credentials.map((c) => c.username) || []
  };
}
async function configureAuthentication(contextId, contextName, auth, cfg) {
  console.log(`[ZAP Auth] Configuring ${auth.type} authentication for context ${contextName}`);
  switch (auth.type) {
    case "form_based": {
      const loginData = auth.loginRequestData || `${auth.usernameField || "username"}={%username%}&${auth.passwordField || "password"}={%password%}`;
      const authMethodParams = [
        `loginUrl=${encodeURIComponent(auth.loginUrl)}`,
        `loginRequestData=${encodeURIComponent(loginData)}`
      ];
      if (auth.loginRequestUrl) {
        authMethodParams.push(`loginPageUrl=${encodeURIComponent(auth.loginRequestUrl)}`);
      }
      await zapApi("/JSON/authentication/action/setAuthenticationMethod/", {
        contextId,
        authMethodName: "formBasedAuthentication",
        authMethodConfigParams: authMethodParams.join("&")
      }, cfg);
      break;
    }
    case "json_api": {
      const loginData = auth.loginRequestData || JSON.stringify({
        [auth.usernameField || "username"]: "{%username%}",
        [auth.passwordField || "password"]: "{%password%}"
      });
      await zapApi("/JSON/authentication/action/setAuthenticationMethod/", {
        contextId,
        authMethodName: "jsonBasedAuthentication",
        authMethodConfigParams: [
          `loginUrl=${encodeURIComponent(auth.loginRequestUrl || auth.loginUrl)}`,
          `loginRequestData=${encodeURIComponent(loginData)}`
        ].join("&")
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
          `realm=`
        ].join("&")
      }, cfg);
      break;
    }
    case "bearer_token": {
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
          initiators: ""
        }, cfg);
      }
      break;
    }
    case "manual_browse": {
      await zapApi("/JSON/authentication/action/setAuthenticationMethod/", {
        contextId,
        authMethodName: "manualAuthentication"
      }, cfg);
      break;
    }
  }
  if (auth.loggedInIndicator) {
    await zapApi("/JSON/authentication/action/setLoggedInIndicator/", {
      contextId,
      loggedInIndicatorRegex: auth.loggedInIndicator
    }, cfg);
  }
  if (auth.loggedOutIndicator) {
    await zapApi("/JSON/authentication/action/setLoggedOutIndicator/", {
      contextId,
      loggedOutIndicatorRegex: auth.loggedOutIndicator
    }, cfg);
  }
  for (const cred of auth.credentials) {
    try {
      const userResult = await zapApi("/JSON/users/action/newUser/", {
        contextId,
        name: cred.username
      }, cfg);
      const userId = String(userResult.userId);
      if (auth.type === "form_based" || auth.type === "json_api") {
        await zapApi("/JSON/users/action/setAuthenticationCredentials/", {
          contextId,
          userId,
          authCredentialsConfigParams: `username=${encodeURIComponent(cred.username)}&password=${encodeURIComponent(cred.password)}`
        }, cfg);
      } else if (auth.type === "http_basic") {
        await zapApi("/JSON/users/action/setAuthenticationCredentials/", {
          contextId,
          userId,
          authCredentialsConfigParams: `username=${encodeURIComponent(cred.username)}&password=${encodeURIComponent(cred.password)}`
        }, cfg);
      }
      await zapApi("/JSON/users/action/setUserEnabled/", {
        contextId,
        userId,
        enabled: "true"
      }, cfg);
      await zapApi("/JSON/forcedUser/action/setForcedUser/", {
        contextId,
        userId
      }, cfg);
      console.log(`[ZAP Auth] Added user ${cred.username} (role: ${cred.role || "default"}) to context`);
    } catch (err) {
      console.warn(`[ZAP Auth] Failed to add user ${cred.username}: ${err.message}`);
    }
  }
  await zapApi("/JSON/forcedUser/action/setForcedUserModeEnabled/", {
    boolean: "true"
  }, cfg).catch(() => {
  });
  if (auth.antiCsrfTokenName) {
    await zapApi("/JSON/acsrf/action/addOptionToken/", {
      String: auth.antiCsrfTokenName
    }, cfg).catch(() => {
    });
  }
  console.log(`[ZAP Auth] Authentication configured for context ${contextName}`);
}
function generateBrowserInstructions(proxyHost, proxyPort, zapBaseUrl) {
  return {
    chrome: [
      `1. Open Chrome with proxy flag:`,
      `   google-chrome --proxy-server="${proxyHost}:${proxyPort}" --ignore-certificate-errors`,
      ``,
      `   Or configure manually:`,
      `   Settings \u2192 System \u2192 Open proxy settings`,
      `   Set HTTP/HTTPS proxy to ${proxyHost}:${proxyPort}`,
      ``,
      `2. Install ZAP CA Certificate for HTTPS interception:`,
      `   Navigate to ${zapBaseUrl}/OTHER/core/other/rootcert/`,
      `   Save the certificate, then import in:`,
      `   Settings \u2192 Privacy and Security \u2192 Manage Certificates \u2192 Authorities \u2192 Import`,
      `   Check "Trust this certificate for identifying websites"`
    ].join("\n"),
    firefox: [
      `1. Open Firefox Preferences \u2192 Network Settings \u2192 Settings`,
      `   Select "Manual proxy configuration"`,
      `   HTTP Proxy: ${proxyHost}  Port: ${proxyPort}`,
      `   Check "Also use this proxy for HTTPS"`,
      ``,
      `2. Install ZAP CA Certificate:`,
      `   Navigate to ${zapBaseUrl}/OTHER/core/other/rootcert/`,
      `   Firefox will prompt to trust \u2014 check "Trust this CA to identify websites"`,
      `   Or: Preferences \u2192 Privacy & Security \u2192 View Certificates \u2192 Import`
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
      `  netsh winhttp set proxy ${proxyHost}:${proxyPort}`
    ].join("\n"),
    curlCommand: `curl -x http://${proxyHost}:${proxyPort} -k https://target.example.com`,
    pythonRequests: [
      `import requests`,
      `proxies = {`,
      `    "http": "http://${proxyHost}:${proxyPort}",`,
      `    "https": "http://${proxyHost}:${proxyPort}",`,
      `}`,
      `response = requests.get("https://target.example.com", proxies=proxies, verify=False)`
    ].join("\n")
  };
}
async function startAuthenticatedCrawl(sessionId, options) {
  const session = activeSessions.get(sessionId);
  if (!session) throw new Error(`Proxy session ${sessionId} not found`);
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...options?.zapConfig };
  session.status = "crawling";
  const spiderResult = await zapApi("/JSON/spider/action/scan/", {
    url: session.targetUrl,
    maxChildren: String(options?.maxChildren || 20),
    recurse: "true",
    contextName: session.contextName,
    subtreeOnly: String(options?.subtreeOnly || false)
  }, cfg);
  const spiderScanId = String(spiderResult.scan);
  let ajaxSpiderStarted = false;
  if (options?.useAjaxSpider) {
    try {
      await zapApi("/JSON/ajaxSpider/action/scan/", {
        url: session.targetUrl,
        inScope: "true",
        contextName: session.contextName,
        subtreeOnly: String(options?.subtreeOnly || false)
      }, cfg);
      ajaxSpiderStarted = true;
    } catch (err) {
      console.warn(`[ZAP Proxy] AJAX spider failed to start: ${err.message}`);
    }
  }
  console.log(`[ZAP Proxy] Authenticated crawl started \u2014 spider ${spiderScanId}, AJAX: ${ajaxSpiderStarted}`);
  return {
    spiderScanId,
    ajaxSpiderStarted,
    contextId: session.contextId
  };
}
async function getProxyHistory(options) {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...options?.zapConfig };
  const result = await zapApi("/JSON/core/view/messages/", {
    baseurl: "",
    start: String(options?.start || 0),
    count: String(options?.count || 100)
  }, cfg);
  const messages = (result.messages || []).map((msg) => ({
    id: msg.id,
    timestamp: msg.timestamp,
    method: msg.requestHeader?.split(" ")[0] || "GET",
    url: msg.requestHeader?.split(" ")[1] || "",
    statusCode: parseInt(msg.responseHeader?.split(" ")[1] || "0", 10),
    responseLength: parseInt(msg.responseBody?.length || "0", 10),
    rtt: parseInt(msg.rtt || "0", 10),
    tags: msg.tags || [],
    note: msg.note || ""
  }));
  return {
    messages,
    totalCount: messages.length
  };
}
async function getCaCertificate(zapConfig) {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...zapConfig };
  try {
    const response = await fetch(`${cfg.baseUrl}/OTHER/core/other/rootcert/?apikey=${cfg.apiKey}`, {
      signal: AbortSignal.timeout(1e4)
    });
    const certPem = await response.text();
    return {
      certPem,
      downloadUrl: `${cfg.baseUrl}/OTHER/core/other/rootcert/`
    };
  } catch {
    return {
      certPem: "",
      downloadUrl: `${cfg.baseUrl}/OTHER/core/other/rootcert/`
    };
  }
}
async function applyWafEvasionSettings(wafAssessment, zapConfig) {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...zapConfig };
  if (!wafAssessment.wafDetected) {
    return {
      applied: false,
      preset: "none",
      settings: WAF_EVASION_PRESETS.default,
      scanTuning: {
        threadCount: 5,
        delayMs: 20,
        maxRps: 50,
        evasionTechniques: []
      }
    };
  }
  const vendorKey = (wafAssessment.wafVendor || "").toLowerCase().replace(/\s+/g, "_").replace(/[^a-z0-9_]/g, "");
  const preset = WAF_EVASION_PRESETS[vendorKey] || WAF_EVASION_PRESETS.default;
  const settings = {
    detectedWaf: wafAssessment.wafVendor,
    requestDelayMs: preset.requestDelayMs || 500,
    maxRequestsPerSecond: preset.maxRequestsPerSecond || 10,
    rotateUserAgents: preset.rotateUserAgents || false,
    randomizeQueryParams: preset.randomizeQueryParams || false,
    useChunkedEncoding: false,
    doubleUrlEncode: preset.doubleUrlEncode || false,
    jitterMs: preset.jitterMs || 200,
    caseVariation: preset.caseVariation || false,
    commentInsertion: preset.commentInsertion || false
  };
  const threadCount = Math.max(1, Math.min(5, Math.floor(settings.maxRequestsPerSecond / 2)));
  await zapApi("/JSON/ascan/action/setOptionDelayInMs/", {
    Integer: String(settings.requestDelayMs)
  }, cfg).catch(() => {
  });
  await zapApi("/JSON/ascan/action/setOptionThreadPerHost/", {
    Integer: String(threadCount)
  }, cfg).catch(() => {
  });
  await zapApi("/JSON/spider/action/setOptionRequestWaitTime/", {
    Integer: String(settings.requestDelayMs)
  }, cfg).catch(() => {
  });
  if (settings.rotateUserAgents) {
    const randomUA = DEFAULT_USER_AGENTS[Math.floor(Math.random() * DEFAULT_USER_AGENTS.length)];
    await zapApi("/JSON/core/action/setOptionDefaultUserAgent/", {
      String: randomUA
    }, cfg).catch(() => {
    });
  }
  const evasionTechniques = [];
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
      evasionTechniques
    }
  };
}
async function getProxySessionStatus(sessionId, zapConfig) {
  const session = activeSessions.get(sessionId);
  if (!session) return null;
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...zapConfig };
  const proxyAddress = session.proxyConfig.listenAddress === "0.0.0.0" ? cfg.baseUrl.replace(/https?:\/\//, "").replace(/:\d+$/, "") : session.proxyConfig.listenAddress;
  let interceptedHosts = [];
  try {
    const sites = await zapApi("/JSON/core/view/sites/", {}, cfg);
    interceptedHosts = sites.sites || [];
  } catch {
  }
  let activeUsers = [];
  try {
    const users = await zapApi("/JSON/users/view/usersList/", { contextId: session.contextId }, cfg);
    activeUsers = (users.usersList || []).map((u) => u.name);
  } catch {
  }
  try {
    const stats = await zapApi("/JSON/core/view/numberOfMessages/", {}, cfg);
    session.requestsProxied = parseInt(stats.numberOfMessages || "0", 10);
  } catch {
  }
  return {
    session,
    proxyAddress,
    proxyPort: session.proxyConfig.listenPort,
    caCertUrl: `${cfg.baseUrl}/OTHER/core/other/rootcert/`,
    pacFileUrl: `${cfg.baseUrl}/OTHER/core/other/proxy.pac/`,
    browserConfigInstructions: generateBrowserInstructions(proxyAddress, session.proxyConfig.listenPort, cfg.baseUrl),
    interceptedHosts,
    activeUsers
  };
}
async function stopProxySession(sessionId, zapConfig) {
  const session = activeSessions.get(sessionId);
  if (!session) return { success: false, requestsProxied: 0, urlsIntercepted: 0 };
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...zapConfig };
  await zapApi("/JSON/forcedUser/action/setForcedUserModeEnabled/", {
    boolean: "false"
  }, cfg).catch(() => {
  });
  session.status = "completed";
  const result = {
    success: true,
    requestsProxied: session.requestsProxied,
    urlsIntercepted: session.urlsIntercepted
  };
  activeSessions.delete(sessionId);
  console.log(`[ZAP Proxy] Session ${sessionId} stopped \u2014 ${result.requestsProxied} requests proxied`);
  return result;
}
function listActiveSessions() {
  return Array.from(activeSessions.values());
}
async function detectLoginConfiguration(loginPageUrl, zapConfig) {
  const cfg = { ...DEFAULT_ZAP_CONFIG, ...zapConfig };
  try {
    const response = await fetch(loginPageUrl, {
      headers: {
        "User-Agent": DEFAULT_USER_AGENTS[0],
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      },
      signal: AbortSignal.timeout(15e3)
    });
    const html = await response.text();
    const headers = Object.fromEntries(response.headers.entries());
    const { invokeLLM } = await import("./llm-4VYDOXOJ.js");
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
  "csrfTokenRegex": "name=\\"_csrf\\" value=\\"([^"]+)\\"",
  "loggedInIndicator": "\\\\QDashboard\\\\E|\\\\QLogout\\\\E|\\\\QMy Account\\\\E",
  "loggedOutIndicator": "\\\\QLogin\\\\E|\\\\QSign In\\\\E",
  "sessionCookies": ["JSESSIONID"],
  "hasAntiBot": false,
  "antiBotType": null,
  "confidence": 0.85,
  "analysis": "Brief analysis of the login mechanism"
}`
        },
        {
          role: "user",
          content: `Analyze this login page at ${loginPageUrl}:

HTTP Headers:
${JSON.stringify(headers, null, 2)}

HTML (first 5000 chars):
${html.substring(0, 5e3)}`
        }
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
              analysis: { type: "string" }
            },
            required: [
              "authType",
              "loginFormAction",
              "usernameField",
              "passwordField",
              "csrfTokenName",
              "csrfTokenRegex",
              "loggedInIndicator",
              "loggedOutIndicator",
              "sessionCookies",
              "hasAntiBot",
              "antiBotType",
              "confidence",
              "analysis"
            ],
            additionalProperties: false
          }
        }
      }
    });
    const parsed = JSON.parse(llmResponse.choices[0].message.content || "{}");
    const authConfig = {
      type: parsed.authType || "form_based",
      loginUrl: loginPageUrl,
      loginRequestUrl: parsed.loginFormAction ? new URL(parsed.loginFormAction, loginPageUrl).toString() : loginPageUrl,
      usernameField: parsed.usernameField || "username",
      passwordField: parsed.passwordField || "password",
      credentials: [],
      // To be filled by the operator
      loggedInIndicator: parsed.loggedInIndicator || void 0,
      loggedOutIndicator: parsed.loggedOutIndicator || void 0,
      csrfTokenName: parsed.csrfTokenName || void 0,
      csrfTokenRegex: parsed.csrfTokenRegex || void 0,
      antiCsrfTokenName: parsed.csrfTokenName || void 0
    };
    return {
      detected: true,
      authConfig,
      analysis: parsed.analysis || "Login page analyzed successfully",
      confidence: parsed.confidence || 0.5
    };
  } catch (err) {
    return {
      detected: false,
      authConfig: null,
      analysis: `Failed to analyze login page: ${err.message}`,
      confidence: 0
    };
  }
}
function getWafEvasionPresets() {
  return Object.entries(WAF_EVASION_PRESETS).map(([vendor, preset]) => {
    const techniques = [];
    if (preset.rotateUserAgents) techniques.push("UA rotation");
    if (preset.randomizeQueryParams) techniques.push("Query randomization");
    if (preset.doubleUrlEncode) techniques.push("Double URL encoding");
    if (preset.caseVariation) techniques.push("Case variation");
    if (preset.commentInsertion) techniques.push("Comment insertion");
    return {
      vendor,
      requestDelay: preset.requestDelayMs || 500,
      maxRps: preset.maxRequestsPerSecond || 10,
      techniques
    };
  });
}
export {
  applyWafEvasionSettings,
  detectLoginConfiguration,
  getCaCertificate,
  getProxyHistory,
  getProxySessionStatus,
  getWafEvasionPresets,
  initializeProxySession,
  listActiveSessions,
  startAuthenticatedCrawl,
  stopProxySession
};
