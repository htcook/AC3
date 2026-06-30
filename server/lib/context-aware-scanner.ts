/**
 * Context-Aware Scanning Engine
 *
 * Provides intelligent target profiling, WAF/CDN/firewall detection,
 * topology classification, and adaptive scan strategy selection.
 *
 * The engine builds a TargetProfile from initial reconnaissance data,
 * then generates an optimized ScanStrategy that respects scope constraints
 * and adapts to detected boundary protections.
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export interface TargetFingerprint {
  /** Raw server header (e.g., "nginx/1.21.3") */
  serverHeader: string | null;
  /** Detected web server software */
  webServer: { name: string; version: string | null; role: "origin" | "proxy" | "cdn_edge" | "load_balancer" | "api_gateway" | "unknown" } | null;
  /** Detected application framework */
  appFramework: { name: string; version: string | null; language: string } | null;
  /** Detected CMS or platform */
  cms: { name: string; version: string | null } | null;
  /** Operating system fingerprint */
  os: { name: string; version: string | null; arch: string | null } | null;
  /** TLS/SSL information */
  tls: {
    version: string;
    cipher: string | null;
    certIssuer: string | null;
    certExpiry: string | null;
    hsts: boolean;
    protocols: string[];
  } | null;
  /** Detected programming languages */
  languages: string[];
  /** Detected JavaScript frameworks (frontend) */
  jsFrameworks: string[];
  /** Database indicators */
  databases: string[];
  /** Raw technology tags from httpx/wappalyzer */
  techTags: string[];
  /** Service banners from Nerva/naabu */
  serviceBanners: Record<number, { service: string; version: string | null; banner: string | null; protocol: string }>;
}

export interface WAFProfile {
  /** Whether a WAF is detected */
  detected: boolean;
  /** WAF vendor/product name */
  vendor: string | null;
  /** WAF type classification */
  type: "cloud_waf" | "appliance_waf" | "host_waf" | "api_gateway_waf" | "unknown";
  /** Confidence level (0-100) */
  confidence: number;
  /** Detection method used */
  detectionMethod: string;
  /** Known bypass techniques for this WAF */
  bypassTechniques: string[];
  /** Recommended evasion profile */
  evasionProfile: EvasionProfile;
  /** Whether the WAF itself is in scope for testing */
  inScope: boolean;
  /** Specific rules/signatures detected */
  detectedRules: string[];
}

export interface CDNProfile {
  /** Whether a CDN is detected */
  detected: boolean;
  /** CDN provider name */
  provider: string | null;
  /** CDN detection evidence */
  evidence: string[];
  /** Discovered origin IP (if found) */
  originIp: string | null;
  /** Origin discovery method */
  originDiscoveryMethod: string | null;
  /** Whether origin is in scope for direct testing */
  originInScope: boolean;
  /** CDN-specific headers observed */
  cdnHeaders: Record<string, string>;
  /** Whether the CDN provides its own WAF */
  hasBuiltInWAF: boolean;
}

export interface FirewallProfile {
  /** Whether a firewall is detected between scanner and target */
  detected: boolean;
  /** Firewall type */
  type: "network_firewall" | "host_firewall" | "cloud_security_group" | "unknown";
  /** Filtered ports detected */
  filteredPorts: number[];
  /** Rate limiting detected */
  rateLimiting: { detected: boolean; requestsPerSecond: number | null; burstLimit: number | null };
  /** Geo-blocking detected */
  geoBlocking: boolean;
  /** IP reputation blocking */
  ipReputationBlocking: boolean;
}

export interface EvasionProfile {
  /** Profile name */
  name: string;
  /** Rate limit (requests per second) */
  rateLimit: number;
  /** Delay between requests (ms) */
  delayMs: number;
  /** Whether to randomize request order */
  randomizeOrder: boolean;
  /** User-Agent rotation strategy */
  userAgentStrategy: "rotate" | "browser_mimic" | "mobile" | "bot" | "custom";
  /** Custom User-Agent string */
  customUserAgent?: string;
  /** HTTP method preferences */
  httpMethodPreferences: string[];
  /** Encoding tricks to try */
  encodingTricks: string[];
  /** Header manipulation */
  headerManipulation: Record<string, string>;
  /** Whether to use chunked transfer encoding */
  chunkedTransfer: boolean;
  /** Whether to use HTTP/2 */
  useHttp2: boolean;
  /** IP rotation strategy */
  ipRotation: "none" | "proxy_chain" | "tor" | "cloud_functions";
  /** Specific WAF bypass payloads */
  wafBypassPayloads: string[];
}

export type AssetRole =
  | "web_application"
  | "api_gateway"
  | "reverse_proxy"
  | "load_balancer"
  | "cdn_edge"
  | "mail_server"
  | "dns_server"
  | "database_server"
  | "file_server"
  | "vpn_gateway"
  | "bastion_host"
  | "iot_device"
  | "embedded_system"
  | "container_host"
  | "cloud_service"
  | "unknown";

export interface TopologyNode {
  /** Asset hostname or IP */
  host: string;
  /** Classified role */
  role: AssetRole;
  /** Confidence in role classification (0-100) */
  confidence: number;
  /** What sits behind this node (if it's a proxy/LB/CDN) */
  backend: TopologyNode | null;
  /** Open ports and their services */
  services: { port: number; service: string; version: string | null }[];
  /** Whether this node is directly reachable */
  directlyReachable: boolean;
}

export interface TargetProfile {
  /** Primary hostname */
  hostname: string;
  /** Resolved IP addresses */
  ips: string[];
  /** Full fingerprint data */
  fingerprint: TargetFingerprint;
  /** WAF detection results */
  waf: WAFProfile;
  /** CDN detection results */
  cdn: CDNProfile;
  /** Firewall detection results */
  firewall: FirewallProfile;
  /** Network topology */
  topology: TopologyNode;
  /** Environment classification */
  environment: "traditional" | "cloud" | "containerized" | "serverless" | "iot" | "hybrid";
  /** Overall risk profile */
  riskProfile: "high_security" | "standard" | "legacy" | "development" | "unknown";
  /** Scope constraints */
  scopeConstraints: ScopeConstraints;
  /** Recommended scan strategy */
  recommendedStrategy: ScanStrategy;
  /** Profiling timestamp */
  profiledAt: number;
}

export interface ScopeConstraints {
  /** Whether WAF bypass testing is authorized */
  wafBypassAuthorized: boolean;
  /** Whether CDN origin direct testing is authorized */
  cdnOriginAuthorized: boolean;
  /** Whether credential brute forcing is authorized */
  bruteForceAuthorized: boolean;
  /** Whether DoS testing is authorized */
  dosTestingAuthorized: boolean;
  /** Whether social engineering is authorized */
  socialEngineeringAuthorized: boolean;
  /** Maximum scan rate (requests/second) */
  maxScanRate: number;
  /** Allowed scan hours (24h format) */
  allowedHours: { start: number; end: number } | null;
  /** Excluded paths/endpoints */
  excludedPaths: string[];
  /** Excluded ports */
  excludedPorts: number[];
  /** Whether shared infrastructure was identified */
  sharedInfrastructure: boolean;
  /** Engagement type affects what's in scope */
  engagementType: "pentest" | "red_team" | "vuln_assessment" | "bug_bounty";
}

export interface ScanStrategy {
  /** Strategy name */
  name: string;
  /** Ordered list of scan phases */
  phases: ScanPhase[];
  /** Global evasion profile */
  evasionProfile: EvasionProfile;
  /** Estimated total scan time (minutes) */
  estimatedTimeMinutes: number;
  /** Risk level of this strategy */
  riskLevel: "low" | "medium" | "high";
  /** Rationale for this strategy */
  rationale: string;
}

export interface ScanPhase {
  /** Phase name */
  name: string;
  /** Tools to use in this phase */
  tools: { tool: string; flags: string; purpose: string }[];
  /** Dependencies (phase names that must complete first) */
  dependsOn: string[];
  /** Expected output type */
  outputType: "ports" | "services" | "vulns" | "credentials" | "evidence" | "fingerprints";
  /** Whether this phase requires operator approval */
  requiresApproval: boolean;
}

// ─── WAF Signatures ──────────────────────────────────────────────────────

const WAF_SIGNATURES: Record<string, { headers: string[]; cookies: string[]; bodyPatterns: string[]; bypassTechniques: string[] }> = {
  cloudflare: {
    headers: ["cf-ray", "cf-cache-status", "cf-request-id", "server: cloudflare"],
    cookies: ["__cfduid", "__cf_bm", "cf_clearance"],
    bodyPatterns: ["Attention Required! | Cloudflare", "cf-error-details", "cloudflare-nginx"],
    bypassTechniques: [
      "Use origin IP directly (find via DNS history, cert transparency, email headers)",
      "Unicode normalization bypass: replace / with ⁄ (U+2044)",
      "Chunked transfer encoding with comment injection",
      "HTTP/2 CONTINUATION frame abuse",
      "Case variation in SQL keywords (SeLeCt, UnIoN)",
      "Double URL encoding for path traversal",
      "JSON content-type with SQL in values",
      "Multipart/form-data boundary manipulation",
    ],
  },
  akamai: {
    headers: ["x-akamai-transformed", "akamai-grn", "x-akamai-request-id", "x-akamai-session-info"],
    cookies: ["akamai_generated_", "AkaSid", "bm_sz", "ak_bmsc", "_abck"],
    bodyPatterns: ["Access Denied", "Reference #", "akamaiedge"],
    bypassTechniques: [
      "Parameter pollution (duplicate params with different values)",
      "HTTP method override headers (X-HTTP-Method-Override)",
      "Null byte injection in parameters",
      "Tab character injection between SQL keywords",
      "Overlong UTF-8 encoding",
      "Request smuggling via CL.TE or TE.CL",
    ],
  },
  aws_waf: {
    headers: ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id"],
    cookies: ["AWSALB", "AWSALBCORS", "aws-waf-token"],
    bodyPatterns: ["403 Forbidden", "Request blocked"],
    bypassTechniques: [
      "Unicode normalization (AWS WAF v1 doesn't normalize)",
      "JSON body with nested objects to bypass regex rules",
      "Multiline payloads in headers",
      "HTTP/2 pseudo-headers manipulation",
      "Alternate IP representation (decimal, hex, octal)",
    ],
  },
  modsecurity: {
    headers: ["server: apache", "server: nginx"],
    cookies: [],
    bodyPatterns: ["ModSecurity", "OWASP_CRS", "SecRule", "mod_security", "Not Acceptable"],
    bypassTechniques: [
      "Identify CRS version (v3.x vs v4.x have different bypass surfaces)",
      "Paranoia level detection (PL1-PL4 have different rule sets)",
      "Comment injection in SQL (/*!50000 SELECT*/)",
      "HPP (HTTP Parameter Pollution) for PHP backends",
      "Alternate function names (CHAR() instead of CHR())",
      "Scientific notation for numeric injection",
      "Case mixing with inline comments",
    ],
  },
  imperva: {
    headers: ["x-iinfo", "x-cdn"],
    cookies: ["incap_ses_", "visid_incap_", "nlbi_"],
    bodyPatterns: ["Incapsula", "incident", "_Incapsula_Resource"],
    bypassTechniques: [
      "Slow-rate attacks (below detection threshold)",
      "Fragment payloads across multiple parameters",
      "Use CNAME uncloaking to find origin",
      "HTTP desync / request smuggling",
      "Alternate encodings (base64 in headers)",
    ],
  },
  f5_bigip: {
    headers: ["server: bigip", "x-cnection"],
    cookies: ["BIGipServer", "TS", "f5_cspm"],
    bodyPatterns: ["The requested URL was rejected", "BIG-IP"],
    bypassTechniques: [
      "HTTP desync via Content-Length / Transfer-Encoding mismatch",
      "Cookie manipulation (BIGipServer cookie reveals backend pool info)",
      "Path normalization differences between F5 and backend",
      "Websocket upgrade bypass",
    ],
  },
  fortinet: {
    headers: ["server: fortiweb"],
    cookies: ["FORTIWAFSID", "cookiesession1"],
    bodyPatterns: ["FortiWeb", "FortiGuard", "fgd_icon"],
    bypassTechniques: [
      "Unicode normalization bypass",
      "Chunked transfer with small chunks",
      "HTTP/2 multiplexing to bypass rate limits",
      "Path traversal via backslash on Windows backends",
    ],
  },
  sucuri: {
    headers: ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"],
    cookies: ["sucuri_cloudproxy_uuid"],
    bodyPatterns: ["Sucuri WebSite Firewall", "Access Denied - Sucuri", "sucuri.net"],
    bypassTechniques: [
      "Find origin via DNS history (SecurityTrails, ViewDNS)",
      "Email header analysis for origin IP",
      "Subdomain enumeration for unprotected subdomains",
      "HTTP method switching (POST instead of GET)",
    ],
  },
};

// ─── CDN Signatures ──────────────────────────────────────────────────────

const CDN_SIGNATURES: Record<string, { headers: string[]; cnames: string[]; hasBuiltInWAF: boolean }> = {
  cloudflare: {
    headers: ["cf-ray", "cf-cache-status"],
    cnames: ["cdn.cloudflare.net", "cloudflare.com"],
    hasBuiltInWAF: true,
  },
  akamai: {
    headers: ["x-akamai-transformed", "akamai-grn"],
    cnames: ["akamaiedge.net", "akamai.net", "edgesuite.net", "edgekey.net"],
    hasBuiltInWAF: true,
  },
  cloudfront: {
    headers: ["x-amz-cf-id", "x-amz-cf-pop", "via: CloudFront"],
    cnames: ["cloudfront.net", "d1.awsstatic.com"],
    hasBuiltInWAF: false, // AWS WAF is separate
  },
  fastly: {
    headers: ["x-served-by", "x-cache", "x-timer", "fastly-restarts"],
    cnames: ["fastly.net", "fastlylb.net"],
    hasBuiltInWAF: true,
  },
  azure_cdn: {
    headers: ["x-msedge-ref", "x-azure-ref"],
    cnames: ["azureedge.net", "trafficmanager.net", "azure.com"],
    hasBuiltInWAF: false,
  },
  google_cloud_cdn: {
    headers: ["via: google", "x-goog-*"],
    cnames: ["googleapis.com", "googleusercontent.com", "1e100.net"],
    hasBuiltInWAF: false,
  },
  incapsula: {
    headers: ["x-iinfo", "x-cdn: Incapsula"],
    cnames: ["incapdns.net"],
    hasBuiltInWAF: true,
  },
};

// ─── Server Role Classification ──────────────────────────────────────────

const SERVER_ROLE_INDICATORS: Record<AssetRole, { serverHeaders: string[]; ports: number[]; paths: string[]; headers: string[] }> = {
  reverse_proxy: {
    serverHeaders: ["nginx", "haproxy", "traefik", "envoy", "caddy", "varnish"],
    ports: [80, 443, 8080, 8443],
    paths: [],
    headers: ["x-forwarded-for", "x-real-ip", "x-forwarded-proto", "via"],
  },
  api_gateway: {
    serverHeaders: ["kong", "tyk", "apigee", "aws-apigateway"],
    ports: [80, 443, 8000, 8443, 9080],
    paths: ["/api/", "/v1/", "/v2/", "/graphql", "/swagger", "/openapi"],
    headers: ["x-ratelimit-limit", "x-ratelimit-remaining", "x-api-key"],
  },
  load_balancer: {
    serverHeaders: ["awselb", "haproxy", "f5", "citrix", "a10"],
    ports: [80, 443],
    paths: [],
    headers: ["x-forwarded-for", "x-forwarded-port"],
  },
  mail_server: {
    serverHeaders: ["postfix", "exim", "sendmail", "exchange", "dovecot"],
    ports: [25, 110, 143, 465, 587, 993, 995],
    paths: [],
    headers: [],
  },
  dns_server: {
    serverHeaders: ["bind", "unbound", "powerdns", "knot"],
    ports: [53],
    paths: [],
    headers: [],
  },
  vpn_gateway: {
    serverHeaders: ["openvpn", "strongswan", "wireguard"],
    ports: [500, 1194, 4500, 51820, 1723],
    paths: [],
    headers: [],
  },
  bastion_host: {
    serverHeaders: ["openssh"],
    ports: [22, 2222, 3389],
    paths: [],
    headers: [],
  },
  database_server: {
    serverHeaders: ["mysql", "postgresql", "mongodb", "redis", "mssql"],
    ports: [3306, 5432, 27017, 6379, 1433, 1521],
    paths: [],
    headers: [],
  },
  file_server: {
    serverHeaders: ["samba", "proftpd", "vsftpd", "pure-ftpd"],
    ports: [21, 22, 139, 445, 2049],
    paths: [],
    headers: [],
  },
  web_application: {
    serverHeaders: [],
    ports: [80, 443, 8080, 8443, 3000, 5000, 8000],
    paths: ["/login", "/register", "/dashboard", "/admin"],
    headers: ["set-cookie", "x-powered-by"],
  },
  cdn_edge: {
    serverHeaders: ["cloudflare", "akamai", "fastly", "cloudfront"],
    ports: [80, 443],
    paths: [],
    headers: ["cf-ray", "x-cache", "x-amz-cf-id"],
  },
  iot_device: {
    serverHeaders: ["lighttpd", "boa", "goahead", "mini_httpd", "uhttpd"],
    ports: [80, 443, 8080, 23, 8443],
    paths: ["/cgi-bin/", "/HNAP1/"],
    headers: [],
  },
  embedded_system: {
    serverHeaders: ["thttpd", "micro_httpd", "busybox"],
    ports: [80, 23, 8080],
    paths: [],
    headers: [],
  },
  container_host: {
    serverHeaders: [],
    ports: [2375, 2376, 6443, 10250],
    paths: ["/v2/", "/_catalog"],
    headers: ["docker-distribution-api-version"],
  },
  cloud_service: {
    serverHeaders: [],
    ports: [80, 443],
    paths: [],
    headers: ["x-amzn-requestid", "x-goog-*", "x-ms-request-id"],
  },
  unknown: {
    serverHeaders: [],
    ports: [],
    paths: [],
    headers: [],
  },
};

// ─── Evasion Profiles ────────────────────────────────────────────────────

const EVASION_PROFILES: Record<string, EvasionProfile> = {
  stealth: {
    name: "Stealth",
    rateLimit: 1,
    delayMs: 2000,
    randomizeOrder: true,
    userAgentStrategy: "browser_mimic",
    httpMethodPreferences: ["GET", "HEAD"],
    encodingTricks: ["double_url_encode", "unicode_normalize"],
    headerManipulation: {
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
      "Accept-Encoding": "gzip, deflate, br",
      "Connection": "keep-alive",
      "Upgrade-Insecure-Requests": "1",
    },
    chunkedTransfer: false,
    useHttp2: true,
    ipRotation: "none",
    wafBypassPayloads: [],
  },
  moderate: {
    name: "Moderate",
    rateLimit: 5,
    delayMs: 500,
    randomizeOrder: true,
    userAgentStrategy: "rotate",
    httpMethodPreferences: ["GET", "POST", "HEAD"],
    encodingTricks: ["url_encode"],
    headerManipulation: {},
    chunkedTransfer: false,
    useHttp2: false,
    ipRotation: "none",
    wafBypassPayloads: [],
  },
  aggressive: {
    name: "Aggressive",
    rateLimit: 50,
    delayMs: 50,
    randomizeOrder: false,
    userAgentStrategy: "bot",
    httpMethodPreferences: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    encodingTricks: [],
    headerManipulation: {},
    chunkedTransfer: false,
    useHttp2: false,
    ipRotation: "none",
    wafBypassPayloads: [],
  },
  waf_bypass: {
    name: "WAF Bypass",
    rateLimit: 2,
    delayMs: 1500,
    randomizeOrder: true,
    userAgentStrategy: "browser_mimic",
    httpMethodPreferences: ["GET", "POST"],
    encodingTricks: [
      "double_url_encode",
      "unicode_normalize",
      "overlong_utf8",
      "null_byte_inject",
      "case_variation",
      "comment_injection",
      "chunked_split",
    ],
    headerManipulation: {
      "X-Forwarded-For": "127.0.0.1",
      "X-Originating-IP": "127.0.0.1",
      "X-Remote-IP": "127.0.0.1",
      "X-Remote-Addr": "127.0.0.1",
      "X-Custom-IP-Authorization": "127.0.0.1",
    },
    chunkedTransfer: true,
    useHttp2: true,
    ipRotation: "proxy_chain",
    wafBypassPayloads: [],
  },
};

// ─── Core Functions ──────────────────────────────────────────────────────

/**
 * Detect WAF from HTTP response headers, cookies, and body patterns
 */
export function detectWAF(
  responseHeaders: Record<string, string>,
  cookies: string[],
  responseBody: string,
  statusCode: number
): WAFProfile {
  const headersLower = Object.fromEntries(
    Object.entries(responseHeaders).map(([k, v]) => [k.toLowerCase(), v.toLowerCase()])
  );
  const cookiesLower = cookies.map(c => c.toLowerCase());
  const bodyLower = responseBody.toLowerCase();

  let bestMatch: { vendor: string; score: number } | null = null;

  for (const [vendor, sig] of Object.entries(WAF_SIGNATURES)) {
    let score = 0;

    // Check headers
    for (const h of sig.headers) {
      const [key, val] = h.includes(":") ? h.split(": ") : [h, null];
      if (val) {
        if (headersLower[key]?.includes(val)) score += 30;
      } else {
        if (key in headersLower) score += 25;
      }
    }

    // Check cookies
    for (const c of sig.cookies) {
      if (cookiesLower.some(ck => ck.includes(c.toLowerCase()))) score += 20;
    }

    // Check body patterns
    for (const p of sig.bodyPatterns) {
      if (bodyLower.includes(p.toLowerCase())) score += 15;
    }

    // Blocked status codes boost confidence
    if (statusCode === 403 || statusCode === 406 || statusCode === 429) {
      score += 10;
    }

    if (!bestMatch || score > bestMatch.score) {
      bestMatch = { vendor, score };
    }
  }

  if (bestMatch && bestMatch.score >= 25) {
    const sig = WAF_SIGNATURES[bestMatch.vendor];
    return {
      detected: true,
      vendor: bestMatch.vendor,
      type: ["cloudflare", "akamai", "aws_waf", "sucuri", "incapsula"].includes(bestMatch.vendor)
        ? "cloud_waf"
        : ["f5_bigip", "fortinet"].includes(bestMatch.vendor)
        ? "appliance_waf"
        : bestMatch.vendor === "modsecurity"
        ? "host_waf"
        : "unknown",
      confidence: Math.min(bestMatch.score, 100),
      detectionMethod: "header_cookie_body_analysis",
      bypassTechniques: sig.bypassTechniques,
      evasionProfile: { ...EVASION_PROFILES.waf_bypass, wafBypassPayloads: sig.bypassTechniques },
      inScope: false, // Must be explicitly set by engagement scope
      detectedRules: [],
    };
  }

  return {
    detected: false,
    vendor: null,
    type: "unknown",
    confidence: 0,
    detectionMethod: "none",
    bypassTechniques: [],
    evasionProfile: EVASION_PROFILES.moderate,
    inScope: false,
    detectedRules: [],
  };
}

/**
 * Detect CDN from HTTP response headers and DNS CNAME records
 */
export function detectCDN(
  responseHeaders: Record<string, string>,
  cnames: string[]
): CDNProfile {
  const headersLower = Object.fromEntries(
    Object.entries(responseHeaders).map(([k, v]) => [k.toLowerCase(), v.toLowerCase()])
  );
  const cnamesLower = cnames.map(c => c.toLowerCase());

  for (const [provider, sig] of Object.entries(CDN_SIGNATURES)) {
    let headerMatch = false;
    let cnameMatch = false;

    for (const h of sig.headers) {
      const [key, val] = h.includes(":") ? h.split(": ") : [h, null];
      if (val) {
        if (headersLower[key]?.includes(val)) headerMatch = true;
      } else {
        if (key.includes("*")) {
          const prefix = key.replace("*", "");
          if (Object.keys(headersLower).some(k => k.startsWith(prefix))) headerMatch = true;
        } else {
          if (key in headersLower) headerMatch = true;
        }
      }
    }

    for (const c of sig.cnames) {
      if (cnamesLower.some(cn => cn.includes(c))) cnameMatch = true;
    }

    if (headerMatch || cnameMatch) {
      const evidence: string[] = [];
      if (headerMatch) evidence.push("HTTP response headers match CDN signature");
      if (cnameMatch) evidence.push("DNS CNAME chain points to CDN infrastructure");

      const cdnHeaders: Record<string, string> = {};
      for (const h of sig.headers) {
        const key = h.includes(":") ? h.split(": ")[0] : h;
        if (!key.includes("*") && headersLower[key]) {
          cdnHeaders[key] = headersLower[key];
        }
      }

      return {
        detected: true,
        provider,
        evidence,
        originIp: null,
        originDiscoveryMethod: null,
        originInScope: false,
        cdnHeaders,
        hasBuiltInWAF: sig.hasBuiltInWAF,
      };
    }
  }

  return {
    detected: false,
    provider: null,
    evidence: [],
    originIp: null,
    originDiscoveryMethod: null,
    originInScope: false,
    cdnHeaders: {},
    hasBuiltInWAF: false,
  };
}

/**
 * Classify the role of a server based on its fingerprint
 */
export function classifyAssetRole(
  fingerprint: TargetFingerprint,
  openPorts: number[],
  responseHeaders: Record<string, string>
): { role: AssetRole; confidence: number; rationale: string } {
  const scores: { role: AssetRole; score: number; reasons: string[] }[] = [];

  for (const [role, indicators] of Object.entries(SERVER_ROLE_INDICATORS)) {
    let score = 0;
    const reasons: string[] = [];

    // Check server header
    if (fingerprint.serverHeader) {
      const serverLower = fingerprint.serverHeader.toLowerCase();
      for (const sh of indicators.serverHeaders) {
        if (serverLower.includes(sh)) {
          score += 30;
          reasons.push(`Server header contains "${sh}"`);
        }
      }
    }

    // Check ports
    const portOverlap = openPorts.filter(p => indicators.ports.includes(p));
    if (portOverlap.length > 0) {
      score += Math.min(portOverlap.length * 5, 20);
      reasons.push(`Open ports match: ${portOverlap.join(", ")}`);
    }

    // Check response headers
    const headersLower = Object.fromEntries(
      Object.entries(responseHeaders).map(([k, v]) => [k.toLowerCase(), v])
    );
    for (const h of indicators.headers) {
      if (h in headersLower) {
        score += 15;
        reasons.push(`Response header "${h}" present`);
      }
    }

    // Proxy detection: if we see forwarding headers AND a known proxy server
    if (role === "reverse_proxy") {
      const hasForwardHeaders = ["x-forwarded-for", "x-real-ip", "via"].some(h => h in headersLower);
      const hasProxyServer = fingerprint.serverHeader && /nginx|haproxy|traefik|envoy|caddy/i.test(fingerprint.serverHeader);
      if (hasForwardHeaders && hasProxyServer) {
        score += 25;
        reasons.push("Forwarding headers + proxy server detected");
      }
    }

    // Web application detection: if we see app framework or CMS
    if (role === "web_application") {
      if (fingerprint.appFramework) {
        score += 25;
        reasons.push(`Application framework detected: ${fingerprint.appFramework.name}`);
      }
      if (fingerprint.cms) {
        score += 30;
        reasons.push(`CMS detected: ${fingerprint.cms.name}`);
      }
    }

    scores.push({ role: role as AssetRole, score, reasons });
  }

  scores.sort((a, b) => b.score - a.score);
  const best = scores[0];

  if (best.score >= 20) {
    return {
      role: best.role,
      confidence: Math.min(best.score, 100),
      rationale: best.reasons.join("; "),
    };
  }

  return { role: "unknown", confidence: 0, rationale: "No strong indicators matched" };
}

/**
 * Select the optimal evasion profile based on detected protections
 */
export function selectEvasionProfile(
  waf: WAFProfile,
  cdn: CDNProfile,
  firewall: FirewallProfile,
  scopeConstraints: ScopeConstraints
): EvasionProfile {
  // Start with the most appropriate base profile
  let profile: EvasionProfile;

  if (waf.detected && scopeConstraints.wafBypassAuthorized) {
    profile = { ...waf.evasionProfile };
  } else if (waf.detected) {
    // WAF detected but bypass not authorized — use stealth to avoid triggering blocks
    profile = { ...EVASION_PROFILES.stealth };
  } else if (cdn.detected) {
    // CDN detected — moderate rate to avoid CDN-level blocking
    profile = { ...EVASION_PROFILES.moderate, rateLimit: 3, delayMs: 800 };
  } else if (firewall.rateLimiting.detected) {
    // Rate limiting detected — stay below threshold
    const maxRate = firewall.rateLimiting.requestsPerSecond || 5;
    profile = { ...EVASION_PROFILES.moderate, rateLimit: Math.max(1, maxRate - 2) };
  } else {
    profile = { ...EVASION_PROFILES.moderate };
  }

  // Apply scope constraints
  if (scopeConstraints.maxScanRate > 0) {
    profile.rateLimit = Math.min(profile.rateLimit, scopeConstraints.maxScanRate);
  }

  // Shared infrastructure — always use stealth
  if (scopeConstraints.sharedInfrastructure) {
    profile.rateLimit = Math.min(profile.rateLimit, 2);
    profile.delayMs = Math.max(profile.delayMs, 1500);
    profile.randomizeOrder = true;
  }

  return profile;
}

/**
 * Generate the recommended scan strategy based on the full target profile
 */
export function generateScanStrategy(
  profile: Omit<TargetProfile, "recommendedStrategy">,
): ScanStrategy {
  const phases: ScanPhase[] = [];
  const { fingerprint, waf, cdn, firewall, topology, scopeConstraints } = profile;

  // Phase 1: Port Discovery (always)
  phases.push({
    name: "port_discovery",
    tools: [
      { tool: "naabu", flags: `-top-ports 1000 -rate ${Math.min(100, scopeConstraints.maxScanRate * 10 || 100)}`, purpose: "Fast TCP port discovery" },
    ],
    dependsOn: [],
    outputType: "ports",
    requiresApproval: false,
  });

  // Phase 2: Service Fingerprinting (always)
  phases.push({
    name: "service_fingerprinting",
    tools: [
      { tool: "nerva", flags: "--target HOST --port DISCOVERED_PORTS", purpose: "Deep service fingerprinting (120+ protocols)" },
      { tool: "httpx", flags: "-td -sc -title -server -ct -cdn -fr -favicon", purpose: "HTTP service probing with tech detection" },
    ],
    dependsOn: ["port_discovery"],
    outputType: "fingerprints",
    requiresApproval: false,
  });

  // Phase 3: WAF/CDN Detection (if web services found)
  if (topology.services.some(s => [80, 443, 8080, 8443].includes(s.port))) {
    phases.push({
      name: "boundary_detection",
      tools: [
        { tool: "wafw00f", flags: "-a TARGET_URL", purpose: "WAF fingerprinting and classification" },
        ...(waf.detected && scopeConstraints.wafBypassAuthorized
          ? [{ tool: "nuclei", flags: "-t waf-detect/ -t technologies/", purpose: "WAF rule detection and technology profiling" }]
          : []),
      ],
      dependsOn: ["service_fingerprinting"],
      outputType: "fingerprints",
      requiresApproval: false,
    });
  }

  // Phase 4: TLS/SSL Audit (if HTTPS found)
  if (topology.services.some(s => [443, 8443, 993, 995, 465].includes(s.port))) {
    phases.push({
      name: "tls_audit",
      tools: [
        { tool: "testssl", flags: "--quiet --color 0 --jsonfile - TARGET:PORT", purpose: "Comprehensive TLS/SSL configuration audit" },
      ],
      dependsOn: ["service_fingerprinting"],
      outputType: "vulns",
      requiresApproval: false,
    });
  }

  // Phase 5: Service-Specific Auditing
  const serviceAuditTools: { tool: string; flags: string; purpose: string }[] = [];

  if (topology.services.some(s => s.service === "ssh" || s.port === 22)) {
    serviceAuditTools.push({ tool: "ssh-audit", flags: "TARGET:22", purpose: "SSH algorithm strength and CVE detection" });
  }
  if (topology.services.some(s => s.service === "ftp" || s.port === 21)) {
    serviceAuditTools.push({ tool: "hydra", flags: "-L users.txt -P pass.txt ftp://TARGET", purpose: "FTP credential testing" });
  }
  if (topology.services.some(s => s.service === "rdp" || s.port === 3389)) {
    serviceAuditTools.push({ tool: "nuclei", flags: "-t network/rdp/ TARGET", purpose: "RDP vulnerability scanning (BlueKeep, DejaBlue)" });
  }
  if (topology.services.some(s => s.service === "smb" || [139, 445].includes(s.port))) {
    serviceAuditTools.push({ tool: "netexec", flags: "smb TARGET --shares", purpose: "SMB share enumeration and access testing" });
  }

  if (serviceAuditTools.length > 0) {
    phases.push({
      name: "service_audit",
      tools: serviceAuditTools,
      dependsOn: ["service_fingerprinting"],
      outputType: "vulns",
      requiresApproval: false,
    });
  }

  // Phase 6: Vulnerability Scanning
  const vulnTools: { tool: string; flags: string; purpose: string }[] = [
    { tool: "nuclei", flags: "-severity critical,high,medium -rate-limit RATE", purpose: "Template-based vulnerability scanning" },
  ];

  if (topology.services.some(s => [80, 443, 8080, 8443].includes(s.port))) {
    vulnTools.push({ tool: "zap", flags: "active-scan TARGET_URL", purpose: "DAST scanning with full request/response evidence" });
    vulnTools.push({ tool: "katana", flags: "-u TARGET_URL -d 3 -jc", purpose: "JavaScript-aware web crawling for endpoint discovery" });
  }

  phases.push({
    name: "vulnerability_scanning",
    tools: vulnTools,
    dependsOn: ["service_fingerprinting", ...(phases.some(p => p.name === "boundary_detection") ? ["boundary_detection"] : [])],
    outputType: "vulns",
    requiresApproval: false,
  });

  // Phase 7: Credential Testing (if authorized)
  if (scopeConstraints.bruteForceAuthorized) {
    const credTools: { tool: string; flags: string; purpose: string }[] = [];

    if (topology.services.some(s => s.service === "ssh" || s.port === 22)) {
      credTools.push({ tool: "hydra", flags: "-L users.txt -P pass.txt ssh://TARGET -t 4", purpose: "SSH credential testing" });
    }
    if (topology.services.some(s => [80, 443].includes(s.port))) {
      credTools.push({ tool: "hydra", flags: "-L users.txt -P pass.txt http-post-form://TARGET", purpose: "Web login credential testing" });
    }

    if (credTools.length > 0) {
      phases.push({
        name: "credential_testing",
        tools: credTools,
        dependsOn: ["vulnerability_scanning"],
        outputType: "credentials",
        requiresApproval: true,
      });
    }
  }

  // Calculate estimated time
  const estimatedTimeMinutes = phases.reduce((total, phase) => {
    return total + phase.tools.length * 5; // rough estimate: 5 min per tool
  }, 0);

  const evasionProfile = selectEvasionProfile(waf, cdn, firewall, scopeConstraints);

  return {
    name: `${profile.environment}_${waf.detected ? "waf_aware" : "standard"}_scan`,
    phases,
    evasionProfile,
    estimatedTimeMinutes,
    riskLevel: scopeConstraints.bruteForceAuthorized ? "high" : waf.detected ? "medium" : "low",
    rationale: buildStrategyRationale(profile),
  };
}

function buildStrategyRationale(profile: Omit<TargetProfile, "recommendedStrategy">): string {
  const parts: string[] = [];

  parts.push(`Target classified as ${profile.topology.role} in ${profile.environment} environment.`);

  if (profile.waf.detected) {
    parts.push(`WAF detected: ${profile.waf.vendor} (${profile.waf.type}, ${profile.waf.confidence}% confidence). ${profile.scopeConstraints.wafBypassAuthorized ? "WAF bypass testing authorized." : "WAF bypass NOT authorized — using stealth approach."}`);
  }

  if (profile.cdn.detected) {
    parts.push(`CDN detected: ${profile.cdn.provider}. ${profile.cdn.originIp ? `Origin IP discovered: ${profile.cdn.originIp}` : "Origin IP not yet discovered."} ${profile.cdn.hasBuiltInWAF ? "CDN includes built-in WAF." : ""}`);
  }

  if (profile.firewall.rateLimiting.detected) {
    parts.push(`Rate limiting detected: ~${profile.firewall.rateLimiting.requestsPerSecond} req/s. Scan rate adjusted accordingly.`);
  }

  if (profile.scopeConstraints.sharedInfrastructure) {
    parts.push("CAUTION: Shared infrastructure detected — using conservative scan rates to avoid impacting other tenants.");
  }

  if (profile.fingerprint.appFramework) {
    parts.push(`Application framework: ${profile.fingerprint.appFramework.name} (${profile.fingerprint.appFramework.language}).`);
  }

  if (profile.fingerprint.cms) {
    parts.push(`CMS: ${profile.fingerprint.cms.name}${profile.fingerprint.cms.version ? ` v${profile.fingerprint.cms.version}` : ""}.`);
  }

  return parts.join(" ");
}

/**
 * Build LLM context for the scan planner with full target awareness
 */
export function buildTargetProfileContext(profile: TargetProfile): string {
  const lines: string[] = [];

  lines.push("## Target Profile");
  lines.push(`- **Host:** ${profile.hostname} (${profile.ips.join(", ")})`);
  lines.push(`- **Role:** ${profile.topology.role} (${profile.topology.confidence}% confidence)`);
  lines.push(`- **Environment:** ${profile.environment}`);
  lines.push(`- **Risk Profile:** ${profile.riskProfile}`);

  if (profile.fingerprint.webServer) {
    const ws = profile.fingerprint.webServer;
    lines.push(`- **Web Server:** ${ws.name}${ws.version ? ` v${ws.version}` : ""} (role: ${ws.role})`);
  }

  if (profile.fingerprint.appFramework) {
    const af = profile.fingerprint.appFramework;
    lines.push(`- **App Framework:** ${af.name}${af.version ? ` v${af.version}` : ""} (${af.language})`);
  }

  if (profile.fingerprint.cms) {
    lines.push(`- **CMS:** ${profile.fingerprint.cms.name}${profile.fingerprint.cms.version ? ` v${profile.fingerprint.cms.version}` : ""}`);
  }

  if (profile.fingerprint.techTags.length > 0) {
    lines.push(`- **Technologies:** ${profile.fingerprint.techTags.join(", ")}`);
  }

  // Services
  if (Object.keys(profile.fingerprint.serviceBanners).length > 0) {
    lines.push("\n### Discovered Services");
    for (const [port, svc] of Object.entries(profile.fingerprint.serviceBanners)) {
      lines.push(`- Port ${port}: ${svc.service}${svc.version ? ` v${svc.version}` : ""}${svc.banner ? ` — "${svc.banner}"` : ""}`);
    }
  }

  // WAF
  if (profile.waf.detected) {
    lines.push("\n### WAF Detection");
    lines.push(`- **Vendor:** ${profile.waf.vendor} (${profile.waf.type})`);
    lines.push(`- **Confidence:** ${profile.waf.confidence}%`);
    lines.push(`- **In Scope:** ${profile.waf.inScope ? "YES" : "NO"}`);
    if (profile.waf.bypassTechniques.length > 0) {
      lines.push("- **Known Bypass Techniques:**");
      for (const t of profile.waf.bypassTechniques.slice(0, 5)) {
        lines.push(`  - ${t}`);
      }
    }
  }

  // CDN
  if (profile.cdn.detected) {
    lines.push("\n### CDN Detection");
    lines.push(`- **Provider:** ${profile.cdn.provider}`);
    lines.push(`- **Origin IP:** ${profile.cdn.originIp || "Not discovered"}`);
    lines.push(`- **Built-in WAF:** ${profile.cdn.hasBuiltInWAF ? "Yes" : "No"}`);
    lines.push(`- **Origin In Scope:** ${profile.cdn.originInScope ? "YES" : "NO"}`);
  }

  // Scope
  lines.push("\n### Scope Constraints");
  lines.push(`- WAF Bypass: ${profile.scopeConstraints.wafBypassAuthorized ? "Authorized" : "NOT Authorized"}`);
  lines.push(`- Brute Force: ${profile.scopeConstraints.bruteForceAuthorized ? "Authorized" : "NOT Authorized"}`);
  lines.push(`- Max Scan Rate: ${profile.scopeConstraints.maxScanRate} req/s`);
  lines.push(`- Engagement Type: ${profile.scopeConstraints.engagementType}`);
  if (profile.scopeConstraints.sharedInfrastructure) {
    lines.push("- ⚠️ SHARED INFRASTRUCTURE — use conservative scan rates");
  }

  // Strategy
  lines.push("\n### Recommended Strategy");
  lines.push(`- **Name:** ${profile.recommendedStrategy.name}`);
  lines.push(`- **Risk Level:** ${profile.recommendedStrategy.riskLevel}`);
  lines.push(`- **Estimated Time:** ${profile.recommendedStrategy.estimatedTimeMinutes} minutes`);
  lines.push(`- **Evasion Profile:** ${profile.recommendedStrategy.evasionProfile.name} (${profile.recommendedStrategy.evasionProfile.rateLimit} req/s)`);
  lines.push(`- **Rationale:** ${profile.recommendedStrategy.rationale}`);

  lines.push("\n### Scan Phases");
  for (const phase of profile.recommendedStrategy.phases) {
    lines.push(`\n**${phase.name}**${phase.requiresApproval ? " ⚠️ REQUIRES APPROVAL" : ""}`);
    for (const tool of phase.tools) {
      lines.push(`- \`${tool.tool} ${tool.flags}\` — ${tool.purpose}`);
    }
  }

  return lines.join("\n");
}

/**
 * Get the default scope constraints for an engagement type
 */
export function getDefaultScopeConstraints(engagementType: "pentest" | "red_team" | "vuln_assessment" | "bug_bounty"): ScopeConstraints {
  switch (engagementType) {
    case "pentest":
      return {
        wafBypassAuthorized: true,
        cdnOriginAuthorized: true,
        bruteForceAuthorized: true,
        dosTestingAuthorized: false,
        socialEngineeringAuthorized: false,
        maxScanRate: 10,
        allowedHours: null,
        excludedPaths: [],
        excludedPorts: [],
        sharedInfrastructure: false,
        engagementType: "pentest",
      };
    case "red_team":
      return {
        wafBypassAuthorized: true,
        cdnOriginAuthorized: true,
        bruteForceAuthorized: true,
        dosTestingAuthorized: false,
        socialEngineeringAuthorized: true,
        maxScanRate: 5, // Lower rate for stealth
        allowedHours: null,
        excludedPaths: [],
        excludedPorts: [],
        sharedInfrastructure: false,
        engagementType: "red_team",
      };
    case "vuln_assessment":
      return {
        wafBypassAuthorized: false,
        cdnOriginAuthorized: false,
        bruteForceAuthorized: false,
        dosTestingAuthorized: false,
        socialEngineeringAuthorized: false,
        maxScanRate: 20,
        allowedHours: null,
        excludedPaths: [],
        excludedPorts: [],
        sharedInfrastructure: false,
        engagementType: "vuln_assessment",
      };
    case "bug_bounty":
      return {
        wafBypassAuthorized: false,
        cdnOriginAuthorized: false,
        bruteForceAuthorized: false,
        dosTestingAuthorized: false,
        socialEngineeringAuthorized: false,
        maxScanRate: 3, // Very conservative
        allowedHours: null,
        excludedPaths: [],
        excludedPorts: [],
        sharedInfrastructure: true, // Assume shared by default
        engagementType: "bug_bounty",
      };
  }
}
