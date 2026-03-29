/**
 * WAF / NGFW Detection & Scan Tuning Engine
 * ═══════════════════════════════════════════════════════════════════════
 * Comprehensive detection of Web Application Firewalls and Next-Generation
 * Firewalls through multi-layer fingerprinting, then generates scan tuning
 * profiles for ScanForge Discovery, Nuclei, and other active tools.
 *
 * Detection Methods:
 *   1. HTTP Header Fingerprinting — Server, Via, X-headers, cookies
 *   2. Challenge Page Detection — CAPTCHA, JS challenges, block pages
 *   3. Error Response Analysis — Custom error pages, WAF block signatures
 *   4. Rate Limit Probing — Detect request throttling thresholds
 *   5. Port Behavior Analysis — TCP RST patterns, stateful inspection
 *   6. TLS Fingerprinting — JA3/JA4 proxy signatures
 *   7. DNS Analysis — CNAME chains to WAF/CDN providers
 *
 * Scan Tuning Outputs:
 *   - ScanForge Discovery timing template (-T0 to -T4), scan flags, evasion scripts
 *   - Nuclei rate limiting, concurrency, and template selection
 *   - General evasion techniques (fragmentation, encoding, timing)
 *   - WAF bypass suggestions per vendor
 *
 * @module waf-ngfw-detection
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export type WafVendor =
  | "cloudflare" | "akamai" | "aws_waf" | "aws_cloudfront"
  | "azure_front_door" | "azure_waf" | "gcp_cloud_armor"
  | "imperva" | "f5_bigip" | "f5_silverline"
  | "sucuri" | "fastly" | "barracuda" | "fortiweb"
  | "citrix_adc" | "radware" | "modsecurity"
  | "cloudfront_shield" | "stackpath" | "edgecast"
  | "wallarm" | "reblaze" | "signal_sciences"
  | "unknown_waf";

export type NgfwVendor =
  | "palo_alto" | "fortinet" | "checkpoint" | "cisco_firepower"
  | "cisco_asa" | "juniper_srx" | "sophos_xg" | "sonicwall"
  | "watchguard" | "barracuda_ngfw" | "untangle"
  | "pfsense" | "opnsense" | "unknown_ngfw";

export type DetectionConfidence = "confirmed" | "high" | "medium" | "low";

export interface WafDetection {
  vendor: WafVendor;
  productName: string;
  confidence: DetectionConfidence;
  evidence: WafEvidence[];
  capabilities: WafCapabilities;
  bypassDifficulty: "very_hard" | "hard" | "medium" | "easy";
}

export interface NgfwDetection {
  vendor: NgfwVendor;
  productName: string;
  confidence: DetectionConfidence;
  evidence: string[];
  capabilities: NgfwCapabilities;
}

export interface WafEvidence {
  method: "header" | "challenge_page" | "error_response" | "cookie" | "dns_cname" | "tls" | "behavior";
  detail: string;
  raw?: string;
}

export interface WafCapabilities {
  sqlInjectionProtection: boolean;
  xssProtection: boolean;
  rfiLfiProtection: boolean;
  commandInjectionProtection: boolean;
  botProtection: boolean;
  ddosProtection: boolean;
  rateLimiting: boolean;
  geoBlocking: boolean;
  ipReputation: boolean;
  customRules: boolean;
  apiProtection: boolean;
  challengePages: boolean;
}

export interface NgfwCapabilities {
  statefulInspection: boolean;
  deepPacketInspection: boolean;
  ipsIdsIntegrated: boolean;
  applicationAwareness: boolean;
  sslDecryption: boolean;
  threatIntelFeed: boolean;
  sandboxing: boolean;
  urlFiltering: boolean;
}

export interface RateLimitProfile {
  detected: boolean;
  requestsPerSecond?: number;
  burstLimit?: number;
  windowSeconds?: number;
  blockDurationSeconds?: number;
  blockType: "429_response" | "captcha" | "connection_drop" | "redirect" | "none";
}

export interface ScanTuningProfile {
  /** Overall aggressiveness recommendation */
  aggressiveness: "stealth" | "cautious" | "normal" | "aggressive";

  /** ScanForge Discovery configuration */
  discovery: {
    timing: "-T0" | "-T1" | "-T2" | "-T3" | "-T4";
    flags: string[];
    scripts: string[];
    evasionFlags: string[];
    maxRetries: number;
    hostTimeout: string;
    scanDelay: string;
    maxRate: number;
    portScanOrder: "random" | "sequential";
    fragmentPackets: boolean;
    decoyScans: boolean;
    sourcePortRandomize: boolean;
    rationale: string;
  };

  /** Nuclei configuration */
  nuclei: {
    rateLimit: number;
    bulkSize: number;
    concurrency: number;
    timeout: number;
    retries: number;
    templateExclusions: string[];
    interactshDisabled: boolean;
    headless: boolean;
    customHeaders: Record<string, string>;
    rationale: string;
  };

  /** General evasion techniques */
  evasion: {
    techniques: EvasionTechnique[];
    encodingStrategies: string[];
    timingStrategies: string[];
    userAgentRotation: boolean;
    ipRotation: boolean;
    headerRandomization: boolean;
  };

  /** WAF-specific bypass suggestions */
  wafBypasses: WafBypassSuggestion[];

  /** Summary for operators */
  summary: string;
  warnings: string[];
}

export interface EvasionTechnique {
  id: string;
  name: string;
  description: string;
  applicableTo: ("scanforge-discovery" | "nuclei" | "custom" | "burp" | "sqlmap")[];
  effectiveness: "high" | "medium" | "low";
  implementationNote: string;
}

export interface WafBypassSuggestion {
  wafVendor: WafVendor;
  technique: string;
  description: string;
  risk: "high" | "medium" | "low";
  references: string[];
}

export interface WafNgfwAssessment {
  domain: string;
  scanTimestamp: number;
  durationMs: number;

  wafDetections: WafDetection[];
  ngfwDetections: NgfwDetection[];
  rateLimitProfile: RateLimitProfile;

  /** Primary WAF (highest confidence) */
  primaryWaf: WafDetection | null;
  /** Primary NGFW (highest confidence) */
  primaryNgfw: NgfwDetection | null;

  /** Generated scan tuning profile */
  scanTuningProfile: ScanTuningProfile;

  /** Overall defensive posture score 0-100 */
  defensivePostureScore: number;

  /** Raw evidence for audit trail */
  rawEvidence: {
    headers: Record<string, string>;
    dnsChain: string[];
    challengeDetected: boolean;
    blockPageDetected: boolean;
    errorSignatures: string[];
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — WAF FINGERPRINT DATABASE
// ═══════════════════════════════════════════════════════════════════════

interface WafFingerprint {
  vendor: WafVendor;
  productName: string;
  headerSignatures: Array<{ header: string; pattern: RegExp; weight: number }>;
  cookieSignatures: Array<{ pattern: RegExp; weight: number }>;
  bodySignatures: Array<{ pattern: RegExp; weight: number }>;
  dnsPatterns: RegExp[];
  capabilities: WafCapabilities;
  bypassDifficulty: WafDetection["bypassDifficulty"];
}

const WAF_FINGERPRINTS: WafFingerprint[] = [
  {
    vendor: "cloudflare",
    productName: "Cloudflare WAF",
    headerSignatures: [
      { header: "server", pattern: /cloudflare/i, weight: 3 },
      { header: "cf-ray", pattern: /.+/, weight: 5 },
      { header: "cf-cache-status", pattern: /.+/, weight: 3 },
      { header: "cf-connecting-ip", pattern: /.+/, weight: 2 },
      { header: "cf-request-id", pattern: /.+/, weight: 2 },
      { header: "expect-ct", pattern: /cloudflare/i, weight: 2 },
    ],
    cookieSignatures: [
      { pattern: /__cfduid/i, weight: 3 },
      { pattern: /cf_clearance/i, weight: 4 },
      { pattern: /__cf_bm/i, weight: 3 },
    ],
    bodySignatures: [
      { pattern: /cloudflare/i, weight: 2 },
      { pattern: /cf-browser-verification/i, weight: 4 },
      { pattern: /Attention Required.*Cloudflare/i, weight: 5 },
      { pattern: /ray\s*ID/i, weight: 3 },
    ],
    dnsPatterns: [/\.cloudflare\.com$/i, /\.cloudflare-dns\.com$/i],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: true, ddosProtection: true,
      rateLimiting: true, geoBlocking: true, ipReputation: true,
      customRules: true, apiProtection: true, challengePages: true,
    },
    bypassDifficulty: "hard",
  },
  {
    vendor: "akamai",
    productName: "Akamai Kona Site Defender",
    headerSignatures: [
      { header: "server", pattern: /akamai/i, weight: 4 },
      { header: "x-akamai-transformed", pattern: /.+/, weight: 5 },
      { header: "x-akamai-request-id", pattern: /.+/, weight: 4 },
      { header: "x-akamai-session-info", pattern: /.+/, weight: 3 },
      { header: "akamai-grn", pattern: /.+/, weight: 3 },
    ],
    cookieSignatures: [
      { pattern: /AkaSid/i, weight: 4 },
      { pattern: /akamai/i, weight: 3 },
      { pattern: /bm_sv/i, weight: 3 },
    ],
    bodySignatures: [
      { pattern: /akamai/i, weight: 2 },
      { pattern: /Access Denied.*akamai/i, weight: 5 },
      { pattern: /Reference #\d+\.\w+/i, weight: 3 },
    ],
    dnsPatterns: [/\.akamai\.net$/i, /\.akamaiedge\.net$/i, /\.akamaized\.net$/i],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: true, ddosProtection: true,
      rateLimiting: true, geoBlocking: true, ipReputation: true,
      customRules: true, apiProtection: true, challengePages: true,
    },
    bypassDifficulty: "very_hard",
  },
  {
    vendor: "aws_waf",
    productName: "AWS WAF + CloudFront",
    headerSignatures: [
      { header: "x-amz-cf-id", pattern: /.+/, weight: 4 },
      { header: "x-amz-cf-pop", pattern: /.+/, weight: 3 },
      { header: "x-amzn-waf-action", pattern: /.+/, weight: 5 },
      { header: "server", pattern: /cloudfront/i, weight: 3 },
      { header: "x-amzn-requestid", pattern: /.+/, weight: 2 },
      { header: "x-cache", pattern: /cloudfront/i, weight: 3 },
    ],
    cookieSignatures: [
      { pattern: /AWSALB/i, weight: 3 },
      { pattern: /AWSALBCORS/i, weight: 3 },
    ],
    bodySignatures: [
      { pattern: /Request blocked/i, weight: 2 },
      { pattern: /aws.*waf/i, weight: 4 },
    ],
    dnsPatterns: [/\.cloudfront\.net$/i, /\.amazonaws\.com$/i],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: true, ddosProtection: true,
      rateLimiting: true, geoBlocking: true, ipReputation: true,
      customRules: true, apiProtection: true, challengePages: false,
    },
    bypassDifficulty: "hard",
  },
  {
    vendor: "imperva",
    productName: "Imperva Cloud WAF (Incapsula)",
    headerSignatures: [
      { header: "x-iinfo", pattern: /.+/, weight: 5 },
      { header: "x-cdn", pattern: /incapsula|imperva/i, weight: 5 },
      { header: "x-iinfo", pattern: /\d+-\d+-\d+/i, weight: 3 },
    ],
    cookieSignatures: [
      { pattern: /incap_ses/i, weight: 5 },
      { pattern: /visid_incap/i, weight: 5 },
      { pattern: /nlbi_/i, weight: 3 },
    ],
    bodySignatures: [
      { pattern: /incapsula/i, weight: 4 },
      { pattern: /imperva/i, weight: 3 },
      { pattern: /Request unsuccessful.*Incapsula/i, weight: 5 },
    ],
    dnsPatterns: [/\.incapdns\.net$/i, /\.impervadns\.net$/i],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: true, ddosProtection: true,
      rateLimiting: true, geoBlocking: true, ipReputation: true,
      customRules: true, apiProtection: true, challengePages: true,
    },
    bypassDifficulty: "hard",
  },
  {
    vendor: "f5_bigip",
    productName: "F5 BIG-IP ASM",
    headerSignatures: [
      { header: "server", pattern: /big-?ip/i, weight: 5 },
      { header: "x-wa-info", pattern: /.+/, weight: 4 },
      { header: "x-cnection", pattern: /close/i, weight: 2 },
    ],
    cookieSignatures: [
      { pattern: /BIGipServer/i, weight: 5 },
      { pattern: /TS[0-9a-f]{8}/i, weight: 3 },
      { pattern: /f5_cspm/i, weight: 4 },
    ],
    bodySignatures: [
      { pattern: /The requested URL was rejected/i, weight: 4 },
      { pattern: /support ID/i, weight: 3 },
    ],
    dnsPatterns: [],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: true, ddosProtection: false,
      rateLimiting: true, geoBlocking: true, ipReputation: false,
      customRules: true, apiProtection: true, challengePages: false,
    },
    bypassDifficulty: "medium",
  },
  {
    vendor: "azure_front_door",
    productName: "Azure Front Door + WAF",
    headerSignatures: [
      { header: "x-azure-ref", pattern: /.+/, weight: 5 },
      { header: "x-fd-healthprobe", pattern: /.+/, weight: 3 },
      { header: "x-ms-ref", pattern: /.+/, weight: 3 },
      { header: "x-azure-requestid", pattern: /.+/, weight: 2 },
    ],
    cookieSignatures: [],
    bodySignatures: [
      { pattern: /azure.*front.*door/i, weight: 4 },
      { pattern: /This request has been blocked/i, weight: 2 },
    ],
    dnsPatterns: [/\.azurefd\.net$/i, /\.azureedge\.net$/i, /\.trafficmanager\.net$/i],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: true, ddosProtection: true,
      rateLimiting: true, geoBlocking: true, ipReputation: true,
      customRules: true, apiProtection: true, challengePages: false,
    },
    bypassDifficulty: "hard",
  },
  {
    vendor: "gcp_cloud_armor",
    productName: "Google Cloud Armor",
    headerSignatures: [
      { header: "via", pattern: /google/i, weight: 2 },
      { header: "server", pattern: /gws|google/i, weight: 2 },
      { header: "x-goog-component", pattern: /.+/, weight: 3 },
    ],
    cookieSignatures: [],
    bodySignatures: [
      { pattern: /cloud armor/i, weight: 5 },
      { pattern: /google cloud/i, weight: 2 },
    ],
    dnsPatterns: [/\.googleusercontent\.com$/i, /\.googleapis\.com$/i],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: true, ddosProtection: true,
      rateLimiting: true, geoBlocking: true, ipReputation: true,
      customRules: true, apiProtection: true, challengePages: false,
    },
    bypassDifficulty: "hard",
  },
  {
    vendor: "sucuri",
    productName: "Sucuri WAF",
    headerSignatures: [
      { header: "server", pattern: /sucuri/i, weight: 5 },
      { header: "x-sucuri-id", pattern: /.+/, weight: 5 },
      { header: "x-sucuri-cache", pattern: /.+/, weight: 3 },
    ],
    cookieSignatures: [
      { pattern: /sucuri/i, weight: 4 },
    ],
    bodySignatures: [
      { pattern: /sucuri/i, weight: 3 },
      { pattern: /Access Denied.*Sucuri/i, weight: 5 },
    ],
    dnsPatterns: [/\.sucuri\.net$/i],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: true, ddosProtection: true,
      rateLimiting: true, geoBlocking: true, ipReputation: false,
      customRules: true, apiProtection: false, challengePages: false,
    },
    bypassDifficulty: "medium",
  },
  {
    vendor: "fortiweb",
    productName: "Fortinet FortiWeb",
    headerSignatures: [
      { header: "server", pattern: /fortiweb/i, weight: 5 },
      { header: "x-powered-by", pattern: /fortiweb/i, weight: 4 },
    ],
    cookieSignatures: [
      { pattern: /FORTIWAFSID/i, weight: 5 },
      { pattern: /cookiesession1/i, weight: 2 },
    ],
    bodySignatures: [
      { pattern: /fortinet/i, weight: 3 },
      { pattern: /FortiWeb/i, weight: 5 },
      { pattern: /block.*page.*fortinet/i, weight: 4 },
    ],
    dnsPatterns: [],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: true, ddosProtection: false,
      rateLimiting: true, geoBlocking: true, ipReputation: true,
      customRules: true, apiProtection: true, challengePages: false,
    },
    bypassDifficulty: "medium",
  },
  {
    vendor: "barracuda",
    productName: "Barracuda WAF",
    headerSignatures: [
      { header: "server", pattern: /barracuda/i, weight: 5 },
      { header: "barra_counter_session", pattern: /.+/, weight: 4 },
    ],
    cookieSignatures: [
      { pattern: /barra_counter_session/i, weight: 5 },
      { pattern: /BNI__BARRACUDA_LB_COOKIE/i, weight: 5 },
    ],
    bodySignatures: [
      { pattern: /barracuda/i, weight: 3 },
      { pattern: /You are being blocked/i, weight: 2 },
    ],
    dnsPatterns: [],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: false, ddosProtection: false,
      rateLimiting: true, geoBlocking: false, ipReputation: false,
      customRules: true, apiProtection: false, challengePages: false,
    },
    bypassDifficulty: "easy",
  },
  {
    vendor: "modsecurity",
    productName: "ModSecurity (OWASP CRS)",
    headerSignatures: [
      { header: "server", pattern: /mod_security|modsecurity/i, weight: 5 },
    ],
    cookieSignatures: [],
    bodySignatures: [
      { pattern: /ModSecurity/i, weight: 5 },
      { pattern: /OWASP.*CRS/i, weight: 4 },
      { pattern: /Not Acceptable!.*406/i, weight: 3 },
    ],
    dnsPatterns: [],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: false, ddosProtection: false,
      rateLimiting: false, geoBlocking: false, ipReputation: false,
      customRules: true, apiProtection: false, challengePages: false,
    },
    bypassDifficulty: "easy",
  },
  {
    vendor: "wallarm",
    productName: "Wallarm WAAP",
    headerSignatures: [
      { header: "server", pattern: /wallarm/i, weight: 5 },
      { header: "x-wallarm-instance", pattern: /.+/, weight: 5 },
    ],
    cookieSignatures: [],
    bodySignatures: [
      { pattern: /wallarm/i, weight: 4 },
    ],
    dnsPatterns: [/\.wallarm\.com$/i],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: true, ddosProtection: false,
      rateLimiting: true, geoBlocking: false, ipReputation: true,
      customRules: true, apiProtection: true, challengePages: false,
    },
    bypassDifficulty: "hard",
  },
  {
    vendor: "fastly",
    productName: "Fastly Next-Gen WAF (Signal Sciences)",
    headerSignatures: [
      { header: "server", pattern: /fastly/i, weight: 3 },
      { header: "x-served-by", pattern: /cache-/i, weight: 3 },
      { header: "x-fastly-request-id", pattern: /.+/, weight: 4 },
      { header: "fastly-debug-digest", pattern: /.+/, weight: 4 },
      { header: "via", pattern: /varnish/i, weight: 2 },
    ],
    cookieSignatures: [],
    bodySignatures: [
      { pattern: /fastly/i, weight: 2 },
    ],
    dnsPatterns: [/\.fastly\.net$/i, /\.fastlylb\.net$/i],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: true, ddosProtection: true,
      rateLimiting: true, geoBlocking: true, ipReputation: true,
      customRules: true, apiProtection: true, challengePages: false,
    },
    bypassDifficulty: "hard",
  },
  {
    vendor: "citrix_adc",
    productName: "Citrix ADC (NetScaler) AppFirewall",
    headerSignatures: [
      { header: "via", pattern: /NS-CACHE/i, weight: 4 },
      { header: "cneonction", pattern: /close/i, weight: 3 },
      { header: "x-ns-cache", pattern: /.+/, weight: 4 },
    ],
    cookieSignatures: [
      { pattern: /NSC_/i, weight: 5 },
      { pattern: /citrix_ns_id/i, weight: 5 },
    ],
    bodySignatures: [
      { pattern: /citrix|netscaler/i, weight: 4 },
      { pattern: /ns_af/i, weight: 4 },
    ],
    dnsPatterns: [],
    capabilities: {
      sqlInjectionProtection: true, xssProtection: true, rfiLfiProtection: true,
      commandInjectionProtection: true, botProtection: false, ddosProtection: true,
      rateLimiting: true, geoBlocking: false, ipReputation: false,
      customRules: true, apiProtection: false, challengePages: false,
    },
    bypassDifficulty: "medium",
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §3 — NGFW FINGERPRINT DATABASE
// ═══════════════════════════════════════════════════════════════════════

interface NgfwFingerprint {
  vendor: NgfwVendor;
  productName: string;
  /** Patterns found in Shodan/Censys banners or HTTP headers */
  bannerPatterns: RegExp[];
  /** SSL certificate org patterns */
  certOrgPatterns: RegExp[];
  /** Known management interface paths */
  managementPaths: string[];
  capabilities: NgfwCapabilities;
}

const NGFW_FINGERPRINTS: NgfwFingerprint[] = [
  {
    vendor: "palo_alto",
    productName: "Palo Alto Networks NGFW",
    bannerPatterns: [/palo\s*alto/i, /PAN-OS/i, /GlobalProtect/i],
    certOrgPatterns: [/Palo Alto Networks/i],
    managementPaths: ["/php/login.php", "/global-protect/login.esp", "/ssl-vpn/login.esp"],
    capabilities: {
      statefulInspection: true, deepPacketInspection: true, ipsIdsIntegrated: true,
      applicationAwareness: true, sslDecryption: true, threatIntelFeed: true,
      sandboxing: true, urlFiltering: true,
    },
  },
  {
    vendor: "fortinet",
    productName: "Fortinet FortiGate NGFW",
    bannerPatterns: [/fortigate/i, /fortinet/i, /FortiOS/i],
    certOrgPatterns: [/Fortinet/i],
    managementPaths: ["/login", "/remote/login", "/remote/logincheck"],
    capabilities: {
      statefulInspection: true, deepPacketInspection: true, ipsIdsIntegrated: true,
      applicationAwareness: true, sslDecryption: true, threatIntelFeed: true,
      sandboxing: true, urlFiltering: true,
    },
  },
  {
    vendor: "checkpoint",
    productName: "Check Point NGFW",
    bannerPatterns: [/check\s*point/i, /CPMI/i, /FW-1/i, /FireWall-1/i],
    certOrgPatterns: [/Check Point/i],
    managementPaths: ["/sslvpn/Login/Login", "/cgi-bin/home.tcl"],
    capabilities: {
      statefulInspection: true, deepPacketInspection: true, ipsIdsIntegrated: true,
      applicationAwareness: true, sslDecryption: true, threatIntelFeed: true,
      sandboxing: true, urlFiltering: true,
    },
  },
  {
    vendor: "cisco_firepower",
    productName: "Cisco Firepower NGFW",
    bannerPatterns: [/firepower/i, /cisco.*ftd/i, /Sourcefire/i],
    certOrgPatterns: [/Cisco/i],
    managementPaths: ["/ui/login", "/login.cgi"],
    capabilities: {
      statefulInspection: true, deepPacketInspection: true, ipsIdsIntegrated: true,
      applicationAwareness: true, sslDecryption: true, threatIntelFeed: true,
      sandboxing: true, urlFiltering: true,
    },
  },
  {
    vendor: "cisco_asa",
    productName: "Cisco ASA",
    bannerPatterns: [/cisco.*asa/i, /Adaptive Security Appliance/i],
    certOrgPatterns: [/Cisco/i],
    managementPaths: ["/+CSCOE+/logon.html", "/CSCOSSLC/tunnel"],
    capabilities: {
      statefulInspection: true, deepPacketInspection: false, ipsIdsIntegrated: false,
      applicationAwareness: false, sslDecryption: false, threatIntelFeed: false,
      sandboxing: false, urlFiltering: false,
    },
  },
  {
    vendor: "juniper_srx",
    productName: "Juniper SRX Series",
    bannerPatterns: [/juniper/i, /JUNOS/i, /SRX/i],
    certOrgPatterns: [/Juniper Networks/i],
    managementPaths: ["/login", "/dana-na/auth/url_default/welcome.cgi"],
    capabilities: {
      statefulInspection: true, deepPacketInspection: true, ipsIdsIntegrated: true,
      applicationAwareness: true, sslDecryption: true, threatIntelFeed: true,
      sandboxing: false, urlFiltering: true,
    },
  },
  {
    vendor: "sophos_xg",
    productName: "Sophos XG Firewall",
    bannerPatterns: [/sophos/i, /cyberoam/i],
    certOrgPatterns: [/Sophos/i],
    managementPaths: ["/webconsole/webpages/login.jsp", "/userportal/webpages/myaccount/login.jsp"],
    capabilities: {
      statefulInspection: true, deepPacketInspection: true, ipsIdsIntegrated: true,
      applicationAwareness: true, sslDecryption: true, threatIntelFeed: true,
      sandboxing: true, urlFiltering: true,
    },
  },
  {
    vendor: "sonicwall",
    productName: "SonicWall NGFW",
    bannerPatterns: [/sonicwall/i, /SonicOS/i],
    certOrgPatterns: [/SonicWall/i, /SonicWALL/i],
    managementPaths: ["/auth.html", "/auth1.html"],
    capabilities: {
      statefulInspection: true, deepPacketInspection: true, ipsIdsIntegrated: true,
      applicationAwareness: true, sslDecryption: true, threatIntelFeed: true,
      sandboxing: true, urlFiltering: true,
    },
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §4 — WAF BYPASS KNOWLEDGE BASE
// ═══════════════════════════════════════════════════════════════════════

const WAF_BYPASS_DB: Record<WafVendor, WafBypassSuggestion[]> = {
  cloudflare: [
    { wafVendor: "cloudflare", technique: "Origin IP Discovery", description: "Find the origin IP behind Cloudflare using historical DNS records, certificate transparency logs, or Shodan. Bypass WAF by connecting directly to origin.", risk: "low", references: ["https://github.com/m0rtem/CloudFail"] },
    { wafVendor: "cloudflare", technique: "HTTP/2 Smuggling", description: "Exploit HTTP/2 to HTTP/1.1 translation differences at the Cloudflare edge to smuggle requests past WAF rules.", risk: "medium", references: ["CL.0 / H2.CL smuggling research"] },
    { wafVendor: "cloudflare", technique: "Unicode Normalization", description: "Use Unicode characters that normalize differently at the WAF vs. application layer to bypass SQL injection and XSS filters.", risk: "low", references: ["Unicode WAF bypass techniques"] },
  ],
  akamai: [
    { wafVendor: "akamai", technique: "Parameter Pollution", description: "Use HTTP Parameter Pollution to split payloads across duplicate parameters. Akamai may only inspect the first occurrence.", risk: "low", references: ["HPP research papers"] },
    { wafVendor: "akamai", technique: "Chunked Transfer Encoding", description: "Use chunked transfer encoding to split malicious payloads across chunks, bypassing pattern matching.", risk: "medium", references: ["Chunked encoding WAF bypass"] },
  ],
  aws_waf: [
    { wafVendor: "aws_waf", technique: "Case Variation", description: "AWS WAF managed rules may be case-sensitive. Try mixed-case SQL keywords (SeLeCt, UnIoN) or HTML tags.", risk: "low", references: ["AWS WAF managed rules documentation"] },
    { wafVendor: "aws_waf", technique: "JSON Content-Type", description: "Send payloads in JSON body with Content-Type: application/json. Some AWS WAF rules only inspect form-encoded data.", risk: "low", references: ["AWS WAF content type handling"] },
  ],
  imperva: [
    { wafVendor: "imperva", technique: "Multipart Form Bypass", description: "Wrap payloads in multipart/form-data boundaries. Imperva may not fully parse nested multipart content.", risk: "medium", references: ["Imperva WAF bypass research"] },
  ],
  f5_bigip: [
    { wafVendor: "f5_bigip", technique: "Cookie Decoding", description: "F5 BIG-IP encodes backend server info in cookies (BIGipServer*). Decode to discover internal IPs and pool members.", risk: "low", references: ["F5 cookie decoding tools"] },
    { wafVendor: "f5_bigip", technique: "HTTP Desync", description: "Exploit request smuggling via CL/TE or TE/CL discrepancies between F5 and backend servers.", risk: "high", references: ["HTTP request smuggling research"] },
  ],
  modsecurity: [
    { wafVendor: "modsecurity", technique: "Paranoia Level Exploitation", description: "ModSecurity CRS has paranoia levels 1-4. Most deployments use PL1-2, leaving advanced evasion techniques effective.", risk: "low", references: ["OWASP CRS documentation"] },
    { wafVendor: "modsecurity", technique: "Comment Injection", description: "Use SQL comments (/**/) and inline comments to break up keywords: SEL/**/ECT, UN/**/ION.", risk: "low", references: ["SQL injection WAF bypass cheatsheets"] },
  ],
  fortiweb: [
    { wafVendor: "fortiweb", technique: "Encoding Chains", description: "Chain multiple encoding layers (URL encode → double URL encode → Unicode) to bypass FortiWeb pattern matching.", risk: "low", references: ["FortiWeb WAF bypass research"] },
  ],
  // Defaults for vendors without specific bypasses
  aws_cloudfront: [], azure_front_door: [], azure_waf: [], gcp_cloud_armor: [],
  f5_silverline: [], barracuda: [], citrix_adc: [], radware: [],
  cloudfront_shield: [], stackpath: [], edgecast: [],
  wallarm: [], reblaze: [], signal_sciences: [], sucuri: [], fastly: [],
  unknown_waf: [
    { wafVendor: "unknown_waf", technique: "Generic Encoding Bypass", description: "Try URL encoding, double encoding, Unicode normalization, and mixed case to bypass unknown WAF rules.", risk: "low", references: ["OWASP WAF bypass techniques"] },
  ],
};

// ═══════════════════════════════════════════════════════════════════════
// §5 — CORE DETECTION ENGINE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Detect WAF from HTTP response headers, cookies, and body content.
 */
export function detectWafFromResponse(
  headers: Record<string, string>,
  body: string = "",
  cookies: string = ""
): WafDetection[] {
  const detections: WafDetection[] = [];

  for (const fp of WAF_FINGERPRINTS) {
    let totalWeight = 0;
    const evidence: WafEvidence[] = [];

    // Header matching
    for (const sig of fp.headerSignatures) {
      const value = headers[sig.header] || headers[sig.header.toLowerCase()] || "";
      if (sig.pattern.test(value)) {
        totalWeight += sig.weight;
        evidence.push({
          method: "header",
          detail: `Header '${sig.header}' matches ${fp.productName} signature`,
          raw: `${sig.header}: ${value}`,
        });
      }
    }

    // Cookie matching
    for (const sig of fp.cookieSignatures) {
      const cookieStr = cookies || headers["set-cookie"] || headers["cookie"] || "";
      if (sig.pattern.test(cookieStr)) {
        totalWeight += sig.weight;
        evidence.push({
          method: "cookie",
          detail: `Cookie matches ${fp.productName} signature`,
          raw: cookieStr.substring(0, 200),
        });
      }
    }

    // Body matching
    if (body) {
      for (const sig of fp.bodySignatures) {
        if (sig.pattern.test(body)) {
          totalWeight += sig.weight;
          evidence.push({
            method: "challenge_page",
            detail: `Response body matches ${fp.productName} signature`,
          });
        }
      }
    }

    if (totalWeight >= 3) {
      let confidence: DetectionConfidence = "low";
      if (totalWeight >= 10) confidence = "confirmed";
      else if (totalWeight >= 7) confidence = "high";
      else if (totalWeight >= 5) confidence = "medium";

      detections.push({
        vendor: fp.vendor,
        productName: fp.productName,
        confidence,
        evidence,
        capabilities: fp.capabilities,
        bypassDifficulty: fp.bypassDifficulty,
      });
    }
  }

  // Sort by confidence weight
  const confOrder: Record<DetectionConfidence, number> = { confirmed: 4, high: 3, medium: 2, low: 1 };
  detections.sort((a, b) => confOrder[b.confidence] - confOrder[a.confidence]);

  return detections;
}

/**
 * Detect WAF from DNS CNAME chain.
 */
export function detectWafFromDns(cnameChain: string[]): WafDetection[] {
  const detections: WafDetection[] = [];

  for (const fp of WAF_FINGERPRINTS) {
    for (const cname of cnameChain) {
      for (const pattern of fp.dnsPatterns) {
        if (pattern.test(cname)) {
          detections.push({
            vendor: fp.vendor,
            productName: fp.productName,
            confidence: "high",
            evidence: [{
              method: "dns_cname",
              detail: `DNS CNAME chain includes ${fp.productName} domain`,
              raw: cname,
            }],
            capabilities: fp.capabilities,
            bypassDifficulty: fp.bypassDifficulty,
          });
        }
      }
    }
  }

  return detections;
}

/**
 * Detect NGFW from Shodan/Censys banner data and observed services.
 */
export function detectNgfwFromBanners(
  banners: string[],
  certOrgs: string[] = [],
  observedPaths: string[] = []
): NgfwDetection[] {
  const detections: NgfwDetection[] = [];

  for (const fp of NGFW_FINGERPRINTS) {
    const evidence: string[] = [];
    let matched = false;

    // Banner matching
    for (const banner of banners) {
      for (const pattern of fp.bannerPatterns) {
        if (pattern.test(banner)) {
          evidence.push(`Banner match: "${banner.substring(0, 100)}"`);
          matched = true;
        }
      }
    }

    // Certificate org matching
    for (const org of certOrgs) {
      for (const pattern of fp.certOrgPatterns) {
        if (pattern.test(org)) {
          evidence.push(`Certificate org match: "${org}"`);
          matched = true;
        }
      }
    }

    // Management path matching
    for (const path of observedPaths) {
      if (fp.managementPaths.some(mp => path.includes(mp))) {
        evidence.push(`Management interface detected: "${path}"`);
        matched = true;
      }
    }

    if (matched) {
      detections.push({
        vendor: fp.vendor,
        productName: fp.productName,
        confidence: evidence.length >= 2 ? "high" : "medium",
        evidence,
        capabilities: fp.capabilities,
      });
    }
  }

  return detections;
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — SCAN TUNING PROFILE GENERATOR
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate a comprehensive scan tuning profile based on detected WAF/NGFW.
 */
export function generateScanTuningProfile(
  wafDetections: WafDetection[],
  ngfwDetections: NgfwDetection[],
  rateLimitProfile: RateLimitProfile
): ScanTuningProfile {
  const primaryWaf = wafDetections[0] || null;
  const primaryNgfw = ngfwDetections[0] || null;
  const hasWaf = wafDetections.length > 0;
  const hasNgfw = ngfwDetections.length > 0;
  const hasRateLimit = rateLimitProfile.detected;

  // ── Determine aggressiveness ──
  let aggressiveness: ScanTuningProfile["aggressiveness"] = "normal";
  if (hasWaf && primaryWaf?.bypassDifficulty === "very_hard") aggressiveness = "stealth";
  else if (hasWaf && hasNgfw) aggressiveness = "stealth";
  else if (hasWaf || hasNgfw) aggressiveness = "cautious";
  else if (hasRateLimit) aggressiveness = "cautious";

  // ── ScanForge Discovery tuning ──
  const scanConfig = generateScanForgeDiscoveryConfig(aggressiveness, primaryWaf, primaryNgfw, rateLimitProfile);

  // ── Nuclei tuning ──
  const nucleiConfig = generateNucleiConfig(aggressiveness, primaryWaf, rateLimitProfile);

  // ── Evasion techniques ──
  const evasion = generateEvasionTechniques(aggressiveness, primaryWaf, primaryNgfw);

  // ── WAF bypasses ──
  const wafBypasses: WafBypassSuggestion[] = [];
  for (const waf of wafDetections) {
    const vendorBypasses = WAF_BYPASS_DB[waf.vendor] || WAF_BYPASS_DB.unknown_waf;
    wafBypasses.push(...vendorBypasses);
  }

  // ── Summary ──
  const warnings: string[] = [];
  if (hasWaf && primaryWaf?.capabilities.rateLimiting) {
    warnings.push(`${primaryWaf.productName} has rate limiting — aggressive scanning will trigger blocks.`);
  }
  if (hasWaf && primaryWaf?.capabilities.ipReputation) {
    warnings.push(`${primaryWaf.productName} uses IP reputation — scanning from known scanner IPs may be blocked immediately.`);
  }
  if (hasNgfw && primaryNgfw?.capabilities.deepPacketInspection) {
    warnings.push(`${primaryNgfw.productName} performs DPI — encrypted payloads may be inspected if SSL decryption is enabled.`);
  }
  if (hasNgfw && primaryNgfw?.capabilities.ipsIdsIntegrated) {
    warnings.push(`${primaryNgfw.productName} has integrated IPS — ScanForge Discovery scripts and aggressive probes may trigger alerts.`);
  }

  const wafNames = wafDetections.map(w => w.productName).join(", ");
  const ngfwNames = ngfwDetections.map(n => n.productName).join(", ");
  let summary = `Scan tuning profile: ${aggressiveness.toUpperCase()} mode.`;
  if (hasWaf) summary += ` WAF detected: ${wafNames}.`;
  if (hasNgfw) summary += ` NGFW detected: ${ngfwNames}.`;
  if (hasRateLimit) summary += ` Rate limiting active (${rateLimitProfile.requestsPerSecond || "unknown"} req/s).`;
  if (!hasWaf && !hasNgfw) summary += " No WAF or NGFW detected — standard scanning parameters apply.";

  return {
    aggressiveness,
    discovery: scanConfig,
    nuclei: nucleiConfig,
    evasion,
    wafBypasses,
    summary,
    warnings,
  };
}

function generateScanForgeDiscoveryConfig(
  aggressiveness: ScanTuningProfile["aggressiveness"],
  primaryWaf: WafDetection | null,
  primaryNgfw: NgfwDetection | null,
  rateLimit: RateLimitProfile
): ScanTuningProfile["scanforge-discovery"] {
  const base = {
    flags: ["-sV", "--version-intensity 5", "-O"],
    scripts: ["default", "vuln", "http-headers"],
    evasionFlags: [] as string[],
    maxRetries: 3,
    hostTimeout: "300s",
    scanDelay: "0ms",
    maxRate: 1000,
    portScanOrder: "sequential" as const,
    fragmentPackets: false,
    decoyScans: false,
    sourcePortRandomize: false,
    rationale: "",
  };

  switch (aggressiveness) {
    case "stealth":
      return {
        ...base,
        timing: "-T1",
        flags: ["-sS", "-sV", "--version-intensity 2", "-Pn"],
        scripts: ["default"],
        evasionFlags: [
          "-f",                          // Fragment packets
          "--mtu 24",                    // Custom MTU for fragmentation
          "--data-length 50",            // Append random data to packets
          "--randomize-hosts",           // Randomize target order
          "--spoof-mac 0",               // Random MAC address
          "-D RND:5",                    // 5 random decoys
          "--source-port 53",            // Spoof DNS source port
          "--badsum",                    // Send bad checksums (some firewalls pass these)
        ],
        maxRetries: 1,
        hostTimeout: "600s",
        scanDelay: "2000ms",
        maxRate: 10,
        portScanOrder: "random",
        fragmentPackets: true,
        decoyScans: true,
        sourcePortRandomize: true,
        rationale: `Stealth mode: ${primaryWaf?.productName || "WAF"} and/or ${primaryNgfw?.productName || "NGFW"} detected. Using SYN scan with fragmentation, decoys, and slow timing to minimize detection. ScanForge Discovery scripts limited to 'default' only.`,
      };

    case "cautious":
      return {
        ...base,
        timing: "-T2",
        flags: ["-sS", "-sV", "--version-intensity 3", "-Pn"],
        scripts: ["default", "http-headers", "ssl-enum-ciphers"],
        evasionFlags: [
          "-f",                          // Fragment packets
          "--randomize-hosts",
          "--data-length 25",
        ],
        maxRetries: 2,
        hostTimeout: "450s",
        scanDelay: rateLimit.detected ? `${Math.max(500, Math.floor(1000 / (rateLimit.requestsPerSecond || 5)))}ms` : "500ms",
        maxRate: rateLimit.detected ? Math.min(50, (rateLimit.requestsPerSecond || 10) * 2) : 100,
        portScanOrder: "random",
        fragmentPackets: true,
        decoyScans: false,
        sourcePortRandomize: true,
        rationale: `Cautious mode: ${primaryWaf?.productName || primaryNgfw?.productName || "security controls"} detected. Using SYN scan with moderate timing and fragmentation. Rate limited to ${rateLimit.requestsPerSecond || "estimated"} req/s based on detected rate limiting.`,
      };

    case "aggressive":
      return {
        ...base,
        timing: "-T4",
        flags: ["-sS", "-sV", "--version-intensity 7", "-O", "--osscan-guess", "-A"],
        scripts: ["default", "vuln", "exploit", "http-headers", "ssl-enum-ciphers", "http-enum"],
        evasionFlags: [],
        maxRetries: 6,
        hostTimeout: "180s",
        scanDelay: "0ms",
        maxRate: 5000,
        portScanOrder: "sequential",
        fragmentPackets: false,
        decoyScans: false,
        sourcePortRandomize: false,
        rationale: "Aggressive mode: No WAF/NGFW detected. Full-speed scanning with comprehensive version detection, OS fingerprinting, and vulnerability scripts enabled.",
      };

    default: // normal
      return {
        ...base,
        timing: "-T3",
        flags: ["-sS", "-sV", "--version-intensity 5", "-O"],
        scripts: ["default", "vuln", "http-headers", "ssl-enum-ciphers"],
        evasionFlags: ["--randomize-hosts"],
        maxRetries: 3,
        hostTimeout: "300s",
        scanDelay: "100ms",
        maxRate: 500,
        portScanOrder: "random",
        fragmentPackets: false,
        decoyScans: false,
        sourcePortRandomize: false,
        rationale: "Normal mode: No significant defensive controls detected. Standard scanning parameters with randomized host order.",
      };
  }
}

function generateNucleiConfig(
  aggressiveness: ScanTuningProfile["aggressiveness"],
  primaryWaf: WafDetection | null,
  rateLimit: RateLimitProfile
): ScanTuningProfile["nuclei"] {
  const base = {
    templateExclusions: [] as string[],
    interactshDisabled: false,
    headless: false,
    customHeaders: {} as Record<string, string>,
    rationale: "",
  };

  switch (aggressiveness) {
    case "stealth":
      return {
        ...base,
        rateLimit: 5,
        bulkSize: 5,
        concurrency: 2,
        timeout: 30,
        retries: 1,
        templateExclusions: [
          "dos", "fuzzing", "brute-force", "sqli-error-based",
          "headless", "file-upload", "ssrf-detection",
        ],
        interactshDisabled: true,
        headless: false,
        customHeaders: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
        },
        rationale: `Stealth mode for ${primaryWaf?.productName || "WAF"}: Very low rate (5 req/s), minimal concurrency, OOB interactions disabled, fuzzing/DoS templates excluded. Using realistic browser User-Agent.`,
      };

    case "cautious":
      return {
        ...base,
        rateLimit: rateLimit.detected ? Math.max(10, (rateLimit.requestsPerSecond || 20) / 2) : 25,
        bulkSize: 15,
        concurrency: 5,
        timeout: 20,
        retries: 2,
        templateExclusions: ["dos", "fuzzing", "brute-force"],
        interactshDisabled: false,
        headless: false,
        customHeaders: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        },
        rationale: `Cautious mode: Rate limited to ${rateLimit.requestsPerSecond ? Math.floor(rateLimit.requestsPerSecond / 2) : 25} req/s. DoS and fuzzing templates excluded. OOB interactions enabled for blind vulnerability detection.`,
      };

    case "aggressive":
      return {
        ...base,
        rateLimit: 150,
        bulkSize: 50,
        concurrency: 25,
        timeout: 10,
        retries: 3,
        templateExclusions: [],
        interactshDisabled: false,
        headless: true,
        customHeaders: {},
        rationale: "Aggressive mode: Full-speed scanning with all templates enabled including headless browser checks.",
      };

    default: // normal
      return {
        ...base,
        rateLimit: 50,
        bulkSize: 25,
        concurrency: 10,
        timeout: 15,
        retries: 2,
        templateExclusions: ["dos"],
        interactshDisabled: false,
        headless: false,
        customHeaders: {},
        rationale: "Normal mode: Standard scanning parameters. DoS templates excluded as a safety measure.",
      };
  }
}

function generateEvasionTechniques(
  aggressiveness: ScanTuningProfile["aggressiveness"],
  primaryWaf: WafDetection | null,
  primaryNgfw: NgfwDetection | null
): ScanTuningProfile["evasion"] {
  const techniques: EvasionTechnique[] = [];

  if (aggressiveness === "stealth" || aggressiveness === "cautious") {
    techniques.push(
      {
        id: "ip_fragmentation",
        name: "IP Fragmentation",
        description: "Split packets into smaller fragments to bypass signature-based detection. Many IDS/IPS struggle to reassemble fragmented packets correctly.",
        applicableTo: ["scanforge-discovery"],
        effectiveness: primaryNgfw?.capabilities.deepPacketInspection ? "low" : "high",
        implementationNote: "Use ScanForge discovery -f or --mtu flags. Note: modern NGFWs with DPI can reassemble fragments.",
      },
      {
        id: "timing_evasion",
        name: "Slow Scan Timing",
        description: "Spread scan probes over extended time periods to stay below IDS/IPS detection thresholds.",
        applicableTo: ["scanforge-discovery", "nuclei", "custom"],
        effectiveness: "high",
        implementationNote: "Use masscan --rate0/-T1 or nuclei rate-limit. Add random jitter between requests.",
      },
      {
        id: "user_agent_rotation",
        name: "User-Agent Rotation",
        description: "Rotate User-Agent strings to appear as different browsers/devices, avoiding bot detection.",
        applicableTo: ["nuclei", "custom", "burp"],
        effectiveness: primaryWaf?.capabilities.botProtection ? "medium" : "high",
        implementationNote: "Maintain a pool of 50+ real browser User-Agent strings. Rotate per request or per target.",
      },
      {
        id: "encoding_bypass",
        name: "Payload Encoding",
        description: "Use URL encoding, double encoding, Unicode normalization, or hex encoding to bypass WAF pattern matching.",
        applicableTo: ["nuclei", "custom", "burp", "sqlmap"],
        effectiveness: "medium",
        implementationNote: "Chain encodings: URL → double URL → Unicode. Test each encoding layer independently.",
      },
    );
  }

  if (aggressiveness === "stealth") {
    techniques.push(
      {
        id: "decoy_scanning",
        name: "Decoy Scanning",
        description: "Generate traffic from spoofed source IPs alongside real scan traffic to obscure the true scanner.",
        applicableTo: ["scanforge-discovery"],
        effectiveness: primaryNgfw?.capabilities.statefulInspection ? "low" : "medium",
        implementationNote: "Use ScanForge discovery -D RND:5 for 5 random decoys. Requires raw socket access.",
      },
      {
        id: "source_port_spoofing",
        name: "Source Port Spoofing",
        description: "Use well-known source ports (53/DNS, 80/HTTP, 443/HTTPS) to bypass firewall rules that allow return traffic from these services.",
        applicableTo: ["scanforge-discovery"],
        effectiveness: "medium",
        implementationNote: "Use ScanForge discovery --source-port 53. Works against poorly configured firewalls.",
      },
      {
        id: "ssl_tls_wrapping",
        name: "TLS-Wrapped Scanning",
        description: "Wrap scan traffic in TLS to prevent DPI from inspecting payloads. Effective against NGFWs without SSL decryption.",
        applicableTo: ["custom", "burp"],
        effectiveness: primaryNgfw?.capabilities.sslDecryption ? "low" : "high",
        implementationNote: "Use stunnel or custom TLS wrappers. Check if NGFW performs SSL interception first.",
      },
    );
  }

  return {
    techniques,
    encodingStrategies: aggressiveness === "stealth"
      ? ["url_encode", "double_url_encode", "unicode_normalize", "hex_encode", "base64", "html_entities"]
      : aggressiveness === "cautious"
        ? ["url_encode", "double_url_encode", "unicode_normalize"]
        : ["url_encode"],
    timingStrategies: aggressiveness === "stealth"
      ? ["random_delay_2s_10s", "exponential_backoff", "time_of_day_variation", "burst_then_pause"]
      : aggressiveness === "cautious"
        ? ["random_delay_500ms_2s", "linear_backoff"]
        : ["no_delay"],
    userAgentRotation: aggressiveness === "stealth" || aggressiveness === "cautious",
    ipRotation: aggressiveness === "stealth",
    headerRandomization: aggressiveness === "stealth",
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — RATE LIMIT DETECTION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Detect rate limiting by analyzing response patterns.
 * This is a passive analysis of observed responses, not active probing.
 */
export function analyzeRateLimiting(
  responses: Array<{ statusCode: number; headers: Record<string, string>; timestamp: number }>
): RateLimitProfile {
  const result: RateLimitProfile = {
    detected: false,
    blockType: "none",
  };

  // Check for 429 responses
  const rateLimitResponses = responses.filter(r => r.statusCode === 429);
  if (rateLimitResponses.length > 0) {
    result.detected = true;
    result.blockType = "429_response";

    // Parse rate limit headers
    const rlHeaders = rateLimitResponses[0].headers;
    const limit = parseInt(rlHeaders["x-ratelimit-limit"] || rlHeaders["ratelimit-limit"] || "0");
    const remaining = parseInt(rlHeaders["x-ratelimit-remaining"] || rlHeaders["ratelimit-remaining"] || "0");
    const reset = parseInt(rlHeaders["x-ratelimit-reset"] || rlHeaders["ratelimit-reset"] || "0");
    const retryAfter = parseInt(rlHeaders["retry-after"] || "0");

    if (limit > 0) result.burstLimit = limit;
    if (retryAfter > 0) result.blockDurationSeconds = retryAfter;
    if (reset > 0) {
      const windowMs = (reset * 1000) - Date.now();
      if (windowMs > 0) result.windowSeconds = Math.ceil(windowMs / 1000);
    }
    if (limit > 0 && result.windowSeconds) {
      result.requestsPerSecond = Math.floor(limit / result.windowSeconds);
    }
  }

  // Check for Cloudflare challenge responses (403 with challenge)
  const challengeResponses = responses.filter(r =>
    r.statusCode === 403 && (r.headers["cf-ray"] || r.headers["server"]?.includes("cloudflare"))
  );
  if (challengeResponses.length > 0 && !result.detected) {
    result.detected = true;
    result.blockType = "captcha";
  }

  // Check for connection drops (status 0 or very high latency)
  const dropResponses = responses.filter(r => r.statusCode === 0);
  if (dropResponses.length > responses.length * 0.3 && !result.detected) {
    result.detected = true;
    result.blockType = "connection_drop";
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — FULL ASSESSMENT FUNCTION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Run a complete WAF/NGFW assessment for a domain.
 * This performs HTTP probing and DNS analysis to detect defensive controls,
 * then generates a scan tuning profile.
 */
export async function runWafNgfwAssessment(
  domain: string,
  options: {
    timeout?: number;
    shodanBanners?: string[];
    certOrgs?: string[];
    dnsChain?: string[];
    observedPaths?: string[];
    previousResponses?: Array<{ statusCode: number; headers: Record<string, string>; timestamp: number }>;
  } = {}
): Promise<WafNgfwAssessment> {
  const start = Date.now();
  const timeout = options.timeout ?? 10000;

  let headers: Record<string, string> = {};
  let body = "";
  let cookies = "";
  let challengeDetected = false;
  let blockPageDetected = false;
  const errorSignatures: string[] = [];

  // ── Step 1: HTTP probe for WAF detection ──
  try {
    const probeUrls = [
      `https://${domain}/`,
      `https://${domain}/?test=<script>alert(1)</script>`,  // Trigger WAF block page
      `https://${domain}/wp-admin/`,                         // Common admin path
    ];

    for (const url of probeUrls) {
      try {
        const res = await fetch(url, {
          method: "GET",
          signal: AbortSignal.timeout(timeout),
          redirect: "follow",
          headers: {
            "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/2.0)",
            "Accept": "text/html",
          },
        });

        // Collect headers
        res.headers.forEach((value, key) => {
          headers[key.toLowerCase()] = value;
        });

        // Collect cookies
        const setCookie = res.headers.get("set-cookie") || "";
        if (setCookie) cookies += setCookie + "; ";

        // Read body for block page detection
        const bodyText = await res.text().catch(() => "");
        if (url.includes("<script>") && (res.status === 403 || res.status === 406)) {
          blockPageDetected = true;
          body = bodyText.substring(0, 5000);
          errorSignatures.push(`WAF block on XSS probe: HTTP ${res.status}`);
        }
        if (res.status === 503 && bodyText.includes("challenge")) {
          challengeDetected = true;
          body = bodyText.substring(0, 5000);
        }
        if (!body && bodyText) body = bodyText.substring(0, 5000);
      } catch {
        // Individual probe failure is non-fatal
      }
    }
  } catch {
    // HTTP probing failed entirely
  }

  // ── Step 2: Detect WAF ──
  const wafDetections = detectWafFromResponse(headers, body, cookies);

  // Add DNS-based detections
  if (options.dnsChain && options.dnsChain.length > 0) {
    const dnsWafs = detectWafFromDns(options.dnsChain);
    for (const dnsWaf of dnsWafs) {
      if (!wafDetections.some(w => w.vendor === dnsWaf.vendor)) {
        wafDetections.push(dnsWaf);
      }
    }
  }

  // ── Step 3: Detect NGFW ──
  const ngfwDetections = detectNgfwFromBanners(
    options.shodanBanners || [],
    options.certOrgs || [],
    options.observedPaths || []
  );

  // ── Step 4: Analyze rate limiting ──
  const rateLimitProfile = options.previousResponses
    ? analyzeRateLimiting(options.previousResponses)
    : { detected: false, blockType: "none" as const };

  // ── Step 5: Generate scan tuning profile ──
  const scanTuningProfile = generateScanTuningProfile(wafDetections, ngfwDetections, rateLimitProfile);

  // ── Step 6: Calculate defensive posture score ──
  let defensivePostureScore = 0;
  if (wafDetections.length > 0) {
    const primaryWaf = wafDetections[0];
    const capCount = Object.values(primaryWaf.capabilities).filter(Boolean).length;
    defensivePostureScore += Math.min(50, capCount * 4);
    if (primaryWaf.bypassDifficulty === "very_hard") defensivePostureScore += 15;
    else if (primaryWaf.bypassDifficulty === "hard") defensivePostureScore += 10;
    else if (primaryWaf.bypassDifficulty === "medium") defensivePostureScore += 5;
  }
  if (ngfwDetections.length > 0) {
    const primaryNgfw = ngfwDetections[0];
    const capCount = Object.values(primaryNgfw.capabilities).filter(Boolean).length;
    defensivePostureScore += Math.min(30, capCount * 4);
  }
  if (rateLimitProfile.detected) defensivePostureScore += 10;
  if (challengeDetected) defensivePostureScore += 5;
  defensivePostureScore = Math.min(100, defensivePostureScore);

  return {
    domain,
    scanTimestamp: Date.now(),
    durationMs: Date.now() - start,
    wafDetections,
    ngfwDetections,
    rateLimitProfile,
    primaryWaf: wafDetections[0] || null,
    primaryNgfw: ngfwDetections[0] || null,
    scanTuningProfile,
    defensivePostureScore,
    rawEvidence: {
      headers,
      dnsChain: options.dnsChain || [],
      challengeDetected,
      blockPageDetected,
      errorSignatures,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §9 — SCANFORGE COMMAND BUILDER
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build a ready-to-use ScanForge Discovery command from the scan tuning profile.
 */
export function buildScanForgeDiscoveryCommand(
  profile: ScanTuningProfile,
  targets: string[],
  ports: string = "1-1000"
): string {
  const parts = ["scanforge-discovery"];

  // Timing
  parts.push(profile.discovery.timing);

  // Flags
  parts.push(...profile.discovery.flags);

  // Evasion flags
  parts.push(...profile.discovery.evasionFlags);

  // Rate limiting
  if (profile.discovery.maxRate < 1000) {
    parts.push(`--max-rate ${profile.discovery.maxRate}`);
  }

  // Scan delay
  if (profile.discovery.scanDelay !== "0ms") {
    parts.push(`--scan-delay ${profile.discovery.scanDelay}`);
  }

  // Host timeout
  parts.push(`--host-timeout ${profile.discovery.hostTimeout}`);

  // Max retries
  parts.push(`--max-retries ${profile.discovery.maxRetries}`);

  // Scripts
  if (profile.discovery.scripts.length > 0) {
    parts.push(`--script=${profile.discovery.scripts.join(",")}`);
  }

  // Ports
  parts.push(`-p ${ports}`);

  // Output
  parts.push("-oJ discovery_results.json");

  // Targets
  parts.push(...targets);

  return parts.join(" ");
}

/**
 * Build a ready-to-use Nuclei command from the scan tuning profile.
 */
export function buildNucleiCommand(
  profile: ScanTuningProfile,
  targets: string[]
): string {
  const parts = ["nuclei"];

  // Rate limiting
  parts.push(`-rl ${profile.nuclei.rateLimit}`);
  parts.push(`-bs ${profile.nuclei.bulkSize}`);
  parts.push(`-c ${profile.nuclei.concurrency}`);
  parts.push(`-timeout ${profile.nuclei.timeout}`);
  parts.push(`-retries ${profile.nuclei.retries}`);

  // Template exclusions
  if (profile.nuclei.templateExclusions.length > 0) {
    parts.push(`-etags ${profile.nuclei.templateExclusions.join(",")}`);
  }

  // Interactsh
  if (profile.nuclei.interactshDisabled) {
    parts.push("-ni");
  }

  // Headless
  if (profile.nuclei.headless) {
    parts.push("-headless");
  }

  // Custom headers
  for (const [key, value] of Object.entries(profile.nuclei.customHeaders)) {
    parts.push(`-H "${key}: ${value}"`);
  }

  // Targets
  if (targets.length === 1) {
    parts.push(`-u ${targets[0]}`);
  } else {
    parts.push("-l targets.txt");
  }

  // Output
  parts.push("-o nuclei_results.json -json");

  return parts.join(" ");
}
