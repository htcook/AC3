/**
 * WAF Detector — identifies Web Application Firewalls protecting target URLs.
 *
 * Uses HTTP response analysis (headers, status codes, body patterns) to detect
 * common WAF products. Results feed into the ZAP scanner for evasion tuning.
 */

export interface WafDetectionResult {
  detected: boolean;
  vendor?: string;
  confidence: "low" | "medium" | "high";
  evidence: string[];
  evasionHints: string[];
  /** Active probing results for NGFW/IDS detection */
  activeProbe?: ActiveProbeResult;
}

export interface ActiveProbeResult {
  /** Whether an IDS/IPS was detected via active probing */
  idsDetected: boolean;
  /** Whether a next-gen firewall was detected */
  ngfwDetected: boolean;
  /** Specific IDS/IPS product identified */
  idsProduct?: string;
  /** Specific NGFW product identified */
  ngfwProduct?: string;
  /** Detection method used */
  detectionMethods: string[];
  /** Behavioral analysis results */
  behavioral: {
    /** Whether rate limiting was detected */
    rateLimitDetected: boolean;
    /** Threshold (requests/sec) before blocking */
    rateLimitThreshold?: number;
    /** Whether geo-blocking is active */
    geoBlockDetected: boolean;
    /** Whether bot detection is active */
    botDetectionActive: boolean;
    /** Whether deep packet inspection is likely */
    dpiLikely: boolean;
    /** Whether TLS inspection is detected */
    tlsInspectionDetected: boolean;
  };
  /** Recommended evasion adjustments based on active probing */
  evasionAdjustments: string[];
}

// ─── WAF Signatures ─────────────────────────────────────────────────────────

interface WafSignature {
  name: string;
  headers: Array<{ name: string; pattern: RegExp }>;
  bodyPatterns: RegExp[];
  statusCodes: number[];
  evasionHints: string[];
}

const WAF_SIGNATURES: WafSignature[] = [
  {
    name: "Cloudflare",
    headers: [
      { name: "server", pattern: /cloudflare/i },
      { name: "cf-ray", pattern: /.+/ },
      { name: "cf-cache-status", pattern: /.+/ },
    ],
    bodyPatterns: [/Attention Required! \| Cloudflare/i, /cf-error-details/i],
    statusCodes: [403, 503],
    evasionHints: [
      "Use slower scan rate (max 2 req/sec)",
      "Rotate User-Agent headers",
      "Avoid common attack payloads in initial spider",
      "Use IP rotation if available",
    ],
  },
  {
    name: "AWS WAF",
    headers: [
      { name: "x-amzn-requestid", pattern: /.+/ },
      { name: "x-amz-apigw-id", pattern: /.+/ },
    ],
    bodyPatterns: [/Request blocked/i, /AWS WAF/i],
    statusCodes: [403],
    evasionHints: [
      "Reduce request rate to avoid rate-based rules",
      "Vary HTTP methods and paths",
      "Use encoded payloads for injection tests",
      "Test with different Content-Type headers",
    ],
  },
  {
    name: "Akamai",
    headers: [
      { name: "x-akamai-transformed", pattern: /.+/ },
      { name: "server", pattern: /AkamaiGHost/i },
    ],
    bodyPatterns: [/Access Denied.*Akamai/i, /Reference #/i],
    statusCodes: [403],
    evasionHints: [
      "Use very slow scan rate (1 req/sec)",
      "Avoid automated scanner signatures",
      "Use custom User-Agent strings",
      "Fragment payloads across multiple parameters",
    ],
  },
  {
    name: "Imperva/Incapsula",
    headers: [
      { name: "x-iinfo", pattern: /.+/ },
      { name: "x-cdn", pattern: /Incapsula/i },
    ],
    bodyPatterns: [/Incapsula incident/i, /Request unsuccessful/i, /_Incapsula_Resource/i],
    statusCodes: [403],
    evasionHints: [
      "Implement cookie handling for Incapsula challenges",
      "Solve JavaScript challenges before scanning",
      "Use browser-like request patterns",
      "Avoid known bad IP ranges",
    ],
  },
  {
    name: "F5 BIG-IP ASM",
    headers: [
      { name: "server", pattern: /BIG-IP/i },
      { name: "x-wa-info", pattern: /.+/ },
    ],
    bodyPatterns: [/The requested URL was rejected/i, /support ID/i],
    statusCodes: [403],
    evasionHints: [
      "Test parameter pollution techniques",
      "Use HTTP method override headers",
      "Try alternative encoding schemes",
      "Check for bypass via HTTP/2",
    ],
  },
  {
    name: "ModSecurity",
    headers: [
      { name: "server", pattern: /mod_security/i },
    ],
    bodyPatterns: [/ModSecurity/i, /Not Acceptable/i, /OWASP.*CRS/i],
    statusCodes: [403, 406],
    evasionHints: [
      "Identify CRS paranoia level via incremental testing",
      "Use Unicode normalization bypasses",
      "Test with different character encodings",
      "Check for rule exclusion via specific paths",
    ],
  },
  {
    name: "Sucuri",
    headers: [
      { name: "x-sucuri-id", pattern: /.+/ },
      { name: "server", pattern: /Sucuri/i },
    ],
    bodyPatterns: [/Sucuri Website Firewall/i, /Access Denied - Sucuri/i],
    statusCodes: [403],
    evasionHints: [
      "Attempt direct origin IP access",
      "Use slow scan rate",
      "Vary request patterns to avoid behavioral detection",
    ],
  },
  {
    name: "Fortinet FortiWeb",
    headers: [
      { name: "server", pattern: /FortiWeb/i },
    ],
    bodyPatterns: [/FortiWeb/i, /Attack was detected/i],
    statusCodes: [403],
    evasionHints: [
      "Use HTTP parameter fragmentation",
      "Test with chunked transfer encoding",
      "Vary case in SQL keywords",
    ],
  },
];

// ─── Detection Logic ────────────────────────────────────────────────────────

export async function detectWaf(targetUrl: string): Promise<WafDetectionResult> {
  const evidence: string[] = [];
  let detectedWaf: WafSignature | null = null;
  let confidence: "low" | "medium" | "high" = "low";

  try {
    // Send a normal request first
    const normalResponse = await fetch(targetUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
      signal: AbortSignal.timeout(10000),
    });

    const normalHeaders = Object.fromEntries(normalResponse.headers.entries());
    const normalBody = await normalResponse.text();

    // Check headers against WAF signatures
    for (const sig of WAF_SIGNATURES) {
      for (const headerSig of sig.headers) {
        const headerValue = normalHeaders[headerSig.name.toLowerCase()];
        if (headerValue && headerSig.pattern.test(headerValue)) {
          detectedWaf = sig;
          evidence.push(`Header match: ${headerSig.name}=${headerValue}`);
          confidence = "high";
        }
      }

      // Check body patterns
      for (const bodyPattern of sig.bodyPatterns) {
        if (bodyPattern.test(normalBody)) {
          detectedWaf = sig;
          evidence.push(`Body pattern match: ${bodyPattern.source}`);
          confidence = "high";
        }
      }
    }

    // If no WAF detected from normal request, send a suspicious request
    if (!detectedWaf) {
      try {
        const suspiciousUrl = new URL(targetUrl);
        suspiciousUrl.searchParams.set("id", "1' OR '1'='1");
        const suspiciousResponse = await fetch(suspiciousUrl.toString(), {
          headers: {
            "User-Agent": "Mozilla/5.0 (compatible; ScanForge Discovery Engine; https://github.com/projectdiscovery)",
          },
          signal: AbortSignal.timeout(10000),
        });

        const suspHeaders = Object.fromEntries(suspiciousResponse.headers.entries());
        const suspBody = await suspiciousResponse.text();

        for (const sig of WAF_SIGNATURES) {
          if (sig.statusCodes.includes(suspiciousResponse.status)) {
            for (const bodyPattern of sig.bodyPatterns) {
              if (bodyPattern.test(suspBody)) {
                detectedWaf = sig;
                evidence.push(`Blocked request matched: status=${suspiciousResponse.status}, pattern=${bodyPattern.source}`);
                confidence = "high";
                break;
              }
            }
          }

          for (const headerSig of sig.headers) {
            const headerValue = suspHeaders[headerSig.name.toLowerCase()];
            if (headerValue && headerSig.pattern.test(headerValue)) {
              detectedWaf = sig;
              evidence.push(`Suspicious request header match: ${headerSig.name}=${headerValue}`);
              if (confidence === "low") confidence = "medium";
            }
          }

          if (detectedWaf) break;
        }

        // Generic WAF detection if blocked but no specific signature
        if (!detectedWaf && suspiciousResponse.status === 403 && normalResponse.status !== 403) {
          evidence.push(`Generic WAF detected: normal=200, suspicious=403`);
          return {
            detected: true,
            vendor: "Unknown WAF",
            confidence: "medium",
            evidence,
            evasionHints: [
              "Use slower scan rate",
              "Rotate User-Agent headers",
              "Use encoded payloads",
              "Avoid common attack signatures in URLs",
            ],
          };
        }
      } catch {
        // Suspicious request failed — could be WAF blocking
        evidence.push("Suspicious request timed out or was blocked");
      }
    }
  } catch (e: any) {
    // Connection error — target might be unreachable
    evidence.push(`Connection error: ${e.message}`);
    return { detected: false, confidence: "low", evidence, evasionHints: [] };
  }

  if (detectedWaf) {
    return {
      detected: true,
      vendor: detectedWaf.name,
      confidence,
      evidence,
      evasionHints: detectedWaf.evasionHints,
    };
  }

  return { detected: false, confidence: "low", evidence, evasionHints: [] };
}

// ─── Active NGFW/IDS Probing ────────────────────────────────────────────────

/**
 * IDS/IPS signature patterns detected in response headers and behavior.
 * These are triggered by sending known-bad payloads and analyzing the response.
 */
interface IDSSignature {
  name: string;
  /** Probe payloads that trigger the IDS */
  probePayloads: Array<{ path: string; headers?: Record<string, string>; method?: string }>;
  /** Response patterns that indicate this IDS */
  responsePatterns: Array<{ status?: number; headerPattern?: { name: string; pattern: RegExp }; bodyPattern?: RegExp }>;
  /** Evasion recommendations specific to this IDS */
  evasionTips: string[];
}

const IDS_SIGNATURES: IDSSignature[] = [
  {
    name: 'Snort/Suricata',
    probePayloads: [
      { path: '/etc/passwd', headers: { 'User-Agent': 'Nikto/2.1.6' } },
      { path: '/?cmd=cat+/etc/shadow' },
      { path: '/?file=../../../../etc/passwd' },
    ],
    responsePatterns: [
      { status: 403 },
      { bodyPattern: /blocked by.*(?:snort|suricata|intrusion)/i },
      { headerPattern: { name: 'x-ids-alert', pattern: /.+/ } },
    ],
    evasionTips: [
      'Fragment payloads across multiple packets (use chunked encoding)',
      'Use Unicode/UTF-8 encoding for path traversal',
      'Vary timing between requests (2-5s random delay)',
      'Use HTTP/2 multiplexing to evade stream-based inspection',
      'Encode payloads with double URL encoding',
    ],
  },
  {
    name: 'Palo Alto NGFW',
    probePayloads: [
      { path: '/?test=<script>alert(1)</script>' },
      { path: '/admin', headers: { 'X-Forwarded-For': '127.0.0.1' } },
      { path: '/', headers: { 'User-Agent': 'sqlmap/1.0' } },
    ],
    responsePatterns: [
      { bodyPattern: /Palo Alto/i },
      { headerPattern: { name: 'x-pan-', pattern: /.+/ } },
      { bodyPattern: /Threat Prevention/i },
    ],
    evasionTips: [
      'Use application-layer tunneling (WebSocket, gRPC)',
      'Encrypt payloads within legitimate-looking POST bodies',
      'Use DNS-over-HTTPS for C2 communication',
      'Leverage allowed cloud services for data exfiltration',
      'Use legitimate browser fingerprints to bypass App-ID',
    ],
  },
  {
    name: 'Cisco Firepower',
    probePayloads: [
      { path: '/?id=1%20UNION%20SELECT%201,2,3--' },
      { path: '/cgi-bin/../../etc/passwd' },
    ],
    responsePatterns: [
      { bodyPattern: /Cisco.*(?:Firepower|ASA)/i },
      { headerPattern: { name: 'server', pattern: /Cisco/i } },
      { bodyPattern: /Access.*Policy.*Block/i },
    ],
    evasionTips: [
      'Use HTTP parameter pollution to split payloads',
      'Leverage IPv6 if available (often less inspected)',
      'Use legitimate-looking HTTP methods (GET with body)',
      'Fragment SQL injection across multiple parameters',
    ],
  },
  {
    name: 'Check Point',
    probePayloads: [
      { path: '/?q=<img+src=x+onerror=alert(1)>' },
      { path: '/wp-admin/../wp-config.php' },
    ],
    responsePatterns: [
      { bodyPattern: /Check Point/i },
      { headerPattern: { name: 'x-checkpoint', pattern: /.+/ } },
      { bodyPattern: /UserCheck/i },
    ],
    evasionTips: [
      'Use HTTPS with client certificates to bypass inspection',
      'Leverage WebSocket connections for payload delivery',
      'Use JSON-based payloads instead of URL-encoded',
      'Employ slow-rate attacks to stay under threshold',
    ],
  },
  {
    name: 'FortiGate NGFW',
    probePayloads: [
      { path: '/?id=1+AND+1=1' },
      { path: '/shell.php' },
    ],
    responsePatterns: [
      { bodyPattern: /FortiGuard/i },
      { bodyPattern: /Fortinet/i },
      { headerPattern: { name: 'server', pattern: /FortiWeb|Fortinet/i } },
    ],
    evasionTips: [
      'Use chunked transfer encoding to split payloads',
      'Employ case variation in SQL keywords',
      'Use HTTP/2 push promises for payload delivery',
      'Leverage allowed application categories for tunneling',
    ],
  },
];

/**
 * Perform active NGFW/IDS probing against a target.
 * Sends carefully crafted probes to detect IDS/IPS, NGFW, rate limiting,
 * bot detection, DPI, and TLS inspection.
 *
 * IMPORTANT: This is a noisy operation. Only use during authorized engagements.
 */
export async function activeProbeTarget(targetUrl: string): Promise<ActiveProbeResult> {
  const result: ActiveProbeResult = {
    idsDetected: false,
    ngfwDetected: false,
    detectionMethods: [],
    behavioral: {
      rateLimitDetected: false,
      geoBlockDetected: false,
      botDetectionActive: false,
      dpiLikely: false,
      tlsInspectionDetected: false,
    },
    evasionAdjustments: [],
  };

  try {
    // ── Phase 1: IDS/IPS Signature Detection ──
    for (const sig of IDS_SIGNATURES) {
      let matched = false;
      for (const probe of sig.probePayloads) {
        try {
          const probeUrl = new URL(probe.path, targetUrl).toString();
          const resp = await fetch(probeUrl, {
            method: probe.method || 'GET',
            headers: {
              'User-Agent': probe.headers?.['User-Agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
              ...probe.headers,
            },
            signal: AbortSignal.timeout(8000),
          });

          const respHeaders = Object.fromEntries(resp.headers.entries());
          const body = await resp.text();

          for (const pattern of sig.responsePatterns) {
            if (pattern.status && resp.status === pattern.status) {
              // Status alone isn't enough — check body/headers too
              if (pattern.bodyPattern && pattern.bodyPattern.test(body)) {
                matched = true;
              }
              if (pattern.headerPattern) {
                const hVal = respHeaders[pattern.headerPattern.name.toLowerCase()];
                if (hVal && pattern.headerPattern.pattern.test(hVal)) {
                  matched = true;
                }
              }
            }
            if (pattern.bodyPattern && pattern.bodyPattern.test(body)) {
              matched = true;
            }
            if (pattern.headerPattern) {
              const hVal = respHeaders[pattern.headerPattern.name.toLowerCase()];
              if (hVal && pattern.headerPattern.pattern.test(hVal)) {
                matched = true;
              }
            }
          }

          if (matched) break;
          // Small delay between probes to avoid self-triggering rate limits
          await new Promise(r => setTimeout(r, 500));
        } catch {
          // Probe blocked or timed out — could indicate IDS
          continue;
        }
      }

      if (matched) {
        const isNGFW = ['Palo Alto NGFW', 'Cisco Firepower', 'Check Point', 'FortiGate NGFW'].includes(sig.name);
        if (isNGFW) {
          result.ngfwDetected = true;
          result.ngfwProduct = sig.name;
          result.detectionMethods.push(`NGFW detected: ${sig.name} (active probe)`);
        } else {
          result.idsDetected = true;
          result.idsProduct = sig.name;
          result.detectionMethods.push(`IDS/IPS detected: ${sig.name} (active probe)`);
        }
        result.evasionAdjustments.push(...sig.evasionTips);
      }
    }

    // ── Phase 2: Behavioral Analysis ──

    // 2a: Rate Limit Detection — send rapid requests and check for 429/throttling
    try {
      const rapidResults: number[] = [];
      for (let i = 0; i < 10; i++) {
        try {
          const resp = await fetch(targetUrl, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
            signal: AbortSignal.timeout(5000),
          });
          rapidResults.push(resp.status);
        } catch {
          rapidResults.push(0);
        }
      }
      const blocked = rapidResults.filter(s => s === 429 || s === 503 || s === 0).length;
      if (blocked >= 3) {
        result.behavioral.rateLimitDetected = true;
        const firstBlock = rapidResults.findIndex(s => s === 429 || s === 503 || s === 0);
        result.behavioral.rateLimitThreshold = firstBlock > 0 ? firstBlock : 5;
        result.detectionMethods.push(`Rate limiting detected: ${blocked}/10 requests blocked`);
        result.evasionAdjustments.push(
          `Rate limit detected at ~${result.behavioral.rateLimitThreshold} req/burst — use ${Math.max(1, (result.behavioral.rateLimitThreshold || 5) - 2)} req/sec max`,
          'Add random jitter (1-3s) between requests',
          'Distribute requests across multiple source IPs if available',
        );
      }
    } catch { /* non-critical */ }

    // 2b: Bot Detection — check for JavaScript challenges, CAPTCHAs
    try {
      const botResp = await fetch(targetUrl, {
        headers: {
          'User-Agent': 'python-requests/2.28.0',
          'Accept': '*/*',
        },
        signal: AbortSignal.timeout(8000),
      });
      const botBody = await botResp.text();
      const botIndicators = [
        /challenge-platform/i,
        /captcha/i,
        /recaptcha/i,
        /hCaptcha/i,
        /turnstile/i,
        /browser.*check/i,
        /please.*enable.*javascript/i,
        /checking.*your.*browser/i,
        /__cf_chl_/i,
        /managed.*challenge/i,
      ];
      const botMatches = botIndicators.filter(p => p.test(botBody));
      if (botMatches.length >= 1) {
        result.behavioral.botDetectionActive = true;
        result.detectionMethods.push(`Bot detection active: ${botMatches.length} indicator(s) found`);
        result.evasionAdjustments.push(
          'Use headless browser with stealth plugins for initial requests',
          'Maintain realistic browser fingerprint (TLS JA3, HTTP/2 settings)',
          'Implement cookie jar to handle challenge-response flows',
          'Pre-solve challenges before launching scan payloads',
        );
      }
    } catch { /* non-critical */ }

    // 2c: Deep Packet Inspection (DPI) — compare benign vs malicious payload responses
    try {
      const benignResp = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
        body: 'username=test&password=test123',
        signal: AbortSignal.timeout(8000),
      });
      const benignStatus = benignResp.status;

      const dpiResp = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
        body: "username=admin'--&password=<script>alert(1)</script>",
        signal: AbortSignal.timeout(8000),
      });
      const dpiStatus = dpiResp.status;

      // If benign request succeeds but malicious is blocked, DPI is likely
      if ((benignStatus < 400 || benignStatus === 404) && (dpiStatus === 403 || dpiStatus === 406)) {
        result.behavioral.dpiLikely = true;
        result.detectionMethods.push(`DPI likely: benign POST=${benignStatus}, malicious POST=${dpiStatus}`);
        result.evasionAdjustments.push(
          'Use multi-layer encoding (URL + Unicode + HTML entity)',
          'Split payloads across multiple parameters',
          'Use JSON content-type instead of form-urlencoded',
          'Employ HTTP parameter pollution techniques',
        );
      }
    } catch { /* non-critical */ }

    // 2d: TLS Inspection Detection — check for certificate anomalies
    try {
      if (targetUrl.startsWith('https://')) {
        // If the server presents a certificate from a known inspection proxy,
        // or if the certificate issuer is a corporate CA, TLS inspection is likely.
        // We can detect this by checking if the response includes inspection headers.
        const tlsResp = await fetch(targetUrl, {
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
          signal: AbortSignal.timeout(8000),
        });
        const tlsHeaders = Object.fromEntries(tlsResp.headers.entries());
        const inspectionIndicators = [
          'x-bluecoat-via',
          'x-zscaler',
          'x-forcepoint',
          'x-websense',
          'via',
        ];
        for (const header of inspectionIndicators) {
          const val = tlsHeaders[header];
          if (val && /proxy|gateway|inspection|zscaler|bluecoat|forcepoint|websense/i.test(val)) {
            result.behavioral.tlsInspectionDetected = true;
            result.detectionMethods.push(`TLS inspection detected via header: ${header}=${val}`);
            result.evasionAdjustments.push(
              'Use certificate pinning bypass techniques',
              'Consider domain fronting for C2 traffic',
              'Use encrypted channels within HTTPS (nested encryption)',
            );
            break;
          }
        }
      }
    } catch { /* non-critical */ }

  } catch (e: any) {
    result.detectionMethods.push(`Active probing error: ${e.message}`);
  }

  // Deduplicate evasion adjustments
  result.evasionAdjustments = [...new Set(result.evasionAdjustments)];

  return result;
}

/**
 * Enhanced WAF detection that combines passive header analysis with active probing.
 * Use this for comprehensive defense profiling during authorized engagements.
 */
export async function detectWafEnhanced(targetUrl: string): Promise<WafDetectionResult> {
  // Run passive detection and active probing in parallel
  const [passiveResult, activeResult] = await Promise.all([
    detectWaf(targetUrl),
    activeProbeTarget(targetUrl),
  ]);

  // Merge active probe results into the passive detection result
  passiveResult.activeProbe = activeResult;

  // If active probing found NGFW/IDS but passive didn't detect WAF,
  // upgrade the detection result
  if (!passiveResult.detected && (activeResult.idsDetected || activeResult.ngfwDetected)) {
    passiveResult.detected = true;
    passiveResult.vendor = activeResult.ngfwProduct || activeResult.idsProduct || 'NGFW/IDS (active probe)';
    passiveResult.confidence = 'medium';
  }

  // Merge evasion hints from active probing
  if (activeResult.evasionAdjustments.length > 0) {
    passiveResult.evasionHints = [
      ...passiveResult.evasionHints,
      '--- Active Probe Recommendations ---',
      ...activeResult.evasionAdjustments,
    ];
  }

  // Add behavioral evidence
  for (const method of activeResult.detectionMethods) {
    passiveResult.evidence.push(method);
  }

  return passiveResult;
}
