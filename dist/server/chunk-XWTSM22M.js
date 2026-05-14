import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/waf-detector.ts
async function detectWaf(targetUrl) {
  const evidence = [];
  let detectedWaf = null;
  let confidence = "low";
  try {
    const normalResponse = await fetch(targetUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      },
      signal: AbortSignal.timeout(1e4)
    });
    const normalHeaders = Object.fromEntries(normalResponse.headers.entries());
    const normalBody = await normalResponse.text();
    for (const sig of WAF_SIGNATURES) {
      for (const headerSig of sig.headers) {
        const headerValue = normalHeaders[headerSig.name.toLowerCase()];
        if (headerValue && headerSig.pattern.test(headerValue)) {
          detectedWaf = sig;
          evidence.push(`Header match: ${headerSig.name}=${headerValue}`);
          confidence = "high";
        }
      }
      for (const bodyPattern of sig.bodyPatterns) {
        if (bodyPattern.test(normalBody)) {
          detectedWaf = sig;
          evidence.push(`Body pattern match: ${bodyPattern.source}`);
          confidence = "high";
        }
      }
    }
    if (!detectedWaf) {
      try {
        const suspiciousUrl = new URL(targetUrl);
        suspiciousUrl.searchParams.set("id", "1' OR '1'='1");
        const suspiciousResponse = await fetch(suspiciousUrl.toString(), {
          headers: {
            "User-Agent": "Mozilla/5.0 (compatible; ScanForge Discovery Engine; https://github.com/projectdiscovery)"
          },
          signal: AbortSignal.timeout(1e4)
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
              "Avoid common attack signatures in URLs"
            ]
          };
        }
      } catch {
        evidence.push("Suspicious request timed out or was blocked");
      }
    }
  } catch (e) {
    evidence.push(`Connection error: ${e.message}`);
    return { detected: false, confidence: "low", evidence, evasionHints: [] };
  }
  if (detectedWaf) {
    return {
      detected: true,
      vendor: detectedWaf.name,
      confidence,
      evidence,
      evasionHints: detectedWaf.evasionHints
    };
  }
  return { detected: false, confidence: "low", evidence, evasionHints: [] };
}
async function activeProbeTarget(targetUrl) {
  const result = {
    idsDetected: false,
    ngfwDetected: false,
    detectionMethods: [],
    behavioral: {
      rateLimitDetected: false,
      geoBlockDetected: false,
      botDetectionActive: false,
      dpiLikely: false,
      tlsInspectionDetected: false
    },
    evasionAdjustments: []
  };
  try {
    for (const sig of IDS_SIGNATURES) {
      let matched = false;
      for (const probe of sig.probePayloads) {
        try {
          const probeUrl = new URL(probe.path, targetUrl).toString();
          const resp = await fetch(probeUrl, {
            method: probe.method || "GET",
            headers: {
              "User-Agent": probe.headers?.["User-Agent"] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
              ...probe.headers
            },
            signal: AbortSignal.timeout(8e3)
          });
          const respHeaders = Object.fromEntries(resp.headers.entries());
          const body = await resp.text();
          for (const pattern of sig.responsePatterns) {
            if (pattern.status && resp.status === pattern.status) {
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
          await new Promise((r) => setTimeout(r, 500));
        } catch {
          continue;
        }
      }
      if (matched) {
        const isNGFW = ["Palo Alto NGFW", "Cisco Firepower", "Check Point", "FortiGate NGFW"].includes(sig.name);
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
    try {
      const rapidResults = [];
      for (let i = 0; i < 10; i++) {
        try {
          const resp = await fetch(targetUrl, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
            signal: AbortSignal.timeout(5e3)
          });
          rapidResults.push(resp.status);
        } catch {
          rapidResults.push(0);
        }
      }
      const blocked = rapidResults.filter((s) => s === 429 || s === 503 || s === 0).length;
      if (blocked >= 3) {
        result.behavioral.rateLimitDetected = true;
        const firstBlock = rapidResults.findIndex((s) => s === 429 || s === 503 || s === 0);
        result.behavioral.rateLimitThreshold = firstBlock > 0 ? firstBlock : 5;
        result.detectionMethods.push(`Rate limiting detected: ${blocked}/10 requests blocked`);
        result.evasionAdjustments.push(
          `Rate limit detected at ~${result.behavioral.rateLimitThreshold} req/burst \u2014 use ${Math.max(1, (result.behavioral.rateLimitThreshold || 5) - 2)} req/sec max`,
          "Add random jitter (1-3s) between requests",
          "Distribute requests across multiple source IPs if available"
        );
      }
    } catch {
    }
    try {
      const botResp = await fetch(targetUrl, {
        headers: {
          "User-Agent": "python-requests/2.28.0",
          "Accept": "*/*"
        },
        signal: AbortSignal.timeout(8e3)
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
        /managed.*challenge/i
      ];
      const botMatches = botIndicators.filter((p) => p.test(botBody));
      if (botMatches.length >= 1) {
        result.behavioral.botDetectionActive = true;
        result.detectionMethods.push(`Bot detection active: ${botMatches.length} indicator(s) found`);
        result.evasionAdjustments.push(
          "Use headless browser with stealth plugins for initial requests",
          "Maintain realistic browser fingerprint (TLS JA3, HTTP/2 settings)",
          "Implement cookie jar to handle challenge-response flows",
          "Pre-solve challenges before launching scan payloads"
        );
      }
    } catch {
    }
    try {
      const benignResp = await fetch(targetUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        body: "username=test&password=test123",
        signal: AbortSignal.timeout(8e3)
      });
      const benignStatus = benignResp.status;
      const dpiResp = await fetch(targetUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        body: "username=admin'--&password=<script>alert(1)</script>",
        signal: AbortSignal.timeout(8e3)
      });
      const dpiStatus = dpiResp.status;
      if ((benignStatus < 400 || benignStatus === 404) && (dpiStatus === 403 || dpiStatus === 406)) {
        result.behavioral.dpiLikely = true;
        result.detectionMethods.push(`DPI likely: benign POST=${benignStatus}, malicious POST=${dpiStatus}`);
        result.evasionAdjustments.push(
          "Use multi-layer encoding (URL + Unicode + HTML entity)",
          "Split payloads across multiple parameters",
          "Use JSON content-type instead of form-urlencoded",
          "Employ HTTP parameter pollution techniques"
        );
      }
    } catch {
    }
    try {
      if (targetUrl.startsWith("https://")) {
        const tlsResp = await fetch(targetUrl, {
          headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
          signal: AbortSignal.timeout(8e3)
        });
        const tlsHeaders = Object.fromEntries(tlsResp.headers.entries());
        const inspectionIndicators = [
          "x-bluecoat-via",
          "x-zscaler",
          "x-forcepoint",
          "x-websense",
          "via"
        ];
        for (const header of inspectionIndicators) {
          const val = tlsHeaders[header];
          if (val && /proxy|gateway|inspection|zscaler|bluecoat|forcepoint|websense/i.test(val)) {
            result.behavioral.tlsInspectionDetected = true;
            result.detectionMethods.push(`TLS inspection detected via header: ${header}=${val}`);
            result.evasionAdjustments.push(
              "Use certificate pinning bypass techniques",
              "Consider domain fronting for C2 traffic",
              "Use encrypted channels within HTTPS (nested encryption)"
            );
            break;
          }
        }
      }
    } catch {
    }
  } catch (e) {
    result.detectionMethods.push(`Active probing error: ${e.message}`);
  }
  result.evasionAdjustments = [...new Set(result.evasionAdjustments)];
  return result;
}
async function detectWafEnhanced(targetUrl) {
  const [passiveResult, activeResult] = await Promise.all([
    detectWaf(targetUrl),
    activeProbeTarget(targetUrl)
  ]);
  passiveResult.activeProbe = activeResult;
  if (!passiveResult.detected && (activeResult.idsDetected || activeResult.ngfwDetected)) {
    passiveResult.detected = true;
    passiveResult.vendor = activeResult.ngfwProduct || activeResult.idsProduct || "NGFW/IDS (active probe)";
    passiveResult.confidence = "medium";
  }
  if (activeResult.evasionAdjustments.length > 0) {
    passiveResult.evasionHints = [
      ...passiveResult.evasionHints,
      "--- Active Probe Recommendations ---",
      ...activeResult.evasionAdjustments
    ];
  }
  for (const method of activeResult.detectionMethods) {
    passiveResult.evidence.push(method);
  }
  return passiveResult;
}
var WAF_SIGNATURES, IDS_SIGNATURES;
var init_waf_detector = __esm({
  "server/lib/waf-detector.ts"() {
    WAF_SIGNATURES = [
      {
        name: "Cloudflare",
        headers: [
          { name: "server", pattern: /cloudflare/i },
          { name: "cf-ray", pattern: /.+/ },
          { name: "cf-cache-status", pattern: /.+/ }
        ],
        bodyPatterns: [/Attention Required! \| Cloudflare/i, /cf-error-details/i],
        statusCodes: [403, 503],
        evasionHints: [
          "Use slower scan rate (max 2 req/sec)",
          "Rotate User-Agent headers",
          "Avoid common attack payloads in initial spider",
          "Use IP rotation if available"
        ]
      },
      {
        name: "AWS WAF",
        headers: [
          { name: "x-amzn-requestid", pattern: /.+/ },
          { name: "x-amz-apigw-id", pattern: /.+/ }
        ],
        bodyPatterns: [/Request blocked/i, /AWS WAF/i],
        statusCodes: [403],
        evasionHints: [
          "Reduce request rate to avoid rate-based rules",
          "Vary HTTP methods and paths",
          "Use encoded payloads for injection tests",
          "Test with different Content-Type headers"
        ]
      },
      {
        name: "Akamai",
        headers: [
          { name: "x-akamai-transformed", pattern: /.+/ },
          { name: "server", pattern: /AkamaiGHost/i }
        ],
        bodyPatterns: [/Access Denied.*Akamai/i, /Reference #/i],
        statusCodes: [403],
        evasionHints: [
          "Use very slow scan rate (1 req/sec)",
          "Avoid automated scanner signatures",
          "Use custom User-Agent strings",
          "Fragment payloads across multiple parameters"
        ]
      },
      {
        name: "Imperva/Incapsula",
        headers: [
          { name: "x-iinfo", pattern: /.+/ },
          { name: "x-cdn", pattern: /Incapsula/i }
        ],
        bodyPatterns: [/Incapsula incident/i, /Request unsuccessful/i, /_Incapsula_Resource/i],
        statusCodes: [403],
        evasionHints: [
          "Implement cookie handling for Incapsula challenges",
          "Solve JavaScript challenges before scanning",
          "Use browser-like request patterns",
          "Avoid known bad IP ranges"
        ]
      },
      {
        name: "F5 BIG-IP ASM",
        headers: [
          { name: "server", pattern: /BIG-IP/i },
          { name: "x-wa-info", pattern: /.+/ }
        ],
        bodyPatterns: [/The requested URL was rejected/i, /support ID/i],
        statusCodes: [403],
        evasionHints: [
          "Test parameter pollution techniques",
          "Use HTTP method override headers",
          "Try alternative encoding schemes",
          "Check for bypass via HTTP/2"
        ]
      },
      {
        name: "ModSecurity",
        headers: [
          { name: "server", pattern: /mod_security/i }
        ],
        bodyPatterns: [/ModSecurity/i, /Not Acceptable/i, /OWASP.*CRS/i],
        statusCodes: [403, 406],
        evasionHints: [
          "Identify CRS paranoia level via incremental testing",
          "Use Unicode normalization bypasses",
          "Test with different character encodings",
          "Check for rule exclusion via specific paths"
        ]
      },
      {
        name: "Sucuri",
        headers: [
          { name: "x-sucuri-id", pattern: /.+/ },
          { name: "server", pattern: /Sucuri/i }
        ],
        bodyPatterns: [/Sucuri Website Firewall/i, /Access Denied - Sucuri/i],
        statusCodes: [403],
        evasionHints: [
          "Attempt direct origin IP access",
          "Use slow scan rate",
          "Vary request patterns to avoid behavioral detection"
        ]
      },
      {
        name: "Fortinet FortiWeb",
        headers: [
          { name: "server", pattern: /FortiWeb/i }
        ],
        bodyPatterns: [/FortiWeb/i, /Attack was detected/i],
        statusCodes: [403],
        evasionHints: [
          "Use HTTP parameter fragmentation",
          "Test with chunked transfer encoding",
          "Vary case in SQL keywords"
        ]
      }
    ];
    IDS_SIGNATURES = [
      {
        name: "Snort/Suricata",
        probePayloads: [
          { path: "/etc/passwd", headers: { "User-Agent": "Nikto/2.1.6" } },
          { path: "/?cmd=cat+/etc/shadow" },
          { path: "/?file=../../../../etc/passwd" }
        ],
        responsePatterns: [
          { status: 403 },
          { bodyPattern: /blocked by.*(?:snort|suricata|intrusion)/i },
          { headerPattern: { name: "x-ids-alert", pattern: /.+/ } }
        ],
        evasionTips: [
          "Fragment payloads across multiple packets (use chunked encoding)",
          "Use Unicode/UTF-8 encoding for path traversal",
          "Vary timing between requests (2-5s random delay)",
          "Use HTTP/2 multiplexing to evade stream-based inspection",
          "Encode payloads with double URL encoding"
        ]
      },
      {
        name: "Palo Alto NGFW",
        probePayloads: [
          { path: "/?test=<script>alert(1)</script>" },
          { path: "/admin", headers: { "X-Forwarded-For": "127.0.0.1" } },
          { path: "/", headers: { "User-Agent": "sqlmap/1.0" } }
        ],
        responsePatterns: [
          { bodyPattern: /Palo Alto/i },
          { headerPattern: { name: "x-pan-", pattern: /.+/ } },
          { bodyPattern: /Threat Prevention/i }
        ],
        evasionTips: [
          "Use application-layer tunneling (WebSocket, gRPC)",
          "Encrypt payloads within legitimate-looking POST bodies",
          "Use DNS-over-HTTPS for C2 communication",
          "Leverage allowed cloud services for data exfiltration",
          "Use legitimate browser fingerprints to bypass App-ID"
        ]
      },
      {
        name: "Cisco Firepower",
        probePayloads: [
          { path: "/?id=1%20UNION%20SELECT%201,2,3--" },
          { path: "/cgi-bin/../../etc/passwd" }
        ],
        responsePatterns: [
          { bodyPattern: /Cisco.*(?:Firepower|ASA)/i },
          { headerPattern: { name: "server", pattern: /Cisco/i } },
          { bodyPattern: /Access.*Policy.*Block/i }
        ],
        evasionTips: [
          "Use HTTP parameter pollution to split payloads",
          "Leverage IPv6 if available (often less inspected)",
          "Use legitimate-looking HTTP methods (GET with body)",
          "Fragment SQL injection across multiple parameters"
        ]
      },
      {
        name: "Check Point",
        probePayloads: [
          { path: "/?q=<img+src=x+onerror=alert(1)>" },
          { path: "/wp-admin/../wp-config.php" }
        ],
        responsePatterns: [
          { bodyPattern: /Check Point/i },
          { headerPattern: { name: "x-checkpoint", pattern: /.+/ } },
          { bodyPattern: /UserCheck/i }
        ],
        evasionTips: [
          "Use HTTPS with client certificates to bypass inspection",
          "Leverage WebSocket connections for payload delivery",
          "Use JSON-based payloads instead of URL-encoded",
          "Employ slow-rate attacks to stay under threshold"
        ]
      },
      {
        name: "FortiGate NGFW",
        probePayloads: [
          { path: "/?id=1+AND+1=1" },
          { path: "/shell.php" }
        ],
        responsePatterns: [
          { bodyPattern: /FortiGuard/i },
          { bodyPattern: /Fortinet/i },
          { headerPattern: { name: "server", pattern: /FortiWeb|Fortinet/i } }
        ],
        evasionTips: [
          "Use chunked transfer encoding to split payloads",
          "Employ case variation in SQL keywords",
          "Use HTTP/2 push promises for payload delivery",
          "Leverage allowed application categories for tunneling"
        ]
      }
    ];
  }
});

export {
  detectWaf,
  activeProbeTarget,
  detectWafEnhanced,
  init_waf_detector
};
