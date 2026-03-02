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
            "User-Agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
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
