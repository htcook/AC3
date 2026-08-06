/**
 * Banner-Based WAF/IDS Detection
 *
 * Detects WAF, IDS, IPS, and load balancer signatures from TCP-level
 * service fingerprint banners. This complements the existing HTTP-based
 * WAF detection (which only works on web ports) by catching network-level
 * security appliances visible in raw banners.
 *
 * Detection categories:
 *   1. WAF/Reverse Proxy — F5 BIG-IP, Citrix NetScaler, Barracuda, etc.
 *   2. IDS/IPS — Snort, Suricata, Palo Alto, Fortinet, etc.
 *   3. Load Balancers — HAProxy, AWS ELB, Nginx Plus, etc.
 *   4. Firewalls — pfSense, OPNsense, Cisco ASA, etc.
 *
 * Runs after autoFingerprint() and before vuln scanning to inform
 * evasion profile selection.
 */

import type { FingerprintResult } from "./service-fingerprinter";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface BannerWafDetection {
  /** Whether a WAF/IDS/firewall was detected */
  detected: boolean;
  /** Product vendor name */
  vendor: string;
  /** Product name */
  product: string;
  /** Detection category */
  category: "waf" | "ids_ips" | "load_balancer" | "firewall" | "reverse_proxy";
  /** Detection confidence (0-100) */
  confidence: number;
  /** Which banner pattern matched */
  matchedPattern: string;
  /** Port where the detection occurred */
  port: number;
  /** Protocol of the service */
  protocol: string;
  /** Recommended evasion techniques */
  evasionTechniques: string[];
  /** Impact on scanning — how to adjust scan behavior */
  scanImpact: {
    reduceRate: boolean;
    useEvasion: boolean;
    skipAggressive: boolean;
    fragmentPayloads: boolean;
  };
}

export interface BannerWafSummary {
  /** All detections found across all banners */
  detections: BannerWafDetection[];
  /** Unique vendors detected */
  uniqueVendors: string[];
  /** Overall security posture assessment */
  posture: "high_security" | "moderate_security" | "minimal_security";
  /** Aggregated evasion recommendations */
  evasionRecommendations: string[];
  /** Whether to reduce overall scan rate */
  reduceGlobalRate: boolean;
}

// ─── Signature Database ─────────────────────────────────────────────────────

interface BannerSignature {
  pattern: RegExp;
  vendor: string;
  product: string;
  category: BannerWafDetection["category"];
  confidence: number;
  evasionTechniques: string[];
  scanImpact: BannerWafDetection["scanImpact"];
}

const BANNER_SIGNATURES: BannerSignature[] = [
  // ── WAF / Reverse Proxy ──────────────────────────────────────────────────
  {
    pattern: /BIG-?IP|F5|BigIP|TMOS/i,
    vendor: "F5 Networks",
    product: "BIG-IP",
    category: "waf",
    confidence: 90,
    evasionTechniques: [
      "Use HTTP parameter pollution",
      "Encode payloads with double URL encoding",
      "Fragment requests across multiple packets",
      "Use HTTP/2 multiplexing",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: false, fragmentPayloads: true },
  },
  {
    pattern: /NetScaler|Citrix\s*ADC|NS-CACHE|Citrix\s*Gateway/i,
    vendor: "Citrix",
    product: "NetScaler ADC",
    category: "waf",
    confidence: 85,
    evasionTechniques: [
      "Use chunked transfer encoding",
      "Vary Content-Type headers",
      "Use non-standard HTTP methods for probing",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: false, fragmentPayloads: false },
  },
  {
    pattern: /Barracuda|BWAF/i,
    vendor: "Barracuda",
    product: "WAF",
    category: "waf",
    confidence: 80,
    evasionTechniques: [
      "Use multipart form encoding",
      "Split payloads across parameters",
      "Use alternative character encodings (UTF-7, UTF-16)",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: true, fragmentPayloads: false },
  },
  {
    pattern: /Imperva|Incapsula|SecureSphere/i,
    vendor: "Imperva",
    product: "SecureSphere",
    category: "waf",
    confidence: 85,
    evasionTechniques: [
      "Use JSON-based payloads instead of URL params",
      "Obfuscate with JavaScript encoding",
      "Use WebSocket upgrade for payload delivery",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: true, fragmentPayloads: true },
  },
  {
    pattern: /ModSecurity|mod_security|OWASP.*CRS/i,
    vendor: "Trustwave",
    product: "ModSecurity",
    category: "waf",
    confidence: 75,
    evasionTechniques: [
      "Use HPP (HTTP Parameter Pollution)",
      "Encode with overlong UTF-8",
      "Use case variation in SQL keywords",
      "Comment injection in SQL payloads",
    ],
    scanImpact: { reduceRate: false, useEvasion: true, skipAggressive: false, fragmentPayloads: false },
  },
  {
    pattern: /Akamai|AkamaiGHost|Kona\s*Site\s*Defender/i,
    vendor: "Akamai",
    product: "Kona Site Defender",
    category: "waf",
    confidence: 80,
    evasionTechniques: [
      "Use IP rotation",
      "Slow down request rate significantly",
      "Use residential proxy chains",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: true, fragmentPayloads: false },
  },

  // ── IDS/IPS ──────────────────────────────────────────────────────────────
  {
    pattern: /Snort|snort_inline/i,
    vendor: "Cisco",
    product: "Snort IDS",
    category: "ids_ips",
    confidence: 85,
    evasionTechniques: [
      "Fragment TCP segments below signature length",
      "Use TTL-based evasion (short TTL packets)",
      "Reorder TCP segments",
      "Use polymorphic shellcode",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: false, fragmentPayloads: true },
  },
  {
    pattern: /Suricata/i,
    vendor: "OISF",
    product: "Suricata IDS/IPS",
    category: "ids_ips",
    confidence: 85,
    evasionTechniques: [
      "Use encrypted channels (TLS) for payload delivery",
      "Fragment at IP layer",
      "Use DNS tunneling for C2",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: false, fragmentPayloads: true },
  },
  {
    pattern: /PAN-?OS|Palo\s*Alto|PA-\d{3,4}/i,
    vendor: "Palo Alto Networks",
    product: "PAN-OS",
    category: "ids_ips",
    confidence: 90,
    evasionTechniques: [
      "Use application-layer tunneling",
      "Encrypt all traffic (TLS 1.3)",
      "Use legitimate cloud services for C2",
      "Avoid known malicious patterns",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: true, fragmentPayloads: true },
  },
  {
    pattern: /FortiOS|Fortinet|FortiGate|FortiGuard/i,
    vendor: "Fortinet",
    product: "FortiGate",
    category: "ids_ips",
    confidence: 90,
    evasionTechniques: [
      "Use SSL/TLS inspection bypass techniques",
      "Fragment payloads across multiple sessions",
      "Use protocol confusion (e.g., HTTP over non-standard ports)",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: true, fragmentPayloads: true },
  },
  {
    pattern: /Check\s*Point|CPSG|FW-1|SmartDefense/i,
    vendor: "Check Point",
    product: "SmartDefense",
    category: "ids_ips",
    confidence: 85,
    evasionTechniques: [
      "Use HTTP smuggling techniques",
      "Vary packet sizes",
      "Use non-standard ports for known protocols",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: false, fragmentPayloads: true },
  },
  {
    pattern: /Sophos\s*(XG|UTM|Firewall)|Cyberoam/i,
    vendor: "Sophos",
    product: "XG Firewall",
    category: "ids_ips",
    confidence: 80,
    evasionTechniques: [
      "Use HTTPS for all traffic",
      "Avoid signature-triggering payloads",
      "Use slow-rate scanning",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: false, fragmentPayloads: false },
  },

  // ── Load Balancers ───────────────────────────────────────────────────────
  {
    pattern: /HAProxy|haproxy/,
    vendor: "HAProxy",
    product: "HAProxy",
    category: "load_balancer",
    confidence: 80,
    evasionTechniques: [
      "Use sticky sessions to target specific backend",
      "Vary X-Forwarded-For headers",
    ],
    scanImpact: { reduceRate: false, useEvasion: false, skipAggressive: false, fragmentPayloads: false },
  },
  {
    pattern: /ELB|aws.*lb|Amazon.*Load/i,
    vendor: "AWS",
    product: "Elastic Load Balancer",
    category: "load_balancer",
    confidence: 75,
    evasionTechniques: [
      "Target backend IPs directly if discoverable",
      "Use X-Forwarded-For manipulation",
    ],
    scanImpact: { reduceRate: false, useEvasion: false, skipAggressive: false, fragmentPayloads: false },
  },
  {
    pattern: /nginx.*plus|nginx\/\d+\.\d+.*commercial/i,
    vendor: "Nginx",
    product: "Nginx Plus",
    category: "load_balancer",
    confidence: 60,
    evasionTechniques: [
      "Check for misconfigured proxy_pass",
      "Test for SSRF via Host header manipulation",
    ],
    scanImpact: { reduceRate: false, useEvasion: false, skipAggressive: false, fragmentPayloads: false },
  },

  // ── Firewalls ────────────────────────────────────────────────────────────
  {
    pattern: /pfSense|pfsense/i,
    vendor: "Netgate",
    product: "pfSense",
    category: "firewall",
    confidence: 85,
    evasionTechniques: [
      "Use non-standard ports",
      "Fragment packets below firewall inspection threshold",
      "Use IPv6 if available (often less filtered)",
    ],
    scanImpact: { reduceRate: false, useEvasion: true, skipAggressive: false, fragmentPayloads: true },
  },
  {
    pattern: /OPNsense/i,
    vendor: "Deciso",
    product: "OPNsense",
    category: "firewall",
    confidence: 85,
    evasionTechniques: [
      "Use non-standard ports",
      "Test for default credentials on management interface",
    ],
    scanImpact: { reduceRate: false, useEvasion: true, skipAggressive: false, fragmentPayloads: false },
  },
  {
    pattern: /Cisco\s*ASA|Adaptive\s*Security/i,
    vendor: "Cisco",
    product: "ASA",
    category: "firewall",
    confidence: 90,
    evasionTechniques: [
      "Use TCP segmentation",
      "Exploit inspection engine limitations",
      "Use application-layer tunneling",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: false, fragmentPayloads: true },
  },
  {
    pattern: /Juniper.*SRX|JunOS|Junos/i,
    vendor: "Juniper",
    product: "SRX",
    category: "firewall",
    confidence: 85,
    evasionTechniques: [
      "Use protocol-level evasion",
      "Test management interfaces on non-standard ports",
    ],
    scanImpact: { reduceRate: false, useEvasion: true, skipAggressive: false, fragmentPayloads: true },
  },
  {
    pattern: /SonicWall|SonicOS/i,
    vendor: "SonicWall",
    product: "SonicOS",
    category: "firewall",
    confidence: 85,
    evasionTechniques: [
      "Use SSL/TLS to bypass DPI",
      "Fragment payloads",
    ],
    scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: false, fragmentPayloads: true },
  },
  {
    pattern: /WatchGuard|Firebox/i,
    vendor: "WatchGuard",
    product: "Firebox",
    category: "firewall",
    confidence: 80,
    evasionTechniques: [
      "Use encrypted channels",
      "Test for default management credentials",
    ],
    scanImpact: { reduceRate: false, useEvasion: true, skipAggressive: false, fragmentPayloads: false },
  },
];

// ─── Detection Functions ────────────────────────────────────────────────────

/**
 * Detect WAF/IDS/firewall signatures from a single fingerprint result's banner.
 */
export function detectFromBanner(fp: FingerprintResult): BannerWafDetection | null {
  if (!fp || fp.error) return null;

  // Combine all text fields for matching
  const searchText = [
    fp.banner || "",
    fp.product || "",
    fp.version || "",
    fp.os || "",
  ].join(" ");

  if (!searchText.trim()) return null;

  for (const sig of BANNER_SIGNATURES) {
    const match = searchText.match(sig.pattern);
    if (match) {
      return {
        detected: true,
        vendor: sig.vendor,
        product: sig.product,
        category: sig.category,
        confidence: sig.confidence,
        matchedPattern: match[0],
        port: fp.port,
        protocol: fp.protocol,
        evasionTechniques: sig.evasionTechniques,
        scanImpact: { ...sig.scanImpact },
      };
    }
  }

  return null;
}

/**
 * Scan all fingerprint results for WAF/IDS/firewall signatures.
 * Returns a summary with all detections and aggregated recommendations.
 */
export function detectWafFromBanners(
  fingerprintResults: FingerprintResult[] | undefined,
): BannerWafSummary {
  const empty: BannerWafSummary = {
    detections: [],
    uniqueVendors: [],
    posture: "minimal_security",
    evasionRecommendations: [],
    reduceGlobalRate: false,
  };

  if (!fingerprintResults || fingerprintResults.length === 0) return empty;

  const detections: BannerWafDetection[] = [];
  const seenVendors = new Set<string>();

  for (const fp of fingerprintResults) {
    const detection = detectFromBanner(fp);
    if (detection) {
      detections.push(detection);
      seenVendors.add(detection.vendor);
    }
  }

  if (detections.length === 0) return empty;

  // Aggregate evasion recommendations (deduplicated, prioritized)
  const allTechniques = new Set<string>();
  for (const d of detections) {
    for (const t of d.evasionTechniques) {
      allTechniques.add(t);
    }
  }

  // Determine security posture
  const hasWaf = detections.some(d => d.category === "waf");
  const hasIds = detections.some(d => d.category === "ids_ips");
  const hasFirewall = detections.some(d => d.category === "firewall");
  const highConfidence = detections.some(d => d.confidence >= 85);

  let posture: BannerWafSummary["posture"] = "minimal_security";
  if ((hasWaf && hasIds) || (hasWaf && hasFirewall && highConfidence)) {
    posture = "high_security";
  } else if (hasWaf || hasIds || (hasFirewall && highConfidence)) {
    posture = "moderate_security";
  }

  // Should we reduce global scan rate?
  const reduceGlobalRate = detections.some(d => d.scanImpact.reduceRate) &&
    (hasIds || detections.filter(d => d.scanImpact.reduceRate).length >= 2);

  return {
    detections,
    uniqueVendors: [...seenVendors],
    posture,
    evasionRecommendations: [...allTechniques],
    reduceGlobalRate,
  };
}

/**
 * Merge banner-based WAF detections into the existing asset WAF data.
 * Returns the merged WAF vendor string and whether new detections were found.
 */
export function mergeBannerWafIntoAsset(
  existingWaf: string | undefined,
  bannerDetections: BannerWafDetection[],
): { wafVendor: string | undefined; newDetections: boolean } {
  if (bannerDetections.length === 0) {
    return { wafVendor: existingWaf, newDetections: false };
  }

  const existingVendors = new Set(
    (existingWaf || "")
      .split(",")
      .map(v => v.trim())
      .filter(Boolean),
  );

  let newDetections = false;
  for (const d of bannerDetections) {
    if (!existingVendors.has(d.vendor)) {
      existingVendors.add(d.vendor);
      newDetections = true;
    }
  }

  const merged = [...existingVendors].join(", ");
  return {
    wafVendor: merged || undefined,
    newDetections,
  };
}

/**
 * Generate an evasion profile based on banner WAF detections.
 * This can be fed into the exploit retry engine and nuclei scan configuration.
 */
export function generateEvasionProfile(summary: BannerWafSummary): {
  rateMultiplier: number;
  useFragmentation: boolean;
  useEncryption: boolean;
  skipAggressive: boolean;
  customHeaders: Record<string, string>;
  nucleiFlags: string[];
} {
  if (summary.detections.length === 0) {
    return {
      rateMultiplier: 1.0,
      useFragmentation: false,
      useEncryption: false,
      skipAggressive: false,
      customHeaders: {},
      nucleiFlags: [],
    };
  }

  const shouldFragment = summary.detections.some(d => d.scanImpact.fragmentPayloads);
  const shouldSkipAggressive = summary.detections.some(d => d.scanImpact.skipAggressive);
  const shouldUseEvasion = summary.detections.some(d => d.scanImpact.useEvasion);

  // Rate multiplier: reduce more for IDS/IPS than for simple firewalls
  let rateMultiplier = 1.0;
  if (summary.reduceGlobalRate) {
    const hasIds = summary.detections.some(d => d.category === "ids_ips");
    rateMultiplier = hasIds ? 0.3 : 0.5;
  } else if (summary.detections.some(d => d.scanImpact.reduceRate)) {
    rateMultiplier = 0.7;
  }

  // Nuclei-specific flags
  const nucleiFlags: string[] = [];
  if (shouldFragment) nucleiFlags.push("-timeout 20");
  if (rateMultiplier < 1.0) nucleiFlags.push(`-rate-limit ${Math.max(10, Math.floor(100 * rateMultiplier))}`);
  if (shouldUseEvasion) nucleiFlags.push("-retries 2");

  return {
    rateMultiplier,
    useFragmentation: shouldFragment,
    useEncryption: summary.posture === "high_security",
    skipAggressive: shouldSkipAggressive,
    customHeaders: shouldUseEvasion
      ? {
          "X-Forwarded-For": "127.0.0.1",
          "X-Originating-IP": "127.0.0.1",
          "X-Real-IP": "127.0.0.1",
        }
      : {},
    nucleiFlags,
  };
}
