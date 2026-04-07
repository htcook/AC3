import { describe, it, expect } from "vitest";
import {
  detectFromBanner,
  detectWafFromBanners,
  mergeBannerWafIntoAsset,
  generateEvasionProfile,
} from "./lib/banner-waf-detector";
import type { BannerWafDetection, BannerWafSummary } from "./lib/banner-waf-detector";

// ─── Helper: create a mock FingerprintResult ────────────────────────────────
function mockFp(overrides: Partial<{
  port: number; protocol: string; product: string | null;
  version: string | null; banner: string | null; os: string | null; error?: string;
}> = {}) {
  return {
    port: overrides.port ?? 443,
    protocol: overrides.protocol ?? "https",
    product: overrides.product ?? null,
    version: overrides.version ?? null,
    banner: overrides.banner ?? null,
    os: overrides.os ?? null,
    error: overrides.error,
    securityFlags: {},
    riskIndicators: [],
    potentialCves: [],
    confidence: 80,
    durationMs: 100,
  } as any;
}

// ─── detectFromBanner ───────────────────────────────────────────────────────

describe("detectFromBanner", () => {
  it("detects F5 BIG-IP from banner", () => {
    const fp = mockFp({ port: 443, banner: "BIG-IP httpd/1.0" });
    const result = detectFromBanner(fp);
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe("F5 Networks");
    expect(result!.product).toBe("BIG-IP");
    expect(result!.category).toBe("waf");
    expect(result!.confidence).toBeGreaterThanOrEqual(80);
    expect(result!.port).toBe(443);
  });

  it("detects Palo Alto PAN-OS from product field", () => {
    const fp = mockFp({ port: 4443, product: "PAN-OS GlobalProtect" });
    const result = detectFromBanner(fp);
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe("Palo Alto Networks");
    expect(result!.category).toBe("ids_ips");
  });

  it("detects Fortinet FortiGate from banner", () => {
    const fp = mockFp({ port: 8443, banner: "FortiOS v6.4.5 build1234" });
    const result = detectFromBanner(fp);
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe("Fortinet");
    expect(result!.product).toBe("FortiGate");
    expect(result!.category).toBe("ids_ips");
  });

  it("detects Cisco ASA from banner", () => {
    const fp = mockFp({ port: 443, banner: "Cisco Adaptive Security Appliance" });
    const result = detectFromBanner(fp);
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe("Cisco");
    expect(result!.product).toBe("ASA");
    expect(result!.category).toBe("firewall");
  });

  it("detects HAProxy from banner", () => {
    const fp = mockFp({ port: 80, banner: "HAProxy 2.4.0" });
    const result = detectFromBanner(fp);
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe("HAProxy");
    expect(result!.category).toBe("load_balancer");
  });

  it("detects pfSense from banner", () => {
    const fp = mockFp({ port: 443, banner: "pfSense 2.6.0" });
    const result = detectFromBanner(fp);
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe("Netgate");
    expect(result!.product).toBe("pfSense");
    expect(result!.category).toBe("firewall");
  });

  it("detects ModSecurity from banner", () => {
    const fp = mockFp({ port: 80, banner: "Apache/2.4.41 ModSecurity/3.0.4" });
    const result = detectFromBanner(fp);
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe("Trustwave");
    expect(result!.product).toBe("ModSecurity");
    expect(result!.category).toBe("waf");
  });

  it("detects Snort IDS from banner", () => {
    const fp = mockFp({ port: 22, banner: "Snort inline mode active" });
    const result = detectFromBanner(fp);
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe("Cisco");
    expect(result!.product).toBe("Snort IDS");
    expect(result!.category).toBe("ids_ips");
  });

  it("returns null for non-matching banner", () => {
    const fp = mockFp({ port: 22, banner: "OpenSSH_8.4p1" });
    const result = detectFromBanner(fp);
    expect(result).toBeNull();
  });

  it("returns null for empty banner", () => {
    const fp = mockFp({ port: 22, banner: "" });
    const result = detectFromBanner(fp);
    expect(result).toBeNull();
  });

  it("returns null for error fingerprint", () => {
    const fp = mockFp({ port: 22, error: "connection refused" });
    const result = detectFromBanner(fp);
    expect(result).toBeNull();
  });

  it("detects Imperva from product field", () => {
    const fp = mockFp({ port: 443, product: "Incapsula CDN" });
    const result = detectFromBanner(fp);
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe("Imperva");
    expect(result!.category).toBe("waf");
  });
});

// ─── detectWafFromBanners ───────────────────────────────────────────────────

describe("detectWafFromBanners", () => {
  it("returns empty summary for no fingerprints", () => {
    const result = detectWafFromBanners([]);
    expect(result.detections).toHaveLength(0);
    expect(result.posture).toBe("minimal_security");
    expect(result.reduceGlobalRate).toBe(false);
  });

  it("returns empty summary for undefined input", () => {
    const result = detectWafFromBanners(undefined);
    expect(result.detections).toHaveLength(0);
  });

  it("detects multiple appliances across ports", () => {
    const fps = [
      mockFp({ port: 443, banner: "BIG-IP httpd/1.0" }),
      mockFp({ port: 8443, banner: "FortiOS v6.4.5" }),
      mockFp({ port: 22, banner: "OpenSSH_8.4p1" }),
    ];
    const result = detectWafFromBanners(fps);
    expect(result.detections).toHaveLength(2);
    expect(result.uniqueVendors).toContain("F5 Networks");
    expect(result.uniqueVendors).toContain("Fortinet");
  });

  it("sets high_security posture for WAF + IDS combo", () => {
    const fps = [
      mockFp({ port: 443, banner: "BIG-IP httpd/1.0" }),  // WAF
      mockFp({ port: 8443, banner: "FortiOS v6.4.5" }),    // IDS/IPS
    ];
    const result = detectWafFromBanners(fps);
    expect(result.posture).toBe("high_security");
  });

  it("sets moderate_security for WAF only", () => {
    const fps = [
      mockFp({ port: 443, banner: "BIG-IP httpd/1.0" }),
    ];
    const result = detectWafFromBanners(fps);
    expect(result.posture).toBe("moderate_security");
  });

  it("aggregates evasion recommendations", () => {
    const fps = [
      mockFp({ port: 443, banner: "BIG-IP httpd/1.0" }),
      mockFp({ port: 8443, banner: "FortiOS v6.4.5" }),
    ];
    const result = detectWafFromBanners(fps);
    expect(result.evasionRecommendations.length).toBeGreaterThan(0);
  });

  it("sets reduceGlobalRate when IDS detected", () => {
    const fps = [
      mockFp({ port: 443, banner: "Suricata IDS" }),
    ];
    const result = detectWafFromBanners(fps);
    expect(result.reduceGlobalRate).toBe(true);
  });
});

// ─── mergeBannerWafIntoAsset ────────────────────────────────────────────────

describe("mergeBannerWafIntoAsset", () => {
  it("adds new vendors to empty existing WAF", () => {
    const detections: BannerWafDetection[] = [{
      detected: true, vendor: "F5 Networks", product: "BIG-IP",
      category: "waf", confidence: 90, matchedPattern: "BIG-IP",
      port: 443, protocol: "https", evasionTechniques: [],
      scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: false, fragmentPayloads: true },
    }];
    const result = mergeBannerWafIntoAsset(undefined, detections);
    expect(result.wafVendor).toBe("F5 Networks");
    expect(result.newDetections).toBe(true);
  });

  it("merges with existing vendors without duplicates", () => {
    const detections: BannerWafDetection[] = [{
      detected: true, vendor: "Fortinet", product: "FortiGate",
      category: "ids_ips", confidence: 90, matchedPattern: "FortiOS",
      port: 8443, protocol: "https", evasionTechniques: [],
      scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: true, fragmentPayloads: true },
    }];
    const result = mergeBannerWafIntoAsset("Cloudflare", detections);
    expect(result.wafVendor).toContain("Cloudflare");
    expect(result.wafVendor).toContain("Fortinet");
    expect(result.newDetections).toBe(true);
  });

  it("does not flag new detections for already-known vendors", () => {
    const detections: BannerWafDetection[] = [{
      detected: true, vendor: "F5 Networks", product: "BIG-IP",
      category: "waf", confidence: 90, matchedPattern: "BIG-IP",
      port: 443, protocol: "https", evasionTechniques: [],
      scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: false, fragmentPayloads: true },
    }];
    const result = mergeBannerWafIntoAsset("F5 Networks", detections);
    expect(result.newDetections).toBe(false);
  });

  it("returns unchanged for empty detections", () => {
    const result = mergeBannerWafIntoAsset("Cloudflare", []);
    expect(result.wafVendor).toBe("Cloudflare");
    expect(result.newDetections).toBe(false);
  });
});

// ─── generateEvasionProfile ─────────────────────────────────────────────────

describe("generateEvasionProfile", () => {
  it("returns default profile for no detections", () => {
    const summary: BannerWafSummary = {
      detections: [], uniqueVendors: [],
      posture: "minimal_security", evasionRecommendations: [],
      reduceGlobalRate: false,
    };
    const profile = generateEvasionProfile(summary);
    expect(profile.rateMultiplier).toBe(1.0);
    expect(profile.useFragmentation).toBe(false);
    expect(profile.skipAggressive).toBe(false);
    expect(profile.nucleiFlags).toHaveLength(0);
  });

  it("reduces rate for IDS detection", () => {
    const summary: BannerWafSummary = {
      detections: [{
        detected: true, vendor: "OISF", product: "Suricata IDS/IPS",
        category: "ids_ips", confidence: 85, matchedPattern: "Suricata",
        port: 80, protocol: "http", evasionTechniques: [],
        scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: false, fragmentPayloads: true },
      }],
      uniqueVendors: ["OISF"], posture: "moderate_security",
      evasionRecommendations: [], reduceGlobalRate: true,
    };
    const profile = generateEvasionProfile(summary);
    expect(profile.rateMultiplier).toBeLessThan(1.0);
    expect(profile.useFragmentation).toBe(true);
  });

  it("enables encryption for high_security posture", () => {
    const summary: BannerWafSummary = {
      detections: [
        { detected: true, vendor: "F5 Networks", product: "BIG-IP", category: "waf", confidence: 90, matchedPattern: "BIG-IP", port: 443, protocol: "https", evasionTechniques: [], scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: false, fragmentPayloads: true } },
        { detected: true, vendor: "Fortinet", product: "FortiGate", category: "ids_ips", confidence: 90, matchedPattern: "FortiOS", port: 8443, protocol: "https", evasionTechniques: [], scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: true, fragmentPayloads: true } },
      ],
      uniqueVendors: ["F5 Networks", "Fortinet"], posture: "high_security",
      evasionRecommendations: [], reduceGlobalRate: true,
    };
    const profile = generateEvasionProfile(summary);
    expect(profile.useEncryption).toBe(true);
    expect(profile.skipAggressive).toBe(true);
    expect(profile.rateMultiplier).toBeLessThanOrEqual(0.3);
  });

  it("adds custom headers when evasion is needed", () => {
    const summary: BannerWafSummary = {
      detections: [{
        detected: true, vendor: "Trustwave", product: "ModSecurity",
        category: "waf", confidence: 75, matchedPattern: "ModSecurity",
        port: 80, protocol: "http", evasionTechniques: [],
        scanImpact: { reduceRate: false, useEvasion: true, skipAggressive: false, fragmentPayloads: false },
      }],
      uniqueVendors: ["Trustwave"], posture: "moderate_security",
      evasionRecommendations: [], reduceGlobalRate: false,
    };
    const profile = generateEvasionProfile(summary);
    expect(profile.customHeaders["X-Forwarded-For"]).toBe("127.0.0.1");
  });

  it("generates nuclei flags for rate-limited scanning", () => {
    const summary: BannerWafSummary = {
      detections: [{
        detected: true, vendor: "Palo Alto Networks", product: "PAN-OS",
        category: "ids_ips", confidence: 90, matchedPattern: "PAN-OS",
        port: 443, protocol: "https", evasionTechniques: [],
        scanImpact: { reduceRate: true, useEvasion: true, skipAggressive: true, fragmentPayloads: true },
      }],
      uniqueVendors: ["Palo Alto Networks"], posture: "moderate_security",
      evasionRecommendations: [], reduceGlobalRate: true,
    };
    const profile = generateEvasionProfile(summary);
    expect(profile.nucleiFlags.length).toBeGreaterThan(0);
    expect(profile.nucleiFlags.some(f => f.includes("rate-limit"))).toBe(true);
  });
});
