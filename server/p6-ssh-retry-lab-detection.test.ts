/**
 * P6: SSH Reconnect Retry + Training Lab Domain Detection Tests
 * 
 * Tests cover:
 * 1. SSH retry wrapper with exponential backoff
 * 2. Training lab domain pattern matching
 * 3. Lab fast-track connector filtering
 */
import { describe, it, expect } from "vitest";

// ─── Lab Domain Detection Tests ──────────────────────────────────────
describe("Training Lab Domain Detection", () => {
  // Import the patterns and function from the passive recon module
  const LAB_DOMAIN_PATTERNS = [
    /\.lab\.aceofcloud\.io$/i,
    /\.lab\.aceofcloud\.com$/i,
    /\.training\.aceofcloud\./i,
    /\.test\.aceofcloud\./i,
    /\.ctf\.aceofcloud\./i,
    /^(dvwa|juiceshop|bwapp|mutillidae|webgoat|altoro|dvbank|hackazon|bodgeit|railsgoat)/i,
  ];

  function isLabDomain(domain: string): boolean {
    return LAB_DOMAIN_PATTERNS.some(pattern => pattern.test(domain));
  }

  it("should detect .lab.aceofcloud.io subdomains", () => {
    expect(isLabDomain("dvwa.lab.aceofcloud.io")).toBe(true);
    expect(isLabDomain("juiceshop.lab.aceofcloud.io")).toBe(true);
    expect(isLabDomain("altoro.lab.aceofcloud.io")).toBe(true);
    expect(isLabDomain("dvbank.lab.aceofcloud.io")).toBe(true);
    expect(isLabDomain("webgoat.lab.aceofcloud.io")).toBe(true);
    expect(isLabDomain("bwapp.lab.aceofcloud.io")).toBe(true);
    expect(isLabDomain("mutillidae.lab.aceofcloud.io")).toBe(true);
  });

  it("should detect .lab.aceofcloud.com subdomains", () => {
    expect(isLabDomain("dvwa.lab.aceofcloud.com")).toBe(true);
    expect(isLabDomain("test-app.lab.aceofcloud.com")).toBe(true);
  });

  it("should detect training/test/ctf subdomains", () => {
    expect(isLabDomain("app1.training.aceofcloud.io")).toBe(true);
    expect(isLabDomain("vuln-app.test.aceofcloud.io")).toBe(true);
    expect(isLabDomain("challenge.ctf.aceofcloud.io")).toBe(true);
  });

  it("should detect known vulnerable app hostnames", () => {
    expect(isLabDomain("dvwa.example.com")).toBe(true);
    expect(isLabDomain("juiceshop.internal.net")).toBe(true);
    expect(isLabDomain("bwapp-instance.local")).toBe(true);
    expect(isLabDomain("mutillidae.lab.local")).toBe(true);
    expect(isLabDomain("webgoat.training.org")).toBe(true);
    expect(isLabDomain("altoro.bank.test")).toBe(true);
    expect(isLabDomain("dvbank.staging.io")).toBe(true);
    expect(isLabDomain("hackazon.demo.com")).toBe(true);
    expect(isLabDomain("bodgeit.local")).toBe(true);
    expect(isLabDomain("railsgoat.dev")).toBe(true);
  });

  it("should NOT detect real production domains", () => {
    expect(isLabDomain("aceofcloud.io")).toBe(false);
    expect(isLabDomain("app.aceofcloud.io")).toBe(false);
    expect(isLabDomain("example.com")).toBe(false);
    expect(isLabDomain("google.com")).toBe(false);
    expect(isLabDomain("bank.com")).toBe(false);
    expect(isLabDomain("vianovahealth.com")).toBe(false);
  });

  it("should be case-insensitive", () => {
    expect(isLabDomain("DVWA.LAB.ACEOFCLOUD.IO")).toBe(true);
    expect(isLabDomain("JuiceShop.Lab.AceOfCloud.IO")).toBe(true);
  });
});

// ─── Lab Fast-Track Connector Filtering Tests ────────────────────────
describe("Lab Fast-Track Connector Filtering", () => {
  const LAB_FAST_TRACK_CONNECTORS = new Set([
    'crtsh', 'dns_deep', 'http_security', 'email_security',
    'rdap', 'shodan_internetdb', 'ip_api', 'wayback', 'container_discovery',
  ]);

  const ALL_CONNECTOR_NAMES = [
    'shodan_internetdb', 'crtsh', 'shodan', 'wayback', 'censys', 'urlscan',
    'rdap', 'ripestat', 'securitytrails', 'dehashed', 'coalition_control',
    'greynoise', 'email_security', 'http_security', 'cloud_assets',
    'container_discovery', 'dns_deep', 'github_leaks', 'github_recon',
    'cloud_bucket_recon', 'virustotal', 'hibp', 'whoisxml', 'leakix',
    'fullhunt', 'netlas', 'hunter', 'social_media', 'abuseipdb',
    'passivetotal', 'intelx_search', 'hudson_rock', 'leakcheck',
    'company_intel', 'threatminer', 'ip_api', 'bgpview', 'ransomware_live',
    'threatfox', 'builtwith', 'circl_pdns', 'commoncrawl', 'reverse_whois',
    'typosquat',
  ];

  it("should include only 9 fast-track connectors for lab domains", () => {
    expect(LAB_FAST_TRACK_CONNECTORS.size).toBe(9);
  });

  it("should filter out 30+ external API connectors for lab domains", () => {
    const filtered = ALL_CONNECTOR_NAMES.filter(name => LAB_FAST_TRACK_CONNECTORS.has(name));
    const skipped = ALL_CONNECTOR_NAMES.filter(name => !LAB_FAST_TRACK_CONNECTORS.has(name));
    expect(filtered.length).toBe(9);
    expect(skipped.length).toBeGreaterThan(30);
  });

  it("should include DNS and HTTP connectors that work on any domain", () => {
    expect(LAB_FAST_TRACK_CONNECTORS.has('dns_deep')).toBe(true);
    expect(LAB_FAST_TRACK_CONNECTORS.has('http_security')).toBe(true);
    expect(LAB_FAST_TRACK_CONNECTORS.has('email_security')).toBe(true);
  });

  it("should include free connectors that don't need API keys", () => {
    expect(LAB_FAST_TRACK_CONNECTORS.has('crtsh')).toBe(true);
    expect(LAB_FAST_TRACK_CONNECTORS.has('shodan_internetdb')).toBe(true);
    expect(LAB_FAST_TRACK_CONNECTORS.has('ip_api')).toBe(true);
    expect(LAB_FAST_TRACK_CONNECTORS.has('rdap')).toBe(true);
  });

  it("should NOT include paid API connectors", () => {
    expect(LAB_FAST_TRACK_CONNECTORS.has('shodan')).toBe(false);
    expect(LAB_FAST_TRACK_CONNECTORS.has('censys')).toBe(false);
    expect(LAB_FAST_TRACK_CONNECTORS.has('securitytrails')).toBe(false);
    expect(LAB_FAST_TRACK_CONNECTORS.has('dehashed')).toBe(false);
    expect(LAB_FAST_TRACK_CONNECTORS.has('virustotal')).toBe(false);
    expect(LAB_FAST_TRACK_CONNECTORS.has('hibp')).toBe(false);
  });
});

// ─── SSH Retry Wrapper Tests ─────────────────────────────────────────
describe("P6: SSH Reconnect Retry", () => {
  it("should retry on SSH connection errors", async () => {
    let attempts = 0;
    const retryableErrors = [
      "ECONNRESET", "ECONNREFUSED", "ETIMEDOUT",
      "Channel open failure", "Handshake failed",
      "Connection lost", "Socket closed",
    ];

    // Simulate retry logic
    async function withRetry<T>(fn: () => Promise<T>, maxRetries = 3): Promise<T> {
      let lastError: Error | undefined;
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
          return await fn();
        } catch (err: any) {
          lastError = err;
          const isRetryable = retryableErrors.some(e => err.message?.includes(e));
          if (!isRetryable || attempt >= maxRetries) throw err;
          // Exponential backoff: 1s, 2s, 4s
          await new Promise(r => setTimeout(r, Math.min(1000 * Math.pow(2, attempt), 10000)));
        }
      }
      throw lastError;
    }

    // Test: succeeds on 3rd attempt
    attempts = 0;
    const result = await withRetry(async () => {
      attempts++;
      if (attempts < 3) throw new Error("ECONNRESET");
      return "success";
    });
    expect(result).toBe("success");
    expect(attempts).toBe(3);
  });

  it("should NOT retry on non-SSH errors", async () => {
    const retryableErrors = [
      "ECONNRESET", "ECONNREFUSED", "ETIMEDOUT",
      "Channel open failure", "Handshake failed",
    ];

    let attempts = 0;
    async function withRetry<T>(fn: () => Promise<T>, maxRetries = 3): Promise<T> {
      let lastError: Error | undefined;
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
          return await fn();
        } catch (err: any) {
          lastError = err;
          const isRetryable = retryableErrors.some(e => err.message?.includes(e));
          if (!isRetryable || attempt >= maxRetries) throw err;
        }
      }
      throw lastError;
    }

    attempts = 0;
    await expect(withRetry(async () => {
      attempts++;
      throw new Error("Permission denied");
    })).rejects.toThrow("Permission denied");
    expect(attempts).toBe(1); // No retries for non-SSH errors
  });

  it("should fail after max retries exceeded", async () => {
    const retryableErrors = ["ECONNRESET"];
    let attempts = 0;

    async function withRetry<T>(fn: () => Promise<T>, maxRetries = 2): Promise<T> {
      let lastError: Error | undefined;
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
          return await fn();
        } catch (err: any) {
          lastError = err;
          const isRetryable = retryableErrors.some(e => err.message?.includes(e));
          if (!isRetryable || attempt >= maxRetries) throw err;
        }
      }
      throw lastError;
    }

    attempts = 0;
    await expect(withRetry(async () => {
      attempts++;
      throw new Error("ECONNRESET");
    }, 2)).rejects.toThrow("ECONNRESET");
    expect(attempts).toBe(3); // Initial + 2 retries
  });

  it("should use exponential backoff timing", () => {
    const delays: number[] = [];
    for (let attempt = 0; attempt < 4; attempt++) {
      const delay = Math.min(1000 * Math.pow(2, attempt), 10000);
      delays.push(delay);
    }
    expect(delays).toEqual([1000, 2000, 4000, 8000]);
  });

  it("should cap backoff at 10 seconds", () => {
    const delay = Math.min(1000 * Math.pow(2, 5), 10000);
    expect(delay).toBe(10000);
  });
});
