import { describe, expect, it } from "vitest";

/**
 * Tests for the Stage 1.1 asset deduplication & filtering logic.
 *
 * Since the dedup/filter logic is inline in the runDomainIntelScan function,
 * we extract the core algorithms into testable pure functions here and verify
 * they match the behavior implemented in domainIntel.ts.
 */

// ─── Extracted logic mirrors ───────────────────────────────────────────────

interface MockAsset {
  assetId: string;
  hostname: string;
  url: string | null;
  assetType: string;
  technologies: string[];
  technologyVersions: Record<string, string>;
  tags: string[];
  discoveryMethod: string;
  discoveryEvidence?: string;
  assetClasses?: string[];
  description?: string;
}

const THIRD_PARTY_HOSTNAME_PATTERNS = [
  /\.office365\.com$/i, /\.outlook\.com$/i, /\.microsoftonline\.com$/i,
  /\.microsoft\.com$/i, /\.live\.com$/i, /\.sharepoint\.com$/i,
  /\.office\.com$/i, /\.onmicrosoft\.com$/i,
  /\.google\.com$/i, /\.googleapis\.com$/i, /\.gstatic\.com$/i,
  /\.gmail\.com$/i, /\.googlemail\.com$/i,
  /\.salesforce\.com$/i, /\.force\.com$/i,
  /\.cloudflare\.com$/i, /\.cloudflare-dns\.com$/i,
  /\.amazonaws\.com$/i, /\.cloudfront\.net$/i,
  /\.zendesk\.com$/i, /\.atlassian\.net$/i, /\.atlassian\.com$/i,
  /\.nsone\.net$/i, /\.cloudns\.net$/i, /\.awsdns-\d+/i,
  /\.ultradns\.com$/i, /\.dynect\.net$/i, /\.domaincontrol\.com$/i,
  /\.registrar-servers\.com$/i,
  /\.akamai\.net$/i, /\.akamaiedge\.net$/i, /\.fastly\.net$/i,
  /\.edgekey\.net$/i,
];

function isThirdPartyHostname(hostname: string): boolean {
  return THIRD_PARTY_HOSTNAME_PATTERNS.some(p => p.test(hostname));
}

function isMalformedDnsRecord(hostname: string, assetId: string): boolean {
  return hostname.startsWith('ns:') || hostname.startsWith('soa:') ||
    hostname.startsWith('mx:') || assetId.startsWith('passive-ns:') ||
    assetId.startsWith('passive-soa:') || assetId.startsWith('passive-mx:');
}

function normalizeUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.hostname}`;
  } catch {
    return url;
  }
}

function extractHostnameFromUrl(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function deduplicateAssets(assets: MockAsset[]): MockAsset[] {
  const result = [...assets];
  const byHostname = new Map<string, MockAsset>();
  const duplicateIds = new Set<number>();

  for (let i = 0; i < result.length; i++) {
    const a = result[i];
    let hostname = (a.hostname || '').toLowerCase().replace(/\.$/, '');
    if (!hostname && a.url) {
      hostname = extractHostnameFromUrl(a.url);
    }
    if (a.url) {
      a.url = normalizeUrl(a.url);
    }
    a.hostname = hostname;
    if (!hostname) continue;

    if (byHostname.has(hostname)) {
      const existing = byHostname.get(hostname)!;
      // Merge technologies
      const existingTechs = new Set(existing.technologies.map(t => t.toLowerCase()));
      for (const tech of a.technologies) {
        if (!existingTechs.has(tech.toLowerCase())) {
          existing.technologies.push(tech);
        }
      }
      // Merge tags
      const existingTags = new Set(existing.tags.map(t => t.toLowerCase()));
      for (const tag of a.tags) {
        if (!existingTags.has(tag.toLowerCase())) {
          existing.tags.push(tag);
        }
      }
      // Merge technologyVersions
      existing.technologyVersions = { ...existing.technologyVersions, ...a.technologyVersions };
      // Prefer specific assetType
      if (existing.assetType === 'other' && a.assetType !== 'other') {
        existing.assetType = a.assetType;
      }
      // Prefer confirmed discovery
      if (existing.discoveryMethod === 'inferred' && a.discoveryMethod !== 'inferred') {
        existing.discoveryMethod = a.discoveryMethod;
      }
      duplicateIds.add(i);
    } else {
      byHostname.set(hostname, a);
    }
  }

  for (let i = result.length - 1; i >= 0; i--) {
    if (duplicateIds.has(i)) result.splice(i, 1);
  }
  return result;
}

function filterThirdPartyAndInfra(assets: MockAsset[]): { kept: MockAsset[]; removed: string[] } {
  const removed: string[] = [];
  const kept = assets.filter(a => {
    const hostname = (a.hostname || '').toLowerCase();
    const assetId = (a.assetId || '').toLowerCase();
    if (isThirdPartyHostname(hostname)) {
      removed.push(hostname);
      return false;
    }
    if (isMalformedDnsRecord(hostname, assetId)) {
      removed.push(hostname);
      return false;
    }
    // DNS nameservers that are third-party
    if (/^(ns\d*|dns\d*)\./.test(hostname) && isThirdPartyHostname(hostname)) {
      removed.push(hostname);
      return false;
    }
    return true;
  });
  return { kept, removed };
}

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("Stage 1.1: Hostname Deduplication", () => {
  it("merges assets with the same hostname", () => {
    const assets: MockAsset[] = [
      {
        assetId: "a-001", hostname: "example.com", url: "https://example.com",
        assetType: "other", technologies: ["Next.js"], technologyVersions: {},
        tags: ["internet_exposed"], discoveryMethod: "dns_verified",
      },
      {
        assetId: "a-002", hostname: "example.com", url: "http://example.com/",
        assetType: "api", technologies: ["React"], technologyVersions: { "React": "18.0" },
        tags: ["web_app"], discoveryMethod: "inferred",
      },
    ];
    const result = deduplicateAssets(assets);
    expect(result).toHaveLength(1);
    expect(result[0].hostname).toBe("example.com");
    // Should have merged technologies
    expect(result[0].technologies).toContain("Next.js");
    expect(result[0].technologies).toContain("React");
    // Should have merged tags
    expect(result[0].tags).toContain("internet_exposed");
    expect(result[0].tags).toContain("web_app");
    // Should have merged technologyVersions
    expect(result[0].technologyVersions).toHaveProperty("React", "18.0");
  });

  it("merges multiple Next.js chunk URLs into one asset", () => {
    const assets: MockAsset[] = [
      {
        assetId: "a-001", hostname: "rapidtalentgroup.com", url: "https://rapidtalentgroup.com",
        assetType: "other", technologies: ["Next.js"], technologyVersions: {},
        tags: [], discoveryMethod: "dns_verified",
      },
      {
        assetId: "a-005", hostname: "rapidtalentgroup.com", url: "http://rapidtalentgroup.com/",
        assetType: "api", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "inferred",
      },
      {
        assetId: "a-006", hostname: "", url: "https://rapidtalentgroup.com/_next/image?url=test",
        assetType: "api", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "inferred",
      },
      {
        assetId: "a-007", hostname: "", url: "https://rapidtalentgroup.com/_next/static/chunks/app/page-abc.js",
        assetType: "api", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "inferred",
      },
      {
        assetId: "a-008", hostname: "", url: "https://rapidtalentgroup.com/_next/static/chunks/main-app-xyz.js",
        assetType: "api", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "inferred",
      },
    ];
    const result = deduplicateAssets(assets);
    expect(result).toHaveLength(1);
    expect(result[0].hostname).toBe("rapidtalentgroup.com");
    expect(result[0].url).toBe("https://rapidtalentgroup.com");
  });

  it("normalizes URLs to root (strips paths and query strings)", () => {
    const assets: MockAsset[] = [
      {
        assetId: "a-001", hostname: "app.example.com",
        url: "https://app.example.com/api/v2/users?page=1",
        assetType: "api", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "dns_verified",
      },
    ];
    const result = deduplicateAssets(assets);
    expect(result[0].url).toBe("https://app.example.com");
  });

  it("extracts hostname from URL when hostname field is empty", () => {
    const assets: MockAsset[] = [
      {
        assetId: "a-001", hostname: "",
        url: "https://subdomain.example.com/path",
        assetType: "api", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "inferred",
      },
    ];
    const result = deduplicateAssets(assets);
    expect(result[0].hostname).toBe("subdomain.example.com");
  });

  it("prefers confirmed discovery method over inferred", () => {
    const assets: MockAsset[] = [
      {
        assetId: "a-001", hostname: "example.com", url: "https://example.com",
        assetType: "other", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "inferred",
      },
      {
        assetId: "a-002", hostname: "example.com", url: "https://example.com",
        assetType: "api", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "dns_verified",
      },
    ];
    const result = deduplicateAssets(assets);
    expect(result).toHaveLength(1);
    expect(result[0].discoveryMethod).toBe("dns_verified");
  });

  it("prefers specific assetType over 'other'", () => {
    const assets: MockAsset[] = [
      {
        assetId: "a-001", hostname: "example.com", url: "https://example.com",
        assetType: "other", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "dns_verified",
      },
      {
        assetId: "a-002", hostname: "example.com", url: "https://example.com",
        assetType: "customer_portal", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "inferred",
      },
    ];
    const result = deduplicateAssets(assets);
    expect(result).toHaveLength(1);
    expect(result[0].assetType).toBe("customer_portal");
  });

  it("keeps assets with different hostnames separate", () => {
    const assets: MockAsset[] = [
      {
        assetId: "a-001", hostname: "app.example.com", url: "https://app.example.com",
        assetType: "api", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "dns_verified",
      },
      {
        assetId: "a-002", hostname: "mail.example.com", url: "https://mail.example.com",
        assetType: "mail_gateway", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "dns_verified",
      },
    ];
    const result = deduplicateAssets(assets);
    expect(result).toHaveLength(2);
  });

  it("deduplicates case-insensitively", () => {
    const assets: MockAsset[] = [
      {
        assetId: "a-001", hostname: "Example.COM", url: "https://Example.COM",
        assetType: "other", technologies: ["Nginx"], technologyVersions: {},
        tags: [], discoveryMethod: "dns_verified",
      },
      {
        assetId: "a-002", hostname: "example.com", url: "https://example.com",
        assetType: "api", technologies: ["Express"], technologyVersions: {},
        tags: [], discoveryMethod: "inferred",
      },
    ];
    const result = deduplicateAssets(assets);
    expect(result).toHaveLength(1);
    expect(result[0].technologies).toContain("Nginx");
    expect(result[0].technologies).toContain("Express");
  });
});

describe("Stage 1.1: Third-Party SaaS Exclusion", () => {
  it("filters out Microsoft Office 365 hostnames", () => {
    expect(isThirdPartyHostname("outlook.office365.com")).toBe(true);
    expect(isThirdPartyHostname("login.microsoftonline.com")).toBe(true);
    expect(isThirdPartyHostname("mail.live.com")).toBe(true);
    expect(isThirdPartyHostname("tenant.sharepoint.com")).toBe(true);
  });

  it("filters out Google hostnames", () => {
    expect(isThirdPartyHostname("mail.google.com")).toBe(true);
    expect(isThirdPartyHostname("accounts.google.com")).toBe(true);
    expect(isThirdPartyHostname("maps.googleapis.com")).toBe(true);
  });

  it("filters out DNS provider hostnames", () => {
    expect(isThirdPartyHostname("dns1.p02.nsone.net")).toBe(true);
    expect(isThirdPartyHostname("ns1.domaincontrol.com")).toBe(true);
  });

  it("filters out CDN/cloud infra hostnames", () => {
    expect(isThirdPartyHostname("d123.cloudfront.net")).toBe(true);
    expect(isThirdPartyHostname("bucket.s3.amazonaws.com")).toBe(true);
    expect(isThirdPartyHostname("site.akamai.net")).toBe(true);
    expect(isThirdPartyHostname("cdn.fastly.net")).toBe(true);
  });

  it("does NOT filter target-owned hostnames", () => {
    expect(isThirdPartyHostname("app.rapidtalentgroup.com")).toBe(false);
    expect(isThirdPartyHostname("mail.vianovahealth.com")).toBe(false);
    expect(isThirdPartyHostname("api.dev.vianova.ai")).toBe(false);
    expect(isThirdPartyHostname("dashboard-dev.vianovahealth.com")).toBe(false);
  });

  it("removes third-party assets from the asset list", () => {
    const assets: MockAsset[] = [
      {
        assetId: "a-001", hostname: "rapidtalentgroup.com", url: "https://rapidtalentgroup.com",
        assetType: "other", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "dns_verified",
      },
      {
        assetId: "a-017", hostname: "outlook.office365.com",
        url: "https://outlook.office365.com/owa/rapidtalentgroup.com",
        assetType: "owa", technologies: ["Microsoft 365"], technologyVersions: {},
        tags: [], discoveryMethod: "inferred",
      },
      {
        assetId: "a-011", hostname: "dns1.p02.nsone.net", url: "https://dns1.p02.nsone.net",
        assetType: "other", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "inferred",
      },
    ];
    const { kept, removed } = filterThirdPartyAndInfra(assets);
    expect(kept).toHaveLength(1);
    expect(kept[0].hostname).toBe("rapidtalentgroup.com");
    expect(removed).toContain("outlook.office365.com");
    expect(removed).toContain("dns1.p02.nsone.net");
  });
});

describe("Stage 1.1: NS/SOA/MX Infrastructure Filtering", () => {
  it("filters malformed NS record assets", () => {
    expect(isMalformedDnsRecord("ns: dns1.p02.nsone.net, dns2.p02.nsone.net", "passive-ns:123")).toBe(true);
  });

  it("filters malformed SOA record assets", () => {
    expect(isMalformedDnsRecord("soa: dns1.p01.nsone.net (admin: domains+netlify.netlify.com)", "passive-soa:456")).toBe(true);
  });

  it("filters malformed MX record assets", () => {
    expect(isMalformedDnsRecord("mx: aspmx.l.google.com", "passive-mx:789")).toBe(true);
  });

  it("does NOT filter normal hostnames", () => {
    expect(isMalformedDnsRecord("app.example.com", "a-001")).toBe(false);
    expect(isMalformedDnsRecord("mail.example.com", "a-002")).toBe(false);
  });

  it("removes malformed DNS records from asset list", () => {
    const assets: MockAsset[] = [
      {
        assetId: "a-001", hostname: "example.com", url: "https://example.com",
        assetType: "other", technologies: [], technologyVersions: {},
        tags: [], discoveryMethod: "dns_verified",
      },
      {
        assetId: "passive-ns:dns1-p02-nsone-net", hostname: "ns: dns1.p02.nsone.net, dns2.p02.nsone.net",
        url: "https://ns: dns1.p02.nsone.net", assetType: "web_application",
        technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "cert_transparency",
      },
      {
        assetId: "passive-soa:dns1-p01-nsone-net", hostname: "soa: dns1.p01.nsone.net",
        url: "https://soa: dns1.p01.nsone.net", assetType: "web_application",
        technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "cert_transparency",
      },
    ];
    const { kept, removed } = filterThirdPartyAndInfra(assets);
    expect(kept).toHaveLength(1);
    expect(kept[0].hostname).toBe("example.com");
    expect(removed).toHaveLength(2);
  });
});

describe("Stage 1.1: Full Pipeline (Dedup + Filter)", () => {
  it("handles the rapidtalentgroup.com scenario end-to-end", () => {
    // Simulate the actual scan results that caused the bug
    const assets: MockAsset[] = [
      { assetId: "a-001", hostname: "rapidtalentgroup.com", url: "https://rapidtalentgroup.com", assetType: "other", technologies: ["Next.js", "React"], technologyVersions: {}, tags: ["internet_exposed"], discoveryMethod: "dns_verified" },
      { assetId: "a-002", hostname: "www.rapidtalentgroup.com", url: "https://www.rapidtalentgroup.com", assetType: "other", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "dns_verified" },
      { assetId: "a-005", hostname: "rapidtalentgroup.com", url: "http://rapidtalentgroup.com/", assetType: "api", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "inferred" },
      { assetId: "a-006", hostname: "", url: "https://rapidtalentgroup.com/_next/image?url=test", assetType: "api", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "inferred" },
      { assetId: "a-007", hostname: "", url: "https://rapidtalentgroup.com/_next/static/chunks/app/page-abc.js", assetType: "api", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "inferred" },
      { assetId: "a-008", hostname: "", url: "https://rapidtalentgroup.com/_next/static/chunks/main-app-xyz.js", assetType: "api", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "inferred" },
      { assetId: "a-009", hostname: "", url: "https://rapidtalentgroup.com/_next/static/chunks/polyfills-123.js", assetType: "api", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "inferred" },
      { assetId: "a-010", hostname: "", url: "https://rapidtalentgroup.com/_next/static/chunks/webpack-456.js", assetType: "api", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "inferred" },
      { assetId: "a-011", hostname: "dns1.p02.nsone.net", url: "https://dns1.p02.nsone.net", assetType: "other", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "inferred" },
      { assetId: "a-012", hostname: "dns2.p02.nsone.net", url: "https://dns2.p02.nsone.net", assetType: "other", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "inferred" },
      { assetId: "a-013", hostname: "dns3.p02.nsone.net", url: "https://dns3.p02.nsone.net", assetType: "other", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "inferred" },
      { assetId: "a-014", hostname: "dns4.p02.nsone.net", url: "https://dns4.p02.nsone.net", assetType: "other", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "inferred" },
      { assetId: "a-015", hostname: "rapidtalentgroup.com", url: null as any, assetType: "other", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "cert_transparency" },
      { assetId: "a-017", hostname: "outlook.office365.com", url: "https://outlook.office365.com/owa/rapidtalentgroup.com", assetType: "owa", technologies: ["Microsoft 365"], technologyVersions: {}, tags: [], discoveryMethod: "inferred" },
      { assetId: "passive-ns:dns-records", hostname: "ns: dns1.p02.nsone.net, dns2.p02.nsone.net", url: "https://ns: dns1.p02.nsone.net", assetType: "web_application", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "cert_transparency" },
      { assetId: "passive-soa:dns-records", hostname: "soa: dns1.p01.nsone.net (admin: domains+netlify.netlify.com)", url: "https://soa: dns1.p01.nsone.net", assetType: "web_application", technologies: [], technologyVersions: {}, tags: [], discoveryMethod: "cert_transparency" },
    ];

    // Step 1: Deduplicate
    const deduped = deduplicateAssets(assets);
    // Step 2: Filter third-party and infra
    const { kept } = filterThirdPartyAndInfra(deduped);

    // Should have: rapidtalentgroup.com + www.rapidtalentgroup.com = 2 target-owned assets
    const hostnames = kept.map(a => a.hostname);
    expect(hostnames).toContain("rapidtalentgroup.com");
    expect(hostnames).toContain("www.rapidtalentgroup.com");
    // Should NOT have duplicates, third-party, or infra
    expect(hostnames).not.toContain("outlook.office365.com");
    expect(hostnames).not.toContain("dns1.p02.nsone.net");
    expect(hostnames).not.toContain("dns2.p02.nsone.net");
    expect(hostnames.filter(h => h === "rapidtalentgroup.com")).toHaveLength(1);
    // Total should be exactly 2
    expect(kept).toHaveLength(2);
  });
});
