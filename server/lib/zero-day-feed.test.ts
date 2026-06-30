import { describe, it, expect, beforeEach } from "vitest";
import {
  _testing,
  searchZeroDays,
  crossReferenceAssets,
  extractAssetsFromObservations,
  getZeroDayFeedStats,
  type ZeroDayEntry,
  type AssetForCrossRef,
} from "./zero-day-feed";

const { parseP0Csv, cleanField, extractFromBanner, isRecent, resetCache, setCache } = _testing;

// ─── Sample Data ────────────────────────────────────────────────────────────────

const SAMPLE_ENTRIES: ZeroDayEntry[] = [
  {
    cve: "CVE-2024-3094",
    vendor: "Tukaani Project",
    product: "xz Utils",
    type: "Backdoor",
    description: "Supply chain compromise via malicious build scripts in xz/liblzma",
    dateDiscovered: "2024-03-29",
    datePatched: "2024-03-30",
    advisoryUrl: "https://example.com/advisory/xz",
    analysisUrl: "https://example.com/analysis/xz",
    rootCauseAnalysis: "Supply chain attack via compromised maintainer",
    reportedBy: "Andres Freund",
    source: "project_zero",
    year: 2024,
  },
  {
    cve: "CVE-2024-23222",
    vendor: "Apple",
    product: "WebKit",
    type: "Type Confusion",
    description: "Type confusion issue in WebKit leading to arbitrary code execution",
    dateDiscovered: "2024-01-22",
    datePatched: "2024-01-22",
    advisoryUrl: "https://example.com/advisory/webkit",
    analysisUrl: null,
    rootCauseAnalysis: null,
    reportedBy: "Anonymous",
    source: "project_zero",
    year: 2024,
  },
  {
    cve: "CVE-2023-4863",
    vendor: "Google",
    product: "Chrome",
    type: "Heap Buffer Overflow",
    description: "Heap buffer overflow in WebP in Google Chrome",
    dateDiscovered: "2023-09-11",
    datePatched: "2023-09-12",
    advisoryUrl: "https://example.com/advisory/chrome-webp",
    analysisUrl: "https://example.com/analysis/chrome-webp",
    rootCauseAnalysis: "Heap buffer overflow in libwebp",
    reportedBy: "Apple SEAR, Citizen Lab",
    source: "project_zero",
    year: 2023,
  },
  {
    cve: "CVE-2021-44228",
    vendor: "Apache",
    product: "Log4j",
    type: "Remote Code Execution",
    description: "Log4Shell - JNDI injection via crafted log messages",
    dateDiscovered: "2021-12-09",
    datePatched: "2021-12-10",
    advisoryUrl: "https://example.com/advisory/log4j",
    analysisUrl: null,
    rootCauseAnalysis: "Unsafe JNDI lookup in log message processing",
    reportedBy: "Alibaba Cloud Security Team",
    source: "project_zero",
    year: 2021,
  },
  {
    cve: "CVE-2025-1234",
    vendor: "Microsoft",
    product: "Windows",
    type: "Privilege Escalation",
    description: "Kernel privilege escalation in Windows",
    dateDiscovered: "2025-01-15",
    datePatched: null,
    advisoryUrl: null,
    analysisUrl: null,
    rootCauseAnalysis: null,
    reportedBy: null,
    source: "project_zero",
    year: 2025,
  },
];

// ─── Tests ──────────────────────────────────────────────────────────────────────

describe("zero-day-feed", () => {
  beforeEach(() => {
    resetCache();
    setCache(SAMPLE_ENTRIES);
  });

  // ─── CSV Parsing ────────────────────────────────────────────────────────────

  describe("parseP0Csv", () => {
    it("parses a well-formed CSV row", () => {
      const csv = [
        "CVE ID,Vendor,Product,Type,Description,Date Discovered,Date Patched,Advisory,Analysis,Root Cause,Reported By",
        'CVE-2024-3094,Tukaani Project,xz Utils,Backdoor,"Supply chain compromise",2024-03-29,2024-03-30,https://adv.example.com,https://analysis.example.com,"Supply chain attack",Andres Freund',
      ].join("\n");

      const entries = parseP0Csv(csv);
      expect(entries).toHaveLength(1);
      expect(entries[0].cve).toBe("CVE-2024-3094");
      expect(entries[0].vendor).toBe("Tukaani Project");
      expect(entries[0].product).toBe("xz Utils");
      expect(entries[0].type).toBe("Backdoor");
      expect(entries[0].year).toBe(2024);
      expect(entries[0].source).toBe("project_zero");
    });

    it("skips rows without CVE prefix", () => {
      const csv = [
        "CVE ID,Vendor,Product,Type,Description,Date Discovered,Date Patched,Advisory,Analysis,Root Cause,Reported By",
        "NOT-A-CVE,Vendor,Product,Type,Desc,2024-01-01,2024-01-02,,,",
        "CVE-2024-1111,Vendor,Product,Type,Desc,2024-01-01,2024-01-02,,,",
      ].join("\n");

      const entries = parseP0Csv(csv);
      expect(entries).toHaveLength(1);
      expect(entries[0].cve).toBe("CVE-2024-1111");
    });

    it("handles rows with fewer than 4 columns", () => {
      const csv = [
        "CVE ID,Vendor,Product",
        "CVE-2024-1111,Vendor",
      ].join("\n");

      const entries = parseP0Csv(csv);
      expect(entries).toHaveLength(0);
    });

    it("extracts year from CVE ID", () => {
      const csv = [
        "CVE ID,Vendor,Product,Type,Description,Date Discovered,Date Patched",
        "CVE-2019-5678,TestVendor,TestProduct,RCE,Test,2019-06-01,2019-06-15",
      ].join("\n");

      const entries = parseP0Csv(csv);
      expect(entries[0].year).toBe(2019);
    });
  });

  describe("cleanField", () => {
    it("returns null for empty string", () => {
      expect(cleanField("")).toBeNull();
    });

    it("returns null for undefined", () => {
      expect(cleanField(undefined)).toBeNull();
    });

    it("returns null for ???", () => {
      expect(cleanField("???")).toBeNull();
    });

    it("strips surrounding quotes", () => {
      expect(cleanField('"hello world"')).toBe("hello world");
    });

    it("trims whitespace", () => {
      expect(cleanField("  test  ")).toBe("test");
    });
  });

  // ─── Search ─────────────────────────────────────────────────────────────────

  describe("searchZeroDays", () => {
    it("searches by exact CVE", async () => {
      const result = await searchZeroDays({ cve: "CVE-2024-3094" });
      expect(result.entries).toHaveLength(1);
      expect(result.entries[0].cve).toBe("CVE-2024-3094");
    });

    it("searches by vendor (case-insensitive)", async () => {
      const result = await searchZeroDays({ vendor: "apple" });
      expect(result.entries).toHaveLength(1);
      expect(result.entries[0].vendor).toBe("Apple");
    });

    it("searches by product", async () => {
      const result = await searchZeroDays({ product: "Chrome" });
      expect(result.entries).toHaveLength(1);
      expect(result.entries[0].product).toBe("Chrome");
    });

    it("searches by free-text query across all fields", async () => {
      const result = await searchZeroDays({ query: "supply chain" });
      expect(result.entries).toHaveLength(1);
      expect(result.entries[0].cve).toBe("CVE-2024-3094");
    });

    it("searches by year", async () => {
      const result = await searchZeroDays({ year: 2023 });
      expect(result.entries).toHaveLength(1);
      expect(result.entries[0].year).toBe(2023);
    });

    it("returns totalCount for pagination", async () => {
      const result = await searchZeroDays({ limit: 2 });
      expect(result.entries).toHaveLength(2);
      expect(result.totalCount).toBe(5);
    });

    it("supports offset for pagination", async () => {
      const result = await searchZeroDays({ limit: 2, offset: 3 });
      expect(result.entries).toHaveLength(2);
      expect(result.totalCount).toBe(5);
    });

    it("returns empty for no matches", async () => {
      const result = await searchZeroDays({ cve: "CVE-9999-0000" });
      expect(result.entries).toHaveLength(0);
      expect(result.totalCount).toBe(0);
    });

    it("combines filters (vendor + year)", async () => {
      const result = await searchZeroDays({ vendor: "Google", year: 2023 });
      expect(result.entries).toHaveLength(1);
      expect(result.entries[0].cve).toBe("CVE-2023-4863");
    });
  });

  // ─── Cross-Reference ──────────────────────────────────────────────────────

  describe("crossReferenceAssets", () => {
    it("finds exact CVE matches with high confidence", async () => {
      const assets: AssetForCrossRef[] = [
        { identifier: "target.com", cves: ["CVE-2024-3094"] },
      ];
      const result = await crossReferenceAssets(assets);
      expect(result.matches).toHaveLength(1);
      expect(result.matches[0].matchType).toBe("cve_exact");
      expect(result.matches[0].confidence).toBe("high");
      expect(result.matches[0].severity).toBe("critical");
    });

    it("finds vendor+product matches with medium confidence", async () => {
      const assets: AssetForCrossRef[] = [
        { identifier: "webserver.com", vendors: ["Apple"], products: ["WebKit"] },
      ];
      const result = await crossReferenceAssets(assets);
      expect(result.matches.length).toBeGreaterThanOrEqual(1);
      const vpMatch = result.matches.find((m) => m.matchType === "vendor_product");
      expect(vpMatch).toBeDefined();
      expect(vpMatch!.confidence).toBe("medium");
    });

    it("finds product-only fuzzy matches with low confidence", async () => {
      const assets: AssetForCrossRef[] = [
        { identifier: "server.com", products: ["Log4j"] },
      ];
      const result = await crossReferenceAssets(assets);
      expect(result.matches.length).toBeGreaterThanOrEqual(1);
      const fuzzyMatch = result.matches.find((m) => m.matchType === "product_fuzzy");
      expect(fuzzyMatch).toBeDefined();
      expect(fuzzyMatch!.confidence).toBe("low");
    });

    it("deduplicates CVE exact + vendor_product matches", async () => {
      const assets: AssetForCrossRef[] = [
        {
          identifier: "target.com",
          cves: ["CVE-2024-23222"],
          vendors: ["Apple"],
          products: ["WebKit"],
        },
      ];
      const result = await crossReferenceAssets(assets);
      // Should have CVE exact but NOT a duplicate vendor_product for same CVE
      const cveMatches = result.matches.filter(
        (m) => m.zeroDayEntry.cve === "CVE-2024-23222"
      );
      expect(cveMatches).toHaveLength(1);
      expect(cveMatches[0].matchType).toBe("cve_exact");
    });

    it("returns empty for unrelated assets", async () => {
      const assets: AssetForCrossRef[] = [
        { identifier: "safe.com", vendors: ["SafeVendor"], products: ["SafeProduct"] },
      ];
      const result = await crossReferenceAssets(assets);
      expect(result.matches).toHaveLength(0);
    });

    it("sorts results by severity then confidence", async () => {
      const assets: AssetForCrossRef[] = [
        {
          identifier: "multi.com",
          cves: ["CVE-2021-44228"],
          vendors: ["Google"],
          products: ["Chrome", "Log4j"],
        },
      ];
      const result = await crossReferenceAssets(assets);
      // Critical matches should come first
      if (result.matches.length > 1) {
        expect(
          ["critical", "high"].indexOf(result.matches[0].severity)
        ).toBeLessThanOrEqual(
          ["critical", "high"].indexOf(result.matches[result.matches.length - 1].severity)
        );
      }
    });
  });

  // ─── Asset Extraction ─────────────────────────────────────────────────────

  describe("extractAssetsFromObservations", () => {
    it("always includes the target domain", () => {
      const assets = extractAssetsFromObservations([], "example.com");
      expect(assets).toHaveLength(1);
      expect(assets[0].identifier).toBe("example.com");
    });

    it("extracts CVEs from rawData", () => {
      const observations = [
        {
          assetValue: "server.example.com",
          rawData: '{"vulns": "CVE-2024-3094, CVE-2023-4863"}',
        },
      ];
      const assets = extractAssetsFromObservations(observations, "example.com");
      const serverAsset = assets.find((a) => a.identifier === "server.example.com");
      expect(serverAsset).toBeDefined();
      expect(serverAsset!.cves).toContain("CVE-2024-3094");
      expect(serverAsset!.cves).toContain("CVE-2023-4863");
    });

    it("extracts vendor/product from JSON rawData", () => {
      const observations = [
        {
          assetValue: "app.example.com",
          rawData: JSON.stringify({ vendor: "Apache", product: "httpd", version: "2.4.51" }),
        },
      ];
      const assets = extractAssetsFromObservations(observations, "example.com");
      const appAsset = assets.find((a) => a.identifier === "app.example.com");
      expect(appAsset!.vendors).toContain("Apache");
      expect(appAsset!.products).toContain("httpd");
      expect(appAsset!.versions).toContain("2.4.51");
    });

    it("extracts technologies from nested JSON", () => {
      const observations = [
        {
          assetValue: "web.example.com",
          rawData: JSON.stringify({
            technologies: [
              { name: "WordPress", vendor: "Automattic" },
              { name: "jQuery" },
            ],
          }),
        },
      ];
      const assets = extractAssetsFromObservations(observations, "example.com");
      const webAsset = assets.find((a) => a.identifier === "web.example.com");
      expect(webAsset!.products).toContain("WordPress");
      expect(webAsset!.products).toContain("jQuery");
      expect(webAsset!.vendors).toContain("Automattic");
    });

    it("deduplicates assets by identifier", () => {
      const observations = [
        { assetValue: "host.example.com", rawData: '{"vendor": "Apache"}' },
        { assetValue: "host.example.com", rawData: '{"product": "httpd"}' },
      ];
      const assets = extractAssetsFromObservations(observations, "example.com");
      const hostAssets = assets.filter((a) => a.identifier === "host.example.com");
      expect(hostAssets).toHaveLength(1);
      expect(hostAssets[0].vendors).toContain("Apache");
      expect(hostAssets[0].products).toContain("httpd");
    });
  });

  // ─── Banner Extraction ────────────────────────────────────────────────────

  describe("extractFromBanner", () => {
    it("extracts Apache from server banner", () => {
      const asset: AssetForCrossRef = { identifier: "test", products: [] };
      extractFromBanner("Apache/2.4.51 (Ubuntu)", asset);
      expect(asset.products).toContain("Apache");
    });

    it("extracts nginx from server banner", () => {
      const asset: AssetForCrossRef = { identifier: "test", products: [] };
      extractFromBanner("nginx/1.21.6", asset);
      expect(asset.products).toContain("nginx");
    });

    it("extracts OpenSSH from banner", () => {
      const asset: AssetForCrossRef = { identifier: "test", products: [] };
      extractFromBanner("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", asset);
      expect(asset.products).toContain("OpenSSH");
    });

    it("extracts multiple products from complex banner", () => {
      const asset: AssetForCrossRef = { identifier: "test", products: [] };
      extractFromBanner("Apache/2.4.51 PHP/8.1.2", asset);
      expect(asset.products).toContain("Apache");
      expect(asset.products).toContain("PHP");
    });
  });

  // ─── isRecent ─────────────────────────────────────────────────────────────

  describe("isRecent", () => {
    it("considers current year as recent", () => {
      const entry: ZeroDayEntry = {
        cve: "CVE-2026-0001",
        vendor: "Test",
        product: "Test",
        type: "RCE",
        description: "",
        dateDiscovered: null,
        datePatched: null,
        advisoryUrl: null,
        analysisUrl: null,
        rootCauseAnalysis: null,
        reportedBy: null,
        source: "project_zero",
        year: new Date().getFullYear(),
      };
      expect(isRecent(entry)).toBe(true);
    });

    it("considers previous year as recent", () => {
      const entry: ZeroDayEntry = {
        cve: "CVE-2025-0001",
        vendor: "Test",
        product: "Test",
        type: "RCE",
        description: "",
        dateDiscovered: null,
        datePatched: null,
        advisoryUrl: null,
        analysisUrl: null,
        rootCauseAnalysis: null,
        reportedBy: null,
        source: "project_zero",
        year: new Date().getFullYear() - 1,
      };
      expect(isRecent(entry)).toBe(true);
    });

    it("considers 2 years ago as not recent", () => {
      const entry: ZeroDayEntry = {
        cve: "CVE-2024-0001",
        vendor: "Test",
        product: "Test",
        type: "RCE",
        description: "",
        dateDiscovered: null,
        datePatched: null,
        advisoryUrl: null,
        analysisUrl: null,
        rootCauseAnalysis: null,
        reportedBy: null,
        source: "project_zero",
        year: new Date().getFullYear() - 2,
      };
      expect(isRecent(entry)).toBe(false);
    });
  });

  // ─── Feed Stats ───────────────────────────────────────────────────────────

  describe("getZeroDayFeedStats", () => {
    it("returns correct total count", async () => {
      const stats = await getZeroDayFeedStats();
      expect(stats.totalEntries).toBe(5);
    });

    it("groups by year correctly", async () => {
      const stats = await getZeroDayFeedStats();
      expect(stats.byYear[2024]).toBe(2);
      expect(stats.byYear[2023]).toBe(1);
      expect(stats.byYear[2021]).toBe(1);
      expect(stats.byYear[2025]).toBe(1);
    });

    it("groups by vendor correctly", async () => {
      const stats = await getZeroDayFeedStats();
      expect(stats.byVendor["Apple"]).toBe(1);
      expect(stats.byVendor["Google"]).toBe(1);
      expect(stats.byVendor["Apache"]).toBe(1);
    });

    it("groups by type correctly", async () => {
      const stats = await getZeroDayFeedStats();
      expect(stats.byType["Backdoor"]).toBe(1);
      expect(stats.byType["Type Confusion"]).toBe(1);
      expect(stats.byType["Remote Code Execution"]).toBe(1);
    });
  });
});
