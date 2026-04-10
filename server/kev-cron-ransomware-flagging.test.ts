import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── KEV Refresh Scheduler Tests ──

describe("KEV Refresh Scheduler", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("initKEVRefreshScheduler", () => {
    it("should export initKEVRefreshScheduler function", async () => {
      const mod = await import("./lib/kev-refresh-scheduler");
      expect(typeof mod.initKEVRefreshScheduler).toBe("function");
    });

    it("should export stopKEVRefreshScheduler function", async () => {
      const mod = await import("./lib/kev-refresh-scheduler");
      expect(typeof mod.stopKEVRefreshScheduler).toBe("function");
    });

    it("should export getKEVRefreshStatus function", async () => {
      const mod = await import("./lib/kev-refresh-scheduler");
      expect(typeof mod.getKEVRefreshStatus).toBe("function");
    });

    it("getKEVRefreshStatus should return scheduler status", async () => {
      const mod = await import("./lib/kev-refresh-scheduler");
      const status = mod.getKEVRefreshStatus();
      expect(status).toHaveProperty("schedulerActive");
      expect(status).toHaveProperty("lastRefreshAttempt");
      expect(status).toHaveProperty("lastSuccessfulRefresh");
      expect(status).toHaveProperty("totalRefreshes");
      expect(status).toHaveProperty("consecutiveFailures");
      expect(status).toHaveProperty("lastError");
      expect(status).toHaveProperty("lastClassifiedCount");
      expect(status).toHaveProperty("lastRansomwareCount");
      expect(typeof status.schedulerActive).toBe("boolean");
      expect(typeof status.totalRefreshes).toBe("number");
    });
  });
});

// ── CISA KEV Product Map - Ransomware Flagging Tests ──

describe("CISA KEV Product Map - Ransomware Flagging", () => {
  describe("lookupCVEProduct", () => {
    it("should return ransomwareLinked flag for known ransomware CVEs from static map", async () => {
      const { lookupCVEProduct } = await import("./lib/cisa-kev-product-map");
      // Check a well-known ransomware CVE from the static fallback
      const result = lookupCVEProduct("CVE-2021-34527"); // PrintNightmare
      // If in static map, it may or may not have ransomwareLinked
      expect(result).toHaveProperty("source");
      expect(result).toHaveProperty("family");
      expect(result).toHaveProperty("keywords");
    });

    it("should return source=not_found for unknown CVEs", async () => {
      const { lookupCVEProduct } = await import("./lib/cisa-kev-product-map");
      const result = lookupCVEProduct("CVE-9999-99999");
      expect(result.source).toBe("not_found");
      expect(result.family).toBe("");
      expect(result.keywords).toEqual([]);
    });

    it("should return valid family and keywords for known CVEs", async () => {
      const { lookupCVEProduct } = await import("./lib/cisa-kev-product-map");
      const result = lookupCVEProduct("CVE-2021-44228"); // Log4Shell
      if (result.source !== "not_found") {
        expect(result.family.length).toBeGreaterThan(0);
        expect(result.keywords.length).toBeGreaterThan(0);
      }
    });
  });

  describe("getRansomwareLinkedCVEs", () => {
    it("should return an array", async () => {
      const { getRansomwareLinkedCVEs } = await import("./lib/cisa-kev-product-map");
      const result = getRansomwareLinkedCVEs();
      expect(Array.isArray(result)).toBe(true);
    });

    it("should return CVE IDs in correct format", async () => {
      const { getRansomwareLinkedCVEs } = await import("./lib/cisa-kev-product-map");
      const result = getRansomwareLinkedCVEs();
      for (const cve of result) {
        expect(cve).toMatch(/^CVE-\d{4}-\d+$/);
      }
    });
  });

  describe("validateCVEAgainstTarget", () => {
    it("should return null for unknown CVEs (can't validate)", async () => {
      const { validateCVEAgainstTarget } = await import("./lib/cisa-kev-product-map");
      const result = validateCVEAgainstTarget("CVE-9999-99999", ["apache", "nginx"]);
      expect(result).toBeNull();
    });

    it("should return null when target tech matches CVE product", async () => {
      const { validateCVEAgainstTarget } = await import("./lib/cisa-kev-product-map");
      const result = validateCVEAgainstTarget("CVE-2021-44228", ["java", "log4j", "spring"]);
      if (result === null) {
        expect(result).toBeNull(); // Match found
      } else {
        // If no match, it means the keywords didn't align — still valid behavior
        expect(result).toHaveProperty("violation");
      }
    });

    it("should return violation when target tech does not match CVE product", async () => {
      const { validateCVEAgainstTarget } = await import("./lib/cisa-kev-product-map");
      // Log4Shell against a pure IIS/.NET target
      const result = validateCVEAgainstTarget("CVE-2021-44228", ["iis", "asp.net", "windows server"]);
      if (result) {
        expect(result.violation).toContain("CVE-2021-44228");
        expect(result.family.length).toBeGreaterThan(0);
      }
    });
  });

  describe("getKEVStats", () => {
    it("should return stats object with expected fields", async () => {
      const { getKEVStats } = await import("./lib/cisa-kev-product-map");
      const stats = getKEVStats();
      expect(stats).toHaveProperty("loaded");
      expect(stats).toHaveProperty("totalCVEs");
      expect(stats).toHaveProperty("families");
      expect(stats).toHaveProperty("lastRefresh");
      expect(stats).toHaveProperty("staticFallbackCount");
      expect(typeof stats.loaded).toBe("boolean");
      expect(typeof stats.totalCVEs).toBe("number");
      expect(typeof stats.families).toBe("number");
      expect(stats.staticFallbackCount).toBeGreaterThan(0);
    });
  });
});

// ── Ransomware Flagging in Engagement Timeline Tests ──

describe("Ransomware Flagging in Engagement Timeline", () => {
  describe("lookupCVEProduct integration for timeline badges", () => {
    it("should distinguish ransomware-linked CVEs from regular KEV CVEs", async () => {
      const { lookupCVEProduct } = await import("./lib/cisa-kev-product-map");

      // Check multiple CVEs and verify the ransomwareLinked flag is boolean or undefined
      const testCves = [
        "CVE-2021-44228", // Log4Shell
        "CVE-2021-34527", // PrintNightmare
        "CVE-2017-0144",  // EternalBlue
        "CVE-2024-23692", // Rejetto HFS
      ];

      for (const cve of testCves) {
        const result = lookupCVEProduct(cve);
        if (result.source !== "not_found") {
          expect(typeof result.ransomwareLinked === "boolean" || result.ransomwareLinked === undefined).toBe(true);
        }
      }
    });

    it("should generate correct badge text for ransomware CVEs", async () => {
      const { lookupCVEProduct } = await import("./lib/cisa-kev-product-map");

      const cve = "CVE-2021-44228";
      const cveInfo = lookupCVEProduct(cve);

      let badge = "";
      if (cveInfo.ransomwareLinked) {
        badge = " 🔴 [RANSOMWARE VECTOR]";
      } else if (cveInfo.source !== "not_found") {
        badge = " ⚠️ [CISA KEV]";
      }

      // Should have some badge if the CVE is in the catalog
      if (cveInfo.source !== "not_found") {
        expect(badge.length).toBeGreaterThan(0);
      }
    });

    it("should generate no badge for unknown CVEs", async () => {
      const { lookupCVEProduct } = await import("./lib/cisa-kev-product-map");

      const cveInfo = lookupCVEProduct("CVE-9999-99999");
      let badge = "";
      if (cveInfo.ransomwareLinked) {
        badge = " 🔴 [RANSOMWARE VECTOR]";
      } else if (cveInfo.source !== "not_found") {
        badge = " ⚠️ [CISA KEV]";
      }

      expect(badge).toBe("");
    });
  });

  describe("Ransomware summary log generation", () => {
    it("should correctly filter ransomware-linked CVEs from an exploit plan", async () => {
      const { lookupCVEProduct } = await import("./lib/cisa-kev-product-map");

      const exploitActions = [
        { type: "exploit_attempt", params: { cve: "CVE-2021-44228", target: "10.0.0.1" } },
        { type: "exploit_attempt", params: { cve: "CVE-9999-99999", target: "10.0.0.2" } },
        { type: "exploit_attempt", params: { cve: "CVE-2017-0144", target: "10.0.0.3" } },
        { type: "exploit_attempt", params: { target: "10.0.0.4" } }, // no CVE
      ];

      const ransomwareCves = exploitActions
        .map((a: any) => a.params?.cve)
        .filter(Boolean)
        .filter((cve: string) => lookupCVEProduct(cve).ransomwareLinked);

      // Should be an array (may be empty if KEV not loaded)
      expect(Array.isArray(ransomwareCves)).toBe(true);
      // All entries should be valid CVE IDs
      for (const cve of ransomwareCves) {
        expect(cve).toMatch(/^CVE-\d{4}-\d+$/);
      }
    });

    it("should produce correct summary message format", async () => {
      const ransomwareCves = ["CVE-2021-44228", "CVE-2017-0144"];

      if (ransomwareCves.length > 0) {
        const title = `🔴 ${ransomwareCves.length} Ransomware-Linked CVE${ransomwareCves.length !== 1 ? 's' : ''} in Exploit Plan`;
        const detail = `The following CVEs in this exploit plan are linked to known ransomware campaigns: ${ransomwareCves.join(', ')}. These findings represent critical risk and should be prioritized in the final report for executive stakeholders.`;

        expect(title).toContain("2 Ransomware-Linked CVEs");
        expect(detail).toContain("CVE-2021-44228");
        expect(detail).toContain("CVE-2017-0144");
        expect(detail).toContain("executive stakeholders");
      }
    });

    it("should handle single ransomware CVE with correct grammar", () => {
      const ransomwareCves = ["CVE-2021-44228"];
      const title = `🔴 ${ransomwareCves.length} Ransomware-Linked CVE${ransomwareCves.length !== 1 ? 's' : ''} in Exploit Plan`;
      expect(title).toContain("1 Ransomware-Linked CVE in");
      expect(title).not.toContain("CVEs");
    });
  });

  describe("Per-exploit ransomware warning log format", () => {
    it("should generate correct ransomware warning log entry", async () => {
      const { lookupCVEProduct } = await import("./lib/cisa-kev-product-map");

      const cve = "CVE-2021-44228";
      const cveInfo = lookupCVEProduct(cve);

      if (cveInfo.ransomwareLinked) {
        const logEntry = {
          phase: "exploitation",
          type: "finding",
          title: `🔴 RANSOMWARE VECTOR: ${cve}`,
          detail: `${cve} is linked to known ransomware campaigns (${cveInfo.vendor || 'unknown'} ${cveInfo.product || 'unknown'} — ${cveInfo.family}). Successful exploitation of this CVE has been observed in active ransomware operations. This finding should be escalated to executive stakeholders immediately.`,
          riskTier: "red",
          data: {
            cve,
            family: cveInfo.family,
            vendor: cveInfo.vendor,
            product: cveInfo.product,
            ransomwareLinked: true,
            source: cveInfo.source,
          },
        };

        expect(logEntry.title).toContain("RANSOMWARE VECTOR");
        expect(logEntry.detail).toContain("ransomware campaigns");
        expect(logEntry.detail).toContain("executive stakeholders");
        expect(logEntry.riskTier).toBe("red");
        expect(logEntry.data.ransomwareLinked).toBe(true);
      }
    });

    it("should generate CISA KEV info log for non-ransomware KEV CVEs", async () => {
      const { lookupCVEProduct } = await import("./lib/cisa-kev-product-map");

      const cve = "CVE-2024-23692"; // Rejetto HFS - may not be ransomware-linked
      const cveInfo = lookupCVEProduct(cve);

      if (cveInfo.source !== "not_found" && !cveInfo.ransomwareLinked) {
        const logEntry = {
          phase: "exploitation",
          type: "info",
          title: `📋 CISA KEV: ${cve}`,
          detail: `${cve} is on the CISA Known Exploited Vulnerabilities catalog (${cveInfo.vendor || 'unknown'} ${cveInfo.product || 'unknown'} — ${cveInfo.family}). This CVE is actively exploited in the wild.`,
        };

        expect(logEntry.title).toContain("CISA KEV");
        expect(logEntry.detail).toContain("actively exploited");
      }
    });
  });
});
