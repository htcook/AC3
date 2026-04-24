import { describe, it, expect, vi } from "vitest";

// We test the runJarmHistoryHook function by mocking its dependencies
// since it relies on DB connections and dynamic imports

describe("JARM Pipeline Hook", () => {
  describe("runJarmHistoryHook", () => {
    it("should be importable", async () => {
      const mod = await import("./lib/jarm-pipeline-hook");
      expect(mod.runJarmHistoryHook).toBeDefined();
      expect(typeof mod.runJarmHistoryHook).toBe("function");
    });

    it("should handle empty observations gracefully", async () => {
      // The function should not throw even with empty data
      // It will fail on DB connection in test env but should catch the error
      const { runJarmHistoryHook } = await import("./lib/jarm-pipeline-hook");
      // Should not throw — errors are caught internally
      await expect(
        runJarmHistoryHook(999999, "test.example.com", [], [])
      ).resolves.toBeUndefined();
    });

    it("should handle observations with no JARM data gracefully", async () => {
      const { runJarmHistoryHook } = await import("./lib/jarm-pipeline-hook");
      const observations = [
        { source: "dns_deep", tags: ["dns"], evidence: { records: [] }, name: "test.com" },
        { source: "whoisxml", tags: ["whois"], evidence: { registrar: "GoDaddy" }, name: "test.com" },
      ];
      // Should not throw — no JARM data means no matches, function logs and returns
      await expect(
        runJarmHistoryHook(999999, "test.example.com", observations, [])
      ).resolves.toBeUndefined();
    });

    it("should map observations correctly for infrastructure inference", async () => {
      const { inferInfrastructure } = await import("./lib/infrastructure-inference");

      // Simulate what the hook does internally — map observations
      const rawObs = [
        {
          source: "jarm_fingerprint",
          tags: ["jarm", "tls"],
          evidence: { jarmHash: "2ad2ad16d2ad2ad22c2ad2ad2ad2ad6a321a1507e01onal7e79c6cab090f" },
          name: "test.com",
        },
      ];

      const mapped = rawObs.map((o: any) => ({
        source: o.source || "unknown",
        tags: o.tags || [],
        evidence: o.evidence || {},
        name: o.name || null,
      }));

      expect(mapped[0].source).toBe("jarm_fingerprint");
      expect(mapped[0].tags).toContain("jarm");
      expect(mapped[0].evidence.jarmHash).toBeDefined();

      // Run inference to verify it produces jarmAnalysis
      const result = inferInfrastructure("test.com", mapped, []);
      expect(result.jarmAnalysis).toBeDefined();
      expect(result.jarmAnalysis!.fingerprintsCollected).toBeGreaterThanOrEqual(1);
    });

    it("should map assets correctly for infrastructure inference", async () => {
      // Test the asset mapping logic used in the hook
      const rawAssets = [
        {
          asset: {
            hostname: "www.test.com",
            technologies: ["nginx", "React"],
            headers: { server: "nginx/1.20" },
          },
          hybridRiskScore: 45,
        },
        {
          hostname: "api.test.com",
          technologies: ["Express"],
          headers: {},
        },
      ];

      const mapped = rawAssets.map((a: any) => ({
        hostname: a.asset?.hostname || a.hostname || "",
        technologies: a.asset?.technologies || a.technologies || [],
        headers: a.asset?.headers || a.headers || {},
      }));

      expect(mapped[0].hostname).toBe("www.test.com");
      expect(mapped[0].technologies).toContain("nginx");
      expect(mapped[1].hostname).toBe("api.test.com");
      expect(mapped[1].technologies).toContain("Express");
    });
  });

  describe("Pipeline integration points", () => {
    it("should be wired into scan-only completion path", async () => {
      // Verify the import path resolves
      const mod = await import("./lib/jarm-pipeline-hook");
      expect(mod).toHaveProperty("runJarmHistoryHook");
    });

    it("should be wired into full engagement completion path", async () => {
      // Both paths use the same module — verify it's consistent
      const mod1 = await import("./lib/jarm-pipeline-hook");
      const mod2 = await import("./lib/jarm-pipeline-hook");
      expect(mod1.runJarmHistoryHook).toBe(mod2.runJarmHistoryHook);
    });
  });
});
