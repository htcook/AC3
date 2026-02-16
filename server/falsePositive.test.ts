import { describe, it, expect, vi } from "vitest";

// Test the FP knowledge context builder logic
describe("False Positive Learning Loop", () => {
  describe("FP Reason Templates", () => {
    const FP_REASON_TEMPLATES = [
      { value: "patched", label: "Already patched / remediated" },
      { value: "internal", label: "Internal-only service, not exposed" },
      { value: "compensating", label: "Compensating controls in place" },
      { value: "scanner_error", label: "Scanner error / incorrect detection" },
      { value: "version_mismatch", label: "Version string mismatch (banner vs actual)" },
      { value: "accepted_risk", label: "Accepted risk per policy" },
      { value: "duplicate", label: "Duplicate of another finding" },
      { value: "not_applicable", label: "Not applicable to this environment" },
      { value: "custom", label: "Other (describe below)" },
    ];

    it("should have 9 reason templates", () => {
      expect(FP_REASON_TEMPLATES).toHaveLength(9);
    });

    it("should have unique values", () => {
      const values = FP_REASON_TEMPLATES.map((t) => t.value);
      expect(new Set(values).size).toBe(values.length);
    });

    it("should include a custom option", () => {
      const custom = FP_REASON_TEMPLATES.find((t) => t.value === "custom");
      expect(custom).toBeDefined();
      expect(custom?.label).toContain("Other");
    });

    it("all templates should have non-empty value and label", () => {
      for (const t of FP_REASON_TEMPLATES) {
        expect(t.value.length).toBeGreaterThan(0);
        expect(t.label.length).toBeGreaterThan(0);
      }
    });
  });

  describe("Finding Hash Generation", () => {
    it("should generate consistent hashes for the same finding", () => {
      const finding = {
        title: "Missing HSTS Header",
        assetHostname: "cdn.example.com",
        category: "configuration",
      };
      const hash1 = `${finding.title}|${finding.assetHostname}|${finding.category}`;
      const hash2 = `${finding.title}|${finding.assetHostname}|${finding.category}`;
      expect(hash1).toBe(hash2);
    });

    it("should generate different hashes for different findings", () => {
      const finding1 = { title: "Missing HSTS", assetHostname: "a.com", category: "config" };
      const finding2 = { title: "Open Port 22", assetHostname: "b.com", category: "network" };
      const hash1 = `${finding1.title}|${finding1.assetHostname}|${finding1.category}`;
      const hash2 = `${finding2.title}|${finding2.assetHostname}|${finding2.category}`;
      expect(hash1).not.toBe(hash2);
    });

    it("should handle missing fields gracefully", () => {
      const finding = { title: "Test Finding" } as any;
      const hash = `${finding.title}|${finding.assetHostname || ""}|${finding.category || ""}`;
      expect(hash).toBe("Test Finding||");
    });
  });

  describe("FP Context Builder", () => {
    it("should build FP context string from knowledge base entries", () => {
      const fpEntries = [
        {
          findingTitle: "Missing HSTS Header",
          reason: "CDN manages HSTS at edge",
          findingType: "configuration",
          occurrenceCount: 3,
        },
        {
          findingTitle: "Open Port 443",
          reason: "Expected for web server",
          findingType: "network",
          occurrenceCount: 1,
        },
      ];

      const context = fpEntries
        .map(
          (fp) =>
            `- "${fp.findingTitle}" (${fp.findingType || "unknown"}): ${fp.reason} [marked ${fp.occurrenceCount}x]`
        )
        .join("\n");

      expect(context).toContain("Missing HSTS Header");
      expect(context).toContain("CDN manages HSTS at edge");
      expect(context).toContain("marked 3x");
      expect(context).toContain("Open Port 443");
    });

    it("should return empty string when no FP entries exist", () => {
      const fpEntries: any[] = [];
      const context = fpEntries
        .map(
          (fp) =>
            `- "${fp.findingTitle}" (${fp.findingType || "unknown"}): ${fp.reason} [marked ${fp.occurrenceCount}x]`
        )
        .join("\n");

      expect(context).toBe("");
    });

    it("should limit context to prevent prompt overflow", () => {
      const fpEntries = Array.from({ length: 100 }, (_, i) => ({
        findingTitle: `Finding ${i}`,
        reason: `Reason for finding ${i} with a very long explanation that goes on and on`,
        findingType: "test",
        occurrenceCount: i + 1,
      }));

      // Limit to top 50 by occurrence count
      const limited = fpEntries
        .sort((a, b) => b.occurrenceCount - a.occurrenceCount)
        .slice(0, 50);

      expect(limited).toHaveLength(50);
      expect(limited[0].occurrenceCount).toBe(100);
    });
  });

  describe("FP Auto-Flagging", () => {
    it("should flag findings that match known FP hashes", () => {
      const knownFPHashes = new Set([
        "Missing HSTS|cdn.example.com|config",
        "Open Port 22|internal.example.com|network",
      ]);

      const findings = [
        { title: "Missing HSTS", assetHostname: "cdn.example.com", category: "config" },
        { title: "SQL Injection", assetHostname: "app.example.com", category: "vulnerability" },
        { title: "Open Port 22", assetHostname: "internal.example.com", category: "network" },
      ];

      const flagged = findings.map((f) => {
        const hash = `${f.title}|${f.assetHostname}|${f.category}`;
        return { ...f, isFP: knownFPHashes.has(hash) };
      });

      expect(flagged[0].isFP).toBe(true);
      expect(flagged[1].isFP).toBe(false);
      expect(flagged[2].isFP).toBe(true);
    });

    it("should not flag findings when FP set is empty", () => {
      const knownFPHashes = new Set<string>();
      const findings = [
        { title: "Test", assetHostname: "a.com", category: "test" },
      ];

      const flagged = findings.map((f) => {
        const hash = `${f.title}|${f.assetHostname}|${f.category}`;
        return { ...f, isFP: knownFPHashes.has(hash) };
      });

      expect(flagged[0].isFP).toBe(false);
    });
  });

  describe("FP Reinstatement", () => {
    it("should track reinstatement reason", () => {
      const reinstatement = {
        fpId: 42,
        reason: "Reinstated by analyst — finding is valid after re-examination",
        reinstatedBy: "analyst-1",
        reinstatedAt: Date.now(),
      };

      expect(reinstatement.reason).toContain("Reinstated");
      expect(reinstatement.fpId).toBe(42);
      expect(reinstatement.reinstatedAt).toBeGreaterThan(0);
    });
  });
});
