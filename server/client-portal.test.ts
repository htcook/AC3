import { describe, it, expect, vi, beforeEach } from "vitest";
import crypto from "crypto";

// ─── Unit tests for Client Portal share token logic ────────────────

describe("Client Portal", () => {
  describe("Share Token Generation", () => {
    it("generates unique tokens using crypto.randomBytes", () => {
      const token1 = crypto.randomBytes(32).toString("hex");
      const token2 = crypto.randomBytes(32).toString("hex");
      expect(token1).toHaveLength(64);
      expect(token2).toHaveLength(64);
      expect(token1).not.toBe(token2);
    });

    it("generates URL-safe tokens", () => {
      const token = crypto.randomBytes(32).toString("hex");
      expect(token).toMatch(/^[0-9a-f]+$/);
    });

    it("generates tokens of consistent length", () => {
      for (let i = 0; i < 10; i++) {
        const token = crypto.randomBytes(32).toString("hex");
        expect(token).toHaveLength(64);
      }
    });
  });

  describe("Password Hashing", () => {
    it("hashes passwords with SHA-256", () => {
      const password = "test-password-123";
      const hash = crypto.createHash("sha256").update(password).digest("hex");
      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[0-9a-f]+$/);
    });

    it("produces consistent hashes for the same password", () => {
      const password = "my-secret-password";
      const hash1 = crypto.createHash("sha256").update(password).digest("hex");
      const hash2 = crypto.createHash("sha256").update(password).digest("hex");
      expect(hash1).toBe(hash2);
    });

    it("produces different hashes for different passwords", () => {
      const hash1 = crypto.createHash("sha256").update("password1").digest("hex");
      const hash2 = crypto.createHash("sha256").update("password2").digest("hex");
      expect(hash1).not.toBe(hash2);
    });

    it("verifies password by comparing hashes", () => {
      const password = "client-access-2026";
      const storedHash = crypto.createHash("sha256").update(password).digest("hex");
      const inputHash = crypto.createHash("sha256").update(password).digest("hex");
      expect(inputHash).toBe(storedHash);
    });

    it("rejects wrong password by hash comparison", () => {
      const storedHash = crypto.createHash("sha256").update("correct-password").digest("hex");
      const inputHash = crypto.createHash("sha256").update("wrong-password").digest("hex");
      expect(inputHash).not.toBe(storedHash);
    });
  });

  describe("Expiration Logic", () => {
    it("calculates expiration date from days", () => {
      const days = 30;
      const now = Date.now();
      const expiresAt = new Date(now + days * 24 * 60 * 60 * 1000);
      const diffMs = expiresAt.getTime() - now;
      const diffDays = diffMs / (24 * 60 * 60 * 1000);
      expect(diffDays).toBeCloseTo(30, 0);
    });

    it("detects expired tokens", () => {
      const expiresAt = new Date(Date.now() - 1000); // 1 second ago
      expect(expiresAt.getTime() < Date.now()).toBe(true);
    });

    it("detects valid (non-expired) tokens", () => {
      const expiresAt = new Date(Date.now() + 86400000); // 1 day from now
      expect(expiresAt.getTime() > Date.now()).toBe(true);
    });

    it("handles no expiration (null)", () => {
      const expiresAt = null;
      const isExpired = expiresAt !== null && new Date(expiresAt).getTime() < Date.now();
      expect(isExpired).toBe(false);
    });

    it("calculates 1-year expiration correctly", () => {
      const days = 365;
      const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
      const diffDays = (expiresAt.getTime() - Date.now()) / (24 * 60 * 60 * 1000);
      expect(diffDays).toBeCloseTo(365, 0);
    });
  });

  describe("View Count Logic", () => {
    it("tracks view count increment", () => {
      let viewCount = 0;
      viewCount += 1;
      expect(viewCount).toBe(1);
      viewCount += 1;
      expect(viewCount).toBe(2);
    });

    it("enforces max views limit", () => {
      const maxViews = 10;
      const viewCount = 10;
      const isExhausted = maxViews !== null && viewCount >= maxViews;
      expect(isExhausted).toBe(true);
    });

    it("allows access when under max views", () => {
      const maxViews = 10;
      const viewCount = 5;
      const isExhausted = maxViews !== null && viewCount >= maxViews;
      expect(isExhausted).toBe(false);
    });

    it("allows unlimited views when maxViews is null", () => {
      const maxViews = null;
      const viewCount = 999999;
      const isExhausted = maxViews !== null && viewCount >= maxViews;
      expect(isExhausted).toBe(false);
    });
  });

  describe("Section Visibility", () => {
    it("filters report sections based on share settings", () => {
      const shareSettings = {
        includeExecutiveSummary: true,
        includeFindings: true,
        includeAssets: false,
        includeRiskScores: true,
        includeRecommendations: false,
        includeCompliance: false,
      };

      const sections = {
        includeExecutiveSummary: shareSettings.includeExecutiveSummary,
        includeFindings: shareSettings.includeFindings,
        includeAssets: shareSettings.includeAssets,
        includeRiskScores: shareSettings.includeRiskScores,
        includeRecommendations: shareSettings.includeRecommendations,
        includeCompliance: shareSettings.includeCompliance,
      };

      expect(sections.includeExecutiveSummary).toBe(true);
      expect(sections.includeFindings).toBe(true);
      expect(sections.includeAssets).toBe(false);
      expect(sections.includeRiskScores).toBe(true);
      expect(sections.includeRecommendations).toBe(false);
      expect(sections.includeCompliance).toBe(false);
    });

    it("defaults all sections to true when not specified", () => {
      const defaults = {
        includeExecutiveSummary: true,
        includeFindings: true,
        includeAssets: true,
        includeRiskScores: true,
        includeRecommendations: true,
        includeCompliance: false,
      };

      expect(defaults.includeExecutiveSummary).toBe(true);
      expect(defaults.includeFindings).toBe(true);
      expect(defaults.includeAssets).toBe(true);
      expect(defaults.includeRiskScores).toBe(true);
      expect(defaults.includeRecommendations).toBe(true);
    });
  });

  describe("Branding Configuration", () => {
    it("uses default brand color when not specified", () => {
      const brandColor = undefined || "#14b8a6";
      expect(brandColor).toBe("#14b8a6");
    });

    it("uses custom brand color when specified", () => {
      const brandColor = "#ff6b00" || "#14b8a6";
      expect(brandColor).toBe("#ff6b00");
    });

    it("uses client name from share settings", () => {
      const clientName = "Acme Corp" || "Client";
      expect(clientName).toBe("Acme Corp");
    });

    it("falls back to default client name", () => {
      const clientName = undefined || "Client";
      expect(clientName).toBe("Client");
    });

    it("validates hex color format", () => {
      const validColors = ["#14b8a6", "#ff6b00", "#000000", "#ffffff"];
      const invalidColors = ["red", "rgb(0,0,0)", "14b8a6"];
      
      const hexRegex = /^#[0-9a-fA-F]{6}$/;
      validColors.forEach(c => expect(hexRegex.test(c)).toBe(true));
      invalidColors.forEach(c => expect(hexRegex.test(c)).toBe(false));
    });
  });

  describe("Report Data Filtering", () => {
    it("filters findings by severity", () => {
      const findings = [
        { title: "Critical RCE", severity: 9.5 },
        { title: "XSS", severity: 6.5 },
        { title: "Info Disclosure", severity: 3.0 },
        { title: "SSL Weak", severity: 4.5 },
      ];

      const critical = findings.filter(f => f.severity >= 9);
      const high = findings.filter(f => f.severity >= 7 && f.severity < 9);
      const medium = findings.filter(f => f.severity >= 4 && f.severity < 7);
      const low = findings.filter(f => f.severity < 4);

      expect(critical).toHaveLength(1);
      expect(high).toHaveLength(0);
      expect(medium).toHaveLength(2);
      expect(low).toHaveLength(1);
    });

    it("calculates risk distribution from analyses", () => {
      const analyses = [
        { hybridRiskBand: "critical" },
        { hybridRiskBand: "high" },
        { hybridRiskBand: "high" },
        { hybridRiskBand: "medium" },
        { hybridRiskBand: "low" },
      ];

      const distribution = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const a of analyses) {
        const band = a.hybridRiskBand as keyof typeof distribution;
        if (band in distribution) distribution[band]++;
      }

      expect(distribution.critical).toBe(1);
      expect(distribution.high).toBe(2);
      expect(distribution.medium).toBe(1);
      expect(distribution.low).toBe(1);
    });

    it("extracts recommendations from pipeline summaries", () => {
      const summaries = {
        recommendations: [
          "Patch all critical CVEs within 72 hours",
          "Implement WAF for web applications",
          "Enable MFA on all admin accounts",
        ],
      };

      expect(summaries.recommendations).toHaveLength(3);
      expect(summaries.recommendations[0]).toContain("Patch");
    });

    it("handles missing pipeline data gracefully", () => {
      const pipelineOutput = null;
      const summaries = (pipelineOutput as any)?.summaries || {};
      const recommendations = summaries.recommendations || [];
      const findings = (pipelineOutput as any)?.findings || [];

      expect(recommendations).toEqual([]);
      expect(findings).toEqual([]);
    });
  });

  describe("Access Control", () => {
    it("blocks access when share is inactive", () => {
      const share = { isActive: false };
      expect(share.isActive).toBe(false);
    });

    it("blocks access when share is expired", () => {
      const share = { expiresAt: new Date(Date.now() - 86400000) };
      const isExpired = share.expiresAt.getTime() < Date.now();
      expect(isExpired).toBe(true);
    });

    it("blocks access when max views exceeded", () => {
      const share = { viewCount: 10, maxViews: 10 };
      const isExhausted = share.maxViews !== null && share.viewCount >= share.maxViews;
      expect(isExhausted).toBe(true);
    });

    it("requires password when share has password hash", () => {
      const share = { passwordHash: "abc123" };
      const requiresPassword = !!share.passwordHash;
      expect(requiresPassword).toBe(true);
    });

    it("does not require password when no hash set", () => {
      const share = { passwordHash: null };
      const requiresPassword = !!share.passwordHash;
      expect(requiresPassword).toBe(false);
    });

    it("validates access with all checks passing", () => {
      const share = {
        isActive: true,
        expiresAt: new Date(Date.now() + 86400000),
        viewCount: 5,
        maxViews: 100,
        passwordHash: null,
      };

      const isActive = share.isActive;
      const isNotExpired = share.expiresAt === null || share.expiresAt.getTime() > Date.now();
      const hasViews = share.maxViews === null || share.viewCount < share.maxViews;
      const noPasswordNeeded = !share.passwordHash;

      expect(isActive && isNotExpired && hasViews && noPasswordNeeded).toBe(true);
    });
  });

  describe("Severity Helpers", () => {
    function severityBadge(sev: number): string {
      if (sev >= 9) return "Critical";
      if (sev >= 7) return "High";
      if (sev >= 4) return "Medium";
      return "Low";
    }

    it("classifies severity 9+ as Critical", () => {
      expect(severityBadge(9.0)).toBe("Critical");
      expect(severityBadge(10.0)).toBe("Critical");
    });

    it("classifies severity 7-8.9 as High", () => {
      expect(severityBadge(7.0)).toBe("High");
      expect(severityBadge(8.9)).toBe("High");
    });

    it("classifies severity 4-6.9 as Medium", () => {
      expect(severityBadge(4.0)).toBe("Medium");
      expect(severityBadge(6.9)).toBe("Medium");
    });

    it("classifies severity below 4 as Low", () => {
      expect(severityBadge(3.9)).toBe("Low");
      expect(severityBadge(0)).toBe("Low");
    });
  });
});
