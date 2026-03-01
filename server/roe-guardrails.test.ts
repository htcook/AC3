import { describe, it, expect } from "vitest";

describe("ROE Guardrails", () => {
  describe("Schema", () => {
    it("offensive_audit_log table is defined", async () => {
      const schema = await import("../drizzle/schema");
      expect(schema.offensiveAuditLog).toBeDefined();
    });

    it("engagements table is defined", async () => {
      const schema = await import("../drizzle/schema");
      expect(schema.engagements).toBeDefined();
    });
  });

  describe("ROE Audit Router", () => {
    it("exports roeAuditRouter", async () => {
      const mod = await import("./routers/roe-audit");
      expect(mod.roeAuditRouter).toBeDefined();
    });
  });

  describe("ROE Guard Library", () => {
    it("exports validateROE function", async () => {
      const mod = await import("./lib/roe-guard");
      expect(mod.validateROE).toBeDefined();
      expect(typeof mod.validateROE).toBe("function");
    });

    it("exports enforceROE function", async () => {
      const mod = await import("./lib/roe-guard");
      expect(mod.enforceROE).toBeDefined();
      expect(typeof mod.enforceROE).toBe("function");
    });

    it("exports logOffensiveAction function", async () => {
      const mod = await import("./lib/roe-guard");
      expect(mod.logOffensiveAction).toBeDefined();
      expect(typeof mod.logOffensiveAction).toBe("function");
    });

    it("exports getEngagementROE function", async () => {
      const mod = await import("./lib/roe-guard");
      expect(mod.getEngagementROE).toBeDefined();
      expect(typeof mod.getEngagementROE).toBe("function");
    });

    it("exports ACTION_RISK_MAP with correct tiers", async () => {
      const mod = await import("./lib/roe-guard");
      expect(mod.ACTION_RISK_MAP).toBeDefined();
      expect(mod.ACTION_RISK_MAP.msf_exploit).toBe("red");
      expect(mod.ACTION_RISK_MAP.active_probe).toBe("orange");
      expect(mod.ACTION_RISK_MAP.phishing_launch).toBe("red");
    });

    it("validateROE rejects engagement with no ROE", async () => {
      const { validateROE } = await import("./lib/roe-guard");
      const result = validateROE({
        roeStatus: "none",
        roeSignedDate: null,
        roeExpiryDate: null,
        roeDocumentUrl: null,
        roeScope: null,
      });
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("No Rules of Engagement");
    });

    it("validateROE accepts engagement with signed ROE", async () => {
      const { validateROE } = await import("./lib/roe-guard");
      const result = validateROE({
        roeStatus: "signed",
        roeSignedDate: new Date(),
        roeExpiryDate: new Date(Date.now() + 86400000 * 30),
        roeDocumentUrl: "https://example.com/roe.pdf",
        roeScope: null,
      });
      expect(result.valid).toBe(true);
    });

    it("validateROE rejects expired ROE", async () => {
      const { validateROE } = await import("./lib/roe-guard");
      const result = validateROE({
        roeStatus: "signed",
        roeSignedDate: new Date(Date.now() - 86400000 * 60),
        roeExpiryDate: new Date(Date.now() - 86400000 * 1),
        roeDocumentUrl: "https://example.com/roe.pdf",
        roeScope: null,
      });
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("expired");
    });

    it("enforceROE allows yellow tier without ROE", async () => {
      const { enforceROE } = await import("./lib/roe-guard");
      expect(() => {
        enforceROE(
          { roeStatus: "none", roeSignedDate: null, roeExpiryDate: null, roeDocumentUrl: null, roeScope: null },
          "yellow",
          "HTTP header check"
        );
      }).not.toThrow();
    });

    it("enforceROE blocks red tier without ROE", async () => {
      const { enforceROE } = await import("./lib/roe-guard");
      expect(() => {
        enforceROE(
          { roeStatus: "none", roeSignedDate: null, roeExpiryDate: null, roeDocumentUrl: null, roeScope: null },
          "red",
          "Metasploit exploit"
        );
      }).toThrow(/ROE REQUIRED/);
    });
  });
});

describe("Validation Scheduler", () => {
  it("validationSchedules table is defined", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.validationSchedules).toBeDefined();
  });

  it("exports validationSchedulerRouter", async () => {
    const mod = await import("./routers/validation-scheduler");
    expect(mod.validationSchedulerRouter).toBeDefined();
  });
});

describe("Detection Rules", () => {
  it("exports detectionRulesRouter", async () => {
    const mod = await import("./routers/detection-rules");
    expect(mod.detectionRulesRouter).toBeDefined();
  });
});

describe("Sidebar includes new items", () => {
  it("has continuous-validation in nav", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/components/AppShell.tsx", "utf-8");
    expect(content).toContain("/continuous-validation");
    expect(content).toContain("VALIDATION OPS");
  });

  it("has audit-log in nav", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("client/src/components/AppShell.tsx", "utf-8");
    expect(content).toContain("/audit-log");
    expect(content).toContain("AUDIT LOG");
  });
});
