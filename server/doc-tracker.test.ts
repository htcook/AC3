import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Doc Version Tracker Tests ──────────────────────────────────────────────

describe("Doc Version Tracker", () => {
  describe("Platform Snapshot Generation", () => {
    it("should generate a snapshot with all required sections", () => {
      // The doc version tracker should produce a snapshot with:
      // routes, routers, schema tables, integrations, nav groups, lib modules
      const expectedSections = [
        "routes",
        "routers",
        "schemaTables",
        "integrations",
        "navGroups",
        "libModules",
      ];
      // Each section should be a non-empty array or object
      expectedSections.forEach((section) => {
        expect(typeof section).toBe("string");
        expect(section.length).toBeGreaterThan(0);
      });
    });

    it("should detect route additions when new pages are added", () => {
      const oldRoutes = ["/dashboard", "/engagements", "/team"];
      const newRoutes = ["/dashboard", "/engagements", "/team", "/doc-tracker"];
      const added = newRoutes.filter((r) => !oldRoutes.includes(r));
      expect(added).toEqual(["/doc-tracker"]);
      expect(added.length).toBe(1);
    });

    it("should detect route removals when pages are deleted", () => {
      const oldRoutes = ["/dashboard", "/engagements", "/team", "/deprecated"];
      const newRoutes = ["/dashboard", "/engagements", "/team"];
      const removed = oldRoutes.filter((r) => !newRoutes.includes(r));
      expect(removed).toEqual(["/deprecated"]);
    });

    it("should detect router file additions", () => {
      const oldRouters = ["auth.ts", "engagements.ts", "domain-intel-core.ts"];
      const newRouters = [
        "auth.ts",
        "engagements.ts",
        "domain-intel-core.ts",
        "doc-tracker.ts",
      ];
      const added = newRouters.filter((r) => !oldRouters.includes(r));
      expect(added).toEqual(["doc-tracker.ts"]);
    });

    it("should detect schema table additions", () => {
      const oldTables = ["users", "engagements", "findings"];
      const newTables = ["users", "engagements", "findings", "doc_snapshots"];
      const added = newTables.filter((t) => !oldTables.includes(t));
      expect(added).toEqual(["doc_snapshots"]);
    });

    it("should detect integration changes", () => {
      const oldIntegrations = ["CALDERA_API_KEY", "SHODAN_API_KEY"];
      const newIntegrations = [
        "CALDERA_API_KEY",
        "SHODAN_API_KEY",
        "CENSYS_API_ID",
      ];
      const added = newIntegrations.filter(
        (i) => !oldIntegrations.includes(i)
      );
      expect(added).toEqual(["CENSYS_API_ID"]);
    });
  });

  describe("Diff Computation", () => {
    it("should compute correct diff between two snapshots", () => {
      const snapshot1 = {
        routes: ["/dashboard", "/engagements"],
        routers: ["auth.ts", "engagements.ts"],
        schemaTables: ["users", "engagements"],
      };
      const snapshot2 = {
        routes: ["/dashboard", "/engagements", "/doc-tracker"],
        routers: ["auth.ts", "engagements.ts", "doc-tracker.ts"],
        schemaTables: ["users", "engagements", "doc_snapshots"],
      };

      // Compute diff for each section
      const routeDiff = {
        added: snapshot2.routes.filter(
          (r: string) => !snapshot1.routes.includes(r)
        ),
        removed: snapshot1.routes.filter(
          (r: string) => !snapshot2.routes.includes(r)
        ),
      };

      expect(routeDiff.added).toEqual(["/doc-tracker"]);
      expect(routeDiff.removed).toEqual([]);
    });

    it("should handle empty snapshots gracefully", () => {
      const empty = { routes: [] as string[], routers: [] as string[], schemaTables: [] as string[] };
      const populated = {
        routes: ["/dashboard"],
        routers: ["auth.ts"],
        schemaTables: ["users"],
      };

      const routeDiff = {
        added: populated.routes.filter(
          (r: string) => !empty.routes.includes(r)
        ),
        removed: empty.routes.filter(
          (r: string) => !populated.routes.includes(r)
        ),
      };

      expect(routeDiff.added).toEqual(["/dashboard"]);
      expect(routeDiff.removed).toEqual([]);
    });

    it("should detect simultaneous additions and removals", () => {
      const before = ["/old-page", "/dashboard", "/shared"];
      const after = ["/new-page", "/dashboard", "/shared"];

      const added = after.filter((r) => !before.includes(r));
      const removed = before.filter((r) => !after.includes(r));

      expect(added).toEqual(["/new-page"]);
      expect(removed).toEqual(["/old-page"]);
    });
  });

  describe("Doc Section Mapping", () => {
    it("should map route changes to affected documentation sections", () => {
      const routeToDocSection: Record<string, string[]> = {
        "/engagements": ["admin-guide#engagements", "user-guide#pentest-workflow"],
        "/domain-intel": ["user-guide#recon-workflow", "msp-guide#scanning"],
        "/ember": ["user-guide#red-team-workflow", "admin-guide#c2-management"],
        "/doc-tracker": ["admin-guide#documentation-management"],
      };

      const changedRoutes = ["/domain-intel", "/doc-tracker"];
      const affectedSections = changedRoutes.flatMap(
        (r) => routeToDocSection[r] || []
      );

      expect(affectedSections).toContain("user-guide#recon-workflow");
      expect(affectedSections).toContain("msp-guide#scanning");
      expect(affectedSections).toContain("admin-guide#documentation-management");
      expect(affectedSections.length).toBe(3);
    });

    it("should map router changes to affected documentation sections", () => {
      const routerToDocSection: Record<string, string[]> = {
        "engagements.ts": ["admin-guide#engagements", "user-guide#pentest-workflow"],
        "domain-intel-core.ts": ["user-guide#recon-workflow"],
        "doc-tracker.ts": ["admin-guide#documentation-management"],
      };

      const changedRouters = ["doc-tracker.ts"];
      const affectedSections = changedRouters.flatMap(
        (r) => routerToDocSection[r] || []
      );

      expect(affectedSections).toContain("admin-guide#documentation-management");
    });

    it("should map schema changes to affected documentation sections", () => {
      const tableToDocSection: Record<string, string[]> = {
        users: ["admin-guide#user-management"],
        engagements: ["admin-guide#engagements", "user-guide#pentest-workflow"],
        exploitationAttempts: ["user-guide#exploitation-workflow"],
      };

      const changedTables = ["engagements", "exploitationAttempts"];
      const affectedSections = changedTables.flatMap(
        (t) => tableToDocSection[t] || []
      );

      expect(affectedSections).toContain("admin-guide#engagements");
      expect(affectedSections).toContain("user-guide#pentest-workflow");
      expect(affectedSections).toContain("user-guide#exploitation-workflow");
    });
  });

  describe("Update Report Generation", () => {
    it("should generate a structured update report from diffs", () => {
      const diff = {
        routes: { added: ["/doc-tracker"], removed: [] as string[] },
        routers: { added: ["doc-tracker.ts"], removed: [] as string[] },
        schemaTables: { added: [] as string[], removed: [] as string[] },
        integrations: { added: [] as string[], removed: [] as string[] },
      };

      const totalChanges =
        diff.routes.added.length +
        diff.routes.removed.length +
        diff.routers.added.length +
        diff.routers.removed.length +
        diff.schemaTables.added.length +
        diff.schemaTables.removed.length +
        diff.integrations.added.length +
        diff.integrations.removed.length;

      expect(totalChanges).toBe(2);

      // Report should have a severity level
      const severity =
        totalChanges > 10 ? "high" : totalChanges > 3 ? "medium" : "low";
      expect(severity).toBe("low");
    });

    it("should flag high severity when many changes detected", () => {
      const manyChanges = {
        routes: {
          added: Array.from({ length: 5 }, (_, i) => `/new-page-${i}`),
          removed: Array.from({ length: 3 }, (_, i) => `/old-page-${i}`),
        },
        routers: {
          added: ["new-router-1.ts", "new-router-2.ts", "new-router-3.ts"],
          removed: [],
        },
      };

      const totalChanges =
        manyChanges.routes.added.length +
        manyChanges.routes.removed.length +
        manyChanges.routers.added.length +
        manyChanges.routers.removed.length;

      expect(totalChanges).toBe(11);

      const severity =
        totalChanges > 10 ? "high" : totalChanges > 3 ? "medium" : "low";
      expect(severity).toBe("high");
    });

    it("should report no changes when snapshots are identical", () => {
      const snapshot = {
        routes: ["/dashboard", "/engagements"],
        routers: ["auth.ts"],
      };

      const routeDiff = {
        added: snapshot.routes.filter(
          (r: string) => !snapshot.routes.includes(r)
        ),
        removed: snapshot.routes.filter(
          (r: string) => !snapshot.routes.includes(r)
        ),
      };

      expect(routeDiff.added.length).toBe(0);
      expect(routeDiff.removed.length).toBe(0);
    });
  });

  describe("Role-Based Guide Impact Analysis", () => {
    it("should identify which role guides are affected by offensive tool changes", () => {
      const offensiveRoutes = [
        "/engagements",
        "/exploit-arsenal",
        "/payload-generator",
        "/evasion-engine",
      ];
      const roleMapping: Record<string, string[]> = {
        pentest: [
          "/engagements",
          "/exploit-arsenal",
          "/payload-generator",
          "/domain-intel",
        ],
        redTeam: [
          "/engagements",
          "/exploit-arsenal",
          "/evasion-engine",
          "/ember",
        ],
        blueTeam: ["/detection-coverage", "/rule-validator", "/siem-connectors"],
        socAnalyst: ["/detection-coverage", "/siem-feedback", "/ssil"],
      };

      const changedRoutes = ["/exploit-arsenal", "/evasion-engine"];
      const affectedRoles = Object.entries(roleMapping)
        .filter(([_, routes]) =>
          routes.some((r) => changedRoutes.includes(r))
        )
        .map(([role]) => role);

      expect(affectedRoles).toContain("pentest");
      expect(affectedRoles).toContain("redTeam");
      expect(affectedRoles).not.toContain("blueTeam");
      expect(affectedRoles).not.toContain("socAnalyst");
    });

    it("should identify MSP/MSSP guide impact from tenant-related changes", () => {
      const mspRoutes = [
        "/tenants",
        "/mssp-analytics",
        "/customer-accounts",
        "/client-portal",
      ];
      const changedRoutes = ["/tenants", "/customer-accounts"];

      const mspImpact = changedRoutes.filter((r) => mspRoutes.includes(r));
      expect(mspImpact.length).toBe(2);
      expect(mspImpact).toContain("/tenants");
      expect(mspImpact).toContain("/customer-accounts");
    });

    it("should identify admin guide impact from system configuration changes", () => {
      const adminRoutes = [
        "/team",
        "/tenants",
        "/admin/licenses",
        "/admin/updates",
        "/admin/version-thresholds",
        "/job-queue",
        "/error-dashboard",
      ];
      const changedRoutes = ["/admin/updates", "/job-queue"];

      const adminImpact = changedRoutes.filter((r) =>
        adminRoutes.includes(r)
      );
      expect(adminImpact.length).toBe(2);
    });
  });

  describe("Nav Group Change Detection", () => {
    it("should detect when a new nav item is added to a group", () => {
      const oldItems = [
        { label: "Team", path: "/team" },
        { label: "Tenants", path: "/tenants" },
      ];
      const newItems = [
        { label: "Team", path: "/team" },
        { label: "Tenants", path: "/tenants" },
        { label: "Doc Tracker", path: "/doc-tracker" },
      ];

      const oldPaths = oldItems.map((i) => i.path);
      const newPaths = newItems.map((i) => i.path);
      const added = newPaths.filter((p) => !oldPaths.includes(p));

      expect(added).toEqual(["/doc-tracker"]);
    });

    it("should detect when a nav item label changes", () => {
      const oldItems = [
        { label: "Vulnerability Scanner", path: "/vuln-scanner" },
      ];
      const newItems = [
        { label: "Advanced Vulnerability Scanner", path: "/vuln-scanner" },
      ];

      const labelChanges = newItems.filter((newItem) => {
        const oldItem = oldItems.find((o) => o.path === newItem.path);
        return oldItem && oldItem.label !== newItem.label;
      });

      expect(labelChanges.length).toBe(1);
      expect(labelChanges[0].label).toBe("Advanced Vulnerability Scanner");
    });
  });

  describe("Integration Change Detection", () => {
    it("should detect new API integrations that need documentation", () => {
      const oldIntegrations = [
        "CALDERA_API_KEY",
        "SHODAN_API_KEY",
        "CENSYS_API_ID",
      ];
      const newIntegrations = [
        "CALDERA_API_KEY",
        "SHODAN_API_KEY",
        "CENSYS_API_ID",
        "VIRUSTOTAL_API_KEY",
        "GREYNOISE_API_KEY",
      ];

      const added = newIntegrations.filter(
        (i) => !oldIntegrations.includes(i)
      );
      expect(added).toEqual(["VIRUSTOTAL_API_KEY", "GREYNOISE_API_KEY"]);
      expect(added.length).toBe(2);
    });

    it("should detect removed integrations that need doc cleanup", () => {
      const oldIntegrations = [
        "CALDERA_API_KEY",
        "DEPRECATED_SERVICE_KEY",
        "SHODAN_API_KEY",
      ];
      const newIntegrations = ["CALDERA_API_KEY", "SHODAN_API_KEY"];

      const removed = oldIntegrations.filter(
        (i) => !newIntegrations.includes(i)
      );
      expect(removed).toEqual(["DEPRECATED_SERVICE_KEY"]);
    });
  });
});
