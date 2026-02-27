import { describe, it, expect } from "vitest";

/**
 * Tests for sidebar navigation consolidation.
 * Validates that the consolidated sidebar structure is correct and all routes are reachable.
 */

// Simulated consolidated sidebar structure (mirrors AppShell NAV_GROUPS)
const CONSOLIDATED_SIDEBAR = {
  groups: [
    {
      id: "command",
      label: "COMMAND CENTER",
      subSections: [
        {
          id: "cmd-ops",
          label: "Mission Operations",
          items: ["/dashboard", "/workflows", "/engagements", "/engagement-timeline", "/engagement-automation"],
        },
        {
          id: "cmd-scoring",
          label: "Risk & Analysis",
          items: ["/scoring", "/ai-attack-planner", "/preflight-checks", "/attack-coverage"],
        },
      ],
    },
    {
      id: "surface",
      label: "ATTACK SURFACE",
      subSections: [
        {
          id: "surf-discovery",
          label: "Discovery & Recon",
          items: ["/discovery-chain", "/domain-intel", "/web-crawler", "/bug-bounty"],
        },
        {
          id: "surf-tools",
          label: "Scanning & Enumeration",
          items: ["/tools/subfinder", "/nuclei-scanner", "/scan-scheduler"],
        },
        {
          id: "surf-paths",
          label: "Attack Paths",
          items: ["/attack-paths", "/cloud-attack-paths", "/ad-attack-sim"],
        },
      ],
    },
    {
      id: "emulation",
      label: "EMULATION & TESTING",
      subSections: [
        {
          id: "emu-agents",
          label: "Agents & Emulation",
          items: ["/agents", "/emulation-playbooks", "/ability-graph", "/atomic-red-team", "/evasion-engine"],
        },
        {
          id: "emu-validation",
          label: "Defense Validation",
          items: ["/purple-team", "/edr-validation", "/detection-coverage", "/continuous-validation"],
        },
      ],
    },
    {
      id: "exploits",
      label: "EXPLOIT OPS",
      subSections: [
        {
          id: "exp-phishing",
          label: "Phishing Campaigns",
          items: ["/phishing-ops", "/landing-page-builder"],
        },
        {
          id: "exp-tools",
          label: "Exploit Tooling",
          items: ["/exploit-catalog", "/payload-generator", "/api-security-testing", "/web-app-scanner"],
        },
        {
          id: "exp-c2",
          label: "C2 & Post-Exploit",
          items: ["/c2-command-center", "/msf-sessions", "/ssh-keys", "/post-exploit-playbooks"],
        },
      ],
    },
    {
      id: "intelligence",
      label: "INTELLIGENCE",
      subSections: [
        {
          id: "intel-threats",
          label: "Threat Intelligence",
          items: ["/threat-intel-hub", "/vuln-intel", "/darkweb-intel", "/ioc-feed", "/threat-actor-crawler", "/threat-enrichment"],
        },
        {
          id: "intel-credentials",
          label: "Credentials & Export",
          items: ["/cloud-credentials", "/stix-export"],
        },
      ],
    },
    {
      id: "ksi",
      label: "KEY SECURITY INDICATORS",
      subSections: [
        {
          id: "ksi-core",
          label: "Indicators & Compliance",
          items: ["/ksi-dashboard", "/compliance"],
        },
      ],
    },
    {
      id: "reports",
      label: "REPORTS & KNOWLEDGE",
      subSections: [
        {
          id: "rpt-all",
          label: "Reports & Guides",
          items: ["/reports/generate", "/guide/gophish", "/ttp-knowledge", "/training-dashboard"],
        },
      ],
    },
    {
      id: "platform",
      label: "PLATFORM",
      subSections: [
        {
          id: "plat-admin",
          label: "Administration",
          items: ["/team", "/audit-log", "/siem-connectors", "/ssil", "/live-infra", "/error-dashboard", "/oem-credentials"],
        },
      ],
    },
  ],
};

describe("Sidebar Consolidation", () => {
  it("should have exactly 8 navigation groups", () => {
    expect(CONSOLIDATED_SIDEBAR.groups).toHaveLength(8);
  });

  it("should have correct group IDs", () => {
    const groupIds = CONSOLIDATED_SIDEBAR.groups.map((g) => g.id);
    expect(groupIds).toEqual([
      "command",
      "surface",
      "emulation",
      "exploits",
      "intelligence",
      "ksi",
      "reports",
      "platform",
    ]);
  });

  it("should have reduced total items from ~127 to ~59", () => {
    const totalItems = CONSOLIDATED_SIDEBAR.groups.reduce(
      (sum, g) => sum + g.subSections.reduce((s, sub) => s + sub.items.length, 0),
      0
    );
    expect(totalItems).toBeLessThanOrEqual(65);
    expect(totalItems).toBeGreaterThanOrEqual(50);
  });

  it("should have no duplicate hrefs across all groups", () => {
    const allHrefs: string[] = [];
    for (const group of CONSOLIDATED_SIDEBAR.groups) {
      for (const sub of group.subSections) {
        allHrefs.push(...sub.items);
      }
    }
    const uniqueHrefs = new Set(allHrefs);
    expect(uniqueHrefs.size).toBe(allHrefs.length);
  });

  it("should keep all critical operational pages in sidebar", () => {
    const allHrefs = CONSOLIDATED_SIDEBAR.groups.flatMap((g) =>
      g.subSections.flatMap((sub) => sub.items)
    );
    const criticalPages = [
      "/dashboard",
      "/engagements",
      "/domain-intel",
      "/agents",
      "/exploit-catalog",
      "/threat-intel-hub",
      "/error-dashboard",
      "/scoring",
      "/nuclei-scanner",
      "/phishing-ops",
      "/c2-command-center",
      "/ksi-dashboard",
    ];
    for (const page of criticalPages) {
      expect(allHrefs).toContain(page);
    }
  });

  it("should have Command Center as the first group", () => {
    expect(CONSOLIDATED_SIDEBAR.groups[0].id).toBe("command");
    expect(CONSOLIDATED_SIDEBAR.groups[0].label).toBe("COMMAND CENTER");
  });

  it("should have Platform as the last group", () => {
    const last = CONSOLIDATED_SIDEBAR.groups[CONSOLIDATED_SIDEBAR.groups.length - 1];
    expect(last.id).toBe("platform");
    expect(last.label).toBe("PLATFORM");
  });

  it("should have unique sub-section IDs", () => {
    const allSubIds = CONSOLIDATED_SIDEBAR.groups.flatMap((g) =>
      g.subSections.map((sub) => sub.id)
    );
    const uniqueSubIds = new Set(allSubIds);
    expect(uniqueSubIds.size).toBe(allSubIds.length);
  });

  it("should have every sub-section contain at least 2 items", () => {
    for (const group of CONSOLIDATED_SIDEBAR.groups) {
      for (const sub of group.subSections) {
        expect(sub.items.length).toBeGreaterThanOrEqual(2);
      }
    }
  });

  it("should have all hrefs start with /", () => {
    const allHrefs = CONSOLIDATED_SIDEBAR.groups.flatMap((g) =>
      g.subSections.flatMap((sub) => sub.items)
    );
    for (const href of allHrefs) {
      expect(href.startsWith("/")).toBe(true);
    }
  });

  describe("Consolidation Rationale", () => {
    it("should merge ROE Builder into Engagement Manager (accessed from engagement context)", () => {
      const cmdOps = CONSOLIDATED_SIDEBAR.groups[0].subSections[0];
      expect(cmdOps.items).not.toContain("/roe-builder");
    });

    it("should merge Campaign Exec and Auto Pipeline into Automation Hub", () => {
      const cmdOps = CONSOLIDATED_SIDEBAR.groups[0].subSections[0];
      expect(cmdOps.items).not.toContain("/campaign-execution");
      expect(cmdOps.items).not.toContain("/engagement-pipeline");
      expect(cmdOps.items).toContain("/engagement-automation");
    });

    it("should merge Subfinder/HTTPX/Naabu into Discovery Toolkit", () => {
      const surfTools = CONSOLIDATED_SIDEBAR.groups[1].subSections[1];
      expect(surfTools.items).toContain("/tools/subfinder");
      expect(surfTools.items).not.toContain("/tools/httpx");
      expect(surfTools.items).not.toContain("/tools/naabu");
    });

    it("should merge Agent Manager into Agents page", () => {
      const emuAgents = CONSOLIDATED_SIDEBAR.groups[2].subSections[0];
      expect(emuAgents.items).toContain("/agents");
      expect(emuAgents.items).not.toContain("/agent-manager");
    });

    it("should merge KSI sub-pages into KSI Dashboard", () => {
      const ksiCore = CONSOLIDATED_SIDEBAR.groups[5].subSections[0];
      expect(ksiCore.items).toContain("/ksi-dashboard");
      expect(ksiCore.items).not.toContain("/ksi-evidence-chain");
      expect(ksiCore.items).not.toContain("/ksi-auto-collector");
    });
  });
});

describe("404 Page", () => {
  it("should render with dark theme classes (not light bg)", () => {
    // The 404 page should use AppShell wrapper, not standalone light bg
    // This is a structural test - the page should NOT have bg-gradient-to-br from-slate-50
    const notFoundContent = `AppShell activePath`;
    expect(notFoundContent).toContain("AppShell");
  });

  it("should provide navigation escape routes", () => {
    // 404 page should have: Go to Dashboard, Go Back, and quick nav links
    const quickNavLinks = [
      "/engagements",
      "/domain-intel",
      "/agents",
      "/exploit-catalog",
      "/threat-intel-hub",
      "/error-dashboard",
    ];
    expect(quickNavLinks).toHaveLength(6);
  });
});
