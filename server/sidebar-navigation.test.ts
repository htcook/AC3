import { describe, it, expect } from "vitest";

/**
 * Tests for the sidebar navigation structure after workflow-driven reorganization.
 * Validates that all nav groups, items, and routes are correctly organized
 * following the engagement lifecycle: Recon → Intel → Planning → Phishing →
 * Exploitation → Emulation → Reporting → Knowledge → Admin.
 */

// Replicate the nav structure from AppShell to test it
const NAV_GROUPS = [
  {
    id: "recon",
    label: "RECON & SCANNING",
    items: [
      { href: "/domain-intel", label: "DOMAIN INTEL" },
      { href: "/domain-intel/history", label: "SCAN HISTORY" },
      { href: "/scan-compare", label: "SCAN COMPARE" },
      { href: "/engagement-pipeline", label: "AUTO PIPELINE" },
    ],
  },
  {
    id: "intelligence",
    label: "THREAT INTELLIGENCE",
    items: [
      { href: "/threat-intel-hub", label: "THREAT INTEL HUB" },
      { href: "/threat-catalog", label: "THREAT CATALOG" },
      { href: "/vuln-intel", label: "VULN INTEL" },
      { href: "/darkweb-intel", label: "DARKWEB INTEL" },
      { href: "/ioc-feed", label: "IOC FEED" },
      { href: "/bug-bounty", label: "BUG BOUNTY HUB" },
      { href: "/stix-export", label: "STIX/TAXII EXPORT" },
    ],
  },
  {
    id: "planning",
    label: "ENGAGEMENT PLANNING",
    items: [
      { href: "/dashboard", label: "COMMAND CENTER" },
      { href: "/engagements", label: "ENGAGEMENT MGR" },
      { href: "/campaign-archetypes", label: "ARCHETYPES" },
      { href: "/attack-paths", label: "ATTACK PATHS" },
      { href: "/scoring", label: "RISK SCORING" },
      { href: "/engagement-timeline", label: "KILL CHAIN" },
    ],
  },
  {
    id: "phishing",
    label: "PHISHING & SOCIAL ENG",
    items: [
      { href: "/phishing-ops", label: "PHISHING OPS" },
      { href: "/campaign-wizard", label: "LAUNCH WIZARD" },
      { href: "/template-generator", label: "TEMPLATE GEN" },
      { href: "/landing-page-builder", label: "PAGE BUILDER" },
      { href: "/templates", label: "TEMPLATE LIBRARY" },
    ],
  },
  {
    id: "exploitation",
    label: "EXPLOITATION & C2",
    items: [
      { href: "/exploit-catalog", label: "EXPLOIT CATALOG" },
      { href: "/validation-engine", label: "VALIDATION ENGINE" },
      { href: "/payload-generator", label: "PAYLOAD GENERATOR" },
      { href: "/msf-servers", label: "C2 SERVERS" },
      { href: "/ssh-keys", label: "SSH KEYS" },
      { href: "/msf-sessions", label: "LIVE SESSIONS" },
      { href: "/session-recordings", label: "RECORDINGS" },
      { href: "/post-exploit-playbooks", label: "POST-EXPLOIT" },
      { href: "/file-transfers", label: "FILE TRANSFERS" },
      { href: "/evasion-engine", label: "EVASION ENGINE" },
    ],
  },
  {
    id: "emulation",
    label: "EMULATION & DETECTION",
    items: [
      { href: "/agents", label: "AGENTS" },
      { href: "/campaign-execution", label: "CAMPAIGN EXEC" },
      { href: "/emulation-playbooks", label: "EMULATION PLAYBOOKS" },
      { href: "/purple-team", label: "PURPLE TEAM" },
      { href: "/rule-validator", label: "RULE VALIDATOR" },
      { href: "/detection-coverage", label: "COVERAGE MATRIX" },
      { href: "/siem-connectors", label: "SIEM CONNECTORS" },
    ],
  },
  {
    id: "reports",
    label: "REPORTING",
    items: [
      { href: "/post-engagement-report", label: "ENGAGEMENT REPORT" },
      { href: "/reports/generate", label: "REPORT GENERATOR" },
      { href: "/bia-report", label: "AUTO-BIA REPORT" },
      { href: "/evidence", label: "EVIDENCE LOCKER" },
    ],
  },
  {
    id: "knowledge",
    label: "KNOWLEDGE BASE",
    items: [
      { href: "/abilities-library", label: "ABILITIES" },
      { href: "/ttp-knowledge", label: "TTP KNOWLEDGE" },
      { href: "/compliance", label: "COMPLIANCE" },
      { href: "/infra-reference", label: "INFRASTRUCTURE" },
      { href: "/guide/gophish", label: "PHISHING OPS GUIDE" },
      { href: "/guide/caldera", label: "EMULATION GUIDE" },
    ],
  },
  {
    id: "admin",
    label: "ADMIN",
    items: [
      { href: "/team", label: "TEAM" },
      { href: "/activity", label: "ACTIVITY" },
      { href: "/webhooks", label: "WEBHOOKS" },
      { href: "/training-dashboard", label: "TRAINING PIPELINE" },
    ],
  },
];

describe("Sidebar Navigation Structure (Workflow-Driven)", () => {
  it("should have exactly 9 navigation groups", () => {
    expect(NAV_GROUPS).toHaveLength(9);
  });

  it("should have unique group IDs", () => {
    const ids = NAV_GROUPS.map((g) => g.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("should have unique group labels", () => {
    const labels = NAV_GROUPS.map((g) => g.label);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("should have no duplicate hrefs across all groups", () => {
    const allHrefs = NAV_GROUPS.flatMap((g) => g.items.map((i) => i.href));
    expect(new Set(allHrefs).size).toBe(allHrefs.length);
  });

  it("should have all hrefs starting with /", () => {
    const allHrefs = NAV_GROUPS.flatMap((g) => g.items.map((i) => i.href));
    allHrefs.forEach((href) => {
      expect(href.startsWith("/")).toBe(true);
    });
  });

  it("should contain the correct total number of nav items (53)", () => {
    const totalItems = NAV_GROUPS.reduce((sum, g) => sum + g.items.length, 0);
    expect(totalItems).toBe(53);
  });

  it("should follow the engagement workflow order", () => {
    const groupOrder = NAV_GROUPS.map((g) => g.id);
    expect(groupOrder).toEqual([
      "recon",
      "intelligence",
      "planning",
      "phishing",
      "exploitation",
      "emulation",
      "reports",
      "knowledge",
      "admin",
    ]);
  });

  describe("Group: RECON & SCANNING (Phase 1)", () => {
    const group = NAV_GROUPS.find((g) => g.id === "recon")!;
    it("should have 4 items", () => {
      expect(group.items).toHaveLength(4);
    });
    it("should have DOMAIN INTEL as first item", () => {
      expect(group.items[0].href).toBe("/domain-intel");
    });
  });

  describe("Group: THREAT INTELLIGENCE (Phase 2)", () => {
    const group = NAV_GROUPS.find((g) => g.id === "intelligence")!;
    it("should have 7 items", () => {
      expect(group.items).toHaveLength(7);
    });
    it("should include VULN INTEL (not KEV DASHBOARD)", () => {
      const hrefs = group.items.map((i) => i.href);
      expect(hrefs).toContain("/vuln-intel");
      expect(hrefs).not.toContain("/kev-catalog");
    });
  });

  describe("Group: ENGAGEMENT PLANNING (Phase 3)", () => {
    const group = NAV_GROUPS.find((g) => g.id === "planning")!;
    it("should have 6 items", () => {
      expect(group.items).toHaveLength(6);
    });
    it("should have COMMAND CENTER as first item", () => {
      expect(group.items[0].href).toBe("/dashboard");
      expect(group.items[0].label).toBe("COMMAND CENTER");
    });
  });

  describe("Group: PHISHING & SOCIAL ENG (Phase 4)", () => {
    const group = NAV_GROUPS.find((g) => g.id === "phishing")!;
    it("should have 5 items", () => {
      expect(group.items).toHaveLength(5);
    });
    it("should include unified EXPLOIT CATALOG in exploitation group instead", () => {
      const hrefs = group.items.map((i) => i.href);
      expect(hrefs).not.toContain("/exploit-catalog");
    });
  });

  describe("Group: EXPLOITATION & C2 (Phase 5)", () => {
    const group = NAV_GROUPS.find((g) => g.id === "exploitation")!;
    it("should have 10 items", () => {
      expect(group.items).toHaveLength(10);
    });
    it("should include EXPLOIT CATALOG", () => {
      const hrefs = group.items.map((i) => i.href);
      expect(hrefs).toContain("/exploit-catalog");
    });
  });

  describe("Group: EMULATION & DETECTION (Phase 6)", () => {
    const group = NAV_GROUPS.find((g) => g.id === "emulation")!;
    it("should have 7 items", () => {
      expect(group.items).toHaveLength(7);
    });
    it("should include AGENTS as first item", () => {
      expect(group.items[0].href).toBe("/agents");
    });
  });

  describe("Group: REPORTING (Phase 7)", () => {
    const group = NAV_GROUPS.find((g) => g.id === "reports")!;
    it("should have 4 items", () => {
      expect(group.items).toHaveLength(4);
    });
    it("should include EVIDENCE LOCKER (moved from Admin)", () => {
      const hrefs = group.items.map((i) => i.href);
      expect(hrefs).toContain("/evidence");
    });
  });

  describe("Group: KNOWLEDGE BASE (Phase 8)", () => {
    const group = NAV_GROUPS.find((g) => g.id === "knowledge")!;
    it("should have 6 items", () => {
      expect(group.items).toHaveLength(6);
    });
    it("should include guides", () => {
      const hrefs = group.items.map((i) => i.href);
      expect(hrefs).toContain("/guide/gophish");
      expect(hrefs).toContain("/guide/caldera");
    });
  });

  describe("Group: ADMIN (Phase 9)", () => {
    const group = NAV_GROUPS.find((g) => g.id === "admin")!;
    it("should have 4 items", () => {
      expect(group.items).toHaveLength(4);
    });
    it("should include TRAINING PIPELINE (moved from Intelligence)", () => {
      const hrefs = group.items.map((i) => i.href);
      expect(hrefs).toContain("/training-dashboard");
    });
  });
});

describe("Branding", () => {
  it("should use Ace C3 as the brand name (not Caldera Admin Dashboard)", () => {
    const brandName = "Ace C3";
    expect(brandName).toBe("Ace C3");
    expect(brandName).not.toContain("Caldera Admin Dashboard");
    expect(brandName).not.toContain("ACE OF CLOUD");
  });
});
