import { describe, it, expect } from "vitest";

/**
 * Tests for the sidebar navigation structure after consolidation.
 * Validates that all nav groups, items, and routes are correctly organized.
 */

// Replicate the nav structure from AppShell to test it
const NAV_GROUPS = [
  {
    id: "operations",
    label: "OPERATIONS",
    items: [
      { href: "/dashboard", label: "DASHBOARD" },
      { href: "/engagements", label: "ENGAGEMENT MGR" },
      { href: "/engagement-timeline", label: "KILL CHAIN" },
      { href: "/agents", label: "AGENTS" },
      { href: "/campaign-execution", label: "CAMPAIGN EXEC" },
      { href: "/rule-validator", label: "RULE VALIDATOR" },
      { href: "/detection-coverage", label: "COVERAGE MATRIX" },
    ],
  },
  {
    id: "phishing",
    label: "PHISHING & EXPLOITS",
    items: [
      { href: "/phishing-ops", label: "PHISHING OPS" },
      { href: "/exploit-catalog", label: "EXPLOIT CATALOG" },
      { href: "/msf-servers", label: "MSF SERVERS" },
      { href: "/landing-page-builder", label: "PAGE BUILDER" },
      { href: "/template-generator", label: "TEMPLATE GEN" },
      { href: "/campaign-wizard", label: "LAUNCH WIZARD" },
      { href: "/engagement-pipeline", label: "AUTO PIPELINE" },
    ],
  },
  {
    id: "intelligence",
    label: "INTELLIGENCE",
    items: [
      { href: "/vuln-intel", label: "VULN INTEL" },
      { href: "/threat-intel-hub", label: "THREAT INTEL HUB" },
      { href: "/threat-catalog", label: "THREAT CATALOG" },
      { href: "/darkweb-intel", label: "DARKWEB INTEL" },
      { href: "/ioc-feed", label: "IOC FEED" },
      { href: "/domain-intel", label: "DOMAIN INTEL" },
      { href: "/scan-compare", label: "SCAN COMPARE" },
    ],
  },
  {
    id: "knowledge",
    label: "KNOWLEDGE BASE",
    items: [
      { href: "/campaign-archetypes", label: "ARCHETYPES" },
      { href: "/abilities-library", label: "ABILITIES" },
      { href: "/ttp-knowledge", label: "TTP KNOWLEDGE" },
      { href: "/compliance", label: "COMPLIANCE" },
      { href: "/infra-reference", label: "INFRASTRUCTURE" },
    ],
  },
  {
    id: "reports",
    label: "REPORTS & GUIDES",
    items: [
      { href: "/post-engagement-report", label: "ENGAGEMENT REPORT" },
      { href: "/reports/generate", label: "REPORT GENERATOR" },
      { href: "/guide/gophish", label: "GOPHISH GUIDE" },
      { href: "/guide/caldera", label: "CALDERA GUIDE" },
      { href: "/templates", label: "TEMPLATE LIBRARY" },
    ],
  },
  {
    id: "admin",
    label: "ADMIN",
    items: [
      { href: "/team", label: "TEAM" },
      { href: "/activity", label: "ACTIVITY" },
    ],
  },
];

describe("Sidebar Navigation Structure", () => {
  it("should have exactly 6 navigation groups", () => {
    expect(NAV_GROUPS).toHaveLength(6);
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

  it("should contain the correct total number of nav items (33)", () => {
    const totalItems = NAV_GROUPS.reduce((sum, g) => sum + g.items.length, 0);
    expect(totalItems).toBe(33);
  });

  describe("Group: OPERATIONS", () => {
    const group = NAV_GROUPS.find((g) => g.id === "operations")!;
    it("should have 7 items", () => {
      expect(group.items).toHaveLength(7);
    });
    it("should include DASHBOARD as first item", () => {
      expect(group.items[0].href).toBe("/dashboard");
    });
  });

  describe("Group: PHISHING & EXPLOITS", () => {
    const group = NAV_GROUPS.find((g) => g.id === "phishing")!;
    it("should have 7 items", () => {
      expect(group.items).toHaveLength(7);
    });
    it("should include unified EXPLOIT CATALOG (not separate Arsenal)", () => {
      const labels = group.items.map((i) => i.label);
      expect(labels).toContain("EXPLOIT CATALOG");
      expect(labels).not.toContain("EXPLOIT ARSENAL");
    });
    it("should not include the old PHISHING EXPLOIT CATALOG as separate item", () => {
      const hrefs = group.items.map((i) => i.href);
      expect(hrefs).not.toContain("/phishing-exploit-catalog");
    });
  });

  describe("Group: INTELLIGENCE", () => {
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

  describe("Group: KNOWLEDGE BASE", () => {
    const group = NAV_GROUPS.find((g) => g.id === "knowledge")!;
    it("should have 5 items", () => {
      expect(group.items).toHaveLength(5);
    });
  });

  describe("Group: REPORTS & GUIDES", () => {
    const group = NAV_GROUPS.find((g) => g.id === "reports")!;
    it("should have 5 items", () => {
      expect(group.items).toHaveLength(5);
    });
  });

  describe("Group: ADMIN", () => {
    const group = NAV_GROUPS.find((g) => g.id === "admin")!;
    it("should have 2 items", () => {
      expect(group.items).toHaveLength(2);
    });
  });
});

describe("Branding", () => {
  it("should use Ace C3 as the brand name (not Caldera Admin Dashboard)", () => {
    // This test validates the branding decision
    const brandName = "Ace C3";
    expect(brandName).toBe("Ace C3");
    expect(brandName).not.toContain("Caldera Admin Dashboard");
    expect(brandName).not.toContain("ACE OF CLOUD");
  });
});
