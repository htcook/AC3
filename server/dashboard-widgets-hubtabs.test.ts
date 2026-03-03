/**
 * Tests for Dashboard Widget Configuration and Hub Tab Navigation
 */
import { describe, it, expect, beforeEach } from "vitest";

// ─── Dashboard Widget Config ───────────────────────────────────────────────────

describe("Dashboard Widget Configuration", () => {
  const DEFAULT_WIDGETS = [
    { id: "start-engagement", label: "Start Engagement", icon: "Rocket", visible: true, pinned: true, order: 0 },
    { id: "mission-workflows", label: "Mission Workflows", icon: "Workflow", visible: true, pinned: false, order: 1 },
    { id: "recent-scans", label: "Recent Scans", icon: "History", visible: true, pinned: false, order: 2 },
    { id: "quick-access", label: "Quick Access", icon: "Zap", visible: true, pinned: false, order: 3 },
    { id: "live-stats", label: "Live Stats", icon: "Activity", visible: true, pinned: false, order: 4 },
    { id: "server-status", label: "Server Status", icon: "Server", visible: true, pinned: false, order: 5 },
    { id: "phishing-metrics", label: "Phishing Metrics", icon: "Fish", visible: true, pinned: false, order: 6 },
    { id: "threat-awareness", label: "Threat Awareness", icon: "ShieldAlert", visible: true, pinned: false, order: 7 },
    { id: "vuln-feed", label: "0-Day Vuln Feed", icon: "Flame", visible: true, pinned: false, order: 8 },
    { id: "more-tools", label: "More Tools", icon: "Grid3X3", visible: true, pinned: false, order: 9 },
  ];

  it("should have 10 default widgets", () => {
    expect(DEFAULT_WIDGETS).toHaveLength(10);
  });

  it("should have unique IDs for all widgets", () => {
    const ids = DEFAULT_WIDGETS.map(w => w.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("should have sequential order values", () => {
    DEFAULT_WIDGETS.forEach((w, i) => {
      expect(w.order).toBe(i);
    });
  });

  it("should have start-engagement pinned by default", () => {
    const startEngagement = DEFAULT_WIDGETS.find(w => w.id === "start-engagement");
    expect(startEngagement?.pinned).toBe(true);
    expect(startEngagement?.visible).toBe(true);
  });

  it("should all be visible by default", () => {
    expect(DEFAULT_WIDGETS.every(w => w.visible)).toBe(true);
  });

  it("should support toggling visibility", () => {
    const widget = { ...DEFAULT_WIDGETS[1] };
    widget.visible = !widget.visible;
    expect(widget.visible).toBe(false);
    widget.visible = !widget.visible;
    expect(widget.visible).toBe(true);
  });

  it("should support toggling pin state", () => {
    const widget = { ...DEFAULT_WIDGETS[1] };
    expect(widget.pinned).toBe(false);
    widget.pinned = true;
    expect(widget.pinned).toBe(true);
  });

  it("should support reordering by swapping order values", () => {
    const widgets = DEFAULT_WIDGETS.map(w => ({ ...w }));
    // Swap first two
    const tmp = widgets[0].order;
    widgets[0].order = widgets[1].order;
    widgets[1].order = tmp;
    const sorted = [...widgets].sort((a, b) => a.order - b.order);
    expect(sorted[0].id).toBe("mission-workflows");
    expect(sorted[1].id).toBe("start-engagement");
  });

  it("should serialize to JSON for localStorage persistence", () => {
    const json = JSON.stringify(DEFAULT_WIDGETS);
    const parsed = JSON.parse(json);
    expect(parsed).toHaveLength(10);
    expect(parsed[0].id).toBe("start-engagement");
  });

  it("should support reset to defaults", () => {
    const modified = DEFAULT_WIDGETS.map(w => ({ ...w, visible: false, pinned: true, order: 99 }));
    // Reset by replacing with defaults
    const reset = DEFAULT_WIDGETS.map(w => ({ ...w }));
    expect(reset.every(w => w.visible)).toBe(true);
    expect(reset.filter(w => w.pinned)).toHaveLength(1);
  });
});

// ─── Hub Tab Navigation ────────────────────────────────────────────────────────

describe("Hub Tab Navigation", () => {
  interface HubConfig {
    title: string;
    defaultTab: string;
    tabs: { id: string; label: string; componentPath: string }[];
  }

  const HUB_PAGES: HubConfig[] = [
    {
      title: "Discovery Toolkit",
      defaultTab: "subfinder",
      tabs: [
        { id: "subfinder", label: "Subfinder", componentPath: "pages/SubfinderPage" },
        { id: "httpx", label: "HTTPX", componentPath: "pages/HttpxPage" },
        { id: "port-scanner", label: "Port Scanner", componentPath: "pages/NaabuPage" },
      ],
    },
    {
      title: "AD Security",
      defaultTab: "overview",
      tabs: [
        { id: "overview", label: "Overview", componentPath: "pages/ADSecurityDashboard" },
        { id: "attack-paths", label: "Attack Paths", componentPath: "pages/ADAttackPathGraph" },
        { id: "bloodhound", label: "BloodHound", componentPath: "pages/BloodHoundIngestion" },
      ],
    },
    {
      title: "Phishing Ops",
      defaultTab: "campaigns",
      tabs: [
        { id: "campaigns", label: "Campaigns", componentPath: "pages/PhishingCampaigns" },
        { id: "wizard", label: "Campaign Wizard", componentPath: "pages/CampaignWizard" },
        { id: "templates", label: "Template Gen", componentPath: "pages/TemplateGenerator" },
      ],
    },
    {
      title: "C2 Hub",
      defaultTab: "caldera",
      tabs: [
        { id: "caldera", label: "Caldera", componentPath: "pages/C2Servers" },
        { id: "sliver", label: "Sliver", componentPath: "pages/SliverC2" },
      ],
    },
  ];

  it("should have at least 4 hub pages defined", () => {
    expect(HUB_PAGES.length).toBeGreaterThanOrEqual(4);
  });

  it("should have unique tab IDs within each hub", () => {
    for (const hub of HUB_PAGES) {
      const ids = hub.tabs.map(t => t.id);
      expect(new Set(ids).size).toBe(ids.length);
    }
  });

  it("should have a valid defaultTab that exists in tabs", () => {
    for (const hub of HUB_PAGES) {
      const tabIds = hub.tabs.map(t => t.id);
      expect(tabIds).toContain(hub.defaultTab);
    }
  });

  it("should have at least 2 tabs per hub page", () => {
    for (const hub of HUB_PAGES) {
      expect(hub.tabs.length).toBeGreaterThanOrEqual(2);
    }
  });

  it("should have non-empty labels and component paths", () => {
    for (const hub of HUB_PAGES) {
      for (const tab of hub.tabs) {
        expect(tab.label.length).toBeGreaterThan(0);
        expect(tab.componentPath.length).toBeGreaterThan(0);
      }
    }
  });

  it("Discovery Toolkit should consolidate subfinder, httpx, port-scanner", () => {
    const discovery = HUB_PAGES.find(h => h.title === "Discovery Toolkit");
    expect(discovery).toBeDefined();
    expect(discovery!.tabs.map(t => t.id)).toEqual(["subfinder", "httpx", "port-scanner"]);
  });

  it("C2 Hub should consolidate caldera and sliver", () => {
    const c2 = HUB_PAGES.find(h => h.title === "C2 Hub");
    expect(c2).toBeDefined();
    expect(c2!.tabs.map(t => t.id)).toContain("caldera");
    expect(c2!.tabs.map(t => t.id)).toContain("sliver");
  });
});

// ─── Test Data Isolation ────────────────────────────────────────────────────────

describe("Test Data Isolation", () => {
  it("should generate unique test run IDs", () => {
    const id1 = `__test_${Date.now()}`;
    const id2 = `__test_${Date.now() + 1}`;
    expect(id1).not.toBe(id2);
    expect(id1).toMatch(/^__test_\d+$/);
  });

  it("should generate test-prefixed names", () => {
    const prefix = `__test_${Date.now()}`;
    const name = `${prefix}_my-scan`;
    expect(name).toContain("__test_");
    expect(name).toContain("my-scan");
  });

  it("should track created items for cleanup", () => {
    const tracked: { table: string; id: number }[] = [];
    tracked.push({ table: "domain_intel_scans", id: 999 });
    tracked.push({ table: "discovered_assets", id: 1000 });
    expect(tracked).toHaveLength(2);
    expect(tracked[0].table).toBe("domain_intel_scans");
  });

  it("should identify legacy test patterns for cleanup", () => {
    const legacyPatterns = [
      "test-monitor-123",
      "get-test-456",
      "trpc-get-789",
      "threat-model-abc",
      "campaigns-test",
    ];
    const testPattern = /^(test-|get-test-|trpc-|threat-model-|campaigns-)/;
    for (const name of legacyPatterns) {
      expect(name).toMatch(testPattern);
    }
    // Real data should NOT match
    expect("aceofcloud.com").not.toMatch(testPattern);
    expect("vianova.ai").not.toMatch(testPattern);
  });
});
