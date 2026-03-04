import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

// ─── Breach Events Endpoint Tests ────────────────────────────────────────────

describe("Breach Events Feed", () => {
  const routerPath = path.resolve(__dirname, "routers/darkweb-intel.ts");
  const routerSrc = fs.readFileSync(routerPath, "utf-8");

  it("getBreachEvents endpoint exists in darkweb-intel router", () => {
    expect(routerSrc).toContain("getBreachEvents:");
    expect(routerSrc).toContain("protectedProcedure.query");
  });

  it("aggregates ransomware_events table", () => {
    expect(routerSrc).toContain("ransomwareEvents");
    expect(routerSrc).toContain("type: \"ransomware\"");
  });

  it("aggregates underground_intel_events table (data_leak, ransomware, credential types)", () => {
    expect(routerSrc).toContain("undergroundIntelEvents");
    expect(routerSrc).toContain("data_leak");
    expect(routerSrc).toContain("credential");
    expect(routerSrc).toContain("exploit_kit");
  });

  it("aggregates incident_reports table", () => {
    expect(routerSrc).toContain("incidentReports");
    expect(routerSrc).toContain("type: \"incident\"");
  });

  it("sorts combined events by date descending and limits to 1000", () => {
    expect(routerSrc).toContain("sort((a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime())");
    expect(routerSrc).toContain(".slice(0, 1000)");
  });

  it("uses ID offsets to prevent collisions between tables", () => {
    expect(routerSrc).toContain("u.id + 100000");
    expect(routerSrc).toContain("ir.id + 200000");
  });

  it("returns consistent event shape with required fields", () => {
    // All mapped events should have: id, type, groupName, victimName, country, sector, description, publishedAt, source, sourceUrl, verified, severity
    expect(routerSrc).toContain("groupName:");
    expect(routerSrc).toContain("victimName:");
    expect(routerSrc).toContain("publishedAt:");
    expect(routerSrc).toContain("source:");
    expect(routerSrc).toContain("sourceUrl:");
    expect(routerSrc).toContain("verified:");
    expect(routerSrc).toContain("severity:");
  });
});

// ─── Breach Events Page Tests ────────────────────────────────────────────────

describe("BreachEvents Page", () => {
  const pagePath = path.resolve(__dirname, "../client/src/pages/BreachEvents.tsx");
  const pageSrc = fs.readFileSync(pagePath, "utf-8");

  it("BreachEvents page file exists", () => {
    expect(fs.existsSync(pagePath)).toBe(true);
  });

  it("calls trpc.darkwebIntel.getBreachEvents.useQuery", () => {
    expect(pageSrc).toContain("trpc.darkwebIntel.getBreachEvents.useQuery");
  });

  it("has tabs for All Events, Ransomware, Data Breach, Data Leak, Incidents", () => {
    expect(pageSrc).toContain("All Events");
    expect(pageSrc).toContain("Ransomware");
    expect(pageSrc).toContain("Data Breach");
    expect(pageSrc).toContain("Data Leak");
    expect(pageSrc).toContain("Incidents");
  });

  it("has search and filter controls", () => {
    expect(pageSrc).toContain("Search events");
    expect(pageSrc).toContain("sectorFilter");
    expect(pageSrc).toContain("countryFilter");
  });

  it("displays stats cards (Total, Last 24h, Last 7 Days, Ransomware, Data Breaches, Threat Groups, Countries)", () => {
    expect(pageSrc).toContain("Total Events");
    expect(pageSrc).toContain("Last 24h");
    expect(pageSrc).toContain("Last 7 Days");
    expect(pageSrc).toContain("Threat Groups");
    expect(pageSrc).toContain("Countries");
  });

  it("shows source attribution with external links", () => {
    expect(pageSrc).toContain("ExternalLink");
    expect(pageSrc).toContain("sourceUrl");
    expect(pageSrc).toContain("Source");
  });

  it("has auto-refresh every 2 minutes", () => {
    expect(pageSrc).toContain("refetchInterval: 120_000");
  });

  it("has a Refresh Feed button that triggers sync", () => {
    expect(pageSrc).toContain("Refresh Feed");
    expect(pageSrc).toContain("syncDailyDarkWeb.useMutation");
  });

  it("uses sonner toast for notifications", () => {
    expect(pageSrc).toContain('import { toast } from "sonner"');
    expect(pageSrc).toContain("toast.success");
    expect(pageSrc).toContain("toast.error");
  });
});

// ─── Route Registration Tests ────────────────────────────────────────────────

describe("BreachEvents Route Registration", () => {
  const appPath = path.resolve(__dirname, "../client/src/App.tsx");
  const appSrc = fs.readFileSync(appPath, "utf-8");

  it("BreachEvents lazy import exists in App.tsx", () => {
    expect(appSrc).toContain("const BreachEvents = lazy(() => import(\"./pages/BreachEvents\"))");
  });

  it("breach-events route is registered", () => {
    expect(appSrc).toContain("/breach-events");
    expect(appSrc).toContain("BreachEvents");
  });
});

// ─── Navigation Tests ────────────────────────────────────────────────────────

describe("BreachEvents Navigation", () => {
  const shellPath = path.resolve(__dirname, "../client/src/components/AppShell.tsx");
  const shellSrc = fs.readFileSync(shellPath, "utf-8");

  it("BREACH EVENTS link exists in AppShell sidebar", () => {
    expect(shellSrc).toContain("BREACH EVENTS");
    expect(shellSrc).toContain("/breach-events");
  });

  it("BREACH EVENTS is in the Intelligence section", () => {
    // Should be near DARKWEB INTEL
    const darkwebIdx = shellSrc.indexOf("DARKWEB INTEL");
    const breachIdx = shellSrc.indexOf("BREACH EVENTS");
    expect(darkwebIdx).toBeGreaterThan(-1);
    expect(breachIdx).toBeGreaterThan(-1);
    // BREACH EVENTS should appear after DARKWEB INTEL
    expect(breachIdx).toBeGreaterThan(darkwebIdx);
  });
});

// ─── Auto-Seed on Startup Tests ──────────────────────────────────────────────

describe("Auto-Seed on Startup", () => {
  const indexPath = path.resolve(__dirname, "_core/index.ts");
  const indexSrc = fs.readFileSync(indexPath, "utf-8");

  it("auto-seed is wired into server startup", () => {
    expect(indexSrc).toContain("Auto-seed");
  });

  it("seeds Daily Dark Web feed data on startup", () => {
    expect(indexSrc).toContain("dailydarkweb-feed");
  });

  it("seeds multi-source RSS feeds on startup", () => {
    expect(indexSrc).toContain("threat-intel-rss");
  });

  it("uses setTimeout delay to avoid blocking startup", () => {
    expect(indexSrc).toContain("setTimeout");
  });
});

// ─── DDW Feed Ransomware Events Insertion Tests ──────────────────────────────

describe("DDW Feed populates ransomware_events", () => {
  const feedPath = path.resolve(__dirname, "lib/dailydarkweb-feed.ts");
  const feedSrc = fs.readFileSync(feedPath, "utf-8");

  it("imports ransomwareEvents table", () => {
    expect(feedSrc).toContain("ransomwareEvents");
  });

  it("inserts into ransomware_events during sync", () => {
    expect(feedSrc).toContain("ransomwareEvents");
    // Should have insert logic for ransomware events
    expect(feedSrc).toContain("victimName");
    expect(feedSrc).toContain("groupName");
  });

  it("includes FULCRUMSEC victim data for ransomware events", () => {
    expect(feedSrc).toContain("FULCRUMSEC");
    expect(feedSrc).toContain("LexisNexis");
    expect(feedSrc).toContain("Avnet");
  });
});
