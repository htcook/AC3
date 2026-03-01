import { describe, it, expect, vi } from "vitest";
import type { AssetObservation, ConnectorResult, PassiveConnector } from "./lib/passive/types";

/**
 * Tests for the passive ASM pipeline integration.
 * Validates the connector orchestrator, signal classifier, and passive guard.
 */

// ─── Mock Helpers ──────────────────────────────────────────────────

function makeObs(overrides: Partial<AssetObservation> & { assetId: string; source: string }): AssetObservation {
  return {
    domain: "example.com",
    assetType: "subdomain",
    observedAt: new Date(),
    tags: [],
    evidence: {},
    attribution: { provider: overrides.source, method: "mock" },
    ...overrides,
  } as AssetObservation;
}

function makeConnectorResult(name: string, observations: AssetObservation[]): ConnectorResult {
  return { connector: name, domain: "example.com", observations, errors: [], durationMs: 100, rateLimited: false };
}

function makeMockConnector(name: string, observations: AssetObservation[]): PassiveConnector {
  return {
    name,
    description: `Mock ${name}`,
    requiresApiKey: false,
    freeUrl: `https://${name}.example`,
    collect: vi.fn().mockResolvedValue(makeConnectorResult(name, observations)),
  };
}

// ─── Mock all connector modules ────────────────────────────────────

const crtshObs = [makeObs({ assetId: "crtsh-mail", source: "crtsh", name: "mail.example.com" })];
const shodanObs = [makeObs({ assetId: "shodan-ip", source: "shodan", assetType: "ip", ip: "93.184.216.34", tags: ["port:80", "port:443"], evidence: { ports: [80, 443] } })];
const waybackObs = [makeObs({ assetId: "wayback-admin", source: "wayback", assetType: "url", name: "https://example.com/admin/login.php", tags: ["admin_path"] })];
const rdapObs = [makeObs({ assetId: "rdap-reg", source: "rdap", name: "example.com" })];
const ripestatObs = [makeObs({ assetId: "ripe-net", source: "ripestat", assetType: "asn" })];

vi.mock("./lib/passive/crtsh", () => ({
  crtshConnector: makeMockConnector("crtsh", crtshObs),
}));
vi.mock("./lib/passive/shodan", () => ({
  shodanConnector: makeMockConnector("shodan", shodanObs),
}));
vi.mock("./lib/passive/wayback", () => ({
  waybackConnector: makeMockConnector("wayback", waybackObs),
}));
vi.mock("./lib/passive/rdap", () => ({
  rdapConnector: makeMockConnector("rdap", rdapObs),
}));
vi.mock("./lib/passive/ripestat", () => ({
  ripestatConnector: makeMockConnector("ripestat", ripestatObs),
}));
vi.mock("./lib/passive/censys", () => ({
  censysConnector: makeMockConnector("censys", []),
}));
vi.mock("./lib/passive/urlscan", () => ({
  urlscanConnector: makeMockConnector("urlscan", []),
}));
vi.mock("./lib/passive/securitytrails", () => ({
  securitytrailsConnector: makeMockConnector("securitytrails", []),
}));
vi.mock("./lib/passive/dehashed", () => ({
  dehashedConnector: makeMockConnector("dehashed", []),
}));
vi.mock("./lib/passive/shodan-internetdb", () => ({
  shodanInternetDBConnector: makeMockConnector("shodan-internetdb", []),
}));
vi.mock("./lib/passive/binaryedge", () => ({
  binaryedgeConnector: makeMockConnector("binaryedge", []),
}));
vi.mock("./lib/passive/greynoise", () => ({
  greynoiseConnector: makeMockConnector("greynoise", []),
}));
vi.mock("./lib/passive/email-security", () => ({
  emailSecurityConnector: makeMockConnector("email-security", []),
}));
vi.mock("./lib/passive/http-security", () => ({
  httpSecurityConnector: makeMockConnector("http-security", []),
}));
vi.mock("./lib/passive/cloud-assets", () => ({
  cloudAssetsConnector: makeMockConnector("cloud-assets", []),
}));
vi.mock("./lib/passive/container-discovery", () => ({
  containerDiscoveryConnector: makeMockConnector("container-discovery", []),
}));
vi.mock("./lib/passive/dns-deep", () => ({
  dnsDeepConnector: makeMockConnector("dns-deep", []),
}));
vi.mock("./lib/passive/github-leaks", () => ({
  githubLeaksConnector: makeMockConnector("github-leaks", []),
}));
vi.mock("./lib/passive/virustotal", () => ({
  virustotalConnector: makeMockConnector("virustotal", []),
}));
vi.mock("./lib/passive/hibp", () => ({
  hibpConnector: makeMockConnector("hibp", []),
}));
vi.mock("./lib/passive/whoisxml", () => ({
  whoisxmlConnector: makeMockConnector("whoisxml", []),
}));
vi.mock("./lib/passive/leakix", () => ({
  leakixConnector: makeMockConnector("leakix", []),
}));
vi.mock("./lib/passive/fullhunt", () => ({
  fullhuntConnector: makeMockConnector("fullhunt", []),
}));
vi.mock("./lib/passive/netlas", () => ({
  netlasConnector: makeMockConnector("netlas", []),
}));
vi.mock("./lib/passive/hunter", () => ({
  hunterConnector: makeMockConnector("hunter", []),
}));
vi.mock("./lib/passive/social-media", () => ({
  socialMediaConnector: makeMockConnector("social-media", []),
}));
vi.mock("./lib/passive/abuseipdb", () => ({
  abuseipdbConnector: makeMockConnector("abuseipdb", []),
}));
vi.mock("./lib/passive/passivetotal", () => ({
  passivetotalConnector: makeMockConnector("passivetotal", []),
}));
vi.mock("./lib/passive/github-recon", () => ({
  githubReconConnector: makeMockConnector("github_recon", []),
}));
vi.mock("./lib/passive/cloud-bucket-recon", () => ({
  cloudBucketReconConnector: makeMockConnector("cloud_bucket_recon", []),
}));

describe("Passive ASM Pipeline Integration", () => {
  // ─── Signal Classifier ─────────────────────────────────────────
  describe("Signal Classifier", () => {
    it("should classify observations into risk signals", async () => {
      const { classifySignals } = await import("./lib/passive/signal-classifier");
      const observations: AssetObservation[] = [
        makeObs({
          assetId: "test-admin",
          source: "wayback",
          assetType: "url",
          name: "https://example.com/admin/login.php",
          tags: ["admin_path"],
        }),
        makeObs({
          assetId: "test-ssh",
          source: "shodan",
          assetType: "ip",
          ip: "93.184.216.34",
          tags: ["port:22"],
        }),
        makeObs({
          assetId: "test-db",
          source: "shodan",
          assetType: "ip",
          ip: "93.184.216.35",
          tags: ["port:3306"],
        }),
      ];
      const signals = classifySignals(observations);
      expect(Array.isArray(signals)).toBe(true);
      expect(signals.length).toBeGreaterThan(0);

      // Should detect admin panel, SSH exposure, and open DB port
      signals.forEach(signal => {
        expect(signal).toHaveProperty("signalId");
        expect(signal).toHaveProperty("signalType");
        expect(signal).toHaveProperty("severity");
        expect(signal).toHaveProperty("rationale");
        expect(signal).toHaveProperty("confidence");
        expect(["critical", "high", "medium", "low", "info"]).toContain(signal.severity);
      });
    });

    it("should detect exposed admin interfaces", async () => {
      const { classifySignals } = await import("./lib/passive/signal-classifier");
      const signals = classifySignals([
        makeObs({ assetId: "admin-1", source: "wayback", name: "admin.example.com", tags: [] }),
      ]);
      const adminSignal = signals.find(s => s.signalType === "admin_panel_exposed");
      expect(adminSignal).toBeDefined();
      expect(adminSignal!.severity).toBe("high");
    });

    it("should detect open database ports", async () => {
      const { classifySignals } = await import("./lib/passive/signal-classifier");
      const signals = classifySignals([
        makeObs({ assetId: "db-1", source: "shodan", assetType: "ip", ip: "10.0.0.1", tags: ["port:5432"] }),
      ]);
      const dbSignal = signals.find(s => s.signalType === "open_db_port");
      expect(dbSignal).toBeDefined();
      expect(dbSignal!.severity).toBe("critical");
    });

    it("should return signal rule descriptions", async () => {
      const { getSignalRuleDescriptions } = await import("./lib/passive/signal-classifier");
      const rules = getSignalRuleDescriptions();
      expect(rules.length).toBeGreaterThan(0);
      rules.forEach(r => {
        expect(r).toHaveProperty("id");
        expect(r).toHaveProperty("name");
        expect(r).toHaveProperty("severity");
      });
    });
  });

  // ─── Passive Guard ─────────────────────────────────────────────
  describe("Passive Guard", () => {
    it("should filter connectors for strict_passive mode", async () => {
      const { filterConnectors } = await import("./lib/passive/passive-guard");
      const connectors: PassiveConnector[] = [
        makeMockConnector("crtsh", []),
        makeMockConnector("shodan", []),
        makeMockConnector("rdap", []),
        makeMockConnector("ripestat", []),
      ];
      const { allowed, blocked } = filterConnectors(connectors, "strict_passive");
      // crtsh and shodan are strict passive; rdap and ripestat are not
      expect(allowed.map(c => c.name)).toContain("crtsh");
      expect(allowed.map(c => c.name)).toContain("shodan");
      expect(blocked.map(b => b.name)).toContain("rdap");
      expect(blocked.map(b => b.name)).toContain("ripestat");
    });

    it("should allow all connectors in standard mode", async () => {
      const { filterConnectors } = await import("./lib/passive/passive-guard");
      const connectors: PassiveConnector[] = [
        makeMockConnector("crtsh", []),
        makeMockConnector("shodan", []),
        makeMockConnector("rdap", []),
        makeMockConnector("ripestat", []),
      ];
      const { allowed, blocked } = filterConnectors(connectors, "standard");
      expect(allowed.length).toBe(4);
      expect(blocked.length).toBe(0);
    });

    it("should provide scan mode descriptions", async () => {
      const { getScanModeDescription } = await import("./lib/passive/passive-guard");
      const desc = getScanModeDescription("strict_passive");
      expect(desc.label).toBe("Strict Passive");
      expect(desc.techniques.length).toBeGreaterThan(0);
      expect(desc.restrictions.length).toBeGreaterThan(0);
    });

    it("should provide default policy configs", async () => {
      const { getDefaultPolicy } = await import("./lib/passive/passive-guard");
      const strictPolicy = getDefaultPolicy("strict_passive");
      expect(strictPolicy.allowDnsResolution).toBe(false);
      expect(strictPolicy.allowWellKnownFetch).toBe(false);

      const standardPolicy = getDefaultPolicy("standard");
      expect(standardPolicy.allowDnsResolution).toBe(true);
      expect(standardPolicy.allowWellKnownFetch).toBe(true);
    });
  });

  // ─── Orchestrator ──────────────────────────────────────────────
  describe("Orchestrator", () => {
    it("should aggregate results from all connectors in active mode", async () => {
      const { runPassiveRecon } = await import("./lib/passive/index");
      const result = await runPassiveRecon("example.com", {
        scanMode: "active",
        apiKeys: { shodan: "test-key" },
      });

      expect(result).toHaveProperty("allObservations");
      expect(result).toHaveProperty("riskSignals");
      expect(result).toHaveProperty("connectorResults");
      expect(result).toHaveProperty("durationMs");
      expect(result).toHaveProperty("summary");
      expect(result.domain).toBe("example.com");
      expect(result.scanMode).toBe("active");

      // Should have observations from the mocked connectors
      expect(result.allObservations.length).toBeGreaterThan(0);

      // Connector results should track all connectors
      expect(Array.isArray(result.connectorResults)).toBe(true);
      expect(result.summary.connectorStats.length).toBeGreaterThan(0);
      result.summary.connectorStats.forEach((cs) => {
        expect(cs).toHaveProperty("name");
        expect(cs).toHaveProperty("observations");
        expect(cs).toHaveProperty("durationMs");
      });
    });

    it("should include timing data for each connector", async () => {
      const { runPassiveRecon } = await import("./lib/passive/index");
      const result = await runPassiveRecon("example.com", {
        scanMode: "standard",
        apiKeys: {},
      });

      result.summary.connectorStats.forEach((cs) => {
        expect(cs).toHaveProperty("durationMs");
        expect(typeof cs.durationMs).toBe("number");
      });

      expect(typeof result.durationMs).toBe("number");
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });

    it("should skip blocked connectors in strict_passive mode", async () => {
      const { runPassiveRecon } = await import("./lib/passive/index");
      const result = await runPassiveRecon("example.com", {
        scanMode: "strict_passive",
        apiKeys: {},
      });

      // rdap and ripestat should be skipped
      const skippedStats = result.summary.connectorStats.filter(cs => cs.skipped);
      expect(skippedStats.length).toBeGreaterThan(0);
      expect(skippedStats.map(s => s.name)).toContain("rdap");
      expect(skippedStats.map(s => s.name)).toContain("ripestat");
    });

    it("should return scan mode description", async () => {
      const { runPassiveRecon } = await import("./lib/passive/index");
      const result = await runPassiveRecon("example.com", {
        scanMode: "standard",
        apiKeys: {},
      });

      expect(result.scanModeDescription).toHaveProperty("label");
      expect(result.scanModeDescription).toHaveProperty("description");
      expect(result.scanModeDescription).toHaveProperty("techniques");
      expect(result.scanModeDescription).toHaveProperty("restrictions");
    });

    it("should deduplicate observations by assetId", async () => {
      const { runPassiveRecon } = await import("./lib/passive/index");
      const result = await runPassiveRecon("example.com", {
        scanMode: "active",
        apiKeys: {},
      });

      // Check no duplicate assetIds
      const assetIds = result.allObservations.map(o => o.assetId);
      const uniqueIds = new Set(assetIds);
      expect(assetIds.length).toBe(uniqueIds.size);
    });
  });
});
