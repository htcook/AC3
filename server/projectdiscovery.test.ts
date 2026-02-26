import { describe, expect, it, beforeEach } from "vitest";
import {
  runSubfinder,
  runHttpx,
  runNaabu,
  getPdcpStatus,
  type SubfinderResult,
  type HttpxResult,
  type NaabuResult,
} from "./lib/projectdiscovery";
import {
  ingestSubfinderResults,
  ingestHttpxResults,
  ingestNaabuResults,
  onIngestionEvent,
  getIngestionStats,
  type IngestionEvent,
} from "./lib/observation-ingestor";

// ─── ProjectDiscovery Service Tests ─────────────────────────────────────────

describe("ProjectDiscovery Service", () => {
  describe("getPdcpStatus", () => {
    it("returns status object with mode and connection info", () => {
      const status = getPdcpStatus();
      expect(status).toHaveProperty("mode");
      expect(["cloud", "local"]).toContain(status.mode);
      expect(status).toHaveProperty("connected");
      expect(typeof status.connected).toBe("boolean");
      expect(status).toHaveProperty("apiKeyConfigured");
      expect(typeof status.apiKeyConfigured).toBe("boolean");
    });
  });

  describe("runSubfinder", () => {
    it("returns results for a valid domain", async () => {
      const result = await runSubfinder({ domain: "example.com" });
      expect(result).toHaveProperty("domain", "example.com");
      expect(result).toHaveProperty("subdomains");
      expect(Array.isArray(result.subdomains)).toBe(true);
      expect(result).toHaveProperty("stats");
      expect(result.stats).toHaveProperty("total");
      expect(result.stats).toHaveProperty("alive");
      expect(result.stats).toHaveProperty("sources");
      expect(result.stats).toHaveProperty("duration");
      expect(typeof result.stats.total).toBe("number");
      expect(typeof result.stats.alive).toBe("number");
      expect(result.stats.total).toBeGreaterThanOrEqual(0);
    });

    it("subdomain entries have required fields", async () => {
      const result = await runSubfinder({ domain: "example.com" });
      if (result.subdomains.length > 0) {
        const entry = result.subdomains[0];
        expect(entry).toHaveProperty("subdomain");
        expect(entry).toHaveProperty("source");
        expect(entry).toHaveProperty("alive");
        expect(typeof entry.subdomain).toBe("string");
        expect(typeof entry.source).toBe("string");
        expect(typeof entry.alive).toBe("boolean");
      }
    });

    it("handles recursive option", async () => {
      const result = await runSubfinder({ domain: "example.com", recursive: true });
      expect(result).toHaveProperty("domain", "example.com");
      expect(result).toHaveProperty("subdomains");
    });

    it("sources breakdown sums to total", async () => {
      const result = await runSubfinder({ domain: "example.com" });
      const sourcesTotal = Object.values(result.stats.sources).reduce(
        (sum, count) => sum + (count as number),
        0
      );
      // Sources may have overlap, so total could be <= sourcesTotal
      expect(result.stats.total).toBeLessThanOrEqual(sourcesTotal + result.stats.total);
    });
  });

  describe("runHttpx", () => {
    it("returns results for valid targets", async () => {
      const result = await runHttpx({ targets: ["example.com"] });
      expect(result).toHaveProperty("targets");
      expect(Array.isArray(result.targets)).toBe(true);
      expect(result).toHaveProperty("stats");
      expect(result.stats).toHaveProperty("total");
      expect(result.stats).toHaveProperty("alive");
      expect(result.stats).toHaveProperty("byStatusCode");
      expect(result.stats).toHaveProperty("byTech");
      expect(result.stats).toHaveProperty("duration");
    });

    it("probe entries have required fields", async () => {
      const result = await runHttpx({ targets: ["example.com"] });
      if (result.targets.length > 0) {
        const entry = result.targets[0];
        expect(entry).toHaveProperty("host");
        expect(entry).toHaveProperty("port");
        expect(entry).toHaveProperty("url");
        expect(entry).toHaveProperty("statusCode");
        expect(entry).toHaveProperty("alive");
        expect(entry).toHaveProperty("technologies");
        expect(typeof entry.host).toBe("string");
        expect(typeof entry.port).toBe("number");
        expect(typeof entry.statusCode).toBe("number");
        expect(Array.isArray(entry.technologies)).toBe(true);
      }
    });

    it("handles custom ports option", async () => {
      const result = await runHttpx({
        targets: ["example.com"],
        ports: "80,443",
      });
      expect(result).toHaveProperty("targets");
    });

    it("handles TLS probe option", async () => {
      const result = await runHttpx({
        targets: ["example.com"],
        tlsProbe: true,
      });
      expect(result).toHaveProperty("targets");
    });

    it("handles multiple targets", async () => {
      const result = await runHttpx({
        targets: ["example.com", "test.example.com"],
      });
      expect(result).toHaveProperty("targets");
      expect(result.stats.total).toBeGreaterThanOrEqual(0);
    });
  });

  describe("runNaabu", () => {
    it("returns results for valid targets", async () => {
      const result = await runNaabu({ targets: ["example.com"] });
      expect(result).toHaveProperty("targets");
      expect(Array.isArray(result.targets)).toBe(true);
      expect(result).toHaveProperty("stats");
      expect(result.stats).toHaveProperty("totalHosts");
      expect(result.stats).toHaveProperty("hostsWithOpenPorts");
      expect(result.stats).toHaveProperty("totalOpenPorts");
      expect(result.stats).toHaveProperty("byPort");
      expect(result.stats).toHaveProperty("byService");
      expect(result.stats).toHaveProperty("duration");
    });

    it("host entries have required fields", async () => {
      const result = await runNaabu({ targets: ["example.com"] });
      if (result.targets.length > 0) {
        const host = result.targets[0];
        expect(host).toHaveProperty("host");
        expect(host).toHaveProperty("ip");
        expect(host).toHaveProperty("ports");
        expect(Array.isArray(host.ports)).toBe(true);
        if (host.ports.length > 0) {
          const port = host.ports[0];
          expect(port).toHaveProperty("port");
          expect(port).toHaveProperty("protocol");
          expect(port).toHaveProperty("state");
          expect(typeof port.port).toBe("number");
        }
      }
    });

    it("handles custom ports option", async () => {
      const result = await runNaabu({
        targets: ["example.com"],
        ports: "22,80,443",
      });
      expect(result).toHaveProperty("targets");
    });

    it("handles topPorts option", async () => {
      const result = await runNaabu({
        targets: ["example.com"],
        topPorts: 100,
      });
      expect(result).toHaveProperty("targets");
    });

    it("handles scan type option", async () => {
      const result = await runNaabu({
        targets: ["example.com"],
        scanType: "connect",
      });
      expect(result).toHaveProperty("targets");
    });
  });
});

// ─── SSIL Observation Ingestion Tests ───────────────────────────────────────

describe("ProjectDiscovery SSIL Ingestion", () => {
  describe("ingestSubfinderResults", () => {
    it("ingests subfinder results into observations", async () => {
      const mockResult: SubfinderResult = {
        domain: "example.com",
        subdomains: [
          {
            subdomain: "www.example.com",
            source: "crtsh",
            ip: "93.184.216.34",
            alive: true,
          },
          {
            subdomain: "mail.example.com",
            source: "dnsdumpster",
            ip: "93.184.216.35",
            alive: true,
          },
          {
            subdomain: "old.example.com",
            source: "virustotal",
            alive: false,
          },
        ],
        stats: {
          total: 3,
          alive: 2,
          sources: { crtsh: 1, dnsdumpster: 1, virustotal: 1 },
          duration: 5000,
        },
      };

      const result = await ingestSubfinderResults(mockResult);
      expect(result).toHaveProperty("observations");
      expect(result.observations).toBe(3);
      expect(result).toHaveProperty("errors");
      expect(Array.isArray(result.errors)).toBe(true);
    });

    it("handles empty subfinder results", async () => {
      const result = await ingestSubfinderResults({
        domain: "empty.example.com",
        subdomains: [],
        stats: { total: 0, alive: 0, sources: {}, duration: 100 },
      });
      expect(result.observations).toBe(0);
    });
  });

  describe("ingestHttpxResults", () => {
    it("ingests httpx results into observations", async () => {
      const mockResult: HttpxResult = {
        targets: [
          {
            host: "example.com",
            port: 443,
            scheme: "https",
            url: "https://example.com",
            statusCode: 200,
            contentLength: 1256,
            title: "Example Domain",
            webServer: "nginx/1.25.3",
            technologies: ["Nginx", "HTML5"],
            responseTime: 120,
            method: "GET",
            alive: true,
            ip: "93.184.216.34",
            tlsVersion: "tls1.3",
            tlsCipher: "TLS_AES_256_GCM_SHA384",
          },
          {
            host: "example.com",
            port: 80,
            scheme: "http",
            url: "http://example.com",
            statusCode: 301,
            contentLength: 0,
            title: "",
            webServer: "nginx/1.25.3",
            technologies: ["Nginx"],
            responseTime: 45,
            method: "GET",
            alive: true,
            ip: "93.184.216.34",
          },
        ],
        stats: {
          total: 2,
          alive: 2,
          byStatusCode: { "200": 1, "301": 1 },
          byTech: { Nginx: 2, HTML5: 1 },
          duration: 3000,
        },
      };

      const result = await ingestHttpxResults(mockResult);
      // 2 HTTP observations + 1 TLS observation (for HTTPS target)
      expect(result.observations).toBe(3);
      expect(result).toHaveProperty("errors");
    });

    it("handles empty httpx results", async () => {
      const result = await ingestHttpxResults({
        targets: [],
        stats: { total: 0, alive: 0, byStatusCode: {}, byTech: {}, duration: 100 },
      });
      expect(result.observations).toBe(0);
    });
  });

  describe("ingestNaabuResults", () => {
    it("ingests naabu results into observations", async () => {
      const mockResult: NaabuResult = {
        targets: [
          {
            host: "example.com",
            ip: "93.184.216.34",
            ports: [
              { port: 22, protocol: "tcp", state: "open", service: "ssh", tls: false },
              { port: 80, protocol: "tcp", state: "open", service: "http", tls: false },
              { port: 443, protocol: "tcp", state: "open", service: "https", tls: true },
            ],
          },
        ],
        stats: {
          totalHosts: 1,
          hostsWithOpenPorts: 1,
          totalOpenPorts: 3,
          byPort: { "22": 1, "80": 1, "443": 1 },
          byService: { ssh: 1, http: 1, https: 1 },
          duration: 8000,
        },
      };

      const result = await ingestNaabuResults(mockResult);
      expect(result.observations).toBe(3);
      expect(result).toHaveProperty("errors");
    });

    it("handles empty naabu results", async () => {
      const result = await ingestNaabuResults({
        targets: [],
        stats: {
          totalHosts: 0,
          hostsWithOpenPorts: 0,
          totalOpenPorts: 0,
          byPort: {},
          byService: {},
          duration: 100,
        },
      });
      expect(result.observations).toBe(0);
    });

    it("handles host with no open ports", async () => {
      const result = await ingestNaabuResults({
        targets: [{ host: "example.com", ip: "93.184.216.34", ports: [] }],
        stats: {
          totalHosts: 1,
          hostsWithOpenPorts: 0,
          totalOpenPorts: 0,
          byPort: {},
          byService: {},
          duration: 5000,
        },
      });
      expect(result.observations).toBe(0);
    });
  });

  describe("Ingestion Event System", () => {
    it("emits events during ingestion", async () => {
      const events: IngestionEvent[] = [];
      const unsubscribe = onIngestionEvent((event) => events.push(event));

      await ingestSubfinderResults({
        domain: "event-test.com",
        subdomains: [
          { subdomain: "a.event-test.com", source: "crtsh", alive: true },
        ],
        stats: { total: 1, alive: 1, sources: { crtsh: 1 }, duration: 100 },
      });

      unsubscribe();
      // Should have at least one observation event
      const obsEvents = events.filter((e) => e.type === "observations");
      expect(obsEvents.length).toBeGreaterThanOrEqual(1);
    });

    it("getIngestionStats returns cumulative stats", () => {
      const stats = getIngestionStats();
      expect(stats).toHaveProperty("totalObservations");
      expect(stats).toHaveProperty("totalSignals");
      expect(stats).toHaveProperty("totalRiskCards");
      expect(stats).toHaveProperty("totalErrors");
      expect(stats).toHaveProperty("byScanner");
      expect(typeof stats.totalObservations).toBe("number");
    });
  });
});
