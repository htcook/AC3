// @ts-nocheck
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the ENV module before importing collectors
vi.mock("./_core/env", () => ({
  ENV: {
    DIGITALOCEAN_ACCESS_TOKEN: "test-do-token",
    calderaBaseUrl: "http://localhost:8888",
    calderaApiKey: "test-caldera-key",
    SHODAN_API_KEY: "test-shodan-key",
    SECURITYTRAILS_API_KEY: "test-st-key",
    SCAN_SERVER_HOST: "10.0.0.1",
  },
}));

// Mock global fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe("KSI Live Collectors Module", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
  });

  describe("collectCloudMisconfigs", () => {
    it("should detect droplets without monitoring", async () => {
      const { collectCloudMisconfigs } = await import("./lib/ksi-live-collectors");

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            droplets: [
              { id: 1, name: "test-droplet", features: [], backup_ids: [], networks: { v4: [{ type: "public", ip_address: "1.2.3.4" }] } },
            ],
          }),
        })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ firewalls: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ load_balancers: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ databases: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ domains: [] }) });

      const results = await collectCloudMisconfigs();
      expect(results.length).toBeGreaterThanOrEqual(1);
      const monitoringIssue = results.find(r => r.misconfigType === "monitoring_disabled");
      expect(monitoringIssue).toBeDefined();
      expect(monitoringIssue?.severity).toBe("medium");
      expect(monitoringIssue?.resourceName).toBe("test-droplet");
    });

    it("should detect overly permissive firewall rules", async () => {
      const { collectCloudMisconfigs } = await import("./lib/ksi-live-collectors");

      mockFetch
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ droplets: [] }) })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            firewalls: [{
              id: "fw-1",
              name: "test-fw",
              inbound_rules: [{
                protocol: "tcp",
                ports: "22",
                sources: { addresses: ["0.0.0.0/0"] },
              }],
              outbound_rules: [],
              droplet_ids: [1],
            }],
          }),
        })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ load_balancers: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ databases: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ domains: [] }) });

      const results = await collectCloudMisconfigs();
      const permissiveRule = results.find(r => r.misconfigType === "overly_permissive_inbound");
      expect(permissiveRule).toBeDefined();
      expect(permissiveRule?.severity).toBe("critical");
    });

    it("should detect droplets without backups", async () => {
      const { collectCloudMisconfigs } = await import("./lib/ksi-live-collectors");

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            droplets: [
              { id: 2, name: "no-backup-droplet", features: ["monitoring"], backup_ids: [], networks: {} },
            ],
          }),
        })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ firewalls: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ load_balancers: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ databases: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ domains: [] }) });

      const results = await collectCloudMisconfigs();
      const backupIssue = results.find(r => r.misconfigType === "backups_disabled");
      expect(backupIssue).toBeDefined();
      expect(backupIssue?.severity).toBe("high");
    });
  });

  describe("collectNgfwValidation", () => {
    it("should generate test results from firewall rules", async () => {
      const { collectNgfwValidation } = await import("./lib/ksi-live-collectors");

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            firewalls: [{
              id: "fw-1",
              name: "test-fw",
              inbound_rules: [{
                protocol: "tcp",
                ports: "22",
                sources: { addresses: ["0.0.0.0/0"] },
              }],
              outbound_rules: [],
              droplet_ids: [1],
            }],
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({
            droplets: [{ id: 1, networks: { v4: [{ type: "public", ip_address: "1.2.3.4" }] } }],
          }),
        });

      const results = await collectNgfwValidation();
      expect(results.length).toBeGreaterThanOrEqual(1);
      const sshTest = results.find(r => r.targetPort === 22);
      expect(sshTest).toBeDefined();
      expect(sshTest?.firewallVendor).toBe("DigitalOcean Cloud Firewall");
    });
  });

  describe("collectAdAttackSims", () => {
    it("should extract AD-related abilities from Caldera", async () => {
      const { collectAdAttackSims } = await import("./lib/ksi-live-collectors");

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve([
            {
              ability_id: "abc-123",
              name: "Kerberoast",
              technique_id: "T1558.003",
              technique_name: "Kerberoasting",
              tactic: "credential-access",
              description: "Kerberoast attack simulation",
              executors: [{ platform: "windows" }],
            },
            {
              ability_id: "def-456",
              name: "List Files",
              technique_id: "T1083",
              technique_name: "File and Directory Discovery",
              tactic: "discovery",
              executors: [{ platform: "linux" }],
            },
          ]),
        })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve([]) });

      const results = await collectAdAttackSims();
      expect(results.length).toBe(1); // Only T1558.003 is AD-related
      expect(results[0].attackType).toBe("kerberoasting");
      expect(results[0].severity).toBe("high");
    });

    it("should handle empty Caldera response", async () => {
      const { collectAdAttackSims } = await import("./lib/ksi-live-collectors");

      mockFetch
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve([]) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve([]) });

      const results = await collectAdAttackSims();
      expect(results).toEqual([]);
    });
  });

  describe("collectEdrValidation", () => {
    it("should analyze operation chains for detection coverage", async () => {
      const { collectEdrValidation } = await import("./lib/ksi-live-collectors");

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([
          {
            id: "op-1",
            name: "Test Op",
            chain: [
              {
                id: "link-1",
                ability: { technique_id: "T1059.001", name: "PowerShell", tactic: "execution" },
                status: 0,
                output: "some output",
                host: "target-1",
                paw: "paw-1",
                finish: "2025-01-01T00:01:00Z",
                decide: "2025-01-01T00:00:00Z",
              },
              {
                id: "link-2",
                ability: { technique_id: "T1003.001", name: "LSASS Dump", tactic: "credential-access" },
                status: -2,
                host: "target-1",
                paw: "paw-1",
              },
            ],
          },
        ]),
      });

      const results = await collectEdrValidation();
      expect(results.length).toBe(2);
      const missed = results.find(r => r.detectionResult === "missed");
      expect(missed).toBeDefined();
      const blocked = results.find(r => r.detectionResult === "blocked");
      expect(blocked).toBeDefined();
    });
  });

  describe("collectAtomicRedTeam", () => {
    it("should extract atomic test executions from Caldera operations", async () => {
      const { collectAtomicRedTeam } = await import("./lib/ksi-live-collectors");

      // abilities
      mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve([]) });
      // agents
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([
          { paw: "paw-1", host: "agent-host", platform: "linux", executors: ["sh"] },
        ]),
      });
      // operations
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve([
          {
            id: "op-1",
            name: "Atomic Test",
            chain: [
              {
                ability: { technique_id: "T1059.004", name: "Unix Shell" },
                status: 0,
                paw: "paw-1",
                host: "agent-host",
                command: "whoami",
                finish: "2025-01-01T00:01:00Z",
                decide: "2025-01-01T00:00:00Z",
              },
            ],
          },
        ]),
      });

      const results = await collectAtomicRedTeam();
      expect(results.length).toBe(1);
      expect(results[0].testName).toBe("Unix Shell");
      expect(results[0].status).toBe("success");
      expect(results[0].targetHost).toBe("agent-host");
    });
  });

  describe("collectSiemConnectors", () => {
    it("should return diagnostic result when no SIEM is reachable", async () => {
      const { collectSiemConnectors } = await import("./lib/ksi-live-collectors");

      // Wazuh auth fails
      mockFetch.mockRejectedValueOnce(new Error("Connection refused"));
      // Elastic fails
      mockFetch.mockRejectedValueOnce(new Error("Connection refused"));
      mockFetch.mockRejectedValueOnce(new Error("Connection refused"));

      const results = await collectSiemConnectors();
      expect(results.length).toBeGreaterThanOrEqual(1);
      // Should have at least one result (either error or diagnostic)
      const hasResult = results.some(r => r.connected === false);
      expect(hasResult).toBe(true);
    });
  });

  describe("collectThreatIntel", () => {
    it("should collect from abuse.ch URLhaus", async () => {
      const { collectThreatIntel } = await import("./lib/ksi-live-collectors");

      // URLhaus
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          urls: [
            { url: "http://evil.com/malware.exe", threat: "malware_download", tags: ["elf", "mirai"], date_added: "2025-01-01", url_status: "online", country: "US" },
          ],
        }),
      });
      // ThreatFox
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: [] }),
      });
      // Shodan host 1
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          ports: [22, 80, 443],
          hostnames: ["test.example.com"],
          vulns: [],
          data: [{ port: 22, transport: "tcp", product: "OpenSSH" }],
          last_update: "2025-01-01",
        }),
      });
      // Shodan host 2
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          ports: [80],
          hostnames: [],
          vulns: ["CVE-2024-1234"],
          data: [],
          last_update: "2025-01-01",
        }),
      });
      // Shodan exploit count
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ total: 50000 }),
      });
      // SecurityTrails domain
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          alexa_rank: 1000,
          current_dns: { a: { values: [{ ip: "1.2.3.4" }] } },
        }),
      });
      // SecurityTrails subdomains
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ subdomains: ["www", "api", "mail"] }),
      });

      const results = await collectThreatIntel();
      expect(results.length).toBeGreaterThanOrEqual(1);

      const urlhaus = results.find(r => r.source === "abuse.ch URLhaus");
      expect(urlhaus).toBeDefined();
      expect(urlhaus?.category).toBe("malware_url");
      expect(urlhaus?.severity).toBe("high");
    });

    it("should handle API failures gracefully", async () => {
      const { collectThreatIntel } = await import("./lib/ksi-live-collectors");

      // All APIs fail
      mockFetch.mockRejectedValue(new Error("Network error"));

      const results = await collectThreatIntel();
      // Should return empty array, not throw
      expect(Array.isArray(results)).toBe(true);
    });
  });

  describe("Integration: All collectors return expected shapes", () => {
    it("cloud misconfigs returns array of CloudMisconfigResult", async () => {
      const { collectCloudMisconfigs } = await import("./lib/ksi-live-collectors");
      mockFetch
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ droplets: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ firewalls: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ load_balancers: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ databases: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ domains: [] }) });

      const results = await collectCloudMisconfigs();
      expect(Array.isArray(results)).toBe(true);
    });

    it("NGFW validation returns array of NgfwTestResult", async () => {
      const { collectNgfwValidation } = await import("./lib/ksi-live-collectors");
      mockFetch
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ firewalls: [] }) })
        .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ droplets: [] }) });

      const results = await collectNgfwValidation();
      expect(Array.isArray(results)).toBe(true);
    });

    it("threat intel returns array even with no API keys", async () => {
      // Re-mock ENV with no keys
      vi.doMock("./_core/env", () => ({
        ENV: {
          DIGITALOCEAN_ACCESS_TOKEN: "",
          calderaBaseUrl: "",
          calderaApiKey: "",
          SHODAN_API_KEY: "",
          SECURITYTRAILS_API_KEY: "",
          SCAN_SERVER_HOST: "",
        },
      }));

      // URLhaus (doesn't need API key)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ urls: [] }),
      });
      // ThreatFox
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: [] }),
      });

      const { collectThreatIntel } = await import("./lib/ksi-live-collectors");
      const results = await collectThreatIntel();
      expect(Array.isArray(results)).toBe(true);
    });
  });
});
