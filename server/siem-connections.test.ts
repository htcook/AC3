import { describe, it, expect } from "vitest";
import {
  exportFindings,
  pushAlertsToSiem,
  type EngagementFinding,
  type SiemPushConfig,
  type ExportedAlert,
} from "./lib/soc-integration-hub";

/* ─── Test data ─── */
const sampleFindings: EngagementFinding[] = [
  {
    id: "f1",
    engagementId: 1,
    title: "SQL Injection",
    description: "SQL injection in login form",
    severity: "critical",
    cvss: 9.8,
    targetHost: "10.0.1.5",
    targetPort: 443,
    toolUsed: "sqlmap",
    cveIds: ["CVE-2024-1234"],
    mitreTechniques: ["T1190"],
    timestamp: Date.now() - 86400000,
  },
  {
    id: "f2",
    engagementId: 1,
    title: "Exposed Admin Panel",
    description: "Admin panel accessible without auth",
    severity: "high",
    cvss: 7.5,
    targetHost: "10.0.1.5",
    targetPort: 8080,
    toolUsed: "nuclei",
    mitreTechniques: ["T1078"],
    timestamp: Date.now() - 43200000,
  },
];

describe("SIEM Push Integration", () => {
  describe("pushAlertsToSiem — Splunk HEC", () => {
    it("should attempt to push alerts to Splunk HEC endpoint and handle connection errors gracefully", async () => {
      const exported = exportFindings(sampleFindings, "json");
      const config: SiemPushConfig = {
        target: "splunk_hec",
        endpoint: "https://splunk-nonexistent.example.com:8088/services/collector",
        authToken: "test-hec-token-12345",
        index: "main",
      };
      const result = await pushAlertsToSiem(exported as ExportedAlert[], config);
      // Should complete without throwing
      expect(result).toBeDefined();
      expect(typeof result.success).toBe("boolean");
      expect(typeof result.alertsSent).toBe("number");
      expect(typeof result.alertsFailed).toBe("number");
      expect(typeof result.durationMs).toBe("number");
      expect(Array.isArray(result.errors)).toBe(true);
      // Since the endpoint doesn't exist, all should fail
      expect(result.alertsFailed).toBeGreaterThan(0);
      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe("pushAlertsToSiem — Elastic", () => {
    it("should attempt bulk push to Elasticsearch and handle connection errors", async () => {
      const exported = exportFindings(sampleFindings, "json");
      const config: SiemPushConfig = {
        target: "elastic",
        endpoint: "https://elastic-nonexistent.example.com:9200",
        authToken: "test-api-key-12345",
        index: "ace-c3-findings",
      };
      const result = await pushAlertsToSiem(exported as ExportedAlert[], config);
      expect(result).toBeDefined();
      expect(result.success).toBe(false);
      expect(result.alertsFailed).toBeGreaterThan(0);
      expect(result.errors.some((e: string) => e.includes("Elastic"))).toBe(true);
    });
  });

  describe("pushAlertsToSiem — Sentinel", () => {
    it("should attempt push to Azure Sentinel and handle connection errors", async () => {
      const exported = exportFindings(sampleFindings, "cef");
      const config: SiemPushConfig = {
        target: "sentinel",
        endpoint: "https://sentinel-nonexistent.example.com/api/logs",
        authToken: "test-shared-key",
      };
      const result = await pushAlertsToSiem(exported as ExportedAlert[], config);
      expect(result).toBeDefined();
      expect(result.success).toBe(false);
      expect(result.alertsFailed).toBeGreaterThan(0);
    });
  });

  describe("pushAlertsToSiem — QRadar", () => {
    it("should attempt push to QRadar and handle connection errors", async () => {
      const exported = exportFindings(sampleFindings, "leef");
      const config: SiemPushConfig = {
        target: "qradar",
        endpoint: "https://qradar-nonexistent.example.com",
        authToken: "test-sec-token",
      };
      const result = await pushAlertsToSiem(exported as ExportedAlert[], config);
      expect(result).toBeDefined();
      expect(result.success).toBe(false);
      expect(result.alertsFailed).toBeGreaterThan(0);
    });
  });

  describe("pushAlertsToSiem — Wazuh", () => {
    it("should attempt push to Wazuh and handle connection errors", async () => {
      const exported = exportFindings(sampleFindings, "json");
      const config: SiemPushConfig = {
        target: "wazuh",
        endpoint: "https://wazuh-nonexistent.example.com:55000",
        authToken: "test-jwt-token",
      };
      const result = await pushAlertsToSiem(exported as ExportedAlert[], config);
      expect(result).toBeDefined();
      expect(result.success).toBe(false);
      expect(result.alertsFailed).toBeGreaterThan(0);
      expect(result.errors.some((e: string) => e.includes("Wazuh"))).toBe(true);
    });

    it("should attempt JWT auth when no token is provided", async () => {
      const exported = exportFindings(sampleFindings, "json");
      const config: SiemPushConfig = {
        target: "wazuh",
        endpoint: "https://wazuh-nonexistent.example.com:55000",
        // No authToken — should attempt /security/user/authenticate
      };
      const result = await pushAlertsToSiem(exported as ExportedAlert[], config);
      expect(result).toBeDefined();
      expect(result.success).toBe(false);
      // Should have auth errors and push errors
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe("pushAlertsToSiem — Syslog", () => {
    it("should handle syslog push (simulated) successfully", async () => {
      const exported = exportFindings(sampleFindings, "syslog");
      const config: SiemPushConfig = {
        target: "syslog",
        endpoint: "syslog://localhost:514",
      };
      const result = await pushAlertsToSiem(exported as ExportedAlert[], config);
      expect(result).toBeDefined();
      // Syslog is simulated, should succeed
      expect(result.success).toBe(true);
      expect(result.alertsSent).toBeGreaterThan(0);
      expect(result.alertsFailed).toBe(0);
    });
  });

  describe("Export format compatibility", () => {
    it("should export in all 5 formats and produce valid ExportedAlert arrays", () => {
      const formats = ["cef", "leef", "json", "syslog", "csv"] as const;
      for (const fmt of formats) {
        const exported = exportFindings(sampleFindings, fmt);
        expect(Array.isArray(exported)).toBe(true);
        expect(exported.length).toBeGreaterThan(0);
        for (const alert of exported) {
          expect(typeof alert.raw).toBe("string");
          expect(alert.raw.length).toBeGreaterThan(0);
          expect(alert.format).toBe(fmt);
          expect(typeof alert.findingId).toBe("string");
          expect(typeof alert.timestamp).toBe("number");
        }
      }
    });

    it("should produce valid JSON when exporting as JSON format", () => {
      const exported = exportFindings(sampleFindings, "json");
      for (const alert of exported) {
        expect(() => JSON.parse(alert.raw)).not.toThrow();
        const parsed = JSON.parse(alert.raw);
        // JSON export wraps findings in a structured envelope
        expect(typeof parsed).toBe("object");
        expect(Object.keys(parsed).length).toBeGreaterThan(0);
      }
    });

    it("should produce valid CEF format with pipe separators", () => {
      const exported = exportFindings(sampleFindings, "cef");
      for (const alert of exported) {
        expect(alert.raw).toContain("CEF:");
        expect(alert.raw.split("|").length).toBeGreaterThanOrEqual(7);
      }
    });

    it("should produce valid CSV with header row", () => {
      const exported = exportFindings(sampleFindings, "csv");
      // First entry should be header
      expect(exported[0].findingId).toBe("header");
      expect(exported[0].raw).toContain(",");
      // Data rows
      expect(exported.length).toBe(sampleFindings.length + 1);
    });
  });

  describe("Push result structure", () => {
    it("should always return a complete SiemPushResult with all required fields", async () => {
      const exported = exportFindings(sampleFindings, "json");
      const config: SiemPushConfig = {
        target: "splunk_hec",
        endpoint: "https://nonexistent.example.com:8088/services/collector",
        authToken: "test-token",
      };
      const result = await pushAlertsToSiem(exported as ExportedAlert[], config);
      expect(result).toHaveProperty("success");
      expect(result).toHaveProperty("alertsSent");
      expect(result).toHaveProperty("alertsFailed");
      expect(result).toHaveProperty("errors");
      expect(result).toHaveProperty("durationMs");
      expect(result.alertsSent + result.alertsFailed).toBeLessThanOrEqual(exported.length);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });
  });
});
