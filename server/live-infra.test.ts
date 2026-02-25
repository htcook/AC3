import { describe, it, expect } from "vitest";
import * as dns from "./lib/dns-automation";
import * as scans from "./lib/opsec-scheduled-scans";
import * as doInfra from "./lib/digitalocean-infra";

// ─── DNS Automation Tests ─────────────────────────────────────────────────────

describe("DNS Automation Service", () => {
  describe("generateSpfRecord", () => {
    it("generates basic SPF with soft fail", () => {
      const spf = dns.generateSpfRecord({});
      expect(spf).toBe("v=spf1 ~all");
    });

    it("includes IPs and includes", () => {
      const spf = dns.generateSpfRecord({
        ips: ["1.2.3.4", "5.6.7.8"],
        includes: ["_spf.google.com"],
        policy: "-all",
      });
      expect(spf).toContain("ip4:1.2.3.4");
      expect(spf).toContain("ip4:5.6.7.8");
      expect(spf).toContain("include:_spf.google.com");
      expect(spf).toMatch(/-all$/);
    });

    it("respects neutral policy", () => {
      const spf = dns.generateSpfRecord({ policy: "?all" });
      expect(spf).toMatch(/\?all$/);
    });
  });

  describe("generateDmarcRecord", () => {
    it("generates default DMARC with none policy", () => {
      const dmarc = dns.generateDmarcRecord({});
      expect(dmarc).toContain("v=DMARC1");
      expect(dmarc).toContain("p=none");
    });

    it("includes rua and ruf", () => {
      const dmarc = dns.generateDmarcRecord({
        policy: "reject",
        rua: "admin@example.com",
        ruf: "forensic@example.com",
        pct: 100,
      });
      expect(dmarc).toContain("p=reject");
      expect(dmarc).toContain("rua=mailto:admin@example.com");
      expect(dmarc).toContain("ruf=mailto:forensic@example.com");
      expect(dmarc).toContain("pct=100");
    });
  });

  describe("generateDkimPlaceholder", () => {
    it("generates DKIM placeholder with selector", () => {
      const dkim = dns.generateDkimPlaceholder("mail");
      expect(dkim).toContain("v=DKIM1");
      expect(dkim).toContain("k=rsa");
      expect(dkim).toContain("selector: mail");
    });
  });
});

// ─── OpSec Scheduled Scans Tests ──────────────────────────────────────────────

describe("OpSec Scheduled Scans Service", () => {
  describe("getBuiltinChecks", () => {
    it("returns all 25 built-in checks", () => {
      const checks = scans.getBuiltinChecks();
      expect(checks.length).toBe(25);
    });

    it("each check has required fields", () => {
      const checks = scans.getBuiltinChecks();
      for (const c of checks) {
        expect(c.id).toBeTruthy();
        expect(c.name).toBeTruthy();
        expect(c.category).toBeTruthy();
        expect(c.severity).toBeTruthy();
        expect(c.command).toBeTruthy();
        expect(c.expectedPattern).toBeTruthy();
      }
    });
  });

  describe("getChecksByCategory", () => {
    it("filters SSH checks", () => {
      const ssh = scans.getChecksByCategory("ssh");
      expect(ssh.length).toBeGreaterThan(0);
      expect(ssh.every((c) => c.category === "ssh")).toBe(true);
    });

    it("returns empty for unknown category", () => {
      const unknown = scans.getChecksByCategory("nonexistent");
      expect(unknown).toHaveLength(0);
    });
  });

  describe("executeScan", () => {
    it("runs scan against a target and returns results", async () => {
      const target: scans.ScanTarget = {
        id: "test-1", name: "Test Server", host: "10.0.0.1", port: 22, tags: ["hardened"],
      };
      const result = await scans.executeScan(target);
      expect(result.targetId).toBe("test-1");
      expect(result.targetName).toBe("Test Server");
      expect(result.findings.length).toBe(25);
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
      expect(result.passCount + result.failCount + result.errorCount).toBe(25);
    });

    it("runs scan with specific check IDs", async () => {
      const target: scans.ScanTarget = {
        id: "test-2", name: "Partial", host: "10.0.0.2", port: 22, tags: [],
      };
      const result = await scans.executeScan(target, ["ssh-root-login", "fw-enabled"]);
      expect(result.findings.length).toBe(2);
    });
  });

  describe("scheduled scan management", () => {
    it("creates and lists scheduled scans", () => {
      const scan = scans.createScheduledScan({
        name: "Test Weekly",
        targets: [{ id: "t-1", name: "Server 1", host: "10.0.0.1", port: 22, tags: [] }],
        intervalHours: 168,
      });
      expect(scan.id).toBeTruthy();
      expect(scan.name).toBe("Test Weekly");
      expect(scan.enabled).toBe(true);

      const list = scans.listScheduledScans();
      expect(list.some((s) => s.id === scan.id)).toBe(true);
    });

    it("deletes a scheduled scan", () => {
      const scan = scans.createScheduledScan({
        name: "To Delete",
        targets: [{ id: "t-2", name: "Server 2", host: "10.0.0.2", port: 22, tags: [] }],
        intervalHours: 24,
      });
      const deleted = scans.deleteScheduledScan(scan.id);
      expect(deleted).toBe(true);
      expect(scans.listScheduledScans().some((s) => s.id === scan.id)).toBe(false);
    });

    it("toggles a scheduled scan", () => {
      const scan = scans.createScheduledScan({
        name: "Toggle Test",
        targets: [{ id: "t-3", name: "Server 3", host: "10.0.0.3", port: 22, tags: [] }],
        intervalHours: 12,
      });
      const toggled = scans.toggleScheduledScan(scan.id, false);
      expect(toggled?.enabled).toBe(false);
    });

    it("runs a scheduled scan and stores history", async () => {
      const scan = scans.createScheduledScan({
        name: "Run Test",
        targets: [{ id: "t-run", name: "Run Server", host: "10.0.0.4", port: 22, tags: ["production"] }],
        intervalHours: 24,
        notifyOnFail: false,
      });
      const results = await scans.runScheduledScan(scan.id);
      expect(results.length).toBe(1);
      expect(results[0].targetId).toBe("t-run");

      const history = scans.getScanHistory("t-run");
      expect(history.length).toBeGreaterThan(0);
    });
  });
});

// ─── DigitalOcean Infrastructure Tests ────────────────────────────────────────

describe("DigitalOcean Infrastructure Service", () => {
  describe("generateRedirectorUserData", () => {
    it("generates HTTP redirector script", () => {
      const script = doInfra.generateRedirectorUserData({
        type: "http",
        backendHost: "10.0.0.5",
        backendPort: 8443,
      });
      expect(script).toContain("#!/bin/bash");
      expect(script).toContain("10.0.0.5");
      expect(script).toContain("8443");
      expect(script).toContain("nginx");
    });

    it("generates SMTP redirector script", () => {
      const script = doInfra.generateRedirectorUserData({
        type: "smtp",
        backendHost: "10.0.0.6",
        backendPort: 25,
      });
      expect(script).toContain("#!/bin/bash");
      expect(script).toContain("postfix");
    });

    it("generates DNS redirector script", () => {
      const script = doInfra.generateRedirectorUserData({
        type: "dns",
        backendHost: "10.0.0.7",
        backendPort: 53,
      });
      expect(script).toContain("#!/bin/bash");
      expect(script).toContain("socat");
    });

    it("generates C2 redirector script with admin CIDR", () => {
      const script = doInfra.generateRedirectorUserData({
        type: "c2",
        backendHost: "10.0.0.8",
        backendPort: 443,
        adminCidr: "192.168.1.0/24",
      });
      expect(script).toContain("#!/bin/bash");
      expect(script).toContain("192.168.1.0/24");
    });
  });

  describe("generateTeamServerUserData", () => {
    it("generates team server setup script", () => {
      const script = doInfra.generateTeamServerUserData({});
      expect(script).toContain("#!/bin/bash");
      expect(script).toContain("ufw");
    });

    it("includes custom caldera port", () => {
      const script = doInfra.generateTeamServerUserData({ calderaPort: 9443 });
      expect(script).toContain("9443");
    });
  });
});
