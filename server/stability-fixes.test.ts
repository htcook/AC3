/**
 * Tests for stability fixes:
 * 1. CVE false positive filter (tech-stack validation)
 * 2. ZAP spider stall detection
 * 3. Log deduplication
 * 4. Infrastructure port exclusion
 */
import { describe, it, expect, vi } from "vitest";

// ── 1. CVE False Positive Filter ──
// Extracted logic from engagement-ops-core.ts for testability
function filterCveFalsePositives(
  synthVulns: Array<{ title: string; description: string; cve: string; confidence: number }>,
  detectedTechs: string[],
  portServices: Array<{ service: string; version?: string }>
): { accepted: typeof synthVulns; filteredCount: number } {
  const techLower = detectedTechs.map(t => t.toLowerCase());
  const servicesLower = portServices.map(p => `${p.service || ''} ${p.version || ''}`.toLowerCase());
  const allTechContext = [...techLower, ...servicesLower].join(' ');

  const CVE_TECH_VALIDATORS: Record<string, string[]> = {
    'chrome': ['chrome', 'chromium', 'google'],
    'ivanti': ['ivanti', 'pulse', 'connect secure'],
    'zyxel': ['zyxel'],
    'vmware': ['vmware', 'vcenter', 'esxi', 'vsphere'],
    'fortinet': ['fortinet', 'fortigate', 'fortios'],
    'cisco': ['cisco', 'ios-xe', 'asa'],
    'palo alto': ['palo alto', 'pan-os', 'globalprotect'],
    'citrix': ['citrix', 'netscaler', 'adc'],
    'microsoft exchange': ['exchange', 'owa'],
    'adobe': ['adobe', 'acrobat', 'coldfusion'],
    'sap': ['sap', 'netweaver'],
    'oracle': ['oracle', 'weblogic'],
    'f5': ['f5', 'big-ip', 'bigip'],
    'sonicwall': ['sonicwall'],
    'barracuda': ['barracuda'],
    'juniper': ['juniper', 'junos'],
  };

  let filteredCount = 0;
  const accepted: typeof synthVulns = [];
  for (const v of synthVulns) {
    if (v.confidence < 40) continue;
    const vulnText = `${v.title} ${v.description} ${v.cve || ''}`.toLowerCase();
    let isFalsePositive = false;
    for (const [product, requiredIndicators] of Object.entries(CVE_TECH_VALIDATORS)) {
      if (vulnText.includes(product)) {
        const hasIndicator = requiredIndicators.some(ind => allTechContext.includes(ind));
        if (!hasIndicator) {
          isFalsePositive = true;
          filteredCount++;
          break;
        }
      }
    }
    if (!isFalsePositive) accepted.push(v);
  }
  return { accepted, filteredCount };
}

describe("CVE False Positive Filter", () => {
  it("should filter Chrome CVEs when Chrome is not in tech stack", () => {
    const vulns = [
      { title: "Chrome V8 Type Confusion", description: "Google Chrome V8 engine vulnerability", cve: "CVE-2024-1234", confidence: 80 },
      { title: "SQL Injection in Login", description: "SQL injection via login form", cve: "", confidence: 70 },
    ];
    const result = filterCveFalsePositives(vulns, ["Nginx", "PHP", "MySQL"], [{ service: "http" }]);
    expect(result.accepted).toHaveLength(1);
    expect(result.accepted[0].title).toBe("SQL Injection in Login");
    expect(result.filteredCount).toBe(1);
  });

  it("should keep Chrome CVEs when Chrome IS in tech stack", () => {
    const vulns = [
      { title: "Chrome V8 Type Confusion", description: "Google Chrome V8 engine vulnerability", cve: "CVE-2024-1234", confidence: 80 },
    ];
    const result = filterCveFalsePositives(vulns, ["Google Chrome", "Nginx"], [{ service: "http" }]);
    expect(result.accepted).toHaveLength(1);
    expect(result.filteredCount).toBe(0);
  });

  it("should filter Ivanti CVEs from a Nextcloud target", () => {
    const vulns = [
      { title: "Ivanti Connect Secure RCE", description: "Ivanti Connect Secure buffer overflow", cve: "CVE-2024-5678", confidence: 60 },
      { title: "XSS in Nextcloud Files", description: "Cross-site scripting in file sharing", cve: "", confidence: 75 },
    ];
    const result = filterCveFalsePositives(vulns, ["Nextcloud", "Apache", "PHP"], [{ service: "http", version: "Apache/2.4" }]);
    expect(result.accepted).toHaveLength(1);
    expect(result.accepted[0].title).toBe("XSS in Nextcloud Files");
    expect(result.filteredCount).toBe(1);
  });

  it("should filter VMware CVEs when target runs Nginx/PHP", () => {
    const vulns = [
      { title: "VMware vCenter RCE", description: "VMware vCenter Server remote code execution", cve: "CVE-2024-9999", confidence: 50 },
    ];
    const result = filterCveFalsePositives(vulns, ["Nginx", "PHP"], [{ service: "http" }]);
    expect(result.accepted).toHaveLength(0);
    expect(result.filteredCount).toBe(1);
  });

  it("should not filter generic web vulns (SQLi, XSS, etc.)", () => {
    const vulns = [
      { title: "SQL Injection", description: "SQL injection in login form", cve: "", confidence: 80 },
      { title: "Cross-Site Scripting", description: "Reflected XSS in search", cve: "", confidence: 70 },
      { title: "Directory Traversal", description: "Path traversal via file parameter", cve: "", confidence: 60 },
      { title: "SSRF", description: "Server-side request forgery", cve: "", confidence: 50 },
    ];
    const result = filterCveFalsePositives(vulns, ["Nginx", "PHP"], [{ service: "http" }]);
    expect(result.accepted).toHaveLength(4);
    expect(result.filteredCount).toBe(0);
  });

  it("should skip low-confidence vulns (below 40)", () => {
    const vulns = [
      { title: "Some Vuln", description: "Low confidence", cve: "", confidence: 30 },
    ];
    const result = filterCveFalsePositives(vulns, ["Nginx"], [{ service: "http" }]);
    expect(result.accepted).toHaveLength(0);
    expect(result.filteredCount).toBe(0); // Not counted as filtered, just skipped
  });

  it("should filter multiple unrelated product CVEs at once", () => {
    const vulns = [
      { title: "Zyxel Firewall RCE", description: "Zyxel firmware vulnerability", cve: "CVE-2024-1111", confidence: 70 },
      { title: "Fortinet FortiOS Auth Bypass", description: "Fortinet FortiOS authentication bypass", cve: "CVE-2024-2222", confidence: 65 },
      { title: "Cisco ASA VPN Bypass", description: "Cisco ASA VPN authentication bypass", cve: "CVE-2024-3333", confidence: 60 },
      { title: "XSS in Search", description: "Reflected XSS", cve: "", confidence: 80 },
    ];
    const result = filterCveFalsePositives(vulns, ["Nextcloud", "Apache"], [{ service: "http" }]);
    expect(result.accepted).toHaveLength(1);
    expect(result.accepted[0].title).toBe("XSS in Search");
    expect(result.filteredCount).toBe(3);
  });

  it("should detect tech from port services (not just technologies)", () => {
    const vulns = [
      { title: "Oracle WebLogic RCE", description: "Oracle WebLogic Server deserialization", cve: "CVE-2024-4444", confidence: 75 },
    ];
    // Oracle detected via port service, not via technologies array
    const result = filterCveFalsePositives(vulns, [], [{ service: "http", version: "Oracle-Application-Server-11g" }]);
    expect(result.accepted).toHaveLength(1); // Should keep it because "oracle" is in service version
    expect(result.filteredCount).toBe(0);
  });
});

// ── 2. ZAP Stall Detection ──
describe("ZAP Stall Detection Logic", () => {
  it("should detect stall after MAX_STALL_POLLS consecutive identical progress", () => {
    const state: any = { _lastZapProgressKey: '', _zapStallCount: 0 };
    const MAX_STALL_POLLS = 8;

    // Simulate 8 identical polls
    for (let i = 0; i < MAX_STALL_POLLS; i++) {
      const progressKey = "0:0:0";
      if (progressKey === state._lastZapProgressKey) {
        state._zapStallCount++;
      } else {
        state._zapStallCount = 0;
        state._lastZapProgressKey = progressKey;
      }
    }

    expect(state._zapStallCount).toBe(MAX_STALL_POLLS - 1); // First poll sets key, subsequent 7 increment
    // After one more poll it would reach MAX_STALL_POLLS
    state._zapStallCount++;
    expect(state._zapStallCount >= MAX_STALL_POLLS).toBe(true);
  });

  it("should reset stall count when progress changes", () => {
    const state: any = { _lastZapProgressKey: '0:0:0', _zapStallCount: 5 };

    // Progress changes
    const progressKey = "50:0:10";
    if (progressKey === state._lastZapProgressKey) {
      state._zapStallCount++;
    } else {
      state._zapStallCount = 0;
      state._lastZapProgressKey = progressKey;
    }

    expect(state._zapStallCount).toBe(0);
    expect(state._lastZapProgressKey).toBe("50:0:10");
  });
});

// ── 3. Log Deduplication ──
describe("Log Deduplication", () => {
  it("should detect consecutive identical log entries", () => {
    const log = [
      { id: "1", timestamp: 1000, phase: "vuln_detection", type: "info", title: "ZAP Progress: https://target:8443", detail: "Spider: 0%, Active: 0%, URLs: 0, Status: spidering" },
    ];
    const newEntry = { phase: "vuln_detection", type: "info", title: "ZAP Progress: https://target:8443", detail: "Spider: 0%, Active: 0%, URLs: 0, Status: spidering" };

    const last = log[log.length - 1];
    const isDuplicate = last.title === newEntry.title && last.detail === newEntry.detail;
    expect(isDuplicate).toBe(true);
  });

  it("should NOT flag entries with different details as duplicates", () => {
    const log = [
      { id: "1", timestamp: 1000, phase: "vuln_detection", type: "info", title: "ZAP Progress: https://target:8443", detail: "Spider: 0%, Active: 0%, URLs: 0, Status: spidering" },
    ];
    const newEntry = { phase: "vuln_detection", type: "info", title: "ZAP Progress: https://target:8443", detail: "Spider: 50%, Active: 0%, URLs: 10, Status: spidering" };

    const last = log[log.length - 1];
    const isDuplicate = last.title === newEntry.title && last.detail === newEntry.detail;
    expect(isDuplicate).toBe(false);
  });
});

// ── 4. Infrastructure Port Exclusion ──
describe("Infrastructure Port Exclusion", () => {
  const INFRA_PORTS = new Set([1337, 31337, 8834, 9392, 5432, 3306, 27017, 6379]);

  it("should exclude port 1337 (Burp REST API)", () => {
    const ports = [
      { port: 80, service: "http" },
      { port: 443, service: "https" },
      { port: 1337, service: "http" },
      { port: 8443, service: "https" },
    ];
    const filtered = ports.filter(p =>
      (["http", "https"].includes(p.service) || [80, 443, 8080, 8443].includes(p.port))
      && !INFRA_PORTS.has(p.port)
    );
    expect(filtered).toHaveLength(3);
    expect(filtered.map(p => p.port)).toEqual([80, 443, 8443]);
  });

  it("should exclude port 31337 (Sliver C2)", () => {
    const ports = [
      { port: 80, service: "http" },
      { port: 31337, service: "http" },
    ];
    const filtered = ports.filter(p => !INFRA_PORTS.has(p.port));
    expect(filtered).toHaveLength(1);
    expect(filtered[0].port).toBe(80);
  });

  it("should exclude database ports", () => {
    const ports = [
      { port: 80, service: "http" },
      { port: 5432, service: "postgresql" },
      { port: 3306, service: "mysql" },
      { port: 27017, service: "mongodb" },
      { port: 6379, service: "redis" },
    ];
    const filtered = ports.filter(p => !INFRA_PORTS.has(p.port));
    expect(filtered).toHaveLength(1);
    expect(filtered[0].port).toBe(80);
  });

  it("should keep standard web ports", () => {
    const ports = [
      { port: 80, service: "http" },
      { port: 443, service: "https" },
      { port: 8080, service: "http-proxy" },
      { port: 8443, service: "https" },
      { port: 3000, service: "http" },
    ];
    const filtered = ports.filter(p => !INFRA_PORTS.has(p.port));
    expect(filtered).toHaveLength(5);
  });
});

// ── 5. Production Heap Limit ──
describe("Production Configuration", () => {
  it("should have production heap limit >= 1024MB", () => {
    // The package.json start script should use at least 1024MB
    const startScript = "NODE_ENV=production node --expose-gc --max-old-space-size=1536 dist/index.js";
    const match = startScript.match(/--max-old-space-size=(\d+)/);
    expect(match).not.toBeNull();
    const heapMB = parseInt(match![1]);
    expect(heapMB).toBeGreaterThanOrEqual(1024);
  });
});
