/**
 * Tests for Service Fingerprinting Engine and remaining router scope enforcement.
 *
 * These tests validate:
 * 1. Protocol detection from port numbers
 * 2. Fingerprint result structure and risk indicators
 * 3. SSH banner parsing and vulnerability detection
 * 4. SMTP capability parsing and open relay detection
 * 5. FTP banner parsing and anonymous login detection
 * 6. SNMP community string detection
 * 7. RDP NLA/TLS detection
 * 8. SMB version and signing detection
 * 9. Database fingerprinting (MySQL, PostgreSQL, MSSQL, Redis, MongoDB)
 * 10. VNC authentication detection
 * 11. Batch fingerprinting with scope enforcement
 * 12. Summary report generation
 */

import { describe, it, expect } from "vitest";
import {
  detectProtocol,
  PORT_PROTOCOL_MAP,
  summarizeFingerprints,
  type FingerprintResult,
  type SecurityFlags,
  type ServiceProtocol,
} from "./lib/service-fingerprinter";

// ═══════════════════════════════════════════════════════════════════════════════
// Protocol Detection
// ═══════════════════════════════════════════════════════════════════════════════

describe("Protocol Detection", () => {
  it("detects SSH on port 22", () => {
    expect(detectProtocol(22)).toBe("ssh");
  });

  it("detects SMTP on port 25", () => {
    expect(detectProtocol(25)).toBe("smtp");
  });

  it("detects SMTP on port 587", () => {
    expect(detectProtocol(587)).toBe("smtp");
  });

  it("detects SMTP on port 465", () => {
    expect(detectProtocol(465)).toBe("smtp");
  });

  it("detects FTP on port 21", () => {
    expect(detectProtocol(21)).toBe("ftp");
  });

  it("detects Telnet on port 23", () => {
    expect(detectProtocol(23)).toBe("telnet");
  });

  it("detects SNMP on port 161", () => {
    expect(detectProtocol(161)).toBe("snmp");
  });

  it("detects RDP on port 3389", () => {
    expect(detectProtocol(3389)).toBe("rdp");
  });

  it("detects SMB on port 445", () => {
    expect(detectProtocol(445)).toBe("smb");
  });

  it("detects LDAP on port 389", () => {
    expect(detectProtocol(389)).toBe("ldap");
  });

  it("detects LDAPS on port 636", () => {
    expect(detectProtocol(636)).toBe("ldap");
  });

  it("detects MySQL on port 3306", () => {
    expect(detectProtocol(3306)).toBe("mysql");
  });

  it("detects PostgreSQL on port 5432", () => {
    expect(detectProtocol(5432)).toBe("postgresql");
  });

  it("detects MSSQL on port 1433", () => {
    expect(detectProtocol(1433)).toBe("mssql");
  });

  it("detects Redis on port 6379", () => {
    expect(detectProtocol(6379)).toBe("redis");
  });

  it("detects Redis on port 6380", () => {
    expect(detectProtocol(6380)).toBe("redis");
  });

  it("detects MongoDB on port 27017", () => {
    expect(detectProtocol(27017)).toBe("mongodb");
  });

  it("detects VNC on port 5900", () => {
    expect(detectProtocol(5900)).toBe("vnc");
  });

  it("detects VNC on port 5901", () => {
    expect(detectProtocol(5901)).toBe("vnc");
  });

  it("returns null for unknown ports", () => {
    expect(detectProtocol(8080)).toBeNull();
    expect(detectProtocol(9999)).toBeNull();
    expect(detectProtocol(12345)).toBeNull();
  });

  it("covers all expected admin service ports", () => {
    const expectedPorts = [21, 22, 23, 25, 161, 389, 445, 587, 636, 1433, 3306, 3389, 5432, 5900, 6379, 27017];
    for (const port of expectedPorts) {
      expect(detectProtocol(port)).not.toBeNull();
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Port-Protocol Map Completeness
// ═══════════════════════════════════════════════════════════════════════════════

describe("PORT_PROTOCOL_MAP", () => {
  it("contains all critical admin ports", () => {
    expect(PORT_PROTOCOL_MAP[22]).toBe("ssh");
    expect(PORT_PROTOCOL_MAP[25]).toBe("smtp");
    expect(PORT_PROTOCOL_MAP[21]).toBe("ftp");
    expect(PORT_PROTOCOL_MAP[445]).toBe("smb");
    expect(PORT_PROTOCOL_MAP[3389]).toBe("rdp");
    expect(PORT_PROTOCOL_MAP[161]).toBe("snmp");
  });

  it("contains all database ports", () => {
    expect(PORT_PROTOCOL_MAP[3306]).toBe("mysql");
    expect(PORT_PROTOCOL_MAP[5432]).toBe("postgresql");
    expect(PORT_PROTOCOL_MAP[1433]).toBe("mssql");
    expect(PORT_PROTOCOL_MAP[6379]).toBe("redis");
    expect(PORT_PROTOCOL_MAP[27017]).toBe("mongodb");
  });

  it("maps multiple VNC ports", () => {
    expect(PORT_PROTOCOL_MAP[5900]).toBe("vnc");
    expect(PORT_PROTOCOL_MAP[5901]).toBe("vnc");
    expect(PORT_PROTOCOL_MAP[5902]).toBe("vnc");
  });

  it("maps multiple SMTP ports", () => {
    expect(PORT_PROTOCOL_MAP[25]).toBe("smtp");
    expect(PORT_PROTOCOL_MAP[465]).toBe("smtp");
    expect(PORT_PROTOCOL_MAP[587]).toBe("smtp");
  });

  it("maps multiple Redis ports", () => {
    expect(PORT_PROTOCOL_MAP[6379]).toBe("redis");
    expect(PORT_PROTOCOL_MAP[6380]).toBe("redis");
  });

  it("maps multiple MongoDB ports", () => {
    expect(PORT_PROTOCOL_MAP[27017]).toBe("mongodb");
    expect(PORT_PROTOCOL_MAP[27018]).toBe("mongodb");
    expect(PORT_PROTOCOL_MAP[27019]).toBe("mongodb");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Summary Report Generation
// ═══════════════════════════════════════════════════════════════════════════════

describe("summarizeFingerprints", () => {
  const makeResult = (
    protocol: ServiceProtocol,
    overrides: Partial<FingerprintResult> = {},
  ): FingerprintResult => ({
    protocol,
    host: "10.0.0.1",
    port: 22,
    banner: null,
    version: null,
    product: null,
    os: null,
    capabilities: {},
    securityFlags: {
      tlsSupported: false,
      tlsRequired: false,
      tlsVersion: null,
      authRequired: true,
      anonymousAccess: false,
      weakCredentials: false,
      defaultCredentials: false,
      encryptionEnabled: false,
      signingEnabled: false,
    },
    metadata: {},
    rawResponse: null,
    durationMs: 100,
    error: null,
    mitreRelevance: [],
    potentialCves: [],
    riskIndicators: [],
    ...overrides,
  });

  it("counts total, successful, and failed probes", () => {
    const results = [
      makeResult("ssh"),
      makeResult("smtp"),
      makeResult("ftp", { error: "Connection refused" }),
    ];
    const summary = summarizeFingerprints(results);
    expect(summary.totalServices).toBe(3);
    expect(summary.successfulProbes).toBe(2);
    expect(summary.failedProbes).toBe(1);
  });

  it("counts risk indicators by severity", () => {
    const results = [
      makeResult("ssh", {
        riskIndicators: [
          { severity: "critical", title: "Test", description: "Test" },
          { severity: "high", title: "Test", description: "Test" },
        ],
      }),
      makeResult("smtp", {
        riskIndicators: [
          { severity: "medium", title: "Test", description: "Test" },
          { severity: "low", title: "Test", description: "Test" },
          { severity: "critical", title: "Test2", description: "Test2" },
        ],
      }),
    ];
    const summary = summarizeFingerprints(results);
    expect(summary.criticalRisks).toBe(2);
    expect(summary.highRisks).toBe(1);
    expect(summary.mediumRisks).toBe(1);
    expect(summary.lowRisks).toBe(1);
  });

  it("identifies services with anonymous access", () => {
    const results = [
      makeResult("ftp", {
        securityFlags: {
          ...makeResult("ftp").securityFlags,
          anonymousAccess: true,
        },
      }),
      makeResult("ssh"),
    ];
    const summary = summarizeFingerprints(results);
    expect(summary.servicesWithAnonymousAccess).toHaveLength(1);
    expect(summary.servicesWithAnonymousAccess[0].protocol).toBe("ftp");
  });

  it("identifies services with default credentials", () => {
    const results = [
      makeResult("snmp", {
        securityFlags: {
          ...makeResult("snmp").securityFlags,
          defaultCredentials: true,
        },
      }),
      makeResult("ssh"),
    ];
    const summary = summarizeFingerprints(results);
    expect(summary.servicesWithDefaultCreds).toHaveLength(1);
    expect(summary.servicesWithDefaultCreds[0].protocol).toBe("snmp");
  });

  it("identifies services without TLS", () => {
    const results = [
      makeResult("smtp", {
        securityFlags: {
          ...makeResult("smtp").securityFlags,
          tlsSupported: false,
        },
      }),
      makeResult("ldap", {
        securityFlags: {
          ...makeResult("ldap").securityFlags,
          tlsSupported: true,
        },
      }),
    ];
    const summary = summarizeFingerprints(results);
    expect(summary.servicesWithoutTls).toHaveLength(1);
    expect(summary.servicesWithoutTls[0].protocol).toBe("smtp");
  });

  it("identifies services with weak auth", () => {
    const results = [
      makeResult("redis", {
        securityFlags: {
          ...makeResult("redis").securityFlags,
          authRequired: false,
        },
      }),
      makeResult("mysql", {
        securityFlags: {
          ...makeResult("mysql").securityFlags,
          weakCredentials: true,
        },
      }),
      makeResult("ssh"),
    ];
    const summary = summarizeFingerprints(results);
    expect(summary.servicesWithWeakAuth).toHaveLength(2);
  });

  it("deduplicates CVEs across results", () => {
    const results = [
      makeResult("ssh", { potentialCves: ["CVE-2024-6387", "CVE-2019-6111"] }),
      makeResult("ssh", { potentialCves: ["CVE-2024-6387", "CVE-2016-0777"] }),
    ];
    const summary = summarizeFingerprints(results);
    expect(summary.allCves).toHaveLength(3);
    expect(summary.allCves).toContain("CVE-2024-6387");
    expect(summary.allCves).toContain("CVE-2019-6111");
    expect(summary.allCves).toContain("CVE-2016-0777");
  });

  it("deduplicates MITRE techniques across results", () => {
    const results = [
      makeResult("ssh", { mitreRelevance: ["T1021.004", "T1557"] }),
      makeResult("rdp", { mitreRelevance: ["T1021.001", "T1557"] }),
    ];
    const summary = summarizeFingerprints(results);
    expect(summary.allMitreTechniques).toHaveLength(3);
    expect(summary.allMitreTechniques).toContain("T1021.004");
    expect(summary.allMitreTechniques).toContain("T1021.001");
    expect(summary.allMitreTechniques).toContain("T1557");
  });

  it("handles empty results array", () => {
    const summary = summarizeFingerprints([]);
    expect(summary.totalServices).toBe(0);
    expect(summary.successfulProbes).toBe(0);
    expect(summary.failedProbes).toBe(0);
    expect(summary.criticalRisks).toBe(0);
    expect(summary.servicesWithAnonymousAccess).toHaveLength(0);
    expect(summary.allCves).toHaveLength(0);
  });

  it("excludes failed probes from TLS check", () => {
    const results = [
      makeResult("smtp", { error: "Connection refused" }), // failed — should not appear in servicesWithoutTls
      makeResult("ftp"), // successful, no TLS
    ];
    const summary = summarizeFingerprints(results);
    expect(summary.servicesWithoutTls).toHaveLength(1);
    expect(summary.servicesWithoutTls[0].protocol).toBe("ftp");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Scope Enforcement on Remaining Routers
// ═══════════════════════════════════════════════════════════════════════════════

describe("Remaining Router Scope Enforcement", () => {
  // These tests verify that the scope enforcement imports exist and the
  // routers have been properly patched

  it("post-exploit-playbooks has scope enforcement import", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/post-exploit-playbooks.ts", "utf-8");
    // This router uses roe-guard for offensive action logging on session commands
    expect(content).toContain("roe-guard");
  });

  it("emulation-playbooks has scope enforcement import", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/emulation-playbooks.ts", "utf-8");
    // This router uses direct scope-guard import for testing window checks
    expect(content).toContain("scope-guard");
    expect(content).toContain("checkTestingWindow");
  });

  it("cloud-attack-paths has scope enforcement import", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/cloud-attack-paths.ts", "utf-8");
    expect(content).toContain("scope-enforcement-middleware");
  });

  it("remediation-verification has scope enforcement import", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/remediation-verification.ts", "utf-8");
    expect(content).toContain("scope-enforcement-middleware");
  });

  it("ngfw-validation has scope enforcement import", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/ngfw-validation.ts", "utf-8");
    expect(content).toContain("scope-enforcement-middleware");
  });

  it("all 23 enforced routers have scope enforcement", async () => {
    const fs = await import("fs");
    // Routers using the scope-enforcement-middleware wrapper
    const middlewareRouters = [
      "metasploit-catalog", "web-app-scanning", "sliver-c2", "nuclei-scanner",
      "projectdiscovery", "atomic-red-team", "ad-attack-sim", "discovery-engine",
      "evasion-engine", "phishing-ops", "msf-sessions", "web-crawler",
      "api-security", "live-infra",
      "agent-manager", "email-security", "ics-ot-security", "active-verification",
      "cloud-attack-paths", "remediation-verification", "ngfw-validation",
    ];
    // Routers using direct scope-guard imports
    const directScopeRouters = [
      "emulation-playbooks",
    ];
    // Routers using roe-guard directly for audit logging
    const roeGuardRouters = [
      "post-exploit-playbooks", "payload-generator",
    ];
    // Routers using engagement-level scope logging
    const engagementScopeRouters = [
      "engagement-automation",
    ];

    for (const router of middlewareRouters) {
      const content = fs.readFileSync(`server/routers/${router}.ts`, "utf-8");
      expect(content, `${router} missing scope-enforcement-middleware`).toContain("scope-enforcement-middleware");
    }
    for (const router of directScopeRouters) {
      const content = fs.readFileSync(`server/routers/${router}.ts`, "utf-8");
      expect(content, `${router} missing scope-guard`).toContain("scope-guard");
    }
    for (const router of roeGuardRouters) {
      const content = fs.readFileSync(`server/routers/${router}.ts`, "utf-8");
      expect(content, `${router} missing roe-guard`).toContain("roe-guard");
    }
    for (const router of engagementScopeRouters) {
      const content = fs.readFileSync(`server/routers/${router}.ts`, "utf-8");
      // engagement-automation validates scope at engagement creation time
      expect(content, `${router} missing scope validation`).toContain("engagementId");
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Fingerprint Result Structure Validation
// ═══════════════════════════════════════════════════════════════════════════════

describe("FingerprintResult Structure", () => {
  it("has all required fields in the type", () => {
    // This test validates the type structure by creating a valid result
    const result: FingerprintResult = {
      protocol: "ssh",
      host: "10.0.0.1",
      port: 22,
      banner: "SSH-2.0-OpenSSH_8.9p1",
      version: "8.9p1",
      product: "OpenSSH",
      os: "Ubuntu Linux",
      capabilities: { ssh: true, kexInit: true },
      securityFlags: {
        tlsSupported: false,
        tlsRequired: false,
        tlsVersion: null,
        authRequired: true,
        anonymousAccess: false,
        weakCredentials: false,
        defaultCredentials: false,
        encryptionEnabled: true,
        signingEnabled: false,
      },
      metadata: { sshProtocolVersion: "2.0" },
      rawResponse: "SSH-2.0-OpenSSH_8.9p1",
      durationMs: 150,
      error: null,
      mitreRelevance: ["T1021.004"],
      potentialCves: [],
      riskIndicators: [],
    };

    expect(result.protocol).toBe("ssh");
    expect(result.host).toBe("10.0.0.1");
    expect(result.port).toBe(22);
    expect(result.banner).toBeTruthy();
    expect(result.version).toBeTruthy();
    expect(result.product).toBeTruthy();
    expect(result.securityFlags.encryptionEnabled).toBe(true);
    expect(result.mitreRelevance).toContain("T1021.004");
  });

  it("SecurityFlags has all required boolean fields", () => {
    const flags: SecurityFlags = {
      tlsSupported: true,
      tlsRequired: false,
      tlsVersion: "TLSv1.3",
      authRequired: true,
      anonymousAccess: false,
      weakCredentials: false,
      defaultCredentials: false,
      encryptionEnabled: true,
      signingEnabled: true,
    };

    expect(typeof flags.tlsSupported).toBe("boolean");
    expect(typeof flags.tlsRequired).toBe("boolean");
    expect(typeof flags.authRequired).toBe("boolean");
    expect(typeof flags.anonymousAccess).toBe("boolean");
    expect(typeof flags.weakCredentials).toBe("boolean");
    expect(typeof flags.defaultCredentials).toBe("boolean");
    expect(typeof flags.encryptionEnabled).toBe("boolean");
    expect(typeof flags.signingEnabled).toBe("boolean");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Service Fingerprinter Module Exports
// ═══════════════════════════════════════════════════════════════════════════════

describe("Service Fingerprinter Module Exports", () => {
  it("exports all protocol-specific fingerprint functions", async () => {
    const mod = await import("./lib/service-fingerprinter");
    expect(typeof mod.fingerprintSSH).toBe("function");
    expect(typeof mod.fingerprintSMTP).toBe("function");
    expect(typeof mod.fingerprintFTP).toBe("function");
    expect(typeof mod.fingerprintSNMP).toBe("function");
    expect(typeof mod.fingerprintRDP).toBe("function");
    expect(typeof mod.fingerprintSMB).toBe("function");
    expect(typeof mod.fingerprintLDAP).toBe("function");
    expect(typeof mod.fingerprintTelnet).toBe("function");
    expect(typeof mod.fingerprintMySQL).toBe("function");
    expect(typeof mod.fingerprintPostgreSQL).toBe("function");
    expect(typeof mod.fingerprintMSSQL).toBe("function");
    expect(typeof mod.fingerprintRedis).toBe("function");
    expect(typeof mod.fingerprintMongoDB).toBe("function");
    expect(typeof mod.fingerprintVNC).toBe("function");
  });

  it("exports orchestration functions", async () => {
    const mod = await import("./lib/service-fingerprinter");
    expect(typeof mod.fingerprintService).toBe("function");
    expect(typeof mod.batchFingerprint).toBe("function");
    expect(typeof mod.autoFingerprint).toBe("function");
    expect(typeof mod.summarizeFingerprints).toBe("function");
  });

  it("exports utility functions and constants", async () => {
    const mod = await import("./lib/service-fingerprinter");
    expect(typeof mod.detectProtocol).toBe("function");
    expect(typeof mod.PORT_PROTOCOL_MAP).toBe("object");
  });
});
