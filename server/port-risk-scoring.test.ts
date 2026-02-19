/**
 * Port-Based Risk Scoring Tests
 * 
 * Tests for the computePortRisk and generatePortPostureFindings functions
 * that analyze exposed ports from passive recon and elevate CARVER/SHOCK scores.
 */
import { describe, it, expect } from "vitest";
import { computePortRisk, generatePortPostureFindings, PortRiskResult } from "./domainIntel";

// Helper to create a minimal asset
function makeAsset(hostname: string, dnsRecords?: Record<string, any>) {
  return {
    assetId: `asset-${hostname}`,
    hostname,
    assetType: "web_application",
    assetClasses: ["web"],
    tags: [],
    dnsRecords,
  };
}

// Helper to create passive recon observations with port data
function makeObs(name: string, ip: string, ports: number[], tags: string[] = [], evidence: Record<string, any> = {}) {
  return {
    name,
    ip,
    tags: [...tags, ...ports.map(p => `port:${p}`)],
    evidence: { ports, ip, ...evidence },
  };
}

describe("Port Risk Scoring - computePortRisk", () => {
  it("should return zero scores when no observations match the asset", () => {
    const asset = makeAsset("example.com");
    const result = computePortRisk(asset, []);
    expect(result.portExposureScore).toBe(0);
    expect(result.highRiskPortCount).toBe(0);
    expect(result.mediumRiskPortCount).toBe(0);
    expect(result.totalOpenPorts).toBe(0);
    expect(result.portFindings).toHaveLength(0);
    expect(result.accessibilityBoost).toBe(0);
    expect(result.likelihoodBoost).toBe(0);
  });

  it("should detect high-risk ports (RDP, Telnet, FTP)", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [3389, 23, 21])];
    const result = computePortRisk(asset, obs);
    expect(result.highRiskPortCount).toBe(3);
    expect(result.totalOpenPorts).toBe(3);
    expect(result.portFindings.some(f => f.service === "RDP")).toBe(true);
    expect(result.portFindings.some(f => f.service === "Telnet")).toBe(true);
    expect(result.portFindings.some(f => f.service === "FTP")).toBe(true);
  });

  it("should detect medium-risk ports (SSH, SNMP, LDAP)", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [22, 161, 389])];
    const result = computePortRisk(asset, obs);
    expect(result.mediumRiskPortCount).toBe(3);
    expect(result.portFindings.some(f => f.service === "SSH")).toBe(true);
    expect(result.portFindings.some(f => f.service === "SNMP")).toBe(true);
    expect(result.portFindings.some(f => f.service === "LDAP")).toBe(true);
  });

  it("should classify standard web ports as low risk", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [80, 443])];
    const result = computePortRisk(asset, obs);
    expect(result.highRiskPortCount).toBe(0);
    expect(result.mediumRiskPortCount).toBe(0);
    expect(result.totalOpenPorts).toBe(2);
    expect(result.portFindings.every(f => f.riskLevel === "low")).toBe(true);
  });

  it("should give high accessibility boost for multiple high-risk ports", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [3389, 445, 23])]; // RDP + SMB + Telnet
    const result = computePortRisk(asset, obs);
    expect(result.accessibilityBoost).toBe(3); // 3+ high-risk ports = max boost
    expect(result.likelihoodBoost).toBe(0.3); // 3+ high-risk ports = max boost
  });

  it("should give moderate boost for 2 high-risk ports", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [3389, 445])]; // RDP + SMB
    const result = computePortRisk(asset, obs);
    expect(result.accessibilityBoost).toBe(2);
    expect(result.likelihoodBoost).toBe(0.2);
  });

  it("should give small boost for 1 high-risk port", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [3389])]; // RDP only
    const result = computePortRisk(asset, obs);
    expect(result.accessibilityBoost).toBe(1.5);
    expect(result.likelihoodBoost).toBe(0.15);
  });

  it("should give small boost for medium-risk ports only", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [22, 161, 389])]; // SSH + SNMP + LDAP
    const result = computePortRisk(asset, obs);
    expect(result.accessibilityBoost).toBe(1); // 3+ medium-risk ports
    expect(result.likelihoodBoost).toBe(0.1);
  });

  it("should match observations by hostname", () => {
    const asset = makeAsset("app.target.com");
    const obs = [makeObs("app.target.com", "1.2.3.4", [3389, 22])];
    const result = computePortRisk(asset, obs);
    expect(result.totalOpenPorts).toBe(2);
    expect(result.highRiskPortCount).toBe(1); // RDP
    expect(result.mediumRiskPortCount).toBe(1); // SSH
  });

  it("should match observations by IP from DNS records", () => {
    const asset = makeAsset("target.com", { A: ["10.0.0.1"] });
    const obs = [makeObs("other-host", "10.0.0.1", [3389, 445])];
    const result = computePortRisk(asset, obs);
    expect(result.totalOpenPorts).toBe(2);
    expect(result.highRiskPortCount).toBe(2);
  });

  it("should extract ports from Shodan host detail evidence", () => {
    const asset = makeAsset("target.com");
    const obs = [{
      name: "target.com",
      ip: "1.2.3.4",
      tags: ["shodan_host_detail"],
      evidence: { port: 3389, transport: "tcp", product: "Microsoft Terminal Services" },
    }];
    const result = computePortRisk(asset, obs);
    expect(result.totalOpenPorts).toBe(1);
    expect(result.highRiskPortCount).toBe(1);
    expect(result.portFindings[0].service).toBe("RDP");
  });

  it("should extract ports from all_ports evidence field", () => {
    const asset = makeAsset("target.com");
    const obs = [{
      name: "target.com",
      ip: "1.2.3.4",
      tags: [],
      evidence: { all_ports: [80, 443, 3389, 22] },
    }];
    const result = computePortRisk(asset, obs);
    expect(result.totalOpenPorts).toBe(4);
    expect(result.highRiskPortCount).toBe(1); // RDP
    expect(result.mediumRiskPortCount).toBe(1); // SSH
  });

  it("should deduplicate ports from multiple observations", () => {
    const asset = makeAsset("target.com");
    const obs = [
      makeObs("target.com", "1.2.3.4", [80, 443, 3389]),
      makeObs("target.com", "1.2.3.4", [80, 443, 22]),
    ];
    const result = computePortRisk(asset, obs);
    expect(result.totalOpenPorts).toBe(4); // 80, 443, 3389, 22 (deduplicated)
  });

  it("should sort findings by severity descending", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [80, 3389, 22, 23])];
    const result = computePortRisk(asset, obs);
    for (let i = 1; i < result.portFindings.length; i++) {
      expect(result.portFindings[i].severity).toBeLessThanOrEqual(result.portFindings[i - 1].severity);
    }
  });

  it("should detect database ports as high risk", () => {
    const asset = makeAsset("db.target.com");
    const obs = [makeObs("db.target.com", "1.2.3.4", [3306, 5432, 27017, 6379])];
    const result = computePortRisk(asset, obs);
    expect(result.highRiskPortCount).toBe(4);
    expect(result.portFindings.some(f => f.service === "MySQL")).toBe(true);
    expect(result.portFindings.some(f => f.service === "PostgreSQL")).toBe(true);
    expect(result.portFindings.some(f => f.service === "MongoDB")).toBe(true);
    expect(result.portFindings.some(f => f.service === "Redis")).toBe(true);
  });

  it("should calculate port exposure score proportional to risk", () => {
    const asset = makeAsset("target.com");
    // Low risk: only web ports
    const lowObs = [makeObs("target.com", "1.2.3.4", [80, 443])];
    const lowResult = computePortRisk(asset, lowObs);
    // High risk: critical ports
    const highObs = [makeObs("target.com", "1.2.3.4", [3389, 23, 445, 21, 5900])];
    const highResult = computePortRisk(asset, highObs);
    expect(highResult.portExposureScore).toBeGreaterThan(lowResult.portExposureScore);
  });

  it("should handle VNC ports", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [5900, 5901])];
    const result = computePortRisk(asset, obs);
    expect(result.highRiskPortCount).toBe(2);
    expect(result.portFindings.every(f => f.service === "VNC")).toBe(true);
  });

  it("should handle Windows service ports (MS-RPC, NetBIOS, SMB)", () => {
    const asset = makeAsset("dc.target.com");
    const obs = [makeObs("dc.target.com", "1.2.3.4", [135, 139, 445])];
    const result = computePortRisk(asset, obs);
    expect(result.highRiskPortCount).toBe(3);
    expect(result.portFindings.some(f => f.service === "MS-RPC")).toBe(true);
    expect(result.portFindings.some(f => f.service === "NetBIOS")).toBe(true);
    expect(result.portFindings.some(f => f.service === "SMB")).toBe(true);
  });
});

describe("Port Risk Scoring - generatePortPostureFindings", () => {
  it("should generate findings for high-risk ports", () => {
    const asset = makeAsset("target.com");
    const portRisk: PortRiskResult = {
      portExposureScore: 70,
      portExposureBand: "high",
      highRiskPortCount: 2,
      mediumRiskPortCount: 0,
      totalOpenPorts: 2,
      portFindings: [
        { port: 3389, service: "RDP", severity: 9, category: "remote_access", rationale: "RDP test", riskLevel: "high" },
        { port: 445, service: "SMB", severity: 8, category: "windows", rationale: "SMB test", riskLevel: "high" },
      ],
      accessibilityBoost: 2,
      likelihoodBoost: 0.2,
    };
    const findings = generatePortPostureFindings(asset, portRisk);
    // Should have 2 individual findings + 1 compound finding
    expect(findings.length).toBe(3);
    expect(findings.some(f => f.title.includes("RDP"))).toBe(true);
    expect(findings.some(f => f.title.includes("SMB"))).toBe(true);
    expect(findings.some(f => f.title.includes("Multiple high-risk"))).toBe(true);
  });

  it("should mark port findings as confirmed corroboration tier", () => {
    const asset = makeAsset("target.com");
    const portRisk: PortRiskResult = {
      portExposureScore: 54,
      portExposureBand: "medium",
      highRiskPortCount: 1,
      mediumRiskPortCount: 0,
      totalOpenPorts: 1,
      portFindings: [
        { port: 3389, service: "RDP", severity: 9, category: "remote_access", rationale: "RDP test", riskLevel: "high" },
      ],
      accessibilityBoost: 1.5,
      likelihoodBoost: 0.15,
    };
    const findings = generatePortPostureFindings(asset, portRisk);
    expect(findings.length).toBe(1);
    expect(findings[0].corroborationTier).toBe("confirmed");
    expect(findings[0].confidence).toBe(1.0);
    expect(findings[0].category).toBe("network_exposure");
  });

  it("should not generate findings for low-risk ports only", () => {
    const asset = makeAsset("target.com");
    const portRisk: PortRiskResult = {
      portExposureScore: 10,
      portExposureBand: "low",
      highRiskPortCount: 0,
      mediumRiskPortCount: 0,
      totalOpenPorts: 2,
      portFindings: [
        { port: 80, service: "HTTP", severity: 2, category: "web", rationale: "HTTP", riskLevel: "low" },
        { port: 443, service: "HTTPS", severity: 2, category: "web", rationale: "HTTPS", riskLevel: "low" },
      ],
      accessibilityBoost: 0,
      likelihoodBoost: 0,
    };
    const findings = generatePortPostureFindings(asset, portRisk);
    expect(findings.length).toBe(0);
  });

  it("should generate findings for medium-risk ports with severity >= 5", () => {
    const asset = makeAsset("target.com");
    const portRisk: PortRiskResult = {
      portExposureScore: 30,
      portExposureBand: "low",
      highRiskPortCount: 0,
      mediumRiskPortCount: 2,
      totalOpenPorts: 2,
      portFindings: [
        { port: 161, service: "SNMP", severity: 6, category: "management", rationale: "SNMP test", riskLevel: "medium" },
        { port: 110, service: "POP3", severity: 5, category: "mail", rationale: "POP3 test", riskLevel: "medium" },
      ],
      accessibilityBoost: 0.5,
      likelihoodBoost: 0.05,
    };
    const findings = generatePortPostureFindings(asset, portRisk);
    expect(findings.length).toBe(2);
    expect(findings.some(f => f.title.includes("SNMP"))).toBe(true);
    expect(findings.some(f => f.title.includes("POP3"))).toBe(true);
  });

  it("should include recommended controls for database ports", () => {
    const asset = makeAsset("db.target.com");
    const portRisk: PortRiskResult = {
      portExposureScore: 48,
      portExposureBand: "medium",
      highRiskPortCount: 1,
      mediumRiskPortCount: 0,
      totalOpenPorts: 1,
      portFindings: [
        { port: 3306, service: "MySQL", severity: 8, category: "database", rationale: "MySQL test", riskLevel: "high" },
      ],
      accessibilityBoost: 1.5,
      likelihoodBoost: 0.15,
    };
    const findings = generatePortPostureFindings(asset, portRisk);
    expect(findings.length).toBe(1);
    expect(findings[0].recommendedControls.some((c: string) => c.includes("authentication"))).toBe(true);
    expect(findings[0].recommendedControls.some((c: string) => c.includes("encryption"))).toBe(true);
  });

  it("should include recommended controls for remote access ports", () => {
    const asset = makeAsset("target.com");
    const portRisk: PortRiskResult = {
      portExposureScore: 54,
      portExposureBand: "medium",
      highRiskPortCount: 1,
      mediumRiskPortCount: 0,
      totalOpenPorts: 1,
      portFindings: [
        { port: 3389, service: "RDP", severity: 9, category: "remote_access", rationale: "RDP test", riskLevel: "high" },
      ],
      accessibilityBoost: 1.5,
      likelihoodBoost: 0.15,
    };
    const findings = generatePortPostureFindings(asset, portRisk);
    expect(findings[0].recommendedControls.some((c: string) => c.includes("multi-factor"))).toBe(true);
    expect(findings[0].recommendedControls.some((c: string) => c.includes("lockout"))).toBe(true);
  });

  it("compound finding should have elevated severity", () => {
    const asset = makeAsset("target.com");
    const portRisk: PortRiskResult = {
      portExposureScore: 70,
      portExposureBand: "high",
      highRiskPortCount: 3,
      mediumRiskPortCount: 0,
      totalOpenPorts: 3,
      portFindings: [
        { port: 3389, service: "RDP", severity: 9, category: "remote_access", rationale: "RDP", riskLevel: "high" },
        { port: 445, service: "SMB", severity: 8, category: "windows", rationale: "SMB", riskLevel: "high" },
        { port: 23, service: "Telnet", severity: 9, category: "remote_access", rationale: "Telnet", riskLevel: "high" },
      ],
      accessibilityBoost: 3,
      likelihoodBoost: 0.3,
    };
    const findings = generatePortPostureFindings(asset, portRisk);
    const compound = findings.find(f => f.title.includes("Multiple high-risk"));
    expect(compound).toBeDefined();
    expect(compound!.severity).toBe(10); // max severity (9) + 1, capped at 10
    expect(compound!.likelihood).toBe(9);
  });
});

describe("Port Risk Scoring - Integration with CARVER/SHOCK", () => {
  it("high-risk ports should produce non-zero accessibility boost", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [3389])];
    const result = computePortRisk(asset, obs);
    expect(result.accessibilityBoost).toBeGreaterThan(0);
  });

  it("high-risk ports should produce non-zero likelihood boost", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [3389])];
    const result = computePortRisk(asset, obs);
    expect(result.likelihoodBoost).toBeGreaterThan(0);
  });

  it("web-only ports should produce zero boosts", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [80, 443])];
    const result = computePortRisk(asset, obs);
    expect(result.accessibilityBoost).toBe(0);
    expect(result.likelihoodBoost).toBe(0);
  });

  it("accessibility boost should be capped at 3", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [3389, 23, 21, 445, 5900, 3306, 27017])]; // 7 high-risk
    const result = computePortRisk(asset, obs);
    expect(result.accessibilityBoost).toBeLessThanOrEqual(3);
  });

  it("likelihood boost should be capped at 0.3", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [3389, 23, 21, 445, 5900, 3306, 27017])]; // 7 high-risk
    const result = computePortRisk(asset, obs);
    expect(result.likelihoodBoost).toBeLessThanOrEqual(0.3);
  });

  it("port exposure score should be 0-100", () => {
    const asset = makeAsset("target.com");
    const obs = [makeObs("target.com", "1.2.3.4", [3389, 23, 21, 445, 5900, 3306, 27017, 6379, 9200, 1433])];
    const result = computePortRisk(asset, obs);
    expect(result.portExposureScore).toBeGreaterThanOrEqual(0);
    expect(result.portExposureScore).toBeLessThanOrEqual(100);
  });
});

describe("Port Risk Scoring - Edge Cases", () => {
  it("should handle empty observations array", () => {
    const asset = makeAsset("target.com");
    const result = computePortRisk(asset, []);
    expect(result.totalOpenPorts).toBe(0);
  });

  it("should handle observations with no port data", () => {
    const asset = makeAsset("target.com");
    const obs = [{ name: "target.com", ip: "1.2.3.4", tags: [], evidence: {} }];
    const result = computePortRisk(asset, obs);
    expect(result.totalOpenPorts).toBe(0);
  });

  it("should handle observations with non-numeric port data", () => {
    const asset = makeAsset("target.com");
    const obs = [{ name: "target.com", ip: "1.2.3.4", tags: [], evidence: { ports: ["not-a-port", null, undefined] } }];
    const result = computePortRisk(asset, obs);
    expect(result.totalOpenPorts).toBe(0);
  });

  it("should handle asset with no hostname", () => {
    const asset = makeAsset("");
    const obs = [makeObs("", "1.2.3.4", [3389])];
    const result = computePortRisk(asset, obs);
    // Empty hostname should not match anything
    expect(result.totalOpenPorts).toBe(0);
  });

  it("should handle DNS records with nested address objects", () => {
    const asset = makeAsset("target.com", { A: [{ address: "10.0.0.1" }] });
    const obs = [makeObs("other-host", "10.0.0.1", [3389])];
    const result = computePortRisk(asset, obs);
    expect(result.totalOpenPorts).toBe(1);
    expect(result.highRiskPortCount).toBe(1);
  });
});
