import { describe, it, expect } from "vitest";
import {
  discoverViaShodan,
  discoverViaCensys,
  fingerprintDevice,
  ICS_PROTOCOLS,
  calculateIcsRiskScore,
} from "./lib/ics-device-discovery";
import {
  ICS_APT_GROUPS,
  MITRE_ICS_TECHNIQUES,
  matchAptGroups,
  searchIcsExploits,
  getTechniquesForDeviceType,
  getTechniquesByTactic,
  getIcsTactics,
  seedAptGroups,
} from "./lib/ics-exploit-catalog";
import {
  analyzeProtocol,
  analyzeModbus,
  analyzeS7comm,
  analyzeBacnet,
  analyzeMqtt,
  analyzeDnp3,
  analyzeOpcUa,
  analyzeIec104,
  analyzeAllProtocols,
  getAggregateProtocolRisk,
} from "./lib/ot-protocol-analyzer";

// ─── ICS Device Discovery ─────────────────────────────────────────────────────

describe("ICS Device Discovery", () => {
  describe("ICS_PROTOCOLS", () => {
    it("should define at least 9 ICS protocols", () => {
      expect(Object.keys(ICS_PROTOCOLS).length).toBeGreaterThanOrEqual(9);
    });

    it("should include core ICS protocols", () => {
      const protocols = Object.keys(ICS_PROTOCOLS);
      expect(protocols).toContain("modbus");
      expect(protocols).toContain("s7comm");
      expect(protocols).toContain("dnp3");
      expect(protocols).toContain("bacnet");
      expect(protocols).toContain("ethernetip");
    });

    it("should include IoT protocols", () => {
      const protocols = Object.keys(ICS_PROTOCOLS);
      expect(protocols).toContain("mqtt");
      expect(protocols).toContain("coap");
    });

    it("should have port numbers for each protocol", () => {
      for (const [, proto] of Object.entries(ICS_PROTOCOLS)) {
        expect(proto).toHaveProperty("port");
        expect(typeof proto.port).toBe("number");
        expect(proto.port).toBeGreaterThan(0);
      }
    });

    it("should have Shodan queries for each protocol", () => {
      for (const [, proto] of Object.entries(ICS_PROTOCOLS)) {
        expect(proto).toHaveProperty("shodanQuery");
        expect(typeof proto.shodanQuery).toBe("string");
        expect(proto.shodanQuery.length).toBeGreaterThan(0);
      }
    });

    it("should have risk levels for each protocol", () => {
      for (const [, proto] of Object.entries(ICS_PROTOCOLS)) {
        expect(proto).toHaveProperty("riskLevel");
        expect(["critical", "high", "medium", "low"]).toContain(proto.riskLevel);
      }
    });
  });

  describe("fingerprintDevice", () => {
    it("should fingerprint a Siemens S7 device from banner", () => {
      const result = fingerprintDevice(
        "Siemens S7-1200 PLC Module Type: CPU 1214C",
        102,
        "S7-1200",
        "V4.5"
      );

      expect(result).toHaveProperty("vendor");
      expect(result).toHaveProperty("deviceType");
      expect(result).toHaveProperty("protocols");
      expect(result.protocols).toContain("s7comm");
    });

    it("should fingerprint a Modbus device", () => {
      const result = fingerprintDevice(
        "Schneider Electric Modicon M340",
        502,
        "Modicon M340"
      );

      expect(result).toHaveProperty("vendor");
      expect(result).toHaveProperty("protocols");
      expect(result.protocols).toContain("modbus");
    });

    it("should handle unknown banners gracefully", () => {
      const result = fingerprintDevice("unknown device response", 502);

      expect(result).toHaveProperty("vendor");
      expect(result).toHaveProperty("deviceType");
      expect(result).toHaveProperty("protocols");
    });

    it("should detect BACnet devices by port", () => {
      const result = fingerprintDevice(
        "Johnson Controls BACnet/IP controller",
        47808
      );

      expect(result.protocols).toContain("bacnet");
    });

    it("should detect MQTT devices by port", () => {
      const result = fingerprintDevice("MQTT Broker", 1883);
      expect(result.protocols).toContain("mqtt");
    });

    it("should return risk factors for unauthenticated protocols", () => {
      const result = fingerprintDevice("Modbus/TCP", 502);
      expect(result).toHaveProperty("riskFactors");
      expect(result.riskFactors.length).toBeGreaterThan(0);
    });
  });

  describe("calculateIcsRiskScore", () => {
    it("should calculate high risk for internet-exposed PLC with default creds", () => {
      const score = calculateIcsRiskScore({
        exposedToInternet: true,
        hasDefaultCredentials: true,
        hasKnownVulns: true,
        purdueLevel: "level_1",
        protocols: ["modbus", "s7comm"],
      });

      expect(score).toBeGreaterThanOrEqual(70);
      expect(score).toBeLessThanOrEqual(100);
    });

    it("should calculate lower risk for isolated device", () => {
      const score = calculateIcsRiskScore({
        exposedToInternet: false,
        hasDefaultCredentials: false,
        hasKnownVulns: false,
        purdueLevel: "level_3",
        protocols: ["bacnet"],
      });

      expect(score).toBeLessThan(50);
    });

    it("should factor in Purdue level (lower = higher risk)", () => {
      const level0Score = calculateIcsRiskScore({
        exposedToInternet: false,
        hasDefaultCredentials: false,
        hasKnownVulns: true,
        purdueLevel: "level_0",
        protocols: ["modbus"],
      });

      const level4Score = calculateIcsRiskScore({
        exposedToInternet: false,
        hasDefaultCredentials: false,
        hasKnownVulns: true,
        purdueLevel: "level_4",
        protocols: ["modbus"],
      });

      expect(level0Score).toBeGreaterThan(level4Score);
    });
  });

  describe("discoverViaShodan", () => {
    it("should be a function", () => {
      expect(typeof discoverViaShodan).toBe("function");
    });

    it("should return a promise", () => {
      const result = discoverViaShodan("modbus", "test-key", { limit: 1 });
      expect(result).toBeInstanceOf(Promise);
      result.catch(() => {});
    });
  });

  describe("discoverViaCensys", () => {
    it("should be a function", () => {
      expect(typeof discoverViaCensys).toBe("function");
    });
  });
});

// ─── ICS Exploit Catalog & APT Intelligence ───────────────────────────────────

describe("ICS Exploit Catalog", () => {
  describe("ICS_APT_GROUPS", () => {
    it("should define at least 10 ICS-targeting APT groups", () => {
      expect(ICS_APT_GROUPS.length).toBeGreaterThanOrEqual(10);
    });

    it("should include SANDWORM (Ukraine grid attacks)", () => {
      const sandworm = ICS_APT_GROUPS.find((g) => g.aptGroupName === "SANDWORM");
      expect(sandworm).toBeDefined();
      expect(sandworm!.targetedSectors).toBeDefined();
    });

    it("should include XENOTIME (TRITON/TRISIS)", () => {
      const xenotime = ICS_APT_GROUPS.find((g) => g.aptGroupName === "XENOTIME");
      expect(xenotime).toBeDefined();
    });

    it("should include VOLT TYPHOON", () => {
      const voltTyphoon = ICS_APT_GROUPS.find((g) => g.aptGroupName === "VOLT TYPHOON");
      expect(voltTyphoon).toBeDefined();
    });

    it("should include CHERNOVITE (PIPEDREAM)", () => {
      const chernovite = ICS_APT_GROUPS.find((g) => g.aptGroupName === "CHERNOVITE");
      expect(chernovite).toBeDefined();
    });

    it("should include BENTONITE (Iranian water utility attacks)", () => {
      const bentonite = ICS_APT_GROUPS.find((g) => g.aptGroupName === "BENTONITE");
      expect(bentonite).toBeDefined();
    });

    it("should have targeted sectors for each group", () => {
      for (const group of ICS_APT_GROUPS) {
        expect(group).toHaveProperty("targetedSectors");
        // targetedSectors can be a string or array depending on schema
        expect(group.targetedSectors).toBeDefined();
      }
    });

    it("should have targeted protocols for each group", () => {
      for (const group of ICS_APT_GROUPS) {
        expect(group).toHaveProperty("targetedProtocols");
        expect(group.targetedProtocols).toBeDefined();
      }
    });

    it("should have known campaigns for each group", () => {
      for (const group of ICS_APT_GROUPS) {
        expect(group).toHaveProperty("knownCampaigns");
      }
    });
  });

  describe("MITRE_ICS_TECHNIQUES", () => {
    it("should define at least 20 ICS-specific MITRE techniques", () => {
      expect(MITRE_ICS_TECHNIQUES.length).toBeGreaterThanOrEqual(20);
    });

    it("should have technique IDs starting with T", () => {
      for (const tech of MITRE_ICS_TECHNIQUES) {
        expect(tech.id).toMatch(/^T\d+/);
      }
    });

    it("should have tactic assignments", () => {
      for (const tech of MITRE_ICS_TECHNIQUES) {
        expect(tech.tactic).toBeDefined();
        expect(tech.tactic.length).toBeGreaterThan(0);
      }
    });

    it("should have platform assignments", () => {
      for (const tech of MITRE_ICS_TECHNIQUES) {
        expect(tech.platforms).toBeDefined();
        expect(tech.platforms.length).toBeGreaterThan(0);
      }
    });

    it("should cover multiple ICS tactics", () => {
      const tactics = new Set(MITRE_ICS_TECHNIQUES.map((t) => t.tactic));
      expect(tactics.size).toBeGreaterThanOrEqual(4);
    });
  });

  describe("matchAptGroups", () => {
    it("should match APT groups to energy sector Siemens devices", () => {
      const matches = matchAptGroups({
        vendors: ["Siemens"],
        protocols: ["s7comm", "modbus"],
        sectors: ["energy"],
        deviceTypes: ["plc"],
      });

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0]).toHaveProperty("matchScore");
      expect(matches[0]).toHaveProperty("matchReasons");
      expect(matches[0].matchScore).toBeGreaterThan(0);
    });

    it("should match APT groups to water sector devices", () => {
      const matches = matchAptGroups({
        vendors: ["Schneider Electric"],
        protocols: ["modbus"],
        sectors: ["water"],
        deviceTypes: ["plc"],
      });

      expect(matches.length).toBeGreaterThan(0);
    });

    it("should return results sorted by match score descending", () => {
      const matches = matchAptGroups({
        vendors: ["Siemens"],
        protocols: ["s7comm"],
        sectors: ["energy"],
      });

      for (let i = 1; i < matches.length; i++) {
        expect(matches[i - 1].matchScore).toBeGreaterThanOrEqual(matches[i].matchScore);
      }
    });

    it("should include relevant MITRE techniques in results", () => {
      const matches = matchAptGroups({
        vendors: ["Siemens"],
        protocols: ["s7comm"],
        sectors: ["energy"],
        deviceTypes: ["plc"],
      });

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0]).toHaveProperty("relevantTechniques");
    });

    it("should return higher confidence for exact vendor+protocol matches", () => {
      const energyMatches = matchAptGroups({
        vendors: ["Siemens"],
        protocols: ["s7comm"],
        sectors: ["energy"],
        deviceTypes: ["plc"],
      });

      const genericMatches = matchAptGroups({
        vendors: ["Unknown"],
        protocols: ["http"],
        sectors: ["other"],
        deviceTypes: ["unknown"],
      });

      const maxEnergy = Math.max(...energyMatches.map((m) => m.matchScore), 0);
      const maxGeneric = Math.max(...genericMatches.map((m) => m.matchScore), 0);

      expect(maxEnergy).toBeGreaterThan(maxGeneric);
    });
  });

  describe("searchIcsExploits", () => {
    it("should return an array of exploits", async () => {
      const results = await searchIcsExploits({});
      expect(Array.isArray(results)).toBe(true);
    });

    it("should filter by vendor", async () => {
      const results = await searchIcsExploits({ vendor: "Siemens" });
      expect(Array.isArray(results)).toBe(true);
    });

    it("should filter by protocol", async () => {
      const results = await searchIcsExploits({ protocol: "modbus" });
      expect(Array.isArray(results)).toBe(true);
    });

    it("should respect limit parameter", async () => {
      const results = await searchIcsExploits({ limit: 5 });
      expect(results.length).toBeLessThanOrEqual(5);
    });
  });

  describe("getTechniquesForDeviceType", () => {
    it("should return techniques relevant to PLCs", () => {
      const techniques = getTechniquesForDeviceType("plc");
      expect(Array.isArray(techniques)).toBe(true);
      expect(techniques.length).toBeGreaterThan(0);
    });

    it("should return techniques relevant to HMIs", () => {
      const techniques = getTechniquesForDeviceType("hmi");
      expect(Array.isArray(techniques)).toBe(true);
      expect(techniques.length).toBeGreaterThan(0);
    });

    it("should return techniques relevant to SCADA servers", () => {
      const techniques = getTechniquesForDeviceType("scada_server");
      expect(Array.isArray(techniques)).toBe(true);
      expect(techniques.length).toBeGreaterThan(0);
    });
  });

  describe("getTechniquesByTactic", () => {
    it("should return techniques for Initial Access tactic", () => {
      const techniques = getTechniquesByTactic("Initial Access");
      expect(Array.isArray(techniques)).toBe(true);
      expect(techniques.length).toBeGreaterThan(0);
    });

    it("should return techniques for Execution tactic", () => {
      const techniques = getTechniquesByTactic("Execution");
      expect(Array.isArray(techniques)).toBe(true);
      expect(techniques.length).toBeGreaterThan(0);
    });
  });

  describe("getIcsTactics", () => {
    it("should return a list of ICS tactics", () => {
      const tactics = getIcsTactics();
      expect(Array.isArray(tactics)).toBe(true);
      expect(tactics.length).toBeGreaterThanOrEqual(4);
    });

    it("should include Initial Access tactic", () => {
      const tactics = getIcsTactics();
      expect(tactics).toContain("Initial Access");
    });
  });

  describe("seedAptGroups", () => {
    it("should be a function", () => {
      expect(typeof seedAptGroups).toBe("function");
    });
  });
});

// ─── OT Protocol Analyzer ─────────────────────────────────────────────────────

describe("OT Protocol Analyzer", () => {
  describe("analyzeModbus", () => {
    it("should detect no-authentication vulnerability", () => {
      const result = analyzeModbus("Modbus/TCP", 502);
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.protocol).toBe("modbus");
    });

    it("should flag authentication issues", () => {
      const result = analyzeModbus("Modbus/TCP", 502);
      const hasAuthFinding = result.vulnerabilities.some(
        (f) =>
          f.title.toLowerCase().includes("auth") ||
          f.description.toLowerCase().includes("auth")
      );
      expect(hasAuthFinding).toBe(true);
    });

    it("should include recommendations", () => {
      const result = analyzeModbus("Modbus/TCP", 502);
      expect(result.recommendations.length).toBeGreaterThan(0);
    });
  });

  describe("analyzeS7comm", () => {
    it("should detect S7comm vulnerabilities", () => {
      const result = analyzeS7comm("Siemens S7-300", 102);
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.protocol).toBe("s7comm");
    });
  });

  describe("analyzeBacnet", () => {
    it("should detect BACnet vulnerabilities", () => {
      const result = analyzeBacnet("BACnet/IP", 47808);
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.protocol).toBe("bacnet");
    });
  });

  describe("analyzeMqtt", () => {
    it("should flag non-TLS MQTT on port 1883", () => {
      const result = analyzeMqtt("MQTT Broker", 1883);
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.protocol).toBe("mqtt");
    });

    it("should still analyze TLS MQTT on port 8883", () => {
      const result = analyzeMqtt("MQTT Broker TLS", 8883);
      expect(result.protocol).toBe("mqtt");
    });
  });

  describe("analyzeDnp3", () => {
    it("should detect DNP3 authentication issues", () => {
      const result = analyzeDnp3("DNP3", 20000);
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.protocol).toBe("dnp3");
    });
  });

  describe("analyzeOpcUa", () => {
    it("should analyze OPC-UA security", () => {
      const result = analyzeOpcUa("OPC-UA Server", 4840);
      expect(result.protocol).toBe("opcua");
    });
  });

  describe("analyzeIec104", () => {
    it("should analyze IEC 60870-5-104 security", () => {
      const result = analyzeIec104("IEC 104", 2404);
      expect(result.protocol).toBe("iec104");
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
    });
  });

  describe("analyzeProtocol (dispatcher)", () => {
    it("should dispatch to correct analyzer for modbus", () => {
      const result = analyzeProtocol("modbus", "Modbus/TCP", 502);
      expect(result).not.toBeNull();
      expect(result!.protocol).toBe("modbus");
    });

    it("should dispatch to correct analyzer for s7comm", () => {
      const result = analyzeProtocol("s7comm", "Siemens S7", 102);
      expect(result).not.toBeNull();
      expect(result!.protocol).toBe("s7comm");
    });

    it("should return null for unknown protocols", () => {
      const result = analyzeProtocol("unknown_proto", "banner", 9999);
      expect(result).toBeNull();
    });
  });

  describe("analyzeAllProtocols", () => {
    it("should analyze multiple protocols at once", () => {
      const results = analyzeAllProtocols(
        ["modbus", "s7comm"],
        "ICS device banner"
      );

      expect(results.length).toBe(2);
      expect(results[0].protocol).toBe("modbus");
      expect(results[1].protocol).toBe("s7comm");
    });
  });

  describe("getAggregateProtocolRisk", () => {
    it("should aggregate risk across multiple protocol analyses", () => {
      const modbusResult = analyzeModbus("Modbus/TCP", 502);
      const s7Result = analyzeS7comm("Siemens S7", 102);

      const aggregate = getAggregateProtocolRisk([modbusResult, s7Result]);
      expect(aggregate).toHaveProperty("overallScore");
      expect(aggregate).toHaveProperty("riskLevel");
      expect(aggregate).toHaveProperty("totalVulnerabilities");
      expect(aggregate.totalVulnerabilities).toBeGreaterThan(0);
    });

    it("should return low risk for empty input", () => {
      const aggregate = getAggregateProtocolRisk([]);
      expect(aggregate).toHaveProperty("overallScore");
      expect(aggregate.overallScore).toBe(0);
    });

    it("should rate critical for multiple unauthenticated ICS protocols", () => {
      const modbusResult = analyzeModbus("Modbus/TCP", 502);
      const s7Result = analyzeS7comm("Siemens S7", 102);
      const dnp3Result = analyzeDnp3("DNP3", 20000);

      const aggregate = getAggregateProtocolRisk([modbusResult, s7Result, dnp3Result]);
      expect(["critical", "high"]).toContain(aggregate.riskLevel);
    });
  });
});

// ─── Integration Tests ────────────────────────────────────────────────────────

describe("ICS Integration Tests", () => {
  it("should correlate APT groups with protocol vulnerabilities", () => {
    const aptMatches = matchAptGroups({
      vendors: ["Siemens"],
      protocols: ["s7comm"],
      sectors: ["energy"],
      deviceTypes: ["plc"],
    });

    const protocolAnalysis = analyzeS7comm("Siemens S7-1500", 102);

    expect(aptMatches.length).toBeGreaterThan(0);
    expect(protocolAnalysis.vulnerabilities.length).toBeGreaterThan(0);
  });

  it("should identify MITRE ATT&CK ICS techniques across all APT groups", () => {
    const allTechniques = new Set<string>();
    for (const tech of MITRE_ICS_TECHNIQUES) {
      allTechniques.add(tech.id);
    }

    expect(allTechniques.size).toBeGreaterThanOrEqual(20);
  });

  it("should fingerprint and then match APT groups for a discovered device", () => {
    const fingerprint = fingerprintDevice(
      "Schneider Electric Modicon M340 PLC",
      502,
      "Modicon M340"
    );

    const aptMatches = matchAptGroups({
      vendors: [fingerprint.vendor || "Unknown"],
      protocols: fingerprint.protocols,
      sectors: ["energy"],
      deviceTypes: [fingerprint.deviceType],
    });

    expect(fingerprint.vendor).toBeDefined();
    expect(aptMatches.length).toBeGreaterThan(0);
  });

  it("should calculate risk and match APTs for a critical OT scenario", () => {
    // Simulate discovering an internet-exposed Siemens PLC with default creds
    const riskScore = calculateIcsRiskScore({
      exposedToInternet: true,
      hasDefaultCredentials: true,
      hasKnownVulns: true,
      purdueLevel: "level_0",
      protocols: ["modbus", "s7comm"],
    });

    const aptMatches = matchAptGroups({
      vendors: ["Siemens"],
      protocols: ["modbus", "s7comm"],
      sectors: ["energy"],
      deviceTypes: ["plc"],
    });

    const protocolRisk = getAggregateProtocolRisk([
      analyzeModbus("Modbus/TCP", 502),
      analyzeS7comm("Siemens S7-1200", 102),
    ]);

    expect(riskScore).toBeGreaterThanOrEqual(70);
    expect(aptMatches.length).toBeGreaterThan(0);
    expect(protocolRisk.totalVulnerabilities).toBeGreaterThan(0);
  });
});
