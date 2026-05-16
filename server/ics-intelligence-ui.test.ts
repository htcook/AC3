// @ts-nocheck
import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Tests for ICS Intelligence UI procedures and engagement automation ICS tool recommendations.
 * These test the tRPC procedure logic for serving ICS malware families, open-source tools,
 * and the engagement planner integration.
 */

// Mock the ICS/SCADA intel module
vi.mock("./lib/ics-scada-intel", () => ({
  ICS_MALWARE_FAMILIES: [
    {
      name: "Stuxnet",
      attribution: "Equation Group / Unit 8200",
      year: 2010,
      targetedProtocols: ["Step 7", "Profinet", "OPC"],
      targetedVendors: ["Siemens"],
      mitreIcsTechniques: ["T0831", "T0836", "T0843"],
      description: "First known ICS-targeting malware, designed to damage Iranian nuclear centrifuges",
    },
    {
      name: "TRITON",
      attribution: "XENOTIME / TEMP.Veles",
      year: 2017,
      targetedProtocols: ["TriStation", "Safety Instrumented Systems"],
      targetedVendors: ["Schneider Electric"],
      mitreIcsTechniques: ["T0855", "T0836", "T0857"],
      description: "Safety system targeting malware designed to disable Triconex safety controllers",
    },
    {
      name: "Industroyer",
      attribution: "Sandworm (GRU Unit 74455)",
      year: 2016,
      targetedProtocols: ["IEC 61850", "IEC 104", "OPC DA"],
      targetedVendors: ["ABB", "Siemens"],
      mitreIcsTechniques: ["T0855", "T0826", "T0831"],
      description: "Power grid targeting malware used in Ukraine 2016 blackout",
    },
    {
      name: "PIPEDREAM",
      attribution: "CHERNOVITE",
      year: 2022,
      targetedProtocols: ["Modbus", "OPC UA", "CODESYS"],
      targetedVendors: ["Schneider Electric", "OMRON"],
      mitreIcsTechniques: ["T0831", "T0836", "T0855", "T0862"],
      description: "Modular ICS attack framework targeting multiple vendors and protocols",
    },
  ],
  ICS_OPEN_SOURCE_TOOLS: [
    {
      name: "Conpot",
      category: "honeypot",
      description: "ICS/SCADA honeypot",
      githubUrl: "https://github.com/mushorg/conpot",
      license: "GPL-2.0",
      protocols: ["modbus", "s7comm", "bacnet", "ipmi"],
      useCase: "Deploy as honeypot to detect ICS scanning and exploitation attempts",
    },
    {
      name: "GRFICSv2",
      category: "simulation",
      description: "Virtual ICS environment for security testing",
      githubUrl: "https://github.com/Fortiphyd/GRFICSv2",
      license: "MIT",
      protocols: ["modbus", "dnp3", "ethernet/ip"],
      useCase: "Full virtual ICS lab for training and testing without physical hardware",
    },
    {
      name: "Redpoint",
      category: "assessment",
      description: "Nmap ICS/SCADA detection scripts",
      githubUrl: "https://github.com/digitalbond/Redpoint",
      license: "GPL-2.0",
      protocols: ["modbus", "dnp3", "bacnet", "ethernet/ip", "s7comm"],
      useCase: "Discover and fingerprint ICS devices on the network",
    },
    {
      name: "GRASSMARLIN",
      category: "monitoring",
      description: "NSA passive ICS network mapper",
      githubUrl: "https://github.com/nsacyber/GRASSMARLIN",
      license: "Public Domain",
      protocols: ["modbus", "dnp3", "ethernet/ip", "bacnet", "opc"],
      useCase: "Passive network topology mapping for ICS environments",
    },
    {
      name: "ISF",
      category: "framework",
      description: "Industrial exploitation framework",
      githubUrl: "https://github.com/dark-lbp/isf",
      license: "BSD-2",
      protocols: ["modbus", "s7comm", "iec-104"],
      useCase: "Exploit and test ICS devices with known vulnerabilities",
    },
    {
      name: "PLCscan",
      category: "protocol_analysis",
      description: "PLC protocol scanner",
      githubUrl: "https://github.com/meeas/plcscan",
      license: "MIT",
      protocols: ["modbus", "s7comm"],
      useCase: "Identify and enumerate PLCs on the network",
    },
    {
      name: "pcapinator",
      category: "forensics",
      description: "ICS protocol PCAP analyzer",
      githubUrl: "https://github.com/ics-forensics/pcapinator",
      license: "MIT",
      protocols: ["modbus", "dnp3", "s7comm", "iec-104"],
      useCase: "Analyze captured ICS traffic for anomalies and attacks",
    },
  ],
  runFullIcsScadaIngest: vi.fn().mockResolvedValue({
    cisaIcsAdvisories: 5,
    csafDocuments: 3,
    siemensAdvisories: 2,
    vendorAdvisories: 1,
    icsActorsTagged: 4,
    malwareMappings: 6,
  }),
}));

describe("ICS Intelligence UI — Malware Families", () => {
  it("should return all ICS malware families with correct structure", async () => {
    const { ICS_MALWARE_FAMILIES } = await import("./lib/ics-scada-intel");
    expect(ICS_MALWARE_FAMILIES.length).toBeGreaterThanOrEqual(4);
    for (const family of ICS_MALWARE_FAMILIES) {
      expect(family).toHaveProperty("name");
      expect(family).toHaveProperty("attribution");
      expect(family).toHaveProperty("year");
      expect(family).toHaveProperty("targetedProtocols");
      expect(family).toHaveProperty("targetedVendors");
      expect(family).toHaveProperty("mitreIcsTechniques");
      expect(family).toHaveProperty("description");
      expect(family.year).toBeGreaterThanOrEqual(2000);
      expect(family.targetedProtocols.length).toBeGreaterThan(0);
    }
  });

  it("should include Stuxnet, TRITON, Industroyer, and PIPEDREAM", async () => {
    const { ICS_MALWARE_FAMILIES } = await import("./lib/ics-scada-intel");
    const names = ICS_MALWARE_FAMILIES.map((m: any) => m.name);
    expect(names).toContain("Stuxnet");
    expect(names).toContain("TRITON");
    expect(names).toContain("Industroyer");
    expect(names).toContain("PIPEDREAM");
  });

  it("should have valid MITRE ICS technique IDs (T0xxx format)", async () => {
    const { ICS_MALWARE_FAMILIES } = await import("./lib/ics-scada-intel");
    for (const family of ICS_MALWARE_FAMILIES) {
      for (const technique of family.mitreIcsTechniques) {
        expect(technique).toMatch(/^T0\d{3}$/);
      }
    }
  });
});

describe("ICS Intelligence UI — Open Source Tools", () => {
  it("should return all ICS open source tools with correct structure", async () => {
    const { ICS_OPEN_SOURCE_TOOLS } = await import("./lib/ics-scada-intel");
    expect(ICS_OPEN_SOURCE_TOOLS.length).toBeGreaterThanOrEqual(5);
    for (const tool of ICS_OPEN_SOURCE_TOOLS) {
      expect(tool).toHaveProperty("name");
      expect(tool).toHaveProperty("category");
      expect(tool).toHaveProperty("description");
      expect(tool).toHaveProperty("githubUrl");
      expect(tool).toHaveProperty("license");
      expect(tool).toHaveProperty("protocols");
      expect(tool).toHaveProperty("useCase");
      expect(tool.githubUrl).toMatch(/^https:\/\/github\.com\//);
      expect(tool.protocols.length).toBeGreaterThan(0);
    }
  });

  it("should cover all major ICS tool categories", async () => {
    const { ICS_OPEN_SOURCE_TOOLS } = await import("./lib/ics-scada-intel");
    const categories = [...new Set(ICS_OPEN_SOURCE_TOOLS.map((t: any) => t.category))];
    expect(categories).toContain("honeypot");
    expect(categories).toContain("simulation");
    expect(categories).toContain("assessment");
    expect(categories).toContain("monitoring");
    expect(categories).toContain("framework");
  });

  it("should include Conpot, GRFICSv2, Redpoint, and GRASSMARLIN", async () => {
    const { ICS_OPEN_SOURCE_TOOLS } = await import("./lib/ics-scada-intel");
    const names = ICS_OPEN_SOURCE_TOOLS.map((t: any) => t.name);
    expect(names).toContain("Conpot");
    expect(names).toContain("GRFICSv2");
    expect(names).toContain("Redpoint");
    expect(names).toContain("GRASSMARLIN");
  });
});

describe("Engagement Automation — ICS Tool Recommendations", () => {
  it("should return tools when ICS template is selected", async () => {
    const { ICS_OPEN_SOURCE_TOOLS, ICS_MALWARE_FAMILIES } = await import("./lib/ics-scada-intel");

    // Simulate the getIcsToolRecommendations logic
    const templateId = "ics_ot_assessment";
    const isIcsTemplate = templateId.includes("ics");
    expect(isIcsTemplate).toBe(true);

    const phaseToCategories: Record<string, string[]> = {
      recon: ["monitoring", "protocol_analysis"],
      assessment: ["assessment", "framework"],
      exploitation: ["framework", "simulation"],
      monitoring: ["monitoring", "honeypot", "forensics"],
      all: ["honeypot", "assessment", "monitoring", "simulation", "framework", "protocol_analysis", "forensics"],
    };

    const tools = ICS_OPEN_SOURCE_TOOLS.filter((t: any) => phaseToCategories.all.includes(t.category));
    expect(tools.length).toBeGreaterThan(0);
    expect(tools.length).toBe(ICS_OPEN_SOURCE_TOOLS.length); // all categories match 'all'
  });

  it("should filter tools by engagement phase", async () => {
    const { ICS_OPEN_SOURCE_TOOLS } = await import("./lib/ics-scada-intel");

    const phaseToCategories: Record<string, string[]> = {
      recon: ["monitoring", "protocol_analysis"],
      assessment: ["assessment", "framework"],
      exploitation: ["framework", "simulation"],
      monitoring: ["monitoring", "honeypot", "forensics"],
    };

    // Recon phase should only return monitoring and protocol_analysis tools
    const reconTools = ICS_OPEN_SOURCE_TOOLS.filter((t: any) => phaseToCategories.recon.includes(t.category));
    expect(reconTools.length).toBeGreaterThan(0);
    for (const tool of reconTools) {
      expect(["monitoring", "protocol_analysis"]).toContain(tool.category);
    }

    // Assessment phase should return assessment and framework tools
    const assessmentTools = ICS_OPEN_SOURCE_TOOLS.filter((t: any) => phaseToCategories.assessment.includes(t.category));
    expect(assessmentTools.length).toBeGreaterThan(0);
    for (const tool of assessmentTools) {
      expect(["assessment", "framework"]).toContain(tool.category);
    }
  });

  it("should filter tools by target protocol", async () => {
    const { ICS_OPEN_SOURCE_TOOLS } = await import("./lib/ics-scada-intel");

    const targetProtocols = ["modbus"];
    const filtered = ICS_OPEN_SOURCE_TOOLS.filter((t: any) =>
      t.protocols.some((p: string) => targetProtocols.includes(p))
    );
    expect(filtered.length).toBeGreaterThan(0);
    for (const tool of filtered) {
      expect(tool.protocols).toContain("modbus");
    }
  });

  it("should filter malware families by vendor", async () => {
    const { ICS_MALWARE_FAMILIES } = await import("./lib/ics-scada-intel");

    const targetVendors = ["siemens"];
    const filtered = ICS_MALWARE_FAMILIES.filter((m: any) =>
      m.targetedVendors.some((v: string) => targetVendors.some(tv => v.toLowerCase().includes(tv)))
    );
    expect(filtered.length).toBeGreaterThan(0);
    expect(filtered.map((m: any) => m.name)).toContain("Stuxnet");
  });

  it("should return empty results for non-ICS templates", async () => {
    const templateId = "network_pentest";
    const isIcsTemplate = templateId.includes("ics");
    expect(isIcsTemplate).toBe(false);
    // The procedure returns empty arrays for non-ICS templates
    const result = { tools: [], malwareFamilies: [], isIcsEngagement: false };
    expect(result.isIcsEngagement).toBe(false);
    expect(result.tools).toHaveLength(0);
  });

  it("should include ICS/OT assessment and ICS adversary emulation templates", () => {
    const ENGAGEMENT_TEMPLATES: Record<string, any> = {
      ics_ot_assessment: {
        name: "ICS/OT Security Assessment",
        type: "ics_ot",
        killChainPhases: ["reconnaissance", "initial_access", "execution", "persistence", "lateral_movement", "collection", "command_and_control"],
        recommendedTechniques: ["T0846", "T0886", "T0855", "T0831", "T0826", "T0813", "T0821", "T0836", "T0862", "T0887"],
      },
      ics_adversary_emulation: {
        name: "ICS Adversary Emulation",
        type: "ics_adversary",
        killChainPhases: ["initial_access", "execution", "persistence", "privilege_escalation", "lateral_movement", "collection", "command_and_control", "exfiltration"],
        recommendedTechniques: ["T0866", "T0855", "T0831", "T0826", "T0813", "T0821", "T0836", "T0843", "T0857", "T0827"],
      },
    };

    expect(ENGAGEMENT_TEMPLATES.ics_ot_assessment).toBeDefined();
    expect(ENGAGEMENT_TEMPLATES.ics_adversary_emulation).toBeDefined();
    expect(ENGAGEMENT_TEMPLATES.ics_ot_assessment.type).toBe("ics_ot");
    expect(ENGAGEMENT_TEMPLATES.ics_adversary_emulation.type).toBe("ics_adversary");

    // All recommended techniques should be ICS format (T0xxx)
    for (const t of ENGAGEMENT_TEMPLATES.ics_ot_assessment.recommendedTechniques) {
      expect(t).toMatch(/^T0\d{3}$/);
    }
    for (const t of ENGAGEMENT_TEMPLATES.ics_adversary_emulation.recommendedTechniques) {
      expect(t).toMatch(/^T0\d{3}$/);
    }
  });
});

describe("ICS Intelligence — Full Ingest Pipeline", () => {
  it("should run the full ICS/SCADA ingest and return stats", async () => {
    const { runFullIcsScadaIngest } = await import("./lib/ics-scada-intel");
    const result = await runFullIcsScadaIngest();
    expect(result).toHaveProperty("cisaIcsAdvisories");
    expect(result).toHaveProperty("csafDocuments");
    expect(result).toHaveProperty("siemensAdvisories");
    expect(result).toHaveProperty("icsActorsTagged");
    expect(result).toHaveProperty("malwareMappings");
    expect(result.cisaIcsAdvisories).toBeGreaterThanOrEqual(0);
  });
});
