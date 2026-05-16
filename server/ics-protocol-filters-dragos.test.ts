/**
 * Tests for ICS Protocol Filters, Start ICS Engagement, and Dragos RSS Feed
 */
import { describe, it, expect } from "vitest";
import { THREAT_INTEL_FEEDS, parseRSSXml } from "./lib/threat-intel-rss";
import { ICS_MALWARE_FAMILIES, ICS_OPEN_SOURCE_TOOLS } from "./lib/ics-scada-intel";

// ─── Dragos & ICS/OT RSS Feeds ──────────────────────────────────────────────

describe("Dragos & ICS/OT RSS Feed Registration", () => {
  it("should include Dragos Blog feed", () => {
    const feed = THREAT_INTEL_FEEDS.find(f => f.id === "dragos-blog");
    expect(feed).toBeDefined();
    expect(feed!.name).toBe("Dragos Blog (ICS/OT)");
    expect(feed!.url).toBe("https://www.dragos.com/blog/feed/");
    expect(feed!.tier).toBe(3);
    expect(feed!.category).toBe("vendor_research");
    expect(feed!.targets).toContain("threat_group_events");
    expect(feed!.targets).toContain("incident_reports");
    expect(feed!.enabled).toBe(true);
  });

  it("should include Dragos Threat Intelligence feed", () => {
    const feed = THREAT_INTEL_FEEDS.find(f => f.id === "dragos-threat-intel");
    expect(feed).toBeDefined();
    expect(feed!.name).toBe("Dragos Threat Intelligence");
    expect(feed!.url).toBe("https://www.dragos.com/threat/feed/");
    expect(feed!.tier).toBe(3);
    expect(feed!.category).toBe("threat_intel");
    expect(feed!.targets).toContain("threat_group_events");
    expect(feed!.enabled).toBe(true);
  });

  it("should include Claroty Team82 Research feed", () => {
    const feed = THREAT_INTEL_FEEDS.find(f => f.id === "claroty-research");
    expect(feed).toBeDefined();
    expect(feed!.name).toBe("Claroty Team82 Research");
    expect(feed!.url).toContain("claroty.com");
    expect(feed!.tier).toBe(3);
    expect(feed!.enabled).toBe(true);
  });

  it("should include Nozomi Networks Labs feed", () => {
    const feed = THREAT_INTEL_FEEDS.find(f => f.id === "nozomi-labs");
    expect(feed).toBeDefined();
    expect(feed!.name).toBe("Nozomi Networks Labs");
    expect(feed!.url).toContain("nozominetworks.com");
    expect(feed!.tier).toBe(3);
    expect(feed!.enabled).toBe(true);
  });

  it("should have at least 4 ICS/OT specific feeds", () => {
    const icsFeeds = THREAT_INTEL_FEEDS.filter(f =>
      f.id.includes("dragos") || f.id.includes("claroty") || f.id.includes("nozomi")
    );
    expect(icsFeeds.length).toBeGreaterThanOrEqual(4);
  });

  it("should have all ICS/OT feeds enabled by default", () => {
    const icsFeeds = THREAT_INTEL_FEEDS.filter(f =>
      f.id.includes("dragos") || f.id.includes("claroty") || f.id.includes("nozomi")
    );
    for (const feed of icsFeeds) {
      expect(feed.enabled).toBe(true);
    }
  });
});

// ─── ICS/OT Threat Group Names in KNOWN_THREAT_GROUPS ───────────────────────

describe("ICS/OT Threat Groups in RSS Parser", () => {
  it("should parse Dragos-style RSS with ICS group mentions", () => {
    const mockRss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
<title>Dragos Blog</title>
<item>
<title>CHERNOVITE Activity Group Targets Energy Sector</title>
<link>https://www.dragos.com/blog/chernovite-energy/</link>
<pubDate>Mon, 12 May 2025 10:00:00 GMT</pubDate>
<description>Analysis of CHERNOVITE targeting energy infrastructure with PIPEDREAM toolset.</description>
<category>ICS Threat Intelligence</category>
</item>
<item>
<title>XENOTIME Resurfaces with New Capabilities</title>
<link>https://www.dragos.com/blog/xenotime-new/</link>
<pubDate>Sun, 11 May 2025 08:00:00 GMT</pubDate>
<description>XENOTIME, the group behind TRITON/TRISIS, shows new activity patterns.</description>
<category>Threat Activity</category>
</item>
</channel>
</rss>`;

    const parsed = parseRSSXml(mockRss);
    expect(parsed.title).toBe("Dragos Blog");
    expect(parsed.items).toHaveLength(2);
    expect(parsed.items[0].title).toContain("CHERNOVITE");
    expect(parsed.items[1].title).toContain("XENOTIME");
    expect(parsed.items[0].description).toContain("PIPEDREAM");
  });

  it("should parse Atom-format feeds (CISA ICS advisories)", () => {
    const mockAtom = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<title>CISA ICS Advisories</title>
<entry>
<title>Siemens SIMATIC S7-1500 Vulnerability</title>
<link href="https://www.cisa.gov/news-events/ics-advisories/icsa-25-100-01" />
<published>2025-04-10T12:00:00Z</published>
<summary>A critical vulnerability in Siemens SIMATIC S7-1500 PLCs allows remote code execution via S7comm protocol.</summary>
<id>icsa-25-100-01</id>
</entry>
</feed>`;

    const parsed = parseRSSXml(mockAtom);
    expect(parsed.title).toBe("CISA ICS Advisories");
    expect(parsed.items).toHaveLength(1);
    expect(parsed.items[0].title).toContain("Siemens");
    expect(parsed.items[0].link).toContain("ics-advisories");
    expect(parsed.items[0].guid).toBe("icsa-25-100-01");
  });
});

// ─── ICS Protocol Filtering Logic ──────────────────────────────────────────

describe("ICS Protocol Filtering", () => {
  const ICS_PROTOCOLS = [
    "modbus", "dnp3", "s7comm", "bacnet", "ethernet/ip", "opc ua", "opc da",
    "iec104", "iec61850", "profinet", "codesys", "tristation", "mqtt", "m-bus",
  ];

  it("should define all major ICS protocols", () => {
    expect(ICS_PROTOCOLS).toContain("modbus");
    expect(ICS_PROTOCOLS).toContain("dnp3");
    expect(ICS_PROTOCOLS).toContain("s7comm");
    expect(ICS_PROTOCOLS).toContain("bacnet");
    expect(ICS_PROTOCOLS).toContain("ethernet/ip");
    expect(ICS_PROTOCOLS).toContain("opc ua");
    expect(ICS_PROTOCOLS).toContain("iec104");
    expect(ICS_PROTOCOLS).toContain("profinet");
    expect(ICS_PROTOCOLS).toContain("codesys");
    expect(ICS_PROTOCOLS).toContain("tristation");
  });

  it("should filter malware families by protocol", () => {
    const modbusTargeting = ICS_MALWARE_FAMILIES.filter(m =>
      m.targetedProtocols.some(p => p.toLowerCase().includes("modbus"))
    );
    expect(modbusTargeting.length).toBeGreaterThan(0);
    // BlackEnergy, PIPEDREAM, FrostyGoop all target Modbus
    const names = modbusTargeting.map(m => m.name);
    expect(names.some(n => n.includes("BlackEnergy") || n.includes("PIPEDREAM") || n.includes("FrostyGoop"))).toBe(true);
  });

  it("should filter malware families by S7comm protocol", () => {
    const s7commTargeting = ICS_MALWARE_FAMILIES.filter(m =>
      m.targetedProtocols.some(p => p.toLowerCase().includes("s7comm"))
    );
    expect(s7commTargeting.length).toBeGreaterThan(0);
    // Stuxnet targets S7comm
    expect(s7commTargeting.some(m => m.name === "Stuxnet")).toBe(true);
  });

  it("should filter malware families by IEC 104 protocol", () => {
    const iec104Targeting = ICS_MALWARE_FAMILIES.filter(m =>
      m.targetedProtocols.some(p => p.toLowerCase().includes("iec104"))
    );
    expect(iec104Targeting.length).toBeGreaterThan(0);
    // Industroyer targets IEC 104
    expect(iec104Targeting.some(m => m.name === "Industroyer" || m.name === "Industroyer2")).toBe(true);
  });

  it("should filter tools by protocol", () => {
    const modbusTools = ICS_OPEN_SOURCE_TOOLS.filter(t =>
      t.protocols.some(p => p.toLowerCase().includes("modbus"))
    );
    expect(modbusTools.length).toBeGreaterThan(0);
  });

  it("should filter tools by category", () => {
    const honeypots = ICS_OPEN_SOURCE_TOOLS.filter(t => t.category === "honeypot");
    expect(honeypots.length).toBeGreaterThan(0);
    const assessmentTools = ICS_OPEN_SOURCE_TOOLS.filter(t => t.category === "assessment");
    expect(assessmentTools.length).toBeGreaterThan(0);
  });
});

// ─── ICS Vendor Filtering ──────────────────────────────────────────────────

describe("ICS Vendor Filtering", () => {
  const ICS_VENDORS = [
    "Siemens", "Schneider Electric", "Rockwell", "ABB", "Honeywell",
    "OMRON", "Emerson", "GE", "Yokogawa", "Mitsubishi",
  ];

  it("should define all major ICS vendors", () => {
    expect(ICS_VENDORS).toContain("Siemens");
    expect(ICS_VENDORS).toContain("Schneider Electric");
    expect(ICS_VENDORS).toContain("Rockwell");
    expect(ICS_VENDORS).toContain("ABB");
    expect(ICS_VENDORS).toContain("Honeywell");
  });

  it("should filter malware families by Siemens vendor", () => {
    const siemensTargeting = ICS_MALWARE_FAMILIES.filter(m =>
      m.targetedVendors.some(v => v.toLowerCase().includes("siemens"))
    );
    expect(siemensTargeting.length).toBeGreaterThan(0);
    // Stuxnet targets Siemens
    expect(siemensTargeting.some(m => m.name === "Stuxnet")).toBe(true);
  });

  it("should filter malware families by Schneider vendor", () => {
    const schneiderTargeting = ICS_MALWARE_FAMILIES.filter(m =>
      m.targetedVendors.some(v => v.toLowerCase().includes("schneider"))
    );
    expect(schneiderTargeting.length).toBeGreaterThan(0);
    // TRITON targets Schneider
    expect(schneiderTargeting.some(m => m.name === "TRITON")).toBe(true);
  });
});

// ─── Start ICS Engagement Pre-fill Logic ────────────────────────────────────

describe("Start ICS Engagement Pre-fill", () => {
  it("should map malware families to engagement context", () => {
    const stuxnet = ICS_MALWARE_FAMILIES.find(m => m.name === "Stuxnet");
    expect(stuxnet).toBeDefined();

    // Simulating what the dialog does
    const engagementContext = {
      name: stuxnet!.attribution,
      techniques: stuxnet!.mitreIcsTechniques,
      protocols: stuxnet!.targetedProtocols,
      vendors: stuxnet!.targetedVendors,
    };

    expect(engagementContext.name).toContain("Equation Group");
    expect(engagementContext.techniques.length).toBeGreaterThan(0);
    expect(engagementContext.techniques[0]).toMatch(/^T\d{4}$/);
    expect(engagementContext.protocols).toContain("s7comm");
    expect(engagementContext.vendors).toContain("Siemens");
  });

  it("should detect ICS techniques for template selection", () => {
    const stuxnet = ICS_MALWARE_FAMILIES.find(m => m.name === "Stuxnet");
    const hasIcsTechniques = stuxnet!.mitreIcsTechniques.some(t => t.startsWith("T08"));
    // ICS MITRE techniques start with T08xx
    expect(hasIcsTechniques).toBe(true);
  });

  it("should recommend tools based on selected protocols", () => {
    const selectedProtocols = ["modbus", "s7comm"];
    const recommendedTools = ICS_OPEN_SOURCE_TOOLS.filter(tool =>
      tool.protocols.some(p => selectedProtocols.includes(p.toLowerCase()))
    );
    expect(recommendedTools.length).toBeGreaterThan(0);
  });

  it("should recommend tools based on engagement category", () => {
    // For assessment engagements
    const assessmentTools = ICS_OPEN_SOURCE_TOOLS.filter(t => t.category === "assessment");
    expect(assessmentTools.length).toBeGreaterThan(0);

    // For adversary emulation engagements
    const simulationTools = ICS_OPEN_SOURCE_TOOLS.filter(t =>
      t.category === "simulation" || t.category === "framework"
    );
    expect(simulationTools.length).toBeGreaterThan(0);
  });
});

// ─── Feed Count Validation ──────────────────────────────────────────────────

describe("Total Feed Count", () => {
  it("should have at least 20 feeds registered (including ICS/OT)", () => {
    expect(THREAT_INTEL_FEEDS.length).toBeGreaterThanOrEqual(20);
  });

  it("should have at least 14 enabled feeds", () => {
    const enabled = THREAT_INTEL_FEEDS.filter(f => f.enabled);
    expect(enabled.length).toBeGreaterThanOrEqual(14);
  });

  it("should have feeds across all 4 tiers", () => {
    const tiers = new Set(THREAT_INTEL_FEEDS.map(f => f.tier));
    expect(tiers.has(1)).toBe(true);
    expect(tiers.has(2)).toBe(true);
    expect(tiers.has(3)).toBe(true);
    expect(tiers.has(4)).toBe(true);
  });
});
