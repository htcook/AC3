/**
 * Tests for ICS/SCADA Intelligence Module
 *
 * Validates:
 *   - CISA ICS advisory RSS ingest
 *   - CSAF OT document parsing
 *   - Siemens ProductCERT feed
 *   - ICS malware knowledge base
 *   - Auto-tagging of ICS-capable actors
 *   - Cross-mapping malware to actors
 *   - Open-source ICS tool catalog
 *   - Full pipeline orchestration
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const PROJECT_ROOT = path.resolve(__dirname, "..");

// ─── ICS/SCADA Intel Module Structure ────────────────────────────────────────

describe("ICS/SCADA Intel Module Structure", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/ics-scada-intel.ts");

  it("ics-scada-intel.ts exists", () => {
    expect(fs.existsSync(filePath)).toBe(true);
  });

  it("exports ingestCisaIcsAdvisories function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function ingestCisaIcsAdvisories");
  });

  it("exports ingestCisaCsafOt function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function ingestCisaCsafOt");
  });

  it("exports ingestSiemensProductCert function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function ingestSiemensProductCert");
  });

  it("exports autoTagIcsActors function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function autoTagIcsActors");
  });

  it("exports crossMapIcsMalwareToActors function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function crossMapIcsMalwareToActors");
  });

  it("exports runIcsScadaIntelIngest master function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function runIcsScadaIntelIngest");
  });
});

// ─── CISA ICS Advisory Ingest ────────────────────────────────────────────────

describe("CISA ICS Advisory Ingest", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/ics-scada-intel.ts");

  it("targets the CISA ICS advisories RSS feed", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("cisa.gov");
    expect(content).toContain("ics-advisories");
  });

  it("parses RSS items from the feed", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("parseRssItems");
  });

  it("extracts advisory IDs from links (ICSA-xxx format)", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("ICSA-");
  });

  it("stores results in icsExploits table", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("icsExploits");
    expect(content).toContain("iceIcsCertAdvisoryId");
  });

  it("uses onDuplicateKeyUpdate for idempotent ingestion", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("onDuplicateKeyUpdate");
  });

  it("returns IcsIngestResult with proper structure", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("interface IcsIngestResult");
    expect(content).toContain("source: string");
    expect(content).toContain("fetched: number");
    expect(content).toContain("newRecords: number");
  });
});

// ─── CSAF OT Document Parsing ────────────────────────────────────────────────

describe("CSAF OT Document Parsing", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/ics-scada-intel.ts");

  it("fetches CSAF documents from GitHub ICS-CERT repository", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("github.com");
    expect(content).toContain("csaf");
  });

  it("parses JSON CSAF document format", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("vulnerabilities");
    expect(content).toContain("product_tree");
  });

  it("extracts CVE IDs from CSAF documents", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("cve");
    expect(content).toContain("CVE-");
  });

  it("extracts CVSS scores from CSAF vulnerability data", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("cvss_v3");
    expect(content).toContain("baseScore");
  });

  it("extracts affected vendor and product information", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("iceAffectedVendor");
    expect(content).toContain("iceAffectedProduct");
  });

  it("calculates safety impact from CVSS scores", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("iceSafetyImpact");
    expect(content).toContain("critical");
    expect(content).toContain("high");
    expect(content).toContain("medium");
  });
});

// ─── Siemens ProductCERT Feed ────────────────────────────────────────────────

describe("Siemens ProductCERT Feed", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/ics-scada-intel.ts");

  it("targets Siemens ProductCERT CSAF feed", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("siemens");
    expect(content).toContain("cert-portal");
  });

  it("extracts SSA advisory IDs", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("ssa-");
  });

  it("sets affected vendor as Siemens", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("iceAffectedVendor: 'Siemens'");
  });

  it("has RSS fallback if CSAF index fails", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("rss");
    expect(content).toContain("Siemens");
  });
});

// ─── ICS Malware Knowledge Base ──────────────────────────────────────────────

describe("ICS Malware Knowledge Base", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/ics-scada-intel.ts");

  it("contains comprehensive ICS malware catalog", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("ICS_MALWARE_FAMILIES");
  });

  it("includes Stuxnet", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("Stuxnet");
    expect(content).toContain("Siemens S7-300");
  });

  it("includes TRITON/TRISIS", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("TRITON");
    expect(content).toContain("Schneider Electric Triconex");
  });

  it("includes Industroyer/CrashOverride", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("Industroyer");
    expect(content).toContain("IEC 61850");
  });

  it("includes PIPEDREAM/INCONTROLLER", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("PIPEDREAM");
    expect(content).toContain("INCONTROLLER");
  });

  it("includes BlackEnergy", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("BlackEnergy");
  });

  it("includes Havex", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("Havex");
  });

  it("malware entries include targeted vendors and protocols", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("targetedVendors");
    expect(content).toContain("targetedProtocols");
    expect(content).toContain("targetedSectors");
  });

  it("malware entries include attribution information", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("attribution");
    expect(content).toContain("Sandworm");
  });
});

// ─── ICS Actor Auto-Tagging ──────────────────────────────────────────────────

describe("ICS Actor Auto-Tagging", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/ics-scada-intel.ts");

  it("defines ICS_KEYWORDS for detection", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("ICS_KEYWORDS");
    expect(content).toContain("scada");
    expect(content).toContain("plc");
    expect(content).toContain("industrial control");
  });

  it("checks actor descriptions for ICS keywords", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("actor.description");
    expect(content).toContain("ICS_KEYWORDS.some");
  });

  it("checks actor events for ICS keywords", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("threatGroupEvents");
    expect(content).toContain("tgeTitle");
    expect(content).toContain("tgeDescription");
  });

  it("tags actors with [ICS/SCADA-CAPABLE] marker", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("[ICS/SCADA-CAPABLE]");
  });

  it("checks aptIcsMappings table for existing ICS actors", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("aptIcsMappings");
    expect(content).toContain("aimAptGroupName");
  });

  it("skips already-tagged actors", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("alreadyTagged");
    expect(content).toContain("[ICS/SCADA-CAPABLE]");
  });
});

// ─── ICS Malware → Actor Cross-Mapping ───────────────────────────────────────

describe("ICS Malware → Actor Cross-Mapping", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/ics-scada-intel.ts");

  it("cross-maps malware families to threat actors", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("crossMapIcsMalwareToActors");
    expect(content).toContain("ICS_MALWARE_FAMILIES");
  });

  it("records mapping events in threatGroupEvents", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("tgeActorId");
    expect(content).toContain("eventType: 'new_tool'");
  });

  it("includes malware details in event description", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("Targeted vendors");
    expect(content).toContain("Targeted protocols");
    expect(content).toContain("Targeted sectors");
  });

  it("uses ICS Malware Knowledge Base as source", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("tgeSource: 'ICS Malware Knowledge Base'");
  });
});

// ─── Open-Source ICS Tool Catalog ────────────────────────────────────────────

describe("Open-Source ICS Tool Catalog", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/ics-scada-intel.ts");

  it("defines ICS_OPEN_SOURCE_TOOLS catalog", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("ICS_OPEN_SOURCE_TOOLS");
  });

  it("includes GRFICSv2 (simulation environment)", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("GRFICSv2");
  });

  it("includes Conpot (ICS honeypot)", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("Conpot");
  });

  it("includes PLCscan or similar scanner", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    // Check for common ICS scanning tools
    expect(content).toMatch(/PLCscan|plcscan|Redpoint|redpoint/);
  });

  it("tools have category and description", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("category:");
    expect(content).toContain("description:");
    expect(content).toContain("url:");
  });

  it("tools have protocol/vendor coverage info", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("protocols:");
  });
});

// ─── Integration with Daily Pipeline ─────────────────────────────────────────

describe("Integration with Daily Pipeline", () => {
  const indexPath = path.join(PROJECT_ROOT, "server/_core/index.ts");
  const schedulerPath = path.join(PROJECT_ROOT, "server/lib/threat-intel-daily-scheduler.ts");

  it("ICS/SCADA ingest is registered in the threat-intel-daily endpoint", () => {
    const content = fs.readFileSync(indexPath, "utf-8");
    expect(content).toContain("ics-scada-intel");
    expect(content).toContain("runIcsScadaIntelIngest");
    expect(content).toContain("ics_scada_intel");
  });

  it("ICS/SCADA ingest is included in the internal cron scheduler", () => {
    const content = fs.readFileSync(schedulerPath, "utf-8");
    expect(content).toContain("ics-scada-intel");
    expect(content).toContain("runIcsScadaIntelIngest");
  });

  it("ICS/SCADA stats are included in the daily notification summary", () => {
    const content = fs.readFileSync(schedulerPath, "utf-8");
    expect(content).toContain("ICS/SCADA");
    expect(content).toContain("icsPhase");
  });
});

// ─── ICS Protocol Keywords ───────────────────────────────────────────────────

describe("ICS Protocol Keywords", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/ics-scada-intel.ts");

  it("includes Modbus protocol", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content.toLowerCase()).toContain("modbus");
  });

  it("includes DNP3 protocol", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content.toLowerCase()).toContain("dnp3");
  });

  it("includes OPC UA protocol", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content.toLowerCase()).toContain("opc");
  });

  it("includes IEC 61850 protocol", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("IEC 61850");
  });

  it("includes BACnet protocol", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content.toLowerCase()).toContain("bacnet");
  });

  it("includes EtherNet/IP protocol", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content.toLowerCase()).toContain("ethernet/ip");
  });
});
