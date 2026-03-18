import { describe, it, expect } from "vitest";
import {
  parseDfirReportHtml,
  parseCisaStix,
  parseOtxPulse,
  parseManualReport,
  autoDetectAndParse,
  type ParsedDfirReport,
} from "./lib/dfir-report-parser";

/**
 * DFIR Report Parser & Training Bridge Tests
 *
 * Tests cover:
 * 1. DFIR Report HTML parsing (IOC extraction, technique extraction)
 * 2. CISA STIX bundle parsing
 * 3. OTX pulse parsing
 * 4. Manual report parsing (markdown/plain text)
 * 5. Auto-detection of report format
 * 6. Engagement training bridge module existence
 * 7. _caller compliance for invokeLLM calls in DFIR library router
 */

// ── Sample DFIR Report HTML ──
const DFIR_HTML = `
<html>
<head><title>Fake Zoom Ends in BlackSuit Ransomware</title></head>
<body>
<article>
<h1 class="entry-title">Fake Zoom Ends in BlackSuit Ransomware</h1>
<div class="entry-content">
<p>In this intrusion, the threat actors used a fake Zoom installer to deliver IcedID malware.</p>
<p>The initial access was achieved through a phishing email containing a link to a fake Zoom download page.</p>
<p>After gaining access, the threat actors deployed Cobalt Strike beacons for lateral movement.</p>
<p>The final payload was BlackSuit ransomware, which encrypted files across the network.</p>
<h2>MITRE ATT&CK</h2>
<table>
<tr><th>Tactic</th><th>Technique</th><th>ID</th></tr>
<tr><td>Initial Access</td><td>Phishing</td><td>T1566.002</td></tr>
<tr><td>Execution</td><td>User Execution</td><td>T1204.002</td></tr>
<tr><td>Defense Evasion</td><td>Masquerading</td><td>T1036.005</td></tr>
<tr><td>Command and Control</td><td>Application Layer Protocol</td><td>T1071.001</td></tr>
<tr><td>Impact</td><td>Data Encrypted for Impact</td><td>T1486</td></tr>
</table>
<h2>Indicators of Compromise</h2>
<p>IP: 192.168.1.100</p>
<p>IP: 10.0.0.50</p>
<p>Domain: evil-zoom.example.com</p>
<p>Domain: c2.malware-domain.net</p>
<p>Hash: d41d8cd98f00b204e9800998ecf8427e</p>
<p>Hash: 5d41402abc4b2a76b9719d911017c592abc4b2a76b9719d911017c592</p>
<p>CVE-2023-1234</p>
<p>CVE-2024-5678</p>
</div>
</article>
</body>
</html>`;

// ── Sample CISA STIX Bundle ──
const CISA_STIX = {
  type: "bundle",
  id: "bundle--abc123",
  objects: [
    {
      type: "report",
      id: "report--def456",
      name: "CISA Alert: APT29 Activity",
      description: "CISA advisory on APT29 targeting government networks.",
      published: "2025-01-15T00:00:00Z",
      labels: ["apt", "government"],
      object_refs: ["indicator--111", "attack-pattern--222"],
    },
    {
      type: "indicator",
      id: "indicator--111",
      name: "Malicious IP",
      pattern: "[ipv4-addr:value = '203.0.113.50']",
      labels: ["malicious-activity"],
    },
    {
      type: "attack-pattern",
      id: "attack-pattern--222",
      name: "Spearphishing Attachment",
      external_references: [
        { source_name: "mitre-attack", external_id: "T1566.001" },
      ],
    },
    {
      type: "malware",
      id: "malware--333",
      name: "SUNBURST",
      labels: ["backdoor"],
    },
    {
      type: "threat-actor",
      id: "threat-actor--444",
      name: "APT29",
      aliases: ["Cozy Bear"],
    },
  ],
};

// ── Sample OTX Pulse ──
const OTX_PULSE = {
  id: "pulse-789",
  name: "Lazarus Group Campaign 2025",
  description: "New campaign by Lazarus Group targeting cryptocurrency exchanges.",
  created: "2025-02-20T12:00:00Z",
  tags: ["lazarus", "cryptocurrency", "apt"],
  attack_ids: [
    { id: "T1059.001", name: "PowerShell" },
    { id: "T1027", name: "Obfuscated Files" },
  ],
  indicators: [
    { type: "IPv4", indicator: "198.51.100.25", title: "C2 Server" },
    { type: "domain", indicator: "lazarus-c2.example.com", title: "C2 Domain" },
    { type: "FileHash-SHA256", indicator: "a" .repeat(64), title: "Malware Hash" },
    { type: "CVE", indicator: "CVE-2025-0001", title: "Exploited CVE" },
  ],
};

// ── DFIR Report HTML Parser Tests ──
describe("DFIR Report HTML Parser", () => {
  it("should extract title from HTML", () => {
    const result = parseDfirReportHtml(DFIR_HTML, "https://thedfirreport.com/2025/03/31/fake-zoom/");
    expect(result.title).toBe("Fake Zoom Ends in BlackSuit Ransomware");
  });

  it("should extract MITRE ATT&CK technique IDs", () => {
    const result = parseDfirReportHtml(DFIR_HTML, "https://thedfirreport.com/2025/03/31/fake-zoom/");
    const techIds = result.mitreAttackTechniques.map(t => t.techniqueId);
    expect(techIds).toContain("T1566.002");
    expect(techIds).toContain("T1204.002");
    expect(techIds).toContain("T1486");
    expect(techIds.length).toBeGreaterThanOrEqual(5);
  });

  it("should extract IP IOCs", () => {
    const result = parseDfirReportHtml(DFIR_HTML, "https://thedfirreport.com/2025/03/31/fake-zoom/");
    const ips = result.iocs.filter(i => i.type === "ip").map(i => i.value);
    expect(ips).toContain("192.168.1.100");
    expect(ips).toContain("10.0.0.50");
  });

  it("should extract domain IOCs", () => {
    const result = parseDfirReportHtml(DFIR_HTML, "https://thedfirreport.com/2025/03/31/fake-zoom/");
    const domains = result.iocs.filter(i => i.type === "domain").map(i => i.value);
    expect(domains).toContain("evil-zoom.example.com");
    expect(domains).toContain("c2.malware-domain.net");
  });

  it("should extract hash IOCs", () => {
    const result = parseDfirReportHtml(DFIR_HTML, "https://thedfirreport.com/2025/03/31/fake-zoom/");
    const hashes = result.iocs.filter(i => i.type.startsWith("hash"));
    expect(hashes.length).toBeGreaterThanOrEqual(1);
  });

  it("should extract CVE IOCs", () => {
    const result = parseDfirReportHtml(DFIR_HTML, "https://thedfirreport.com/2025/03/31/fake-zoom/");
    const cves = result.iocs.filter(i => i.type === "cve").map(i => i.value);
    expect(cves).toContain("CVE-2023-1234");
    expect(cves).toContain("CVE-2024-5678");
  });

  it("should set source to dfir_report", () => {
    const result = parseDfirReportHtml(DFIR_HTML, "https://thedfirreport.com/2025/03/31/fake-zoom/");
    expect(result.source).toBe("dfir_report");
  });

  it("should generate a stable externalId from URL", () => {
    const result = parseDfirReportHtml(DFIR_HTML, "https://thedfirreport.com/2025/03/31/fake-zoom/");
    expect(result.externalId).toBeTruthy();
    // Same URL should produce same ID
    const result2 = parseDfirReportHtml(DFIR_HTML, "https://thedfirreport.com/2025/03/31/fake-zoom/");
    expect(result2.externalId).toBe(result.externalId);
  });

  it("should extract summary from content", () => {
    const result = parseDfirReportHtml(DFIR_HTML, "https://thedfirreport.com/2025/03/31/fake-zoom/");
    expect(result.summary).toBeTruthy();
    expect(result.summary!.length).toBeGreaterThan(10);
  });
});

// ── CISA STIX Parser Tests ──
describe("CISA STIX Parser", () => {
  it("should extract report title", () => {
    const result = parseCisaStix(CISA_STIX);
    expect(result.title).toBe("CISA Alert: APT29 Activity");
  });

  it("should extract threat actors", () => {
    const result = parseCisaStix(CISA_STIX);
    expect(result.threatActors).toContain("APT29");
  });

  it("should extract malware families", () => {
    const result = parseCisaStix(CISA_STIX);
    expect(result.malwareFamilies).toContain("SUNBURST");
  });

  it("should extract ATT&CK techniques from attack-pattern objects", () => {
    const result = parseCisaStix(CISA_STIX);
    const techIds = result.mitreAttackTechniques.map(t => t.techniqueId);
    expect(techIds).toContain("T1566.001");
  });

  it("should extract IOCs from indicator patterns", () => {
    const result = parseCisaStix(CISA_STIX);
    const ips = result.iocs.filter(i => i.type === "ip").map(i => i.value);
    expect(ips).toContain("203.0.113.50");
  });

  it("should set source to cisa", () => {
    const result = parseCisaStix(CISA_STIX);
    expect(result.source).toBe("cisa");
  });

  it("should extract published date", () => {
    const result = parseCisaStix(CISA_STIX);
    expect(result.publishedAt).toBeTruthy();
  });

  it("should extract tags from labels", () => {
    const result = parseCisaStix(CISA_STIX);
    expect(result.tags).toContain("apt");
  });
});

// ── OTX Pulse Parser Tests ──
describe("OTX Pulse Parser", () => {
  it("should extract pulse name as title", () => {
    const result = parseOtxPulse(OTX_PULSE);
    expect(result.title).toBe("Lazarus Group Campaign 2025");
  });

  it("should extract ATT&CK techniques from attack_ids", () => {
    const result = parseOtxPulse(OTX_PULSE);
    const techIds = result.mitreAttackTechniques.map(t => t.techniqueId);
    expect(techIds).toContain("T1059.001");
    expect(techIds).toContain("T1027");
  });

  it("should extract IOCs from indicators", () => {
    const result = parseOtxPulse(OTX_PULSE);
    expect(result.iocs.length).toBeGreaterThanOrEqual(4);
    const ips = result.iocs.filter(i => i.type === "ip").map(i => i.value);
    expect(ips).toContain("198.51.100.25");
    const domains = result.iocs.filter(i => i.type === "domain").map(i => i.value);
    expect(domains).toContain("lazarus-c2.example.com");
  });

  it("should extract CVE IOCs", () => {
    const result = parseOtxPulse(OTX_PULSE);
    const cves = result.iocs.filter(i => i.type === "cve").map(i => i.value);
    expect(cves).toContain("CVE-2025-0001");
  });

  it("should set source to otx", () => {
    const result = parseOtxPulse(OTX_PULSE);
    expect(result.source).toBe("otx");
  });

  it("should extract tags", () => {
    const result = parseOtxPulse(OTX_PULSE);
    expect(result.tags).toContain("lazarus");
    expect(result.tags).toContain("cryptocurrency");
  });
});

// ── Manual Report Parser Tests ──
describe("Manual Report Parser", () => {
  const MANUAL_MD = `# APT28 Campaign Analysis

## Summary
APT28 (Fancy Bear) deployed custom malware targeting government agencies.

## Techniques Used
- T1566.001 - Spearphishing Attachment
- T1059.001 - PowerShell
- T1078 - Valid Accounts

## IOCs
- 198.51.100.10 (C2 server)
- apt28-c2.example.com
- CVE-2024-9999
- e99a18c428cb38d5f260853678922e03`;

  it("should use provided title", () => {
    const result = parseManualReport(MANUAL_MD, "APT28 Campaign Analysis");
    expect(result.title).toBe("APT28 Campaign Analysis");
  });

  it("should extract ATT&CK technique IDs", () => {
    const result = parseManualReport(MANUAL_MD, "Test");
    const techIds = result.mitreAttackTechniques.map(t => t.techniqueId);
    expect(techIds).toContain("T1566.001");
    expect(techIds).toContain("T1059.001");
    expect(techIds).toContain("T1078");
  });

  it("should extract IOCs", () => {
    const result = parseManualReport(MANUAL_MD, "Test");
    expect(result.iocs.length).toBeGreaterThanOrEqual(3);
  });

  it("should set source to manual", () => {
    const result = parseManualReport(MANUAL_MD, "Test");
    expect(result.source).toBe("manual");
  });
});

// ── Auto-Detection Tests ──
describe("Auto-Detection", () => {
  it("should detect STIX JSON bundles", () => {
    const result = autoDetectAndParse(JSON.stringify(CISA_STIX));
    expect(result.source).toBe("cisa");
    expect(result.title).toBe("CISA Alert: APT29 Activity");
  });

  it("should detect OTX pulse JSON", () => {
    const result = autoDetectAndParse(JSON.stringify(OTX_PULSE));
    expect(result.source).toBe("otx");
    expect(result.title).toBe("Lazarus Group Campaign 2025");
  });

  it("should detect HTML content", () => {
    const result = autoDetectAndParse(DFIR_HTML, undefined, "https://thedfirreport.com/test");
    expect(result.source).toBe("dfir_report");
  });

  it("should fall back to manual parser for plain text", () => {
    const result = autoDetectAndParse("# Simple Report\nT1059.001 was used.\n192.168.1.1 was the C2.");
    expect(result.source).toBe("manual");
    expect(result.mitreAttackTechniques.length).toBeGreaterThanOrEqual(1);
  });
});

// ── Engagement Training Bridge Module Tests ──
describe("Engagement Training Bridge", () => {
  it("should export captureDecision function", async () => {
    const mod = await import("./lib/engagement-training-bridge");
    expect(typeof mod.captureDecision).toBe("function");
  });

  it("should export updateDecisionOutcome function", async () => {
    const mod = await import("./lib/engagement-training-bridge");
    expect(typeof mod.updateDecisionOutcome).toBe("function");
  });

  it("should export captureExploitOutcome function", async () => {
    const mod = await import("./lib/engagement-training-bridge");
    expect(typeof mod.captureExploitOutcome).toBe("function");
  });
});

// ── _caller Compliance Tests ──
describe("_caller compliance in DFIR library router", () => {
  it("should have _caller within 3 lines of every invokeLLM call", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/dfir-library.ts", "utf-8");
    const lines = content.split("\n");

    const invokeLLMLines: number[] = [];
    lines.forEach((line, idx) => {
      if (line.includes("invokeLLM(")) invokeLLMLines.push(idx);
    });

    for (const lineIdx of invokeLLMLines) {
      const window = lines.slice(lineIdx, lineIdx + 4).join("\n");
      expect(window).toContain("_caller");
    }
  });
});

// ── _caller Compliance in Engagement Scan Imports ──
describe("_caller compliance in engagement scan imports router", () => {
  it("should have _caller within 3 lines of every invokeLLM call", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("server/routers/engagement-scan-imports.ts", "utf-8");
    const lines = content.split("\n");

    const invokeLLMLines: number[] = [];
    lines.forEach((line, idx) => {
      if (line.includes("invokeLLM(")) invokeLLMLines.push(idx);
    });

    for (const lineIdx of invokeLLMLines) {
      const window = lines.slice(lineIdx, lineIdx + 4).join("\n");
      expect(window).toContain("_caller");
    }
  });
});
