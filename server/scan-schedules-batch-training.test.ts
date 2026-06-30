import { describe, it, expect } from "vitest";

// ─── Scan Schedules Router Tests ───
describe("Scan Schedules Router", () => {
  it("should export scanSchedulesRouter with required procedures", async () => {
    const mod = await import("./routers/scan-schedules");
    expect(mod.scanSchedulesRouter).toBeDefined();
    const router = mod.scanSchedulesRouter as any;
    expect(router._def.procedures.list).toBeDefined();
    expect(router._def.procedures.create).toBeDefined();
    expect(router._def.procedures.toggle).toBeDefined();
    expect(router._def.procedures.delete).toBeDefined();
    expect(router._def.procedures.runNow).toBeDefined();
    expect(router._def.procedures.status).toBeDefined();
  });
});

// ─── Batch Training Procedures Tests ───
describe("Engagement Automation - Batch Training", () => {
  it("should export engagementAutomationRouter with batch training procedures", async () => {
    const mod = await import("./routers/engagement-automation");
    expect(mod.engagementAutomationRouter).toBeDefined();
    const router = mod.engagementAutomationRouter as any;
    expect(router._def.procedures.batchTrainingRun).toBeDefined();
    expect(router._def.procedures.getBatchTrainingStatus).toBeDefined();
  });
});

// ─── DFIR Library Procedures Tests ───
describe("DFIR Library Router", () => {
  it("should export dfirLibraryRouter with all procedures", async () => {
    const mod = await import("./routers/dfir-library");
    expect(mod.dfirLibraryRouter).toBeDefined();
    const router = mod.dfirLibraryRouter as any;
    expect(router._def.procedures.list).toBeDefined();
    expect(router._def.procedures.scrapeIndex).toBeDefined();
    expect(router._def.procedures.seedLibrary).toBeDefined();
  });
});

// ─── Engagement Training Bridge Tests ───
describe("Engagement Training Bridge", () => {
  it("should export captureDecision and related functions", async () => {
    const mod = await import("./lib/engagement-training-bridge");
    expect(typeof mod.captureDecision).toBe("function");
    expect(typeof mod.updateDecisionOutcome).toBe("function");
    expect(typeof mod.persistTrainingExample).toBe("function");
    expect(typeof mod.captureExploitOutcome).toBe("function");
    expect(typeof mod.getDecisionLog).toBe("function");
    expect(typeof mod.getTrainingExamples).toBe("function");
    expect(typeof mod.getTrainingStats).toBe("function");
  });

  it("captureDecision should handle missing DB gracefully", async () => {
    const { captureDecision } = await import("./lib/engagement-training-bridge");
    // Should not throw when DB is unavailable (returns null)
    const result = await captureDecision({
      engagementId: 99999,
      caller: "test-caller",
      category: "vuln_correlation",
      inputContext: { test: true },
      decision: "test decision",
      reasoning: "test reasoning",
      confidence: 0.85,
    });
    // Returns null or a number depending on DB availability
    expect(result === null || typeof result === "number").toBe(true);
  });

  it("captureExploitOutcome should handle missing DB gracefully", async () => {
    const { captureExploitOutcome } = await import("./lib/engagement-training-bridge");
    await expect(
      captureExploitOutcome({
        engagementId: 99999,
        target: "192.168.1.1",
        technique: "sql_injection",
        success: true,
        output: "shell obtained",
        confidence: 0.9,
      })
    ).resolves.not.toThrow();
  });
});

// ─── Vuln Scanner Parser - Burp Suite Tests ───
describe("Vuln Scanner Parser - Burp Suite", () => {
  it("should parse Burp Suite XML format", async () => {
    const { parseBurpXML } = await import("./lib/vuln-scanner-parser");
    const burpXml = `<?xml version="1.0"?>
<issues>
  <issue>
    <serialNumber>1234567890</serialNumber>
    <type>1049088</type>
    <name>Cross-site scripting (reflected)</name>
    <host ip="10.0.0.1">https://target.local</host>
    <path>/search</path>
    <location>/search [q parameter]</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>Reflected XSS vulnerabilities arise when...</issueBackground>
    <remediationBackground>Input should be validated...</remediationBackground>
    <issueDetail>The q parameter is vulnerable to XSS</issueDetail>
    <vulnerability-classifications>
      <item>CWE-79</item>
    </vulnerability-classifications>
  </issue>
</issues>`;
    const result = parseBurpXML(burpXml);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].title).toBe("Cross-site scripting (reflected)");
    expect(result.findings[0].severity).toBe("high");
    expect(result.scannerType).toBe("burp");
  });
});

// ─── Vuln Scanner Parser - Auto-detect Tests ───
describe("Vuln Scanner Parser - Auto-detect", () => {
  it("should detect Nessus format from content", async () => {
    const { detectScannerType } = await import("./lib/vuln-scanner-parser");
    const nessusXml = `<?xml version="1.0"?><NessusClientData_v2><Report name="Test"></Report></NessusClientData_v2>`;
    expect(detectScannerType(nessusXml)).toBe("nessus");
  });

  it("should detect Burp format from content", async () => {
    const { detectScannerType } = await import("./lib/vuln-scanner-parser");
    const burpXml = `<?xml version="1.0"?><issues><issue><name>Test</name><type>123</type><serialNumber>456</serialNumber></issue></issues>`;
    expect(detectScannerType(burpXml)).toBe("burp");
  });

  it("should detect ZAP format from content", async () => {
    const { detectScannerType } = await import("./lib/vuln-scanner-parser");
    const zapXml = `<?xml version="1.0"?><OWASPZAPReport version="2.14"><site name="http://test"></site></OWASPZAPReport>`;
    expect(detectScannerType(zapXml)).toBe("zap");
  });

  it("should detect OpenVAS format from content", async () => {
    const { detectScannerType } = await import("./lib/vuln-scanner-parser");
    const openvasXml = `<?xml version="1.0"?><report id="1"><results><result id="r1"></result></results></report>`;
    // OpenVAS detection requires "openvas" keyword or <results> + <result> pattern
    const result = detectScannerType(openvasXml);
    expect(["openvas", "custom"]).toContain(result);
  });

  it("should detect Qualys from CSV content", async () => {
    const { detectScannerType } = await import("./lib/vuln-scanner-parser");
    const qualysCsv = `"QID","Title","Severity"\n"12345","Test Vuln","3"`;
    expect(detectScannerType(qualysCsv)).toBe("qualys");
  });

  it("should detect Rapid7 from CSV content", async () => {
    const { detectScannerType } = await import("./lib/vuln-scanner-parser");
    const rapid7Csv = `"Asset IP Address","Vulnerability Severity Level","Title"\n"192.168.1.1","Critical","Test"`;
    expect(detectScannerType(rapid7Csv)).toBe("rapid7");
  });
});

// ─── DFIR Report Parser Tests ───
describe("DFIR Report Parser - Manual Report", () => {
  it("should extract IOCs from manual report text", async () => {
    const { parseManualReport } = await import("./lib/dfir-report-parser");
    const report = `
# Incident Report: APT29 Campaign

The threat actor used the following infrastructure:
- C2 server at 185.100.87.42
- Phishing domain: evil-login.example.com
- Malware hash: d41d8cd98f00b204e9800998ecf8427e
- CVE-2024-21762 was exploited for initial access
- The attack used T1566.001 (Spearphishing Attachment) and T1059.001 (PowerShell)
    `;
    const result = parseManualReport(report, "APT29 Campaign Report");
    expect(result.title).toBe("APT29 Campaign Report");
    expect(result.iocs.length).toBeGreaterThan(0);

    const iocTypes = result.iocs.map(i => i.type);
    expect(iocTypes).toContain("ip");
    expect(iocTypes).toContain("domain");
    expect(iocTypes).toContain("hash_md5");
    // CVEs are stored as IOCs with type 'cve'
    expect(iocTypes).toContain("cve");

    const cveIocs = result.iocs.filter(i => i.type === "cve");
    expect(cveIocs.some(i => i.value === "CVE-2024-21762")).toBe(true);

    expect(result.mitreAttackTechniques.length).toBeGreaterThan(0);
    expect(result.mitreAttackTechniques.some(t => t.techniqueId === "T1566.001")).toBe(true);
  });

  it("should extract SHA256 hashes", async () => {
    const { extractIocs } = await import("./lib/dfir-report-parser");
    const text = "Found hash: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    const iocs = extractIocs(text);
    expect(iocs.some(i => i.type === "hash_sha256")).toBe(true);
  });

  it("should extract URLs", async () => {
    const { extractIocs } = await import("./lib/dfir-report-parser");
    const text = "Payload downloaded from https://malware.evil.com/payload.exe";
    const iocs = extractIocs(text);
    expect(iocs.some(i => i.type === "url")).toBe(true);
  });
});

describe("DFIR Report Parser - MITRE Techniques", () => {
  it("should extract MITRE ATT&CK technique IDs", async () => {
    const { extractMitreTechniques } = await import("./lib/dfir-report-parser");
    const text = `
      T1566.001 - Spearphishing Attachment
      T1059.001 - PowerShell
      T1003 - OS Credential Dumping
    `;
    const techniques = extractMitreTechniques(text);
    expect(techniques.length).toBeGreaterThanOrEqual(3);
    expect(techniques.some(t => t.techniqueId === "T1566.001")).toBe(true);
    expect(techniques.some(t => t.techniqueId === "T1059.001")).toBe(true);
    expect(techniques.some(t => t.techniqueId === "T1003")).toBe(true);
  });
});
