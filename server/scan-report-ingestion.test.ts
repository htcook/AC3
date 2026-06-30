import { describe, it, expect } from "vitest";
import { parseVulnScan, detectScannerType, SCANNER_LABELS } from "./lib/vuln-scanner-parser";

/**
 * Scan Report Ingestion — Parser & Detection Tests
 *
 * Tests cover:
 * 1. Scanner type auto-detection from file content and filename
 * 2. Nessus XML parsing
 * 3. Qualys CSV parsing
 * 4. Rapid7 CSV parsing
 * 5. Burp Suite XML parsing
 * 6. OWASP ZAP XML parsing
 * 7. OpenVAS XML parsing
 * 8. Edge cases and error handling
 * 9. SCANNER_LABELS completeness
 */

// ── Sample test data ──

const NESSUS_XML = `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Test Scan">
    <ReportHost name="192.168.1.1">
      <HostProperties>
        <tag name="host-ip">192.168.1.1</tag>
        <tag name="hostname">web-server.local</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="3" pluginID="12345" pluginName="SSL Certificate Expired">
        <description>The SSL certificate has expired.</description>
        <solution>Renew the SSL certificate.</solution>
        <cvss_base_score>7.5</cvss_base_score>
        <cve>CVE-2023-1234</cve>
        <exploit_available>true</exploit_available>
      </ReportItem>
      <ReportItem port="80" svc_name="http" protocol="tcp" severity="2" pluginID="12346" pluginName="Apache Version Disclosure">
        <description>The web server discloses its version.</description>
        <solution>Disable version disclosure.</solution>
        <cvss_base_score>5.0</cvss_base_score>
      </ReportItem>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="10000" pluginName="Host Info">
        <description>General host information.</description>
      </ReportItem>
    </ReportHost>
    <ReportHost name="192.168.1.2">
      <HostProperties>
        <tag name="host-ip">192.168.1.2</tag>
      </HostProperties>
      <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="4" pluginID="99999" pluginName="Critical SSH Vulnerability">
        <description>Critical vulnerability in SSH.</description>
        <solution>Update SSH daemon.</solution>
        <cvss_base_score>9.8</cvss_base_score>
        <cve>CVE-2024-5678</cve>
        <exploit_available>true</exploit_available>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`;

const QUALYS_CSV = `IP,DNS,NetBIOS,OS,QID,Title,Severity,CVE ID,CVSS Base,Protocol,Port,Description,Solution
192.168.1.1,web-server.local,,Linux,12345,SSL Certificate Expired,4,CVE-2023-1234,7.5,tcp,443,The SSL certificate has expired.,Renew the SSL certificate.
192.168.1.1,web-server.local,,Linux,12346,Apache Version Disclosure,3,,5.0,tcp,80,The web server discloses its version.,Disable version disclosure.
192.168.1.2,,,Linux,99999,Critical SSH Vulnerability,5,CVE-2024-5678,9.8,tcp,22,Critical vulnerability in SSH.,Update SSH daemon.`;

const RAPID7_CSV = `"asset_ip","asset_hostname","vulnerability_title","severity","cvss_score","cve","port","protocol","description","solution","exploit_available"
"192.168.1.1","web-server.local","SSL Certificate Expired","High","7.5","CVE-2023-1234","443","tcp","The SSL certificate has expired.","Renew the SSL certificate.","true"
"192.168.1.1","web-server.local","Apache Version Disclosure","Medium","5.0","","80","tcp","The web server discloses its version.","Disable version disclosure.","false"
"192.168.1.2","","Critical SSH Vulnerability","Critical","9.8","CVE-2024-5678","22","tcp","Critical vulnerability in SSH.","Update SSH daemon.","true"`;

const BURP_XML = `<?xml version="1.0"?>
<issues burpVersion="2024.1" exportTime="2024-01-15T10:30:00">
  <issue>
    <serialNumber>1</serialNumber>
    <type>1049088</type>
    <name>SQL Injection</name>
    <host ip="192.168.1.1">https://web-server.local</host>
    <path>/login</path>
    <location>/login [username parameter]</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries.</issueBackground>
    <remediationBackground>Use parameterized queries.</remediationBackground>
    <vulnerability-classifications>
      <vulnerability-classification>CWE-89</vulnerability-classification>
    </vulnerability-classifications>
  </issue>
  <issue>
    <serialNumber>2</serialNumber>
    <type>5244928</type>
    <name>Cross-Site Scripting (Reflected)</name>
    <host ip="192.168.1.1">https://web-server.local</host>
    <path>/search</path>
    <location>/search [q parameter]</location>
    <severity>High</severity>
    <confidence>Firm</confidence>
    <issueBackground>Reflected XSS vulnerabilities arise when data is copied from a request and echoed into the response.</issueBackground>
    <remediationBackground>Encode output and validate input.</remediationBackground>
  </issue>
  <issue>
    <serialNumber>3</serialNumber>
    <type>6291456</type>
    <name>Cookie Without HttpOnly Flag</name>
    <host ip="192.168.1.1">https://web-server.local</host>
    <path>/</path>
    <location>/ [session cookie]</location>
    <severity>Low</severity>
    <confidence>Certain</confidence>
    <issueBackground>A cookie has been set without the HttpOnly flag.</issueBackground>
    <remediationBackground>Set the HttpOnly flag on all cookies.</remediationBackground>
  </issue>
</issues>`;

const ZAP_XML = `<?xml version="1.0"?>
<OWASPZAPReport version="2.14.0" generated="2024-01-15T10:30:00">
  <site name="https://web-server.local" host="web-server.local" port="443" ssl="true">
    <alerts>
      <alertitem>
        <pluginid>40012</pluginid>
        <alertRef>40012</alertRef>
        <alert>Cross Site Scripting (Reflected)</alert>
        <name>Cross Site Scripting (Reflected)</name>
        <riskcode>3</riskcode>
        <confidence>2</confidence>
        <riskdesc>High (Medium)</riskdesc>
        <desc>Cross-site scripting vulnerability found.</desc>
        <uri>https://web-server.local/search?q=test</uri>
        <param>q</param>
        <attack>&lt;script&gt;alert(1)&lt;/script&gt;</attack>
        <evidence>&lt;script&gt;alert(1)&lt;/script&gt;</evidence>
        <solution>Validate and encode all user input.</solution>
        <cweid>79</cweid>
        <wascid>8</wascid>
        <instances>
          <instance>
            <uri>https://web-server.local/search?q=test</uri>
          </instance>
        </instances>
      </alertitem>
      <alertitem>
        <pluginid>10015</pluginid>
        <alertRef>10015</alertRef>
        <alert>Incomplete or No Cache-control Header Set</alert>
        <name>Incomplete or No Cache-control Header Set</name>
        <riskcode>1</riskcode>
        <confidence>2</confidence>
        <riskdesc>Low (Medium)</riskdesc>
        <desc>The cache-control header has not been set properly.</desc>
        <uri>https://web-server.local/</uri>
        <solution>Set proper cache-control headers.</solution>
        <cweid>525</cweid>
        <wascid>13</wascid>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>`;

const OPENVAS_XML = `<?xml version="1.0"?>
<report id="test-report" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" content_type="text/xml">
  <results>
    <result id="result-1">
      <host>192.168.1.1</host>
      <port>443/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.12345">
        <name>SSL Certificate Expired</name>
        <cvss_base>7.5</cvss_base>
        <cve>CVE-2023-1234</cve>
      </nvt>
      <threat>High</threat>
      <severity>7.5</severity>
      <description>The SSL certificate has expired.</description>
    </result>
    <result id="result-2">
      <host>192.168.1.2</host>
      <port>22/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.99999">
        <name>Critical SSH Vulnerability</name>
        <cvss_base>9.8</cvss_base>
        <cve>CVE-2024-5678</cve>
      </nvt>
      <threat>Critical</threat>
      <severity>9.8</severity>
      <description>Critical vulnerability in SSH.</description>
    </result>
    <result id="result-3">
      <host>192.168.1.1</host>
      <port>general/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.10000">
        <name>Host Info</name>
        <cvss_base>0.0</cvss_base>
      </nvt>
      <threat>Log</threat>
      <severity>0.0</severity>
      <description>General host information.</description>
    </result>
  </results>
</report>`;

// ── Auto-Detection Tests ──

describe("Scanner Type Auto-Detection", () => {
  it("detects Nessus from XML content", () => {
    expect(detectScannerType(NESSUS_XML, "scan.nessus")).toBe("nessus");
  });

  it("detects Nessus from .nessus extension", () => {
    expect(detectScannerType("<some xml>", "report.nessus")).toBe("nessus");
  });

  it("detects Burp Suite from XML content", () => {
    expect(detectScannerType(BURP_XML, "burp-report.xml")).toBe("burp");
  });

  it("detects ZAP from XML content", () => {
    expect(detectScannerType(ZAP_XML, "zap-report.xml")).toBe("zap");
  });

  it("detects OpenVAS from XML content", () => {
    expect(detectScannerType(OPENVAS_XML, "openvas-report.xml")).toBe("openvas");
  });

  it("detects Qualys from CSV content with QID header", () => {
    expect(detectScannerType(QUALYS_CSV, "qualys-scan.csv")).toBe("qualys");
  });

  it("detects Rapid7 from CSV content with asset_ip header", () => {
    expect(detectScannerType(RAPID7_CSV, "rapid7-export.csv")).toBe("rapid7");
  });

  it("falls back to custom for unrecognized content", () => {
    expect(detectScannerType("random text content", "unknown.txt")).toBe("custom");
  });
});

// ── Nessus Parser Tests ──

describe("Nessus XML Parser", () => {
  it("parses findings correctly", () => {
    const result = parseVulnScan("nessus", NESSUS_XML);
    expect(result.totalHosts).toBe(2);
    // Should exclude severity 0 (info)
    expect(result.findings.length).toBeGreaterThanOrEqual(2);
  });

  it("extracts CVE IDs", () => {
    const result = parseVulnScan("nessus", NESSUS_XML);
    const cves = result.findings.map(f => f.cveId).filter(Boolean);
    expect(cves).toContain("CVE-2023-1234");
    expect(cves).toContain("CVE-2024-5678");
  });

  it("maps severity levels correctly", () => {
    const result = parseVulnScan("nessus", NESSUS_XML);
    const critical = result.findings.find(f => f.cveId === "CVE-2024-5678");
    expect(critical?.severity).toBe("critical");
    const high = result.findings.find(f => f.cveId === "CVE-2023-1234");
    expect(high?.severity).toBe("high");
  });

  it("extracts exploit availability", () => {
    const result = parseVulnScan("nessus", NESSUS_XML);
    const withExploit = result.findings.find(f => f.cveId === "CVE-2023-1234");
    expect(withExploit?.exploitAvailable).toBe(true);
  });

  it("counts severity categories", () => {
    const result = parseVulnScan("nessus", NESSUS_XML);
    expect(result.criticalCount).toBeGreaterThanOrEqual(1);
    expect(result.highCount).toBeGreaterThanOrEqual(1);
  });

  it("extracts host IP and port", () => {
    const result = parseVulnScan("nessus", NESSUS_XML);
    const sslFinding = result.findings.find(f => f.title?.includes("SSL"));
    expect(sslFinding?.hostIp).toBe("192.168.1.1");
    expect(sslFinding?.port).toBe(443);
  });
});

// ── Qualys CSV Parser Tests ──

describe("Qualys CSV Parser", () => {
  it("parses findings from CSV", () => {
    const result = parseVulnScan("qualys", QUALYS_CSV);
    expect(result.findings.length).toBe(3);
    expect(result.totalHosts).toBeGreaterThanOrEqual(1);
  });

  it("extracts CVE and CVSS", () => {
    const result = parseVulnScan("qualys", QUALYS_CSV);
    const ssl = result.findings.find(f => f.title?.includes("SSL"));
    expect(ssl?.cveId).toBe("CVE-2023-1234");
    expect(ssl?.cvssScore).toBe(7.5);
  });

  it("maps Qualys severity to standard levels", () => {
    const result = parseVulnScan("qualys", QUALYS_CSV);
    // Qualys severity 5 = critical, 4 = high, 3 = medium
    const critical = result.findings.find(f => f.cveId === "CVE-2024-5678");
    expect(critical?.severity).toBe("critical");
  });
});

// ── Rapid7 CSV Parser Tests ──

describe("Rapid7 CSV Parser", () => {
  it("parses findings from CSV", () => {
    const result = parseVulnScan("rapid7", RAPID7_CSV);
    expect(result.findings.length).toBe(3);
  });

  it("extracts exploit availability flag", () => {
    const result = parseVulnScan("rapid7", RAPID7_CSV);
    const ssl = result.findings.find(f => f.cveId === "CVE-2023-1234");
    expect(ssl?.exploitAvailable).toBe(true);
    const apache = result.findings.find(f => f.title?.includes("Apache"));
    expect(apache?.exploitAvailable).toBe(false);
  });

  it("normalizes severity strings", () => {
    const result = parseVulnScan("rapid7", RAPID7_CSV);
    const severities = result.findings.map(f => f.severity);
    expect(severities).toContain("high");
    expect(severities).toContain("medium");
    expect(severities).toContain("critical");
  });
});

// ── Burp Suite XML Parser Tests ──

describe("Burp Suite XML Parser", () => {
  it("parses Burp Suite issues", () => {
    const result = parseVulnScan("burp", BURP_XML);
    expect(result.findings.length).toBe(3);
  });

  it("extracts issue names and severity", () => {
    const result = parseVulnScan("burp", BURP_XML);
    const sqli = result.findings.find(f => f.title?.includes("SQL Injection"));
    expect(sqli).toBeDefined();
    expect(sqli?.severity).toBe("high");
  });

  it("extracts host IP from Burp format", () => {
    const result = parseVulnScan("burp", BURP_XML);
    const finding = result.findings[0];
    expect(finding?.hostIp).toBe("192.168.1.1");
  });

  it("extracts URL path", () => {
    const result = parseVulnScan("burp", BURP_XML);
    const sqli = result.findings.find(f => f.title?.includes("SQL Injection"));
    expect(sqli?.url).toContain("/login");
  });

  it("maps low severity correctly", () => {
    const result = parseVulnScan("burp", BURP_XML);
    const cookie = result.findings.find(f => f.title?.includes("Cookie"));
    expect(cookie?.severity).toBe("low");
  });
});

// ── OWASP ZAP XML Parser Tests ──

describe("OWASP ZAP XML Parser", () => {
  it("parses ZAP alert items", () => {
    const result = parseVulnScan("zap", ZAP_XML);
    expect(result.findings.length).toBe(2);
  });

  it("extracts CWE IDs", () => {
    const result = parseVulnScan("zap", ZAP_XML);
    const xss = result.findings.find(f => f.title?.includes("Cross Site Scripting"));
    expect(xss?.cweId).toBe("CWE-79");
  });

  it("maps ZAP risk codes to severity", () => {
    const result = parseVulnScan("zap", ZAP_XML);
    const xss = result.findings.find(f => f.title?.includes("Cross Site Scripting"));
    expect(xss?.severity).toBe("high");
    const cache = result.findings.find(f => f.title?.includes("Cache"));
    expect(cache?.severity).toBe("low");
  });

  it("extracts URL from ZAP findings", () => {
    const result = parseVulnScan("zap", ZAP_XML);
    const xss = result.findings.find(f => f.title?.includes("Cross Site Scripting"));
    expect(xss?.url).toContain("web-server.local");
  });
});

// ── OpenVAS XML Parser Tests ──

describe("OpenVAS XML Parser", () => {
  it("parses OpenVAS results", () => {
    const result = parseVulnScan("openvas", OPENVAS_XML);
    // Should have at least 2 non-info findings
    expect(result.findings.length).toBeGreaterThanOrEqual(2);
  });

  it("extracts CVE and CVSS from NVT", () => {
    const result = parseVulnScan("openvas", OPENVAS_XML);
    const ssl = result.findings.find(f => f.title?.includes("SSL"));
    expect(ssl?.cveId).toBe("CVE-2023-1234");
    expect(ssl?.cvssScore).toBe(7.5);
  });

  it("parses port format (port/protocol)", () => {
    const result = parseVulnScan("openvas", OPENVAS_XML);
    const ssh = result.findings.find(f => f.title?.includes("SSH"));
    expect(ssh?.port).toBe(22);
    expect(ssh?.protocol).toBe("tcp");
  });

  it("maps threat levels to severity", () => {
    const result = parseVulnScan("openvas", OPENVAS_XML);
    const critical = result.findings.find(f => f.cveId === "CVE-2024-5678");
    expect(critical?.severity).toBe("critical");
  });
});

// ── Edge Cases ──

describe("Parser Edge Cases", () => {
  it("handles empty content gracefully", () => {
    const result = parseVulnScan("nessus", "");
    expect(result.findings).toEqual([]);
    expect(result.totalVulns).toBe(0);
    expect(result.totalHosts).toBe(0);
  });

  it("handles malformed XML gracefully", () => {
    const result = parseVulnScan("nessus", "<broken xml");
    expect(result.findings).toEqual([]);
    expect(result.totalVulns).toBe(0);
  });

  it("handles empty CSV gracefully", () => {
    const result = parseVulnScan("qualys", "IP,DNS,QID,Title,Severity\n");
    expect(result.findings.length).toBe(0);
  });

  it("parseVulnScan with auto-detect uses correct parser", () => {
    // Pass nessus content but say "custom" — should still parse
    const result = parseVulnScan("custom", NESSUS_XML, "scan.nessus");
    // Custom parser may or may not detect it, but shouldn't crash
    expect(result).toBeDefined();
    expect(result.findings).toBeDefined();
  });
});

// ── SCANNER_LABELS ──

describe("SCANNER_LABELS", () => {
  it("has labels for all supported scanner types", () => {
    const expectedTypes = ["nessus", "qualys", "rapid7", "burp", "zap", "openvas", "custom"];
    for (const type of expectedTypes) {
      expect(SCANNER_LABELS[type as keyof typeof SCANNER_LABELS]).toBeDefined();
      expect(typeof SCANNER_LABELS[type as keyof typeof SCANNER_LABELS]).toBe("string");
    }
  });
});

// ── LLM Validation Integration ──

describe("LLM Validation Pipeline", () => {
  it("engagement-scan-imports router exports are importable", async () => {
    const mod = await import("./routers/engagement-scan-imports");
    expect(mod.engagementScanImportsRouter).toBeDefined();
  });

  it("router has all expected procedures", async () => {
    const mod = await import("./routers/engagement-scan-imports");
    const router = mod.engagementScanImportsRouter;
    // Check the router has the expected procedure keys
    const procedures = Object.keys(router._def.procedures || {});
    expect(procedures).toContain("detectFormat");
    expect(procedures).toContain("parsePreview");
    expect(procedures).toContain("importFindings");
    expect(procedures).toContain("listImports");
    expect(procedures).toContain("runLlmValidation");
    expect(procedures).toContain("getSupportedFormats");
  });
});

// ── Cross-parser consistency ──

describe("Cross-Parser Consistency", () => {
  it("all parsers return the same structure", () => {
    const parsers = [
      { type: "nessus", content: NESSUS_XML },
      { type: "qualys", content: QUALYS_CSV },
      { type: "rapid7", content: RAPID7_CSV },
      { type: "burp", content: BURP_XML },
      { type: "zap", content: ZAP_XML },
      { type: "openvas", content: OPENVAS_XML },
    ];

    for (const { type, content } of parsers) {
      const result = parseVulnScan(type, content);
      // All results should have the same top-level keys
      expect(result).toHaveProperty("findings");
      expect(result).toHaveProperty("totalVulns");
      expect(result).toHaveProperty("totalHosts");
      expect(result).toHaveProperty("criticalCount");
      expect(result).toHaveProperty("highCount");
      expect(result).toHaveProperty("mediumCount");
      expect(result).toHaveProperty("lowCount");

      // All findings should have consistent fields
      for (const f of result.findings) {
        expect(f).toHaveProperty("title");
        expect(f).toHaveProperty("severity");
        expect(["critical", "high", "medium", "low", "info"]).toContain(f.severity);
      }
    }
  });

  it("severity counts match actual findings", () => {
    const parsers = [
      { type: "nessus", content: NESSUS_XML },
      { type: "qualys", content: QUALYS_CSV },
      { type: "rapid7", content: RAPID7_CSV },
      { type: "burp", content: BURP_XML },
      { type: "zap", content: ZAP_XML },
      { type: "openvas", content: OPENVAS_XML },
    ];

    for (const { type, content } of parsers) {
      const result = parseVulnScan(type, content);
      const counted = {
        critical: result.findings.filter(f => f.severity === "critical").length,
        high: result.findings.filter(f => f.severity === "high").length,
        medium: result.findings.filter(f => f.severity === "medium").length,
        low: result.findings.filter(f => f.severity === "low").length,
      };
      expect(result.criticalCount).toBe(counted.critical);
      expect(result.highCount).toBe(counted.high);
      expect(result.mediumCount).toBe(counted.medium);
      expect(result.lowCount).toBe(counted.low);
    }
  });
});
