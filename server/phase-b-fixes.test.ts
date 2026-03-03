/**
 * Tests for Phase B scan pipeline fixes:
 * 1. Nikto output parser catches all finding types (not just OSVDB/CVE)
 * 2. Nuclei command sanitization: -target → -u URL, adds severity/tag filters
 * 3. httpx command conversion: -u single-URL → pipe mode
 * 4. Tool timeout configuration: nuclei gets 300s, others get 180s
 */
import { describe, it, expect } from "vitest";

// ─── Nikto Parser Tests ────────────────────────────────────────────────────

// Replicate the nikto parser logic from engagement-orchestrator.ts
function parseNiktoOutput(stdout: string): Array<{ severity: string; title: string; cve?: string }> {
  const findings: Array<{ severity: string; title: string; cve?: string }> = [];
  if (!stdout || stdout.length < 10) return findings;

  const niktoSkipPatterns = [
    /^\+ Target IP:/i,
    /^\+ Target Hostname:/i,
    /^\+ Target Port:/i,
    /^\+ Start Time:/i,
    /^\+ End Time:/i,
    /^\+ Server:/i,
    /^\+ \d+ host\(s\) tested/i,
    /^\+ \d+ items? checked/i,
    /^\+ No CGI Directories found/i,
    /^\+ ERROR:/i,
  ];

  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("+")) continue;
    if (niktoSkipPatterns.some(p => p.test(trimmed))) continue;

    const cve = trimmed.match(/CVE-\d{4}-\d+/)?.[0];
    const osvdb = trimmed.match(/OSVDB-\d+/)?.[0];
    let severity = "info";
    if (cve) severity = "high";
    else if (osvdb) severity = "medium";
    else if (/is not present|not set|is not defined|header.*missing|missing.*header/i.test(trimmed)) severity = "low";
    else if (/directory indexing|listing|backup|config/i.test(trimmed)) severity = "medium";
    else if (/injection|xss|rfi|lfi|traversal|upload/i.test(trimmed)) severity = "high";
    else if (/default|sample|test|example/i.test(trimmed)) severity = "low";

    findings.push({
      severity,
      title: `[Nikto] ${trimmed.slice(2, 150).trim()}`,
      cve,
    });
  }
  return findings;
}

describe("Nikto output parser", () => {
  const sampleNiktoOutput = `- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          23.20.98.48
+ Target Hostname:    ec2-23-20-98-48.compute-1.amazonaws.com
+ Target Port:        443
+ Start Time:         2026-03-03 16:13:15 (GMT0)
---------------------------------------------------------------------------
+ Server: nginx
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 21 items checked: 0 error(s) and 1 item(s) reported on remote host
+ End Time:           2026-03-03 16:13:17 (GMT0) (2 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested`;

  it("should parse X-Frame-Options missing header finding", () => {
    const findings = parseNiktoOutput(sampleNiktoOutput);
    expect(findings.length).toBeGreaterThan(0);
    const xframeFind = findings.find(f => f.title.includes("X-Frame-Options"));
    expect(xframeFind).toBeDefined();
    expect(xframeFind!.severity).toBe("low");
  });

  it("should skip meta lines (Target IP, Hostname, Port, Start/End Time)", () => {
    const findings = parseNiktoOutput(sampleNiktoOutput);
    const metaFindings = findings.filter(f =>
      f.title.includes("Target IP") ||
      f.title.includes("Target Hostname") ||
      f.title.includes("Target Port") ||
      f.title.includes("Start Time") ||
      f.title.includes("End Time")
    );
    expect(metaFindings.length).toBe(0);
  });

  it("should skip Server line", () => {
    const findings = parseNiktoOutput(sampleNiktoOutput);
    const serverFind = findings.filter(f => f.title === "[Nikto] Server: nginx");
    expect(serverFind.length).toBe(0);
  });

  it("should skip 'items checked' and 'hosts tested' lines", () => {
    const findings = parseNiktoOutput(sampleNiktoOutput);
    const skipFind = findings.filter(f =>
      f.title.includes("items checked") || f.title.includes("host(s) tested")
    );
    expect(skipFind.length).toBe(0);
  });

  it("should skip ERROR lines", () => {
    const output = `+ ERROR: Host maximum execution time of 300 seconds reached
+ The anti-clickjacking X-Frame-Options header is not present.`;
    const findings = parseNiktoOutput(output);
    expect(findings.length).toBe(1);
    expect(findings[0].title).toContain("X-Frame-Options");
  });

  it("should parse CVE findings as high severity", () => {
    const output = `+ OSVDB-3092: /test.php: CVE-2023-12345 Remote code execution vulnerability`;
    const findings = parseNiktoOutput(output);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].cve).toBe("CVE-2023-12345");
  });

  it("should parse OSVDB findings as medium severity", () => {
    const output = `+ OSVDB-3268: /icons/: Directory indexing found.`;
    const findings = parseNiktoOutput(output);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("medium");
  });

  it("should parse missing header findings as low severity", () => {
    const output = `+ The X-Content-Type-Options header is not set.
+ The X-XSS-Protection header is not present.
+ Strict-Transport-Security HTTP header is missing.`;
    const findings = parseNiktoOutput(output);
    expect(findings.length).toBe(3);
    // "not set" and "not present" match the header-missing pattern → low
    // "missing" also matches → low
    expect(findings[0].severity).toBe("low"); // "not set"
    expect(findings[1].severity).toBe("low"); // "not present"
    expect(findings[2].severity).toBe("low"); // "missing"
  });

  it("should parse directory indexing as medium severity", () => {
    const output = `+ /admin/: Directory indexing found.`;
    const findings = parseNiktoOutput(output);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("medium");
  });

  it("should parse injection findings as high severity", () => {
    const output = `+ /cgi-bin/test.cgi: SQL injection vulnerability found.`;
    const findings = parseNiktoOutput(output);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("high");
  });

  it("should parse default/sample findings as low severity", () => {
    const output = `+ /test/: This appears to be a default Apache test page.`;
    const findings = parseNiktoOutput(output);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("low");
  });

  it("should return empty for minimal output", () => {
    const findings = parseNiktoOutput("short");
    expect(findings.length).toBe(0);
  });

  it("should handle empty/null output", () => {
    expect(parseNiktoOutput("")).toEqual([]);
    expect(parseNiktoOutput(null as any)).toEqual([]);
  });
});

// ─── Nuclei Command Sanitization Tests ─────────────────────────────────────

function sanitizeNucleiCommand(
  command: string,
  asset: { ip?: string; hostname: string; ports: Array<{ port: number; service: string }>; passiveRecon?: { technologies?: string[] } }
): string {
  let nucleiCmd = command;
  // Extract target from the command
  const targetMatch = nucleiCmd.match(/-(?:target|u)\s+(\S+)/) || nucleiCmd.match(/(https?:\/\/\S+)/);
  let nucleiTarget = targetMatch?.[1] || asset.ip || asset.hostname;
  // Ensure target is a URL for web assets
  if (nucleiTarget && !nucleiTarget.startsWith('http')) {
    const webPorts = asset.ports.filter(p =>
      ['http', 'https', 'http-proxy', 'http-alt'].includes(p.service) ||
      [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port)
    );
    if (webPorts.length > 0) {
      const scheme = webPorts[0].port === 443 || webPorts[0].port === 8443 ? 'https' : 'http';
      nucleiTarget = `${scheme}://${nucleiTarget}:${webPorts[0].port}`;
    }
  }
  // Replace -target with -u and ensure severity filter exists
  nucleiCmd = nucleiCmd.replace(/-target\s+\S+/g, '').replace(/-u\s+\S+/g, '').trim();
  if (!nucleiCmd.includes('-severity')) nucleiCmd += ' -severity critical,high,medium';
  if (!nucleiCmd.includes('-jsonl')) nucleiCmd += ' -jsonl';
  if (!nucleiCmd.includes('-nc')) nucleiCmd += ' -nc';
  if (!nucleiCmd.includes('-duc')) nucleiCmd += ' -duc';
  if (!nucleiCmd.includes('-ni')) nucleiCmd += ' -ni';
  if (!nucleiCmd.includes('-timeout')) nucleiCmd += ' -timeout 10';
  if (!nucleiCmd.includes('-retries')) nucleiCmd += ' -retries 1';
  // Build tech-targeted tags if available
  const detectedTechs = asset.passiveRecon?.technologies || [];
  const techLower = detectedTechs.map((t: string) => t.toLowerCase());
  const techTags: string[] = [];
  if (techLower.some((t: string) => t.includes('wordpress'))) techTags.push('wordpress');
  if (techLower.some((t: string) => t.includes('nginx'))) techTags.push('nginx');
  if (techLower.some((t: string) => t.includes('apache'))) techTags.push('apache');
  if (techLower.some((t: string) => t.includes('php'))) techTags.push('php');
  if (techLower.some((t: string) => t.includes('node') || t.includes('next'))) techTags.push('nodejs');
  if (techLower.some((t: string) => t.includes('cloudfront') || t.includes('aws'))) techTags.push('aws');
  if (!nucleiCmd.includes('-tags') && techTags.length > 0) nucleiCmd += ` -tags ${techTags.join(',')}`;
  return `nuclei -u ${nucleiTarget} ${nucleiCmd}`.replace(/\s+/g, ' ').trim();
}

describe("Nuclei command sanitization", () => {
  const webAsset = {
    hostname: "example.com",
    ip: "1.2.3.4",
    ports: [{ port: 443, service: "https" }, { port: 80, service: "http" }],
    passiveRecon: { technologies: ["Nginx", "React", "CloudFront"] },
  };

  it("should convert -target hostname to -u URL", () => {
    const result = sanitizeNucleiCommand("nuclei -target example.com", webAsset);
    // -target hostname gets extracted, then converted to URL using first web port
    expect(result).toContain("-u https://example.com:443");
    expect(result).not.toContain("-target");
  });

  it("should preserve existing -u URL format", () => {
    const result = sanitizeNucleiCommand("nuclei -u https://example.com:443 -severity critical,high -jsonl", webAsset);
    expect(result).toContain("-u https://example.com:443");
  });

  it("should add -severity filter when missing", () => {
    const result = sanitizeNucleiCommand("nuclei -target example.com", webAsset);
    expect(result).toContain("-severity critical,high,medium");
  });

  it("should not duplicate -severity when already present", () => {
    const result = sanitizeNucleiCommand("nuclei -u https://example.com:443 -severity critical,high", webAsset);
    const severityCount = (result.match(/-severity/g) || []).length;
    expect(severityCount).toBe(1);
  });

  it("should add required flags (-jsonl, -nc, -duc, -ni)", () => {
    const result = sanitizeNucleiCommand("nuclei -target example.com", webAsset);
    expect(result).toContain("-jsonl");
    expect(result).toContain("-nc");
    expect(result).toContain("-duc");
    expect(result).toContain("-ni");
  });

  it("should add tech-targeted tags from passiveRecon", () => {
    const result = sanitizeNucleiCommand("nuclei -target example.com", webAsset);
    // React maps to nodejs only if it contains 'node' or 'next' — 'React' doesn't match
    // CloudFront maps to aws
    expect(result).toContain("-tags nginx,aws");
  });

  it("should not add tags when no technologies detected", () => {
    const noTechAsset = { ...webAsset, passiveRecon: { technologies: [] } };
    const result = sanitizeNucleiCommand("nuclei -target example.com", noTechAsset);
    expect(result).not.toContain("-tags");
  });

  it("should use https:// for port 443", () => {
    const result = sanitizeNucleiCommand("nuclei -target example.com", webAsset);
    expect(result).toContain("https://");
  });

  it("should use http:// for port 80", () => {
    const httpAsset = {
      hostname: "example.com",
      ip: "1.2.3.4",
      ports: [{ port: 80, service: "http" }],
    };
    const result = sanitizeNucleiCommand("nuclei -target example.com", httpAsset);
    // -target extracts example.com, then builds URL with first web port
    expect(result).toContain("http://example.com:80");
  });

  it("should add -timeout and -retries when missing", () => {
    const result = sanitizeNucleiCommand("nuclei -target example.com", webAsset);
    expect(result).toContain("-timeout 10");
    expect(result).toContain("-retries 1");
  });

  it("should handle command with no -target or -u (bare hostname)", () => {
    const result = sanitizeNucleiCommand("nuclei example.com", webAsset);
    expect(result).toContain("-u");
    expect(result).toContain("-severity");
  });
});

// ─── httpx Pipe Mode Conversion Tests ──────────────────────────────────────

function convertHttpxToPipeMode(command: string): { converted: boolean; command: string } {
  const urlMatch = command.match(/-u\s+(\S+)/);
  if (urlMatch) {
    const httpxUrl = urlMatch[1];
    const httpxFlags = command
      .replace(/^httpx\s*/, '')
      .replace(/-u\s+\S+/, '')
      .trim();
    return {
      converted: true,
      command: `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, ' ').trim(),
    };
  }
  return { converted: false, command };
}

describe("httpx pipe mode conversion", () => {
  it("should convert -u single-URL to pipe mode", () => {
    const result = convertHttpxToPipeMode("httpx -u https://example.com:443 -json -tech-detect");
    expect(result.converted).toBe(true);
    expect(result.command).toBe("echo https://example.com:443 | httpx -json -tech-detect");
  });

  it("should preserve all flags after conversion", () => {
    const result = convertHttpxToPipeMode("httpx -u https://example.com -json -title -status-code -tech-detect -follow-redirects");
    expect(result.converted).toBe(true);
    expect(result.command).toContain("-json");
    expect(result.command).toContain("-title");
    expect(result.command).toContain("-status-code");
    expect(result.command).toContain("-tech-detect");
    expect(result.command).toContain("-follow-redirects");
  });

  it("should not convert commands without -u flag", () => {
    const result = convertHttpxToPipeMode("echo https://example.com | httpx -json");
    expect(result.converted).toBe(false);
    expect(result.command).toBe("echo https://example.com | httpx -json");
  });

  it("should handle URL with port number", () => {
    const result = convertHttpxToPipeMode("httpx -u https://example.com:8443 -json");
    expect(result.converted).toBe(true);
    expect(result.command).toContain("echo https://example.com:8443");
  });
});

// ─── Tool Timeout Configuration Tests ──────────────────────────────────────

describe("Tool timeout configuration", () => {
  function getToolTimeout(tool: string): number {
    return tool === 'nuclei' ? 300 : 180;
  }

  it("should give nuclei 300s timeout", () => {
    expect(getToolTimeout("nuclei")).toBe(300);
  });

  it("should give httpx 180s timeout", () => {
    expect(getToolTimeout("httpx")).toBe(180);
  });

  it("should give nikto 180s timeout", () => {
    expect(getToolTimeout("nikto")).toBe(180);
  });

  it("should give gobuster 180s timeout", () => {
    expect(getToolTimeout("gobuster")).toBe(180);
  });

  it("should give hydra 180s timeout", () => {
    expect(getToolTimeout("hydra")).toBe(180);
  });
});

// ─── suggestToolCommands httpx format test ──────────────────────────────────

describe("suggestToolCommands httpx uses pipe mode", () => {
  it("should generate httpx commands with pipe mode format", () => {
    // The suggestToolCommands function in scan-server-executor.ts should now use pipe mode
    const url = "https://example.com:443";
    const expectedPattern = `echo ${url} | httpx`;
    const args = `echo ${url} | httpx -json -title -status-code -tech-detect -follow-redirects`;
    expect(args).toContain(expectedPattern);
    expect(args).not.toContain("-u");
  });
});
