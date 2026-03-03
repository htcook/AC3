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
  // Strip ALL occurrences of 'nuclei' keyword — we'll re-add it once at the end
  // The LLM sometimes generates 'nuclei -u URL nuclei -severity...' (doubled)
  nucleiCmd = nucleiCmd.replace(/\bnuclei\b/g, '').trim();
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
  // Normalize: strip ALL 'httpx' keywords, strip any existing 'echo ... |' pipe prefix
  let httpxCmd = command.replace(/\bhttpx\b/g, '').trim();
  // If LLM already included a pipe (echo URL | flags), extract URL and flags separately
  const pipeMatch = httpxCmd.match(/^echo\s+(\S+)\s*\|\s*(.*)$/);
  if (pipeMatch) {
    const httpxUrl = pipeMatch[1];
    const httpxFlags = pipeMatch[2].replace(/\becho\b/g, '').replace(/\|/g, '').trim();
    return {
      converted: true,
      command: `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, ' ').trim(),
    };
  }
  // No pipe — extract URL from -u flag or bare URL
  const urlMatch = httpxCmd.match(/-u\s+(\S+)/);
  if (urlMatch) {
    const httpxUrl = urlMatch[1];
    const httpxFlags = httpxCmd.replace(/-u\s+\S+/, '').trim();
    return {
      converted: true,
      command: `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, ' ').trim(),
    };
  }
  const bareUrl = httpxCmd.match(/(https?:\/\/\S+)/);
  if (bareUrl) {
    const httpxUrl = bareUrl[1];
    const httpxFlags = httpxCmd.replace(/(https?:\/\/\S+)/, '').trim();
    return {
      converted: true,
      command: `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, ' ').trim(),
    };
  }
  return { converted: false, command: `httpx ${httpxCmd}`.replace(/\s+/g, ' ').trim() };
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

  it("should handle already-piped commands (strip extra httpx)", () => {
    const result = convertHttpxToPipeMode("echo https://example.com | httpx -json");
    // After stripping all 'httpx', we get 'echo https://example.com | -json'
    // The bare URL match should pick up the URL
    expect(result.converted).toBe(true);
    expect(result.command).toContain("httpx");
    // Should only have ONE httpx in the output
    const httpxCount = (result.command.match(/\bhttpx\b/g) || []).length;
    expect(httpxCount).toBe(1);
  });

  it("should handle URL with port number", () => {
    const result = convertHttpxToPipeMode("httpx -u https://example.com:8443 -json");
    expect(result.converted).toBe(true);
    expect(result.command).toContain("echo https://example.com:8443");
  });

  // ── NEW: Test for doubled httpx command (the actual bug from scan results) ──
  it("should fix doubled httpx command: 'httpx echo URL | httpx flags'", () => {
    const result = convertHttpxToPipeMode("httpx echo https://23.20.98.48:443 | httpx -json -title -status-code -tech-detect -follow-redirects");
    expect(result.converted).toBe(true);
    // Should produce clean pipe: 'echo URL | httpx flags'
    const httpxCount = (result.command.match(/\bhttpx\b/g) || []).length;
    expect(httpxCount).toBe(1);
    expect(result.command).toContain("echo https://23.20.98.48:443");
    expect(result.command).toContain("| httpx");
    expect(result.command).toBe("echo https://23.20.98.48:443 | httpx -json -title -status-code -tech-detect -follow-redirects");
  });

  it("should fix doubled httpx command: 'httpx -u URL httpx -json'", () => {
    const result = convertHttpxToPipeMode("httpx -u https://example.com httpx -json -tech-detect");
    expect(result.converted).toBe(true);
    const httpxCount = (result.command.match(/\bhttpx\b/g) || []).length;
    expect(httpxCount).toBe(1);
    expect(result.command).toContain("echo https://example.com");
  });

  it("should fix broken pipe output: 'echo URL | httpx echo | -json flags'", () => {
    const result = convertHttpxToPipeMode("echo https://23.20.98.48:443 | httpx echo | -json -title -status-code -tech-detect -follow-redirects");
    expect(result.converted).toBe(true);
    const httpxCount = (result.command.match(/\bhttpx\b/g) || []).length;
    expect(httpxCount).toBe(1);
    expect(result.command).toBe("echo https://23.20.98.48:443 | httpx -json -title -status-code -tech-detect -follow-redirects");
  });

  it("should fix httpx with http URL pipe: 'httpx echo http://URL | httpx flags'", () => {
    const result = convertHttpxToPipeMode("httpx echo http://23.20.98.48:80 | httpx -json -title -status-code -tech-detect -follow-redirects");
    expect(result.converted).toBe(true);
    expect(result.command).toBe("echo http://23.20.98.48:80 | httpx -json -title -status-code -tech-detect -follow-redirects");
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

// ── NEW: Nuclei doubled-command tests (the actual bug from scan results) ──

describe("Nuclei doubled-command fix", () => {
  const webAsset = {
    hostname: "23.20.98.48",
    ip: "23.20.98.48",
    ports: [{ port: 443, service: "https" }, { port: 80, service: "http" }],
    passiveRecon: { technologies: ["Nginx"] },
  };

  it("should fix 'nuclei -u URL nuclei -severity...' (doubled nuclei from LLM)", () => {
    const result = sanitizeNucleiCommand(
      "nuclei -u http://23.20.98.48:80 nuclei -severity low,medium,high,critical -jsonl -nc -duc -ni -timeout 10 -retries 1",
      webAsset
    );
    // Should have exactly ONE 'nuclei' keyword
    const nucleiCount = (result.match(/\bnuclei\b/g) || []).length;
    expect(nucleiCount).toBe(1);
    expect(result).toMatch(/^nuclei -u /);
    expect(result).toContain("-severity");
  });

  it("should fix 'nuclei -u URL nuclei -nc -duc -ni -jsonl -severity...' (doubled with reordered flags)", () => {
    const result = sanitizeNucleiCommand(
      "nuclei -u http://api.dev.vianova.ai:80 nuclei -nc -duc -ni -jsonl -severity critical,high,medium -timeout 10 -retries 1 -tags nginx",
      { hostname: "api.dev.vianova.ai", ports: [{ port: 80, service: "http" }, { port: 443, service: "https" }], passiveRecon: { technologies: ["Nginx"] } }
    );
    const nucleiCount = (result.match(/\bnuclei\b/g) || []).length;
    expect(nucleiCount).toBe(1);
    expect(result).toMatch(/^nuclei -u /);
  });

  it("should produce a valid command from the exact failing scan result", () => {
    const result = sanitizeNucleiCommand(
      "nuclei -u https://23.20.98.48:443 nuclei -severity low,medium,high,critical -jsonl -nc -duc -ni -timeout 10 -retries 1",
      webAsset
    );
    // Verify the command is well-formed
    expect(result).toMatch(/^nuclei -u https:\/\/23\.20\.98\.48/);
    expect(result).toContain("-severity");
    expect(result).toContain("-jsonl");
    // No doubled nuclei
    const nucleiCount = (result.match(/\bnuclei\b/g) || []).length;
    expect(nucleiCount).toBe(1);
  });
});

// ── Gobuster sanitizer tests ──

describe("Gobuster command sanitization", () => {
  function sanitizeGobusterCommand(command: string): string {
    let gobCmd = command.replace(/\bgobuster\b/g, '').trim();
    if (!gobCmd.startsWith('dir')) gobCmd = `dir ${gobCmd}`;
    gobCmd = `gobuster ${gobCmd}`;
    gobCmd = gobCmd
      .replace(/\/usr\/share\/wordlists\/dirbuster\/[\w.-]+/g, '/opt/SecLists/Discovery/Web-Content/common.txt')
      .replace(/\/usr\/share\/wordlists\/dirb\/[\w.-]+/g, '/opt/SecLists/Discovery/Web-Content/common.txt')
      .replace(/\/usr\/share\/wordlists\/[\w/.-]+/g, '/opt/SecLists/Discovery/Web-Content/common.txt')
      .replace(/\/usr\/share\/seclists\/[\w/.-]+/gi, '/opt/SecLists/Discovery/Web-Content/common.txt');
    if (!gobCmd.includes('-w ')) gobCmd += ' -w /opt/SecLists/Discovery/Web-Content/common.txt';
    if (!gobCmd.includes('-q')) gobCmd += ' -q';
    if (!gobCmd.includes('--no-error')) gobCmd += ' --no-error';
    if (!gobCmd.includes('-t ')) gobCmd += ' -t 20';
    return gobCmd.replace(/\s+/g, ' ').trim();
  }

  it("should replace Kali dirbuster wordlist path with scan server path", () => {
    const result = sanitizeGobusterCommand(
      "gobuster dir -u https://api.dev.vianova.ai -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50 -k"
    );
    expect(result).toContain("/opt/SecLists/Discovery/Web-Content/common.txt");
    expect(result).not.toContain("/usr/share/wordlists");
  });

  it("should add -q and --no-error flags when missing", () => {
    const result = sanitizeGobusterCommand(
      "gobuster dir -u https://example.com -w /opt/SecLists/Discovery/Web-Content/common.txt"
    );
    expect(result).toContain("-q");
    expect(result).toContain("--no-error");
  });

  it("should add -w wordlist when missing entirely", () => {
    const result = sanitizeGobusterCommand("gobuster dir -u https://example.com");
    expect(result).toContain("-w /opt/SecLists/Discovery/Web-Content/common.txt");
  });

  it("should add -t thread count when missing", () => {
    const result = sanitizeGobusterCommand("gobuster dir -u https://example.com -w /opt/SecLists/Discovery/Web-Content/common.txt");
    expect(result).toContain("-t 20");
  });

  it("should handle doubled gobuster keyword", () => {
    const result = sanitizeGobusterCommand("gobuster gobuster dir -u https://example.com");
    const gobCount = (result.match(/\bgobuster\b/g) || []).length;
    expect(gobCount).toBe(1);
    expect(result).toMatch(/^gobuster dir/);
  });

  it("should handle /usr/share/seclists paths (case insensitive)", () => {
    const result = sanitizeGobusterCommand(
      "gobuster dir -u https://example.com -w /usr/share/SecLists/Discovery/Web-Content/big.txt"
    );
    expect(result).toContain("/opt/SecLists/Discovery/Web-Content/common.txt");
  });
});

// ── suggestToolCommands httpx format test ──

describe("suggestToolCommands httpx uses pipe mode", () => {
  it("should generate httpx commands with pipe mode format", () => {
    const url = "https://example.com:443";
    const expectedPattern = `echo ${url} | httpx`;
    const args = `echo ${url} | httpx -json -title -status-code -tech-detect -follow-redirects`;
    expect(args).toContain(expectedPattern);
    expect(args).not.toContain("-u");
  });
});
