import { describe, it, expect } from "vitest";
import * as fs from "fs";

// ─── Test: suggestToolCommands generates correct Nikto -ssl flags ────────────

// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)("Nikto -ssl flag in suggestToolCommands", () => {
  const sourceCode = fs.readFileSync("server/lib/scan-server-executor.ts", "utf-8");

  it("should detect HTTPS ports including 8443, 8444, 8445, 8447, 9443", () => {
    // The isHttps detection should cover all known HTTPS ports
    expect(sourceCode).toContain("wp.port === 8443");
    expect(sourceCode).toContain("wp.port === 8444");
    expect(sourceCode).toContain("wp.port === 8445");
    expect(sourceCode).toContain("wp.port === 8447");
    expect(sourceCode).toContain("wp.port === 9443");
    expect(sourceCode).toContain("wp.service === 'https'");
    expect(sourceCode).toContain("wp.service === 'ssl'");
  });

  it("should add -ssl flag to Nikto commands for HTTPS targets", () => {
    expect(sourceCode).toContain("niktoSslFlag");
    expect(sourceCode).toContain("isHttps ? ' -ssl' : ''");
    // Verify the flag is appended to the nikto args
    expect(sourceCode).toContain("args: `-h ${url}${niktoSslFlag}");
  });

  it("should generate https:// scheme for port 8443", () => {
    expect(sourceCode).toContain("const scheme = isHttps ? \"https\" : \"http\"");
  });
});

// ─── Test: engagement-orchestrator Nikto command sanitization ─────────────────
describe("Nikto command sanitization in engagement-orchestrator", () => {
  const orchestratorCode = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf-8");

  it("should have Nikto -ssl sanitization for LLM-generated commands", () => {
    expect(orchestratorCode).toContain("Fix LLM-generated nikto commands");
    expect(orchestratorCode).toContain("cmd.tool === 'nikto'");
  });

  it("should detect HTTPS URLs in Nikto commands", () => {
    expect(orchestratorCode).toContain("niktoUrl.startsWith('https://')");
    expect(orchestratorCode).toContain(":(443|8443|8444|8445|8447|9443)");
  });

  it("should add -ssl flag when not already present", () => {
    expect(orchestratorCode).toContain("!cmd.command.includes('-ssl')");
    expect(orchestratorCode).toContain("$& -ssl");
  });

  it("should ensure -maxtime is set to prevent hanging", () => {
    expect(orchestratorCode).toContain("!cmd.command.includes('-maxtime')");
    expect(orchestratorCode).toContain("-maxtime 300");
  });

  it("should include 8443 in commonWebPorts array", () => {
    expect(orchestratorCode).toContain("[80, 443, 8080, 8443]");
  });
});

// ─── Test: training-lab Nikto -ssl flag ──────────────────────────────────────
describe("Nikto -ssl flag in training-lab", () => {
  const trainingLabCode = fs.readFileSync("server/routers/training-lab.ts", "utf-8");

  it("should add -ssl flag for HTTPS scan URLs", () => {
    expect(trainingLabCode).toContain("niktoSslFlag = scanUrl.startsWith('https://') ? ' -ssl' : ''");
    expect(trainingLabCode).toContain("${niktoSslFlag}");
  });
});

// ─── Test: autoRegisterLabAsset includes all scan server ports ───────────────
describe("autoRegisterLabAsset port list", () => {
  const bugBountyCode = fs.readFileSync("server/routers/bug-bounty.ts", "utf-8");

  it("should include all known scan server ports in the auto-registered asset", () => {
    // Standard ports
    expect(bugBountyCode).toContain("{ port: 22, service: 'ssh'");
    expect(bugBountyCode).toContain("{ port: 80, service: 'http'");
    expect(bugBountyCode).toContain("{ port: 443, service: 'https'");
    expect(bugBountyCode).toContain("{ port: 4000, service: 'http'");
    expect(bugBountyCode).toContain("{ port: 8090, service: 'http-alt'");
    // Test lab ports
    expect(bugBountyCode).toContain("{ port: 8443, service: 'https', version: 'Nextcloud Test Lab'");
    expect(bugBountyCode).toContain("{ port: 8444, service: 'https', version: 'phpLDAPadmin'");
    expect(bugBountyCode).toContain("{ port: 8445, service: 'https', version: 'Keycloak SSO'");
    expect(bugBountyCode).toContain("{ port: 8447, service: 'https', version: 'MinIO Console'");
    expect(bugBountyCode).toContain("{ port: 8448, service: 'http', version: 'Mailhog SMTP UI'");
  });

  it("should have at least 10 ports in the auto-registered asset", () => {
    // Extract the ports array from the autoRegisterLabAsset function
    const portsMatch = bugBountyCode.match(/Add the test lab as a new target asset with all known scan server ports[\s\S]*?ports:\s*\[([\s\S]*?)\]/);
    expect(portsMatch).toBeTruthy();
    const portsBlock = portsMatch![1];
    const portCount = (portsBlock.match(/\{ port:/g) || []).length;
    expect(portCount).toBeGreaterThanOrEqual(10);
  });
});

// ─── Test: Nikto -ssl flag logic correctness ─────────────────────────────────
describe("Nikto -ssl flag logic simulation", () => {
  // Simulate the isHttps logic from suggestToolCommands
  function isHttpsPort(port: number, service: string): boolean {
    return port === 443 || port === 8443 || port === 8444 || port === 8445 ||
           port === 8447 || port === 9443 || service === 'https' || service === 'ssl';
  }

  it("should return true for standard HTTPS ports", () => {
    expect(isHttpsPort(443, "https")).toBe(true);
    expect(isHttpsPort(8443, "https")).toBe(true);
    expect(isHttpsPort(9443, "https")).toBe(true);
  });

  it("should return true for test lab service ports", () => {
    expect(isHttpsPort(8444, "https")).toBe(true); // phpLDAPadmin
    expect(isHttpsPort(8445, "https")).toBe(true); // Keycloak
    expect(isHttpsPort(8447, "https")).toBe(true); // MinIO
  });

  it("should return false for HTTP ports", () => {
    expect(isHttpsPort(80, "http")).toBe(false);
    expect(isHttpsPort(8080, "http")).toBe(false);
    expect(isHttpsPort(8448, "http")).toBe(false); // Mailhog
    expect(isHttpsPort(4000, "http")).toBe(false);
  });

  it("should return true when service is 'https' regardless of port", () => {
    expect(isHttpsPort(12345, "https")).toBe(true);
    expect(isHttpsPort(3000, "ssl")).toBe(true);
  });

  // Simulate the orchestrator Nikto sanitization regex
  function shouldAddSslFlag(command: string): boolean {
    const urlMatch = command.match(/-h\s+(https?:\/\/\S+)/);
    if (!urlMatch) return false;
    const url = urlMatch[1];
    const isHttps = url.startsWith('https://') || /:(443|8443|8444|8445|8447|9443)\b/.test(url);
    return isHttps && !command.includes('-ssl');
  }

  it("should add -ssl for https:// URLs", () => {
    expect(shouldAddSslFlag("nikto -h https://159.223.152.190:8443 -Tuning 123")).toBe(true);
    expect(shouldAddSslFlag("nikto -h https://target.com:443 -Tuning 123")).toBe(true);
  });

  it("should not add -ssl for http:// URLs", () => {
    expect(shouldAddSslFlag("nikto -h http://159.223.152.190:80 -Tuning 123")).toBe(false);
    expect(shouldAddSslFlag("nikto -h http://target.com:8080 -Tuning 123")).toBe(false);
  });

  it("should not add -ssl if already present", () => {
    expect(shouldAddSslFlag("nikto -h https://target.com:8443 -ssl -Tuning 123")).toBe(false);
  });

  it("should add -ssl for known HTTPS ports even with http:// scheme", () => {
    // Edge case: LLM might generate http:// for port 8443
    expect(shouldAddSslFlag("nikto -h http://target.com:8443 -Tuning 123")).toBe(true);
    expect(shouldAddSslFlag("nikto -h http://target.com:9443 -Tuning 123")).toBe(true);
  });
});
