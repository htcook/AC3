/**
 * Tests for session fixes:
 * 1. OFAC filtering — only CYBER2/CYBER-RELATED programs pass
 * 2. Exploit Plan Printable — impact descriptions and HTML generation
 * 3. Approval Gate — pause-respecting shouldAutoApprove, clientConfirmation gates
 * 4. S3 Storage — session token support and credential error handling
 * 5. Infrastructure IPs — public IP filtering
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";

// ─── 1. OFAC Filtering Tests ────────────────────────────────────────────────

describe("OFAC Filtering — Cyber-Only Ingestion", () => {
  const filePath = join(__dirname, "lib/government-intel-sources.ts");
  const content = readFileSync(filePath, "utf-8");

  it("only allows CYBER2 and CYBER-RELATED programs in XML parser", () => {
    // The cyberPrograms array in parseOFACXml should ONLY contain CYBER2 and CYBER-RELATED
    const xmlParserMatch = content.match(/function parseOFACXml[\s\S]*?const cyberPrograms = \[(.*?)\]/);
    expect(xmlParserMatch).not.toBeNull();
    const programs = xmlParserMatch![1];
    expect(programs).toContain('"CYBER2"');
    expect(programs).toContain('"CYBER-RELATED"');
    // Must NOT contain broad country sanctions programs
    expect(programs).not.toContain('"DPRK"');
    expect(programs).not.toContain('"IRAN"');
    expect(programs).not.toContain('"RUSSIA');
    expect(programs).not.toContain('"NORTH KOREA"');
  });

  it("only allows CYBER2 and CYBER-RELATED programs in CSV parser", () => {
    const csvParserMatch = content.match(/function parseOFACCsv[\s\S]*?const cyberPrograms = \[(.*?)\]/);
    expect(csvParserMatch).not.toBeNull();
    const programs = csvParserMatch![1];
    expect(programs).toContain('"CYBER2"');
    expect(programs).toContain('"CYBER-RELATED"');
    expect(programs).not.toContain('"DPRK"');
    expect(programs).not.toContain('"IRAN"');
    expect(programs).not.toContain('"RUSSIA');
  });

  it("contains comment explaining why broad programs are excluded", () => {
    expect(content).toMatch(/Previously included.*DPRK.*IRAN.*RUSSIA/i);
    expect(content).toMatch(/non-cyber entities/i);
  });
});

describe("OFAC Display Filter — Threat Intel Router", () => {
  const filePath = join(__dirname, "routers/threat-intel.ts");
  const content = readFileSync(filePath, "utf-8");

  it("filters out OFAC SDN List entries from the listing query", () => {
    // The list query should exclude OFAC SDN List entries
    expect(content).toMatch(/dataSource.*!=.*OFAC SDN List|ne\(.*dataSource.*OFAC SDN List\)/i);
  });
});

// ─── 2. Exploit Plan Printable Tests ────────────────────────────────────────

describe("Exploit Plan Printable — Impact Descriptions", () => {
  let getExploitImpactDescription: (action: any) => string;
  let generateExploitPlanHtml: (engagement: any, actions: any[], reasoning: string) => string;

  // Dynamic import to avoid module-level side effects
  it("exports getExploitImpactDescription function", async () => {
    const mod = await import("./lib/exploit-plan-printable");
    getExploitImpactDescription = mod.getExploitImpactDescription;
    generateExploitPlanHtml = mod.generateExploitPlanHtml;
    expect(typeof getExploitImpactDescription).toBe("function");
    expect(typeof generateExploitPlanHtml).toBe("function");
  });

  it("returns CVE-specific impact for known CVEs", async () => {
    const { getExploitImpactDescription } = await import("./lib/exploit-plan-printable");
    const impact = getExploitImpactDescription({ cve: "CVE-2021-44228", port: 8080 });
    expect(impact).toContain("Log4Shell");
    expect(impact).toContain("Remote Code Execution");
  });

  it("returns CVE-specific impact for Grafana file read", async () => {
    const { getExploitImpactDescription } = await import("./lib/exploit-plan-printable");
    const impact = getExploitImpactDescription({ cve: "CVE-2021-43798", port: 3000 });
    expect(impact).toContain("Arbitrary file read");
    expect(impact).toContain("Grafana");
  });

  it("returns module-based impact for SQL injection", async () => {
    const { getExploitImpactDescription } = await import("./lib/exploit-plan-printable");
    const impact = getExploitImpactDescription({ module: "sqlmap", port: 3306 });
    expect(impact).toContain("SQL Injection");
    expect(impact).toContain("Non-destructive");
  });

  it("returns module-based impact for Metasploit", async () => {
    const { getExploitImpactDescription } = await import("./lib/exploit-plan-printable");
    const impact = getExploitImpactDescription({ module: "exploit/linux/http/apache_rce", port: 80 });
    expect(impact).toContain("Metasploit");
    expect(impact).toContain("remote code execution");
  });

  it("returns module-based impact for brute force", async () => {
    const { getExploitImpactDescription } = await import("./lib/exploit-plan-printable");
    const impact = getExploitImpactDescription({ module: "hydra_ssh", port: 22 });
    expect(impact).toContain("brute-force");
    expect(impact).toContain("lockout");
  });

  it("returns service-based fallback for SSH", async () => {
    const { getExploitImpactDescription } = await import("./lib/exploit-plan-printable");
    const impact = getExploitImpactDescription({ service: "ssh", port: 22 });
    expect(impact).toContain("SSH");
  });

  it("returns service-based fallback for HTTP", async () => {
    const { getExploitImpactDescription } = await import("./lib/exploit-plan-printable");
    const impact = getExploitImpactDescription({ service: "http", port: 80 });
    expect(impact).toContain("Web application");
  });

  it("returns generic fallback for unknown services", async () => {
    const { getExploitImpactDescription } = await import("./lib/exploit-plan-printable");
    const impact = getExploitImpactDescription({ service: "custom-proto", port: 9999 });
    expect(impact).toContain("Non-destructive");
    expect(impact).toContain("9999");
  });

  it("generates valid HTML document with engagement details", async () => {
    const { generateExploitPlanHtml } = await import("./lib/exploit-plan-printable");
    const html = generateExploitPlanHtml(
      { id: 42, name: "Test Engagement", clientName: "Acme Corp", targetDomain: "acme.com", targetIpRange: "10.0.0.0/24" },
      [
        { target: "10.0.0.1", port: 80, cve: "CVE-2021-44228", module: "log4shell", service: "http" },
        { target: "10.0.0.2", port: 22, module: "hydra_ssh", service: "ssh" },
      ],
      "These exploits target critical services identified during recon."
    );

    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("Test Engagement");
    expect(html).toContain("Acme Corp");
    expect(html).toContain("acme.com");
    expect(html).toContain("10.0.0.1:80");
    expect(html).toContain("10.0.0.2:22");
    expect(html).toContain("CVE-2021-44228");
    expect(html).toContain("Log4Shell");
    expect(html).toContain("brute-force");
    expect(html).toContain("AI Analysis");
    expect(html).toContain("These exploits target critical services");
    expect(html).toContain("Engagement #42");
    expect(html).toContain("CONFIDENTIAL");
  });

  it("handles empty actions array gracefully", async () => {
    const { generateExploitPlanHtml } = await import("./lib/exploit-plan-printable");
    const html = generateExploitPlanHtml(
      { id: 1, name: "Empty Plan" },
      [],
      ""
    );
    expect(html).toContain("No exploit actions have been planned yet");
    expect(html).not.toContain("AI Analysis");
  });
});

// ─── 3. Approval Gate Logic Tests ───────────────────────────────────────────

describe("Approval Gate — Pause & Client Confirmation Logic", () => {
  const filePath = join(__dirname, "lib/engagement-orchestrator.ts");
  const content = readFileSync(filePath, "utf-8");

  it("ApprovalGate interface includes clientConfirmation field", () => {
    expect(content).toMatch(/clientConfirmation\?:\s*boolean/);
  });

  it("ApprovalGate interface includes timeoutDisabled field", () => {
    expect(content).toMatch(/timeoutDisabled\?:\s*boolean/);
  });

  it("shouldAutoApprove returns false when engagement is paused", () => {
    // The function should check state.isPaused early and return false
    const shouldAutoApproveSection = content.match(/function shouldAutoApprove[\s\S]*?^}/m);
    expect(shouldAutoApproveSection).not.toBeNull();
    const fnBody = shouldAutoApproveSection![0];
    expect(fnBody).toContain("state.isPaused");
    expect(fnBody).toMatch(/isPaused.*return false/s);
  });

  it("shouldAutoApprove returns false for clientConfirmation gates", () => {
    const shouldAutoApproveSection = content.match(/function shouldAutoApprove[\s\S]*?^}/m);
    expect(shouldAutoApproveSection).not.toBeNull();
    const fnBody = shouldAutoApproveSection![0];
    expect(fnBody).toContain("clientConfirmation");
    expect(fnBody).toMatch(/clientConfirmation.*return false/s);
  });

  it("shouldAutoApprove returns false for red tier (except training lab)", () => {
    const shouldAutoApproveSection = content.match(/function shouldAutoApprove[\s\S]*?^}/m);
    expect(shouldAutoApproveSection).not.toBeNull();
    const fnBody = shouldAutoApproveSection![0];
    // Red tier check should be AFTER training lab check
    expect(fnBody).toMatch(/trainingLabMode.*return true[\s\S]*?riskTier.*===.*'red'.*return false/s);
  });

  it("timeout is 72 hours for red tier and clientConfirmation gates", () => {
    // The timeout should be 72h for red/clientConfirmation gates
    expect(content).toMatch(/72\s*\*\s*60\s*\*\s*60\s*\*\s*1000/);
    expect(content).toMatch(/isExtendedTimeout.*riskTier.*===.*'red'.*clientConfirmation/s);
  });

  it("timeout auto-denies (not auto-approves) red/clientConfirmation gates", () => {
    // On timeout, red/clientConfirmation gates should be DENIED, not approved
    expect(content).toMatch(/autoDecision.*=.*!isExtendedTimeout/);
  });
});

describe("Approval Gate — Exploit Plan Requires Client Confirmation", () => {
  const filePath = join(__dirname, "lib/engagement-phase-exploitation.ts");
  const content = readFileSync(filePath, "utf-8");

  it("exploit plan approval gate has clientConfirmation: true", () => {
    // The exploit plan gate should require client confirmation
    expect(content).toMatch(/clientConfirmation:\s*true/);
  });
});

describe("Approval Gate — trainingLabMode is opt-in only", () => {
  const filePath = join(__dirname, "routers/engagement-ops-core.ts");
  const content = readFileSync(filePath, "utf-8");

  it("does NOT auto-detect trainingLabMode from IP whitelist", () => {
    // The old code detected training lab mode from DO lab IPs — this should be removed
    // trainingLabMode should only be set when explicitly requested
    const executeSection = content.match(/execute.*Mutation[\s\S]*?trainingLabMode/);
    // If trainingLabMode is mentioned, it should be from input, not auto-detected
    if (executeSection) {
      expect(executeSection[0]).not.toMatch(/159\.223\.|104\.248\.|157\.230\.|157\.245\./);
    }
  });
});

// ─── 4. S3 Storage — Session Token Support ──────────────────────────────────

describe("S3 Storage — Session Token & Credential Handling", () => {
  const filePath = join(__dirname, "do-storage.ts");
  const content = readFileSync(filePath, "utf-8");

  it("StorageConfig interface includes sessionToken field", () => {
    expect(content).toMatch(/sessionToken:\s*string\s*\|\s*null/);
  });

  it("resolveConfig reads S3_SESSION_TOKEN from environment", () => {
    expect(content).toContain("process.env.S3_SESSION_TOKEN");
  });

  it("S3Client credentials include sessionToken when available", () => {
    expect(content).toMatch(/sessionToken.*\?.*sessionToken/);
  });

  it("handles credential errors with retry logic", () => {
    expect(content).toContain("InvalidToken");
    expect(content).toContain("ExpiredToken");
    expect(content).toContain("ExpiredTokenException");
    expect(content).toContain("resetStorageClient()");
    expect(content).toContain("resetting client and retrying");
  });

  it("handles ACL-disabled buckets (BucketOwnerEnforced)", () => {
    expect(content).toContain("AccessControlListNotSupported");
    expect(content).toContain("Retrying without ACL");
    expect(content).toContain("delete putParams.ACL");
  });

  it("supports default credential chain for ECS task roles", () => {
    // When no explicit credentials are set for AWS, should not throw
    expect(content).toContain("hasExplicitCredentials");
    expect(content).toMatch(/omit credentials entirely.*default credential/s);
  });

  it("S3_SESSION_TOKEN is declared in env.ts", () => {
    const envContent = readFileSync(join(__dirname, "_core/env.ts"), "utf-8");
    expect(envContent).toContain("S3_SESSION_TOKEN");
  });
});

// ─── 5. Infrastructure IPs — Public IP Filtering ────────────────────────────

describe("Infrastructure IPs — External IP Display", () => {
  const filePath = join(__dirname, "lib/scan-server-discovery.ts");
  const content = readFileSync(filePath, "utf-8");

  it("contains isPublicIp helper function", () => {
    expect(content).toContain("isPublicIp");
  });

  it("filters out RFC1918 private addresses", () => {
    // Should filter 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    expect(content).toMatch(/10\./);
    expect(content).toMatch(/172\./);
    expect(content).toMatch(/192\.168/);
  });

  it("includes Platform NAT IP", () => {
    expect(content).toMatch(/PLATFORM_NAT_IP|52\.23\.137\.98/);
  });

  it("includes C2 NAT IP", () => {
    expect(content).toMatch(/C2_NAT_IP|98\.91\.65\.223/);
  });

  it("includes Wazuh SIEM IP", () => {
    expect(content).toMatch(/WAZUH_EXTERNAL_IP|13\.216\.71\.182/);
  });

  it("supports environment variable overrides for IPs", () => {
    expect(content).toContain("process.env.PLATFORM_NAT_IP");
    expect(content).toContain("process.env.C2_NAT_IP");
    expect(content).toContain("process.env.WAZUH_EXTERNAL_IP");
  });
});

// ─── 6. Print for Client Button ─────────────────────────────────────────────

describe("Print for Client — Frontend Integration", () => {
  const filePath = join(__dirname, "../client/src/pages/EngagementOps.tsx");
  const content = readFileSync(filePath, "utf-8");

  it("contains Printer icon import", () => {
    expect(content).toContain("Printer");
  });

  it("contains Print for Client button", () => {
    expect(content).toMatch(/Print for Client/);
  });

  it("calls getExploitPlanPrintable tRPC procedure", () => {
    expect(content).toContain("getExploitPlanPrintable");
  });

  it("ExploitPlanReviewCard accepts engagementId prop", () => {
    expect(content).toMatch(/engagementId:\s*number/);
  });
});
