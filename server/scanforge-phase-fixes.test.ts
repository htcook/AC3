import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

// ─── Test 1: Template request→requests normalization ────────────────────────

describe("ScanForge template request normalization", () => {
  const templatesDir = path.join(__dirname, "scanforge/templates/definitions");

  it("should find template definition files", () => {
    expect(fs.existsSync(templatesDir)).toBe(true);
    const files = fs.readdirSync(templatesDir).filter(f => f.endsWith(".json"));
    expect(files.length).toBeGreaterThan(0);
  });

  it("all templates should have either request or requests field", () => {
    const files = fs.readdirSync(templatesDir).filter(f => f.endsWith(".json"));
    for (const file of files) {
      const tmpl = JSON.parse(fs.readFileSync(path.join(templatesDir, file), "utf-8"));
      // default-creds-services-01 is multi-protocol and has neither
      if (tmpl.protocol === "multi") continue;
      const hasRequest = "request" in tmpl;
      const hasRequests = "requests" in tmpl;
      expect(hasRequest || hasRequests, `${file} has neither request nor requests`).toBe(true);
    }
  });

  it("normalization logic should convert singular request to requests array", () => {
    // Simulate the normalization logic from engagement-integration.ts
    const files = fs.readdirSync(templatesDir).filter(f => f.endsWith(".json"));
    let normalizedCount = 0;

    for (const file of files) {
      const tmpl = JSON.parse(fs.readFileSync(path.join(templatesDir, file), "utf-8"));

      // Apply the same normalization as the fix
      if (tmpl.request && !tmpl.requests) {
        tmpl.requests = [tmpl.request];
        normalizedCount++;
      }

      // After normalization, all non-multi templates should have requests array
      if (tmpl.protocol !== "multi") {
        expect(Array.isArray(tmpl.requests), `${file} should have requests array after normalization`).toBe(true);
        expect(tmpl.requests.length, `${file} should have at least 1 request`).toBeGreaterThan(0);
      }
    }

    // Most templates use singular "request", so normalization should have converted many
    expect(normalizedCount).toBeGreaterThan(20);
  });

  it("HTTP templates should have valid request path after normalization", () => {
    const files = fs.readdirSync(templatesDir).filter(f => f.endsWith(".json"));

    for (const file of files) {
      const tmpl = JSON.parse(fs.readFileSync(path.join(templatesDir, file), "utf-8"));
      if (tmpl.request && !tmpl.requests) {
        tmpl.requests = [tmpl.request];
      }

      const proto = (tmpl.protocol || "http").toLowerCase();
      if (!["http", "https"].includes(proto)) continue;

      for (const req of (tmpl.requests || [])) {
        // HTTP requests should have a method and path
        expect(req.method || "GET").toBeTruthy();
        expect(typeof req.path).toBe("string");
        expect(req.path.startsWith("/"), `${file}: path should start with /`).toBe(true);
      }
    }
  });
});

// ─── Test 2: Non-HTTP template filtering ────────────────────────────────────

describe("ScanForge non-HTTP template filtering", () => {
  const templatesDir = path.join(__dirname, "scanforge/templates/definitions");

  it("should correctly identify DNS templates as non-HTTP", () => {
    const files = fs.readdirSync(templatesDir).filter(f => f.endsWith(".json"));
    const dnsTemplates = files.filter(f => {
      const tmpl = JSON.parse(fs.readFileSync(path.join(templatesDir, f), "utf-8"));
      return tmpl.protocol === "dns";
    });

    expect(dnsTemplates.length).toBeGreaterThan(5);

    for (const file of dnsTemplates) {
      const tmpl = JSON.parse(fs.readFileSync(path.join(templatesDir, file), "utf-8"));
      const protocol = (tmpl.protocol || "http").toLowerCase();
      expect(["http", "https"].includes(protocol)).toBe(false);
    }
  });

  it("should count HTTP vs non-HTTP templates correctly", () => {
    const files = fs.readdirSync(templatesDir).filter(f => f.endsWith(".json"));
    let httpCount = 0;
    let nonHttpCount = 0;

    for (const file of files) {
      const tmpl = JSON.parse(fs.readFileSync(path.join(templatesDir, file), "utf-8"));
      const proto = (tmpl.protocol || "http").toLowerCase();
      if (["http", "https"].includes(proto)) httpCount++;
      else nonHttpCount++;
    }

    expect(httpCount).toBeGreaterThan(15);
    expect(nonHttpCount).toBeGreaterThan(5);
  });
});

// ─── Test 3: SSH fallback guard ─────────────────────────────────────────────

describe("SSH fallback guard in do-scan-api.ts", () => {
  const doScanApiPath = path.join(__dirname, "lib/do-scan-api.ts");

  it("should have SSH key check before attempting SSH fallback", () => {
    const content = fs.readFileSync(doScanApiPath, "utf-8");

    // Both fallback functions should check for SSH key
    const fallbackToSSHMatch = content.match(/async function fallbackToSSH\b[\s\S]*?^}/m);
    const fallbackToSSHRawMatch = content.match(/async function fallbackToSSHRaw\b[\s\S]*?^}/m);

    expect(fallbackToSSHMatch).toBeTruthy();
    expect(fallbackToSSHRawMatch).toBeTruthy();

    // Check that both functions have the SSH key guard
    expect(content).toContain("SCAN_SERVER_SSH_KEY");
    expect(content).toContain("sshKeyConfigured");
    expect(content).toContain("SSH fallback skipped");
    expect(content).toContain("SSH fallback unavailable");
  });

  it("fallbackToSSH should return error result when SSH key not configured", () => {
    const content = fs.readFileSync(doScanApiPath, "utf-8");

    // The guard should return early with exitCode -1 and descriptive error
    expect(content).toContain("SSH fallback unavailable (no SSH key configured)");
    expect(content).toContain("exitCode: -1");
  });

  it("fallbackToSSHRaw should also have the SSH key guard", () => {
    const content = fs.readFileSync(doScanApiPath, "utf-8");

    // Count occurrences of the guard pattern
    const guardMatches = content.match(/const sshKeyConfigured = !!\(process\.env\.SCAN_SERVER_SSH_KEY/g);
    expect(guardMatches).toBeTruthy();
    expect(guardMatches!.length).toBe(2); // One in each fallback function
  });
});

// ─── Test 4: ffuf removed from tool references ──────────────────────────────

describe("ffuf/feroxbuster removed from tool references", () => {
  const orchestratorPath = path.join(__dirname, "lib/engagement-orchestrator.ts");

  it("should not have ffuf in the available tools list", () => {
    const content = fs.readFileSync(orchestratorPath, "utf-8");

    // The toolRef block should not contain ffuf
    const toolRefSection = content.slice(
      content.indexOf("const toolRef ="),
      content.indexOf("].join('\\n')")
    );
    expect(toolRefSection).not.toContain("'ffuf:");
    expect(toolRefSection).not.toContain("'feroxbuster:");
  });

  it("should have gobuster in the available tools list", () => {
    const content = fs.readFileSync(orchestratorPath, "utf-8");

    const toolRefSection = content.slice(
      content.indexOf("const toolRef ="),
      content.indexOf("].join('\\n')")
    );
    expect(toolRefSection).toContain("'gobuster:");
  });

  it("should not have ffuf in the availableTools array", () => {
    const content = fs.readFileSync(orchestratorPath, "utf-8");

    // Find the availableTools array
    const availableToolsMatch = content.match(/availableTools:\s*\[([^\]]+)\]/);
    expect(availableToolsMatch).toBeTruthy();
    expect(availableToolsMatch![1]).not.toContain("'ffuf'");
    expect(availableToolsMatch![1]).toContain("'gobuster'");
  });

  it("Phase B prompt should reference gobuster instead of ffuf/feroxbuster", () => {
    const content = fs.readFileSync(orchestratorPath, "utf-8");

    const phaseBLine = content.match(/PHASE B.*?Login→hydra\./)?.[0] || "";
    expect(phaseBLine).toContain("gobuster");
    expect(phaseBLine).not.toContain("ffuf");
    expect(phaseBLine).not.toContain("feroxbuster");
  });
});

// ─── Test 5: engagement-integration.ts normalization in loader ──────────────

describe("engagement-integration.ts template loader normalization", () => {
  const integrationPath = path.join(__dirname, "scanforge/engine/engagement-integration.ts");

  it("should have the request→requests normalization in the template loader", () => {
    const content = fs.readFileSync(integrationPath, "utf-8");

    // The normalization block should exist
    expect(content).toContain("tmpl.request && !tmpl.requests");
    expect(content).toContain("tmpl.requests = [tmpl.request]");
  });

  it("should have non-HTTP protocol guard in executeTemplate", () => {
    const content = fs.readFileSync(integrationPath, "utf-8");

    // The protocol check should exist in executeTemplate
    expect(content).toContain("template.protocol || 'http'");
    expect(content).toContain("['http', 'https'].includes(protocol)");
  });
});
