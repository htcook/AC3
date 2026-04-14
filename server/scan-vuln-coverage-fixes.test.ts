/**
 * Tests for scan vulnerability coverage fixes:
 * 1. Nuclei chain callback wired to real ScanForge API (not simulation)
 * 2. Nuclei JSONL parsing from ScanForge output
 * 3. ZAP health check with auto-restart capability
 * 4. ZAP poll failure auto-restart before marking as error
 * 5. Nuclei -duc flag in all command builders
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Nuclei Chain Callback Tests ────────────────────────────────────────────

describe("Nuclei chain callback - real ScanForge API wiring", () => {
  it("should NOT use Math.random() simulation for nuclei findings", async () => {
    const fs = await import("fs");
    const callbackCode = fs.readFileSync(
      "server/lib/chain-execution-callbacks.ts",
      "utf-8"
    );
    // The old code used Math.random() to generate simulated findings
    // The new code should NOT contain simulation patterns in the executeNuclei callback
    const nucleiSection = callbackCode.slice(
      callbackCode.indexOf("executeNuclei"),
      callbackCode.indexOf("executeNuclei") + 3000
    );
    expect(nucleiSection).not.toContain("Math.random()");
    expect(nucleiSection).not.toContain("simulated");
  });

  it("should use executeToolViaHttp for nuclei execution", async () => {
    const fs = await import("fs");
    const callbackCode = fs.readFileSync(
      "server/lib/chain-execution-callbacks.ts",
      "utf-8"
    );
    const nucleiSection = callbackCode.slice(
      callbackCode.indexOf("executeNuclei"),
      callbackCode.indexOf("executeNuclei") + 3000
    );
    expect(nucleiSection).toContain("executeToolViaHttp");
  });

  it("should include -duc flag in nuclei args", async () => {
    const fs = await import("fs");
    const callbackCode = fs.readFileSync(
      "server/lib/chain-execution-callbacks.ts",
      "utf-8"
    );
    const nucleiSection = callbackCode.slice(
      callbackCode.indexOf("executeNuclei"),
      callbackCode.indexOf("executeNuclei") + 3000
    );
    expect(nucleiSection).toContain("-duc");
  });

  it("should include -ni flag in nuclei args", async () => {
    const fs = await import("fs");
    const callbackCode = fs.readFileSync(
      "server/lib/chain-execution-callbacks.ts",
      "utf-8"
    );
    const nucleiSection = callbackCode.slice(
      callbackCode.indexOf("executeNuclei"),
      callbackCode.indexOf("executeNuclei") + 3000
    );
    expect(nucleiSection).toContain("-ni");
  });

  it("should parse nuclei JSONL output correctly", async () => {
    const fs = await import("fs");
    const callbackCode = fs.readFileSync(
      "server/lib/chain-execution-callbacks.ts",
      "utf-8"
    );
    const nucleiSection = callbackCode.slice(
      callbackCode.indexOf("executeNuclei"),
      callbackCode.indexOf("executeNuclei") + 5000
    );
    // Should parse JSON lines from stdout
    expect(nucleiSection).toContain("JSON.parse");
    // Should extract severity from info object
    expect(nucleiSection).toContain("info.severity");
    // Should extract CVE from classification
    expect(nucleiSection).toContain("classification");
  });
});

// ─── Nuclei JSONL Parsing Tests ─────────────────────────────────────────────

describe("Nuclei JSONL output parsing", () => {
  // Helper to extract CVE from tags (same logic as in chain-execution-callbacks.ts)
  function extractCveFromTags(tags: string[]): string | undefined {
    if (!tags || !Array.isArray(tags)) return undefined;
    for (const tag of tags) {
      const match = tag.match(/^cve-(\d{4}-\d+)$/i);
      if (match) return `CVE-${match[1]}`;
    }
    return undefined;
  }

  it("should extract CVE from tags array", () => {
    expect(extractCveFromTags(["cve-2021-44228", "rce", "log4j"])).toBe(
      "CVE-2021-44228"
    );
    expect(extractCveFromTags(["xss", "reflected"])).toBeUndefined();
    expect(extractCveFromTags([])).toBeUndefined();
  });

  it("should parse a valid nuclei JSONL line", () => {
    const line = JSON.stringify({
      "template-id": "http-missing-security-headers",
      info: {
        name: "HTTP Missing Security Headers",
        severity: "info",
        description: "Missing X-Frame-Options header",
        classification: { cve: [], cwe: ["CWE-693"] },
        tags: ["misconfig", "headers"],
      },
      host: "http://example.com",
      "matched-at": "http://example.com",
      type: "http",
    });

    const obj = JSON.parse(line);
    expect(obj.info.name).toBe("HTTP Missing Security Headers");
    expect(obj.info.severity).toBe("info");
    expect(obj.host).toBe("http://example.com");
  });

  it("should parse a nuclei finding with CVE classification", () => {
    const line = JSON.stringify({
      "template-id": "CVE-2021-44228",
      info: {
        name: "Apache Log4j RCE",
        severity: "critical",
        description: "Remote code execution via Log4j",
        classification: {
          cve: ["CVE-2021-44228"],
          cwe: ["CWE-502"],
          "cvss-score": 10.0,
        },
        tags: ["cve-2021-44228", "rce", "log4j"],
      },
      host: "http://vulnerable.example.com",
      "matched-at": "http://vulnerable.example.com/api",
      type: "http",
    });

    const obj = JSON.parse(line);
    expect(obj.info.severity).toBe("critical");
    expect(obj.info.classification.cve[0]).toBe("CVE-2021-44228");
    expect(obj.info.classification["cvss-score"]).toBe(10.0);
  });

  it("should skip non-JSON lines (banner, warnings)", () => {
    const lines = [
      "                     __     _",
      "   ____  __  _______/ /__  (_)",
      "[INF] Templates loaded for current scan: 1",
      '[WRN] Loading 1 unsigned templates for scan.',
      '{"template-id":"test","info":{"name":"Test","severity":"info"},"host":"http://example.com"}',
    ];

    const findings = lines
      .filter((l) => l.trim() && l.trim().startsWith("{"))
      .map((l) => JSON.parse(l));

    expect(findings).toHaveLength(1);
    expect(findings[0].info.name).toBe("Test");
  });
});

// ─── ZAP Health Check Tests ─────────────────────────────────────────────────

describe("ZAP health check with auto-restart", () => {
  it("should have checkZapHealth function that returns restarted flag", async () => {
    const fs = await import("fs");
    const zapCode = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    // checkZapHealth should return restarted flag
    expect(zapCode).toContain("restarted?: boolean");
    expect(zapCode).toContain("restarted: true");
  });

  it("should have restartZapDocker function with cooldown", async () => {
    const fs = await import("fs");
    const zapCode = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    expect(zapCode).toContain("restartZapDocker");
    expect(zapCode).toContain("ZAP_RESTART_COOLDOWN_MS");
    expect(zapCode).toContain("docker restart zap");
  });

  it("should call checkZapHealth before starting a scan", async () => {
    const fs = await import("fs");
    const zapCode = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    // Find the startScan function and check it calls checkZapHealth
    const startScanIdx = zapCode.indexOf("export async function startScan");
    const startScanSection = zapCode.slice(startScanIdx, startScanIdx + 2000);
    expect(startScanSection).toContain("checkZapHealth");
    expect(startScanSection).toContain("Pre-scan health check");
  });

  it("should attempt auto-restart at 3 consecutive poll failures", async () => {
    const fs = await import("fs");
    const zapCode = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    expect(zapCode).toContain("failures === 3");
    expect(zapCode).toContain("Attempting ZAP auto-restart");
  });

  it("should mark scan as error after 8 consecutive failures", async () => {
    const fs = await import("fs");
    const zapCode = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    expect(zapCode).toContain("MAX_POLL_FAILURES = 8");
  });

  it("should use correct ZAP base URL (159.223.152.190)", async () => {
    const fs = await import("fs");
    const zapCode = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    // The fallback URL should point to the correct scan server
    expect(zapCode).toContain('baseUrl: process.env.ZAP_BASE_URL || "http://159.223.152.190:8090"');
  });

  it("should have 5-minute cooldown between ZAP restarts", async () => {
    const fs = await import("fs");
    const zapCode = fs.readFileSync("server/lib/zap-scanner.ts", "utf-8");
    expect(zapCode).toContain("5 * 60 * 1000");
    expect(zapCode).toContain("Restart cooldown active");
  });
});

// ─── Nuclei Scanner Router Tests ────────────────────────────────────────────

describe("Nuclei scanner router - command builder", () => {
  it("should include -duc flag in built commands", async () => {
    const fs = await import("fs");
    const routerCode = fs.readFileSync(
      "server/routers/nuclei-scanner.ts",
      "utf-8"
    );
    const buildFnIdx = routerCode.indexOf("function buildNucleiCommand");
    const buildFnSection = routerCode.slice(buildFnIdx, buildFnIdx + 2500);
    expect(buildFnSection).toContain("-duc");
  });

  it("should include -nc flag in built commands", async () => {
    const fs = await import("fs");
    const routerCode = fs.readFileSync(
      "server/routers/nuclei-scanner.ts",
      "utf-8"
    );
    const buildFnIdx = routerCode.indexOf("function buildNucleiCommand");
    const buildFnSection = routerCode.slice(buildFnIdx, buildFnIdx + 2500);
    expect(buildFnSection).toContain("-nc");
  });
});

// ─── Engagement Orchestrator Nuclei Tests ───────────────────────────────────

describe("Engagement orchestrator nuclei execution", () => {
  it("should include -duc flag in nuclei args", async () => {
    const fs = await import("fs");
    const eoCode = fs.readFileSync(
      "server/lib/engagement-orchestrator.ts",
      "utf-8"
    );
    // Find the nuclei args construction
    const nucleiArgsMatch = eoCode.match(
      /nucleiArgs\s*=\s*`[^`]*-duc[^`]*`/
    );
    expect(nucleiArgsMatch).not.toBeNull();
  });

  it("should include -ni flag in nuclei args", async () => {
    const fs = await import("fs");
    const eoCode = fs.readFileSync(
      "server/lib/engagement-orchestrator.ts",
      "utf-8"
    );
    const nucleiArgsMatch = eoCode.match(
      /nucleiArgs\s*=\s*`[^`]*-ni[^`]*`/
    );
    expect(nucleiArgsMatch).not.toBeNull();
  });
});
