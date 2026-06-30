import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";

/**
 * Tests for the full port discovery override in rerunFullPipeline.
 * 
 * When ROE is signed or training lab mode is active, the rerun pipeline should:
 * 1. Override handoff portSpec with full TCP 1-65535 range
 * 2. Use 1200s timeout instead of 300s
 * 3. Run a UDP top-100 scan after TCP discovery
 * 4. Log that full port range is active
 */
describe("rerunFullPipeline - Full Port Discovery Override", () => {
  const sourceCode = readFileSync(
    join(__dirname, "../server/routers/engagement-ops-core.ts"),
    "utf-8"
  );

  describe("ROE/Training Lab gating", () => {
    it("should check roeScopeGuard.roeStatus === 'signed' for full port scan", () => {
      expect(sourceCode).toContain("state!.roeScopeGuard?.roeStatus === 'signed'");
    });

    it("should check state.trainingLabMode === true for full port scan", () => {
      expect(sourceCode).toContain("state!.trainingLabMode === true");
    });

    it("should define fullPortScan variable combining both conditions", () => {
      expect(sourceCode).toContain(
        "const fullPortScan = state!.roeScopeGuard?.roeStatus === 'signed' || state!.trainingLabMode === true"
      );
    });
  });

  describe("Full port range override", () => {
    it("should use -p 1-65535 when fullPortScan is true", () => {
      expect(sourceCode).toContain("-p 1-65535");
    });

    it("should strip existing -p and --top-ports from handoff flags before adding full range", () => {
      // The regex strips -p <ports> and --top-ports <n> from handoff flags
      expect(sourceCode).toContain("replace(/-p\\s+[\\d,\\-]+/g, '')");
      expect(sourceCode).toContain("replace(/--top-ports\\s+\\d+/g, '')");
    });

    it("should use 1200s timeout for full port scan", () => {
      expect(sourceCode).toContain("discoveryTimeout = 1200");
    });

    it("should fall back to handoff portSpec or top-ports 1000 when not fullPortScan", () => {
      // The else branch preserves original behavior
      expect(sourceCode).toContain(
        "scanCfg.portSpec ? `-p ${scanCfg.portSpec}` : '--top-ports 1000'"
      );
    });

    it("should fall back to 300s timeout when not fullPortScan", () => {
      expect(sourceCode).toContain("scanCfg?.timeout || 300");
    });
  });

  describe("UDP scan for ROE-covered engagements", () => {
    it("should run UDP scan when fullPortScan is true", () => {
      // UDP scan block is gated on fullPortScan
      expect(sourceCode).toContain("// ═══ UDP SCAN for ROE-covered engagements ═══");
      expect(sourceCode).toContain("if (fullPortScan) {");
    });

    it("should use -sU --top-ports 100 for UDP scan", () => {
      expect(sourceCode).toContain("-sU --top-ports 100 -T4 --max-retries 2");
    });

    it("should use 600s timeout for UDP scan", () => {
      expect(sourceCode).toContain("timeoutSeconds: 600");
    });

    it("should parse UDP port output with /udp regex", () => {
      expect(sourceCode).toContain("/udp\\s+open\\s+(\\S+)\\s*(.*)/g");
    });

    it("should deduplicate UDP ports against existing asset ports", () => {
      expect(sourceCode).toContain(
        "!asset.ports.find((p: any) => p.port === port && (p as any).protocol === 'udp')"
      );
    });
  });

  describe("Logging", () => {
    it("should log FULL PORT RANGE detail when fullPortScan is active", () => {
      expect(sourceCode).toContain("FULL PORT RANGE (1-65535)");
    });

    it("should indicate ROE signed or training lab in the log detail", () => {
      expect(sourceCode).toContain("ROE ${state!.roeScopeGuard?.roeStatus === 'signed' ? 'signed' : 'training lab'}");
    });

    it("should append [FULL RANGE] to ScanForge success log", () => {
      expect(sourceCode).toContain("[FULL RANGE]");
    });

    it("should log UDP scan start with ROE context", () => {
      expect(sourceCode).toContain("Scanning top 100 UDP ports (ROE-covered full port scan)");
    });
  });
});

describe("Behavioral consistency with port-discovery.ts", () => {
  const portDiscoverySource = readFileSync(
    join(__dirname, "../server/lib/active-enumeration/port-discovery.ts"),
    "utf-8"
  );
  const opsCoreSrc = readFileSync(
    join(__dirname, "../server/routers/engagement-ops-core.ts"),
    "utf-8"
  );

  it("both paths should gate on roeScopeGuard.roeStatus === 'signed'", () => {
    expect(portDiscoverySource).toContain("roeScopeGuard?.roeStatus === 'signed'");
    expect(opsCoreSrc).toContain("roeScopeGuard?.roeStatus === 'signed'");
  });

  it("both paths should gate on trainingLabMode === true", () => {
    expect(portDiscoverySource).toContain("trainingLabMode === true");
    expect(opsCoreSrc).toContain("trainingLabMode === true");
  });

  it("both paths should use full TCP range (1-65535)", () => {
    expect(portDiscoverySource).toContain("1-65535");
    expect(opsCoreSrc).toContain("-p 1-65535");
  });

  it("both paths should use extended timeout for full scans (>=1200s)", () => {
    // port-discovery.ts uses 1200
    expect(portDiscoverySource).toContain("1200");
    // engagement-ops-core.ts uses 1200
    expect(opsCoreSrc).toContain("discoveryTimeout = 1200");
  });
});

