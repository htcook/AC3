/**
 * Tests for Ops View / Engagement Ops UI fixes
 * 
 * Covers:
 * 1. Attack path deduplication (semantic signature instead of node IDs)
 * 2. Retry button label reflects crashed phase
 * 3. KPI percentage cap at ±999%
 * 4. Node label tooltips (structural — verified by grep)
 */
import { describe, it, expect } from "vitest";

// ═══════════════════════════════════════════════════════════════════════
// §1 — Attack Path Deduplication
// ═══════════════════════════════════════════════════════════════════════

describe("Attack path deduplication", () => {
  // Simulate the dedup logic from exploit-reasoning-engine.ts
  interface MockPath {
    id: string;
    name: string;
    description: string;
    nodes: string[];
  }

  function deduplicatePaths(paths: MockPath[], maxPaths: number): MockPath[] {
    const seen = new Set<string>();
    const unique: MockPath[] = [];
    for (const path of paths) {
      const sig = `${path.name}||${path.description}`;
      if (!seen.has(sig)) {
        seen.add(sig);
        unique.push(path);
        if (unique.length >= maxPaths) break;
      }
    }
    return unique;
  }

  it("should deduplicate paths with same name and description but different node IDs", () => {
    const paths: MockPath[] = [
      {
        id: "path-1",
        name: "XSS → SSRF",
        description: "2-step attack path crossing 2 layer(s) and 2 category/ies.",
        nodes: ["node-xss-1", "node-ssrf-1"],
      },
      {
        id: "path-2",
        name: "XSS → SSRF",
        description: "2-step attack path crossing 2 layer(s) and 2 category/ies.",
        nodes: ["node-xss-2", "node-ssrf-2"],
      },
      {
        id: "path-3",
        name: "XSS → SSRF",
        description: "2-step attack path crossing 2 layer(s) and 2 category/ies.",
        nodes: ["node-xss-3", "node-ssrf-3"],
      },
    ];

    const result = deduplicatePaths(paths, 20);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("path-1");
  });

  it("should keep paths with different names", () => {
    const paths: MockPath[] = [
      {
        id: "path-1",
        name: "XSS → SSRF",
        description: "2-step attack path.",
        nodes: ["node-xss-1", "node-ssrf-1"],
      },
      {
        id: "path-2",
        name: "SQLi → RCE",
        description: "2-step attack path.",
        nodes: ["node-sqli-1", "node-rce-1"],
      },
      {
        id: "path-3",
        name: "SSTI → LFI → RCE",
        description: "3-step attack path.",
        nodes: ["node-ssti-1", "node-lfi-1", "node-rce-2"],
      },
    ];

    const result = deduplicatePaths(paths, 20);
    expect(result).toHaveLength(3);
  });

  it("should keep paths with same name but different descriptions", () => {
    const paths: MockPath[] = [
      {
        id: "path-1",
        name: "XSS → SSRF",
        description: "2-step attack path crossing 2 layer(s).",
        nodes: ["node-xss-1", "node-ssrf-1"],
      },
      {
        id: "path-2",
        name: "XSS → SSRF",
        description: "2-step attack path crossing 1 layer(s) and 2 category/ies.",
        nodes: ["node-xss-2", "node-ssrf-2"],
      },
    ];

    const result = deduplicatePaths(paths, 20);
    expect(result).toHaveLength(2);
  });

  it("should respect maxPaths limit", () => {
    const paths: MockPath[] = Array.from({ length: 50 }, (_, i) => ({
      id: `path-${i}`,
      name: `Unique Path ${i}`,
      description: `Description ${i}`,
      nodes: [`node-${i}`],
    }));

    const result = deduplicatePaths(paths, 5);
    expect(result).toHaveLength(5);
  });

  it("should handle empty paths array", () => {
    const result = deduplicatePaths([], 20);
    expect(result).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §2 — Retry Button Label
// ═══════════════════════════════════════════════════════════════════════

describe("Retry button label", () => {
  const PHASE_LABELS: Record<string, string> = {
    idle: "Idle",
    recon: "Phase 1: Recon & Domain Discovery",
    passive_discovery: "Phase 2: Passive Discovery",
    scoping: "Phase 3: Scoping & RoE Review",
    test_plan: "Phase 4: Test Plan Generation",
    test_plan_approval: "Phase 4b: Test Plan Approval",
    enumeration: "Phase 5: Active Enumeration & Fingerprinting",
    vuln_detection: "Phase 6: Vulnerability Detection",
    social_engineering: "Phase 6b: Social Engineering",
    exploitation: "Phase 7: Exploitation",
    post_exploit: "Phase 8: Post-Exploitation",
    error: "Error",
  };

  function getRetryLabel(currentPhaseLabel?: string): string {
    if (currentPhaseLabel) {
      return `Retry ${currentPhaseLabel.replace(/^Phase \d+[a-z]?: /, "")}`;
    }
    return "Retry Scan";
  }

  it("should show 'Retry Vulnerability Detection' for vuln_detection phase", () => {
    expect(getRetryLabel(PHASE_LABELS["vuln_detection"])).toBe("Retry Vulnerability Detection");
  });

  it("should show 'Retry Active Enumeration & Fingerprinting' for enumeration phase", () => {
    expect(getRetryLabel(PHASE_LABELS["enumeration"])).toBe("Retry Active Enumeration & Fingerprinting");
  });

  it("should show 'Retry Exploitation' for exploitation phase", () => {
    expect(getRetryLabel(PHASE_LABELS["exploitation"])).toBe("Retry Exploitation");
  });

  it("should show 'Retry Passive Discovery' for passive_discovery phase", () => {
    expect(getRetryLabel(PHASE_LABELS["passive_discovery"])).toBe("Retry Passive Discovery");
  });

  it("should show 'Retry Error' for error phase (edge case)", () => {
    expect(getRetryLabel(PHASE_LABELS["error"])).toBe("Retry Error");
  });

  it("should show 'Retry Scan' when no phase label available", () => {
    expect(getRetryLabel(undefined)).toBe("Retry Scan");
  });

  it("should handle phase labels without 'Phase N:' prefix", () => {
    expect(getRetryLabel("Custom Phase Name")).toBe("Retry Custom Phase Name");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §3 — KPI Percentage Cap
// ═══════════════════════════════════════════════════════════════════════

describe("KPI percentage cap at ±999%", () => {
  function formatDeltaPercent(pct: number): string {
    const sign = pct > 0 ? "+" : "";
    const capped = Math.abs(pct) > 999 ? `${sign}${pct > 0 ? "" : "-"}999%+` : `${sign}${pct.toFixed(1)}%`;
    return capped;
  }

  it("should cap +2000% to +999%+", () => {
    expect(formatDeltaPercent(2000)).toBe("+999%+");
  });

  it("should cap -1500% to -999%+", () => {
    expect(formatDeltaPercent(-1500)).toBe("-999%+");
  });

  it("should not cap +500%", () => {
    expect(formatDeltaPercent(500)).toBe("+500.0%");
  });

  it("should not cap -200%", () => {
    expect(formatDeltaPercent(-200)).toBe("-200.0%");
  });

  it("should handle exactly +999%", () => {
    expect(formatDeltaPercent(999)).toBe("+999.0%");
  });

  it("should handle exactly -999%", () => {
    expect(formatDeltaPercent(-999)).toBe("-999.0%");
  });

  it("should cap +999.1% to +999%+", () => {
    expect(formatDeltaPercent(999.1)).toBe("+999%+");
  });

  it("should handle 0%", () => {
    expect(formatDeltaPercent(0)).toBe("0.0%");
  });

  it("should handle small positive", () => {
    expect(formatDeltaPercent(12.5)).toBe("+12.5%");
  });

  it("should handle small negative", () => {
    expect(formatDeltaPercent(-3.7)).toBe("-3.7%");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §4 — ZAP Error Detection
// ═══════════════════════════════════════════════════════════════════════

describe("ZAP error detection in error banner", () => {
  function isZapError(errorMsg: string | undefined): boolean {
    return !!errorMsg && /zap|proxy|owasp/i.test(errorMsg);
  }

  it("should detect ZAP timeout error", () => {
    expect(isZapError("ZAP scan timed out after 300s")).toBe(true);
  });

  it("should detect OWASP ZAP error", () => {
    expect(isZapError("OWASP ZAP connection refused")).toBe(true);
  });

  it("should detect proxy error", () => {
    expect(isZapError("Proxy connection failed on port 8080")).toBe(true);
  });

  it("should not match generic errors", () => {
    expect(isZapError("nuclei scan failed: template error")).toBe(false);
  });

  it("should not match undefined", () => {
    expect(isZapError(undefined)).toBe(false);
  });

  it("should be case insensitive", () => {
    expect(isZapError("zap container is not responding")).toBe(true);
    expect(isZapError("ZAP CONTAINER IS NOT RESPONDING")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// §5 — Structural Verification (tooltip attributes)
// ═══════════════════════════════════════════════════════════════════════

describe("Structural verification of tooltip attributes", () => {
  it("should have title attributes on truncated elements in OpsViewer", async () => {
    const fs = await import("fs");
    const opsViewerContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/OpsViewer.tsx",
      "utf-8"
    );

    // All truncated elements should have a title attribute
    const truncateLines = opsViewerContent.split("\n").filter((l) => l.includes("truncate"));
    for (const line of truncateLines) {
      // Skip lines that are just CSS class definitions or comments
      if (line.trim().startsWith("//") || line.trim().startsWith("*")) continue;
      expect(line).toContain("title=");
    }
  });

  it("should have semantic dedup signature in exploit-reasoning-engine.ts", async () => {
    const fs = await import("fs");
    const engineContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-reasoning-engine.ts",
      "utf-8"
    );

    // Should use name||description as signature, not just nodes.join
    expect(engineContent).toContain("path.name}||${path.description}");
    expect(engineContent).not.toContain('path.nodes.join("→")');
  });

  it("should have phase-aware retry label in EngagementOps.tsx", async () => {
    const fs = await import("fs");
    const opsContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/EngagementOps.tsx",
      "utf-8"
    );

    // Should reference currentPhaseLabel for the retry button
    expect(opsContent).toContain("resumeCapabilityQ.data?.currentPhaseLabel");
    expect(opsContent).toContain("Retry ${resumeCapabilityQ.data.currentPhaseLabel");
  });

  it("should have ZAP status check button in error banner", async () => {
    const fs = await import("fs");
    const opsContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/EngagementOps.tsx",
      "utf-8"
    );

    expect(opsContent).toContain("Check ZAP Status");
    expect(opsContent).toContain("scan-server-health");
    expect(opsContent).toContain("/zap|proxy|owasp/i");
  });
});
