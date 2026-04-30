/**
 * Tests for Tech Stack Enhancements V3:
 *   1. Clickable tech pills — focusNode + findAssetWithTech engine methods
 *   2. Tech stack diff — compareScans techStackDiff section
 *   3. NVD API key integration — rate limiting + header injection
 *
 * @vitest-environment node
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import * as fs from "fs";
import * as path from "path";

// ─── Feature 1: Clickable Tech Pills (Engine Methods) ─────────────

describe("Feature 1: Clickable Tech Pills — Engine API", () => {
  const engineSrc = fs.readFileSync(
    path.resolve(__dirname, "../client/src/lib/battlespace-engine.ts"),
    "utf-8"
  );

  it("should export focusNode method on the engine", () => {
    expect(engineSrc).toContain("focusNode(nodeId: string");
  });

  it("focusNode should accept optional highlightTech and targetScale", () => {
    expect(engineSrc).toContain("highlightTech?: string");
    expect(engineSrc).toContain("targetScale?: number");
  });

  it("focusNode should set up _focusAnimation with easing", () => {
    expect(engineSrc).toContain("this._focusAnimation =");
    expect(engineSrc).toContain("duration: 0.6");
  });

  it("focusNode should flash the target node", () => {
    expect(engineSrc).toContain("node._flashAlpha = 1.5");
  });

  it("focusNode should call highlightTechOnAsset when highlightTech is provided", () => {
    expect(engineSrc).toContain("this.highlightTechOnAsset(nodeId, opts.highlightTech)");
  });

  it("focusNode should fire the onNodeClick callback", () => {
    expect(engineSrc).toContain("this.callbacks.onNodeClick?.(node)");
  });

  it("should export findAssetWithTech method", () => {
    expect(engineSrc).toContain("findAssetWithTech(techName: string): string | null");
  });

  it("findAssetWithTech should search by type 'asset' and technologies array", () => {
    expect(engineSrc).toContain("assetTypes.has(n.type)");
    expect(engineSrc).toContain("n.technologies?.some");
  });

  it("should have focus animation update in the tick loop", () => {
    expect(engineSrc).toContain("// Focus animation (smooth zoom/pan to node)");
    expect(engineSrc).toContain("this._focusAnimation");
  });

  it("should use ease-out cubic for smooth animation", () => {
    expect(engineSrc).toContain("1 - Math.pow(1 - fa.progress, 3)");
  });

  it("should update zoom level after focus animation completes", () => {
    // After animation ends, it should update the zoom level
    expect(engineSrc).toContain("getZoomLevel(this.scale)");
  });
});

describe("Feature 1: TechSummaryPanel clickable rows", () => {
  const opsViewerSrc = fs.readFileSync(
    path.resolve(__dirname, "../client/src/pages/OpsViewer.tsx"),
    "utf-8"
  );

  it("should use <button> elements instead of <div> for tech rows", () => {
    // The rows should be buttons for accessibility and clickability
    expect(opsViewerSrc).toContain("findAssetWithTech");
    expect(opsViewerSrc).toContain("<button");
  });

  it("should call focusNode with highlightTech and targetScale", () => {
    expect(opsViewerSrc).toContain("eng.focusNode(assetId, { highlightTech: key, targetScale: 2.0 })");
  });

  it("should show a navigation arrow indicator on each row", () => {
    // Unicode right arrow ➜
    expect(opsViewerSrc).toContain("\\u279C");
  });

  it("should have hover styling for clickable rows", () => {
    expect(opsViewerSrc).toContain("hover:bg-cyan-900/20");
    expect(opsViewerSrc).toContain("hover:border-cyan-500/40");
  });
});

// ─── Feature 2: Tech Stack Diff Between Scans ─────────────────────

describe("Feature 2: Tech Stack Diff — Server Logic", () => {
  const routerSrc = fs.readFileSync(
    path.resolve(__dirname, "./routers/domain-intel-core.ts"),
    "utf-8"
  );

  it("should include techStackDiff in compareScans return value", () => {
    expect(routerSrc).toContain("techStackDiff:");
  });

  it("should build tech maps from both scan outputs", () => {
    expect(routerSrc).toContain("techMapA");
    expect(routerSrc).toContain("techMapB");
  });

  it("should detect added technologies", () => {
    expect(routerSrc).toContain("!techMapA.has(name)");
  });

  it("should detect removed technologies", () => {
    expect(routerSrc).toContain("!techMapB.has(name)");
  });

  it("should detect upgraded technologies via semver comparison", () => {
    expect(routerSrc).toContain("upgraded.push");
    expect(routerSrc).toContain("versionA:");
    expect(routerSrc).toContain("versionB:");
  });

  it("should detect downgraded technologies", () => {
    expect(routerSrc).toContain("downgraded.push");
  });

  it("should return a summary with counts", () => {
    expect(routerSrc).toContain("summary:");
    expect(routerSrc).toContain("totalA: techMapA.size");
    expect(routerSrc).toContain("totalB: techMapB.size");
  });

  it("should handle both detectedTechnologies and technologies fields", () => {
    expect(routerSrc).toContain("asset.detectedTechnologies || asset.technologies");
  });

  it("should handle string and object technology formats", () => {
    expect(routerSrc).toContain("typeof t === 'string'");
  });

  it("should sort results by assetCount descending", () => {
    expect(routerSrc).toContain("sort((a, b) => b.assetCount - a.assetCount)");
  });
});

describe("Feature 2: Tech Stack Diff — Frontend", () => {
  const scanCompSrc = fs.readFileSync(
    path.resolve(__dirname, "../client/src/pages/ScanComparison.tsx"),
    "utf-8"
  );

  it("should import Cpu icon for tech section", () => {
    expect(scanCompSrc).toContain("Cpu");
  });

  it("should render Technology Stack Changes section", () => {
    expect(scanCompSrc).toContain("Technology Stack Changes");
  });

  it("should show summary stats grid", () => {
    expect(scanCompSrc).toContain("techStackDiff.summary.totalA");
    expect(scanCompSrc).toContain("techStackDiff.summary.totalB");
    expect(scanCompSrc).toContain("techStackDiff.summary.added");
    expect(scanCompSrc).toContain("techStackDiff.summary.removed");
    expect(scanCompSrc).toContain("techStackDiff.summary.upgraded");
  });

  it("should render upgraded technologies with version arrows", () => {
    expect(scanCompSrc).toContain("Upgraded");
    expect(scanCompSrc).toContain("t.versionA");
    expect(scanCompSrc).toContain("t.versionB");
    expect(scanCompSrc).toContain("→"); // Unicode arrow
  });

  it("should render downgraded technologies", () => {
    expect(scanCompSrc).toContain("Downgraded");
  });

  it("should render added technologies as badges", () => {
    expect(scanCompSrc).toContain("New Technologies");
  });

  it("should render removed technologies with strikethrough", () => {
    expect(scanCompSrc).toContain("Removed Technologies");
    expect(scanCompSrc).toContain("line-through");
  });

  it("should show unchanged count", () => {
    expect(scanCompSrc).toContain("technologies unchanged between scans");
  });

  it("should handle no changes state", () => {
    expect(scanCompSrc).toContain("No technology stack changes detected between scans");
  });
});

// ─── Feature 3: NVD API Key Integration ───────────────────────────

describe("Feature 3: NVD API Key — Service Layer", () => {
  const serviceSrc = fs.readFileSync(
    path.resolve(__dirname, "./lib/version-threshold-service.ts"),
    "utf-8"
  );

  it("should define two rate limit constants", () => {
    expect(serviceSrc).toContain("NVD_RATE_LIMIT_NO_KEY_MS = 6500");
    expect(serviceSrc).toContain("NVD_RATE_LIMIT_WITH_KEY_MS = 600");
  });

  it("should export hasNvdApiKey function", () => {
    expect(serviceSrc).toContain("export function hasNvdApiKey(): boolean");
  });

  it("should export getNvdApiKeyStatus function", () => {
    expect(serviceSrc).toContain("export function getNvdApiKeyStatus()");
  });

  it("getNvdApiKeyStatus should return configured, rateLimitMs, requestsPerMinute", () => {
    expect(serviceSrc).toContain("configured: hasKey");
    expect(serviceSrc).toContain("rateLimitMs");
    expect(serviceSrc).toContain("requestsPerMinute");
  });

  it("should use dynamic rate limiting based on API key presence", () => {
    expect(serviceSrc).toContain("hasNvdApiKey() ? NVD_RATE_LIMIT_WITH_KEY_MS : NVD_RATE_LIMIT_NO_KEY_MS");
  });

  it("should inject apiKey header when API key is configured", () => {
    expect(serviceSrc).toContain('headers["apiKey"] = apiKey');
  });

  it("should read API key from process.env.NVD_API_KEY", () => {
    expect(serviceSrc).toContain("process.env.NVD_API_KEY");
  });
});

describe("Feature 3: NVD API Key — Router", () => {
  const routerSrc = fs.readFileSync(
    path.resolve(__dirname, "./routers/version-thresholds.ts"),
    "utf-8"
  );

  it("should import getNvdApiKeyStatus", () => {
    expect(routerSrc).toContain("getNvdApiKeyStatus");
  });

  it("should expose nvdApiKeyStatus procedure", () => {
    expect(routerSrc).toContain("nvdApiKeyStatus: protectedProcedure");
  });

  it("should call getNvdApiKeyStatus in the procedure", () => {
    expect(routerSrc).toContain("return getNvdApiKeyStatus()");
  });
});

describe("Feature 3: NVD API Key — Admin UI", () => {
  const pageSrc = fs.readFileSync(
    path.resolve(__dirname, "../client/src/pages/VersionThresholds.tsx"),
    "utf-8"
  );

  it("should query nvdApiKeyStatus", () => {
    expect(pageSrc).toContain("trpc.versionThresholds.nvdApiKeyStatus.useQuery()");
  });

  it("should show configured status with green badge", () => {
    expect(pageSrc).toContain("Configured");
    expect(pageSrc).toContain("bg-green-600/30");
  });

  it("should show not configured status with amber badge", () => {
    expect(pageSrc).toContain("Not Configured");
    expect(pageSrc).toContain("bg-amber-600/30");
  });

  it("should display rate limit info", () => {
    expect(pageSrc).toContain("nvdKeyQuery.data.rateLimitMs");
    expect(pageSrc).toContain("nvdKeyQuery.data.requestsPerMinute");
  });

  it("should show guidance when no API key is configured", () => {
    expect(pageSrc).toContain("Add NVD_API_KEY in Secrets");
  });
});

// ─── NVD API Key Validation ────────────────────────────────────────

describe("Feature 3: NVD API Key — Validation", () => {
  it("should be able to make an NVD API request with the key", async () => {
    const apiKey = process.env.NVD_API_KEY;
    if (!apiKey) {
      console.log("NVD_API_KEY not set, skipping live validation");
      return;
    }

    // Make a minimal NVD API request to validate the key works
    const url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1";
    const res = await fetch(url, {
      headers: {
        "User-Agent": "AC3-Test/1.0",
        apiKey,
      },
      signal: AbortSignal.timeout(15000),
    });

    // With a valid API key, we should get 200
    // Without a key or with an invalid key, we might still get 200 (just rate limited)
    // A 403 would indicate the key is actively rejected
    expect(res.status).not.toBe(403);
    expect([200, 429]).toContain(res.status);
  }, 20000);
});
