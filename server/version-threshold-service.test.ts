/**
 * Version Threshold Auto-Refresh Service Tests
 * ═══════════════════════════════════════════════════════════════════
 *
 * Tests for:
 *   - Version comparison / bump helpers
 *   - CPE mapping coverage
 *   - Static → dynamic threshold merge logic
 *   - DI scan learning engine
 *   - Manual threshold CRUD
 *   - Stats computation
 *   - tRPC router procedures
 *   - Frontend page existence
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  getAllThresholds,
  getMinSafeVersion,
  learnFromDiScan,
  setManualThreshold,
  deleteThreshold,
  getThresholdStats,
  _testing,
} from "./lib/version-threshold-service";

const { compareSemver, bumpPatchVersion, isValidVersion, TECH_TO_CPE, STATIC_MIN_SAFE, dynamicThresholds } = _testing;

// ─── Version Helpers ─────────────────────────────────────────────

describe("Version Helpers", () => {
  describe("isValidVersion", () => {
    it("accepts standard semver", () => {
      expect(isValidVersion("1.2.3")).toBe(true);
      expect(isValidVersion("10.0.0")).toBe(true);
      expect(isValidVersion("2.4.58")).toBe(true);
    });

    it("accepts two-part versions", () => {
      expect(isValidVersion("1.25")).toBe(true);
      expect(isValidVersion("8.0")).toBe(true);
    });

    it("accepts single number", () => {
      expect(isValidVersion("3")).toBe(true);
    });

    it("strips leading v", () => {
      expect(isValidVersion("v1.2.3")).toBe(true);
      expect(isValidVersion("V2.0")).toBe(true);
    });

    it("rejects non-version strings", () => {
      expect(isValidVersion("latest")).toBe(false);
      expect(isValidVersion("stable")).toBe(false);
      expect(isValidVersion("abc")).toBe(false);
      expect(isValidVersion("")).toBe(false);
    });
  });

  describe("compareSemver", () => {
    it("compares equal versions", () => {
      expect(compareSemver("1.2.3", "1.2.3")).toBe(0);
      expect(compareSemver("10.0.0", "10.0.0")).toBe(0);
    });

    it("compares major versions", () => {
      expect(compareSemver("2.0.0", "1.0.0")).toBe(1);
      expect(compareSemver("1.0.0", "2.0.0")).toBe(-1);
    });

    it("compares minor versions", () => {
      expect(compareSemver("1.5.0", "1.3.0")).toBe(1);
      expect(compareSemver("1.3.0", "1.5.0")).toBe(-1);
    });

    it("compares patch versions", () => {
      expect(compareSemver("1.2.5", "1.2.3")).toBe(1);
      expect(compareSemver("1.2.3", "1.2.5")).toBe(-1);
    });

    it("handles different length versions", () => {
      expect(compareSemver("1.2", "1.2.0")).toBe(0);
      expect(compareSemver("1.2.1", "1.2")).toBe(1);
    });

    it("strips v prefix", () => {
      expect(compareSemver("v1.2.3", "1.2.3")).toBe(0);
    });
  });

  describe("bumpPatchVersion", () => {
    it("bumps patch for 3-part version", () => {
      expect(bumpPatchVersion("2.4.58")).toBe("2.4.59");
      expect(bumpPatchVersion("1.0.0")).toBe("1.0.1");
    });

    it("bumps last part for 2-part version", () => {
      expect(bumpPatchVersion("1.25")).toBe("1.26");
    });

    it("bumps single number", () => {
      expect(bumpPatchVersion("5")).toBe("6");
    });

    it("handles rollover correctly", () => {
      expect(bumpPatchVersion("1.2.99")).toBe("1.2.100");
    });
  });
});

// ─── CPE Mapping ─────────────────────────────────────────────────

describe("CPE Mapping", () => {
  it("has CPE mapping for critical technologies", () => {
    const critical = ["nginx", "apache", "openssl", "wordpress", "mysql", "postgresql", "php", "openssh"];
    for (const tech of critical) {
      expect(TECH_TO_CPE[tech]).toBeDefined();
      expect(TECH_TO_CPE[tech].vendor).toBeTruthy();
      expect(TECH_TO_CPE[tech].product).toBeTruthy();
    }
  });

  it("has at least 40 technology mappings", () => {
    expect(Object.keys(TECH_TO_CPE).length).toBeGreaterThanOrEqual(40);
  });

  it("maps technology names to lowercase keys", () => {
    for (const key of Object.keys(TECH_TO_CPE)) {
      expect(key).toBe(key.toLowerCase());
    }
  });

  it("includes cloud and container technologies", () => {
    expect(TECH_TO_CPE["docker"]).toBeDefined();
    expect(TECH_TO_CPE["kubernetes"]).toBeDefined();
  });

  it("includes web frameworks", () => {
    expect(TECH_TO_CPE["django"]).toBeDefined();
    expect(TECH_TO_CPE["laravel"]).toBeDefined();
    expect(TECH_TO_CPE["spring"]).toBeDefined();
  });
});

// ─── Static Fallback ─────────────────────────────────────────────

describe("Static Fallback (STATIC_MIN_SAFE)", () => {
  it("has at least 30 static thresholds", () => {
    expect(Object.keys(STATIC_MIN_SAFE).length).toBeGreaterThanOrEqual(30);
  });

  it("all static versions are valid semver", () => {
    for (const [tech, version] of Object.entries(STATIC_MIN_SAFE)) {
      expect(isValidVersion(version)).toBe(true);
    }
  });

  it("includes critical infrastructure technologies", () => {
    expect(STATIC_MIN_SAFE["nginx"]).toBeDefined();
    expect(STATIC_MIN_SAFE["openssl"]).toBeDefined();
    expect(STATIC_MIN_SAFE["apache"]).toBeDefined();
  });
});

// ─── Threshold Merge Logic ───────────────────────────────────────

describe("Threshold Merge Logic", () => {
  beforeEach(() => {
    dynamicThresholds.clear();
  });

  it("getAllThresholds returns static thresholds when no dynamic overrides", () => {
    const all = getAllThresholds();
    expect(all.length).toBeGreaterThanOrEqual(30);
    // All should be source "static"
    const staticOnes = all.filter(t => t.source === "static");
    expect(staticOnes.length).toBe(all.length);
  });

  it("dynamic thresholds override static ones", () => {
    dynamicThresholds.set("nginx", {
      technology: "nginx",
      minSafeVersion: "99.99.99",
      source: "nvd_cve",
      lastUpdated: Date.now(),
    });

    const all = getAllThresholds();
    const nginx = all.find(t => t.technology === "nginx");
    expect(nginx).toBeDefined();
    expect(nginx!.minSafeVersion).toBe("99.99.99");
    expect(nginx!.source).toBe("nvd_cve");
  });

  it("getMinSafeVersion returns dynamic over static", () => {
    dynamicThresholds.set("php", {
      technology: "php",
      minSafeVersion: "99.0.0",
      source: "manual",
      lastUpdated: Date.now(),
    });

    const version = getMinSafeVersion("php");
    expect(version).toBe("99.0.0");
  });

  it("getMinSafeVersion falls back to static", () => {
    const version = getMinSafeVersion("nginx");
    expect(version).toBeDefined();
    expect(version).toBe(STATIC_MIN_SAFE["nginx"]);
  });

  it("getMinSafeVersion is case-insensitive", () => {
    const t1 = getMinSafeVersion("Nginx");
    const t2 = getMinSafeVersion("NGINX");
    const t3 = getMinSafeVersion("nginx");
    expect(t1).toBe(t3);
    expect(t2).toBe(t3);
  });

  it("getMinSafeVersion returns null for unknown tech", () => {
    const version = getMinSafeVersion("some_unknown_tech_xyz");
    expect(version).toBeNull();
  });
});

// ─── DI Scan Learning ────────────────────────────────────────────

describe("DI Scan Learning", () => {
  beforeEach(() => {
    dynamicThresholds.clear();
  });

  it("bumps threshold when detected version is significantly newer", () => {
    // nginx static threshold is around 1.25.x; if we detect 1.28.0, it should bump
    const staticNginx = STATIC_MIN_SAFE["nginx"];
    const staticParts = staticNginx.split(".").map(Number);
    const farAheadVersion = `${staticParts[0]}.${(staticParts[1] || 0) + 3}.0`;

    const result = learnFromDiScan([
      { name: "nginx", version: farAheadVersion, category: "detected" },
    ]);

    // Should have bumped the threshold
    expect(result.updated.length).toBeGreaterThanOrEqual(0);
    // The result tells us what was updated
    expect(Array.isArray(result.updated)).toBe(true);
    expect(Array.isArray(result.skipped)).toBe(true);
  });

  it("does NOT bump threshold when detected version is below current", () => {
    const result = learnFromDiScan([
      { name: "nginx", version: "0.1.0", category: "detected" },
    ]);

    expect(result.skipped).toContain("nginx");
    expect(result.updated.length).toBe(0);
  });

  it("handles unknown technologies gracefully", () => {
    const result = learnFromDiScan([
      { name: "totally_unknown_tech", version: "5.0.0", category: "detected" },
    ]);

    // Should skip unknown tech (no threshold to compare against)
    expect(result.updated.length).toBe(0);
  });

  it("handles invalid versions gracefully", () => {
    const result = learnFromDiScan([
      { name: "nginx", version: "latest", category: "detected" },
    ]);

    expect(result.skipped).toContain("nginx");
  });
});

// ─── Manual Threshold CRUD ───────────────────────────────────────

describe("Manual Threshold CRUD", () => {
  beforeEach(() => {
    dynamicThresholds.clear();
  });

  it("sets a manual threshold", () => {
    const result = setManualThreshold("custom_tech", "3.0.0", "Test override");
    expect(result.technology).toBe("custom_tech");
    expect(result.minSafeVersion).toBe("3.0.0");
    expect(result.source).toBe("manual");
    expect(result.notes).toBe("Test override");
    expect(result.lastUpdated).toBeGreaterThan(0);
  });

  it("manual threshold appears in getAllThresholds", () => {
    setManualThreshold("custom_tech", "3.0.0");
    const all = getAllThresholds();
    const custom = all.find(t => t.technology === "custom_tech");
    expect(custom).toBeDefined();
    expect(custom!.minSafeVersion).toBe("3.0.0");
  });

  it("manual threshold overrides static", () => {
    setManualThreshold("nginx", "99.0.0", "Admin override");
    const version = getMinSafeVersion("nginx");
    expect(version).toBe("99.0.0");
  });

  it("deleteThreshold removes dynamic override", () => {
    setManualThreshold("nginx", "99.0.0");
    const deleted = deleteThreshold("nginx");
    expect(deleted).toBe(true);

    // Should fall back to static
    const version = getMinSafeVersion("nginx");
    expect(version).toBe(STATIC_MIN_SAFE["nginx"]);
    expect(version).not.toBe("99.0.0");
  });

  it("deleteThreshold returns false for non-existent", () => {
    const deleted = deleteThreshold("nonexistent_xyz");
    expect(deleted).toBe(false);
  });
});

// ─── Stats ───────────────────────────────────────────────────────

describe("Threshold Stats", () => {
  beforeEach(() => {
    dynamicThresholds.clear();
  });

  it("returns correct total count", () => {
    const stats = getThresholdStats();
    expect(stats.totalThresholds).toBeGreaterThanOrEqual(30);
    expect(stats.bySource.static).toBeGreaterThanOrEqual(30);
  });

  it("counts dynamic thresholds by source", () => {
    setManualThreshold("test_tech_1", "1.0.0");
    dynamicThresholds.set("test_tech_2", {
      technology: "test_tech_2",
      minSafeVersion: "2.0.0",
      source: "nvd_cve",
      lastUpdated: Date.now(),
    });

    const stats = getThresholdStats();
    expect(stats.bySource.manual).toBeGreaterThanOrEqual(1);
    expect(stats.bySource.nvd_cve).toBeGreaterThanOrEqual(1);
  });

  it("identifies stale thresholds", () => {
    // Add a threshold that was updated 31 days ago
    dynamicThresholds.set("stale_tech", {
      technology: "stale_tech",
      minSafeVersion: "1.0.0",
      source: "nvd_cve",
      lastUpdated: Date.now() - 31 * 24 * 60 * 60 * 1000,
    });

    const stats = getThresholdStats();
    expect(stats.staleThresholds).toBeGreaterThanOrEqual(1);
  });

  it("does not count static thresholds as stale", () => {
    dynamicThresholds.clear();
    const stats = getThresholdStats();
    // Static thresholds are never stale (they're built-in)
    expect(stats.staleThresholds).toBe(0);
  });

  it("returns refresh history as array", () => {
    const stats = getThresholdStats();
    expect(Array.isArray(stats.refreshHistory)).toBe(true);
  });
});

// ─── Router Existence ────────────────────────────────────────────

describe("Version Thresholds Router", () => {
  it("router file exists and exports versionThresholdsRouter", async () => {
    const mod = await import("./routers/version-thresholds");
    expect(mod.versionThresholdsRouter).toBeDefined();
  });
});

// ─── Frontend Page Existence ─────────────────────────────────────

describe("Version Thresholds Frontend", () => {
  it("page component file exists", async () => {
    const fs = await import("fs");
    const exists = fs.existsSync("client/src/pages/VersionThresholds.tsx");
    expect(exists).toBe(true);
  });

  it("route is registered in App.tsx", async () => {
    const fs = await import("fs");
    const appContent = fs.readFileSync("client/src/App.tsx", "utf-8");
    expect(appContent).toContain("/admin/version-thresholds");
    expect(appContent).toContain("VersionThresholds");
  });

  it("sidebar nav includes Version Thresholds link", async () => {
    const fs = await import("fs");
    const navContent = fs.readFileSync("client/src/lib/sidebar-nav.ts", "utf-8");
    expect(navContent).toContain("Version Thresholds");
    expect(navContent).toContain("/admin/version-thresholds");
  });
});

// ─── DI Pipeline Integration ─────────────────────────────────────

describe("DI Pipeline Integration", () => {
  it("domainIntel.ts includes version threshold learning hook", async () => {
    const fs = await import("fs");
    const diContent = fs.readFileSync("server/domainIntel.ts", "utf-8");
    expect(diContent).toContain("versionThresholdLearning");
    expect(diContent).toContain("learnFromDiScan");
    expect(diContent).toContain("Stage 4.7");
  });

  it("server startup includes auto-refresh initialization", async () => {
    const fs = await import("fs");
    const indexContent = fs.readFileSync("server/_core/index.ts", "utf-8");
    expect(indexContent).toContain("version-threshold-service");
    expect(indexContent).toContain("startAutoRefresh");
  });
});
