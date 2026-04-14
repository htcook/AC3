/**
 * Tech Stack Visual Attachment Tests
 * ═══════════════════════════════════════════════════════════════════
 * Verifies:
 *  1. TECH_ICONS coverage for common technologies
 *  2. extractAffectedTech function in battlespace-transform
 *  3. BattlespaceNode.affectedTechnology field exists
 *  4. Vulnerability→Asset edges use "exploits" type
 *  5. Tech orbit rendering method exists in engine
 *  6. ZOOM_LEVELS.MESO has showBadges enabled
 *  7. Version-aware badges with isVersionOutdated
 *  8. Tech highlight interaction (highlightTechOnAsset)
 *  9. TechSummaryPanel in OpsViewer
 *  10. technologyVersions field on BattlespaceNode
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const typesPath = path.resolve(__dirname, "../client/src/lib/battlespace-types.ts");
const transformPath = path.resolve(__dirname, "../client/src/lib/battlespace-transform.ts");
const enginePath = path.resolve(__dirname, "../client/src/lib/battlespace-engine.ts");
const opsViewerPath = path.resolve(__dirname, "../client/src/pages/OpsViewer.tsx");

const typesSource = fs.readFileSync(typesPath, "utf-8");
const transformSource = fs.readFileSync(transformPath, "utf-8");
const engineSource = fs.readFileSync(enginePath, "utf-8");
const opsViewerSource = fs.readFileSync(opsViewerPath, "utf-8");

describe("Tech Stack Visual Attachment", () => {
  describe("TECH_ICONS Coverage", () => {
    const commonTechs = [
      "apache", "nginx", "iis", "wordpress", "php", "java", "python",
      "node", "react", "angular", "vue", "jquery", "bootstrap",
      "docker", "kubernetes", "mysql", "postgresql", "mongodb", "redis",
      "cloudflare", "akamai", "aws", "azure", "gcp",
      "exchange", "microsoft 365", "openssl", "django", "laravel",
      "spring", "flask", "rails", "express",
    ];

    for (const tech of commonTechs) {
      it(`should have icon mapping for "${tech}"`, () => {
        const escaped = tech.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const pattern = new RegExp(`(?:["']${escaped}["']|${escaped})\\s*:\\s*\\{\\s*label`);
        expect(typesSource).toMatch(pattern);
      });
    }

    it("should have a default fallback icon", () => {
      expect(typesSource).toContain('default:');
    });
  });

  describe("extractAffectedTech Function", () => {
    it("should be defined in battlespace-transform", () => {
      expect(transformSource).toContain("function extractAffectedTech(");
    });

    it("should extract parenthesized product names", () => {
      expect(transformSource).toContain("parenMatch");
      expect(transformSource).toContain("([^)]+)");
    });

    it("should cross-reference with asset technologies", () => {
      expect(transformSource).toContain("assetTechs: string[]");
    });
  });

  describe("BattlespaceNode.affectedTechnology Field", () => {
    it("should have affectedTechnology field in BattlespaceNode interface", () => {
      expect(typesSource).toContain("affectedTechnology?: string;");
    });

    it("should be set on vulnerability nodes in DI transform", () => {
      expect(transformSource).toContain("affectedTechnology: affectedTech || undefined");
    });

    it("should be set on engagement transform nodes", () => {
      expect(transformSource).toContain("affectedTechnology: n.details?.technology || n.details?.service || undefined");
    });
  });

  describe("Vulnerability Edge Type", () => {
    it("should use 'exploits' edge type for vulnerability-to-asset connections", () => {
      expect(transformSource).toContain('type: "exploits"');
    });

    it("should include affected tech as edge label", () => {
      expect(transformSource).toContain("label: affectedTech || undefined");
    });
  });

  describe("Tech Orbit Rendering", () => {
    it("should have drawTechOrbit method in engine", () => {
      expect(engineSource).toContain("private drawTechOrbit(");
    });

    it("should render at MESO and MICRO zoom levels", () => {
      expect(engineSource).toContain('this.currentZoomLevel === "MICRO" || this.currentZoomLevel === "MESO"');
      expect(engineSource).toContain("this.drawTechOrbit(ctx, n, r)");
    });

    it("should draw connecting lines from node to badge", () => {
      expect(engineSource).toContain("Connecting line from node edge to badge");
      expect(engineSource).toContain("setLineDash(isBadgeHighlighted ? [] : [2, 3])");
    });

    it("should draw pill-shaped badges", () => {
      expect(engineSource).toContain("Pill shape (rounded rect)");
    });

    it("should use orbit geometry with slow rotation", () => {
      expect(engineSource).toContain("Orbit geometry");
      expect(engineSource).toContain("Slow rotation");
    });

    it("should show affected tech badge on vulnerability nodes", () => {
      expect(engineSource).toContain('n.type === "vulnerability" && n.affectedTechnology');
    });

    it("should show tech labels on exploit edges", () => {
      expect(engineSource).toContain('e.type === "exploits" || e.type === "targets"');
    });
  });

  describe("ZOOM_LEVELS Configuration", () => {
    it("should have showBadges enabled at MESO zoom", () => {
      expect(typesSource).toMatch(/MESO:\s*\{[^}]*showBadges:\s*true/);
    });

    it("should have showBadges enabled at MICRO zoom", () => {
      expect(typesSource).toMatch(/MICRO:\s*\{[^}]*showBadges:\s*true/);
    });

    it("should NOT have showBadges at MACRO zoom", () => {
      expect(typesSource).toMatch(/MACRO:\s*\{[^}]*showBadges:\s*false/);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// NEW: Version-Aware Badges Tests
// ═══════════════════════════════════════════════════════════════════
describe("Version-Aware Badges", () => {
  describe("isVersionOutdated function", () => {
    it("should be exported from battlespace-types", () => {
      expect(typesSource).toContain("export function isVersionOutdated(");
    });

    it("should accept techKey and version parameters", () => {
      expect(typesSource).toContain("isVersionOutdated(techKey: string, version: string): boolean");
    });

    it("should use KNOWN_MIN_SAFE_VERSIONS lookup", () => {
      expect(typesSource).toContain("KNOWN_MIN_SAFE_VERSIONS");
      expect(typesSource).toContain("const minSafe = KNOWN_MIN_SAFE_VERSIONS[key]");
    });

    it("should strip leading v from version strings", () => {
      expect(typesSource).toContain('version.replace(/^v/i, "")');
    });

    it("should return false for unknown technologies", () => {
      expect(typesSource).toContain("if (!minSafe || !version) return false");
    });
  });

  describe("KNOWN_MIN_SAFE_VERSIONS", () => {
    it("should be exported from battlespace-types", () => {
      expect(typesSource).toContain("export const KNOWN_MIN_SAFE_VERSIONS");
    });

    const requiredTechs = [
      "nginx", "apache", "php", "mysql", "wordpress", "jquery",
      "openssl", "docker", "kubernetes", "postgresql", "mongodb",
    ];

    for (const tech of requiredTechs) {
      it(`should have minimum safe version for "${tech}"`, () => {
        expect(typesSource).toMatch(new RegExp(`["']?${tech}["']?\\s*:\\s*"`));
      });
    }
  });

  describe("compareSemver helper", () => {
    it("should exist as a private function in battlespace-types", () => {
      expect(typesSource).toContain("function compareSemver(a: string, b: string): number");
    });
  });

  describe("technologyVersions field", () => {
    it("should be on BattlespaceNode interface", () => {
      expect(typesSource).toContain("technologyVersions?: Record<string, string>");
    });

    it("should be populated in DI scan transform", () => {
      expect(transformSource).toContain("technologyVersions:");
    });
  });

  describe("Version display in drawTechOrbit", () => {
    it("should read technologyVersions from node", () => {
      expect(engineSource).toContain("n.technologyVersions || {}");
    });

    it("should call isVersionOutdated for each tech", () => {
      expect(engineSource).toContain("isVersionOutdated(key, ver)");
    });

    it("should display version text at MICRO zoom", () => {
      expect(engineSource).toContain('badge.version && this.currentZoomLevel === "MICRO"');
    });

    it("should use red fill for outdated badges", () => {
      expect(engineSource).toContain("rgba(40,8,8,0.92)");
    });

    it("should use red border for outdated badges", () => {
      expect(engineSource).toContain('#FF0040');
    });

    it("should show warning indicator for outdated at MICRO zoom", () => {
      expect(engineSource).toContain("badge.isOutdated && this.currentZoomLevel");
    });
  });

  describe("Version display in NodeDetailPanel", () => {
    it("should show version in tech stack badges", () => {
      expect(opsViewerSource).toContain("node.technologyVersions");
      expect(opsViewerSource).toContain("ver ? ` v${ver}` : \"\"");
    });

    it("should flag outdated versions with warning icon", () => {
      expect(opsViewerSource).toContain("Outdated version");
    });

    it("should use red styling for outdated tech badges", () => {
      expect(opsViewerSource).toContain("bg-[#2A0808] border-[#FF0040] text-red-400");
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// NEW: Tech Highlight Interaction Tests
// ═══════════════════════════════════════════════════════════════════
describe("Tech Highlight Interaction", () => {
  describe("Engine highlight API", () => {
    it("should have highlightTechOnAsset method", () => {
      expect(engineSource).toContain("highlightTechOnAsset(");
    });

    it("should track highlighted asset ID", () => {
      expect(engineSource).toContain("_highlightedAssetId");
    });

    it("should track highlighted tech name", () => {
      expect(engineSource).toContain("_highlightedTech");
    });

    it("should have getNodes public method", () => {
      expect(engineSource).toContain("getNodes()");
    });

    it("should have getEdges public method", () => {
      expect(engineSource).toContain("getEdges()");
    });
  });

  describe("Highlight rendering in drawTechOrbit", () => {
    it("should check if badge matches highlighted tech", () => {
      expect(engineSource).toContain("isBadgeHighlighted");
    });

    it("should dim non-highlighted badges", () => {
      expect(engineSource).toContain("dimmed");
      expect(engineSource).toContain("alphaMultiplier");
    });

    it("should use white border for highlighted badge", () => {
      expect(engineSource).toContain('isBadgeHighlighted ? "#FFFFFF"');
    });

    it("should use solid line for highlighted connecting line", () => {
      expect(engineSource).toContain("isBadgeHighlighted ? [] : [2, 3]");
    });
  });

  describe("OpsViewer click handler", () => {
    it("should call highlightTechOnAsset on vulnerability click", () => {
      expect(opsViewerSource).toContain("highlightTechOnAsset(parentId, node.affectedTechnology)");
    });

    it("should clear highlight on non-vulnerability click", () => {
      expect(opsViewerSource).toContain("highlightTechOnAsset(null, null)");
    });

    it("should clear highlight when closing NodeDetailPanel", () => {
      expect(opsViewerSource).toContain("engineRef.current?.highlightTechOnAsset(null, null)");
    });

    it("should find parent asset via edges", () => {
      expect(opsViewerSource).toContain("engineRef.current.getEdges()");
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// NEW: Tech Stack Summary Panel Tests
// ═══════════════════════════════════════════════════════════════════
describe("Tech Stack Summary Panel", () => {
  it("should have TechSummaryPanel component defined", () => {
    expect(opsViewerSource).toContain("function TechSummaryPanel(");
  });

  it("should accept visible and engineRef props", () => {
    expect(opsViewerSource).toContain("visible: boolean");
    expect(opsViewerSource).toContain("engineRef: React.RefObject<BattlespaceEngine | null>");
  });

  it("should aggregate tech data from all nodes", () => {
    expect(opsViewerSource).toContain("engineRef.current?.getNodes()");
  });

  it("should count unique technologies", () => {
    expect(opsViewerSource).toContain("uniqueTechs");
  });

  it("should count total technology instances", () => {
    expect(opsViewerSource).toContain("totalTechs");
  });

  it("should count outdated technologies", () => {
    expect(opsViewerSource).toContain("outdatedCount");
  });

  it("should sort outdated technologies first", () => {
    expect(opsViewerSource).toContain("a.outdated !== b.outdated");
  });

  it("should show stats row with unique/total/outdated counts", () => {
    expect(opsViewerSource).toContain("UNIQUE");
    expect(opsViewerSource).toContain("TOTAL");
    expect(opsViewerSource).toContain("OUTDATED");
  });

  it("should have a toggle button in the toolbar", () => {
    expect(opsViewerSource).toContain("showTechSummary");
    expect(opsViewerSource).toContain("setShowTechSummary");
    expect(opsViewerSource).toContain("Tech Stack Summary");
  });

  it("should render TechSummaryPanel in the canvas area", () => {
    expect(opsViewerSource).toContain("<TechSummaryPanel visible={showTechSummary}");
  });

  it("should show version info for each technology", () => {
    expect(opsViewerSource).toContain("data.versions");
    expect(opsViewerSource).toContain('versions.join(", v")');
  });

  it("should show empty state when no technologies detected", () => {
    expect(opsViewerSource).toContain("No technologies detected");
  });

  it("should use red styling for outdated entries", () => {
    expect(opsViewerSource).toContain("bg-[#2A0808]/50 border-[#FF0040]/40");
  });

  it("should import TECH_ICONS and isVersionOutdated", () => {
    expect(opsViewerSource).toContain("TECH_ICONS, isVersionOutdated");
  });
});
