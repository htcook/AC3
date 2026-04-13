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
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const typesPath = path.resolve(__dirname, "../client/src/lib/battlespace-types.ts");
const transformPath = path.resolve(__dirname, "../client/src/lib/battlespace-transform.ts");
const enginePath = path.resolve(__dirname, "../client/src/lib/battlespace-engine.ts");

const typesSource = fs.readFileSync(typesPath, "utf-8");
const transformSource = fs.readFileSync(transformPath, "utf-8");
const engineSource = fs.readFileSync(enginePath, "utf-8");

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
        // Check that the tech key exists in TECH_ICONS (may be quoted or unquoted)
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
      // The function looks for (Product Name) at end of title
      expect(transformSource).toContain("parenMatch");
      expect(transformSource).toContain("([^)]+)");
    });

    it("should cross-reference with asset technologies", () => {
      // The function takes assetTechs parameter
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
      // DI transform: vulnerability edges should use "exploits" not "network_link"
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
      expect(engineSource).toContain("setLineDash([2, 3])");
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
      // MESO should show badges (was false, now true)
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
