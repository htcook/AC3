import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { resolve } from "path";

/**
 * Five Rings (Go Rin No Sho) About Section — Homepage
 *
 * Validates that the homepage contains the Five Rings section with all
 * required content: kanji characters, ring names, Musashi quotes, capabilities,
 * navigation link, and proper attribution.
 */

const homePath = resolve(__dirname, "../client/src/pages/Home.tsx");
const homeSource = readFileSync(homePath, "utf-8");

const indexHtmlPath = resolve(__dirname, "../client/index.html");
const indexHtmlSource = readFileSync(indexHtmlPath, "utf-8");

describe("Five Rings (Go Rin No Sho) About Section", () => {
  describe("Section structure", () => {
    it("should have the five-rings section anchor id", () => {
      expect(homeSource).toContain('id="five-rings"');
    });

    it("should have the STRATEGIC DOCTRINE badge", () => {
      expect(homeSource).toContain("STRATEGIC DOCTRINE");
    });

    it("should have THE FIVE RINGS heading", () => {
      expect(homeSource).toContain("THE FIVE RINGS");
    });

    it("should reference Miyamoto Musashi and Go Rin No Sho", () => {
      expect(homeSource).toContain("Miyamoto Musashi");
      expect(homeSource).toContain("Go Rin No Sho");
      expect(homeSource).toContain("Book of Five Rings");
    });
  });

  describe("All five rings present", () => {
    const rings = [
      { kanji: "地", name: "EARTH", romaji: "Chi", principle: "Establish the ground truth." },
      { kanji: "水", name: "WATER", romaji: "Sui", principle: "Adapt to the terrain." },
      { kanji: "火", name: "FIRE", romaji: "Ka", principle: "Act with purpose." },
      { kanji: "風", name: "WIND", romaji: "Fū", principle: "Know other schools." },
      { kanji: "空", name: "VOID", romaji: "Kū", principle: "See beyond the immediate step." },
    ];

    rings.forEach((ring, index) => {
      describe(`Ring ${index + 1}: ${ring.name}`, () => {
        it(`should contain the kanji character ${ring.kanji}`, () => {
          expect(homeSource).toContain(ring.kanji);
        });

        it(`should contain the ring name "${ring.name}"`, () => {
          expect(homeSource).toContain(`ring: "${ring.name}"`);
        });

        it(`should contain the romaji "${ring.romaji}"`, () => {
          expect(homeSource).toContain(ring.romaji);
        });

        it(`should contain the principle "${ring.principle}"`, () => {
          expect(homeSource).toContain(ring.principle);
        });
      });
    });
  });

  describe("Ring capabilities", () => {
    it("should mention CARVER scoring for Earth ring", () => {
      expect(homeSource).toContain("CARVER");
    });

    it("should mention attack graph generation for Water ring", () => {
      expect(homeSource).toContain("attack graph generation");
    });

    it("should mention Caldera campaign for Fire ring", () => {
      expect(homeSource).toContain("Caldera campaign generation");
    });

    it("should mention threat actor profiles for Wind ring", () => {
      expect(homeSource).toContain("threat actor profiles");
    });

    it("should mention MITRE ATT&CK for Wind ring", () => {
      expect(homeSource).toContain("MITRE ATT&CK");
    });

    it("should mention risk forecasting for Void ring", () => {
      expect(homeSource).toContain("risk forecasting");
    });

    it("should mention compliance mapping for Void ring", () => {
      expect(homeSource).toContain("Compliance mapping across NIST, CMMC, and OWASP");
    });
  });

  describe("Musashi quotes", () => {
    it("should contain a Musashi quote about the Way of nature (Earth)", () => {
      expect(homeSource).toContain("The Way of strategy is the Way of nature");
    });

    it("should contain a Musashi quote about favourite weapon (Water)", () => {
      expect(homeSource).toContain("You should not have a favourite weapon");
    });

    it("should contain a Musashi quote about intention to cut (Fire)", () => {
      expect(homeSource).toContain("your intention to cut the enemy");
    });

    it("should contain a Musashi quote about knowing the Way broadly (Wind)", () => {
      expect(homeSource).toContain("If you know the Way broadly");
    });

    it("should contain a Musashi quote about the void (Void)", () => {
      expect(homeSource).toContain("In the void is virtue, and no evil");
    });
  });

  describe("Navigation", () => {
    it("should have a FIVE RINGS link in the nav bar", () => {
      expect(homeSource).toContain('href="#five-rings"');
      expect(homeSource).toContain("FIVE RINGS");
    });
  });

  describe("Attribution", () => {
    it("should credit Go Rin No Sho (1645) by Miyamoto Musashi", () => {
      expect(homeSource).toContain("1645");
      expect(homeSource).toContain("Miyamoto Musashi");
    });

    it("should credit Harrison Cook as platform architect", () => {
      expect(homeSource).toContain("Harrison Cook");
    });

    it("should link to Ace of Cloud", () => {
      expect(homeSource).toContain("aceofcloud.com");
    });
  });

  describe("Design system integration", () => {
    it("should use distinct color schemes for each ring", () => {
      expect(homeSource).toContain("amber"); // Earth
      expect(homeSource).toContain("cyan");  // Water
      expect(homeSource).toContain("red");   // Fire
      expect(homeSource).toContain("emerald"); // Wind
      expect(homeSource).toContain("violet"); // Void
    });

    it("should use the Swords icon for the section badge", () => {
      expect(homeSource).toContain("Swords");
    });

    it("should use Noto Serif JP font for kanji characters", () => {
      expect(homeSource).toContain("Noto Serif JP");
    });
  });

  describe("Font loading", () => {
    it("should include Noto Serif JP in the Google Fonts link", () => {
      expect(indexHtmlSource).toContain("Noto+Serif+JP");
    });
  });

  describe("Responsive layout", () => {
    it("should use responsive grid for capabilities (sm:grid-cols-2)", () => {
      expect(homeSource).toContain("sm:grid-cols-2");
    });

    it("should use responsive layout for ring cards (lg:flex-row)", () => {
      expect(homeSource).toContain("lg:flex-row");
    });

    it("should have responsive kanji panel width (lg:w-48)", () => {
      expect(homeSource).toContain("lg:w-48");
    });
  });
});
