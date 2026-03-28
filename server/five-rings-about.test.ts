import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { resolve } from "path";

/**
 * Five Rings (Go Rin No Sho) About Section — Homepage
 *
 * Validates that the homepage contains the Five Rings section with all
 * required content: kanji characters, ring names, Musashi quotes, capabilities,
 * navigation link, proper attribution, scroll animations, detail modals,
 * and mobile hamburger menu.
 */

const homePath = resolve(__dirname, "../client/src/pages/Home.tsx");
const homeSource = readFileSync(homePath, "utf-8");

const indexHtmlPath = resolve(__dirname, "../client/index.html");
const indexHtmlSource = readFileSync(indexHtmlPath, "utf-8");

const mainTsxPath = resolve(__dirname, "../client/src/main.tsx");
const mainTsxSource = readFileSync(mainTsxPath, "utf-8");

const engagementCtxPath = resolve(__dirname, "../client/src/contexts/EngagementContext.tsx");
const engagementCtxSource = readFileSync(engagementCtxPath, "utf-8");

const globalAiChatPath = resolve(__dirname, "../client/src/components/GlobalAiChat.tsx");
const globalAiChatSource = readFileSync(globalAiChatPath, "utf-8");

const sessionMonitorPath = resolve(__dirname, "../client/src/components/SessionTimeoutMonitor.tsx");
const sessionMonitorSource = readFileSync(sessionMonitorPath, "utf-8");

const useInViewPath = resolve(__dirname, "../client/src/hooks/useInView.ts");
const useInViewSource = readFileSync(useInViewPath, "utf-8");

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

  // ═══════════════════════════════════════════════════════════════
  //  NEW: Scroll Animations
  // ═══════════════════════════════════════════════════════════════
  describe("Scroll animations", () => {
    it("should import useInView hook", () => {
      expect(homeSource).toContain("useInView");
    });

    it("should have an AnimatedRingCard wrapper component", () => {
      expect(homeSource).toContain("AnimatedRingCard");
    });

    it("should wrap ring cards with AnimatedRingCard", () => {
      expect(homeSource).toContain("<AnimatedRingCard");
    });

    it("useInView hook should use IntersectionObserver", () => {
      expect(useInViewSource).toContain("IntersectionObserver");
    });

    it("useInView hook should be one-shot (unobserve after trigger)", () => {
      expect(useInViewSource).toContain("observer.unobserve");
    });

    it("should apply opacity and translateY transitions", () => {
      expect(homeSource).toContain("opacity: inView ? 1 : 0");
      expect(homeSource).toContain("translateY");
    });

    it("should stagger animation delays per card index", () => {
      expect(homeSource).toContain("transitionDelay");
      expect(homeSource).toContain("index * 100");
    });
  });

  // ═══════════════════════════════════════════════════════════════
  //  NEW: Interactive Ring Detail Modals
  // ═══════════════════════════════════════════════════════════════
  describe("Ring detail modals", () => {
    it("should import Dialog components", () => {
      expect(homeSource).toContain("Dialog");
      expect(homeSource).toContain("DialogContent");
      expect(homeSource).toContain("DialogHeader");
      expect(homeSource).toContain("DialogTitle");
    });

    it("should have selectedRing state for modal control", () => {
      expect(homeSource).toContain("selectedRing");
      expect(homeSource).toContain("setSelectedRing");
    });

    it("should open modal on ring card click", () => {
      expect(homeSource).toContain("onClick={() => setSelectedRing(ring)");
    });

    it("should support keyboard activation (Enter and Space)", () => {
      expect(homeSource).toContain("onKeyDown");
      expect(homeSource).toContain("'Enter'");
      expect(homeSource).toContain("' '");
    });

    it("should have EXPLORE RING hover hint", () => {
      expect(homeSource).toContain("EXPLORE RING");
    });

    it("should have FIVE_RINGS_DATA with extended modal content", () => {
      expect(homeSource).toContain("FIVE_RINGS_DATA");
    });

    it("should include strategic objectives in extended data", () => {
      expect(homeSource).toContain("objective:");
    });

    it("should include components list in extended data", () => {
      expect(homeSource).toContain("components:");
    });

    it("should include outputs list in extended data", () => {
      expect(homeSource).toContain("outputs:");
    });

    it("should include strategic questions in extended data", () => {
      expect(homeSource).toContain("strategicQuestions:");
    });

    it("should include data flow descriptions in extended data", () => {
      expect(homeSource).toContain("dataFlow:");
    });

    it("should include CARVER factors for Earth ring", () => {
      expect(homeSource).toContain("carverFactors:");
    });

    it("should include assessment criteria for Water ring", () => {
      expect(homeSource).toContain("assessmentCriteria:");
    });

    it("should include operational details for Fire ring", () => {
      expect(homeSource).toContain("operationalDetails:");
    });

    it("should include sector examples for Wind ring", () => {
      expect(homeSource).toContain("sectorExamples:");
    });

    it("should include reasoning tasks for Void ring", () => {
      expect(homeSource).toContain("reasoningTasks:");
    });

    it("should render the Dialog with open state tied to selectedRing", () => {
      expect(homeSource).toContain("open={!!selectedRing}");
    });

    it("should display ring-specific detail sections conditionally", () => {
      expect(homeSource).toContain("'carverFactors' in r");
      expect(homeSource).toContain("'assessmentCriteria' in r");
      expect(homeSource).toContain("'operationalDetails' in r");
      expect(homeSource).toContain("'sectorExamples' in r");
      expect(homeSource).toContain("'reasoningTasks' in r");
    });
  });

  // ═══════════════════════════════════════════════════════════════
  //  NEW: Mobile Hamburger Menu
  // ═══════════════════════════════════════════════════════════════
  describe("Mobile hamburger menu", () => {
    it("should import Sheet components for mobile menu", () => {
      expect(homeSource).toContain("Sheet");
      expect(homeSource).toContain("SheetTrigger");
      expect(homeSource).toContain("SheetContent");
    });

    it("should import Menu icon for hamburger trigger", () => {
      expect(homeSource).toContain("Menu");
    });

    it("should have a Sheet-based mobile navigation", () => {
      expect(homeSource).toContain("<Sheet");
      expect(homeSource).toContain("<SheetTrigger");
      expect(homeSource).toContain("<SheetContent");
    });

    it("should hide desktop nav on mobile (hidden md:flex or similar)", () => {
      expect(homeSource).toMatch(/hidden\s+(sm|md|lg):flex/);
    });

    it("should show hamburger only on mobile (md:hidden or similar)", () => {
      expect(homeSource).toMatch(/(sm|md|lg):hidden/);
    });
  });

  // ═══════════════════════════════════════════════════════════════
  //  NEW: Homepage Login Redirect Fix
  // ═══════════════════════════════════════════════════════════════
  describe("Homepage login redirect fix", () => {
    it("should define PUBLIC_ROUTES array in main.tsx", () => {
      expect(mainTsxSource).toContain("PUBLIC_ROUTES");
    });

    it("should include '/' in PUBLIC_ROUTES", () => {
      expect(mainTsxSource).toMatch(/PUBLIC_ROUTES.*=.*\[.*"\/"/s);
    });

    it("should include '/overview' in PUBLIC_ROUTES", () => {
      expect(mainTsxSource).toContain("/overview");
    });

    it("should check isPublicRoute before redirecting", () => {
      expect(mainTsxSource).toContain("isPublicRoute");
    });

    it("should skip redirect for public routes", () => {
      expect(mainTsxSource).toContain("if (isPublicRoute) return");
    });

    it("should skip redirect for portal routes", () => {
      expect(mainTsxSource).toContain('currentPath.startsWith("/portal/")');
    });

    it("should detect unauthorized by HTTP status code (not just message)", () => {
      expect(mainTsxSource).toContain("httpStatus === 401");
    });

    it("should detect unauthorized by error code", () => {
      expect(mainTsxSource).toContain("'UNAUTHORIZED'");
    });
  });

  // ═══════════════════════════════════════════════════════════════
  //  Public Route Gating — No Protected Queries on Homepage
  // ═══════════════════════════════════════════════════════════════
  describe("EngagementContext public route gating", () => {
    it("should import useLocation from wouter", () => {
      expect(engagementCtxSource).toContain('import { useLocation } from "wouter"');
    });

    it("should define PUBLIC_ROUTES", () => {
      expect(engagementCtxSource).toContain("PUBLIC_ROUTES");
    });

    it("should check isPublicRoute before firing engagements.list query", () => {
      expect(engagementCtxSource).toContain("enabled: !isPublicRoute");
    });
  });

  describe("GlobalAiChat public route gating", () => {
    it("should define PUBLIC_ROUTES for route checking", () => {
      expect(globalAiChatSource).toContain("PUBLIC_ROUTES");
    });

    it("should gate getConfig query with isPublicRoute", () => {
      expect(globalAiChatSource).toContain("enabled: !isPublicRoute");
    });

    it("should gate listSessions query with isPublicRoute", () => {
      expect(globalAiChatSource).toContain("enabled: isOpen && !isPublicRoute");
    });
  });

  describe("SessionTimeoutMonitor public route gating", () => {
    it("should define SESSION_PUBLIC_ROUTES", () => {
      expect(sessionMonitorSource).toContain("SESSION_PUBLIC_ROUTES");
    });

    it("should gate session query with isPublicRoute", () => {
      expect(sessionMonitorSource).toContain("enabled: !isPublicRoute");
    });
  });
});
