import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { resolve } from "path";

/**
 * Five Rings Section Removal & Threat Groups Update
 *
 * Validates that:
 * 1. The Five Rings section has been fully removed from the homepage
 * 2. The Threat Actor Feed now shows top 20 active groups (not all 1700+)
 * 3. Navigation links no longer reference Five Rings
 * 4. No stale references remain
 */

const homePath = resolve(__dirname, "../client/src/pages/Home.tsx");
const homeSource = readFileSync(homePath, "utf-8");

const threatFeedPath = resolve(__dirname, "../client/src/components/ThreatActorFeed.tsx");
const threatFeedSource = readFileSync(threatFeedPath, "utf-8");

describe("Five Rings Section Removal", () => {
  describe("Section content removed", () => {
    it("should NOT have the five-rings section anchor id", () => {
      expect(homeSource).not.toContain('id="five-rings"');
    });

    it("should NOT have THE FIVE RINGS heading", () => {
      expect(homeSource).not.toContain("THE FIVE RINGS");
    });

    it("should NOT have FIVE_RINGS_DATA constant", () => {
      expect(homeSource).not.toContain("FIVE_RINGS_DATA");
    });

    it("should NOT have AnimatedRingCard component", () => {
      expect(homeSource).not.toContain("AnimatedRingCard");
    });

    it("should NOT have selectedRing state", () => {
      expect(homeSource).not.toContain("selectedRing");
    });

    it("should NOT have STRATEGIC DOCTRINE badge", () => {
      expect(homeSource).not.toContain("STRATEGIC DOCTRINE");
    });

    it("should NOT reference Go Rin No Sho", () => {
      expect(homeSource).not.toContain("Go Rin No Sho");
    });
  });

  describe("Navigation updated", () => {
    it("should NOT have FIVE RINGS nav link in desktop nav", () => {
      expect(homeSource).not.toContain('href="#five-rings"');
    });

    it("should NOT have FIVE RINGS in mobile nav", () => {
      expect(homeSource).not.toContain('label: "FIVE RINGS"');
    });

    it("should still have HOW IT WORKS nav link", () => {
      expect(homeSource).toContain('href="#how-it-works"');
    });

    it("should still have CAPABILITIES nav link", () => {
      expect(homeSource).toContain('href="#capabilities"');
    });

    it("should still have THREAT FEED nav link", () => {
      expect(homeSource).toContain('href="#threat-feed"');
    });
  });

  describe("Unused imports cleaned up", () => {
    it("should NOT import Swords icon", () => {
      expect(homeSource).not.toContain("Swords");
    });

    it("should NOT import Dialog components", () => {
      expect(homeSource).not.toContain("DialogContent");
      expect(homeSource).not.toContain("DialogHeader");
    });

    it("should NOT import useInView hook", () => {
      expect(homeSource).not.toContain("useInView");
    });
  });

  describe("Remaining homepage sections intact", () => {
    it("should still have HOW IT WORKS section", () => {
      expect(homeSource).toContain('id="how-it-works"');
    });

    it("should still have WHO IT'S FOR section", () => {
      expect(homeSource).toContain('id="who-its-for"');
    });

    it("should still have CAPABILITIES section", () => {
      expect(homeSource).toContain('id="capabilities"');
    });

    it("should still have THREAT FEED section", () => {
      expect(homeSource).toContain('id="threat-feed"');
    });

    it("should still have ThreatActorFeed component", () => {
      expect(homeSource).toContain("<ThreatActorFeed");
    });
  });
});

describe("Threat Groups — Top 20 Active", () => {
  describe("Query limit", () => {
    it("should request only 20 actors from the API", () => {
      expect(threatFeedSource).toContain("limit: 20");
    });

    it("should NOT request 50 actors", () => {
      expect(threatFeedSource).not.toContain("limit: 50");
    });
  });

  describe("Display limit", () => {
    it("should slice to max 20 actors", () => {
      expect(threatFeedSource).toContain("actors.slice(0, 20)");
    });

    it("should NOT have showAll state", () => {
      expect(threatFeedSource).not.toContain("showAll");
    });

    it("should NOT have SHOW ALL button", () => {
      expect(threatFeedSource).not.toContain("SHOW ALL");
    });
  });

  describe("Updated header text", () => {
    it("should show TOP ACTIVE THREAT GROUPS heading", () => {
      expect(threatFeedSource).toContain("TOP ACTIVE THREAT GROUPS");
    });

    it("should NOT show THREAT ACTOR FEED heading", () => {
      expect(threatFeedSource).not.toContain(">THREAT ACTOR FEED<");
    });

    it("should describe top 20 most active groups", () => {
      expect(threatFeedSource).toContain("20 most active threat groups");
    });

    it("should NOT reference 1,700+ in the description", () => {
      expect(threatFeedSource).not.toContain("1,700");
    });

    it("should show ACTIVE GROUPS count label", () => {
      expect(threatFeedSource).toContain("ACTIVE GROUPS");
    });
  });

  describe("Filter tabs still work", () => {
    it("should still have filter tabs (ALL, APT, RANSOMWARE, etc.)", () => {
      expect(threatFeedSource).toContain("FILTER_TABS");
      expect(threatFeedSource).toContain('"apt"');
      expect(threatFeedSource).toContain('"ransomware"');
    });

    it("should sort by threat level (critical first)", () => {
      expect(threatFeedSource).toContain("critical: 0, high: 1, medium: 2, low: 3");
    });
  });

  describe("Detail modal still works", () => {
    it("should still have ActorDetailModal", () => {
      expect(threatFeedSource).toContain("ActorDetailModal");
    });

    it("should still have selectedActorId state", () => {
      expect(threatFeedSource).toContain("selectedActorId");
    });
  });
});
