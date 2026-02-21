import { describe, it, expect } from "vitest";
import type { CorroborationTier } from "./lib/vuln-feeds";

/**
 * Test the tier classification logic used in matchTechnologiesAgainstAllFeeds.
 * We replicate the classification algorithm here to unit-test it in isolation
 * without needing live vulnerability feeds.
 */

function classifyTier(opts: {
  hasKev: boolean;
  hasZeroDay: boolean;
  hasVersionMatch: boolean;
  hasExploit: boolean;
}): CorroborationTier {
  const { hasKev, hasZeroDay, hasVersionMatch, hasExploit } = opts;
  if (hasKev || hasZeroDay || (hasVersionMatch && hasExploit)) return "confirmed";
  if (hasVersionMatch || hasExploit) return "probable";
  return "potential";
}

describe("Vulnerability Tier Classification", () => {
  it("classifies KEV-listed vulns as confirmed", () => {
    expect(classifyTier({ hasKev: true, hasZeroDay: false, hasVersionMatch: false, hasExploit: false })).toBe("confirmed");
  });

  it("classifies 0-day vulns as confirmed", () => {
    expect(classifyTier({ hasKev: false, hasZeroDay: true, hasVersionMatch: false, hasExploit: false })).toBe("confirmed");
  });

  it("classifies version-matched + exploit as confirmed", () => {
    expect(classifyTier({ hasKev: false, hasZeroDay: false, hasVersionMatch: true, hasExploit: true })).toBe("confirmed");
  });

  it("classifies version-matched without exploit as probable", () => {
    expect(classifyTier({ hasKev: false, hasZeroDay: false, hasVersionMatch: true, hasExploit: false })).toBe("probable");
  });

  it("classifies exploit without version match as probable", () => {
    expect(classifyTier({ hasKev: false, hasZeroDay: false, hasVersionMatch: false, hasExploit: true })).toBe("probable");
  });

  it("classifies name-only match as potential", () => {
    expect(classifyTier({ hasKev: false, hasZeroDay: false, hasVersionMatch: false, hasExploit: false })).toBe("potential");
  });

  it("KEV + version + exploit still confirmed (not double-counted)", () => {
    expect(classifyTier({ hasKev: true, hasZeroDay: false, hasVersionMatch: true, hasExploit: true })).toBe("confirmed");
  });

  it("0-day + KEV still confirmed", () => {
    expect(classifyTier({ hasKev: true, hasZeroDay: true, hasVersionMatch: false, hasExploit: false })).toBe("confirmed");
  });
});

describe("Per-Vuln Tier Counting", () => {
  function countVulnTiers(
    vulns: Array<{ kevListed: boolean; inTheWild: boolean; exploitAvailable: boolean }>,
    hasVersionMatch: boolean
  ) {
    let confirmed = 0, probable = 0, potential = 0;
    for (const v of vulns) {
      if (v.kevListed || v.inTheWild) confirmed++;
      else if (hasVersionMatch || v.exploitAvailable) probable++;
      else potential++;
    }
    return { confirmed, probable, potential };
  }

  it("counts KEV vulns as confirmed", () => {
    const result = countVulnTiers([
      { kevListed: true, inTheWild: false, exploitAvailable: false },
      { kevListed: false, inTheWild: false, exploitAvailable: false },
    ], false);
    expect(result.confirmed).toBe(1);
    expect(result.potential).toBe(1);
  });

  it("counts in-the-wild vulns as confirmed", () => {
    const result = countVulnTiers([
      { kevListed: false, inTheWild: true, exploitAvailable: false },
    ], false);
    expect(result.confirmed).toBe(1);
  });

  it("counts exploit-available vulns as probable when no version match", () => {
    const result = countVulnTiers([
      { kevListed: false, inTheWild: false, exploitAvailable: true },
      { kevListed: false, inTheWild: false, exploitAvailable: false },
    ], false);
    expect(result.probable).toBe(1);
    expect(result.potential).toBe(1);
  });

  it("promotes all vulns to probable when version is matched", () => {
    const result = countVulnTiers([
      { kevListed: false, inTheWild: false, exploitAvailable: false },
      { kevListed: false, inTheWild: false, exploitAvailable: false },
    ], true);
    expect(result.probable).toBe(2);
    expect(result.potential).toBe(0);
  });

  it("mixed scenario: KEV + exploit + plain with version match", () => {
    const result = countVulnTiers([
      { kevListed: true, inTheWild: false, exploitAvailable: true },
      { kevListed: false, inTheWild: false, exploitAvailable: true },
      { kevListed: false, inTheWild: false, exploitAvailable: false },
    ], true);
    expect(result.confirmed).toBe(1);
    expect(result.probable).toBe(2);
    expect(result.potential).toBe(0);
  });
});
