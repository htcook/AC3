import { describe, it, expect } from "vitest";
import { compareVersions } from "./lib/service-fingerprinter";

describe("compareVersions — numeric (semver-style), not lexicographic", () => {
  it("orders segments numerically, not by character code", () => {
    // The bug this replaces: '2.4.9' < '2.4.50' is FALSE as a string compare
    // (char '9' > '5'), so a vulnerable 2.4.9 slipped past `ver < '2.4.50'`.
    expect(compareVersions("2.4.9", "2.4.50")).toBeLessThan(0);
    expect(compareVersions("2.4.50", "2.4.9")).toBeGreaterThan(0);
  });

  it("flags the old Apache/nginx versions the CVE checks target", () => {
    // Apache path-traversal guard: ver < 2.4.50
    expect(compareVersions("2.4.9", "2.4.50") < 0).toBe(true);
    expect(compareVersions("2.4.49", "2.4.50") < 0).toBe(true);
    expect(compareVersions("2.4.50", "2.4.50") < 0).toBe(false);
    // nginx resolver guard: ver < 1.20.0
    expect(compareVersions("1.9.15", "1.20.0") < 0).toBe(true);
    expect(compareVersions("1.20.0", "1.20.0") < 0).toBe(false);
    expect(compareVersions("1.21.0", "1.20.0") < 0).toBe(false);
  });

  it("returns 0 for equal versions and handles differing segment counts", () => {
    expect(compareVersions("1.2.0", "1.2")).toBe(0); // trailing zero == absent
    expect(compareVersions("1.2", "1.2.1")).toBeLessThan(0);
    expect(compareVersions("10.0", "9.9")).toBeGreaterThan(0); // 10 > 9 numerically
  });

  it("strips non-numeric suffixes (e.g. OpenSSH pN, build tags)", () => {
    expect(compareVersions("9.8p1", "9.8")).toBe(0);
    expect(compareVersions("8.5p1", "9.8p1")).toBeLessThan(0);
    expect(compareVersions("7.5", "7.5")).toBe(0);
  });

  it("IIS <= 7.5 guard behaves numerically", () => {
    expect(compareVersions("7.5", "7.5") <= 0).toBe(true);
    expect(compareVersions("6.0", "7.5") <= 0).toBe(true);
    expect(compareVersions("10.0", "7.5") <= 0).toBe(false); // 10 > 7, not <=
  });
});
