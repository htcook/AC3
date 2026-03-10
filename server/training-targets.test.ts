/**
 * Training Targets Integration Tests
 *
 * Verifies VAmPI, DVGA, and WebGoat are properly integrated
 * into the Training Lab catalog with correct metadata.
 */
import { describe, it, expect } from "vitest";
import { TRAINING_TARGETS, type TrainingTarget } from "./routers/training-lab";

describe("Training Lab Target Catalog", () => {
  it("should contain VAmPI target", () => {
    const vampi = TRAINING_TARGETS.find(t => t.id === "vampi");
    expect(vampi).toBeDefined();
    expect(vampi!.name).toBe("VAmPI (Vulnerable REST API)");
    expect(vampi!.category).toBe("API");
    expect(vampi!.difficulty).toBe("intermediate");
    expect(vampi!.liveInstanceUrl).toContain(":5000");
    expect(vampi!.knownVulns).toContain("SQL Injection");
    expect(vampi!.knownVulns).toContain("Broken Object Level Authorization (BOLA)");
    expect(vampi!.knownVulns).toContain("Mass Assignment");
    expect(vampi!.knownVulns).toContain("JWT Authentication Bypass");
    expect(vampi!.tags).toContain("rest-api");
    expect(vampi!.tags).toContain("owasp-api-top10");
    expect(vampi!.roe.provider).toContain("NeuraLegion");
  });

  it("should contain DVGA target", () => {
    const dvga = TRAINING_TARGETS.find(t => t.id === "dvga");
    expect(dvga).toBeDefined();
    expect(dvga!.name).toBe("Damn Vulnerable GraphQL Application (DVGA)");
    expect(dvga!.category).toBe("API");
    expect(dvga!.difficulty).toBe("advanced");
    expect(dvga!.liveInstanceUrl).toContain(":5013");
    expect(dvga!.knownVulns).toContain("GraphQL Introspection");
    expect(dvga!.knownVulns).toContain("OS Command Injection");
    expect(dvga!.knownVulns).toContain("SQL Injection");
    expect(dvga!.knownVulns).toContain("SSRF");
    expect(dvga!.tags).toContain("graphql");
    expect(dvga!.roe.provider).toContain("NeuraLegion");
  });

  it("should contain WebGoat target", () => {
    const webgoat = TRAINING_TARGETS.find(t => t.id === "webgoat");
    expect(webgoat).toBeDefined();
    expect(webgoat!.name).toBe("OWASP WebGoat");
    expect(webgoat!.category).toBe("Web Application");
    expect(webgoat!.difficulty).toBe("beginner");
    expect(webgoat!.liveInstanceUrl).toContain(":8080/WebGoat");
    expect(webgoat!.knownVulns).toContain("SQL Injection");
    expect(webgoat!.knownVulns).toContain("XSS");
    expect(webgoat!.knownVulns).toContain("XXE");
    expect(webgoat!.knownVulns).toContain("Insecure Deserialization");
    expect(webgoat!.knownVulns).toContain("SSRF");
    expect(webgoat!.owaspCategories.length).toBeGreaterThanOrEqual(10);
    expect(webgoat!.tags).toContain("owasp");
    expect(webgoat!.tags).toContain("spring-boot");
    expect(webgoat!.roe.provider).toBe("OWASP Foundation");
  });

  it("all new targets should have valid liveInstanceUrl pointing to scan server", () => {
    const newTargets = ["vampi", "dvga", "webgoat"];
    for (const id of newTargets) {
      const target = TRAINING_TARGETS.find(t => t.id === id);
      expect(target).toBeDefined();
      expect(target!.liveInstanceUrl).toBeDefined();
      expect(target!.liveInstanceUrl).toContain("159.223.152.190");
    }
  });

  it("all new targets should have self-hosted RoE with no restrictions", () => {
    const newTargets = ["vampi", "dvga", "webgoat"];
    for (const id of newTargets) {
      const target = TRAINING_TARGETS.find(t => t.id === id);
      expect(target).toBeDefined();
      expect(target!.roe.requiresOwnInstance).toBe(false);
      expect(target!.roe.noBruteForce).toBe(false);
      expect(target!.roe.noDoS).toBe(false);
      expect(target!.roe.noExfiltration).toBe(false);
      expect(target!.roe.prohibited.length).toBe(0);
    }
  });

  it("all targets should have unique IDs", () => {
    const ids = TRAINING_TARGETS.map(t => t.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it("all targets should have required fields populated", () => {
    for (const target of TRAINING_TARGETS) {
      expect(target.id).toBeTruthy();
      expect(target.name).toBeTruthy();
      expect(target.description).toBeTruthy();
      expect(["beginner", "intermediate", "advanced"]).toContain(target.difficulty);
      expect(target.category).toBeTruthy();
      expect(target.roe).toBeDefined();
      expect(target.roe.provider).toBeTruthy();
      expect(target.roe.summary).toBeTruthy();
    }
  });

  it("custom target should still be the last entry", () => {
    const lastTarget = TRAINING_TARGETS[TRAINING_TARGETS.length - 1];
    expect(lastTarget.id).toBe("custom");
  });

  it("targets procedure should filter out custom target", () => {
    // The targets procedure filters: TRAINING_TARGETS.filter(t => t.id !== "custom")
    const filtered = TRAINING_TARGETS.filter(t => t.id !== "custom");
    expect(filtered.find(t => t.id === "vampi")).toBeDefined();
    expect(filtered.find(t => t.id === "dvga")).toBeDefined();
    expect(filtered.find(t => t.id === "webgoat")).toBeDefined();
    expect(filtered.find(t => t.id === "custom")).toBeUndefined();
  });
});
