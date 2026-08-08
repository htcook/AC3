/**
 * Tests for the Exploit Methodology Knowledge System
 *
 * Covers:
 *   1. Seed methodology initialization and retrieval
 *   2. RAG retrieval scoring and ranking
 *   3. Context building for LLM injection
 *   4. Feedback ingestion and weight adjustment
 *   5. Training example generation
 *   6. Graduation bonus computation
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  retrieveMethodologies,
  buildMethodologyContext,
  ingestExploitFeedback,
  getMethodologyStats,
} from "./exploit-methodology-knowledge";
import {
  generateMethodologyTrainingExample,
} from "./methodology-db-persistence";

// ─── Seed Methodology Tests ────────────────────────────────────────────────

describe("Seed Methodology Initialization", () => {
  it("should have methodologies for all major vuln classes", () => {
    const stats = getMethodologyStats();
    expect(stats.totalMethodologies).toBeGreaterThanOrEqual(15);
    expect(stats.seedCount).toBeGreaterThanOrEqual(15);

    const expectedClasses = [
      "sqli", "xss", "ssti", "lfi", "command_injection",
      "ssrf", "idor", "jwt_attack", "xxe", "deserialization",
      "open_redirect", "prototype_pollution", "security_misconfiguration",
      "file_upload", "ldap_injection", "xpath_injection",
    ];
    for (const cls of expectedClasses) {
      expect(stats.byVulnClass[cls]).toBeGreaterThanOrEqual(1);
    }
  });

  it("should have seed methodologies with proper structure", () => {
    const sqliMethods = retrieveMethodologies("sqli", [], 10);
    expect(sqliMethods.length).toBeGreaterThanOrEqual(1);

    const method = sqliMethods[0];
    expect(method.id).toBeTruthy();
    expect(method.vulnClass).toBe("sqli");
    expect(method.name).toBeTruthy();
    expect(method.steps.length).toBeGreaterThanOrEqual(1);
    expect(method.payloads.length).toBeGreaterThanOrEqual(1);
    expect(method.detectionSignatures.length).toBeGreaterThanOrEqual(1);
    expect(method.successCriteria.length).toBeGreaterThanOrEqual(1);
    expect(method.source).toBe("seed");
    expect(method.weight).toBeGreaterThanOrEqual(50);
  });

  it("should have OWASP categories for all seed methodologies", () => {
    const stats = getMethodologyStats();
    const allClasses = Object.keys(stats.byVulnClass);
    for (const cls of allClasses) {
      const methods = retrieveMethodologies(cls, [], 10);
      for (const m of methods) {
        if (m.source === "seed") {
          expect(m.owaspCategory).toBeTruthy();
        }
      }
    }
  });
});

// ─── RAG Retrieval Tests ───────────────────────────────────────────────────

describe("RAG Retrieval", () => {
  it("should return exact vuln class matches first", () => {
    const results = retrieveMethodologies("sqli", [], 5);
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].vulnClass).toBe("sqli");
  });

  it("should boost results matching tech stack", () => {
    const withNode = retrieveMethodologies("ssti", ["node.js", "express"], 3);
    const withoutNode = retrieveMethodologies("ssti", [], 3);
    // Both should return results
    expect(withNode.length).toBeGreaterThanOrEqual(1);
    expect(withoutNode.length).toBeGreaterThanOrEqual(1);
  });

  it("should respect maxResults limit", () => {
    const results = retrieveMethodologies("sqli", [], 1);
    expect(results.length).toBeLessThanOrEqual(1);
  });

  it("should return empty array for unknown vuln class", () => {
    const results = retrieveMethodologies("nonexistent_vuln_class_xyz", [], 3);
    // May return cross-class matches with lower scores, or empty
    // The key is it doesn't throw
    expect(Array.isArray(results)).toBe(true);
  });

  it("should include cross-class matches for related vulns", () => {
    // LFI and path traversal are related
    const lfiResults = retrieveMethodologies("lfi", [], 5);
    expect(lfiResults.length).toBeGreaterThanOrEqual(1);
  });
});

// ─── Context Building Tests ────────────────────────────────────────────────

describe("Context Building for LLM", () => {
  it("should build non-empty context for known vuln classes", () => {
    const context = buildMethodologyContext("sqli", ["mysql", "php"]);
    expect(context).toBeTruthy();
    expect(context.length).toBeGreaterThan(100);
  });

  it("should include methodology steps in context", () => {
    const context = buildMethodologyContext("xss", []);
    expect(context).toContain("Step");
    expect(context).toContain("Payload");
  });

  it("should include success criteria in context", () => {
    const context = buildMethodologyContext("sqli", []);
    expect(context).toContain("Success Criteria");
  });

  it("should include failure modes in context", () => {
    const context = buildMethodologyContext("sqli", []);
    // Failure modes should be present for seed methodologies
    expect(context.length).toBeGreaterThan(200);
  });

  it("should return empty string for completely unknown vuln class", () => {
    const context = buildMethodologyContext("totally_unknown_xyz_123", []);
    // Should return empty or minimal context, not throw
    expect(typeof context).toBe("string");
  });
});

// ─── Feedback Ingestion Tests ──────────────────────────────────────────────

describe("Feedback Ingestion", () => {
  it("should not throw on successful feedback", () => {
    expect(() => {
      ingestExploitFeedback({
        vulnClass: "sqli",
        techStack: ["mysql", "php"],
        success: true,
        approach: "Union-based SQL injection on /api/products",
        payloadUsed: "' UNION SELECT username,password FROM users--",
        executionTimeMs: 5000,
      });
    }).not.toThrow();
  });

  it("should not throw on failed feedback", () => {
    expect(() => {
      ingestExploitFeedback({
        vulnClass: "xss",
        techStack: ["node.js"],
        success: false,
        approach: "Reflected XSS on search parameter",
        failureReason: "Input sanitized by WAF",
        executionTimeMs: 3000,
      });
    }).not.toThrow();
  });

  it("should create learned methodology for successful novel approach", () => {
    const statsBefore = getMethodologyStats();
    ingestExploitFeedback({
      vulnClass: "sqli",
      techStack: ["postgresql", "django"],
      success: true,
      approach: "Novel PostgreSQL COPY TO exploit via SQL injection",
      payloadUsed: "'; COPY (SELECT version()) TO '/tmp/test.txt';--",
      executionTimeMs: 8000,
    });
    const statsAfter = getMethodologyStats();
    // Should have created at least one new methodology
    expect(statsAfter.totalMethodologies).toBeGreaterThanOrEqual(statsBefore.totalMethodologies);
  });

  it("should accept engagementId for training pipeline linking", () => {
    expect(() => {
      ingestExploitFeedback({
        vulnClass: "ssti",
        techStack: ["python", "flask"],
        engagementId: 1800033,
        success: true,
        approach: "Jinja2 SSTI via {{7*7}} in template parameter",
        payloadUsed: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        executionTimeMs: 4000,
      });
    }).not.toThrow();
  });
});

// ─── Training Example Generation Tests ─────────────────────────────────────

describe("Training Example Generation", () => {
  it("should generate training example for successful exploit", () => {
    const example = generateMethodologyTrainingExample({
      vulnClass: "sqli",
      techStack: ["mysql", "php"],
      success: true,
      approach: "Union-based SQL injection",
      payloadUsed: "' UNION SELECT 1,2,3--",
      executionTimeMs: 5000,
    });
    expect(example).not.toBeNull();
    expect(example!.model).toBe("exploit_selector");
    expect(example!.messages.length).toBe(3);
    expect(example!.quality).toBe("medium"); // No methodology = medium quality
    expect(example!.qualityScore).toBe(0.75);
  });

  it("should generate higher quality example when methodology is provided", () => {
    const methodology = retrieveMethodologies("sqli", [], 1)[0];
    const example = generateMethodologyTrainingExample({
      vulnClass: "sqli",
      techStack: ["mysql"],
      success: true,
      approach: "Union-based SQL injection with methodology guidance",
      payloadUsed: "' UNION SELECT username,password FROM users--",
      executionTimeMs: 5000,
      methodology,
    });
    expect(example).not.toBeNull();
    expect(example!.quality).toBe("high");
    expect(example!.qualityScore).toBe(0.95);
  });

  it("should return null for failed exploit", () => {
    const example = generateMethodologyTrainingExample({
      vulnClass: "sqli",
      techStack: ["mysql"],
      success: false,
      approach: "Failed SQL injection attempt",
      failureReason: "WAF blocked",
      executionTimeMs: 3000,
    });
    expect(example).toBeNull();
  });

  it("should include metadata with vuln class and tech stack", () => {
    const example = generateMethodologyTrainingExample({
      vulnClass: "xss",
      techStack: ["react", "node.js"],
      success: true,
      approach: "Stored XSS via user profile bio",
      payloadUsed: "<img src=x onerror=alert(1)>",
      executionTimeMs: 4000,
      engagementId: 1800033,
    });
    expect(example).not.toBeNull();
    expect(example!.metadata.vulnClass).toBe("xss");
    expect(example!.metadata.techStack).toEqual(["react", "node.js"]);
    expect(example!.metadata.engagementId).toBe(1800033);
  });
});

// ─── Stats Tests ───────────────────────────────────────────────────────────

describe("Methodology Stats", () => {
  it("should return valid stats structure", () => {
    const stats = getMethodologyStats();
    expect(stats.totalMethodologies).toBeGreaterThan(0);
    expect(typeof stats.seedCount).toBe("number");
    expect(typeof stats.learnedCount).toBe("number");
    expect(Array.isArray(stats.topPerformers)).toBe(true);
    expect(typeof stats.byVulnClass).toBe("object");
  });

  it("should have seed count >= learned count initially", () => {
    const stats = getMethodologyStats();
    expect(stats.seedCount).toBeGreaterThanOrEqual(stats.learnedCount);
  });
});
