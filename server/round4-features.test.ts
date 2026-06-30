// ─────────────────────────────────────────────────────────────────────────────
// Round 4 Feature Tests
// ─────────────────────────────────────────────────────────────────────────────
// Tests for: CI Preflight Gate, ECR Lifecycle Policy, Hypothesis-ScanForge
// Bridge, Submission History Router, and Production Hardening Middleware.
//
// Author: Harrison Cook — AceofCloud (https://aceofcloud.com)
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import path from "path";

const ROOT = path.resolve(__dirname, "..");

// ═══════════════════════════════════════════════════════════════════════════
// 1. CI Preflight Gate + ECR Lifecycle Policy
// ═══════════════════════════════════════════════════════════════════════════
describe("CI Preflight Gate", () => {
  const workflowPath = path.join(ROOT, ".github/workflows/deploy-aws.yml");

  it("deploy-aws.yml contains a preflight job", () => {
    const content = fs.readFileSync(workflowPath, "utf8");
    expect(content).toContain("preflight:");
  });

  it("preflight-check job runs the preflight script", () => {
    const content = fs.readFileSync(workflowPath, "utf8");
    expect(content).toContain("preflight-check.sh");
  });

  it("deploy job depends on preflight", () => {
    const content = fs.readFileSync(workflowPath, "utf8");
    // The deploy job should have preflight in its needs
    expect(content).toMatch(/deploy:[\s\S]*?needs:[\s\S]*?preflight/);
  });

  it("preflight-check job uses the correct OIDC role", () => {
    const content = fs.readFileSync(workflowPath, "utf8");
    // Should reference the setup job outputs for role ARN
    expect(content).toContain("needs.setup.outputs");
  });
});

describe("ECR Lifecycle Policy", () => {
  const policyPath = path.join(ROOT, "infrastructure/ecr/lifecycle-policy.json");

  it("lifecycle policy file exists and is valid JSON", () => {
    const content = fs.readFileSync(policyPath, "utf8");
    const policy = JSON.parse(content);
    expect(policy).toHaveProperty("rules");
    expect(Array.isArray(policy.rules)).toBe(true);
  });

  it("has a rule to expire untagged images", () => {
    const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    const untaggedRule = policy.rules.find((r: any) =>
      r.selection?.tagStatus === "untagged"
    );
    expect(untaggedRule).toBeDefined();
    expect(untaggedRule.action.type).toBe("expire");
  });

  it("has a rule to limit tagged images per environment", () => {
    const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    const taggedRule = policy.rules.find((r: any) =>
      r.selection?.tagStatus === "tagged"
    );
    expect(taggedRule).toBeDefined();
    expect(taggedRule.selection.countType).toBe("imageCountMoreThan");
  });

  it("apply-ecr-lifecycle.sh script exists and is executable", () => {
    const scriptPath = path.join(ROOT, "infrastructure/scripts/apply-ecr-lifecycle.sh");
    expect(fs.existsSync(scriptPath)).toBe(true);
    const stats = fs.statSync(scriptPath);
    // Check executable bit
    expect(stats.mode & 0o111).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Hypothesis-ScanForge Bridge
// ═══════════════════════════════════════════════════════════════════════════
describe("Hypothesis-ScanForge Bridge", () => {
  const bridgePath = path.join(ROOT, "server/lib/hypothesis-scanforge-bridge.ts");

  it("bridge module exists", () => {
    expect(fs.existsSync(bridgePath)).toBe(true);
  });

  it("exports enrichScanPlanWithHypotheses function", () => {
    const content = fs.readFileSync(bridgePath, "utf8");
    expect(content).toContain("export function enrichScanPlanWithHypotheses");
  });

  it("exports formatHypothesisEnrichmentSummary function", () => {
    const content = fs.readFileSync(bridgePath, "utf8");
    expect(content).toContain("export function formatHypothesisEnrichmentSummary");
  });

  it("applies priority boosts based on confidence scores", () => {
    const content = fs.readFileSync(bridgePath, "utf8");
    // Should reference confidence-based priority boosting
    expect(content).toMatch(/confidence|priority.*boost|boost.*priority/i);
  });

  it("injects hypothesis-specific scan templates", () => {
    const content = fs.readFileSync(bridgePath, "utf8");
    // Should have scan template injection logic
    expect(content).toMatch(/template|scanConfig|scan.*config/i);
  });

  it("is wired into the engagement-ops-core router", () => {
    const routerPath = path.join(ROOT, "server/routers/engagement-ops-core.ts");
    const content = fs.readFileSync(routerPath, "utf8");
    expect(content).toContain("hypothesis-scanforge-bridge");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. Submission History Database + Router
// ═══════════════════════════════════════════════════════════════════════════
describe("Submission History Schema", () => {
  const schemaPath = path.join(ROOT, "drizzle/schema.ts");

  it("submission_history table is defined in schema", () => {
    const content = fs.readFileSync(schemaPath, "utf8");
    expect(content).toContain("submissionHistory");
    expect(content).toContain("submission_history");
  });

  it("schema includes required columns", () => {
    const content = fs.readFileSync(schemaPath, "utf8");
    const requiredColumns = [
      "engagement_id",
      "user_id",
      "platform",
      "vuln_class",
      "severity",
      "title",
      "status",
    ];
    for (const col of requiredColumns) {
      expect(content).toContain(col);
    }
  });

  it("schema includes analytics columns", () => {
    const content = fs.readFileSync(schemaPath, "utf8");
    expect(content).toContain("bounty_amount_cents");
    expect(content).toContain("rejection_reason");
    expect(content).toContain("rejection_category");
    expect(content).toContain("confidence_at_generation");
  });
});

describe("Submission History Router", () => {
  const routerPath = path.join(ROOT, "server/routers/submission-history.ts");

  it("router module exists", () => {
    expect(fs.existsSync(routerPath)).toBe(true);
  });

  it("exports submissionHistoryRouter", () => {
    const content = fs.readFileSync(routerPath, "utf8");
    expect(content).toContain("export const submissionHistoryRouter");
  });

  it("has CRUD procedures", () => {
    const content = fs.readFileSync(routerPath, "utf8");
    expect(content).toContain("create:");
    expect(content).toContain("list:");
    expect(content).toContain("getById:");
    expect(content).toContain("update:");
    expect(content).toContain("delete:");
  });

  it("has lifecycle tracking procedures", () => {
    const content = fs.readFileSync(routerPath, "utf8");
    expect(content).toContain("markExported:");
    expect(content).toContain("markSubmitted:");
    expect(content).toContain("recordOutcome:");
  });

  it("has analytics procedure with win rate calculation", () => {
    const content = fs.readFileSync(routerPath, "utf8");
    expect(content).toContain("analytics:");
    expect(content).toContain("winRate");
    expect(content).toContain("platformBreakdown");
    expect(content).toContain("severityBreakdown");
    expect(content).toContain("rejectionPatterns");
  });

  it("is registered in the main router", () => {
    const mainRouterPath = path.join(ROOT, "server/routers.ts");
    const content = fs.readFileSync(mainRouterPath, "utf8");
    expect(content).toContain("submissionHistory: submissionHistoryRouter");
  });

  it("uses async getDb() pattern (not direct db import)", () => {
    const content = fs.readFileSync(routerPath, "utf8");
    expect(content).toContain("requireDb");
    expect(content).toContain("getDb");
    expect(content).not.toContain("from \"../_core/db\"");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. Production Hardening
// ═══════════════════════════════════════════════════════════════════════════
describe("Security Headers Middleware", () => {
  const headersPath = path.join(ROOT, "server/lib/security-headers.ts");

  it("module exists", () => {
    expect(fs.existsSync(headersPath)).toBe(true);
  });

  it("exports cspMiddleware", () => {
    const content = fs.readFileSync(headersPath, "utf8");
    expect(content).toContain("export function cspMiddleware");
  });

  it("exports securityHeadersMiddleware", () => {
    const content = fs.readFileSync(headersPath, "utf8");
    expect(content).toContain("export function securityHeadersMiddleware");
  });

  it("exports corsMiddleware", () => {
    const content = fs.readFileSync(headersPath, "utf8");
    expect(content).toContain("export function corsMiddleware");
  });

  it("CSP includes nonce generation", () => {
    const content = fs.readFileSync(headersPath, "utf8");
    expect(content).toContain("generateNonce");
    expect(content).toContain("randomBytes");
  });

  it("sets X-Frame-Options DENY", () => {
    const content = fs.readFileSync(headersPath, "utf8");
    expect(content).toContain("X-Frame-Options");
    expect(content).toContain("DENY");
  });

  it("sets Permissions-Policy restricting sensitive APIs", () => {
    const content = fs.readFileSync(headersPath, "utf8");
    expect(content).toContain("Permissions-Policy");
    expect(content).toContain("camera=()");
    expect(content).toContain("microphone=()");
    expect(content).toContain("geolocation=()");
  });

  it("disables API response caching", () => {
    const content = fs.readFileSync(headersPath, "utf8");
    expect(content).toContain("no-store");
    expect(content).toContain("no-cache");
  });
});

describe("Correlation ID Middleware", () => {
  const corrPath = path.join(ROOT, "server/lib/correlation-id.ts");

  it("module exists", () => {
    expect(fs.existsSync(corrPath)).toBe(true);
  });

  it("exports correlationIdMiddleware", () => {
    const content = fs.readFileSync(corrPath, "utf8");
    expect(content).toContain("export function correlationIdMiddleware");
  });

  it("exports requestLoggingMiddleware", () => {
    const content = fs.readFileSync(corrPath, "utf8");
    expect(content).toContain("export function requestLoggingMiddleware");
  });

  it("accepts upstream trace IDs (X-Correlation-ID, X-Request-ID, X-Amzn-Trace-Id)", () => {
    const content = fs.readFileSync(corrPath, "utf8");
    expect(content).toContain("x-correlation-id");
    expect(content).toContain("x-request-id");
    expect(content).toContain("x-amzn-trace-id");
  });

  it("generates UUIDv4 when no upstream ID exists", () => {
    const content = fs.readFileSync(corrPath, "utf8");
    expect(content).toContain("uuidv4");
  });

  it("echoes correlation ID in response headers", () => {
    const content = fs.readFileSync(corrPath, "utf8");
    expect(content).toContain("X-Correlation-ID");
    expect(content).toContain("X-Request-ID");
  });

  it("validates incoming correlation IDs", () => {
    const content = fs.readFileSync(corrPath, "utf8");
    expect(content).toContain("isValidCorrelationId");
  });
});

describe("Structured Logger", () => {
  const loggerPath = path.join(ROOT, "server/lib/structured-logger.ts");

  it("module exists", () => {
    expect(fs.existsSync(loggerPath)).toBe(true);
  });

  it("uses pino for structured logging", () => {
    const content = fs.readFileSync(loggerPath, "utf8");
    expect(content).toContain("import pino");
  });

  it("exports module-scoped loggers", () => {
    const content = fs.readFileSync(loggerPath, "utf8");
    expect(content).toContain("export const serverLogger");
    expect(content).toContain("export const authLogger");
    expect(content).toContain("export const trpcLogger");
    expect(content).toContain("export const securityLogger");
  });

  it("exports auditLog helper for security events", () => {
    const content = fs.readFileSync(loggerPath, "utf8");
    expect(content).toContain("export function auditLog");
  });

  it("redacts sensitive fields", () => {
    const content = fs.readFileSync(loggerPath, "utf8");
    expect(content).toContain("redact");
    expect(content).toContain("[REDACTED]");
    expect(content).toContain("password");
    expect(content).toContain("authorization");
  });

  it("uses pino-pretty in development, raw JSON in production", () => {
    const content = fs.readFileSync(loggerPath, "utf8");
    expect(content).toContain("pino-pretty");
    expect(content).toContain("isoTime");
  });

  it("exports createRequestLogger for per-request context", () => {
    const content = fs.readFileSync(loggerPath, "utf8");
    expect(content).toContain("export function createRequestLogger");
    expect(content).toContain("correlationId");
  });
});

describe("Production Hardening Integration", () => {
  const indexPath = path.join(ROOT, "server/_core/index.ts");

  it("server wires in correlation ID middleware", () => {
    const content = fs.readFileSync(indexPath, "utf8");
    expect(content).toContain("correlationIdMiddleware");
  });

  it("server wires in security headers middleware", () => {
    const content = fs.readFileSync(indexPath, "utf8");
    expect(content).toContain("securityHeadersMiddleware");
    expect(content).toContain("cspMiddleware");
  });

  it("server wires in CORS middleware for API routes", () => {
    const content = fs.readFileSync(indexPath, "utf8");
    expect(content).toContain("corsMiddleware");
  });

  it("server wires in request logging middleware", () => {
    const content = fs.readFileSync(indexPath, "utf8");
    expect(content).toContain("requestLoggingMiddleware");
  });

  it("middleware is ordered correctly (correlation ID first)", () => {
    const content = fs.readFileSync(indexPath, "utf8");
    const corrIdx = content.indexOf("app.use(correlationIdMiddleware)");
    const secIdx = content.indexOf("app.use(securityHeadersMiddleware)");
    const cspIdx = content.indexOf("app.use(cspMiddleware)");
    const logIdx = content.indexOf("app.use(requestLoggingMiddleware)");
    // Correlation ID should come before security headers
    expect(corrIdx).toBeLessThan(secIdx);
    // Security headers before CSP
    expect(secIdx).toBeLessThan(cspIdx);
    // CSP before request logging
    expect(cspIdx).toBeLessThan(logIdx);
  });
});
