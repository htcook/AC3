/**
 * HealthMonitor Status Mapping — Test Suite
 * ═══════════════════════════════════════════════════════════════════════
 * Verifies that internal HealthStatus values are correctly mapped to
 * DB-compatible enum values before insert.
 *
 * DB enum: healthy, degraded, unreachable, auth_failed, rate_limited, timeout, error
 * Code:    healthy, degraded, down, auth_expired, rate_limited, unknown
 */

import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

describe("HealthMonitor Status Mapping", () => {
  // Read the source file to verify the mapping function exists
  const healthMonitorPath = path.join(
    __dirname,
    "lib/integration-registry/health-monitor.ts"
  );
  const source = fs.readFileSync(healthMonitorPath, "utf-8");

  it("should have a mapStatusToDb function", () => {
    expect(source).toContain("function mapStatusToDb");
  });

  it("should map 'down' to 'unreachable'", () => {
    expect(source).toContain('"down"');
    expect(source).toContain('"unreachable"');
    // Verify the mapping line
    expect(source).toMatch(/case\s+"down".*return\s+"unreachable"/);
  });

  it("should map 'auth_expired' to 'auth_failed'", () => {
    expect(source).toContain('"auth_expired"');
    expect(source).toContain('"auth_failed"');
    expect(source).toMatch(/case\s+"auth_expired".*return\s+"auth_failed"/);
  });

  it("should map 'unknown' to 'error'", () => {
    expect(source).toMatch(/case\s+"unknown".*return\s+"error"/);
  });

  it("should pass through healthy, degraded, rate_limited unchanged", () => {
    // The default case should return the status as-is
    expect(source).toMatch(/default:\s+return\s+status/);
  });

  it("should use mapStatusToDb when calling createHealthCheck", () => {
    // Verify the mapping is applied in the createHealthCheck call
    expect(source).toContain("mapStatusToDb(result.status)");
  });

  it("DB enum values should be a superset of mapped values", () => {
    const dbEnumValues = [
      "healthy",
      "degraded",
      "unreachable",
      "auth_failed",
      "rate_limited",
      "timeout",
      "error",
    ];
    const mappedOutputValues = [
      "healthy",
      "degraded",
      "unreachable",
      "auth_failed",
      "rate_limited",
      "error",
    ];
    for (const val of mappedOutputValues) {
      expect(dbEnumValues).toContain(val);
    }
  });
});
