/**
 * Vitest Global Setup — Test Data Isolation
 * 
 * This setup file ensures that any data created during tests is cleaned up
 * after each test suite runs. It also provides a TEST_PREFIX constant
 * that all integration tests should use when creating data, making cleanup
 * reliable and preventing pollution of production data.
 * 
 * Strategy:
 * 1. All test-created data uses a recognizable prefix: "__test_" + timestamp
 * 2. afterAll hooks clean up any rows matching the test prefix
 * 3. A global afterAll sweeps for any orphaned test data
 */

import { afterAll, beforeAll } from "vitest";

// Unique prefix for this test run — all test data should include this
export const TEST_RUN_ID = `__test_${Date.now()}`;

// Helper to generate test-prefixed names
export function testName(base: string): string {
  return `${TEST_RUN_ID}_${base}`;
}

// Track IDs created during tests for cleanup
const createdIds: { table: string; id: number }[] = [];

export function trackCreated(table: string, id: number) {
  createdIds.push({ table, id });
}

// Global cleanup that runs after all test suites
afterAll(async () => {
  try {
    // Dynamic import to avoid circular deps
    const { db } = await import("./db");
    const { sql } = await import("drizzle-orm");

    // Clean up tracked IDs
    const tables = [...new Set(createdIds.map(c => c.table))];
    for (const table of tables) {
      const ids = createdIds.filter(c => c.table === table).map(c => c.id);
      if (ids.length > 0) {
        try {
          await db.execute(sql.raw(`DELETE FROM \`${table}\` WHERE id IN (${ids.join(",")})`));
        } catch {
          // Table might not exist or IDs already cleaned
        }
      }
    }

    // Sweep for any orphaned test data by prefix pattern
    const testPatterns = [
      { table: "domain_intel_scans", column: "primary_domain", pattern: "__test_%" },
      { table: "discovered_assets", column: "hostname", pattern: "__test_%" },
      { table: "osint_monitors", column: "domain", pattern: "__test_%" },
      { table: "threat_actors", column: "name", pattern: "__test_%" },
      { table: "engagements", column: "name", pattern: "__test_%" },
      { table: "platform_errors", column: "message", pattern: "__test_%" },
      // Also clean up legacy test patterns from before this setup existed
      { table: "domain_intel_scans", column: "primary_domain", pattern: "test-%" },
      { table: "domain_intel_scans", column: "primary_domain", pattern: "get-scan-%" },
      { table: "domain_intel_scans", column: "primary_domain", pattern: "get-test-%" },
      { table: "domain_intel_scans", column: "primary_domain", pattern: "trpc-%" },
      { table: "osint_monitors", column: "domain", pattern: "trpc-%" },
      { table: "osint_monitors", column: "domain", pattern: "test-%" },
      { table: "osint_monitors", column: "domain", pattern: "get-%" },
    ];

    for (const { table, column, pattern } of testPatterns) {
      try {
        await db.execute(sql.raw(`DELETE FROM \`${table}\` WHERE \`${column}\` LIKE '${pattern}'`));
      } catch {
        // Ignore — table/column might not exist
      }
    }
  } catch {
    // If DB connection fails, silently skip cleanup
    // This happens in unit tests that don't use the DB
  }
});
