import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { getDbRequired } from "./db";
import * as schema from "../drizzle/schema";
import { eq, desc } from "drizzle-orm";

describe("Entity Profile Override", () => {
  let testScanId: number;
  const testDomain = "test-override.example.com";
  const testUserId = 1;

  beforeAll(async () => {
    // Get a real scan ID from the database to satisfy the FK constraint
    const db = await getDbRequired();
    const [existingScan] = await db.select({ id: schema.domainIntelScans.id })
      .from(schema.domainIntelScans)
      .orderBy(desc(schema.domainIntelScans.id))
      .limit(1);

    if (!existingScan) {
      // Create a minimal scan entry for testing
      const [result] = await db.insert(schema.domainIntelScans).values({
        userId: testUserId,
        primaryDomain: testDomain,
        status: "completed",
        sector: "Technology",
        clientType: "enterprise",
        customerName: "Test Corp",
      } as any);
      testScanId = Number(result.insertId);
    } else {
      testScanId = existingScan.id;
    }
  });

  afterAll(async () => {
    // Cleanup test override data
    const db = await getDbRequired();
    await db.delete(schema.entityProfileOverrides)
      .where(eq(schema.entityProfileOverrides.scanId, testScanId));
  });

  it("should create an entity override", async () => {
    const db = await getDbRequired();
    const [result] = await db.insert(schema.entityProfileOverrides).values({
      scanId: testScanId,
      domain: testDomain,
      orgName: "Test Corp",
      industry: "Cybersecurity",
      subSector: "Offensive Security",
      companySize: "small",
      estimatedRevenue: 500000,
      estimatedEmployees: 25,
      headquarters: "Tampa, FL, USA",
      foundedYear: 2022,
      isPublicCompany: 0,
      stockTicker: null,
      keyProducts: JSON.stringify(["Penetration Testing", "Red Team"]),
      overrideReason: "Auto-detection matched wrong company",
      overriddenBy: testUserId,
    });

    expect(result.insertId).toBeGreaterThan(0);
  });

  it("should retrieve the entity override by scanId", async () => {
    const db = await getDbRequired();
    const [override] = await db.select()
      .from(schema.entityProfileOverrides)
      .where(eq(schema.entityProfileOverrides.scanId, testScanId))
      .limit(1);

    expect(override).toBeDefined();
    expect(override.orgName).toBe("Test Corp");
    expect(override.industry).toBe("Cybersecurity");
    expect(override.headquarters).toBe("Tampa, FL, USA");
    expect(override.estimatedRevenue).toBe(500000);
    expect(override.estimatedEmployees).toBe(25);
    expect(override.domain).toBe(testDomain);
  });

  it("should update an existing override", async () => {
    const db = await getDbRequired();
    await db.update(schema.entityProfileOverrides)
      .set({ orgName: "Updated Corp", estimatedEmployees: 50 })
      .where(eq(schema.entityProfileOverrides.scanId, testScanId));

    const [updated] = await db.select()
      .from(schema.entityProfileOverrides)
      .where(eq(schema.entityProfileOverrides.scanId, testScanId))
      .limit(1);

    expect(updated).toBeDefined();
    expect(updated.orgName).toBe("Updated Corp");
    expect(updated.estimatedEmployees).toBe(50);
    // Other fields should remain unchanged
    expect(updated.industry).toBe("Cybersecurity");
  });

  it("should delete an override", async () => {
    const db = await getDbRequired();
    await db.delete(schema.entityProfileOverrides)
      .where(eq(schema.entityProfileOverrides.scanId, testScanId));

    const [deleted] = await db.select()
      .from(schema.entityProfileOverrides)
      .where(eq(schema.entityProfileOverrides.scanId, testScanId))
      .limit(1);

    expect(deleted).toBeUndefined();
  });
});
