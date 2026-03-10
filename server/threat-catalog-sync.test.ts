import { describe, it, expect, vi } from "vitest";

/**
 * Tests for threat catalog sync — verifies that the Drizzle schema field names
 * used in queries match the actual database column names.
 * 
 * Root cause: The schema defines `actorType` (maps to `actor_type` column),
 * but queries were using `threatActors.type` which doesn't exist.
 * Similarly, `iocFeeds.severity` should be `iocFeeds.feedSeverity`,
 * `iocFeeds.iocType` should be `iocFeeds.feedIocType`, etc.
 */

describe("Threat Catalog Schema Field Names", () => {
  it("threatActors schema should have actorType, not type", async () => {
    const { threatActors } = await import("../drizzle/schema");
    // The schema should expose actorType
    expect(threatActors.actorType).toBeDefined();
    expect(threatActors.actorType.name).toBe("actorType");
    // The old wrong field 'type' should NOT exist on the schema
    expect((threatActors as any).type).toBeUndefined();
  });

  it("iocFeeds schema should have feedSeverity, not severity", async () => {
    const { iocFeeds } = await import("../drizzle/schema");
    expect(iocFeeds.feedSeverity).toBeDefined();
    expect(iocFeeds.feedSeverity.name).toBe("feedSeverity");
    expect((iocFeeds as any).severity).toBeUndefined();
  });

  it("iocFeeds schema should have feedIocType, not iocType", async () => {
    const { iocFeeds } = await import("../drizzle/schema");
    expect(iocFeeds.feedIocType).toBeDefined();
    expect(iocFeeds.feedIocType.name).toBe("feedIocType");
    expect((iocFeeds as any).iocType).toBeUndefined();
  });

  it("iocFeeds schema should have feedTags, not tags", async () => {
    const { iocFeeds } = await import("../drizzle/schema");
    expect(iocFeeds.feedTags).toBeDefined();
    expect(iocFeeds.feedTags.name).toBe("feedTags");
    expect((iocFeeds as any).tags).toBeUndefined();
  });
});

describe("Threat Intel Connectors - getCatalogStats", () => {
  it("should reference actorType field in the select query", async () => {
    // Read the source file and verify it uses the correct field name
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/threat-intel-connectors.ts", "utf-8");
    
    // Should use actorType, not type, in the select
    expect(source).toContain("actorType: threatActors.actorType");
    expect(source).not.toContain("type: threatActors.type");
    
    // The mapping loop should use a.actorType
    expect(source).toContain("a.actorType");
    expect(source).not.toMatch(/a\.type\b/);
  });
});

describe("Threat Intel Router - list procedure", () => {
  it("should use actorType for type filtering", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/threat-intel.ts", "utf-8");
    
    // The list filter should use actorType
    expect(source).toContain("eq(threatActors.actorType, opts.type)");
    expect(source).not.toContain("eq(threatActors.type, opts.type)");
  });

  it("should use actorType in events query join", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/threat-intel.ts", "utf-8");
    
    // The events query should reference actorType
    expect(source).toContain("actorType: threatActors.actorType");
    expect(source).not.toMatch(/actorType:\s*threatActors\.type\b/);
  });

  it("should use actorType in techniqueCoverage query", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/threat-intel.ts", "utf-8");
    
    // The technique coverage query should use actorType
    expect(source).toContain("actorType: threatActors.actorType");
  });
});

describe("DB Stats Functions - field alignment", () => {
  it("getThreatActorStats should use actorType", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/db.ts", "utf-8");
    
    // byType query should use actorType
    expect(source).toContain("type: threatActors.actorType");
    expect(source).toContain("groupBy(threatActors.actorType)");
    expect(source).not.toContain("threatActors.type");
  });

  it("getIocFeedStats should use feedSeverity", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/db.ts", "utf-8");
    
    // bySeverity query should use feedSeverity
    expect(source).toContain("severity: iocFeeds.feedSeverity");
    expect(source).toContain("groupBy(iocFeeds.feedSeverity)");
    expect(source).not.toContain("iocFeeds.severity");
  });
});

describe("IOC Feed Router - insert field names", () => {
  it("should use feedSeverity, feedIocType, feedTags in insert objects", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/routers/ioc-feed.ts", "utf-8");
    
    // Should use the correct schema field names
    expect(source).toContain("feedSeverity:");
    expect(source).toContain("feedIocType:");
    expect(source).toContain("feedTags:");
    
    // Should NOT use the old wrong field names in insert contexts
    // (severity: 'critical' etc. should now be feedSeverity: 'critical')
    expect(source).not.toMatch(/\bseverity:\s*['"][^'"]+['"]\s*as\s*const/);
    expect(source).not.toMatch(/\biocType:\s*['"][^'"]+['"]/);
    expect(source).not.toMatch(/\btags:\s*\[/);
  });
});

describe("Threat Intel Catalog - field alignment", () => {
  it("should use actorType in insert/update objects", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/threat-intel-catalog.ts", "utf-8");
    
    // Insert objects should use actorType
    expect(source).toContain("actorType: profile.type");
    expect(source).toContain("actorType: parsed.type");
    
    // Query filters should use actorType
    expect(source).toContain("eq(threatActors.actorType, filters.type)");
    expect(source).not.toContain("eq(threatActors.type, filters.type)");
    
    // Stats query should use actorType
    expect(source).toContain("type: threatActors.actorType");
    expect(source).toContain("groupBy(threatActors.actorType)");
  });

  it("ensureActorInCatalog should use actorType in insert", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync("server/lib/threat-intel-connectors.ts", "utf-8");
    
    // The insert in ensureActorInCatalog should use actorType
    expect(source).toContain('actorType: metadata?.type || "unknown"');
    expect(source).not.toMatch(/\btype:\s*metadata\?\.(type|actorType)/);
  });
});
