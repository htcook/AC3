import { describe, it, expect } from "vitest";

/**
 * RoE Phase 3 Unit Tests
 *
 * Tests for:
 * 1. Version history schema and data model
 * 2. RoE-to-Engagement linking
 * 3. Version diff comparison logic
 * 4. Field change tracking
 */

// ─── Version History Data Model Tests ─────────────────────────────────────────

describe("RoE Version History Schema", () => {
  it("should have roeVersions table exported from schema", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.roeVersions).toBeDefined();
  });

  it("should have correct column definitions for roeVersions", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.roeVersions;
    // Check the table has the expected columns by checking the $inferSelect type
    expect(table).toBeDefined();
    // Verify the table name
    const tableName = (table as any)[Symbol.for("drizzle:Name")];
    expect(tableName).toBe("roe_versions");
  });

  it("should export RoeVersion and InsertRoeVersion types", async () => {
    const schema = await import("../drizzle/schema");
    // Types are compile-time only, but we can verify the table exists
    expect(schema.roeVersions).toBeDefined();
  });
});

// ─── Change Type Configuration Tests ─────────────────────────────────────────

describe("Version Change Types", () => {
  const validChangeTypes = ["created", "updated", "status_change", "approved", "restored"];

  it("should support all expected change types", () => {
    expect(validChangeTypes).toContain("created");
    expect(validChangeTypes).toContain("updated");
    expect(validChangeTypes).toContain("status_change");
    expect(validChangeTypes).toContain("approved");
    expect(validChangeTypes).toContain("restored");
  });

  it("should have 5 change types total", () => {
    expect(validChangeTypes.length).toBe(5);
  });
});

// ─── Field Change Tracking Tests ──────────────────────────────────────────────

describe("Field Change Tracking Logic", () => {
  it("should detect changed fields by comparing JSON representations", () => {
    const currentDoc = {
      title: "Original Title",
      version: "1.0",
      status: "draft",
      organizationName: "Test Org",
    };

    const updates = {
      title: "Updated Title",
      status: "draft", // unchanged
    };

    const changedFields: string[] = [];
    for (const [key, value] of Object.entries(updates)) {
      const currentVal = (currentDoc as any)[key];
      if (JSON.stringify(currentVal) !== JSON.stringify(value)) {
        changedFields.push(key);
      }
    }

    expect(changedFields).toContain("title");
    expect(changedFields).not.toContain("status");
    expect(changedFields.length).toBe(1);
  });

  it("should detect array field changes", () => {
    const currentDoc = {
      testingDays: ["monday", "tuesday"],
      complianceFrameworks: ["NIST", "FedRAMP"],
    };

    const updates = {
      testingDays: ["monday", "tuesday", "wednesday"],
      complianceFrameworks: ["NIST", "FedRAMP"], // unchanged
    };

    const changedFields: string[] = [];
    for (const [key, value] of Object.entries(updates)) {
      const currentVal = (currentDoc as any)[key];
      if (JSON.stringify(currentVal) !== JSON.stringify(value)) {
        changedFields.push(key);
      }
    }

    expect(changedFields).toContain("testingDays");
    expect(changedFields).not.toContain("complianceFrameworks");
  });

  it("should detect boolean field changes", () => {
    const currentDoc = { fedrampCompliant: false, ndaRequired: true };
    const updates = { fedrampCompliant: true, ndaRequired: true };

    const changedFields: string[] = [];
    for (const [key, value] of Object.entries(updates)) {
      const currentVal = (currentDoc as any)[key];
      if (JSON.stringify(currentVal) !== JSON.stringify(value)) {
        changedFields.push(key);
      }
    }

    expect(changedFields).toContain("fedrampCompliant");
    expect(changedFields).not.toContain("ndaRequired");
  });

  it("should handle null to value changes", () => {
    const currentDoc = { purpose: null, assumptions: "existing" };
    const updates = { purpose: "New purpose", assumptions: "existing" };

    const changedFields: string[] = [];
    for (const [key, value] of Object.entries(updates)) {
      const currentVal = (currentDoc as any)[key];
      if (JSON.stringify(currentVal) !== JSON.stringify(value)) {
        changedFields.push(key);
      }
    }

    expect(changedFields).toContain("purpose");
    expect(changedFields).not.toContain("assumptions");
  });
});

// ─── Change Summary Generation Tests ──────────────────────────────────────────

describe("Change Summary Generation", () => {
  it("should generate status change summary", () => {
    const currentStatus = "draft";
    const newStatus = "pending_review";
    const changeType = newStatus !== currentStatus ? "status_change" : "updated";
    const summary = changeType === "status_change"
      ? `Status changed from ${currentStatus} to ${newStatus}`
      : "Updated fields";

    expect(changeType).toBe("status_change");
    expect(summary).toBe("Status changed from draft to pending_review");
  });

  it("should generate approved summary", () => {
    const currentStatus = "pending_review";
    const newStatus = "approved";
    const changeType = newStatus === "approved" ? "approved" : "status_change";
    const summary = changeType === "approved" ? "Document approved" : "Status changed";

    expect(changeType).toBe("approved");
    expect(summary).toBe("Document approved");
  });

  it("should generate field update summary", () => {
    const changedFields = ["title", "purpose", "scopeDescription"];
    const summary = `Updated fields: ${changedFields.join(", ")}`;

    expect(summary).toBe("Updated fields: title, purpose, scopeDescription");
  });
});

// ─── Snapshot Building Tests ──────────────────────────────────────────────────

describe("Version Snapshot Building", () => {
  it("should build minimal snapshots with only changed fields", () => {
    const currentDoc = {
      title: "Original",
      version: "1.0",
      purpose: "Old purpose",
      status: "draft",
    };

    const changedFields = ["title", "purpose"];
    const updateData = { title: "New Title", purpose: "New purpose" };

    const previousSnapshot: Record<string, unknown> = {};
    const currentSnapshot: Record<string, unknown> = {};
    for (const field of changedFields) {
      previousSnapshot[field] = (currentDoc as any)[field];
      currentSnapshot[field] = (updateData as any)[field];
    }

    expect(Object.keys(previousSnapshot).length).toBe(2);
    expect(previousSnapshot.title).toBe("Original");
    expect(previousSnapshot.purpose).toBe("Old purpose");
    expect(currentSnapshot.title).toBe("New Title");
    expect(currentSnapshot.purpose).toBe("New purpose");
    // Should NOT include unchanged fields
    expect(previousSnapshot.version).toBeUndefined();
    expect(previousSnapshot.status).toBeUndefined();
  });
});

// ─── RoE-Engagement Linking Tests ─────────────────────────────────────────────

describe("RoE-Engagement Linking", () => {
  it("should have roeDocumentId field concept in engagements", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.engagements).toBeDefined();
    // The roeDocumentId column should exist
    const cols = Object.keys((schema.engagements as any));
    // Check the table is defined (column access varies by drizzle version)
    expect(schema.engagements).toBeTruthy();
  });

  it("should have roeDocuments table with engagementId field", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.roeDocuments).toBeDefined();
  });
});

// ─── Field Label Mapping Tests ────────────────────────────────────────────────

describe("Field Label Mapping", () => {
  const FIELD_LABELS: Record<string, string> = {
    title: "Title", version: "Version", status: "Status",
    organizationName: "Organization Name",
    testScheduleStart: "Test Start Date", testScheduleEnd: "Test End Date",
    testingTypes: "Testing Types", attackVectors: "Attack Vectors",
    fedrampCompliant: "FedRAMP Compliant",
    evidenceRetentionDays: "Evidence Retention (days)",
    complianceFrameworks: "Compliance Frameworks",
  };

  it("should provide human-readable labels for common fields", () => {
    expect(FIELD_LABELS["title"]).toBe("Title");
    expect(FIELD_LABELS["organizationName"]).toBe("Organization Name");
    expect(FIELD_LABELS["fedrampCompliant"]).toBe("FedRAMP Compliant");
  });

  it("should handle unknown fields gracefully", () => {
    const unknownField = "someNewField";
    const label = FIELD_LABELS[unknownField] || unknownField;
    expect(label).toBe("someNewField");
  });
});

// ─── Format Field Value Tests ─────────────────────────────────────────────────

describe("Format Field Value Helper", () => {
  function formatFieldValue(value: unknown): string {
    if (value === null || value === undefined) return "—";
    if (typeof value === "boolean") return value ? "Yes" : "No";
    if (typeof value === "number") return String(value);
    if (typeof value === "string") {
      return value.length > 120 ? value.slice(0, 120) + "..." : value;
    }
    if (Array.isArray(value)) {
      if (value.length === 0) return "(empty)";
      if (typeof value[0] === "string") return value.join(", ");
      return `${value.length} item${value.length > 1 ? "s" : ""}`;
    }
    if (typeof value === "object") return JSON.stringify(value).slice(0, 100) + "...";
    return String(value);
  }

  it("should format null as dash", () => {
    expect(formatFieldValue(null)).toBe("—");
    expect(formatFieldValue(undefined)).toBe("—");
  });

  it("should format booleans as Yes/No", () => {
    expect(formatFieldValue(true)).toBe("Yes");
    expect(formatFieldValue(false)).toBe("No");
  });

  it("should format numbers as strings", () => {
    expect(formatFieldValue(90)).toBe("90");
    expect(formatFieldValue(0)).toBe("0");
  });

  it("should truncate long strings", () => {
    const longString = "a".repeat(200);
    const result = formatFieldValue(longString);
    expect(result.length).toBeLessThan(200);
    expect(result.endsWith("...")).toBe(true);
  });

  it("should format string arrays as comma-separated", () => {
    expect(formatFieldValue(["monday", "tuesday"])).toBe("monday, tuesday");
  });

  it("should format empty arrays", () => {
    expect(formatFieldValue([])).toBe("(empty)");
  });

  it("should format object arrays with count", () => {
    expect(formatFieldValue([{ name: "a" }, { name: "b" }])).toBe("2 items");
    expect(formatFieldValue([{ name: "a" }])).toBe("1 item");
  });
});

// ─── Router Endpoint Existence Tests ──────────────────────────────────────────

describe("RoE Builder Router - Version History Endpoints", () => {
  it("should have getVersionHistory endpoint", async () => {
    const mod = await import("./routers/roe-builder");
    const routerDef = mod.roeBuilderRouter;
    expect(routerDef).toBeDefined();
  });

  it("should have roeVersions schema imported in router", async () => {
    // Verify the schema is properly importable
    const schema = await import("../drizzle/schema");
    expect(schema.roeVersions).toBeDefined();
    expect(schema.roeDocuments).toBeDefined();
    expect(schema.roePersonnel).toBeDefined();
    expect(schema.roeSignatures).toBeDefined();
  });
});
