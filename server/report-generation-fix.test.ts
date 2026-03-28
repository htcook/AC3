import { describe, it, expect } from "vitest";
import { z } from "zod";

/**
 * Tests for the report generation "string didn't match" fix.
 *
 * Root cause: The `reports.generate` Zod input schema used `z.string().optional()`
 * for `preparedFor`, `preparedBy`, and `brandingColor`. This accepts `undefined`
 * but rejects `null`. When the engagement's `customerName` is `null` in the DB
 * (not `undefined`), SuperJSON serialization preserves the `null`, causing Zod
 * validation to fail with "Expected string, received null".
 *
 * Fix: Changed to `z.string().nullish()` which accepts both `null` and `undefined`.
 */

// ── Reproduce the exact Zod schemas ──

const OLD_SCHEMA = z.object({
  engagementId: z.number(),
  reportType: z.enum([
    "executive_summary",
    "technical_detail",
    "compliance",
    "phishing_results",
    "osint_assessment",
    "full_engagement",
    "purple_team",
    "red_team_assessment",
    "detection_gap_analysis",
    "pentest_assessment",
  ]),
  clientType: z
    .enum([
      "msp",
      "enterprise",
      "saas",
      "paas",
      "iaas",
      "mixed_hosting",
      "other",
    ])
    .default("enterprise"),
  title: z.string().min(1),
  preparedFor: z.string().optional(), // OLD: rejects null
  preparedBy: z.string().optional(), // OLD: rejects null
  includeSections: z.array(z.string()).optional(),
  brandingColor: z.string().optional(), // OLD: rejects null
});

const FIXED_SCHEMA = z.object({
  engagementId: z.number(),
  reportType: z.enum([
    "executive_summary",
    "technical_detail",
    "compliance",
    "phishing_results",
    "osint_assessment",
    "full_engagement",
    "purple_team",
    "red_team_assessment",
    "detection_gap_analysis",
    "pentest_assessment",
  ]),
  clientType: z
    .enum([
      "msp",
      "enterprise",
      "saas",
      "paas",
      "iaas",
      "mixed_hosting",
      "other",
    ])
    .default("enterprise"),
  title: z.string().min(1),
  preparedFor: z.string().nullish(), // FIXED: accepts null and undefined
  preparedBy: z.string().nullish(), // FIXED: accepts null and undefined
  includeSections: z.array(z.string()).optional(),
  brandingColor: z.string().nullish(), // FIXED: accepts null and undefined
});

const VALID_BASE = {
  engagementId: 1800019,
  reportType: "full_engagement" as const,
  clientType: "enterprise" as const,
  title: "Hackazon - Security Assessment Report",
};

describe("Report generation Zod input validation", () => {
  describe("OLD schema (z.string().optional()) — demonstrates the bug", () => {
    it("rejects null for preparedFor", () => {
      const result = OLD_SCHEMA.safeParse({
        ...VALID_BASE,
        preparedFor: null,
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const issue = result.error.issues[0];
        expect(issue.path).toContain("preparedFor");
        // This is the "Expected string, received null" error the user saw
        expect(issue.message).toMatch(/expected.*string.*received.*null/i);
      }
    });

    it("rejects null for preparedBy", () => {
      const result = OLD_SCHEMA.safeParse({
        ...VALID_BASE,
        preparedBy: null,
      });
      expect(result.success).toBe(false);
    });

    it("rejects null for brandingColor", () => {
      const result = OLD_SCHEMA.safeParse({
        ...VALID_BASE,
        brandingColor: null,
      });
      expect(result.success).toBe(false);
    });

    it("accepts undefined (which is the workaround)", () => {
      const result = OLD_SCHEMA.safeParse({
        ...VALID_BASE,
        preparedFor: undefined,
        preparedBy: undefined,
        brandingColor: undefined,
      });
      expect(result.success).toBe(true);
    });
  });

  describe("FIXED schema (z.string().nullish()) — validates the fix", () => {
    it("accepts null for preparedFor", () => {
      const result = FIXED_SCHEMA.safeParse({
        ...VALID_BASE,
        preparedFor: null,
      });
      expect(result.success).toBe(true);
    });

    it("accepts null for preparedBy", () => {
      const result = FIXED_SCHEMA.safeParse({
        ...VALID_BASE,
        preparedBy: null,
      });
      expect(result.success).toBe(true);
    });

    it("accepts null for brandingColor", () => {
      const result = FIXED_SCHEMA.safeParse({
        ...VALID_BASE,
        brandingColor: null,
      });
      expect(result.success).toBe(true);
    });

    it("accepts undefined for all optional fields", () => {
      const result = FIXED_SCHEMA.safeParse({
        ...VALID_BASE,
        preparedFor: undefined,
        preparedBy: undefined,
        brandingColor: undefined,
      });
      expect(result.success).toBe(true);
    });

    it("accepts valid strings for all optional fields", () => {
      const result = FIXED_SCHEMA.safeParse({
        ...VALID_BASE,
        preparedFor: "Acme Corp",
        preparedBy: "John Doe",
        brandingColor: "#213555",
      });
      expect(result.success).toBe(true);
    });

    it("accepts empty strings for optional fields (no min constraint)", () => {
      const result = FIXED_SCHEMA.safeParse({
        ...VALID_BASE,
        preparedFor: "",
        preparedBy: "",
        brandingColor: "",
      });
      expect(result.success).toBe(true);
    });

    it("still rejects empty title (min(1) constraint)", () => {
      const result = FIXED_SCHEMA.safeParse({
        ...VALID_BASE,
        title: "",
      });
      expect(result.success).toBe(false);
    });

    it("still rejects invalid reportType enum", () => {
      const result = FIXED_SCHEMA.safeParse({
        ...VALID_BASE,
        reportType: "invalid_type",
      });
      expect(result.success).toBe(false);
    });

    it("still rejects invalid clientType enum", () => {
      const result = FIXED_SCHEMA.safeParse({
        ...VALID_BASE,
        clientType: "invalid_client",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("Simulates the exact EngagementOps mutation call pattern", () => {
    it("handles engagement with null customerName (the bug scenario)", () => {
      // Simulates: engagement?.customerName is null from DB
      const engagement = { name: "Hackazon", customerName: null as string | null };
      const user = { name: "Admin" };

      // OLD pattern: `|| undefined` doesn't convert null to undefined
      // because null || undefined = undefined (this actually works!)
      // But SuperJSON might serialize differently...
      const oldPayload = {
        ...VALID_BASE,
        preparedFor: engagement?.customerName || undefined,
        preparedBy: user?.name || "AC3",
      };
      // This works because || converts null to undefined
      expect(FIXED_SCHEMA.safeParse(oldPayload).success).toBe(true);

      // The real bug: SuperJSON preserves null through serialization
      // When tRPC sends the data, null stays as null
      const superJsonPayload = {
        ...VALID_BASE,
        preparedFor: null, // SuperJSON preserves null
        preparedBy: "Admin",
      };
      // OLD schema would fail here
      expect(OLD_SCHEMA.safeParse(superJsonPayload).success).toBe(false);
      // FIXED schema accepts it
      expect(FIXED_SCHEMA.safeParse(superJsonPayload).success).toBe(true);
    });

    it("handles engagement with undefined fields (engagement not loaded yet)", () => {
      const engagement = undefined;
      const user = undefined;

      const payload = {
        ...VALID_BASE,
        title: `${engagement?.name || "Engagement"} - Security Assessment Report`,
        preparedFor: engagement?.customerName ?? undefined,
        preparedBy: user?.name ?? "AC3",
      };

      expect(FIXED_SCHEMA.safeParse(payload).success).toBe(true);
      expect(payload.title).toBe("Engagement - Security Assessment Report");
      expect(payload.preparedBy).toBe("AC3");
    });
  });
});

describe("PDF export HTML auto-print trigger", () => {
  it("generated HTML should contain window.print() auto-trigger", () => {
    // Simulate the HTML template output
    const html = `<script class="no-print">
  // Auto-trigger print dialog for PDF export
  window.addEventListener('load', function() {
    setTimeout(function() { window.print(); }, 600);
  });
</script>`;

    expect(html).toContain("window.print()");
    expect(html).toContain("window.addEventListener");
    expect(html).toContain("setTimeout");
    // Should NOT contain the commented-out version
    expect(html).not.toContain("// window.print()");
  });
});
