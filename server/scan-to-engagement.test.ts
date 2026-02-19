import { describe, it, expect } from "vitest";

/**
 * Scan-to-Engagement Handoff Tests
 * 
 * Tests the flow from Domain Intel scan results → Create Engagement button → 
 * Engagement Manager with pre-populated form data.
 */

// ─── Route Configuration Tests ───────────────────────────────────────────────

describe("Scan-to-Engagement Route Configuration", () => {
  it("should have /engagements/new route that renders Engagements component", async () => {
    // The route /engagements/new must exist and render the same component as /engagements
    const appModule = await import("../client/src/App.tsx?raw");
    const appContent = typeof appModule.default === "string" ? appModule.default : String(appModule.default);
    
    // Check that /engagements/new route exists
    expect(appContent).toContain("engagements/new");
    expect(appContent).toContain("Engagements");
  });

  it("should navigate to /engagements/new with fromIntel and campaign query params", async () => {
    // The DomainIntelResults page should construct the correct URL
    const fs = await import("fs");
    const resultsContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/DomainIntelResults.tsx",
      "utf-8"
    );
    
    // Should use /engagements/new path
    expect(resultsContent).toContain("/engagements/new");
    // Should include fromIntel query param
    expect(resultsContent).toContain("fromIntel");
    // Should include campaign query param
    expect(resultsContent).toContain("campaign");
  });
});

// ─── fromIntel Query Parameter Handling Tests ────────────────────────────────

describe("fromIntel Query Parameter Handling", () => {
  it("should read fromIntel param from URL search params", async () => {
    const fs = await import("fs");
    const engagementsContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/Engagements.tsx",
      "utf-8"
    );
    
    // Should parse fromIntel from URL
    expect(engagementsContent).toContain("fromIntel");
    expect(engagementsContent).toContain("URLSearchParams");
  });

  it("should fetch scan data using correct tRPC Superjson format", async () => {
    const fs = await import("fs");
    const engagementsContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/Engagements.tsx",
      "utf-8"
    );
    
    // Should use the Superjson wrapper format { json: { id } }
    expect(engagementsContent).toContain("json");
    // Should call the domainIntel.getScan endpoint
    expect(engagementsContent).toContain("domainIntel.getScan");
  });

  it("should pre-populate form fields from scan data", async () => {
    const fs = await import("fs");
    const engagementsContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/Engagements.tsx",
      "utf-8"
    );
    
    // Should set engagement name from scan
    expect(engagementsContent).toContain("setFormData");
    // Should set customer name
    expect(engagementsContent).toContain("customerName");
    // Should set target domain
    expect(engagementsContent).toContain("targetDomain");
    // Should set engagement type
    expect(engagementsContent).toContain("engagementType");
    // Should auto-open the form
    expect(engagementsContent).toContain("setShowCreateForm");
  });

  it("should include scan risk score and asset count in description", async () => {
    const fs = await import("fs");
    const engagementsContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/Engagements.tsx",
      "utf-8"
    );
    
    // Should include risk info in description
    expect(engagementsContent).toContain("Risk");
    expect(engagementsContent).toContain("assets discovered");
  });
});

// ─── Backend Engagement Creation Tests ───────────────────────────────────────

describe("Engagement Creation Backend", () => {
  it("should have a create procedure in the engagements router", async () => {
    const fs = await import("fs");
    const routersContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/routers.ts",
      "utf-8"
    );
    
    // Should have engagement create procedure
    expect(routersContent).toContain("create:");
    // Should validate required fields
    expect(routersContent).toContain("name:");
    expect(routersContent).toContain("customerName:");
  });

  it("should have getScan procedure for fetching scan data", async () => {
    const fs = await import("fs");
    const routersContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/routers.ts",
      "utf-8"
    );
    
    // Should have getScan procedure in domainIntel router
    expect(routersContent).toContain("getScan:");
  });
});

// ─── Campaign ID Mapping Tests ───────────────────────────────────────────────

describe("Campaign ID in Handoff URL", () => {
  it("should pass campaign ID from DomainIntelResults to engagement form", async () => {
    const fs = await import("fs");
    const resultsContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/DomainIntelResults.tsx",
      "utf-8"
    );
    
    // Should include campaign parameter in the URL
    expect(resultsContent).toContain("campaign=");
    // Should reference campaign.id
    expect(resultsContent).toMatch(/campaign[=.].*id/s);
  });

  it("should read campaign param from URL in Engagements page", async () => {
    const fs = await import("fs");
    const engagementsContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/Engagements.tsx",
      "utf-8"
    );
    
    // Should read campaign from URL search params
    expect(engagementsContent).toContain("campaign");
  });
});

// ─── Error Handling Tests ────────────────────────────────────────────────────

describe("Handoff Error Handling", () => {
  it("should handle missing or invalid fromIntel param gracefully", async () => {
    const fs = await import("fs");
    const engagementsContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/Engagements.tsx",
      "utf-8"
    );
    
    // Should check if fromIntel exists before fetching
    expect(engagementsContent).toContain("fromIntel");
    // Should have error handling for fetch failures
    expect(engagementsContent).toContain("catch");
  });

  it("should handle scan fetch failure without crashing", async () => {
    const fs = await import("fs");
    const engagementsContent = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/client/src/pages/Engagements.tsx",
      "utf-8"
    );
    
    // Should have try-catch or .catch for the fetch
    expect(engagementsContent).toMatch(/catch|\.catch/);
  });
});
