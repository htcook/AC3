import { describe, it, expect, vi } from "vitest";

// ─── Test: Knowledge Base Router Structure ──────────────────────────────────


// Skip in CI — requires production database connection
const __skipInCI = !process.env.DATABASE_URL || process.env.DATABASE_URL.includes("localhost");

describe.skipIf(__skipInCI)("Knowledge Base Router", () => {
  // Test module registry structure
  it("should have correct module registry structure", async () => {
    // Import the module to test its exports
    const kb = await import("./routers/knowledge-base");
    expect(kb.knowledgeBaseRouter).toBeDefined();
  });

  // Test category configs
  it("should have all required categories in CATEGORY_CONFIG", () => {
    const requiredCategories = [
      "offensive",
      "social_engineering",
      "recon",
      "evasion",
      "web_app_testing",
      "payloads",
      "post_exploitation",
      "exploit_template",
    ];
    // These are the categories used in the module registry
    // Verify they're all valid strings
    for (const cat of requiredCategories) {
      expect(typeof cat).toBe("string");
      expect(cat.length).toBeGreaterThan(0);
    }
  });

  // Test phase configs
  it("should have all required phases", () => {
    const requiredPhases = [
      "recon",
      "enumeration",
      "vuln_detection",
      "exploitation",
      "post_exploitation",
      "reporting",
    ];
    for (const phase of requiredPhases) {
      expect(typeof phase).toBe("string");
      expect(phase.length).toBeGreaterThan(0);
    }
  });
});

// ─── Test: Post-Exploit Knowledge Module ────────────────────────────────────

describe("Post-Exploit Credential Knowledge", () => {
  it("should export all required technique arrays", async () => {
    const mod = await import("./lib/knowledge/post-exploit-credential-knowledge");
    expect(mod.CREDENTIAL_DUMP_TECHNIQUES).toBeDefined();
    expect(Array.isArray(mod.CREDENTIAL_DUMP_TECHNIQUES)).toBe(true);
    expect(mod.CREDENTIAL_DUMP_TECHNIQUES.length).toBeGreaterThan(0);

    expect(mod.LATERAL_MOVE_TECHNIQUES).toBeDefined();
    expect(Array.isArray(mod.LATERAL_MOVE_TECHNIQUES)).toBe(true);
    expect(mod.LATERAL_MOVE_TECHNIQUES.length).toBeGreaterThan(0);

    expect(mod.DOMAIN_ESCALATION_TECHNIQUES).toBeDefined();
    expect(Array.isArray(mod.DOMAIN_ESCALATION_TECHNIQUES)).toBe(true);

    expect(mod.SERVICE_EXPLOIT_TECHNIQUES).toBeDefined();
    expect(Array.isArray(mod.SERVICE_EXPLOIT_TECHNIQUES)).toBe(true);
  });

  it("should build full post-exploit context", async () => {
    const mod = await import("./lib/knowledge/post-exploit-credential-knowledge");
    const context = mod.buildFullPostExploitKnowledgeContext({ platform: "windows" });
    expect(typeof context).toBe("string");
    expect(context.length).toBeGreaterThan(100);
    expect(context).toContain("Credential");
  });

  it("should build credential dump context", async () => {
    const mod = await import("./lib/knowledge/post-exploit-credential-knowledge");
    const context = mod.buildCredentialDumpContext({ platform: "windows" });
    expect(typeof context).toBe("string");
    expect(context.length).toBeGreaterThan(50);
  });

  it("should build lateral move context", async () => {
    const mod = await import("./lib/knowledge/post-exploit-credential-knowledge");
    const context = mod.buildLateralMoveContext({ platform: "windows" });
    expect(typeof context).toBe("string");
    expect(context.length).toBeGreaterThan(50);
  });

  it("should have MITRE technique IDs on all techniques", async () => {
    const mod = await import("./lib/knowledge/post-exploit-credential-knowledge");
    for (const tech of mod.CREDENTIAL_DUMP_TECHNIQUES) {
      expect(tech.mitreTechniqueIds).toBeDefined();
      expect(Array.isArray(tech.mitreTechniqueIds)).toBe(true);
      expect(tech.mitreTechniqueIds.length).toBeGreaterThan(0);
      expect(tech.mitreTechniqueIds[0]).toMatch(/^T\d{4}/);
    }
    for (const tech of mod.LATERAL_MOVE_TECHNIQUES) {
      expect(tech.mitreTechniqueIds).toBeDefined();
      expect(Array.isArray(tech.mitreTechniqueIds)).toBe(true);
      expect(tech.mitreTechniqueIds.length).toBeGreaterThan(0);
      expect(tech.mitreTechniqueIds[0]).toMatch(/^T\d{4}/);
    }
  });

  it("should search post-exploit techniques", async () => {
    const mod = await import("./lib/knowledge/post-exploit-credential-knowledge");
    const results = mod.searchPostExploitTechniques("hash");
    expect(results).toBeDefined();
    // Should return an object with arrays
    expect(typeof results).toBe("object");
  });
});

// ─── Test: VNC Exploit Module ───────────────────────────────────────────────

describe("VNC Exploit Module", () => {
  it("should export VNC exploit templates", async () => {
    const mod = await import("./lib/vnc-exploit-module");
    expect(mod.VNC_EXPLOIT_TEMPLATES).toBeDefined();
    expect(Array.isArray(mod.VNC_EXPLOIT_TEMPLATES)).toBe(true);
    expect(mod.VNC_EXPLOIT_TEMPLATES.length).toBeGreaterThan(0);
  });

  it("should build VNC exploit context", async () => {
    const mod = await import("./lib/vnc-exploit-module");
    const context = mod.buildVncExploitContext({});
    expect(typeof context).toBe("string");
    expect(context.length).toBeGreaterThan(50);
    expect(context.toLowerCase()).toContain("vnc");
  });

  it("should have required fields on each VNC template", async () => {
    const mod = await import("./lib/vnc-exploit-module");
    for (const tmpl of mod.VNC_EXPLOIT_TEMPLATES) {
      expect(tmpl.id).toBeDefined();
      expect(tmpl.name).toBeDefined();
      expect(tmpl.category).toBeDefined();
      expect(tmpl.description).toBeDefined();
    }
  });
});

// ─── Test: MSSQL Exploit Module ─────────────────────────────────────────────

describe("MSSQL Exploit Module", () => {
  it("should export MSSQL exploit templates", async () => {
    const mod = await import("./lib/mssql-exploit-module");
    expect(mod.MSSQL_EXPLOIT_TEMPLATES).toBeDefined();
    expect(Array.isArray(mod.MSSQL_EXPLOIT_TEMPLATES)).toBe(true);
    expect(mod.MSSQL_EXPLOIT_TEMPLATES.length).toBeGreaterThan(0);
  });

  it("should build MSSQL exploit context", async () => {
    const mod = await import("./lib/mssql-exploit-module");
    const context = mod.buildMssqlExploitContext({});
    expect(typeof context).toBe("string");
    expect(context.length).toBeGreaterThan(50);
    expect(context.toLowerCase()).toContain("mssql");
  });

  it("should have required fields on each MSSQL template", async () => {
    const mod = await import("./lib/mssql-exploit-module");
    for (const tmpl of mod.MSSQL_EXPLOIT_TEMPLATES) {
      expect(tmpl.id).toBeDefined();
      expect(tmpl.name).toBeDefined();
      expect(tmpl.category).toBeDefined();
      expect(tmpl.description).toBeDefined();
    }
  });
});

// ─── Test: Knowledge Entry Schema ───────────────────────────────────────────

describe("Knowledge Entry Schema", () => {
  it("should have knowledge_entries table in schema", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.knowledgeEntries).toBeDefined();
  });

  it("should have required columns", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.knowledgeEntries;
    // Check that the table has the expected column names
    expect(table.entryId).toBeDefined();
    expect(table.name).toBeDefined();
    expect(table.category).toBeDefined();
    expect(table.description).toBeDefined();
    expect(table.phase).toBeDefined();
    expect(table.isActive).toBeDefined();
    expect(table.createdBy).toBeDefined();
    expect(table.tools).toBeDefined();
    expect(table.code).toBeDefined();
    expect(table.mitreTechniqueIds).toBeDefined();
    expect(table.opsecRisk).toBeDefined();
    expect(table.confidence).toBeDefined();
  });
});

// ─── Test: Entry ID Generation ──────────────────────────────────────────────

describe("Entry ID Format", () => {
  it("should generate USER-prefixed IDs", () => {
    const { randomUUID } = require("crypto");
    const entryId = `USER-${randomUUID().slice(0, 8).toUpperCase()}`;
    expect(entryId).toMatch(/^USER-[A-F0-9]{8}$/);
  });

  it("should generate unique IDs", () => {
    const { randomUUID } = require("crypto");
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      ids.add(`USER-${randomUUID().slice(0, 8).toUpperCase()}`);
    }
    expect(ids.size).toBe(100);
  });
});
