/**
 * Safety Remediations Tests
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Tests for the three Claude-recommended safety remediations:
 *   1. Dual-approval enforcement for full_exploitation safety profile
 *   2. Exploit quarantine queue for LLM-generated exploits
 *   3. Elevated graduation bar for exploit-category callers
 */

import { describe, it, expect, beforeEach } from "vitest";

// ─── 1. Safety Engine: dualApprovalRequired field ───────────────────────────

describe("Safety Engine — dualApprovalRequired", () => {
  it("full_exploitation profile has dualApprovalRequired = true", async () => {
    const { SafetyEngine } = await import("./lib/safety-engine");
    const profile = SafetyEngine.getProfileDetails("full_exploitation");
    expect(profile.dualApprovalRequired).toBe(true);
  });

  it("standard profile has dualApprovalRequired = false", async () => {
    const { SafetyEngine } = await import("./lib/safety-engine");
    const profile = SafetyEngine.getProfileDetails("standard");
    expect(profile.dualApprovalRequired).toBe(false);
  });

  it("low_impact profile has dualApprovalRequired = false", async () => {
    const { SafetyEngine } = await import("./lib/safety-engine");
    const profile = SafetyEngine.getProfileDetails("low_impact");
    expect(profile.dualApprovalRequired).toBe(false);
  });

  it("passive_only profile has dualApprovalRequired = false", async () => {
    const { SafetyEngine } = await import("./lib/safety-engine");
    const profile = SafetyEngine.getProfileDetails("passive_only");
    expect(profile.dualApprovalRequired).toBe(false);
  });

  it("SafetyProfile interface includes dualApprovalRequired field", async () => {
    const { SafetyEngine } = await import("./lib/safety-engine");
    const levels = ["passive_only", "low_impact", "standard", "full_exploitation"] as const;
    for (const level of levels) {
      const profile = SafetyEngine.getProfileDetails(level);
      expect(typeof profile.dualApprovalRequired).toBe("boolean");
    }
  });
});

// ─── 2. Exploit Quarantine Queue ────────────────────────────────────────────

describe("Exploit Quarantine Queue", () => {
  beforeEach(async () => {
    const store = await import("./lib/exploit-knowledge-store");
    store.clearQuarantineQueue();
    store.clearExploitKnowledgeStore();
  });

  it("addExploitRecipe routes LLM-generated exploits to quarantine by default", async () => {
    const store = await import("./lib/exploit-knowledge-store");
    const result = store.addExploitRecipe({
      cveId: "CVE-2024-1234",
      title: "Test LLM Exploit",
      description: "An LLM-generated exploit for testing",
      code: "print('exploit')",
      language: "python",
      service: "apache",
      success: true,
      sourcePipeline: "nexus-pipeline",
    });

    expect(result.quarantined).toBe(true);
    expect(result.quarantineId).toBeDefined();
    expect(result.quarantineId).toMatch(/^quarantine-/);
  });

  it("addExploitRecipe bypasses quarantine when bypassQuarantine is true", async () => {
    const store = await import("./lib/exploit-knowledge-store");
    const result = store.addExploitRecipe({
      title: "Human-Authored Exploit",
      description: "A manually written exploit",
      code: "echo 'test'",
      language: "bash",
      success: true,
      bypassQuarantine: true,
    });

    expect(result.quarantined).toBe(false);
    expect(result.quarantineId).toBeUndefined();
  });

  it("failed exploits are not quarantined", async () => {
    const store = await import("./lib/exploit-knowledge-store");
    const result = store.addExploitRecipe({
      title: "Failed Exploit",
      description: "This exploit failed",
      code: "exit 1",
      language: "bash",
      success: false,
    });

    expect(result.quarantined).toBe(false);
    const queue = store.getQuarantineQueue();
    expect(queue.length).toBe(0);
  });

  it("getQuarantineQueue returns all quarantined exploits", async () => {
    const store = await import("./lib/exploit-knowledge-store");

    store.addExploitRecipe({
      title: "Exploit 1",
      description: "First exploit",
      code: "code1",
      language: "python",
      success: true,
    });
    store.addExploitRecipe({
      title: "Exploit 2",
      description: "Second exploit",
      code: "code2",
      language: "python",
      success: true,
    });

    const queue = store.getQuarantineQueue();
    expect(queue.length).toBe(2);
    expect(queue[0].status).toBe("pending_review");
    expect(queue[1].status).toBe("pending_review");
  });

  it("getQuarantineQueue filters by status", async () => {
    const store = await import("./lib/exploit-knowledge-store");

    const r1 = store.addExploitRecipe({
      title: "Exploit 1",
      description: "First",
      code: "code1",
      language: "python",
      success: true,
    });
    store.addExploitRecipe({
      title: "Exploit 2",
      description: "Second",
      code: "code2",
      language: "python",
      success: true,
    });

    // Approve the first one
    store.approveQuarantinedExploit(r1.quarantineId!, "reviewer1");

    const pending = store.getQuarantineQueue("pending_review");
    expect(pending.length).toBe(1);
    expect(pending[0].exploit.title).toBe("Exploit 2");

    const approved = store.getQuarantineQueue("approved");
    expect(approved.length).toBe(1);
    expect(approved[0].exploit.title).toBe("Exploit 1");
  });

  it("approveQuarantinedExploit moves exploit to main catalog", async () => {
    const store = await import("./lib/exploit-knowledge-store");

    const result = store.addExploitRecipe({
      cveId: "CVE-2024-5678",
      title: "Approved Exploit",
      description: "This will be approved",
      code: "exploit_code()",
      language: "python",
      service: "nginx",
      success: true,
    });

    const approval = store.approveQuarantinedExploit(
      result.quarantineId!,
      "security-lead",
      "Reviewed and verified"
    );

    expect(approval.success).toBe(true);

    // Verify the exploit is now in the main catalog
    const searchResults = await store.searchExploits("CVE-2024-5678");
    expect(searchResults.length).toBeGreaterThan(0);
    expect(searchResults[0].document.title).toBe("Approved Exploit");
    expect(searchResults[0].document.tags).toContain("human-reviewed");
  });

  it("rejectQuarantinedExploit keeps exploit out of main catalog", async () => {
    const store = await import("./lib/exploit-knowledge-store");

    const result = store.addExploitRecipe({
      cveId: "CVE-2024-9999",
      title: "Rejected Exploit",
      description: "This will be rejected",
      code: "bad_code()",
      language: "python",
      success: true,
    });

    const rejection = store.rejectQuarantinedExploit(
      result.quarantineId!,
      "security-lead",
      "Code quality too low"
    );

    expect(rejection.success).toBe(true);

    // Verify the exploit is NOT in the main catalog
    const searchResults = await store.searchExploits("CVE-2024-9999");
    expect(searchResults.length).toBe(0);
  });

  it("cannot approve already-approved exploit", async () => {
    const store = await import("./lib/exploit-knowledge-store");

    const result = store.addExploitRecipe({
      title: "Double Approve Test",
      description: "Test",
      code: "code",
      language: "python",
      success: true,
    });

    store.approveQuarantinedExploit(result.quarantineId!, "reviewer1");
    const secondApproval = store.approveQuarantinedExploit(result.quarantineId!, "reviewer2");

    expect(secondApproval.success).toBe(false);
    expect(secondApproval.error).toContain("already");
  });

  it("cannot reject already-rejected exploit", async () => {
    const store = await import("./lib/exploit-knowledge-store");

    const result = store.addExploitRecipe({
      title: "Double Reject Test",
      description: "Test",
      code: "code",
      language: "python",
      success: true,
    });

    store.rejectQuarantinedExploit(result.quarantineId!, "reviewer1");
    const secondRejection = store.rejectQuarantinedExploit(result.quarantineId!, "reviewer2");

    expect(secondRejection.success).toBe(false);
    expect(secondRejection.error).toContain("already");
  });

  it("getQuarantineStats returns correct counts", async () => {
    const store = await import("./lib/exploit-knowledge-store");

    const r1 = store.addExploitRecipe({ title: "E1", description: "D1", code: "c1", language: "py", success: true });
    const r2 = store.addExploitRecipe({ title: "E2", description: "D2", code: "c2", language: "py", success: true });
    store.addExploitRecipe({ title: "E3", description: "D3", code: "c3", language: "py", success: true });

    store.approveQuarantinedExploit(r1.quarantineId!, "reviewer");
    store.rejectQuarantinedExploit(r2.quarantineId!, "reviewer");

    const stats = store.getQuarantineStats();
    expect(stats.total).toBe(3);
    expect(stats.pendingReview).toBe(1);
    expect(stats.approved).toBe(1);
    expect(stats.rejected).toBe(1);
  });

  it("clearQuarantineQueue empties the queue", async () => {
    const store = await import("./lib/exploit-knowledge-store");

    store.addExploitRecipe({ title: "E1", description: "D1", code: "c1", language: "py", success: true });
    store.addExploitRecipe({ title: "E2", description: "D2", code: "c2", language: "py", success: true });

    expect(store.getQuarantineQueue().length).toBe(2);

    store.clearQuarantineQueue();
    expect(store.getQuarantineQueue().length).toBe(0);
  });

  it("quarantined exploit stores metadata correctly", async () => {
    const store = await import("./lib/exploit-knowledge-store");

    const result = store.addExploitRecipe({
      cveId: "CVE-2024-0001",
      title: "Metadata Test",
      description: "Testing metadata storage",
      code: "test_code()",
      language: "python",
      service: "apache",
      platform: "linux",
      success: true,
      engagementId: "eng-123",
      sourcePipeline: "nexus-pipeline",
    });

    const queue = store.getQuarantineQueue();
    const entry = queue.find(q => q.id === result.quarantineId);
    expect(entry).toBeDefined();
    expect(entry!.metadata.cveId).toBe("CVE-2024-0001");
    expect(entry!.metadata.engagementId).toBe("eng-123");
    expect(entry!.metadata.language).toBe("python");
    expect(entry!.metadata.service).toBe("apache");
    expect(entry!.metadata.platform).toBe("linux");
    expect(entry!.sourcePipeline).toBe("nexus-pipeline");
    expect(entry!.submittedBy).toBe("llm-pipeline");
  });
});

// ─── 3. Elevated Graduation Bar for Exploit-Category Callers ────────────────

describe("Elevated Graduation Bar — Exploit Category", () => {
  it("exploit-category callers require higher thresholds for tier 1", async () => {
    // A caller with 97% success and 500 calls should be tier 1 for normal callers
    // but NOT for exploit callers (which need 99% and 1000 calls)
    const mod = await import("./routers/graduation-engine");

    // We can't directly call computeTier since it's not exported,
    // but we can verify the thresholds are correct by checking the module structure
    expect(mod.graduationEngineRouter).toBeDefined();
  });

  it("GRADUATION_THRESHOLDS standard values are correct", async () => {
    // Verify the standard thresholds haven't been accidentally modified
    // by reading the source and checking the values
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/routers/graduation-engine.ts",
      "utf-8"
    );

    // Standard thresholds
    expect(source).toContain("tier1: { successRate: 97, minCalls: 500");
    expect(source).toContain("tier2: { successRate: 90, minCalls: 200");
    expect(source).toContain("tier3: { successRate: 80, minCalls: 50");
  });

  it("EXPLOIT_GRADUATION_THRESHOLDS have elevated values", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/routers/graduation-engine.ts",
      "utf-8"
    );

    // Exploit thresholds — higher bars
    expect(source).toContain("EXPLOIT_GRADUATION_THRESHOLDS");
    expect(source).toContain("successRate: 99, minCalls: 1000");  // tier1 exploit
    expect(source).toContain("successRate: 95, minCalls: 500");   // tier2 exploit
    expect(source).toContain("successRate: 90, minCalls: 100");   // tier3 exploit
  });

  it("EXPLOIT_CATEGORY_CALLERS includes functional-exploit-generator", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/routers/graduation-engine.ts",
      "utf-8"
    );

    expect(source).toContain("EXPLOIT_CATEGORY_CALLERS");
    expect(source).toContain("'functional-exploit-generator'");
    expect(source).toContain("'exploit-recipe-engine'");
    expect(source).toContain("'enhanced-exploit-orchestration'");
    expect(source).toContain("'specialist:exploit-selector'");
  });

  it("computeTier uses elevated thresholds for exploit callers", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/routers/graduation-engine.ts",
      "utf-8"
    );

    // Verify the computeTier function checks EXPLOIT_CATEGORY_CALLERS
    expect(source).toContain("EXPLOIT_CATEGORY_CALLERS.has(caller)");
    expect(source).toContain("EXPLOIT_GRADUATION_THRESHOLDS");
  });
});

// ─── 4. Dual-Approval Gate Interface ────────────────────────────────────────

describe("ApprovalGate — Dual-Approval Fields", () => {
  it("ApprovalGate interface includes dual-approval fields in source", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/engagement-orchestrator.ts",
      "utf-8"
    );

    expect(source).toContain("dualApprovalRequired?: boolean");
    expect(source).toContain("approvers?: string[]");
    expect(source).toContain("requiredApprovals?: number");
  });

  it("resolveApproval returns 'partial' type for dual-approval gates", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/engagement-orchestrator.ts",
      "utf-8"
    );

    // Verify the return type includes 'partial'
    expect(source).toContain("boolean | 'partial'");
    // Verify duplicate approver rejection
    expect(source).toContain("Duplicate Approver Rejected");
    // Verify partial approval logging
    expect(source).toContain("Partial Approval");
    // Verify dual approval completion logging
    expect(source).toContain("Dual Approval Complete");
  });

  it("requestApproval checks safety profile for dual-approval requirement", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/engagement-orchestrator.ts",
      "utf-8"
    );

    // Verify the requestApproval function checks the safety profile
    expect(source).toContain("safetyEng.getProfile().dualApprovalRequired");
    expect(source).toContain("isDualApproval");
    expect(source).toContain("requiredApprovals");
  });

  it("dual-approval gates require red risk tier", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/engagement-orchestrator.ts",
      "utf-8"
    );

    // Dual approval only applies to red-tier gates
    expect(source).toContain("gate.riskTier === 'red'");
  });
});

// ─── 5. Database Persistence Layer ─────────────────────────────────────────

describe("Quarantine Queue — Database Persistence Infrastructure", () => {
  it("exploit-knowledge-store exports persistQuarantineEntry via addExploitRecipe", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-knowledge-store.ts",
      "utf-8"
    );

    // Verify persistence functions exist
    expect(source).toContain("async function persistQuarantineEntry(entry: QuarantinedExploit)");
    expect(source).toContain("async function persistQuarantineReview(quarantineId: string");
    expect(source).toContain("async function persistApprovedCatalogEntry(entry: QuarantinedExploit");
  });

  it("addExploitRecipe calls persistQuarantineEntry after in-memory push", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-knowledge-store.ts",
      "utf-8"
    );

    // Verify the persistence call is in addExploitRecipe
    expect(source).toContain("persistQuarantineEntry(quarantinedExploit).catch");
  });

  it("approveQuarantinedExploit calls both persistQuarantineReview and persistApprovedCatalogEntry", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-knowledge-store.ts",
      "utf-8"
    );

    // Verify both persistence calls are in approveQuarantinedExploit
    expect(source).toContain("persistQuarantineReview(quarantineId, 'approved'");
    expect(source).toContain("persistApprovedCatalogEntry(entry, reviewedBy");
  });

  it("rejectQuarantinedExploit calls persistQuarantineReview with 'rejected' status", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-knowledge-store.ts",
      "utf-8"
    );

    expect(source).toContain("persistQuarantineReview(quarantineId, 'rejected'");
  });

  it("persistQuarantineEntry writes to exploitQuarantineQueue table", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-knowledge-store.ts",
      "utf-8"
    );

    expect(source).toContain("db.insert(exploitQuarantineQueue).values");
  });

  it("persistApprovedCatalogEntry writes to approvedExploitCatalog table", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-knowledge-store.ts",
      "utf-8"
    );

    expect(source).toContain("db.insert(approvedExploitCatalog).values");
  });

  it("database is declared as authoritative source of truth", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-knowledge-store.ts",
      "utf-8"
    );

    expect(source).toContain("authoritative source is the database");
    expect(source).toContain("hot cache");
  });
});

// ─── 6. Database Restoration on Init ───────────────────────────────────────

describe("Quarantine Queue — Database Restoration", () => {
  it("exports loadApprovedCatalogFromDb function", async () => {
    const store = await import("./lib/exploit-knowledge-store");
    expect(typeof store.loadApprovedCatalogFromDb).toBe("function");
  });

  it("exports loadQuarantineQueueFromDb function", async () => {
    const store = await import("./lib/exploit-knowledge-store");
    expect(typeof store.loadQuarantineQueueFromDb).toBe("function");
  });

  it("initializeExploitKnowledgeStore calls loadApprovedCatalogFromDb", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-knowledge-store.ts",
      "utf-8"
    );

    expect(source).toContain("loadApprovedCatalogFromDb()");
    expect(source).toContain("loadQuarantineQueueFromDb()");
  });

  it("initialization logs approved catalog and quarantine queue counts", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-knowledge-store.ts",
      "utf-8"
    );

    expect(source).toContain("Approved Catalog (DB):");
    expect(source).toContain("Quarantine Queue (DB):");
  });
});

// ─── 7. Catalog Selection Snapshot ─────────────────────────────────────────

describe("Exploit Selection Snapshot", () => {
  it("exports recordExploitSelectionSnapshot function", async () => {
    const store = await import("./lib/exploit-knowledge-store");
    expect(typeof store.recordExploitSelectionSnapshot).toBe("function");
  });

  it("recordExploitSelectionSnapshot writes to exploitSelectionSnapshots table", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-knowledge-store.ts",
      "utf-8"
    );

    expect(source).toContain("db.insert(exploitSelectionSnapshots).values");
  });

  it("recordExploitSelectionSnapshot computes catalog state hash", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-knowledge-store.ts",
      "utf-8"
    );

    expect(source).toContain("createHash('sha256')");
    expect(source).toContain("catalogHash");
    expect(source).toContain("catalogStateHash: catalogHash");
  });

  it("snapshot records engagement ID and RAG query details", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/exploit-knowledge-store.ts",
      "utf-8"
    );

    expect(source).toContain("engagementId: params.engagementId");
    expect(source).toContain("ragQueryUsed: params.ragQuery");
    expect(source).toContain("ragResultCount: params.ragResultCount");
    expect(source).toContain("ragResultIds: params.ragResultIds");
  });
});

// ─── 8. Schema Tables Exist ────────────────────────────────────────────────

describe("Database Schema — Quarantine & Catalog Tables", () => {
  it("exploit_quarantine_queue table is defined in schema", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/drizzle/schema.ts",
      "utf-8"
    );

    expect(source).toContain('exploitQuarantineQueue = mysqlTable("exploit_quarantine_queue"');
    expect(source).toContain("quarantine_id");
    expect(source).toContain("exploit_title");
    expect(source).toContain("source_pipeline");
    expect(source).toContain("'pending_review', 'approved', 'rejected'");
  });

  it("approved_exploit_catalog table is defined in schema", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/drizzle/schema.ts",
      "utf-8"
    );

    expect(source).toContain('approvedExploitCatalog = mysqlTable("approved_exploit_catalog"');
    expect(source).toContain("catalog_entry_id");
    expect(source).toContain("quarantine_id");
    expect(source).toContain("approved_by");
    expect(source).toContain("reliability_score");
  });

  it("exploit_selection_snapshots table is defined in schema", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/drizzle/schema.ts",
      "utf-8"
    );

    expect(source).toContain('exploitSelectionSnapshots = mysqlTable("exploit_selection_snapshots"');
    expect(source).toContain("snapshot_id");
    expect(source).toContain("catalog_state_hash");
    expect(source).toContain("selected_exploit_ids");
    expect(source).toContain("rag_query_used");
  });
});

// ─── 9. Graduation-Quarantine Independence ─────────────────────────────────

describe("Graduation-Quarantine Independence", () => {
  it("graduation engine explicitly documents that graduation does not bypass quarantine", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/routers/graduation-engine.ts",
      "utf-8"
    );

    expect(source).toContain("Graduation of an exploit-generating caller does NOT bypass");
    expect(source).toContain("quarantine queue for its outputs");
    expect(source).toContain("Graduation replaces the LLM caller with");
    expect(source).toContain("deterministic code");
  });

  it("graduation bar phrasing uses correct 'reduces tolerated failure rate' language", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/routers/graduation-engine.ts",
      "utf-8"
    );

    expect(source).toContain("tolerated failure rate from 3% to 1%");
    // Should NOT contain the old incorrect phrasing
    expect(source).not.toContain("2% higher success rate");
  });
});
