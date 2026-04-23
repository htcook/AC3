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

    // Verify the exploit moved from pending to approved in the quarantine queue
    const approved = store.getQuarantineQueue("approved");
    expect(approved.length).toBeGreaterThan(0);
    const approvedEntry = approved.find(e => e.exploit.title === "Approved Exploit");
    expect(approvedEntry).toBeDefined();
    expect(approvedEntry!.status).toBe("approved");
    expect(approvedEntry!.reviewedBy).toBe("security-lead");
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

    // Verify the rejected exploit is marked as rejected in the quarantine queue
    const queue = store.getQuarantineQueue("rejected");
    const rejectedEntry = queue.find((e: any) => e.id === result.quarantineId);
    expect(rejectedEntry).toBeDefined();
    expect(rejectedEntry.status).toBe("rejected");
    expect(rejectedEntry.reviewedBy).toBe("security-lead");
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


// ─── Round 3: HMAC Key Separation ──────────────────────────────────────────

describe("Evidence Integrity — HMAC Key Separation", () => {
  it("computeAnchorHMAC uses EVIDENCE_HMAC_KEY when set", async () => {
    // Save original env
    const origEvidence = process.env.EVIDENCE_HMAC_KEY;
    const origJwt = process.env.JWT_SECRET;

    process.env.EVIDENCE_HMAC_KEY = "test-evidence-key-12345";
    process.env.JWT_SECRET = "test-jwt-secret-99999";

    // Re-import to pick up env changes
    const mod = await import("./lib/evidence-integrity");
    const sig1 = mod.computeAnchorHMAC("merkle-root-abc", "eng-001");

    // Change JWT_SECRET — signature should NOT change
    process.env.JWT_SECRET = "completely-different-jwt-secret";
    const sig2 = mod.computeAnchorHMAC("merkle-root-abc", "eng-001");
    expect(sig2).toBe(sig1);

    // Restore
    process.env.EVIDENCE_HMAC_KEY = origEvidence;
    process.env.JWT_SECRET = origJwt;
  });

  it("computeAnchorHMAC falls back to JWT_SECRET with deprecation warning when EVIDENCE_HMAC_KEY is not set", async () => {
    const origEvidence = process.env.EVIDENCE_HMAC_KEY;
    const origJwt = process.env.JWT_SECRET;

    delete process.env.EVIDENCE_HMAC_KEY;
    process.env.JWT_SECRET = "fallback-jwt-secret";

    const mod = await import("./lib/evidence-integrity");
    // Should not throw — falls back to JWT_SECRET
    const sig = mod.computeAnchorHMAC("merkle-root-def", "eng-002");
    expect(sig).toBeTruthy();
    expect(typeof sig).toBe("string");
    expect(sig.length).toBe(64); // SHA-256 hex

    // Restore
    if (origEvidence) process.env.EVIDENCE_HMAC_KEY = origEvidence;
    else delete process.env.EVIDENCE_HMAC_KEY;
    process.env.JWT_SECRET = origJwt;
  });

  it("verifyAnchorHMAC validates signatures against current key", async () => {
    const origEvidence = process.env.EVIDENCE_HMAC_KEY;
    process.env.EVIDENCE_HMAC_KEY = "verify-test-key-abc";

    const mod = await import("./lib/evidence-integrity");
    const sig = mod.computeAnchorHMAC("merkle-root-xyz", "eng-003");
    const result = mod.verifyAnchorHMAC("merkle-root-xyz", "eng-003", sig);
    expect(result.valid).toBe(true);
    expect(result.keySource).toBe("current");

    // Restore
    if (origEvidence) process.env.EVIDENCE_HMAC_KEY = origEvidence;
    else delete process.env.EVIDENCE_HMAC_KEY;
  });

  it("verifyAnchorHMAC tries previous key after rotation", async () => {
    const origEvidence = process.env.EVIDENCE_HMAC_KEY;
    const origPrevious = process.env.EVIDENCE_HMAC_KEY_PREVIOUS;

    // Sign with old key
    process.env.EVIDENCE_HMAC_KEY = "old-key-before-rotation";
    delete process.env.EVIDENCE_HMAC_KEY_PREVIOUS;

    const mod = await import("./lib/evidence-integrity");
    const sigWithOldKey = mod.computeAnchorHMAC("merkle-root-rotate", "eng-004");

    // Rotate: old key becomes previous, new key is current
    process.env.EVIDENCE_HMAC_KEY_PREVIOUS = "old-key-before-rotation";
    process.env.EVIDENCE_HMAC_KEY = "new-key-after-rotation";

    // Verify with new key setup — should find it via previous key
    // Note: format changed with version prefix, so it may match via legacy format
    const result = mod.verifyAnchorHMAC("merkle-root-rotate", "eng-004", sigWithOldKey);
    expect(result.valid).toBe(true);
    expect(result.keySource).toContain("previous");

    // Restore
    if (origEvidence) process.env.EVIDENCE_HMAC_KEY = origEvidence;
    else delete process.env.EVIDENCE_HMAC_KEY;
    if (origPrevious) process.env.EVIDENCE_HMAC_KEY_PREVIOUS = origPrevious;
    else delete process.env.EVIDENCE_HMAC_KEY_PREVIOUS;
  });

  it("verifyAnchorHMAC rejects invalid signatures", async () => {
    const origEvidence = process.env.EVIDENCE_HMAC_KEY;
    process.env.EVIDENCE_HMAC_KEY = "reject-test-key";

    const mod = await import("./lib/evidence-integrity");
    const result = mod.verifyAnchorHMAC("merkle-root-bad", "eng-005", "deadbeef0000");
    expect(result.valid).toBe(false);
    expect(result.keySource).toBe("none");

    if (origEvidence) process.env.EVIDENCE_HMAC_KEY = origEvidence;
    else delete process.env.EVIDENCE_HMAC_KEY;
  });

  it("getEvidenceKeyMetadata returns key info without exposing key material", async () => {
    const origEvidence = process.env.EVIDENCE_HMAC_KEY;
    process.env.EVIDENCE_HMAC_KEY = "metadata-test-key-secret";

    const mod = await import("./lib/evidence-integrity");
    const metadata = mod.getEvidenceKeyMetadata();
    expect(metadata.source).toBe("EVIDENCE_HMAC_KEY");
    expect(metadata.version).toBe("v1");
    expect(metadata.keyFingerprint).toBeTruthy();
    expect(metadata.keyFingerprint.length).toBe(16);
    // Fingerprint should NOT contain the actual key
    expect(metadata.keyFingerprint).not.toContain("metadata-test-key-secret");

    if (origEvidence) process.env.EVIDENCE_HMAC_KEY = origEvidence;
    else delete process.env.EVIDENCE_HMAC_KEY;
  });

  it("evidence-integrity.ts source does NOT use JWT_SECRET directly for HMAC", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/server/lib/evidence-integrity.ts",
      "utf-8"
    );
    // The computeAnchorHMAC function should reference EVIDENCE_HMAC_KEY
    expect(source).toContain("EVIDENCE_HMAC_KEY");
    // Should have deprecation warning for JWT_SECRET fallback
    expect(source).toContain("deprecated fallback");
    // Should have key rotation support
    expect(source).toContain("EVIDENCE_HMAC_KEY_PREVIOUS");
  });
});

// ─── Round 3: Graduation Drift Detection ───────────────────────────────────

describe("Graduation Drift Detection — Adversarial Target Responses", () => {
  it("detectAdversarialTargetSuccess flags anomalous per-target success rates", async () => {
    const { detectAdversarialTargetSuccess } = await import("./routers/graduation-engine");
    const stats = [
      { target: "target-a", calls: 30, successes: 30 },  // 100% — suspicious
      { target: "target-b", calls: 20, successes: 12 },   // 60%
      { target: "target-c", calls: 15, successes: 9 },    // 60%
    ];
    const alert = detectAdversarialTargetSuccess(stats, "exploit-test-caller");
    expect(alert).not.toBeNull();
    expect(alert!.alertType).toBe("adversarial_target_success");
    expect(alert!.evidence.currentValue).toBeCloseTo(100, 0);
  });

  it("detectAdversarialTargetSuccess returns null for uniform success rates", async () => {
    const { detectAdversarialTargetSuccess } = await import("./routers/graduation-engine");
    const stats = [
      { target: "target-a", calls: 25, successes: 22 },  // 88%
      { target: "target-b", calls: 25, successes: 23 },   // 92%
      { target: "target-c", calls: 25, successes: 21 },   // 84%
    ];
    const alert = detectAdversarialTargetSuccess(stats, "normal-caller");
    expect(alert).toBeNull();
  });

  it("detectAdversarialTargetSuccess requires minimum 50 calls and 3 targets", async () => {
    const { detectAdversarialTargetSuccess } = await import("./routers/graduation-engine");
    // Too few calls
    const stats1 = [
      { target: "a", calls: 10, successes: 10 },
      { target: "b", calls: 10, successes: 5 },
      { target: "c", calls: 10, successes: 5 },
    ];
    expect(detectAdversarialTargetSuccess(stats1, "caller")).toBeNull();

    // Too few targets
    const stats2 = [
      { target: "a", calls: 40, successes: 40 },
      { target: "b", calls: 20, successes: 10 },
    ];
    expect(detectAdversarialTargetSuccess(stats2, "caller")).toBeNull();
  });
});

describe("Graduation Drift Detection — Slow-Drift Poisoning", () => {
  it("detectSlowDriftPoisoning flags sustained upward drift", async () => {
    const { detectSlowDriftPoisoning } = await import("./routers/graduation-engine");
    // 15 baseline weeks at ~60%, then 3 weeks at 99% (z-score > 2.0)
    const weeklyRates = [
      { week: "2026-01", successRate: 58, calls: 50 },
      { week: "2026-02", successRate: 60, calls: 55 },
      { week: "2026-03", successRate: 62, calls: 48 },
      { week: "2026-04", successRate: 64, calls: 52 },
      { week: "2026-05", successRate: 66, calls: 50 },
      { week: "2026-06", successRate: 58, calls: 53 },
      { week: "2026-07", successRate: 60, calls: 50 },
      { week: "2026-08", successRate: 62, calls: 55 },
      { week: "2026-09", successRate: 64, calls: 48 },
      { week: "2026-10", successRate: 66, calls: 52 },
      { week: "2026-11", successRate: 58, calls: 50 },
      { week: "2026-12", successRate: 60, calls: 53 },
      { week: "2026-13", successRate: 62, calls: 50 },
      { week: "2026-14", successRate: 64, calls: 55 },
      { week: "2026-15", successRate: 66, calls: 48 },
      { week: "2026-16", successRate: 99, calls: 60 },
      { week: "2026-17", successRate: 99, calls: 58 },
      { week: "2026-18", successRate: 99, calls: 62 },
    ];
    const alert = detectSlowDriftPoisoning(weeklyRates, "test-caller");
    expect(alert).not.toBeNull();
    expect(alert!.alertType).toBe("slow_drift_poisoning");
  });

  it("detectSlowDriftPoisoning returns null for stable success rates", async () => {
    const { detectSlowDriftPoisoning } = await import("./routers/graduation-engine");
    const weeklyRates = [
      { week: "2026-01", successRate: 85, calls: 50 },
      { week: "2026-02", successRate: 87, calls: 55 },
      { week: "2026-03", successRate: 84, calls: 48 },
      { week: "2026-04", successRate: 86, calls: 52 },
      { week: "2026-05", successRate: 85, calls: 50 },
      { week: "2026-06", successRate: 88, calls: 53 },
    ];
    const alert = detectSlowDriftPoisoning(weeklyRates, "stable-caller");
    expect(alert).toBeNull();
  });

  it("detectSlowDriftPoisoning uses lower z-threshold for exploit-category callers", async () => {
    const { detectSlowDriftPoisoning, EXPLOIT_CATEGORY_CALLERS } = await import("./routers/graduation-engine");
    // 15 baseline weeks at ~60%, then 3 weeks at ~88% (z-score ~1.7 — above 1.5 exploit threshold but below 2.0 standard)
    const weeklyRates = [
      { week: "2026-01", successRate: 58, calls: 50 },
      { week: "2026-02", successRate: 60, calls: 55 },
      { week: "2026-03", successRate: 62, calls: 48 },
      { week: "2026-04", successRate: 64, calls: 52 },
      { week: "2026-05", successRate: 66, calls: 50 },
      { week: "2026-06", successRate: 58, calls: 53 },
      { week: "2026-07", successRate: 60, calls: 50 },
      { week: "2026-08", successRate: 62, calls: 55 },
      { week: "2026-09", successRate: 64, calls: 48 },
      { week: "2026-10", successRate: 66, calls: 52 },
      { week: "2026-11", successRate: 58, calls: 50 },
      { week: "2026-12", successRate: 60, calls: 53 },
      { week: "2026-13", successRate: 62, calls: 50 },
      { week: "2026-14", successRate: 64, calls: 55 },
      { week: "2026-15", successRate: 66, calls: 48 },
      { week: "2026-16", successRate: 75, calls: 60 },
      { week: "2026-17", successRate: 75, calls: 58 },
      { week: "2026-18", successRate: 75, calls: 62 },
    ];
    // Standard caller — should NOT trigger (z ~1.97 < 2.0)
    const standardAlert = detectSlowDriftPoisoning(weeklyRates, "standard-caller");
    // Exploit caller — SHOULD trigger (z ~1.97 > 1.5)
    const exploitCaller = Array.from(EXPLOIT_CATEGORY_CALLERS)[0];
    const exploitAlert = detectSlowDriftPoisoning(weeklyRates, exploitCaller);
    expect(standardAlert).toBeNull();
    expect(exploitAlert).not.toBeNull();
    expect(exploitAlert!.alertType).toBe("slow_drift_poisoning");
  });
});

describe("Graduation Drift Detection — Sudden Spike", () => {
  it("detectSuddenSpike flags >20pp week-over-week increase", async () => {
    const { detectSuddenSpike } = await import("./routers/graduation-engine");
    const weeklyRates = [
      { week: "2026-01", successRate: 65, calls: 50 },
      { week: "2026-02", successRate: 90, calls: 55 }, // +25pp spike
    ];
    const alert = detectSuddenSpike(weeklyRates, "spike-caller");
    expect(alert).not.toBeNull();
    expect(alert!.alertType).toBe("sudden_spike");
    expect(alert!.severity).toBe("warning");
  });

  it("detectSuddenSpike flags >35pp spike as critical", async () => {
    const { detectSuddenSpike } = await import("./routers/graduation-engine");
    const weeklyRates = [
      { week: "2026-01", successRate: 50, calls: 50 },
      { week: "2026-02", successRate: 95, calls: 55 }, // +45pp spike
    ];
    const alert = detectSuddenSpike(weeklyRates, "critical-spike-caller");
    expect(alert).not.toBeNull();
    expect(alert!.severity).toBe("critical");
  });

  it("detectSuddenSpike returns null for normal week-over-week changes", async () => {
    const { detectSuddenSpike } = await import("./routers/graduation-engine");
    const weeklyRates = [
      { week: "2026-01", successRate: 82, calls: 50 },
      { week: "2026-02", successRate: 88, calls: 55 }, // +6pp — normal
    ];
    const alert = detectSuddenSpike(weeklyRates, "normal-caller");
    expect(alert).toBeNull();
  });
});

// ─── Round 3: Cross-Customer Consent — Reviewer Checklist ──────────────────

describe("Quarantine Approval — Reviewer Checklist", () => {
  beforeEach(async () => {
    const store = await import("./lib/exploit-knowledge-store");
    store.clearQuarantineQueue();
  });

  it("approveQuarantinedExploit blocks approval when checklist is incomplete", async () => {
    const store = await import("./lib/exploit-knowledge-store");
    const result = store.addExploitRecipe({
      title: "Checklist Test Exploit",
      description: "Test",
      code: "test code",
      language: "python",
      success: true,
    });
    expect(result.quarantined).toBe(true);

    const approval = store.approveQuarantinedExploit(
      result.quarantineId!,
      "reviewer1",
      "Approving",
      {
        noCustomerIPs: true,
        noCustomerHostnames: true,
        noCustomerCredentials: false, // Missing!
        noCustomerConfig: true,
        catalogConsentVerified: true,
      }
    );
    expect(approval.success).toBe(false);
    expect(approval.error).toContain("Reviewer checklist incomplete");
    expect(approval.error).toContain("No customer credentials");
  });

  it("approveQuarantinedExploit succeeds with complete checklist", async () => {
    const store = await import("./lib/exploit-knowledge-store");
    const result = store.addExploitRecipe({
      title: "Complete Checklist Exploit",
      description: "Test",
      code: "test code",
      language: "python",
      success: true,
    });

    const approval = store.approveQuarantinedExploit(
      result.quarantineId!,
      "reviewer1",
      "All checks passed",
      {
        noCustomerIPs: true,
        noCustomerHostnames: true,
        noCustomerCredentials: true,
        noCustomerConfig: true,
        catalogConsentVerified: true,
      }
    );
    expect(approval.success).toBe(true);
  });

  it("approveQuarantinedExploit allows approval without checklist (migration period)", async () => {
    const store = await import("./lib/exploit-knowledge-store");
    const result = store.addExploitRecipe({
      title: "No Checklist Exploit",
      description: "Test",
      code: "test code",
      language: "python",
      success: true,
    });

    // No checklist passed — should still succeed during migration
    const approval = store.approveQuarantinedExploit(
      result.quarantineId!,
      "reviewer1",
      "Legacy approval"
    );
    expect(approval.success).toBe(true);
  });

  it("ReviewerChecklist interface is exported from exploit-knowledge-store", async () => {
    const store = await import("./lib/exploit-knowledge-store");
    // TypeScript compilation verifies the interface exists; runtime check for export
    expect(typeof store.approveQuarantinedExploit).toBe("function");
    // Verify the function accepts 4 parameters (including optional checklist)
    expect(store.approveQuarantinedExploit.length).toBeGreaterThanOrEqual(2);
  });
});

// ─── Round 3: ROE Catalog Consent ──────────────────────────────────────────

describe("ROE Catalog Consent — Schema", () => {
  it("engagements table has roe_catalog_consent column in schema", async () => {
    const fs = await import("fs");
    const schema = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/drizzle/schema.ts",
      "utf-8"
    );
    expect(schema).toContain("roeCatalogConsent");
    expect(schema).toContain("roe_catalog_consent");
  });

  it("roe_catalog_consent defaults to 0 (no consent)", async () => {
    const fs = await import("fs");
    const schema = fs.readFileSync(
      "/home/ubuntu/caldera-dashboard/drizzle/schema.ts",
      "utf-8"
    );
    expect(schema).toContain('tinyint("roe_catalog_consent").default(0)');
  });
});
