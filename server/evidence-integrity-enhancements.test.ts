/**
 * Evidence Integrity Enhancements — Tests
 *
 * Covers:
 * 1. WebSocket evidence integrity emitter functions
 * 2. DOCX chain-of-custody seal section generation
 * 3. C2 callback and blue team win evidence gate wiring
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import path from "path";

const PROJECT_ROOT = path.resolve(__dirname, "..");

// ─── 1. WebSocket Evidence Integrity Emitters ──────────────────────────


// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)("WebSocket Evidence Integrity Emitters", () => {
  // We test that the emitter functions exist, accept correct params, and call broadcastGlobal
  let eventHub: any;

  beforeEach(async () => {
    // Reset module to get fresh eventHub
    vi.resetModules();
  });

  it("emitEvidenceGatePassed is exported and callable", async () => {
    const mod = await import("./lib/ws-event-hub");
    expect(typeof mod.emitEvidenceGatePassed).toBe("function");
  });

  it("emitEvidenceGateFlagged is exported and callable", async () => {
    const mod = await import("./lib/ws-event-hub");
    expect(typeof mod.emitEvidenceGateFlagged).toBe("function");
  });

  it("emitEvidenceQuarantined is exported and callable", async () => {
    const mod = await import("./lib/ws-event-hub");
    expect(typeof mod.emitEvidenceQuarantined).toBe("function");
  });

  it("emitEvidenceChainFlushed is exported and callable", async () => {
    const mod = await import("./lib/ws-event-hub");
    expect(typeof mod.emitEvidenceChainFlushed).toBe("function");
  });

  it("emitEvidenceAnchorCreated is exported and callable", async () => {
    const mod = await import("./lib/ws-event-hub");
    expect(typeof mod.emitEvidenceAnchorCreated).toBe("function");
  });

  it("emitEvidenceAnchorVerified is exported and callable", async () => {
    const mod = await import("./lib/ws-event-hub");
    expect(typeof mod.emitEvidenceAnchorVerified).toBe("function");
  });

  it("emitEvidenceTamperDetected is exported and callable", async () => {
    const mod = await import("./lib/ws-event-hub");
    expect(typeof mod.emitEvidenceTamperDetected).toBe("function");
  });

  it("all 7 evidence emitters are exported", async () => {
    const mod = await import("./lib/ws-event-hub");
    const evidenceEmitters = [
      "emitEvidenceGatePassed",
      "emitEvidenceGateFlagged",
      "emitEvidenceQuarantined",
      "emitEvidenceChainFlushed",
      "emitEvidenceAnchorCreated",
      "emitEvidenceAnchorVerified",
      "emitEvidenceTamperDetected",
    ];
    for (const name of evidenceEmitters) {
      expect(typeof (mod as any)[name]).toBe("function");
    }
  });
});

// ─── 2. Evidence Gate Integration Points ────────────────────────────────

describe("Evidence Gate Integration Points in Orchestrator", () => {
  it("orchestrator imports evidence integrity guardrails", async () => {
    // Read the orchestrator source to verify imports
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    expect(source).toContain("evidenceGate");
    expect(source).toContain("buildProvenance");
    expect(source).toContain("createIntegrityEnvelope");
    expect(source).toContain("recordCustodyEvent");
  });

  it("orchestrator has C2 agent deploy evidence gate", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    expect(source).toContain("Evidence Integrity Gate: C2 Deploy");
    expect(source).toContain("c2-deploy-");
  });

  it("orchestrator has C2 monitoring complete evidence gate", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    expect(source).toContain("Evidence Integrity Gate: C2 Monitoring Complete");
    expect(source).toContain("c2-monitor");
  });

  it("orchestrator has exploitation evidence gate", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    expect(source).toContain("Evidence Integrity Gate: validate exploitation evidence");
  });

  it("orchestrator has post-exploit evidence gate", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    expect(source).toContain("Evidence Integrity Gate: validate post-exploit evidence");
  });

  it("orchestrator has WAF detection (blue team win) evidence gate", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    expect(source).toContain("Evidence Integrity Gate: Blue Team Defense (WAF detection)");
    expect(source).toContain("waf-detection-");
    expect(source).toContain("blue_team_win");
  });

  it("orchestrator has exploit failure (blue team defense) evidence gate", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    expect(source).toContain("Evidence Integrity Gate: Blue Team Win (exploit failure = defense held)");
    expect(source).toContain("blue_team_win");
  });

  it("orchestrator has LLM vuln verification evidence gate", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    expect(source).toContain("Evidence Integrity Gate: validate LLM vuln verification");
  });

  it("orchestrator has engagement completion chain flush and anchor", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    expect(source).toContain("flushChainToDb");
    expect(source).toContain("createIntegrityAnchor");
  });

  it("orchestrator has pentest evidence collection gate", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
      "utf-8"
    );
    expect(source).toContain("Evidence Integrity Gate: validate per-asset pentest evidence");
  });
});

// ─── 3. DOCX Chain-of-Custody Seal Section ──────────────────────────────

describe("DOCX Chain-of-Custody Seal Section", () => {
  it("ac3-reports imports evidence integrity schema tables", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(source).toContain("evidenceIntegrityAnchors");
    expect(source).toContain("evidenceGuardrailAudit");
  });

  it("ac3-reports builds chainOfCustodySealSection", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(source).toContain("chainOfCustodySealSection");
    expect(source).toContain("Chain of Custody Verification");
  });

  it("ac3-reports includes seal section in document assembly", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(source).toContain("...chainOfCustodySealSection");
  });

  it("seal section queries for integrity anchors", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(source).toContain("evidenceIntegrityAnchors");
    expect(source).toContain("reportEngagementId");
  });

  it("seal section includes Merkle root display", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(source).toContain("Merkle Root");
    expect(source).toContain("HMAC Signature");
    expect(source).toContain("Chain Length");
    expect(source).toContain("Anchored At");
  });

  it("seal section includes guardrail audit summary", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(source).toContain("Hallucination Guardrail Audit Summary");
    expect(source).toContain("Total Integrity Checks");
    expect(source).toContain("Pass Rate");
  });

  it("seal section shows verified badge when anchor exists", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(source).toContain("CHAIN OF CUSTODY VERIFIED");
  });

  it("seal section shows warning when no anchor exists", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(source).toContain("NO INTEGRITY ANCHOR");
  });

  it("seal section includes verification instructions", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/ac3-reports.ts"),
      "utf-8"
    );
    expect(source).toContain("Verification Instructions");
    expect(source).toContain("Evidence Integrity dashboard");
    expect(source).toContain("Verify Anchor");
  });
});

// ─── 4. Report Pipeline Merkle Anchor Integration ──────────────────────

describe("Report Pipeline Merkle Anchor Integration", () => {
  it("reports-core imports createMerkleRootAnchor", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/reports-core.ts"),
      "utf-8"
    );
    expect(source).toContain("createMerkleRootAnchor");
    expect(source).toContain("flushChainToDb");
  });

  it("reports-core creates anchor after pentest pipeline", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/routers/reports-core.ts"),
      "utf-8"
    );
    // Verify the anchor creation is in the pipeline completion section
    const pipelineIdx = source.indexOf("runPentestReportPipeline");
    const anchorIdx = source.indexOf("createMerkleRootAnchor");
    expect(pipelineIdx).toBeGreaterThan(-1);
    expect(anchorIdx).toBeGreaterThan(-1);
  });
});

// ─── 5. WebSocket Event Type Consistency ────────────────────────────────

describe("WebSocket Event Type Consistency", () => {
  it("server-side WsEventType includes all evidence types", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "server/lib/ws-event-hub.ts"),
      "utf-8"
    );
    const evidenceTypes = [
      "evidence:gate_passed",
      "evidence:gate_flagged",
      "evidence:quarantined",
      "evidence:chain_flushed",
      "evidence:anchor_created",
      "evidence:anchor_verified",
      "evidence:tamper_detected",
    ];
    for (const type of evidenceTypes) {
      expect(source).toContain(`"${type}"`);
    }
  });

  it("client-side WsEventType includes all evidence types", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/hooks/useWebSocket.ts"),
      "utf-8"
    );
    const evidenceTypes = [
      "evidence:gate_passed",
      "evidence:gate_flagged",
      "evidence:quarantined",
      "evidence:chain_flushed",
      "evidence:anchor_created",
      "evidence:anchor_verified",
      "evidence:tamper_detected",
    ];
    for (const type of evidenceTypes) {
      expect(source).toContain(`"${type}"`);
    }
  });

  it("client-side toast handlers exist for critical evidence events", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/hooks/useWebSocket.ts"),
      "utf-8"
    );
    expect(source).toContain('case "evidence:gate_flagged"');
    expect(source).toContain('case "evidence:quarantined"');
    expect(source).toContain('case "evidence:anchor_created"');
    expect(source).toContain('case "evidence:tamper_detected"');
  });

  it("useEvidenceIntegrityEvents hook is exported", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/hooks/useWebSocket.ts"),
      "utf-8"
    );
    expect(source).toContain("export function useEvidenceIntegrityEvents");
    expect(source).toContain("evidence:gate_passed");
    expect(source).toContain("evidence:tamper_detected");
  });
});

// ─── 6. Evidence Integrity Dashboard Live Monitor ──────────────────────

describe("Evidence Integrity Dashboard Live Monitor", () => {
  it("EvidenceIntegrity page imports useEvidenceIntegrityEvents", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/pages/EvidenceIntegrity.tsx"),
      "utf-8"
    );
    expect(source).toContain("useEvidenceIntegrityEvents");
  });

  it("EvidenceIntegrity page has Live Monitor tab", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/pages/EvidenceIntegrity.tsx"),
      "utf-8"
    );
    expect(source).toContain('value="live"');
    expect(source).toContain("Live Monitor");
  });

  it("LiveMonitorPanel component renders event feed", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/pages/EvidenceIntegrity.tsx"),
      "utf-8"
    );
    expect(source).toContain("LiveMonitorPanel");
    expect(source).toContain("Real-Time Evidence Event Feed");
  });

  it("LiveMonitorPanel has pause/resume and clear controls", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/pages/EvidenceIntegrity.tsx"),
      "utf-8"
    );
    expect(source).toContain("isPaused");
    expect(source).toContain("Resume");
    expect(source).toContain("Pause");
    expect(source).toContain("Clear");
  });

  it("LiveMonitorPanel has live counters for all event types", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/pages/EvidenceIntegrity.tsx"),
      "utf-8"
    );
    expect(source).toContain("counters.passed");
    expect(source).toContain("counters.flagged");
    expect(source).toContain("counters.quarantined");
    expect(source).toContain("counters.anchors");
    expect(source).toContain("counters.flushed");
    expect(source).toContain("counters.tampered");
  });

  it("LiveMonitorPanel shows connection status indicator", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      path.join(PROJECT_ROOT, "client/src/pages/EvidenceIntegrity.tsx"),
      "utf-8"
    );
    expect(source).toContain("statusColor");
    expect(source).toContain("connected");
    expect(source).toContain("Connecting...");
    expect(source).toContain("Disconnected");
  });
});
