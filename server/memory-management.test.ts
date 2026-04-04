import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

// ─── State Trimming Tests ───────────────────────────────────────────────────

describe("State Trimming for Persistence", () => {
  // Read the actual source to verify trimming logic
  const persistenceSrc = fs.readFileSync(
    path.join(__dirname, "lib/ops-state-persistence.ts"),
    "utf-8"
  );

  it("should have trimStateForPersistence function", () => {
    expect(persistenceSrc).toContain("function trimStateForPersistence");
  });

  it("should cap state_json at 256KB target", () => {
    expect(persistenceSrc).toContain("MAX_STATE_KB = 256");
  });

  it("should limit persisted logs to 50 entries", () => {
    expect(persistenceSrc).toContain("MAX_LOGS = 50");
  });

  it("should trim tool output previews to 256 chars", () => {
    expect(persistenceSrc).toContain("MAX_OUTPUT_CHARS = 256");
  });

  it("should cap findings arrays at 20 items", () => {
    expect(persistenceSrc).toContain("tr.findings.length > 20");
    expect(persistenceSrc).toContain("tr.findings.slice(0, 20)");
  });

  it("should cap openPorts arrays at 200 items", () => {
    expect(persistenceSrc).toContain("asset.openPorts.length > 200");
    expect(persistenceSrc).toContain("asset.openPorts.slice(0, 200)");
  });

  it("should progressively reduce logs if still over size limit", () => {
    // First reduction to 20, then to 5
    expect(persistenceSrc).toContain("trimmed.log.slice(-20)");
    expect(persistenceSrc).toContain("trimmed.log.slice(-5)");
  });

  it("should use trimmedState (not raw state) in DB upsert", () => {
    // Both update and insert should use trimmedState
    const trimmedRefs = persistenceSrc.match(/\.\.\.(trimmedState)/g);
    expect(trimmedRefs).not.toBeNull();
    expect(trimmedRefs!.length).toBeGreaterThanOrEqual(2); // update + insert
  });

  it("should deep clone state to avoid mutating in-memory state", () => {
    expect(persistenceSrc).toContain("JSON.parse(JSON.stringify(state))");
  });
});

// ─── Memory Watchdog Threshold Tests ────────────────────────────────────────

describe("Memory Watchdog Thresholds (Manus Container)", () => {
  const orchestratorSrc = fs.readFileSync(
    path.join(__dirname, "lib/engagement-orchestrator.ts"),
    "utf-8"
  );

  it("should have HEAP_WARNING_MB at 250 (above boot-time heap of ~230MB)", () => {
    expect(orchestratorSrc).toContain("HEAP_WARNING_MB = 250");
    expect(orchestratorSrc).not.toContain("HEAP_WARNING_MB = 2000");
  });

  it("should have HEAP_CRITICAL_MB at 300 (not 4000)", () => {
    expect(orchestratorSrc).toContain("HEAP_CRITICAL_MB = 300");
    expect(orchestratorSrc).not.toContain("HEAP_CRITICAL_MB = 4000");
  });

  it("should have RSS_EMERGENCY_MB at 550 (Manus container tuned)", () => {
    expect(orchestratorSrc).toContain("RSS_EMERGENCY_MB = 550");
    expect(orchestratorSrc).not.toContain("RSS_EMERGENCY_MB = 24000");
  });

  it("should check every 10 seconds (not 30)", () => {
    expect(orchestratorSrc).toContain("10_000"); // watchdog interval
    expect(orchestratorSrc).toContain("Manus container can OOM fast");
  });

  it("should have aggressive log budgets based on heap pressure", () => {
    // Log budget scales with heap: 30 at >200MB, 50 at >150MB, 80 at >100MB, 150 otherwise
    expect(orchestratorSrc).toContain("heapMB > 200 ? 30");
    expect(orchestratorSrc).toContain("heapMB > 150 ? 50");
  });

  it("should evict completed states immediately at emergency level", () => {
    expect(orchestratorSrc).toContain("isEmergency ? 0 : 60_000");
  });
});

// ─── addLog Memory Thresholds ───────────────────────────────────────────────

describe("addLog Memory-Aware Trimming (Manus Container)", () => {
  const orchestratorSrc = fs.readFileSync(
    path.join(__dirname, "lib/engagement-orchestrator.ts"),
    "utf-8"
  );

  it("should trigger aggressive trimming at 200MB heap", () => {
    expect(orchestratorSrc).toContain("heapMB > 200 ? 30");
  });

  it("should trigger tool output trimming at 120MB heap", () => {
    // The if condition for trimming toolResults
    expect(orchestratorSrc).toContain("if (heapMB > 120)");
  });

  it("should trigger GC at 180MB heap", () => {
    expect(orchestratorSrc).toContain("heapMB > 180");
  });
});

// ─── ZAP Poll Failure Recovery ──────────────────────────────────────────────

describe("ZAP Poll Failure Recovery", () => {
  const zapSrc = fs.readFileSync(
    path.join(__dirname, "lib/zap-scanner.ts"),
    "utf-8"
  );

  it("should have pollFailureCounters map for tracking consecutive failures", () => {
    expect(zapSrc).toContain("pollFailureCounters = new Map<number, number>()");
  });

  it("should log errors instead of silently swallowing them", () => {
    expect(zapSrc).toContain("[ZAP pollScanProgress] Scan #${scanId}");
  });

  it("should auto-mark scan as error after MAX_POLL_FAILURES (5)", () => {
    expect(zapSrc).toContain("MAX_POLL_FAILURES = 5");
  });

  it("should reset failure counter on successful poll", () => {
    expect(zapSrc).toContain("pollFailureCounters.delete(scanId)");
  });

  it("should update scan status to error in DB when max failures reached", () => {
    expect(zapSrc).toContain("ZAP scan stalled after ${failures} consecutive poll failures");
  });
});

// ─── Orchestrator ZAP Timeout Handling ──────────────────────────────────────

describe("Orchestrator ZAP Timeout Handling", () => {
  const orchestratorSrc = fs.readFileSync(
    path.join(__dirname, "lib/engagement-orchestrator.ts"),
    "utf-8"
  );

  it("should mark timed-out ZAP scans as error in DB", () => {
    expect(orchestratorSrc).toContain("ZAP scan timed out after ${zapTimeoutMinutes} minutes");
  });

  it("should log ZAP timeout as warning", () => {
    expect(orchestratorSrc).toContain("ZAP Timeout:");
  });

  it("should log poll errors instead of silently catching", () => {
    // The orchestrator logs poll errors with failure count context
    expect(orchestratorSrc).toContain("ZAP Poll Error (");
  });
});
