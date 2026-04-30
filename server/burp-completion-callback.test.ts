import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const PROJECT_ROOT = path.resolve(__dirname, "..");


// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)("Burp Scan Completion Callback", () => {
  // ─── db.addTimelineEvent Fix ───

  describe("db.addTimelineEvent function", () => {
    it("addTimelineEvent is exported from db.ts", async () => {
      const db = await import("../server/db");
      expect(typeof db.addTimelineEvent).toBe("function");
    });

    it("getTimelineEvents is exported from db.ts", async () => {
      const db = await import("../server/db");
      expect(typeof db.getTimelineEvents).toBe("function");
    });

    it("addTimelineEvent accepts the same params used by burp-auto-scan", async () => {
      // Verify the function signature matches what burp-auto-scan calls
      const dbSource = fs.readFileSync(path.join(PROJECT_ROOT, "server/db.ts"), "utf-8");
      expect(dbSource).toContain("export async function addTimelineEvent");
      expect(dbSource).toContain("engagementId: number");
      expect(dbSource).toContain("eventType:");
      expect(dbSource).toContain("scan_completed");
      expect(dbSource).toContain("title: string");
      expect(dbSource).toContain("description?:");
      expect(dbSource).toContain("metadata?:");
      expect(dbSource).toContain("userId?:");
    });
  });

  // ─── Burp Completion Callback System ───

  describe("Burp completion callback system", () => {
    it("onBurpScanComplete is exported from burp-auto-scan", async () => {
      const mod = await import("./lib/burp-auto-scan");
      expect(typeof mod.onBurpScanComplete).toBe("function");
    });

    it("BurpScanCompleteCallback type is exported", () => {
      const source = fs.readFileSync(
        path.join(PROJECT_ROOT, "server/lib/burp-auto-scan.ts"),
        "utf-8"
      );
      expect(source).toContain("export type BurpScanCompleteCallback");
    });

    it("notifyBurpScanComplete is called after findings import", () => {
      const source = fs.readFileSync(
        path.join(PROJECT_ROOT, "server/lib/burp-auto-scan.ts"),
        "utf-8"
      );
      expect(source).toContain("notifyBurpScanComplete");
      // Should be called after exploit matching and severity escalation
      const exploitMatchIdx = source.indexOf("feedBurpFindingsToExploitEngine");
      const escalationIdx = source.indexOf("runSeverityEscalation");
      const notifyIdx = source.indexOf("notifyBurpScanComplete(config, state)");
      expect(exploitMatchIdx).toBeGreaterThan(-1);
      expect(escalationIdx).toBeGreaterThan(-1);
      expect(notifyIdx).toBeGreaterThan(-1);
      expect(notifyIdx).toBeGreaterThan(exploitMatchIdx);
      expect(notifyIdx).toBeGreaterThan(escalationIdx);
    });
  });

  // ─── Severity Escalation on Burp Completion ───

  describe("Severity escalation on Burp completion", () => {
    it("burp-auto-scan triggers runSeverityEscalation after findings import", () => {
      const source = fs.readFileSync(
        path.join(PROJECT_ROOT, "server/lib/burp-auto-scan.ts"),
        "utf-8"
      );
      expect(source).toContain("runSeverityEscalation");
      // Escalation should come after findings import
      const importIdx = source.indexOf("state.importedCount = imported");
      const escalationIdx = source.indexOf("runSeverityEscalation");
      expect(importIdx).toBeGreaterThan(-1);
      expect(escalationIdx).toBeGreaterThan(-1);
      expect(escalationIdx).toBeGreaterThan(importIdx);
    });

    it("escalation results are logged to timeline", () => {
      const source = fs.readFileSync(
        path.join(PROJECT_ROOT, "server/lib/burp-auto-scan.ts"),
        "utf-8"
      );
      expect(source).toContain("Cross-Tool Severity Escalation");
      expect(source).toContain("burp_completion_escalation");
    });

    it("escalation logs include severity breakdown and top results", () => {
      const source = fs.readFileSync(
        path.join(PROJECT_ROOT, "server/lib/burp-auto-scan.ts"),
        "utf-8"
      );
      expect(source).toContain("severityBreakdown");
      expect(source).toContain("topResults");
      expect(source).toContain("escalatedCount");
      expect(source).toContain("priorityFlaggedCount");
    });
  });

  // ─── Orchestrator Integration ───

  describe("Orchestrator Burp completion integration", () => {
    it("orchestrator registers onBurpScanComplete callback", () => {
      const source = fs.readFileSync(
        path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
        "utf-8"
      );
      expect(source).toContain("onBurpScanComplete");
    });

    it("callback is registered BEFORE Burp scan is launched", () => {
      const source = fs.readFileSync(
        path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
        "utf-8"
      );
      const registerIdx = source.indexOf("onBurpScanComplete");
      const launchIdx = source.indexOf("onEngagementVulnDetectionPhase");
      expect(registerIdx).toBeGreaterThan(-1);
      expect(launchIdx).toBeGreaterThan(-1);
      expect(registerIdx).toBeLessThan(launchIdx);
    });

    it("callback logs Burp completion to engagement ops log", () => {
      const source = fs.readFileSync(
        path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
        "utf-8"
      );
      expect(source).toContain("Burp Scan Complete:");
      expect(source).toContain("findings imported");
    });

    it("callback filters by engagement ID", () => {
      const source = fs.readFileSync(
        path.join(PROJECT_ROOT, "server/lib/engagement-orchestrator.ts"),
        "utf-8"
      );
      // Should check engagementId matches before processing
      expect(source).toContain("burpConfig.engagementId !== state.engagementId");
    });
  });

  // ─── Burp Scan Pipeline Order ───

  describe("Burp scan pipeline execution order", () => {
    it("Step 4 (import) → Step 5 (exploit match) → Step 6 (escalation) → Step 7 (notify)", () => {
      const source = fs.readFileSync(
        path.join(PROJECT_ROOT, "server/lib/burp-auto-scan.ts"),
        "utf-8"
      );
      const step4 = source.indexOf("Step 4: Import findings");
      const step5 = source.indexOf("Step 5: Feed findings into exploit matching");
      const step6 = source.indexOf("Step 6: Trigger severity escalation");
      const step7 = source.indexOf("Step 7: Notify completion callback");
      expect(step4).toBeGreaterThan(-1);
      expect(step5).toBeGreaterThan(-1);
      expect(step6).toBeGreaterThan(-1);
      expect(step7).toBeGreaterThan(-1);
      expect(step5).toBeGreaterThan(step4);
      expect(step6).toBeGreaterThan(step5);
      expect(step7).toBeGreaterThan(step6);
    });
  });
});
