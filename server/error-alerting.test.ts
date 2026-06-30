/**
 * Tests for Error Alerting module
 * Validates: deduplication, rate spike detection, severity routing, config updates
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  processErrorAlert,
  updateAlertConfig,
  getAlertStatus,
  resetAlertState,
} from "./lib/error-alerting";

// Mock notifyOwner to prevent actual notifications
vi.mock("./_core/notification", () => ({
  notifyOwner: vi.fn().mockResolvedValue(true),
}));

describe("Error Alerting", () => {
  beforeEach(() => {
    resetAlertState();
    updateAlertConfig({
      enabled: true,
      deduplicationCooldownSec: 300,
      rateSpikeThreshold: 10,
      rateSpikeWindowSec: 60,
      immediateSeverities: ["critical"],
    });
  });

  describe("getAlertStatus", () => {
    it("returns default config and zero stats after reset", () => {
      const status = getAlertStatus();
      expect(status.config.enabled).toBe(true);
      expect(status.config.deduplicationCooldownSec).toBe(300);
      expect(status.config.rateSpikeThreshold).toBe(10);
      expect(status.config.rateSpikeWindowSec).toBe(60);
      expect(status.config.immediateSeverities).toEqual(["critical"]);
      expect(status.stats.totalAlertsSent).toBe(0);
      expect(status.stats.totalSuppressed).toBe(0);
      expect(status.stats.totalRateSpikeAlerts).toBe(0);
      expect(status.cooldownCount).toBe(0);
      expect(status.windowErrorCount).toBe(0);
    });
  });

  describe("updateAlertConfig", () => {
    it("merges partial config updates", () => {
      updateAlertConfig({ rateSpikeThreshold: 20, enabled: false });
      const status = getAlertStatus();
      expect(status.config.rateSpikeThreshold).toBe(20);
      expect(status.config.enabled).toBe(false);
      // Other values remain unchanged
      expect(status.config.deduplicationCooldownSec).toBe(300);
    });
  });

  describe("processErrorAlert", () => {
    it("does nothing when alerting is disabled", async () => {
      updateAlertConfig({ enabled: false });
      await processErrorAlert({
        message: "Critical failure",
        source: "server",
        severity: "critical",
      });
      const status = getAlertStatus();
      expect(status.stats.totalAlertsSent).toBe(0);
    });

    it("sends alert for critical severity errors", async () => {
      await processErrorAlert({
        message: "ReferenceError: Can't find variable: FileCheck",
        source: "react_boundary",
        severity: "critical",
        page: "/dashboard",
      });
      const status = getAlertStatus();
      expect(status.stats.totalAlertsSent).toBe(1);
      expect(status.cooldownCount).toBe(1);
    });

    it("does not send alert for non-critical severity", async () => {
      await processErrorAlert({
        message: "Minor warning",
        source: "client",
        severity: "warning",
      });
      const status = getAlertStatus();
      expect(status.stats.totalAlertsSent).toBe(0);
    });

    it("deduplicates same error within cooldown window", async () => {
      const error = {
        message: "ReferenceError: Can't find variable: FileCheck",
        source: "react_boundary",
        severity: "critical",
        page: "/dashboard",
      };
      await processErrorAlert(error);
      await processErrorAlert(error);
      await processErrorAlert(error);
      const status = getAlertStatus();
      expect(status.stats.totalAlertsSent).toBe(1);
      expect(status.stats.totalSuppressed).toBe(2);
    });

    it("allows different errors to each trigger alerts", async () => {
      await processErrorAlert({
        message: "Error A",
        source: "server",
        severity: "critical",
      });
      await processErrorAlert({
        message: "Error B",
        source: "client",
        severity: "critical",
      });
      const status = getAlertStatus();
      expect(status.stats.totalAlertsSent).toBe(2);
    });

    it("tracks window error count for rate spike detection", async () => {
      // Send 5 non-critical errors (won't trigger individual alerts but count toward rate)
      for (let i = 0; i < 5; i++) {
        await processErrorAlert({
          message: `Error ${i}`,
          source: "client",
          severity: "error",
        });
      }
      const status = getAlertStatus();
      expect(status.windowErrorCount).toBe(5);
    });

    it("triggers rate spike alert when threshold is exceeded", async () => {
      updateAlertConfig({ rateSpikeThreshold: 5 });
      // Send 5 errors to trigger the spike
      for (let i = 0; i < 5; i++) {
        await processErrorAlert({
          message: `Spike error ${i}`,
          source: "server",
          severity: "error", // non-critical, so no individual alert
        });
      }
      const status = getAlertStatus();
      expect(status.stats.totalRateSpikeAlerts).toBe(1);
    });

    it("only sends one rate spike alert per window", async () => {
      updateAlertConfig({ rateSpikeThreshold: 3 });
      // Send 6 errors — should only trigger 1 rate spike alert
      for (let i = 0; i < 6; i++) {
        await processErrorAlert({
          message: `Spike error ${i}`,
          source: "server",
          severity: "error",
        });
      }
      const status = getAlertStatus();
      expect(status.stats.totalRateSpikeAlerts).toBe(1);
    });
  });

  describe("resetAlertState", () => {
    it("clears all counters and cooldowns", async () => {
      await processErrorAlert({
        message: "Test error",
        source: "server",
        severity: "critical",
      });
      expect(getAlertStatus().stats.totalAlertsSent).toBe(1);

      resetAlertState();
      const status = getAlertStatus();
      expect(status.stats.totalAlertsSent).toBe(0);
      expect(status.stats.totalSuppressed).toBe(0);
      expect(status.cooldownCount).toBe(0);
      expect(status.windowErrorCount).toBe(0);
    });
  });
});
