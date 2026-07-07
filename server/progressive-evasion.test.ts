// @ts-nocheck
import { describe, it, expect, beforeEach } from "vitest";
import {
  initProgressiveEvasion,
  getProgressiveEvasionState,
  getEffectiveEvasionConfig,
  changeEvasionLevel,
  updateEvasionOverrides,
  resetEvasionOverrides,
  evasionToNmapFlags,
  evasionToNucleiConfig,
  evasionToHttpxConfig,
  createPauseGate,
  resolvePauseGate,
  getNextLevel,
  getPreviousLevel,
  recordDetection,
  getDetectionSummary,
  startScanRun,
  completeScanRun,
  shouldPauseBeforePhase,
  hasPendingPauseGate,
  getEvasionLevels,
  operatorLevelToDiscoveryProfile,
  EVASION_LEVELS,
} from "./lib/progressive-evasion-pipeline";

describe("Progressive Evasion Pipeline", () => {
  let engId: number;
  beforeEach(() => {
    engId = Math.floor(Math.random() * 100000) + 10000;
  });

  describe("§1 — Evasion Level Definitions", () => {
    it("defines 5 evasion levels ordered quiet → loud", () => {
      const levels = getEvasionLevels();
      expect(levels).toHaveLength(5);
      expect(levels[0].id).toBe("stealth");
      expect(levels[4].id).toBe("noisy");
    });

    it("stealth level has slowest timing and most evasion features", () => {
      const stealth = EVASION_LEVELS.stealth;
      expect(stealth.nmapTiming).toBe("T1");
      expect(stealth.requestsPerSecond).toBe(1);
      expect(stealth.fragmentation).toBe(true);
      expect(stealth.decoys).toBe(true);
      expect(stealth.randomizeHosts).toBe(true);
      expect(stealth.dataLengthPadding).toBe(true);
      expect(stealth.sourcePortSpoofing).toBe(true);
      expect(stealth.maxConcurrentTargets).toBe(1);
    });

    it("noisy level has fastest timing and no evasion", () => {
      const noisy = EVASION_LEVELS.noisy;
      expect(noisy.nmapTiming).toBe("T5");
      expect(noisy.requestsPerSecond).toBe(100);
      expect(noisy.fragmentation).toBe(false);
      expect(noisy.decoys).toBe(false);
      expect(noisy.randomizeHosts).toBe(false);
      expect(noisy.delayBetweenRequestsMs).toBe(0);
      expect(noisy.maxConcurrentTargets).toBe(10);
    });

    it("levels have monotonically increasing requestsPerSecond", () => {
      const order: Array<keyof typeof EVASION_LEVELS> = ["stealth", "low", "medium", "aggressive", "noisy"];
      for (let i = 0; i < order.length - 1; i++) {
        expect(EVASION_LEVELS[order[i]].requestsPerSecond)
          .toBeLessThan(EVASION_LEVELS[order[i + 1]].requestsPerSecond);
      }
    });
  });

  describe("§2 — Pipeline Initialization", () => {
    it("initializes pipeline for red_team engagement", () => {
      const state = initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      expect(state).toBeDefined();
      expect(state.currentLevel).toBe("stealth");
      expect(state.engagementType).toBe("red_team");
      expect(state.levelHistory).toHaveLength(1);
      expect(state.levelHistory[0].level).toBe("stealth");
    });

    it("initializes pipeline for pentest engagement", () => {
      const state = initProgressiveEvasion(engId, "pentest", "low", "op-2");
      expect(state.currentLevel).toBe("low");
      expect(state.engagementType).toBe("pentest");
    });

    it("accepts custom pipeline config", () => {
      const state = initProgressiveEvasion(engId, "red_team", "stealth", "op-1", {
        pauseBetweenScans: false,
        pauseBeforeExploit: true,
        pauseOnDetection: true,
        requireClientApproval: true,
      });
      expect(state.pipelineConfig.pauseBetweenScans).toBe(false);
      expect(state.pipelineConfig.requireClientApproval).toBe(true);
    });

    it("red_team defaults: pauseBetweenScans=true, pauseOnDetection=true, requireClientApproval=true", () => {
      const state = initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      expect(state.pipelineConfig.pauseBetweenScans).toBe(true);
      expect(state.pipelineConfig.pauseBeforeExploit).toBe(true);
      expect(state.pipelineConfig.pauseOnDetection).toBe(true);
      expect(state.pipelineConfig.requireClientApproval).toBe(true);
    });

    it("pentest defaults: pauseBetweenScans=false, pauseOnDetection=false", () => {
      const state = initProgressiveEvasion(engId, "pentest", "stealth", "op-1");
      expect(state.pipelineConfig.pauseBetweenScans).toBe(false);
      expect(state.pipelineConfig.pauseOnDetection).toBe(false);
      expect(state.pipelineConfig.pauseBeforeExploit).toBe(true);
    });

    it("getProgressiveEvasionState returns null for unknown engagement", () => {
      expect(getProgressiveEvasionState(99999)).toBeNull();
    });

    it("getProgressiveEvasionState returns state after init", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      const state = getProgressiveEvasionState(engId);
      expect(state).not.toBeNull();
      expect(state!.currentLevel).toBe("stealth");
    });
  });

  describe("§3 — Effective Config & Overrides", () => {
    it("getEffectiveEvasionConfig returns base level config when no overrides", () => {
      initProgressiveEvasion(engId, "red_team", "medium", "op-1");
      const config = getEffectiveEvasionConfig(engId);
      expect(config.nmapTiming).toBe("T3");
      expect(config.requestsPerSecond).toBe(15);
      expect(config.fragmentation).toBe(true);
    });

    it("updateEvasionOverrides merges on top of base level", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      const result = updateEvasionOverrides(engId, { requestsPerSecond: 3, fragmentation: false });
      expect(result.success).toBe(true);
      const config = getEffectiveEvasionConfig(engId);
      expect(config.requestsPerSecond).toBe(3);
      expect(config.fragmentation).toBe(false);
      expect(config.decoys).toBe(true); // Still from base stealth level
    });

    it("resetEvasionOverrides clears all overrides", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      updateEvasionOverrides(engId, { requestsPerSecond: 50 });
      resetEvasionOverrides(engId);
      const config = getEffectiveEvasionConfig(engId);
      expect(config.requestsPerSecond).toBe(1); // Back to stealth base
    });
  });

  describe("§4 — Evasion Level Changes (Escalation/De-escalation)", () => {
    it("changeEvasionLevel escalates from stealth to low", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      const result = changeEvasionLevel(engId, "low", "op-1", "No detections at stealth, escalating", "recon");
      expect(result.success).toBe(true);
      expect(result.previousLevel).toBe("stealth");
      expect(result.newLevel).toBe("low");
      const state = getProgressiveEvasionState(engId)!;
      expect(state.currentLevel).toBe("low");
      expect(state.levelHistory).toHaveLength(2);
    });

    it("changeEvasionLevel de-escalates from aggressive to medium", () => {
      initProgressiveEvasion(engId, "red_team", "aggressive", "op-1");
      const result = changeEvasionLevel(engId, "medium", "op-1", "Getting blocked, backing off", "vuln_scan");
      expect(result.success).toBe(true);
      expect(result.previousLevel).toBe("aggressive");
      expect(result.newLevel).toBe("medium");
    });

    it("changeEvasionLevel records history with reason", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      changeEvasionLevel(engId, "medium", "op-1", "Skipping to medium for time pressure", "recon");
      const state = getProgressiveEvasionState(engId)!;
      expect(state.levelHistory[1].reason).toContain("time pressure");
      expect(state.levelHistory[1].changedBy).toBe("op-1");
    });

    it("getNextLevel returns correct progression", () => {
      expect(getNextLevel("stealth")).toBe("low");
      expect(getNextLevel("low")).toBe("medium");
      expect(getNextLevel("medium")).toBe("aggressive");
      expect(getNextLevel("aggressive")).toBe("noisy");
      expect(getNextLevel("noisy")).toBeNull();
    });

    it("getPreviousLevel returns correct regression", () => {
      expect(getPreviousLevel("noisy")).toBe("aggressive");
      expect(getPreviousLevel("aggressive")).toBe("medium");
      expect(getPreviousLevel("medium")).toBe("low");
      expect(getPreviousLevel("low")).toBe("stealth");
      expect(getPreviousLevel("stealth")).toBeNull();
    });
  });

  describe("§5 — Nmap Flag Generation", () => {
    it("stealth level generates comprehensive evasion flags", () => {
      const flags = evasionToNmapFlags(EVASION_LEVELS.stealth);
      expect(flags).toContain("-T1");
      expect(flags).toContain("-f");
      expect(flags).toContain("-D");
      expect(flags).toContain("--randomize-hosts");
      expect(flags).toContain("--data-length");
      expect(flags).toContain("-g");
      expect(flags).toContain("--max-rate");
      expect(flags).toContain("--scan-delay");
      expect(flags).toContain("--max-retries");
    });

    it("noisy level generates minimal flags", () => {
      const flags = evasionToNmapFlags(EVASION_LEVELS.noisy);
      expect(flags).toContain("-T5");
      expect(flags).not.toContain("-f");
      expect(flags).not.toContain("-D");
      expect(flags).not.toContain("--randomize-hosts");
      expect(flags).not.toContain("--data-length");
      expect(flags).not.toContain("--scan-delay");
    });

    it("medium level has balanced flags", () => {
      const flags = evasionToNmapFlags(EVASION_LEVELS.medium);
      expect(flags).toContain("-T3");
      expect(flags).toContain("-f");
      expect(flags).not.toContain("-D");
      expect(flags).toContain("--randomize-hosts");
    });
  });

  describe("§6 — Nuclei Config Generation", () => {
    it("stealth level produces conservative nuclei config", () => {
      const config = evasionToNucleiConfig(EVASION_LEVELS.stealth);
      expect(config.rateLimit).toBeLessThanOrEqual(1);
      expect(config.concurrency).toBe(1);
      expect(config.retries).toBe(0);
      expect(config.interactshDisable).toBe(true);
    });

    it("aggressive level produces fast nuclei config", () => {
      const config = evasionToNucleiConfig(EVASION_LEVELS.aggressive);
      expect(config.rateLimit).toBeGreaterThan(10);
      expect(config.concurrency).toBe(5);
      expect(config.retries).toBe(1);
      expect(config.interactshDisable).toBe(false);
    });

    it("respects operator nucleiRateLimit override", () => {
      const config = evasionToNucleiConfig(EVASION_LEVELS.stealth, { nucleiRateLimit: 10 });
      expect(config.rateLimit).toBe(10);
    });
  });

  describe("§7 — Httpx Config Generation", () => {
    it("stealth level produces conservative httpx config", () => {
      const config = evasionToHttpxConfig(EVASION_LEVELS.stealth);
      expect(config.threads).toBe(1);
      expect(config.rateLimit).toBe(1);
      expect(config.randomAgent).toBe(true);
      expect(config.retries).toBe(0);
    });

    it("respects operator httpxThreads override", () => {
      const config = evasionToHttpxConfig(EVASION_LEVELS.stealth, { httpxThreads: 5 });
      expect(config.threads).toBe(5);
    });
  });

  describe("§8 — Pipeline Pause Gates", () => {
    it("createPauseGate creates a pending gate", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      const gate = createPauseGate(engId, {
        phase: "recon",
        nextPhase: "port_scan",
        reason: "between_scan_types",
        title: "Recon Complete — Ready for Port Scan?",
        description: "Passive recon finished. Escalate to active port scanning?",
      });
      expect(gate).toBeDefined();
      expect(gate!.status).toBe("pending");
      expect(gate!.reason).toBe("between_scan_types");
      expect(gate!.currentEvasionLevel).toBe("stealth");
    });

    it("resolvePauseGate with resume action resolves the gate", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      const gate = createPauseGate(engId, {
        phase: "recon",
        nextPhase: "port_scan",
        reason: "between_scan_types",
        title: "Ready?",
        description: "Continue?",
      });
      const result = resolvePauseGate(engId, gate!.id, {
        action: "resume",
        operatorId: "op-1",
      });
      expect(result.success).toBe(true);
      // Resolution action is on the gate object
      expect(result.gate!.resolution!.action).toBe("resume");
    });

    it("resolvePauseGate with escalate changes evasion level", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      const gate = createPauseGate(engId, {
        phase: "port_scan",
        nextPhase: "vuln_scan",
        reason: "between_scan_types",
        title: "Escalate?",
        description: "Port scan done, escalate for vuln scan?",
      });
      const result = resolvePauseGate(engId, gate!.id, {
        action: "escalate",
        operatorId: "op-1",
        notes: "No detections, safe to escalate",
      });
      expect(result.success).toBe(true);
      const state = getProgressiveEvasionState(engId)!;
      expect(state.currentLevel).toBe("low"); // Escalated from stealth → low
    });

    it("resolvePauseGate with rescan_different_level changes level", () => {
      initProgressiveEvasion(engId, "red_team", "low", "op-1");
      const gate = createPauseGate(engId, {
        phase: "vuln_scan",
        nextPhase: "exploit",
        reason: "between_scan_types",
        title: "Rescan?",
        description: "Try different level?",
      });
      const result = resolvePauseGate(engId, gate!.id, {
        action: "rescan_different_level",
        operatorId: "op-1",
        newEvasionLevel: "medium",
      });
      expect(result.success).toBe(true);
      const state = getProgressiveEvasionState(engId)!;
      expect(state.currentLevel).toBe("medium");
    });

    it("resolvePauseGate with abort stops pipeline", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      const gate = createPauseGate(engId, {
        phase: "exploit",
        nextPhase: "post_exploit",
        reason: "pre_exploit",
        title: "Abort?",
        description: "Abort pipeline?",
      });
      const result = resolvePauseGate(engId, gate!.id, {
        action: "abort",
        operatorId: "op-1",
        notes: "Client requested stop",
      });
      expect(result.success).toBe(true);
      expect(result.gate!.resolution!.action).toBe("abort");
    });

    it("hasPendingPauseGate returns pending gate", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      createPauseGate(engId, {
        phase: "recon",
        nextPhase: "port_scan",
        reason: "between_scan_types",
        title: "Pause",
        description: "Paused",
      });
      const pending = hasPendingPauseGate(engId);
      expect(pending).not.toBeNull();
      expect(pending!.status).toBe("pending");
    });

    it("hasPendingPauseGate returns null when all resolved", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      const gate = createPauseGate(engId, {
        phase: "recon",
        nextPhase: "port_scan",
        reason: "between_scan_types",
        title: "Pause",
        description: "Paused",
      });
      resolvePauseGate(engId, gate!.id, { action: "resume", operatorId: "op-1" });
      expect(hasPendingPauseGate(engId)).toBeNull();
    });
  });

  describe("§9 — Detection Tracking", () => {
    it("recordDetection adds event to state", () => {
      initProgressiveEvasion(engId, "red_team", "medium", "op-1");
      const event = recordDetection(engId, {
        engagementId: engId,
        target: "192.168.1.100",
        evasionLevel: "medium",
        detectedBy: "waf",
        detectionProduct: "Cloudflare",
        evidence: "HTTP 403 with cf-ray header",
        scanTool: "nuclei",
        impact: "scan_blocked",
        timestamp: Date.now(),
      });
      expect(event).toBeDefined();
      expect(event!.target).toBe("192.168.1.100");
      expect(event!.detectedBy).toBe("waf");
    });

    it("recordDetection updates targetDetectionMap with firstDetectedAt", () => {
      initProgressiveEvasion(engId, "red_team", "medium", "op-1");
      recordDetection(engId, {
        engagementId: engId,
        target: "10.0.0.1",
        evasionLevel: "medium",
        detectedBy: "ids",
        evidence: "Snort alert",
        scanTool: "nmap",
        impact: "scan_degraded",
        timestamp: Date.now(),
      });
      const state = getProgressiveEvasionState(engId)!;
      expect(state.targetDetectionMap["10.0.0.1"]).toBeDefined();
      expect(state.targetDetectionMap["10.0.0.1"].firstDetectedAt).toBe("medium");
      expect(state.targetDetectionMap["10.0.0.1"].detectionCount).toBe(1);
    });

    it("getDetectionSummary returns totalDetections and breakdown", () => {
      initProgressiveEvasion(engId, "red_team", "aggressive", "op-1");
      recordDetection(engId, {
        engagementId: engId,
        target: "target-a.com",
        evasionLevel: "aggressive",
        detectedBy: "waf",
        detectionProduct: "Cloudflare",
        evidence: "Blocked",
        scanTool: "nuclei",
        impact: "scan_blocked",
        timestamp: Date.now(),
      });
      recordDetection(engId, {
        engagementId: engId,
        target: "target-b.com",
        evasionLevel: "aggressive",
        detectedBy: "rate_limiter",
        evidence: "429 Too Many Requests",
        scanTool: "httpx",
        impact: "scan_degraded",
        timestamp: Date.now(),
      });
      const summary = getDetectionSummary(engId);
      expect(summary).not.toBeNull();
      expect(summary!.totalDetections).toBe(2);
      expect(summary!.detectionsByLevel.aggressive).toBe(2);
    });
  });

  describe("§10 — Scan Run Tracking", () => {
    it("startScanRun records a new scan with correct params", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      const run = startScanRun(engId, {
        phase: "enumeration",
        scanType: "port_scan",
        targetsCount: 24,
      });
      expect(run).toBeDefined();
      expect(run!.scanType).toBe("port_scan");
      expect(run!.evasionLevel).toBe("stealth");
      expect(run!.status).toBe("running");
      expect(run!.targetsScanned).toBe(24);
    });

    it("completeScanRun marks scan as completed (returns boolean)", () => {
      initProgressiveEvasion(engId, "red_team", "low", "op-1");
      const run = startScanRun(engId, {
        phase: "vuln_detection",
        scanType: "vuln_scan",
        targetsCount: 5,
      });
      const result = completeScanRun(engId, run!.id, {
        status: "completed",
        findingsCount: 12,
      });
      expect(result).toBe(true);
      // Verify the record was updated
      const state = getProgressiveEvasionState(engId)!;
      const record = state.scanHistory.find(s => s.id === run!.id)!;
      expect(record.status).toBe("completed");
      expect(record.findingsCount).toBe(12);
    });

    it("completeScanRun marks scan as blocked", () => {
      initProgressiveEvasion(engId, "red_team", "medium", "op-1");
      const run = startScanRun(engId, {
        phase: "web_scan",
        scanType: "web_app_scan",
        targetsCount: 1,
      });
      const result = completeScanRun(engId, run!.id, {
        status: "blocked",
        findingsCount: 3,
      });
      expect(result).toBe(true);
      const state = getProgressiveEvasionState(engId)!;
      const record = state.scanHistory.find(s => s.id === run!.id)!;
      expect(record.status).toBe("blocked");
    });
  });

  describe("§11 — shouldPauseBeforePhase", () => {
    it("returns shouldPause=true for enumeration phase on red_team (pauseBetweenScans=true)", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      // shouldPauseBeforePhase requires stats param
      const result = shouldPauseBeforePhase(engId, "recon", "enumeration", {
        hostsScanned: 10,
        portsFound: 50,
        vulnsFound: 0,
        wafDetections: [],
        blockedAttempts: 0,
        detectionEvents: [],
      });
      expect(result.shouldPause).toBe(true);
      expect(result.reason).toBe("between_scan_types");
    });

    it("returns shouldPause=false for enumeration on pentest (pauseBetweenScans=false)", () => {
      initProgressiveEvasion(engId, "pentest", "stealth", "op-1");
      const result = shouldPauseBeforePhase(engId, "recon", "enumeration", {
        hostsScanned: 10,
        portsFound: 50,
        vulnsFound: 0,
        wafDetections: [],
        blockedAttempts: 0,
        detectionEvents: [],
      });
      expect(result.shouldPause).toBe(false);
    });

    it("returns shouldPause=true before exploitation phase", () => {
      initProgressiveEvasion(engId, "pentest", "stealth", "op-1");
      const result = shouldPauseBeforePhase(engId, "vuln_scan", "exploitation", {
        hostsScanned: 10,
        portsFound: 50,
        vulnsFound: 5,
        wafDetections: [],
        blockedAttempts: 0,
        detectionEvents: [],
      });
      expect(result.shouldPause).toBe(true);
      expect(result.reason).toBe("pre_exploit");
    });
  });

  describe("§12 — operatorLevelToDiscoveryProfile", () => {
    it("maps stealth to discovery profile with T1 timing", () => {
      const profile = operatorLevelToDiscoveryProfile("stealth");
      expect(profile).toBeDefined();
      expect(profile.timing).toBe("T1");
      expect(profile.fragmentation).toBe(true);
      expect(profile.decoys).toBe(true);
      expect(profile.rationale).toContain("Stealth");
    });

    it("maps noisy to fast discovery profile with T5 timing", () => {
      const profile = operatorLevelToDiscoveryProfile("noisy");
      expect(profile).toBeDefined();
      expect(profile.timing).toBe("T5");
      expect(profile.fragmentation).toBe(false);
    });
  });

  describe("§13 — Edge Cases", () => {
    it("getEffectiveEvasionConfig returns stealth defaults for non-existent pipeline", () => {
      const config = getEffectiveEvasionConfig(99998);
      expect(config.nmapTiming).toBe("T1"); // Falls back to stealth
    });

    it("returns false for operations on non-existent pipeline", () => {
      expect(changeEvasionLevel(99998, "low", "op", "test", "recon").success).toBe(false);
      expect(updateEvasionOverrides(99998, { requestsPerSecond: 5 }).success).toBe(false);
      expect(resetEvasionOverrides(99998)).toBe(false);
      expect(recordDetection(99998, { engagementId: 99998, target: "x", evasionLevel: "low", detectedBy: "waf", evidence: "x", scanTool: "nmap", impact: "scan_blocked", timestamp: Date.now() })).toBeNull();
      expect(getDetectionSummary(99998)).toBeNull();
      expect(startScanRun(99998, { phase: "recon", scanType: "port_scan", targetsCount: 1 })).toBeNull();
    });

    it("multiple pause gates can exist (only first pending blocks)", () => {
      initProgressiveEvasion(engId, "red_team", "stealth", "op-1");
      const gate1 = createPauseGate(engId, {
        phase: "recon", nextPhase: "port_scan",
        reason: "between_scan_types", title: "Gate 1", description: "First",
      });
      resolvePauseGate(engId, gate1!.id, { action: "resume", operatorId: "op-1" });
      const gate2 = createPauseGate(engId, {
        phase: "port_scan", nextPhase: "vuln_scan",
        reason: "between_scan_types", title: "Gate 2", description: "Second",
      });
      const pending = hasPendingPauseGate(engId);
      expect(pending!.id).toBe(gate2!.id);
    });
  });
});
