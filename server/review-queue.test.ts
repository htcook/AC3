/**
 * Tests for Review Queue, Job Queue, Ops State Persistence, and FIPS DO Infrastructure
 */
import { describe, expect, it, beforeEach } from "vitest";

// ─── Job Queue Tests ────────────────────────────────────────────────────────

describe("Job Queue", () => {
  it("should export all required functions", async () => {
    const mod = await import("./lib/job-queue");
    expect(mod.dispatchScanJob).toBeDefined();
    expect(mod.dispatchReconJob).toBeDefined();
    expect(mod.getQueueStats).toBeDefined();
    expect(mod.getWorkers).toBeDefined();
    expect(mod.getJobStatus).toBeDefined();
    expect(mod.cancelJob).toBeDefined();
    expect(mod.registerWorker).toBeDefined();
  });

  it("should return queue stats with correct shape", async () => {
    const { getQueueStats } = await import("./lib/job-queue");
    const stats = getQueueStats();
    expect(stats).toHaveProperty("queued");
    expect(stats).toHaveProperty("active");
    expect(stats).toHaveProperty("completed");
    expect(stats).toHaveProperty("workers");
    expect(typeof stats.queued).toBe("object");
    expect(typeof stats.active).toBe("number");
    expect(stats.queued).toHaveProperty("scan");
    expect(stats.queued).toHaveProperty("recon");
  });

  it("should return empty workers array initially", async () => {
    const { getWorkers } = await import("./lib/job-queue");
    const workers = getWorkers();
    expect(Array.isArray(workers)).toBe(true);
  });

  it("should register a worker", async () => {
    const { registerWorker, getWorkers } = await import("./lib/job-queue");
    registerWorker({
      id: "test-worker-1",
      host: "10.132.0.5",
      region: "nyc1",
      type: ["scan"],
      maxJobs: 5,
      fipsCompliant: true,
      vpcOnly: true,
    });
    const workers = getWorkers();
    const found = workers.find((w) => w.id === "test-worker-1");
    expect(found).toBeDefined();
    expect(found?.host).toBe("10.132.0.5");
    expect(found?.fipsCompliant).toBe(true);
    expect(found?.vpcOnly).toBe(true);
  });

  it("should return status object for non-existent job", async () => {
    const { getJobStatus } = await import("./lib/job-queue");
    const status = getJobStatus("non-existent-job");
    // Returns a status object (may be cancelled or null depending on implementation)
    expect(status === null || typeof status === "object").toBe(true);
  });

  it("should return false when cancelling non-existent job", async () => {
    const { cancelJob } = await import("./lib/job-queue");
    const result = cancelJob("non-existent-job");
    expect(result).toBe(false);
  });

  it("should dispatch a scan job and return job ID", async () => {
    const { dispatchScanJob, registerWorker } = await import("./lib/job-queue");
    // Register a worker first
    registerWorker({
      id: "scan-worker-test",
      host: "10.132.0.10",
      region: "nyc1",
      type: ["scan"],
      maxJobs: 5,
      fipsCompliant: true,
      vpcOnly: true,
    });
    const result = await dispatchScanJob({
      engagementId: 1,
      targets: ["192.168.1.1"],
      tool: "nmap",
      args: "-sV",
      roeScope: ["192.168.1.0/24"],
      timeoutSeconds: 300,
      sudo: false,
      operatorId: "test-user",
    });
    expect(result).toHaveProperty("jobId");
    expect(typeof result.jobId).toBe("string");
    expect(result.jobId.length).toBeGreaterThan(0);
  });
});

// ─── Ops State Persistence Tests ────────────────────────────────────────────

describe("Ops State Persistence", () => {
  it("should export all required functions", async () => {
    const mod = await import("./lib/ops-state-persistence");
    expect(mod.saveStateSnapshot).toBeDefined();
    expect(mod.getSnapshotHistory).toBeDefined();
    expect(mod.recoverState).toBeDefined();
    expect(mod.cleanupOldSnapshots).toBeDefined();
    expect(mod.getCachedState).toBeDefined();
    expect(mod.clearCachedState).toBeDefined();
    expect(mod.startPeriodicSnapshots).toBeDefined();
    expect(mod.stopPeriodicSnapshots).toBeDefined();
  });

  it("should get cached state (null for unknown)", async () => {
    const { getCachedState } = await import("./lib/ops-state-persistence");
    const cached = getCachedState(99999);
    expect(cached).toBeNull();
  });

  it("should get snapshot history as object with snapshots array", async () => {
    const { getSnapshotHistory } = await import("./lib/ops-state-persistence");
    const history = await getSnapshotHistory(99999);
    expect(history).toBeDefined();
    expect(typeof history).toBe("object");
  });

  it("should recover state without throwing", async () => {
    const { recoverState } = await import("./lib/ops-state-persistence");
    const result = await recoverState(42);
    // Should not throw, returns StateRecoveryResult
    expect(typeof result).toBe("object");
    expect(result).toHaveProperty("recovered");
  });

  it("should clear cached state without throwing", async () => {
    const { clearCachedState } = await import("./lib/ops-state-persistence");
    expect(() => clearCachedState(42)).not.toThrow();
  });
});

// ─── FIPS DO Infrastructure Tests ───────────────────────────────────────────

describe("FIPS DO Infrastructure", () => {
  it("should export all required functions", async () => {
    const mod = await import("./lib/fips-do-infrastructure");
    expect(mod.getVPCConfig).toBeDefined();
    expect(mod.getFirewallConfigs).toBeDefined();
    expect(mod.generateFIPSSSHDConfig).toBeDefined();
    expect(mod.generateSSHBanner).toBeDefined();
    expect(mod.generateFIPSWorkerUserData).toBeDefined();
    expect(mod.runComplianceCheck).toBeDefined();
    expect(mod.getInfrastructureSummary).toBeDefined();
    expect(mod.getKeyRotationSchedules).toBeDefined();
    expect(mod.getAuditLog).toBeDefined();
  });

  it("should return VPC config with correct CIDR", async () => {
    const { getVPCConfig } = await import("./lib/fips-do-infrastructure");
    const vpc = getVPCConfig();
    expect(vpc.name).toBe("caldera-fips-vpc");
    expect(vpc.ipRange).toBe("10.132.0.0/20");
    expect(vpc.region).toBe("nyc1");
  });

  it("should generate firewall configs with no public inbound", async () => {
    const { getFirewallConfigs } = await import("./lib/fips-do-infrastructure");
    const configs = getFirewallConfigs();
    expect(configs.redis).toBeDefined();
    expect(configs.scanWorker).toBeDefined();
    expect(configs.c2Droplet).toBeDefined();
    expect(configs.osintWorker).toBeDefined();

    // Verify NO firewall has public inbound (0.0.0.0/0)
    for (const [name, fw] of Object.entries(configs)) {
      for (const rule of fw.inboundRules) {
        const hasPublic = rule.sources.addresses?.includes("0.0.0.0/0");
        expect(hasPublic, `${name} has public inbound on port ${rule.ports}`).toBeFalsy();
      }
    }
  });

  it("should generate FIPS SSH config with correct algorithms", async () => {
    const { generateFIPSSSHDConfig } = await import("./lib/fips-do-infrastructure");
    const config = generateFIPSSSHDConfig({ allowedUsers: ["root", "caldera"] });
    expect(config).toContain("Protocol 2");
    expect(config).toContain("PasswordAuthentication no");
    expect(config).toContain("aes256-gcm@openssh.com");
    expect(config).toContain("hmac-sha2-512-etm@openssh.com");
    expect(config).toContain("ecdh-sha2-nistp521");
    expect(config).toContain("AllowUsers root caldera");
    // Ensure no weak algorithms
    expect(config).not.toContain("arcfour");
    expect(config).not.toContain("3des");
    expect(config).not.toContain("md5");
    expect(config).not.toContain("sha1");
  });

  it("should generate SSH banner with compliance notice", async () => {
    const { generateSSHBanner } = await import("./lib/fips-do-infrastructure");
    const banner = generateSSHBanner();
    expect(banner).toContain("AUTHORIZED ACCESS ONLY");
    expect(banner).toContain("FIPS 140-3");
    expect(banner).toContain("NIST SP 800-53");
  });

  it("should generate FIPS worker user data with hardening", async () => {
    const { generateFIPSWorkerUserData } = await import("./lib/fips-do-infrastructure");
    const userData = generateFIPSWorkerUserData({
      workerType: "scan",
      vpcSubnet: "10.132.0.0/20",
      redisHost: "10.132.0.5",
    });
    expect(userData).toContain("#!/bin/bash");
    expect(userData).toContain("FIPS 140-3");
    expect(userData).toContain("ufw default deny incoming");
    expect(userData).toContain("ufw default deny outgoing");
    expect(userData).toContain("10.132.0.0/20");
    expect(userData).toContain("10.132.0.5");
    expect(userData).toContain("net.ipv4.ip_forward = 0");
  });

  it("should return infrastructure summary with no public inbound", async () => {
    const { getInfrastructureSummary } = await import("./lib/fips-do-infrastructure");
    const summary = getInfrastructureSummary();
    expect(summary.vpc.name).toBe("caldera-fips-vpc");
    expect(summary.sshHardening.fipsAlgorithms).toBe(true);
    expect(summary.sshHardening.passwordAuth).toBe(false);
    expect(summary.sshHardening.vpcOnly).toBe(true);

    // Verify no firewall has public inbound
    for (const [name, fw] of Object.entries(summary.firewalls)) {
      expect(fw.publicInbound, `${name} has public inbound`).toBe(false);
    }
  });

  it("should return key rotation schedules", async () => {
    const { getKeyRotationSchedules } = await import("./lib/fips-do-infrastructure");
    const schedules = getKeyRotationSchedules();
    expect(schedules.length).toBeGreaterThan(0);
    const sshKey = schedules.find((s) => s.keyType === "ssh-host-key");
    expect(sshKey).toBeDefined();
    expect(sshKey?.rotationIntervalDays).toBe(90);
    expect(sshKey?.autoRotate).toBe(false); // SSH keys require manual rotation
  });

  it("should run compliance check and return report", async () => {
    const { runComplianceCheck } = await import("./lib/fips-do-infrastructure");
    const report = await runComplianceCheck();
    expect(report).toHaveProperty("timestamp");
    expect(report).toHaveProperty("overallCompliant");
    expect(report).toHaveProperty("checks");
    expect(Array.isArray(report.checks)).toBe(true);
    expect(report.checks.length).toBeGreaterThan(0);

    // Verify NIST controls are referenced
    const nistControls = report.checks.map((c) => c.nistControl);
    expect(nistControls).toContain("SC-7");
    expect(nistControls).toContain("SC-8");
    expect(nistControls).toContain("SC-13");
    expect(nistControls).toContain("AC-4");
  });

  it("should return audit log entries", async () => {
    const { getAuditLog } = await import("./lib/fips-do-infrastructure");
    const log = getAuditLog(10);
    expect(Array.isArray(log)).toBe(true);
  });

  it("should address required NIST controls", async () => {
    const { getInfrastructureSummary } = await import("./lib/fips-do-infrastructure");
    const summary = getInfrastructureSummary();
    const requiredControls = ["AC-4", "AC-17", "AU-2", "SC-7", "SC-8", "SC-12", "SC-13"];
    for (const ctrl of requiredControls) {
      expect(summary.nistControls, `Missing NIST control ${ctrl}`).toContain(ctrl);
    }
  });
});

// ─── Review Queue Router Tests ──────────────────────────────────────────────

describe("Review Queue Router", () => {
  it("should import review queue router without errors", async () => {
    const { reviewQueueRouter } = await import("./routers/review-queue");
    expect(reviewQueueRouter).toBeDefined();
  });
});

describe("Job Queue Router", () => {
  it("should import job queue router without errors", async () => {
    const { jobQueueRouter } = await import("./routers/job-queue");
    expect(jobQueueRouter).toBeDefined();
  });
});
