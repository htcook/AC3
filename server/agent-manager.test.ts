import { describe, expect, it, beforeEach } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

// ─── Test Context Factory ─────────────────────────────────────────────────

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createTestContext(overrides?: Partial<AuthenticatedUser>): TrpcContext {
  const user: AuthenticatedUser = {
    id: 1,
    openId: "test-operator",
    email: "operator@acec3.test",
    name: "Test Operator",
    loginMethod: "manus",
    role: "admin",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
    ...overrides,
  };

  return {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };
}

function createPublicContext(): TrpcContext {
  return {
    user: null,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: () => {},
    } as TrpcContext["res"],
  };
}

describe("agentManager router", () => {
  // ─── FIPS Compliance ──────────────────────────────────────────────────

  describe("fipsStatus", () => {
    it("returns a FIPS compliance report for authenticated users", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const report = await caller.agentManager.fipsStatus();

      expect(report).toHaveProperty("fipsProviderActive");
      expect(report).toHaveProperty("opensslVersion");
      expect(report).toHaveProperty("nodeVersion");
      expect(report).toHaveProperty("approvedAlgorithms");
      expect(report).toHaveProperty("prohibitedAlgorithms");
      expect(report).toHaveProperty("tlsCiphers");
      expect(report).toHaveProperty("complianceLevel");
      expect(["full", "partial", "software-only"]).toContain(report.complianceLevel);
    });

    it("rejects unauthenticated access", async () => {
      const ctx = createPublicContext();
      const caller = appRouter.createCaller(ctx);

      await expect(caller.agentManager.fipsStatus()).rejects.toThrow();
    });
  });

  describe("fipsAudit", () => {
    it("runs a full FIPS audit and returns check results", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.agentManager.fipsAudit();

      expect(result).toHaveProperty("checks");
      expect(result).toHaveProperty("overallStatus");
      expect(Array.isArray(result.checks)).toBe(true);
      expect(result.checks.length).toBeGreaterThanOrEqual(4); // provider, aes, ecdsa, hmac, pbkdf2, full_audit

      // Verify check structure
      for (const check of result.checks) {
        expect(check).toHaveProperty("checkType");
        expect(check).toHaveProperty("status");
        expect(check).toHaveProperty("component");
        expect(check).toHaveProperty("details");
        expect(["compliant", "non_compliant", "warning"]).toContain(check.status);
      }

      // AES-256-GCM should be compliant
      const aesCheck = result.checks.find((c) => c.component === "aes-256-gcm");
      expect(aesCheck).toBeTruthy();
      expect(aesCheck?.status).toBe("compliant");

      // ECDSA P-256 should be compliant
      const ecdsaCheck = result.checks.find((c) => c.component === "ecdsa-p256");
      expect(ecdsaCheck).toBeTruthy();
      expect(ecdsaCheck?.status).toBe("compliant");

      // HMAC-SHA256 should be compliant
      const hmacCheck = result.checks.find((c) => c.component === "hmac-sha256");
      expect(hmacCheck).toBeTruthy();
      expect(hmacCheck?.status).toBe("compliant");
    });
  });

  describe("fipsHistory", () => {
    it("returns compliance history records", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const history = await caller.agentManager.fipsHistory({ limit: 10 });
      expect(Array.isArray(history)).toBe(true);
    });
  });

  // ─── C2 Servers ───────────────────────────────────────────────────────

  describe("C2 server management", () => {
    it("adds a new C2 server", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.agentManager.addC2Server({
        name: "Test CALDERA",
        type: "caldera",
        baseUrl: "https://caldera.test:8443",
        authConfig: { apiKey: "test-key-123" },
      });

      expect(result).toHaveProperty("id");
      expect(result.name).toBe("Test CALDERA");
      expect(result.type).toBe("caldera");
    });

    it("lists C2 servers", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const servers = await caller.agentManager.listC2Servers();
      expect(Array.isArray(servers)).toBe(true);
    });

    it("tests C2 server connectivity", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      // First add a server
      const server = await caller.agentManager.addC2Server({
        name: "Connectivity Test",
        type: "sliver",
        baseUrl: "https://sliver.test:31337",
        authConfig: { token: "test-token" },
      });

      // Test connection
      const result = await caller.agentManager.testC2Connection({ id: server.id });
      expect(result).toHaveProperty("status");
      expect(result).toHaveProperty("latencyMs");
      expect(result).toHaveProperty("message");
    });

    it("removes a C2 server", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const server = await caller.agentManager.addC2Server({
        name: "To Remove",
        type: "metasploit",
        baseUrl: "https://msf.test:4444",
        authConfig: { apiKey: "test" },
      });

      const result = await caller.agentManager.removeC2Server({ id: server.id });
      expect(result.success).toBe(true);
    });

    it("throws NOT_FOUND for non-existent C2 server test", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      await expect(
        caller.agentManager.testC2Connection({ id: "non-existent-id" })
      ).rejects.toThrow();
    });
  });

  // ─── Agent Deployments ────────────────────────────────────────────────

  describe("Agent deployment lifecycle", () => {
    it("requests a new agent deployment", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.agentManager.requestDeployment({
        name: "test-agent-01",
        description: "Test agent for vitest",
        targetPlatform: "linux",
        c2Protocol: "caldera",
        ttlSeconds: 3600,
        beaconIntervalSeconds: 30,
        targetHostname: "target.test",
        targetIp: "10.0.1.50",
      });

      expect(result).toHaveProperty("id");
      expect(result).toHaveProperty("registrationToken");
      expect(result).toHaveProperty("publicKey");
      expect(result.id).toMatch(/^[0-9a-f-]+$/);
      expect(result.registrationToken).toHaveLength(64); // 32 bytes hex
      expect(result.publicKey).toContain("BEGIN PUBLIC KEY");
    });

    it("lists agents with default parameters", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.agentManager.listAgents({
        limit: 50,
        offset: 0,
      });

      expect(result).toHaveProperty("agents");
      expect(result).toHaveProperty("total");
      expect(Array.isArray(result.agents)).toBe(true);
    });

    it("filters agents by status", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const result = await caller.agentManager.listAgents({
        status: "pending_approval",
        limit: 50,
        offset: 0,
      });

      expect(result).toHaveProperty("agents");
      for (const agent of result.agents) {
        expect(agent.status).toBe("pending_approval");
      }
    });

    it("gets agent details by ID", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      // Create an agent first
      const deployed = await caller.agentManager.requestDeployment({
        name: "detail-test-agent",
        targetPlatform: "windows",
        c2Protocol: "native",
      });

      const agent = await caller.agentManager.getAgent({ id: deployed.id });
      expect(agent.id).toBe(deployed.id);
      expect(agent.name).toBe("detail-test-agent");
      expect(agent.targetPlatform).toBe("windows");
      expect(agent.c2Protocol).toBe("native");
      expect(agent.status).toBe("pending_approval");
    });

    it("approves a pending deployment", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const deployed = await caller.agentManager.requestDeployment({
        name: "approve-test-agent",
        targetPlatform: "linux",
        c2Protocol: "caldera",
      });

      const result = await caller.agentManager.approveDeployment({ id: deployed.id });
      expect(result.success).toBe(true);

      const agent = await caller.agentManager.getAgent({ id: deployed.id });
      expect(agent.status).toBe("approved");
      expect(agent.approvedBy).toBe(1);
      expect(agent.approvedAt).toBeTruthy();
    });

    it("rejects a pending deployment", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const deployed = await caller.agentManager.requestDeployment({
        name: "reject-test-agent",
        targetPlatform: "linux",
        c2Protocol: "sliver",
      });

      const result = await caller.agentManager.rejectDeployment({
        id: deployed.id,
        reason: "Not authorized for this network segment",
      });
      expect(result.success).toBe(true);

      const agent = await caller.agentManager.getAgent({ id: deployed.id });
      expect(agent.status).toBe("failed");
      expect(agent.rejectionReason).toBe("Not authorized for this network segment");
    });

    it("cannot approve a non-pending agent", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const deployed = await caller.agentManager.requestDeployment({
        name: "double-approve-test",
        targetPlatform: "linux",
        c2Protocol: "caldera",
      });

      // Approve once
      await caller.agentManager.approveDeployment({ id: deployed.id });

      // Try to approve again
      await expect(
        caller.agentManager.approveDeployment({ id: deployed.id })
      ).rejects.toThrow("Cannot approve agent in approved state");
    });

    it("pauses an active agent", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const deployed = await caller.agentManager.requestDeployment({
        name: "pause-test-agent",
        targetPlatform: "linux",
        c2Protocol: "native",
      });

      // Approve first, then manually set to active via pause/resume test
      await caller.agentManager.approveDeployment({ id: deployed.id });

      // Pause (works from any non-terminal state in our implementation)
      const result = await caller.agentManager.pauseAgent({ id: deployed.id });
      expect(result.success).toBe(true);

      const agent = await caller.agentManager.getAgent({ id: deployed.id });
      expect(agent.status).toBe("paused");
    });

    it("resumes a paused agent", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const deployed = await caller.agentManager.requestDeployment({
        name: "resume-test-agent",
        targetPlatform: "darwin",
        c2Protocol: "native",
      });

      await caller.agentManager.approveDeployment({ id: deployed.id });
      await caller.agentManager.pauseAgent({ id: deployed.id });

      const result = await caller.agentManager.resumeAgent({ id: deployed.id });
      expect(result.success).toBe(true);

      const agent = await caller.agentManager.getAgent({ id: deployed.id });
      expect(agent.status).toBe("active");
    });

    it("terminates an agent", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const deployed = await caller.agentManager.requestDeployment({
        name: "terminate-test-agent",
        targetPlatform: "linux",
        c2Protocol: "caldera",
      });

      const result = await caller.agentManager.terminateAgent({
        id: deployed.id,
        reason: "Engagement complete",
      });
      expect(result.success).toBe(true);

      const agent = await caller.agentManager.getAgent({ id: deployed.id });
      expect(agent.status).toBe("terminated");
      expect(agent.terminatedAt).toBeTruthy();
    });

    it("throws NOT_FOUND for non-existent agent", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      await expect(
        caller.agentManager.getAgent({ id: "non-existent-agent-id" })
      ).rejects.toThrow();
    });
  });

  // ─── Agent Tasks ──────────────────────────────────────────────────────

  describe("Agent task management", () => {
    it("assigns a task to an agent", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const deployed = await caller.agentManager.requestDeployment({
        name: "task-test-agent",
        targetPlatform: "linux",
        c2Protocol: "caldera",
      });

      const result = await caller.agentManager.assignTask({
        agentId: deployed.id,
        techniqueId: "T1059.004",
        techniqueName: "Unix Shell",
        command: "whoami && id",
        executor: "sh",
        timeoutSeconds: 60,
      });

      expect(result).toHaveProperty("id");
      expect(result.id).toMatch(/^[0-9a-f-]+$/);
    });

    it("lists tasks for an agent", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const deployed = await caller.agentManager.requestDeployment({
        name: "task-list-agent",
        targetPlatform: "linux",
        c2Protocol: "native",
      });

      // Assign a couple tasks
      await caller.agentManager.assignTask({
        agentId: deployed.id,
        command: "ls -la",
        executor: "sh",
      });
      await caller.agentManager.assignTask({
        agentId: deployed.id,
        command: "cat /etc/passwd",
        executor: "sh",
      });

      const tasks = await caller.agentManager.listTasks({
        agentId: deployed.id,
        limit: 50,
      });

      expect(Array.isArray(tasks)).toBe(true);
      expect(tasks.length).toBeGreaterThanOrEqual(2);
    });

    it("cancels a queued task", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const deployed = await caller.agentManager.requestDeployment({
        name: "cancel-task-agent",
        targetPlatform: "linux",
        c2Protocol: "native",
      });

      const task = await caller.agentManager.assignTask({
        agentId: deployed.id,
        command: "sleep 999",
        executor: "sh",
      });

      const result = await caller.agentManager.cancelTask({ taskId: task.id });
      expect(result.success).toBe(true);
    });

    it("cannot cancel a non-queued task", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const deployed = await caller.agentManager.requestDeployment({
        name: "double-cancel-agent",
        targetPlatform: "linux",
        c2Protocol: "native",
      });

      const task = await caller.agentManager.assignTask({
        agentId: deployed.id,
        command: "echo test",
        executor: "sh",
      });

      // Cancel once
      await caller.agentManager.cancelTask({ taskId: task.id });

      // Try to cancel again
      await expect(
        caller.agentManager.cancelTask({ taskId: task.id })
      ).rejects.toThrow("Can only cancel queued tasks");
    });
  });

  // ─── Audit Log ────────────────────────────────────────────────────────

  describe("Audit log", () => {
    it("retrieves audit log entries", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      // Create an agent to generate audit entries
      const deployed = await caller.agentManager.requestDeployment({
        name: "audit-test-agent",
        targetPlatform: "linux",
        c2Protocol: "caldera",
      });

      const log = await caller.agentManager.getAuditLog({
        agentId: deployed.id,
        limit: 100,
      });

      expect(Array.isArray(log)).toBe(true);
      expect(log.length).toBeGreaterThanOrEqual(1); // At least the register event

      // Verify audit entry structure
      const entry = log[0];
      expect(entry).toHaveProperty("agentId");
      expect(entry).toHaveProperty("eventType");
      expect(entry).toHaveProperty("actorType");
      expect(entry).toHaveProperty("recordHash");
      expect(entry).toHaveProperty("previousHash");
    });

    it("verifies audit chain integrity", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const deployed = await caller.agentManager.requestDeployment({
        name: "chain-test-agent",
        targetPlatform: "linux",
        c2Protocol: "native",
      });

      // Generate multiple audit events
      await caller.agentManager.approveDeployment({ id: deployed.id });
      await caller.agentManager.pauseAgent({ id: deployed.id });
      await caller.agentManager.resumeAgent({ id: deployed.id });

      const result = await caller.agentManager.verifyAuditChain({ agentId: deployed.id });
      expect(result.valid).toBe(true);
      expect(result.totalEntries).toBeGreaterThanOrEqual(4); // register, approved, paused, resumed
      expect(result.brokenAt).toBeNull();
    });
  });

  // ─── Dashboard Stats ──────────────────────────────────────────────────

  describe("dashboardStats", () => {
    it("returns dashboard statistics", async () => {
      const ctx = createTestContext();
      const caller = appRouter.createCaller(ctx);

      const stats = await caller.agentManager.dashboardStats();

      expect(stats).toHaveProperty("agents");
      expect(stats).toHaveProperty("c2Servers");
      expect(stats).toHaveProperty("tasks");
      expect(stats).toHaveProperty("fips");

      expect(stats.agents).toHaveProperty("total");
      expect(stats.agents).toHaveProperty("active");
      expect(stats.agents).toHaveProperty("pending");
      expect(stats.c2Servers).toHaveProperty("total");
      expect(stats.c2Servers).toHaveProperty("connected");
      expect(stats.tasks).toHaveProperty("total");
      expect(stats.tasks).toHaveProperty("queued");
      expect(stats.fips).toHaveProperty("providerActive");
      expect(stats.fips).toHaveProperty("complianceLevel");
    });
  });
});
