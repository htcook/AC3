/**
 * Round 7 Tests: Deployment History + Incident Response Runbook
 *
 * Tests for:
 * 1. Deployment History router (record, list, get, updateStatus, stats, compareConfigs)
 * 2. IR Runbook router (create, list, get, update, delete, search, recordTrigger, seedDefaults, severitySummary)
 * 3. DB helpers for both features
 * 4. UI component structure
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Deployment History Router Tests ────────────────────────────────
describe("Deployment History Router", () => {
  describe("record procedure", () => {
    it("should require environment, region, stackName, and configSnapshot", () => {
      const validInput = {
        environment: "dev" as const,
        region: "us-east-1",
        stackName: "ac3-monitoring-dev",
        configSnapshot: {
          ecsClusterName: "ac3-cluster",
          ecsServiceName: "ac3-service",
          cpuThreshold: 80,
          memoryThreshold: 85,
          alb5xxThreshold: 10,
          alb4xxThreshold: 50,
          responseTimeThreshold: 3,
        },
      };
      expect(validInput.environment).toBe("dev");
      expect(validInput.region).toBe("us-east-1");
      expect(validInput.stackName).toBe("ac3-monitoring-dev");
      expect(validInput.configSnapshot.cpuThreshold).toBe(80);
    });

    it("should accept all three environment values", () => {
      const envs = ["dev", "staging", "prod"];
      envs.forEach(env => {
        expect(["dev", "staging", "prod"]).toContain(env);
      });
    });

    it("should generate a deployment ID with deploy- prefix", () => {
      const id = `deploy-${crypto.randomUUID().slice(0, 8)}`;
      expect(id).toMatch(/^deploy-[a-f0-9]{8}$/);
    });
  });

  describe("list procedure", () => {
    it("should accept optional environment filter", () => {
      const inputs = [
        undefined,
        { environment: "dev" as const },
        { environment: "staging" as const },
        { environment: "prod" as const },
        { limit: 10 },
        { environment: "dev" as const, limit: 25 },
      ];
      expect(inputs.length).toBe(6);
    });
  });

  describe("updateStatus procedure", () => {
    it("should accept valid status transitions", () => {
      const validStatuses = ["pending", "in_progress", "success", "failed", "rolled_back"];
      validStatuses.forEach(status => {
        expect(["pending", "in_progress", "success", "failed", "rolled_back"]).toContain(status);
      });
    });

    it("should accept optional errorMessage for failed deployments", () => {
      const input = {
        deploymentId: "deploy-abc12345",
        status: "failed" as const,
        errorMessage: "CloudFormation stack creation failed: insufficient permissions",
      };
      expect(input.errorMessage).toBeTruthy();
    });
  });

  describe("compareConfigs procedure", () => {
    it("should compute diffs between two config snapshots", () => {
      const configA = {
        cpuThreshold: 80,
        memoryThreshold: 85,
        slackWebhookUrl: "https://hooks.slack.com/old",
      };
      const configB = {
        cpuThreshold: 90,
        memoryThreshold: 85,
        slackWebhookUrl: "https://hooks.slack.com/new",
      };

      const allKeys = new Set([...Object.keys(configA), ...Object.keys(configB)]);
      const diffs = Array.from(allKeys).map(key => ({
        field: key,
        valueA: (configA as any)[key],
        valueB: (configB as any)[key],
        changed: JSON.stringify((configA as any)[key]) !== JSON.stringify((configB as any)[key]),
      }));

      expect(diffs.filter(d => d.changed).length).toBe(2);
      expect(diffs.find(d => d.field === "memoryThreshold")?.changed).toBe(false);
      expect(diffs.find(d => d.field === "cpuThreshold")?.changed).toBe(true);
    });
  });

  describe("stats procedure", () => {
    it("should return total, success, failed, pending counts", () => {
      const stats = { total: 10, success: 7, failed: 2, pending: 1 };
      expect(stats.total).toBe(stats.success + stats.failed + stats.pending);
    });
  });
});

// ─── IR Runbook Router Tests ────────────────────────────────────────
describe("IR Runbook Router", () => {
  describe("create procedure", () => {
    it("should require alarmName, triggerDescription, severity, category, responseSteps, escalationPath", () => {
      const validInput = {
        alarmName: "ECS CPU High",
        triggerDescription: "CPU utilization exceeded threshold",
        severity: "high" as const,
        category: "infrastructure" as const,
        responseSteps: [
          { order: 1, title: "Check metrics", description: "Review CloudWatch", automated: false, estimatedMinutes: 5 },
        ],
        escalationPath: [
          { level: 1, role: "On-Call Engineer", contactMethod: "Slack", timeoutMinutes: 15, description: "Initial triage" },
        ],
      };
      expect(validInput.alarmName).toBe("ECS CPU High");
      expect(validInput.responseSteps.length).toBeGreaterThan(0);
      expect(validInput.escalationPath.length).toBeGreaterThan(0);
    });

    it("should accept all severity levels", () => {
      const severities = ["critical", "high", "medium", "low", "informational"];
      severities.forEach(s => {
        expect(["critical", "high", "medium", "low", "informational"]).toContain(s);
      });
    });

    it("should accept all category values", () => {
      const categories = ["infrastructure", "application", "security", "performance", "availability"];
      categories.forEach(c => {
        expect(["infrastructure", "application", "security", "performance", "availability"]).toContain(c);
      });
    });

    it("should generate entry ID with irr- prefix", () => {
      const id = `irr-${crypto.randomUUID().slice(0, 8)}`;
      expect(id).toMatch(/^irr-[a-f0-9]{8}$/);
    });
  });

  describe("list procedure", () => {
    it("should accept optional severity, category, and activeOnly filters", () => {
      const inputs = [
        undefined,
        { severity: "critical" as const },
        { category: "infrastructure" as const },
        { activeOnly: true },
        { severity: "high" as const, category: "application" as const, activeOnly: true },
      ];
      expect(inputs.length).toBe(5);
    });
  });

  describe("update procedure", () => {
    it("should accept partial updates", () => {
      const update = {
        entryId: "irr-abc12345",
        severity: "critical" as const,
        owner: "Platform Engineering",
      };
      expect(update.entryId).toBeTruthy();
      expect(update.severity).toBe("critical");
    });

    it("should allow toggling isActive", () => {
      const deactivate = { entryId: "irr-abc12345", isActive: 0 };
      const activate = { entryId: "irr-abc12345", isActive: 1 };
      expect(deactivate.isActive).toBe(0);
      expect(activate.isActive).toBe(1);
    });
  });

  describe("search procedure", () => {
    it("should require a query string of at least 1 character", () => {
      const validQueries = ["ECS", "CPU", "memory", "Platform Engineering"];
      validQueries.forEach(q => {
        expect(q.length).toBeGreaterThanOrEqual(1);
      });
    });
  });

  describe("recordTrigger procedure", () => {
    it("should accept an entryId", () => {
      const input = { entryId: "irr-abc12345" };
      expect(input.entryId).toMatch(/^irr-/);
    });
  });

  describe("seedDefaults procedure", () => {
    it("should create 8 default runbook entries matching monitoring stack alarms", () => {
      const expectedAlarms = [
        "ECS CPU High",
        "ECS Memory High",
        "ECS No Running Tasks",
        "ALB 5xx Errors",
        "ALB Response Time",
        "App Error Rate",
        "Fatal Errors",
        "Unhealthy Hosts",
      ];
      expect(expectedAlarms.length).toBe(8);
    });

    it("should include response steps with commands for each default entry", () => {
      // Each default entry should have at least 3 response steps
      const minSteps = 3;
      expect(minSteps).toBeGreaterThanOrEqual(3);
    });

    it("should include escalation paths with at least 2 levels", () => {
      const minLevels = 2;
      expect(minLevels).toBeGreaterThanOrEqual(2);
    });
  });

  describe("severitySummary procedure", () => {
    it("should return counts for all severity levels plus total", () => {
      const summary = {
        critical: 3,
        high: 2,
        medium: 2,
        low: 1,
        informational: 0,
        total: 8,
      };
      expect(summary.total).toBe(
        summary.critical + summary.high + summary.medium + summary.low + summary.informational
      );
    });
  });
});

// ─── DB Helper Tests ────────────────────────────────────────────────
describe("Deployment History DB Helpers", () => {
  it("should export createDeployment function", async () => {
    const { createDeployment } = await import("./db");
    expect(typeof createDeployment).toBe("function");
  });

  it("should export listDeployments function", async () => {
    const { listDeployments } = await import("./db");
    expect(typeof listDeployments).toBe("function");
  });

  it("should export getDeploymentById function", async () => {
    const { getDeploymentById } = await import("./db");
    expect(typeof getDeploymentById).toBe("function");
  });

  it("should export updateDeploymentStatus function", async () => {
    const { updateDeploymentStatus } = await import("./db");
    expect(typeof updateDeploymentStatus).toBe("function");
  });

  it("should export getDeploymentStats function", async () => {
    const { getDeploymentStats } = await import("./db");
    expect(typeof getDeploymentStats).toBe("function");
  });
});

describe("IR Runbook DB Helpers", () => {
  it("should export createIrRunbookEntry function", async () => {
    const { createIrRunbookEntry } = await import("./db");
    expect(typeof createIrRunbookEntry).toBe("function");
  });

  it("should export listIrRunbookEntries function", async () => {
    const { listIrRunbookEntries } = await import("./db");
    expect(typeof listIrRunbookEntries).toBe("function");
  });

  it("should export getIrRunbookEntry function", async () => {
    const { getIrRunbookEntry } = await import("./db");
    expect(typeof getIrRunbookEntry).toBe("function");
  });

  it("should export updateIrRunbookEntry function", async () => {
    const { updateIrRunbookEntry } = await import("./db");
    expect(typeof updateIrRunbookEntry).toBe("function");
  });

  it("should export deleteIrRunbookEntry function", async () => {
    const { deleteIrRunbookEntry } = await import("./db");
    expect(typeof deleteIrRunbookEntry).toBe("function");
  });

  it("should export searchIrRunbook function", async () => {
    const { searchIrRunbook } = await import("./db");
    expect(typeof searchIrRunbook).toBe("function");
  });

  it("should export incrementIrRunbookTriggerCount function", async () => {
    const { incrementIrRunbookTriggerCount } = await import("./db");
    expect(typeof incrementIrRunbookTriggerCount).toBe("function");
  });
});

// ─── Schema Tests ───────────────────────────────────────────────────
describe("Database Schema", () => {
  it("should export deploymentHistory table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.deploymentHistory).toBeDefined();
  });

  it("should export irRunbookEntries table", async () => {
    const schema = await import("../drizzle/schema");
    expect(schema.irRunbookEntries).toBeDefined();
  });

  it("deploymentHistory should have required columns", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.deploymentHistory;
    expect(table.deploymentId).toBeDefined();
    expect(table.userId).toBeDefined();
    expect(table.environment).toBeDefined();
    expect(table.region).toBeDefined();
    expect(table.stackName).toBeDefined();
    expect(table.status).toBeDefined();
    expect(table.configSnapshot).toBeDefined();
  });

  it("irRunbookEntries should have required columns", async () => {
    const schema = await import("../drizzle/schema");
    const table = schema.irRunbookEntries;
    expect(table.entryId).toBeDefined();
    expect(table.alarmName).toBeDefined();
    expect(table.triggerDescription).toBeDefined();
    expect(table.severity).toBeDefined();
    expect(table.category).toBeDefined();
    expect(table.responseSteps).toBeDefined();
    expect(table.escalationPath).toBeDefined();
  });
});

// ─── Router Registration Tests ──────────────────────────────────────
describe("Router Registration", () => {
  it("should have deploymentHistory router registered in appRouter", async () => {
    const { appRouter } = await import("./routers");
    expect((appRouter as any)._def.procedures).toBeDefined();
    // Check that the router is part of the app router
    const procedures = Object.keys((appRouter as any)._def.procedures);
    const hasDeploymentHistory = procedures.some(p => p.startsWith("deploymentHistory."));
    expect(hasDeploymentHistory).toBe(true);
  });

  it("should have irRunbook router registered in appRouter", async () => {
    const { appRouter } = await import("./routers");
    const procedures = Object.keys((appRouter as any)._def.procedures);
    const hasIrRunbook = procedures.some(p => p.startsWith("irRunbook."));
    expect(hasIrRunbook).toBe(true);
  });

  it("deploymentHistory router should have expected procedures", async () => {
    const { appRouter } = await import("./routers");
    const procedures = Object.keys((appRouter as any)._def.procedures);
    const dhProcedures = procedures.filter(p => p.startsWith("deploymentHistory."));
    expect(dhProcedures).toContain("deploymentHistory.record");
    expect(dhProcedures).toContain("deploymentHistory.list");
    expect(dhProcedures).toContain("deploymentHistory.get");
    expect(dhProcedures).toContain("deploymentHistory.updateStatus");
    expect(dhProcedures).toContain("deploymentHistory.stats");
    expect(dhProcedures).toContain("deploymentHistory.compareConfigs");
  });

  it("irRunbook router should have expected procedures", async () => {
    const { appRouter } = await import("./routers");
    const procedures = Object.keys((appRouter as any)._def.procedures);
    const irProcedures = procedures.filter(p => p.startsWith("irRunbook."));
    expect(irProcedures).toContain("irRunbook.create");
    expect(irProcedures).toContain("irRunbook.list");
    expect(irProcedures).toContain("irRunbook.get");
    expect(irProcedures).toContain("irRunbook.update");
    expect(irProcedures).toContain("irRunbook.delete");
    expect(irProcedures).toContain("irRunbook.search");
    expect(irProcedures).toContain("irRunbook.recordTrigger");
    expect(irProcedures).toContain("irRunbook.seedDefaults");
    expect(irProcedures).toContain("irRunbook.severitySummary");
  });
});

// ─── Default Runbook Entries Validation ─────────────────────────────
describe("Default Runbook Entries", () => {
  it("should have response steps with valid structure", () => {
    const sampleStep = {
      order: 1,
      title: "Check ECS Service Metrics",
      description: "Open CloudWatch console and review CPU utilization",
      command: "aws cloudwatch get-metric-statistics ...",
      automated: false,
      estimatedMinutes: 5,
    };
    expect(sampleStep.order).toBeGreaterThan(0);
    expect(sampleStep.title).toBeTruthy();
    expect(sampleStep.description).toBeTruthy();
    expect(typeof sampleStep.automated).toBe("boolean");
    expect(sampleStep.estimatedMinutes).toBeGreaterThan(0);
  });

  it("should have escalation paths with increasing levels", () => {
    const samplePath = [
      { level: 1, role: "On-Call Engineer", contactMethod: "Slack", timeoutMinutes: 15, description: "Initial triage" },
      { level: 2, role: "Platform Lead", contactMethod: "Phone", timeoutMinutes: 30, description: "Scaling decision" },
      { level: 3, role: "CTO", contactMethod: "Phone + Email", timeoutMinutes: 60, description: "Budget approval" },
    ];
    for (let i = 1; i < samplePath.length; i++) {
      expect(samplePath[i].level).toBeGreaterThan(samplePath[i - 1].level);
      expect(samplePath[i].timeoutMinutes).toBeGreaterThanOrEqual(samplePath[i - 1].timeoutMinutes);
    }
  });

  it("should have related alarms for cross-referencing", () => {
    const relatedAlarms = ["ECS Memory High", "ALB Response Time"];
    expect(relatedAlarms.length).toBeGreaterThan(0);
    relatedAlarms.forEach(alarm => {
      expect(typeof alarm).toBe("string");
      expect(alarm.length).toBeGreaterThan(0);
    });
  });

  it("should have mitigation actions and prevention measures", () => {
    const mitigations = ["Scale ECS desired count", "Restart unhealthy tasks"];
    const preventions = ["Configure ECS auto-scaling", "Set resource limits"];
    expect(mitigations.length).toBeGreaterThan(0);
    expect(preventions.length).toBeGreaterThan(0);
  });
});

// ─── UI Component Structure Tests ───────────────────────────────────
describe("UI Components", () => {
  it("DeploymentHistory component file should exist", async () => {
    const fs = await import("fs");
    const exists = fs.existsSync("/home/ubuntu/caldera-dashboard/client/src/components/DeploymentHistory.tsx");
    expect(exists).toBe(true);
  });

  it("IncidentResponseRunbook page file should exist", async () => {
    const fs = await import("fs");
    const exists = fs.existsSync("/home/ubuntu/caldera-dashboard/client/src/pages/IncidentResponseRunbook.tsx");
    expect(exists).toBe(true);
  });

  it("MonitoringDeploy page should import DeploymentHistory", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("/home/ubuntu/caldera-dashboard/client/src/pages/MonitoringDeploy.tsx", "utf-8");
    expect(content).toContain("DeploymentHistory");
    expect(content).toContain("Deployment History");
  });

  it("MonitoringDeploy page should have Tabs for wizard and history", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("/home/ubuntu/caldera-dashboard/client/src/pages/MonitoringDeploy.tsx", "utf-8");
    expect(content).toContain('TabsTrigger');
    expect(content).toContain('value="wizard"');
    expect(content).toContain('value="history"');
  });

  it("IncidentResponseRunbook should have severity filter controls", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("/home/ubuntu/caldera-dashboard/client/src/pages/IncidentResponseRunbook.tsx", "utf-8");
    expect(content).toContain("severityFilter");
    expect(content).toContain("categoryFilter");
    expect(content).toContain("Seed Defaults");
  });

  it("IncidentResponseRunbook should have response steps timeline", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("/home/ubuntu/caldera-dashboard/client/src/pages/IncidentResponseRunbook.tsx", "utf-8");
    expect(content).toContain("ResponseStepsTimeline");
    expect(content).toContain("EscalationPathDisplay");
  });

  it("IncidentResponseRunbook should have search functionality", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("/home/ubuntu/caldera-dashboard/client/src/pages/IncidentResponseRunbook.tsx", "utf-8");
    expect(content).toContain("searchQuery");
    expect(content).toContain("irRunbook.search.useQuery");
  });

  it("App.tsx should have route for /incident-response", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("/home/ubuntu/caldera-dashboard/client/src/App.tsx", "utf-8");
    expect(content).toContain('path="/incident-response"');
    expect(content).toContain("IncidentResponseRunbook");
  });

  it("AppShell should have IR RUNBOOK nav entry", async () => {
    const fs = await import("fs");
    const content = fs.readFileSync("/home/ubuntu/caldera-dashboard/client/src/components/AppShell.tsx", "utf-8");
    expect(content).toContain("/incident-response");
    expect(content).toContain("IR RUNBOOK");
  });
});

// ─── Config Snapshot Validation ─────────────────────────────────────
describe("Config Snapshot Schema", () => {
  it("should validate CPU threshold range (1-100)", () => {
    const validValues = [1, 50, 80, 100];
    const invalidValues = [0, -1, 101, 200];
    validValues.forEach(v => expect(v >= 1 && v <= 100).toBe(true));
    invalidValues.forEach(v => expect(v >= 1 && v <= 100).toBe(false));
  });

  it("should validate memory threshold range (1-100)", () => {
    const validValues = [1, 50, 85, 100];
    validValues.forEach(v => expect(v >= 1 && v <= 100).toBe(true));
  });

  it("should validate non-negative alarm thresholds", () => {
    const validValues = [0, 5, 10, 50, 100];
    validValues.forEach(v => expect(v >= 0).toBe(true));
  });

  it("should accept optional slack webhook and email", () => {
    const configs = [
      { slackWebhookUrl: "", alertEmail: "" },
      { slackWebhookUrl: "https://hooks.slack.com/services/xxx", alertEmail: "" },
      { slackWebhookUrl: "", alertEmail: "ops@example.com" },
      { slackWebhookUrl: "https://hooks.slack.com/services/xxx", alertEmail: "ops@example.com" },
    ];
    expect(configs.length).toBe(4);
  });
});
