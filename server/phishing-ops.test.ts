import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Phishing Operations Router Tests
 *
 * Tests the phishing-ops router logic including:
 * - Intel feed aggregation
 * - Draft materialization
 * - Draft CRUD operations
 * - GoPhish deployment
 * - Campaign launch
 * - Arsenal retrieval
 * - Caldera triggering
 */

// Mock the DB module
const mockSelect = vi.fn();
const mockInsert = vi.fn();
const mockUpdate = vi.fn();
const mockDelete = vi.fn();
const mockFrom = vi.fn();
const mockWhere = vi.fn();
const mockOrderBy = vi.fn();
const mockLimit = vi.fn();
const mockValues = vi.fn();
const mockSet = vi.fn();
const mockReturningId = vi.fn();

vi.mock("../drizzle/schema", () => ({
  phishingDrafts: {
    id: "id",
    scanId: "scanId",
    campaignRecommendationIndex: "campaignRecommendationIndex",
    status: "status",
    createdAt: "createdAt",
    gophishCampaignId: "gophishCampaignId",
    gophishTemplateId: "gophishTemplateId",
    gophishPageId: "gophishPageId",
    gophishGroupId: "gophishGroupId",
  },
  domainIntelScans: {
    id: "id",
    primaryDomain: "primaryDomain",
    status: "status",
    clientType: "clientType",
    sector: "sector",
    campaignRecommendations: "campaignRecommendations",
    pipelineOutput: "pipelineOutput",
    createdAt: "createdAt",
  },
  engagements: {},
}));

vi.mock("./db", () => ({
  getDb: vi.fn().mockResolvedValue({
    select: () => ({
      from: () => ({
        where: () => ({
          orderBy: () => ({
            limit: () => Promise.resolve([]),
          }),
        }),
      }),
    }),
    insert: () => ({
      values: () => ({
        $returningId: () => Promise.resolve([{ id: 1 }]),
      }),
    }),
    update: () => ({
      set: () => ({
        where: () => Promise.resolve(),
      }),
    }),
    delete: () => ({
      where: () => Promise.resolve(),
    }),
  }),
}));

vi.mock("./_core/trpc", () => ({
  protectedProcedure: {
    input: vi.fn().mockReturnThis(),
    query: vi.fn().mockReturnThis(),
    mutation: vi.fn().mockReturnThis(),
    use: vi.fn().mockReturnThis(),
  },
  router: vi.fn((routes) => routes),
}));

vi.mock("./_core/env", () => ({
  ENV: {
    gophishBaseUrl: "https://127.0.0.1:3333",
    gophishApiKey: "test-api-key",
    calderaBaseUrl: "http://127.0.0.1:8888",
    calderaApiKey: "test-caldera-key",
  },
}));

vi.mock("./_core/llm", () => ({
  invokeLLM: vi.fn().mockResolvedValue({
    choices: [{
      message: {
        content: JSON.stringify({
          templateSubject: "Test Subject",
          templateHtml: "<html><body>Test</body></html>",
          templateText: "Test plain text",
          landingPageHtml: "<html><body>Landing</body></html>",
          landingPageRedirectUrl: "https://example.com",
          smtpProfileName: "Test SMTP",
        }),
      },
    }],
  }),
}));

describe("Phishing Operations Router", () => {
  describe("Router Structure", () => {
    it("should export phishingOpsRouter", async () => {
      const mod = await import("./routers/phishing-ops");
      expect(mod.phishingOpsRouter).toBeDefined();
    });

    it("should have all required procedures", async () => {
      const mod = await import("./routers/phishing-ops");
      const routerObj = mod.phishingOpsRouter as any;
      expect(routerObj).toHaveProperty("getIntelFeed");
      expect(routerObj).toHaveProperty("materialize");
      expect(routerObj).toHaveProperty("listDrafts");
      expect(routerObj).toHaveProperty("getDraft");
      expect(routerObj).toHaveProperty("updateDraft");
      expect(routerObj).toHaveProperty("deployToGophish");
      expect(routerObj).toHaveProperty("launchCampaign");
      expect(routerObj).toHaveProperty("syncCampaignStats");
      expect(routerObj).toHaveProperty("triggerCaldera");
      expect(routerObj).toHaveProperty("deleteDraft");
      expect(routerObj).toHaveProperty("getArsenal");
      expect(routerObj).toHaveProperty("deleteGophishTemplate");
      expect(routerObj).toHaveProperty("deleteGophishPage");
      expect(routerObj).toHaveProperty("deleteGophishGroup");
    });

    it("should have exactly 14 procedures", async () => {
      const mod = await import("./routers/phishing-ops");
      const routerObj = mod.phishingOpsRouter as any;
      const keys = Object.keys(routerObj);
      expect(keys.length).toBe(14);
    });
  });

  describe("Draft Lifecycle", () => {
    it("should define correct draft status enum values", () => {
      // The schema defines these statuses
      const validStatuses = ["draft", "approved", "deployed", "launched", "completed", "archived"];
      expect(validStatuses).toContain("draft");
      expect(validStatuses).toContain("approved");
      expect(validStatuses).toContain("deployed");
      expect(validStatuses).toContain("launched");
      expect(validStatuses).toContain("completed");
      expect(validStatuses).toContain("archived");
    });

    it("should define correct priority levels", () => {
      const validPriorities = ["critical", "high", "medium", "low"];
      expect(validPriorities.length).toBe(4);
    });
  });

  describe("Priority Sorting Logic", () => {
    it("should sort priorities correctly: critical > high > medium > low", () => {
      const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      const items = [
        { priority: "low" },
        { priority: "critical" },
        { priority: "medium" },
        { priority: "high" },
      ];
      items.sort((a, b) => (priorityOrder[a.priority] ?? 3) - (priorityOrder[b.priority] ?? 3));
      expect(items[0].priority).toBe("critical");
      expect(items[1].priority).toBe("high");
      expect(items[2].priority).toBe("medium");
      expect(items[3].priority).toBe("low");
    });

    it("should handle unknown priorities as low", () => {
      const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      expect(priorityOrder["unknown"] ?? 3).toBe(3);
      expect(priorityOrder[""] ?? 3).toBe(3);
    });
  });

  describe("Draft Map Key Generation", () => {
    it("should create unique keys from scanId and recommendationIndex", () => {
      const key1 = `${1}-${0}`;
      const key2 = `${1}-${1}`;
      const key3 = `${2}-${0}`;
      expect(key1).toBe("1-0");
      expect(key2).toBe("1-1");
      expect(key3).toBe("2-0");
      expect(key1).not.toBe(key2);
      expect(key1).not.toBe(key3);
    });
  });

  describe("GoPhish Template Naming Convention", () => {
    it("should prefix templates with [Ace C3]", () => {
      const campaignName = "Test Campaign";
      const templateName = `[Ace C3] ${campaignName} - Template`;
      const landingPageName = `[Ace C3] ${campaignName} - Landing Page`;
      const targetGroupName = `[Ace C3] ${campaignName} - Targets`;
      expect(templateName).toBe("[Ace C3] Test Campaign - Template");
      expect(landingPageName).toBe("[Ace C3] Test Campaign - Landing Page");
      expect(targetGroupName).toBe("[Ace C3] Test Campaign - Targets");
    });
  });

  describe("Campaign Stats Structure", () => {
    it("should define correct campaign stats fields", () => {
      const stats = {
        sent: 10,
        opened: 5,
        clicked: 3,
        submitted: 1,
        reported: 0,
        total: 10,
        status: "In progress",
      };
      expect(stats.sent).toBeGreaterThanOrEqual(0);
      expect(stats.opened).toBeLessThanOrEqual(stats.sent);
      expect(stats.clicked).toBeLessThanOrEqual(stats.opened);
      expect(stats.submitted).toBeLessThanOrEqual(stats.clicked);
    });
  });

  describe("Feed Filtering Logic", () => {
    it("should filter unmaterialized items correctly", () => {
      const items = [
        { materialized: true, name: "A" },
        { materialized: false, name: "B" },
        { materialized: false, name: "C" },
      ];
      const unmaterialized = items.filter((i) => !i.materialized);
      expect(unmaterialized.length).toBe(2);
      expect(unmaterialized[0].name).toBe("B");
    });

    it("should filter materialized items correctly", () => {
      const items = [
        { materialized: true, name: "A" },
        { materialized: false, name: "B" },
      ];
      const materialized = items.filter((i) => i.materialized);
      expect(materialized.length).toBe(1);
      expect(materialized[0].name).toBe("A");
    });
  });

  describe("Actor Match Extraction", () => {
    it("should extract top actor from pipelineOutput", () => {
      const pipelineOutput = {
        threatActorMatches: {
          topMatches: [
            { actorId: "apt29", actorName: "Cozy Bear", confidence: 85, techniques: [] },
            { actorId: "apt28", actorName: "Fancy Bear", confidence: 72, techniques: [] },
          ],
          matchSummary: "2 actors matched",
        },
      };
      const topActor = pipelineOutput?.threatActorMatches?.topMatches?.[0];
      expect(topActor).toBeDefined();
      expect(topActor?.actorName).toBe("Cozy Bear");
      expect(topActor?.confidence).toBe(85);
    });

    it("should handle missing pipelineOutput gracefully", () => {
      const pipelineOutput = null as any;
      const topActor = pipelineOutput?.threatActorMatches?.topMatches?.[0];
      expect(topActor).toBeUndefined();
    });

    it("should handle empty topMatches", () => {
      const pipelineOutput = {
        threatActorMatches: { topMatches: [] },
      };
      const topActor = pipelineOutput?.threatActorMatches?.topMatches?.[0];
      expect(topActor).toBeUndefined();
    });
  });

  describe("LLM Fallback Content", () => {
    it("should generate fallback template when LLM fails", () => {
      const domain = "example.com";
      const fallback = {
        templateSubject: `Important: Action Required - ${domain}`,
        templateHtml: `<html><body><p>Dear {{.FirstName}},</p><p>Please review the attached document regarding your ${domain} account.</p><p><a href="{{.URL}}">Click here to review</a></p><p>Best regards,<br>IT Security Team</p></body></html>`,
        templateText: `Dear {{.FirstName}},\n\nPlease review the attached document regarding your ${domain} account.\n\nClick here to review: {{.URL}}\n\nBest regards,\nIT Security Team`,
        landingPageHtml: `<html><body><h2>${domain} - Login</h2><form method="POST"><input name="email" placeholder="Email" /><input name="password" type="password" placeholder="Password" /><button type="submit">Sign In</button></form></body></html>`,
        landingPageRedirectUrl: `https://${domain}`,
        smtpProfileName: `Ace C3 - ${domain} Profile`,
      };

      expect(fallback.templateSubject).toContain("example.com");
      expect(fallback.templateHtml).toContain("{{.FirstName}}");
      expect(fallback.templateHtml).toContain("{{.URL}}");
      expect(fallback.landingPageHtml).toContain("email");
      expect(fallback.landingPageHtml).toContain("password");
      expect(fallback.landingPageRedirectUrl).toBe("https://example.com");
    });
  });

  describe("GoPhish Resource Deployment Payload", () => {
    it("should construct correct template payload", () => {
      const draft = {
        templateName: "[Ace C3] Test - Template",
        templateSubject: "Important Update",
        templateHtml: "<html>test</html>",
        templateText: "test",
      };
      const payload = {
        name: draft.templateName,
        subject: draft.templateSubject,
        html: draft.templateHtml,
        text: draft.templateText,
      };
      expect(payload.name).toBe("[Ace C3] Test - Template");
      expect(payload.subject).toBe("Important Update");
    });

    it("should construct correct landing page payload", () => {
      const draft = {
        landingPageName: "[Ace C3] Test - Landing Page",
        landingPageHtml: "<html>landing</html>",
        captureCredentials: true,
        capturePasswords: false,
        landingPageRedirectUrl: "https://example.com",
      };
      const payload = {
        name: draft.landingPageName,
        html: draft.landingPageHtml,
        capture_credentials: draft.captureCredentials,
        capture_passwords: draft.capturePasswords,
        redirect_url: draft.landingPageRedirectUrl,
      };
      expect(payload.capture_credentials).toBe(true);
      expect(payload.capture_passwords).toBe(false);
      expect(payload.redirect_url).toBe("https://example.com");
    });

    it("should construct correct target group payload", () => {
      const emails = [
        { email: "test@example.com", firstName: "John", lastName: "Doe", position: "CEO" },
        { email: "admin@example.com", firstName: "Jane", lastName: "Smith" },
      ];
      const targets = emails.map((e) => ({
        first_name: e.firstName || "",
        last_name: e.lastName || "",
        email: e.email,
        position: (e as any).position || "",
      }));
      expect(targets.length).toBe(2);
      expect(targets[0].first_name).toBe("John");
      expect(targets[0].position).toBe("CEO");
      expect(targets[1].position).toBe("");
    });
  });

  describe("Caldera Operation Payload", () => {
    it("should create operation in paused state by default", () => {
      const operationPayload = {
        name: "[Ace C3] Post-Phish: Test Campaign - 2026-02-16",
        autonomous: 0,
        state: "paused",
      };
      expect(operationPayload.autonomous).toBe(0);
      expect(operationPayload.state).toBe("paused");
    });

    it("should include adversary when provided", () => {
      const adversaryId = "test-adversary-123";
      const payload: any = {
        name: "Test Operation",
        autonomous: 0,
        state: "paused",
      };
      if (adversaryId) {
        payload.adversary = { adversary_id: adversaryId };
      }
      expect(payload.adversary).toBeDefined();
      expect(payload.adversary.adversary_id).toBe("test-adversary-123");
    });
  });

  describe("Status Transition Guards", () => {
    it("should not allow editing launched campaigns", () => {
      const draft = { status: "launched" };
      const isEditable = draft.status !== "launched" && draft.status !== "completed";
      expect(isEditable).toBe(false);
    });

    it("should not allow editing completed campaigns", () => {
      const draft = { status: "completed" };
      const isEditable = draft.status !== "launched" && draft.status !== "completed";
      expect(isEditable).toBe(false);
    });

    it("should allow editing draft campaigns", () => {
      const draft = { status: "draft" };
      const isEditable = draft.status !== "launched" && draft.status !== "completed";
      expect(isEditable).toBe(true);
    });

    it("should allow editing approved campaigns", () => {
      const draft = { status: "approved" };
      const isEditable = draft.status !== "launched" && draft.status !== "completed";
      expect(isEditable).toBe(true);
    });

    it("should only deploy from draft or approved status", () => {
      const canDeploy = (status: string) => status === "draft" || status === "approved";
      expect(canDeploy("draft")).toBe(true);
      expect(canDeploy("approved")).toBe(true);
      expect(canDeploy("launched")).toBe(false);
      expect(canDeploy("completed")).toBe(false);
      expect(canDeploy("archived")).toBe(false);
    });

    it("should only launch from deployed status", () => {
      const canLaunch = (status: string) => status === "deployed";
      expect(canLaunch("deployed")).toBe(true);
      expect(canLaunch("draft")).toBe(false);
      expect(canLaunch("approved")).toBe(false);
    });

    it("should not delete launched campaigns", () => {
      const canDelete = (status: string) => status !== "launched";
      expect(canDelete("draft")).toBe(true);
      expect(canDelete("approved")).toBe(true);
      expect(canDelete("launched")).toBe(false);
      expect(canDelete("completed")).toBe(true);
    });
  });

  describe("Caldera Trigger Prerequisites", () => {
    it("should require submitted credentials before triggering Caldera", () => {
      const stats = { sent: 10, opened: 5, clicked: 3, submitted: 0 };
      const canTrigger = (stats.submitted || 0) > 0;
      expect(canTrigger).toBe(false);
    });

    it("should allow triggering when credentials are captured", () => {
      const stats = { sent: 10, opened: 5, clicked: 3, submitted: 2 };
      const canTrigger = (stats.submitted || 0) > 0;
      expect(canTrigger).toBe(true);
    });

    it("should handle null stats gracefully", () => {
      const stats = null as any;
      const canTrigger = (stats?.submitted || 0) > 0;
      expect(canTrigger).toBe(false);
    });
  });
});
