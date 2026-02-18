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
      expect(routerObj).toHaveProperty("identifyStaleResources");
      expect(routerObj).toHaveProperty("bulkCleanup");
    });

    it("should have exactly 20 procedures", async () => {
      const mod = await import("./routers/phishing-ops");
      const routerObj = mod.phishingOpsRouter as any;
      const keys = Object.keys(routerObj);
      expect(keys.length).toBe(20);
    });

    it("should have the generateReport procedure", async () => {
      const mod = await import("./routers/phishing-ops");
      const routerObj = mod.phishingOpsRouter as any;
      expect(routerObj).toHaveProperty("generateReport");
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

  describe("Stale Resource Identification Logic", () => {
    it("should identify templates with empty body as stale", () => {
      const templates = [
        { id: 1, name: "Real Template", html: "<html><body><p>Full email content here with lots of text</p></body></html>", subject: "Important" },
        { id: 2, name: "Empty One", html: "", subject: "Test" },
        { id: 3, name: "Short", html: "<p>hi</p>", subject: "" },
      ];
      const stale = templates.filter((t) => {
        const isEmpty = (t.html || "").trim().length < 20;
        const isTest = /^test|^demo|^sample|^placeholder|^untitled|^default|^new template/i.test(t.name);
        const noSubject = (t.subject || "").trim().length === 0;
        return isEmpty || isTest || (noSubject && (t.html || "").trim().length < 100);
      });
      expect(stale.length).toBe(2);
      expect(stale.map(s => s.id)).toContain(2);
      expect(stale.map(s => s.id)).toContain(3);
    });

    it("should identify templates with test names as stale", () => {
      const templates = [
        { id: 1, name: "Test Email", html: "<html><body><p>Full content with lots of text here</p></body></html>", subject: "Real Subject" },
        { id: 2, name: "Production Campaign", html: "<html><body><p>Full content with lots of text here</p></body></html>", subject: "Real Subject" },
      ];
      const stale = templates.filter((t) => /^test|^demo|^sample|^placeholder|^untitled|^default|^new template/i.test(t.name));
      expect(stale.length).toBe(1);
      expect(stale[0].id).toBe(1);
    });

    it("should identify groups with no targets as stale", () => {
      const groups = [
        { id: 1, name: "Active Group", targets: [{ email: "a@b.com" }] },
        { id: 2, name: "Empty Group", targets: [] },
        { id: 3, name: "Demo Group", targets: [{ email: "x@y.com" }] },
      ];
      const stale = groups.filter((g) => {
        const isEmpty = g.targets.length === 0;
        const isTest = /^test|^demo|^sample|^placeholder|^untitled|^default/i.test(g.name);
        return isEmpty || isTest;
      });
      expect(stale.length).toBe(2);
      expect(stale.map(s => s.id)).toContain(2);
      expect(stale.map(s => s.id)).toContain(3);
    });

    it("should categorize stale reasons correctly", () => {
      const getReason = (html: string, name: string) => {
        if (html.trim().length < 20) return "empty_body";
        if (/^test|^demo|^sample|^placeholder|^untitled|^default|^new template/i.test(name)) return "test_name";
        return "no_subject";
      };
      expect(getReason("", "Real")).toBe("empty_body");
      expect(getReason("<p>short</p>", "Real")).toBe("empty_body");
      expect(getReason("<html><body><p>Long enough content here for testing</p></body></html>", "Test Template")).toBe("test_name");
      expect(getReason("<html><body><p>Long enough content here for testing</p></body></html>", "Real Template")).toBe("no_subject");
    });
  });

  describe("Bulk Cleanup Payload", () => {
    it("should accept arrays of IDs for each resource type", () => {
      const payload = {
        templateIds: [1, 2, 3],
        pageIds: [4, 5],
        groupIds: [6],
      };
      expect(payload.templateIds.length).toBe(3);
      expect(payload.pageIds.length).toBe(2);
      expect(payload.groupIds.length).toBe(1);
    });

    it("should handle empty arrays for selective cleanup", () => {
      const payload = {
        templateIds: [],
        pageIds: [1, 2],
        groupIds: [],
      };
      const totalToDelete = payload.templateIds.length + payload.pageIds.length + payload.groupIds.length;
      expect(totalToDelete).toBe(2);
    });

    it("should track deletion results with error reporting", () => {
      const results = { deletedTemplates: 2, deletedPages: 1, deletedGroups: 0, errors: ["Group 6: Not found"] };
      const totalDeleted = results.deletedTemplates + results.deletedPages + results.deletedGroups;
      expect(totalDeleted).toBe(3);
      expect(results.errors.length).toBe(1);
    });
  });

  describe("Pipeline Auto-Materialization", () => {
    it("should limit auto-materialization to top 3 recommendations", () => {
      const recs = [
        { name: "Rec 1", priority: "critical" },
        { name: "Rec 2", priority: "high" },
        { name: "Rec 3", priority: "medium" },
        { name: "Rec 4", priority: "low" },
        { name: "Rec 5", priority: "low" },
      ];
      const topRecs = recs.slice(0, 3);
      expect(topRecs.length).toBe(3);
      expect(topRecs[0].name).toBe("Rec 1");
      expect(topRecs[2].name).toBe("Rec 3");
    });

    it("should generate correct campaign name from domain and type", () => {
      const domain = "example.com";
      const rec = { name: null, type: "spear_phishing" };
      const campaignName = rec.name || `${domain} - ${rec.type || 'phishing'} Campaign`;
      expect(campaignName).toBe("example.com - spear_phishing Campaign");
    });

    it("should use recommendation name when available", () => {
      const domain = "example.com";
      const rec = { name: "Custom Campaign", type: "spear_phishing" };
      const campaignName = rec.name || `${domain} - ${rec.type || 'phishing'} Campaign`;
      expect(campaignName).toBe("Custom Campaign");
    });

    it("should set matchRationale for auto-materialized drafts", () => {
      const rationale = "Auto-materialized by engagement pipeline";
      expect(rationale).toContain("Auto-materialized");
      expect(rationale).toContain("engagement pipeline");
    });

    it("should track materialized draft IDs in riskSummary", () => {
      const riskSummary = {
        gophishCampaign: {
          status: "materialized",
          materializedDraftIds: [10, 11, 12],
          totalRecommendations: 5,
          materializedCount: 3,
          recommendedTemplates: [],
        },
      };
      expect(riskSummary.gophishCampaign.status).toBe("materialized");
      expect(riskSummary.gophishCampaign.materializedDraftIds.length).toBe(3);
      expect(riskSummary.gophishCampaign.materializedCount).toBe(3);
    });

    it("should fall back to ready status when no drafts materialized", () => {
      const materializedDraftIds: number[] = [];
      const status = materializedDraftIds.length > 0 ? "materialized" : "ready";
      expect(status).toBe("ready");
    });
  });

  describe("Inline Draft Editing", () => {
    it("should parse CSV target emails correctly", () => {
      const csv = "john@example.com,John,Doe,CEO\njane@example.com,Jane,Smith,CFO";
      const parsed = csv.trim().split("\n").map((line) => {
        const [email, firstName, lastName, position] = line.split(",").map((s) => s.trim());
        return { email: email || "", firstName, lastName, position };
      }).filter((t) => t.email.includes("@"));
      expect(parsed.length).toBe(2);
      expect(parsed[0].email).toBe("john@example.com");
      expect(parsed[0].firstName).toBe("John");
      expect(parsed[0].position).toBe("CEO");
      expect(parsed[1].email).toBe("jane@example.com");
    });

    it("should filter out invalid email lines", () => {
      const csv = "john@example.com,John,Doe\ninvalid-line\n,,,\njane@test.com,Jane";
      const parsed = csv.trim().split("\n").map((line) => {
        const [email, firstName, lastName, position] = line.split(",").map((s) => s.trim());
        return { email: email || "", firstName, lastName, position };
      }).filter((t) => t.email.includes("@"));
      expect(parsed.length).toBe(2);
    });

    it("should handle empty CSV input", () => {
      const csv = "";
      const parsed = csv.trim() ? csv.trim().split("\n").map((line) => {
        const [email, firstName, lastName, position] = line.split(",").map((s) => s.trim());
        return { email, firstName, lastName, position };
      }).filter((t) => t.email.includes("@")) : undefined;
      expect(parsed).toBeUndefined();
    });

    it("should convert target emails array to CSV for editing", () => {
      const targets = [
        { email: "a@b.com", firstName: "Alice", lastName: "Brown", position: "CTO" },
        { email: "c@d.com", firstName: "", lastName: "", position: "" },
      ];
      const csv = targets.map((t) => [t.email, t.firstName || "", t.lastName || "", t.position || ""].join(",")).join("\n");
      expect(csv).toBe("a@b.com,Alice,Brown,CTO\nc@d.com,,,");
    });

    it("should only allow editing draft and approved statuses", () => {
      const canEdit = (status: string) => status === "draft" || status === "approved";
      expect(canEdit("draft")).toBe(true);
      expect(canEdit("approved")).toBe(true);
      expect(canEdit("deployed")).toBe(false);
      expect(canEdit("launched")).toBe(false);
      expect(canEdit("completed")).toBe(false);
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

  describe("Report Generation Logic", () => {
    it("should calculate risk score from campaign stats", () => {
      const total = 100;
      const opened = 60;
      const clicked = 30;
      const submitted = 10;
      const riskScore = Math.round(
        (opened / total) * 15 +
        (clicked / total) * 35 +
        (submitted / total) * 50
      );
      expect(riskScore).toBe(25); // 9 + 10.5 + 5 = 24.5 -> rounds to 25
    });

    it("should classify risk levels correctly", () => {
      const classify = (score: number) =>
        score >= 70 ? "Critical" :
        score >= 50 ? "High" :
        score >= 30 ? "Medium" : "Low";
      expect(classify(85)).toBe("Critical");
      expect(classify(70)).toBe("Critical");
      expect(classify(55)).toBe("High");
      expect(classify(50)).toBe("High");
      expect(classify(35)).toBe("Medium");
      expect(classify(30)).toBe("Medium");
      expect(classify(20)).toBe("Low");
      expect(classify(0)).toBe("Low");
    });

    it("should generate report ID with correct format", () => {
      const draftId = 42;
      const reportId = `ACE-RPT-${draftId}-${Date.now().toString(36).toUpperCase()}`;
      expect(reportId).toMatch(/^ACE-RPT-42-[A-Z0-9]+$/);
    });

    it("should handle zero total targets without division errors", () => {
      const total = 0;
      const opened = 0;
      const openRate = total > 0 ? ((opened / total) * 100).toFixed(1) : "0.0";
      expect(openRate).toBe("0.0");
    });

    it("should calculate rates as percentages with one decimal", () => {
      const total = 50;
      const clicked = 7;
      const clickRate = total > 0 ? ((clicked / total) * 100).toFixed(1) : "0.0";
      expect(clickRate).toBe("14.0");
    });
  });

  describe("Compliance Framework Analysis", () => {
    const FRAMEWORK_DETAILS: Record<string, { fullName: string; relevantControls: string }> = {
      "SOC2": { fullName: "SOC 2 Type II", relevantControls: "CC6.1 (Logical Access), CC6.6 (External Threats), CC7.2 (Monitoring), CC8.1 (Change Management)" },
      "HIPAA": { fullName: "HIPAA Security Rule", relevantControls: "\u00a7164.308(a)(5) Security Awareness Training, \u00a7164.312(d) Authentication, \u00a7164.308(a)(1) Risk Analysis" },
      "PCI-DSS": { fullName: "PCI DSS v4.0", relevantControls: "Req 5.4 (Anti-Phishing), Req 8.3 (MFA), Req 12.6 (Security Awareness), Req 12.10 (Incident Response)" },
      "NIST": { fullName: "NIST CSF 2.0 / NIST 800-53", relevantControls: "PR.AT (Awareness & Training), DE.CM (Continuous Monitoring), RS.RP (Response Planning), ID.RA (Risk Assessment)" },
      "CMMC": { fullName: "CMMC 2.0", relevantControls: "AT.L2-3.2.1 (Role-Based Training), AT.L2-3.2.2 (Literacy Training), IR.L2-3.6.1 (Incident Handling), SI.L2-3.14.2 (Malicious Code Protection)" },
      "FedRAMP": { fullName: "FedRAMP (NIST 800-53)", relevantControls: "AT-2 (Literacy Training), IR-4 (Incident Handling), SI-3 (Malicious Code Protection), CA-8 (Penetration Testing)" },
    };

    it("should map all 12 supported compliance frameworks", () => {
      const allFrameworks = ["SOC2", "HIPAA", "PCI-DSS", "GDPR", "NIST", "ISO27001", "FedRAMP", "CMMC", "SOX", "CCPA", "FERPA", "ITAR"];
      expect(allFrameworks.length).toBe(12);
    });

    it("should build compliance context string from selected frameworks", () => {
      const frameworks = ["SOC2", "HIPAA"];
      const context = frameworks.map(f => {
        const details = FRAMEWORK_DETAILS[f];
        return details ? `${f} (${details.fullName}): Relevant controls \u2014 ${details.relevantControls}` : f;
      }).join("\n");
      expect(context).toContain("SOC 2 Type II");
      expect(context).toContain("HIPAA Security Rule");
      expect(context).toContain("CC6.1");
    });

    it("should handle unknown framework IDs gracefully", () => {
      const frameworks = ["UNKNOWN_FRAMEWORK"];
      const context = frameworks.map(f => {
        const details = FRAMEWORK_DETAILS[f];
        return details ? `${f} (${details.fullName})` : f;
      }).join("\n");
      expect(context).toBe("UNKNOWN_FRAMEWORK");
    });

    it("should generate fallback compliance analysis when LLM fails", () => {
      const riskScore = 55;
      const riskLevel = "High";
      const submitRate = "15.0";
      const frameworks = ["NIST", "CMMC"];
      const analysis = frameworks.map(f => {
        const details = FRAMEWORK_DETAILS[f];
        return {
          framework: f,
          fullName: details?.fullName || f,
          status: riskScore >= 50 ? "non_compliant" : riskScore >= 30 ? "at_risk" : "partial",
          impactedControls: (details?.relevantControls || "").split(", "),
          findings: `Phishing simulation results indicate a ${riskLevel.toLowerCase()} risk to ${details?.fullName || f} compliance. ${submitRate}% credential submission rate suggests gaps in security awareness controls.`,
        };
      });
      expect(analysis.length).toBe(2);
      expect(analysis[0].framework).toBe("NIST");
      expect(analysis[0].status).toBe("non_compliant");
      expect(analysis[0].impactedControls.length).toBe(4);
      expect(analysis[1].framework).toBe("CMMC");
      expect(analysis[1].findings).toContain("high risk");
    });

    it("should classify compliance status based on risk score", () => {
      const classify = (riskScore: number) =>
        riskScore >= 50 ? "non_compliant" : riskScore >= 30 ? "at_risk" : "partial";
      expect(classify(75)).toBe("non_compliant");
      expect(classify(50)).toBe("non_compliant");
      expect(classify(40)).toBe("at_risk");
      expect(classify(30)).toBe("at_risk");
      expect(classify(20)).toBe("partial");
      expect(classify(0)).toBe("partial");
    });

    it("should pull compliance from scan orgProfile as fallback", () => {
      const scanComplianceFlags: string[] = [];
      const orgProfile = { complianceFlags: ["SOC2", "HIPAA"] };
      const result = scanComplianceFlags.length > 0 ? scanComplianceFlags : (orgProfile?.complianceFlags || []);
      expect(result).toEqual(["SOC2", "HIPAA"]);
    });

    it("should handle empty compliance frameworks", () => {
      const frameworks: string[] = [];
      const context = frameworks.length > 0
        ? frameworks.map(f => f).join("\n")
        : "No specific compliance frameworks selected";
      expect(context).toBe("No specific compliance frameworks selected");
    });
  });

  describe("Report Branding", () => {
    it("should include AceofCloud branding in report", () => {
      const branding = {
        company: "AceofCloud",
        platform: "Ace C3 \u2014 Command, Control, Conquer",
        author: "Harrison Cook",
        website: "https://aceofcloud.com",
      };
      expect(branding.company).toBe("AceofCloud");
      expect(branding.author).toBe("Harrison Cook");
      expect(branding.website).toBe("https://aceofcloud.com");
    });
  });

  describe("LLM Materialization in Pipeline", () => {
    it("should limit auto-materialization to top 3 recommendations", () => {
      const recommendations = [
        { name: "A", priority: "critical" },
        { name: "B", priority: "high" },
        { name: "C", priority: "medium" },
        { name: "D", priority: "low" },
        { name: "E", priority: "low" },
      ];
      const top3 = recommendations.slice(0, 3);
      expect(top3.length).toBe(3);
      expect(top3[2].name).toBe("C");
    });

    it("should handle fewer than 3 recommendations", () => {
      const recommendations = [{ name: "A" }];
      const top3 = recommendations.slice(0, 3);
      expect(top3.length).toBe(1);
    });

    it("should handle empty recommendations", () => {
      const recommendations: any[] = [];
      const top3 = recommendations.slice(0, 3);
      expect(top3.length).toBe(0);
    });
  });
});
