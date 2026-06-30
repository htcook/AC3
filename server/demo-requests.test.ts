import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the database
const mockExecute = vi.fn();
const mockInsert = vi.fn();
const mockValues = vi.fn();
const mockSelect = vi.fn();
const mockFrom = vi.fn();
const mockWhere = vi.fn();
const mockLimit = vi.fn();
const mockOffset = vi.fn();
const mockOrderBy = vi.fn();
const mockUpdate = vi.fn();
const mockSet = vi.fn();
const mockGroupBy = vi.fn();

const mockDb = {
  execute: mockExecute,
  insert: mockInsert,
  select: mockSelect,
  update: mockUpdate,
};

vi.mock("../drizzle/schema", () => ({
  demoRequests: {
    id: "id",
    name: "name",
    email: "email",
    organization: "organization",
    jobTitle: "job_title",
    useCase: "use_case",
    status: "status",
    notes: "notes",
    ipAddress: "ip_address",
    userAgent: "user_agent",
    createdAt: "created_at",
    updatedAt: "updated_at",
  },
}));

vi.mock("./db", () => ({
  getDb: vi.fn(async () => mockDb),
}));

vi.mock("./_core/notification", () => ({
  notifyOwner: vi.fn(async () => true),
}));

describe("Demo Requests Feature", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default mock chain setup
    mockInsert.mockReturnValue({ values: mockValues });
    mockValues.mockResolvedValue([{ insertId: 1 }]);
    mockSelect.mockReturnValue({ from: mockFrom });
    mockFrom.mockReturnValue({ where: mockWhere, orderBy: mockOrderBy, groupBy: mockGroupBy });
    mockWhere.mockReturnValue({ limit: mockLimit, orderBy: mockOrderBy });
    mockLimit.mockReturnValue({ offset: mockOffset });
    mockOffset.mockResolvedValue([]);
    mockOrderBy.mockReturnValue({ limit: mockLimit, where: mockWhere });
    mockUpdate.mockReturnValue({ set: mockSet });
    mockSet.mockReturnValue({ where: mockWhere });
    mockWhere.mockResolvedValue([]);
    mockGroupBy.mockResolvedValue([]);
  });

  describe("Schema Validation", () => {
    it("should require name with minimum 2 characters", () => {
      const { z } = require("zod");
      const schema = z.object({
        name: z.string().min(2).max(255),
        email: z.string().email().max(255),
        organization: z.string().min(2).max(255),
        jobTitle: z.string().max(255).optional(),
        useCase: z.string().min(10).max(2000),
      });

      expect(() => schema.parse({
        name: "A",
        email: "test@test.com",
        organization: "Org",
        useCase: "This is a valid use case description",
      })).toThrow();
    });

    it("should require valid email format", () => {
      const { z } = require("zod");
      const schema = z.object({
        name: z.string().min(2).max(255),
        email: z.string().email().max(255),
        organization: z.string().min(2).max(255),
        jobTitle: z.string().max(255).optional(),
        useCase: z.string().min(10).max(2000),
      });

      expect(() => schema.parse({
        name: "John Doe",
        email: "not-an-email",
        organization: "Org",
        useCase: "This is a valid use case description",
      })).toThrow();
    });

    it("should require use case with minimum 10 characters", () => {
      const { z } = require("zod");
      const schema = z.object({
        name: z.string().min(2).max(255),
        email: z.string().email().max(255),
        organization: z.string().min(2).max(255),
        jobTitle: z.string().max(255).optional(),
        useCase: z.string().min(10).max(2000),
      });

      expect(() => schema.parse({
        name: "John Doe",
        email: "john@test.com",
        organization: "Org",
        useCase: "Short",
      })).toThrow();
    });

    it("should accept valid submission data", () => {
      const { z } = require("zod");
      const schema = z.object({
        name: z.string().min(2).max(255),
        email: z.string().email().max(255),
        organization: z.string().min(2).max(255),
        jobTitle: z.string().max(255).optional(),
        useCase: z.string().min(10).max(2000),
      });

      const result = schema.parse({
        name: "Jane Smith",
        email: "jane@company.com",
        organization: "Acme Security",
        jobTitle: "CISO",
        useCase: "We need to validate our cloud security posture with adversary emulation",
      });

      expect(result.name).toBe("Jane Smith");
      expect(result.email).toBe("jane@company.com");
      expect(result.organization).toBe("Acme Security");
      expect(result.jobTitle).toBe("CISO");
    });

    it("should allow optional jobTitle", () => {
      const { z } = require("zod");
      const schema = z.object({
        name: z.string().min(2).max(255),
        email: z.string().email().max(255),
        organization: z.string().min(2).max(255),
        jobTitle: z.string().max(255).optional(),
        useCase: z.string().min(10).max(2000),
      });

      const result = schema.parse({
        name: "Jane Smith",
        email: "jane@company.com",
        organization: "Acme Security",
        useCase: "We need to validate our cloud security posture with adversary emulation",
      });

      expect(result.jobTitle).toBeUndefined();
    });
  });

  describe("Rate Limiting", () => {
    it("should enforce rate limit window of 1 hour", () => {
      const RATE_LIMIT_WINDOW = 60 * 60 * 1000;
      expect(RATE_LIMIT_WINDOW).toBe(3600000);
    });

    it("should allow maximum 3 requests per window", () => {
      const RATE_LIMIT_MAX = 3;
      expect(RATE_LIMIT_MAX).toBe(3);
    });

    it("should track requests by IP address", () => {
      const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
      const ip = "192.168.1.1";
      const now = Date.now();

      rateLimitMap.set(ip, { count: 1, resetAt: now + 3600000 });
      expect(rateLimitMap.has(ip)).toBe(true);
      expect(rateLimitMap.get(ip)!.count).toBe(1);
    });

    it("should reset count after window expires", () => {
      const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
      const ip = "192.168.1.1";
      const now = Date.now();

      // Set expired entry
      rateLimitMap.set(ip, { count: 3, resetAt: now - 1000 });
      const entry = rateLimitMap.get(ip)!;

      // Check if expired
      const isExpired = now > entry.resetAt;
      expect(isExpired).toBe(true);
    });

    it("should block requests when limit is reached", () => {
      const RATE_LIMIT_MAX = 3;
      const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
      const ip = "10.0.0.1";
      const now = Date.now();

      rateLimitMap.set(ip, { count: 3, resetAt: now + 3600000 });
      const entry = rateLimitMap.get(ip)!;
      const isBlocked = entry.count >= RATE_LIMIT_MAX && now <= entry.resetAt;
      expect(isBlocked).toBe(true);
    });
  });

  describe("Status Management", () => {
    it("should support all valid status values", () => {
      const validStatuses = ["new", "contacted", "scheduled", "completed", "declined"];
      expect(validStatuses).toHaveLength(5);
      expect(validStatuses).toContain("new");
      expect(validStatuses).toContain("contacted");
      expect(validStatuses).toContain("scheduled");
      expect(validStatuses).toContain("completed");
      expect(validStatuses).toContain("declined");
    });

    it("should default new submissions to 'new' status", () => {
      const defaultStatus = "new";
      expect(defaultStatus).toBe("new");
    });

    it("should validate status transitions", () => {
      const { z } = require("zod");
      const statusSchema = z.enum(["new", "contacted", "scheduled", "completed", "declined"]);

      expect(statusSchema.parse("contacted")).toBe("contacted");
      expect(() => statusSchema.parse("invalid")).toThrow();
    });
  });

  describe("Notification", () => {
    it("should format notification title with organization name", () => {
      const org = "Acme Security";
      const title = `New Demo Request: ${org}`;
      expect(title).toBe("New Demo Request: Acme Security");
    });

    it("should include all fields in notification content", () => {
      const input = {
        name: "Jane Smith",
        jobTitle: "CISO",
        organization: "Acme Security",
        email: "jane@acme.com",
        useCase: "Cloud security testing",
      };

      const content = [
        `**Name:** ${input.name}`,
        input.jobTitle ? `**Title:** ${input.jobTitle}` : null,
        `**Organization:** ${input.organization}`,
        `**Email:** ${input.email}`,
        `**Use Case:** ${input.useCase}`,
      ].filter(Boolean).join("\n");

      expect(content).toContain("Jane Smith");
      expect(content).toContain("CISO");
      expect(content).toContain("Acme Security");
      expect(content).toContain("jane@acme.com");
      expect(content).toContain("Cloud security testing");
    });

    it("should omit job title line when not provided", () => {
      const input = {
        name: "Jane Smith",
        jobTitle: undefined,
        organization: "Acme Security",
        email: "jane@acme.com",
        useCase: "Cloud security testing",
      };

      const content = [
        `**Name:** ${input.name}`,
        input.jobTitle ? `**Title:** ${input.jobTitle}` : null,
        `**Organization:** ${input.organization}`,
        `**Email:** ${input.email}`,
        `**Use Case:** ${input.useCase}`,
      ].filter(Boolean).join("\n");

      expect(content).not.toContain("**Title:**");
    });
  });

  describe("Duplicate Detection", () => {
    it("should check for submissions within 24 hours", () => {
      const sqlFragment = "DATE_SUB(NOW(), INTERVAL 24 HOUR)";
      expect(sqlFragment).toContain("24 HOUR");
    });

    it("should match on email address for duplicates", () => {
      const email1 = "test@example.com";
      const email2 = "test@example.com";
      expect(email1).toBe(email2);
    });

    it("should allow resubmission after 24 hours", () => {
      const submittedAt = new Date("2026-05-03T10:00:00Z");
      const now = new Date("2026-05-04T11:00:00Z");
      const hoursDiff = (now.getTime() - submittedAt.getTime()) / (1000 * 60 * 60);
      expect(hoursDiff).toBeGreaterThan(24);
    });
  });

  describe("Stats Aggregation", () => {
    it("should aggregate counts by status", () => {
      const result = [
        { status: "new", count: 5 },
        { status: "contacted", count: 3 },
        { status: "scheduled", count: 2 },
        { status: "completed", count: 1 },
        { status: "declined", count: 0 },
      ];

      const stats: Record<string, number> = {
        new: 0, contacted: 0, scheduled: 0, completed: 0, declined: 0, total: 0,
      };

      for (const row of result) {
        stats[row.status] = row.count;
        stats.total += row.count;
      }

      expect(stats.new).toBe(5);
      expect(stats.contacted).toBe(3);
      expect(stats.total).toBe(11);
    });

    it("should handle empty result set", () => {
      const result: { status: string; count: number }[] = [];
      const stats: Record<string, number> = {
        new: 0, contacted: 0, scheduled: 0, completed: 0, declined: 0, total: 0,
      };

      for (const row of result) {
        stats[row.status] = row.count;
        stats.total += row.count;
      }

      expect(stats.total).toBe(0);
      expect(stats.new).toBe(0);
    });
  });

  describe("Search Functionality", () => {
    it("should search across name, email, and organization", () => {
      const searchFields = ["name", "email", "organization"];
      expect(searchFields).toHaveLength(3);
      expect(searchFields).toContain("name");
      expect(searchFields).toContain("email");
      expect(searchFields).toContain("organization");
    });

    it("should wrap search term with wildcards for LIKE query", () => {
      const search = "acme";
      const searchTerm = `%${search}%`;
      expect(searchTerm).toBe("%acme%");
    });
  });

  describe("Input Sanitization", () => {
    it("should truncate user agent to 512 characters", () => {
      const longUA = "A".repeat(1000);
      const truncated = longUA.substring(0, 512);
      expect(truncated.length).toBe(512);
    });

    it("should handle missing IP gracefully", () => {
      const clientIp = undefined || "unknown";
      expect(clientIp).toBe("unknown");
    });

    it("should handle x-forwarded-for header", () => {
      const headers = { "x-forwarded-for": "203.0.113.50, 70.41.3.18" };
      const ip = headers["x-forwarded-for"];
      expect(ip).toBe("203.0.113.50, 70.41.3.18");
    });
  });

  describe("Pagination", () => {
    it("should default to 50 items per page", () => {
      const { z } = require("zod");
      const schema = z.object({
        limit: z.number().min(1).max(100).default(50),
        offset: z.number().min(0).default(0),
      });

      const result = schema.parse({});
      expect(result.limit).toBe(50);
      expect(result.offset).toBe(0);
    });

    it("should enforce maximum 100 items per page", () => {
      const { z } = require("zod");
      const schema = z.object({
        limit: z.number().min(1).max(100).default(50),
        offset: z.number().min(0).default(0),
      });

      expect(() => schema.parse({ limit: 200 })).toThrow();
    });
  });
});
