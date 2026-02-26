/**
 * Workflow Persistence — Vitest Tests
 * Tests the workflow state persistence service and tRPC router integration.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Hoisted Mocks ─────────────────────────────────────────────────

const {
  mockInsertValues,
  mockInsert,
  mockSelectFrom,
  mockSelectWhere,
  mockSelectOrderBy,
  mockSelectLimit,
  mockUpdateSet,
  mockUpdateWhere,
  mockSelect,
  mockUpdate,
} = vi.hoisted(() => {
  const mockInsertValues = vi.fn().mockResolvedValue([{ insertId: 42 }]);
  const mockInsert = vi.fn().mockReturnValue({ values: mockInsertValues });

  const mockSelectFrom = vi.fn();
  const mockSelectWhere = vi.fn();
  const mockSelectOrderBy = vi.fn();
  const mockSelectLimit = vi.fn();

  const mockUpdateSet = vi.fn();
  const mockUpdateWhere = vi.fn();

  // Chain builders
  mockSelectFrom.mockReturnValue({ where: mockSelectWhere, orderBy: mockSelectOrderBy });
  mockSelectWhere.mockReturnValue({ orderBy: mockSelectOrderBy, limit: mockSelectLimit });
  mockSelectOrderBy.mockReturnValue({ limit: mockSelectLimit });
  mockSelectLimit.mockResolvedValue([]);

  const mockSelect = vi.fn().mockReturnValue({ from: mockSelectFrom });
  const mockUpdate = vi.fn().mockReturnValue({ set: mockUpdateSet });
  mockUpdateSet.mockReturnValue({ where: mockUpdateWhere });
  mockUpdateWhere.mockResolvedValue([]);

  return {
    mockInsertValues,
    mockInsert,
    mockSelectFrom,
    mockSelectWhere,
    mockSelectOrderBy,
    mockSelectLimit,
    mockUpdateSet,
    mockUpdateWhere,
    mockSelect,
    mockUpdate,
  };
});

vi.mock("../db", () => ({
  getDb: vi.fn().mockResolvedValue({
    insert: mockInsert,
    select: mockSelect,
    update: mockUpdate,
  }),
}));

vi.mock("../../drizzle/schema", () => ({
  workflowSessions: {
    id: "id",
    userId: "userId",
    workflowId: "workflowId",
    status: "status",
    lastActivityAt: "lastActivityAt",
    currentStepIndex: "currentStepIndex",
    totalSteps: "totalSteps",
    stepData: "stepData",
    contextData: "contextData",
    workflowName: "workflowName",
    startedAt: "startedAt",
    completedAt: "completedAt",
  },
  workflowStepHistory: {
    id: "id",
    sessionId: "sessionId",
    stepIndex: "stepIndex",
    stepId: "stepId",
    stepName: "stepName",
    status: "status",
    inputData: "inputData",
    outputData: "outputData",
    linkedEntityType: "linkedEntityType",
    linkedEntityId: "linkedEntityId",
    startedAt: "startedAt",
    completedAt: "completedAt",
  },
}));

vi.mock("drizzle-orm", () => ({
  eq: vi.fn((col, val) => ({ type: "eq", col, val })),
  and: vi.fn((...args: any[]) => ({ type: "and", args })),
  desc: vi.fn((col) => ({ type: "desc", col })),
}));

import {
  WORKFLOW_DEFINITIONS,
  startWorkflow,
  getActiveWorkflows,
  getWorkflowSession,
  advanceWorkflowStep,
  updateStepData,
  abandonWorkflow,
  getWorkflowHistory,
} from "./workflow-persistence";

// ─── Tests ──────────────────────────────────────────────────────────

describe("Workflow Persistence", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset default mock return values
    mockInsertValues.mockResolvedValue([{ insertId: 42 }]);
    mockSelectFrom.mockReturnValue({ where: mockSelectWhere, orderBy: mockSelectOrderBy });
    mockSelectWhere.mockReturnValue({ orderBy: mockSelectOrderBy, limit: mockSelectLimit });
    mockSelectOrderBy.mockReturnValue({ limit: mockSelectLimit });
    mockSelectLimit.mockResolvedValue([]);
    mockUpdateSet.mockReturnValue({ where: mockUpdateWhere });
    mockUpdateWhere.mockResolvedValue([]);
  });

  // ─── Workflow Definitions ──────────────────────────────────────────

  describe("WORKFLOW_DEFINITIONS", () => {
    it("should have 6 workflow definitions", () => {
      expect(WORKFLOW_DEFINITIONS).toHaveLength(6);
    });

    it("should have unique workflow IDs", () => {
      const ids = WORKFLOW_DEFINITIONS.map(w => w.workflowId);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it("should include all expected workflow IDs", () => {
      const ids = WORKFLOW_DEFINITIONS.map(w => w.workflowId);
      expect(ids).toContain("new-engagement");
      expect(ids).toContain("domain-recon");
      expect(ids).toContain("detection-validation");
      expect(ids).toContain("phishing-campaign");
      expect(ids).toContain("cloud-security");
      expect(ids).toContain("compliance-report");
    });

    it("each workflow should have at least 3 steps", () => {
      for (const wf of WORKFLOW_DEFINITIONS) {
        expect(wf.steps.length).toBeGreaterThanOrEqual(3);
      }
    });

    it("each step should have stepId, stepName, and route", () => {
      for (const wf of WORKFLOW_DEFINITIONS) {
        for (const step of wf.steps) {
          expect(step.stepId).toBeTruthy();
          expect(step.stepName).toBeTruthy();
          expect(step.route).toBeTruthy();
          expect(step.route.startsWith("/")).toBe(true);
        }
      }
    });

    it("each workflow should have a unique workflowName", () => {
      const names = WORKFLOW_DEFINITIONS.map(w => w.workflowName);
      expect(new Set(names).size).toBe(names.length);
    });
  });

  // ─── startWorkflow ─────────────────────────────────────────────────

  describe("startWorkflow", () => {
    it("should create a new session and return the session ID", async () => {
      const sessionId = await startWorkflow("user-123", "new-engagement");
      expect(sessionId).toBe(42);
      expect(mockInsert).toHaveBeenCalled();
    });

    it("should throw for unknown workflow ID", async () => {
      await expect(startWorkflow("user-123", "nonexistent")).rejects.toThrow("Unknown workflow");
    });

    it("should insert step history entries for all steps", async () => {
      await startWorkflow("user-123", "domain-recon");
      // 1 session insert + 5 step inserts (domain-recon has 5 steps)
      expect(mockInsert).toHaveBeenCalledTimes(6);
    });

    it("should set first step as in_progress and others as pending", async () => {
      await startWorkflow("user-123", "domain-recon");
      // Check the step insert calls (calls[0] is session, calls[1..5] are steps)
      const stepCalls = mockInsertValues.mock.calls.slice(1);
      expect(stepCalls[0][0].status).toBe("in_progress");
      for (let i = 1; i < stepCalls.length; i++) {
        expect(stepCalls[i][0].status).toBe("pending");
      }
    });

    it("should set correct totalSteps in session", async () => {
      await startWorkflow("user-123", "compliance-report");
      // Session insert is the first call
      const sessionInsertData = mockInsertValues.mock.calls[0][0];
      expect(sessionInsertData.totalSteps).toBe(4);
    });
  });

  // ─── getActiveWorkflows ────────────────────────────────────────────

  describe("getActiveWorkflows", () => {
    it("should query for in_progress sessions for the user", async () => {
      mockSelectOrderBy.mockResolvedValue([]);
      const result = await getActiveWorkflows("user-123");
      expect(mockSelect).toHaveBeenCalled();
      expect(mockSelectFrom).toHaveBeenCalled();
      expect(mockSelectWhere).toHaveBeenCalled();
    });

    it("should return empty array when no active workflows", async () => {
      mockSelectOrderBy.mockResolvedValue([]);
      const result = await getActiveWorkflows("user-123");
      expect(result).toEqual([]);
    });
  });

  // ─── getWorkflowSession ───────────────────────────────────────────

  describe("getWorkflowSession", () => {
    it("should return null for non-existent session", async () => {
      mockSelectWhere.mockResolvedValueOnce([]);
      const result = await getWorkflowSession(999);
      expect(result).toBeNull();
    });

    it("should return session with steps and definition when found", async () => {
      const mockSession = {
        id: 1,
        userId: "user-123",
        workflowId: "domain-recon",
        currentStepIndex: 2,
        totalSteps: 5,
        status: "in_progress",
      };
      const mockSteps = [
        { id: 1, sessionId: 1, stepIndex: 0, status: "completed" },
        { id: 2, sessionId: 1, stepIndex: 1, status: "completed" },
        { id: 3, sessionId: 1, stepIndex: 2, status: "in_progress" },
      ];

      // First select (session) - goes through where
      mockSelectWhere.mockResolvedValueOnce([mockSession]);
      // Second select (steps) - goes through where -> orderBy
      const mockOrderByForSteps = vi.fn().mockResolvedValue(mockSteps);
      mockSelectWhere.mockReturnValueOnce({ orderBy: mockOrderByForSteps });

      const result = await getWorkflowSession(1);
      expect(result).not.toBeNull();
      expect(result!.workflowId).toBe("domain-recon");
      expect(result!.steps).toEqual(mockSteps);
      expect(result!.definition).toBeDefined();
      expect(result!.definition!.workflowId).toBe("domain-recon");
    });
  });

  // ─── advanceWorkflowStep ──────────────────────────────────────────

  describe("advanceWorkflowStep", () => {
    it("should mark the current step as completed", async () => {
      const mockStep = { id: 10, sessionId: 1, stepIndex: 0, status: "in_progress" };
      // Find current step
      mockSelectWhere.mockResolvedValueOnce([mockStep]);
      // Find session
      mockSelectWhere.mockResolvedValueOnce([{ id: 1, totalSteps: 5, currentStepIndex: 0 }]);
      // Find next step
      mockSelectWhere.mockResolvedValueOnce([{ id: 11, sessionId: 1, stepIndex: 1, status: "pending" }]);
      // getWorkflowSession: find session
      mockSelectWhere.mockResolvedValueOnce([{ id: 1, workflowId: "domain-recon" }]);
      // getWorkflowSession: find steps
      const mockOrderBy = vi.fn().mockResolvedValue([]);
      mockSelectWhere.mockReturnValueOnce({ orderBy: mockOrderBy });

      await advanceWorkflowStep(1, 0);
      expect(mockUpdate).toHaveBeenCalled();
    });

    it("should return null if session not found", async () => {
      // Find current step
      mockSelectWhere.mockResolvedValueOnce([{ id: 10 }]);
      // Find session - not found
      mockSelectWhere.mockResolvedValueOnce([]);

      const result = await advanceWorkflowStep(999, 0);
      expect(result).toBeNull();
    });

    it("should mark workflow as completed when advancing past last step", async () => {
      // Find current step (step 4 of 5, index 4)
      mockSelectWhere.mockResolvedValueOnce([{ id: 10, sessionId: 1, stepIndex: 4 }]);
      // Find session (5 total steps, completing step 4 = last)
      mockSelectWhere.mockResolvedValueOnce([{ id: 1, totalSteps: 5, currentStepIndex: 4 }]);
      // getWorkflowSession: find session
      mockSelectWhere.mockResolvedValueOnce([{ id: 1, workflowId: "domain-recon", status: "completed" }]);
      // getWorkflowSession: find steps
      const mockOrderBy = vi.fn().mockResolvedValue([]);
      mockSelectWhere.mockReturnValueOnce({ orderBy: mockOrderBy });

      await advanceWorkflowStep(1, 4);
      // Should update session to completed status
      expect(mockUpdateSet).toHaveBeenCalledWith(
        expect.objectContaining({ status: "completed" })
      );
    });
  });

  // ─── updateStepData ───────────────────────────────────────────────

  describe("updateStepData", () => {
    it("should update step input data", async () => {
      // Find session for step data merge
      mockSelectWhere.mockResolvedValueOnce([{ id: 1, stepData: {} }]);

      await updateStepData(1, 2, { domain: "example.com" });
      expect(mockUpdate).toHaveBeenCalled();
    });

    it("should merge with existing step data", async () => {
      mockSelectWhere.mockResolvedValueOnce([{
        id: 1,
        stepData: { step_0: { target: "test.com" } },
      }]);

      await updateStepData(1, 1, { scanId: "abc-123" });
      expect(mockUpdateSet).toHaveBeenCalled();
    });
  });

  // ─── abandonWorkflow ──────────────────────────────────────────────

  describe("abandonWorkflow", () => {
    it("should set session status to abandoned", async () => {
      await abandonWorkflow(1);
      expect(mockUpdate).toHaveBeenCalled();
      expect(mockUpdateSet).toHaveBeenCalledWith(
        expect.objectContaining({ status: "abandoned" })
      );
    });
  });

  // ─── getWorkflowHistory ───────────────────────────────────────────

  describe("getWorkflowHistory", () => {
    it("should query sessions for the user with limit", async () => {
      mockSelectLimit.mockResolvedValue([]);
      const result = await getWorkflowHistory("user-123", 10);
      expect(mockSelect).toHaveBeenCalled();
      expect(result).toEqual([]);
    });

    it("should default to limit of 20", async () => {
      mockSelectLimit.mockResolvedValue([]);
      await getWorkflowHistory("user-123");
      expect(mockSelectLimit).toHaveBeenCalledWith(20);
    });
  });
});

// ─── Workflow Router Schema Tests ───────────────────────────────────

describe("Workflow Router Schema Validation", () => {
  it("workflow definitions should match between UI and persistence", () => {
    const persistenceIds = WORKFLOW_DEFINITIONS.map(w => w.workflowId);
    const expectedIds = [
      "new-engagement",
      "domain-recon",
      "detection-validation",
      "phishing-campaign",
      "cloud-security",
      "compliance-report",
    ];
    for (const id of expectedIds) {
      expect(persistenceIds).toContain(id);
    }
  });

  it("new-engagement workflow should have correct steps", () => {
    const wf = WORKFLOW_DEFINITIONS.find(w => w.workflowId === "new-engagement");
    expect(wf).toBeDefined();
    expect(wf!.steps.length).toBe(6);
    expect(wf!.steps[0].stepId).toBe("define-roe");
  });

  it("domain-recon workflow should have correct steps", () => {
    const wf = WORKFLOW_DEFINITIONS.find(w => w.workflowId === "domain-recon");
    expect(wf).toBeDefined();
    expect(wf!.steps.length).toBe(5);
    expect(wf!.steps[0].stepId).toBe("input-domain");
  });

  it("phishing-campaign workflow should have correct steps", () => {
    const wf = WORKFLOW_DEFINITIONS.find(w => w.workflowId === "phishing-campaign");
    expect(wf).toBeDefined();
    expect(wf!.steps.length).toBe(5);
    expect(wf!.steps[0].stepId).toBe("create-template");
  });

  it("compliance-report workflow should have correct steps", () => {
    const wf = WORKFLOW_DEFINITIONS.find(w => w.workflowId === "compliance-report");
    expect(wf).toBeDefined();
    expect(wf!.steps.length).toBe(4);
    expect(wf!.steps[0].stepId).toBe("select-framework");
  });
});

// ─── WorkflowLauncher UI Integration Tests ──────────────────────────

describe("WorkflowLauncher UI Integration", () => {
  it("UI workflow IDs should match persistence workflow IDs", () => {
    const uiWorkflowIds = [
      "new-engagement",
      "domain-recon",
      "detection-validation",
      "phishing-campaign",
      "cloud-security",
      "compliance-report",
    ];
    const persistenceIds = WORKFLOW_DEFINITIONS.map(w => w.workflowId);
    for (const id of uiWorkflowIds) {
      expect(persistenceIds).toContain(id);
    }
  });

  it("persistence definitions should have steps for all UI workflows", () => {
    for (const def of WORKFLOW_DEFINITIONS) {
      expect(def.steps.length).toBeGreaterThan(0);
      expect(def.workflowName).toBeTruthy();
    }
  });

  it("all step routes should start with /", () => {
    for (const def of WORKFLOW_DEFINITIONS) {
      for (const step of def.steps) {
        expect(step.route).toMatch(/^\//);
      }
    }
  });
});
