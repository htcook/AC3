/**
 * Workflow State Persistence — DB helpers for saving and resuming
 * multi-step guided workflow sessions across user sessions.
 */

import { getDb } from "../db";
import { workflowSessions, workflowStepHistory } from "../../drizzle/schema";
import { eq, and, desc } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────

export interface WorkflowStepDef {
  stepId: string;
  stepName: string;
  route: string;        // The page route for this step
}

export interface WorkflowDef {
  workflowId: string;
  workflowName: string;
  steps: WorkflowStepDef[];
}

// ─── Workflow Definitions ───────────────────────────────────────────

export const WORKFLOW_DEFINITIONS: WorkflowDef[] = [
  {
    workflowId: "new-engagement",
    workflowName: "Start a New Engagement",
    steps: [
      { stepId: "define-roe", stepName: "Define Rules of Engagement", route: "/roe-builder" },
      { stepId: "run-recon", stepName: "Run Domain Reconnaissance", route: "/domain-intel" },
      { stepId: "review-findings", stepName: "Review Scan Findings", route: "/domain-intel" },
      { stepId: "score-targets", stepName: "Score & Prioritize Targets", route: "/carver-shock" },
      { stepId: "design-campaign", stepName: "Design Attack Campaign", route: "/campaign-designer" },
      { stepId: "execute-campaign", stepName: "Execute Campaign", route: "/live-attack" },
    ],
  },
  {
    workflowId: "domain-recon",
    workflowName: "Run Domain Reconnaissance",
    steps: [
      { stepId: "input-domain", stepName: "Enter Target Domain", route: "/domain-intel" },
      { stepId: "run-scan", stepName: "Run Intelligence Scan", route: "/domain-intel" },
      { stepId: "review-assets", stepName: "Review Discovered Assets", route: "/domain-intel" },
      { stepId: "review-enrichment", stepName: "Review Cross-Module Enrichment", route: "/domain-intel" },
      { stepId: "review-analysis", stepName: "Review LLM Analysis", route: "/domain-intel" },
    ],
  },
  {
    workflowId: "detection-validation",
    workflowName: "Validate Detection Coverage",
    steps: [
      { stepId: "select-techniques", stepName: "Select ATT&CK Techniques", route: "/attack-tests" },
      { stepId: "configure-siem", stepName: "Configure SIEM Connector", route: "/siem-connectors" },
      { stepId: "run-tests", stepName: "Run Detection Tests", route: "/attack-tests" },
      { stepId: "review-coverage", stepName: "Review Coverage Matrix", route: "/coverage-matrix" },
      { stepId: "purple-team", stepName: "Purple Team Analysis", route: "/purple-team" },
    ],
  },
  {
    workflowId: "phishing-campaign",
    workflowName: "Launch Phishing Campaign",
    steps: [
      { stepId: "create-template", stepName: "Create Email Template", route: "/phishing-templates" },
      { stepId: "build-landing", stepName: "Build Landing Page", route: "/landing-pages" },
      { stepId: "define-targets", stepName: "Define Target List", route: "/phishing-targets" },
      { stepId: "launch-campaign", stepName: "Launch via GoPhish", route: "/gophish" },
      { stepId: "monitor-results", stepName: "Monitor Campaign Results", route: "/gophish" },
    ],
  },
  {
    workflowId: "cloud-security",
    workflowName: "Assess Cloud Security",
    steps: [
      { stepId: "map-attack-paths", stepName: "Map Cloud Attack Paths", route: "/cloud-attack-paths" },
      { stepId: "test-credentials", stepName: "Test Cloud Credentials", route: "/credential-rotation" },
      { stepId: "validate-edr", stepName: "Validate EDR Coverage", route: "/edr-validation" },
      { stepId: "review-findings", stepName: "Review Cloud Findings", route: "/cloud-attack-paths" },
    ],
  },
  {
    workflowId: "compliance-report",
    workflowName: "Generate Compliance Report",
    steps: [
      { stepId: "select-framework", stepName: "Select Compliance Framework", route: "/compliance-mapper" },
      { stepId: "map-controls", stepName: "Map Controls to Findings", route: "/compliance-mapper" },
      { stepId: "export-oscal", stepName: "Export OSCAL Package", route: "/oscal-export" },
      { stepId: "generate-report", stepName: "Generate Final Report", route: "/report-generator" },
    ],
  },
];

// ─── Session Management ─────────────────────────────────────────────

export async function startWorkflow(userId: string, workflowId: string): Promise<number> {
  const def = WORKFLOW_DEFINITIONS.find(w => w.workflowId === workflowId);
  if (!def) throw new Error(`Unknown workflow: ${workflowId}`);

  const database = await getDb();
  if (!database) throw new Error("Database not available");
  const now = Date.now();
  const [result] = await database.insert(workflowSessions).values({
    userId,
    workflowId,
    workflowName: def.workflowName,
    currentStepIndex: 0,
    totalSteps: def.steps.length,
    status: "in_progress",
    stepData: {},
    contextData: {},
    startedAt: now,
    lastActivityAt: now,
  });

  const sessionId = result.insertId;

  // Create step history entries for all steps
  for (let i = 0; i < def.steps.length; i++) {
    await database.insert(workflowStepHistory).values({
      sessionId,
      stepIndex: i,
      stepId: def.steps[i].stepId,
      stepName: def.steps[i].stepName,
      status: i === 0 ? "in_progress" : "pending",
      startedAt: i === 0 ? now : undefined,
    });
  }

  return sessionId;
}

export async function getActiveWorkflows(userId: string) {
  const database = await getDb();
  if (!database) throw new Error("Database not available");
  return database
    .select()
    .from(workflowSessions)
    .where(and(eq(workflowSessions.userId, userId), eq(workflowSessions.status, "in_progress")))
    .orderBy(desc(workflowSessions.lastActivityAt));
}

export async function getWorkflowSession(sessionId: number) {
  const database = await getDb();
  if (!database) throw new Error("Database not available");
  const [session] = await database
    .select()
    .from(workflowSessions)
    .where(eq(workflowSessions.id, sessionId));

  if (!session) return null;

  const steps = await database
    .select()
    .from(workflowStepHistory)
    .where(eq(workflowStepHistory.sessionId, sessionId))
    .orderBy(workflowStepHistory.stepIndex);

  const def = WORKFLOW_DEFINITIONS.find(w => w.workflowId === session.workflowId);

  return { ...session, steps, definition: def };
}

export async function advanceWorkflowStep(
  sessionId: number,
  completedStepIndex: number,
  outputData?: Record<string, any>,
  linkedEntity?: { type: string; id: string }
) {
  const database = await getDb();
  if (!database) throw new Error("Database not available");
  const now = Date.now();

  // Mark current step as completed
  const [currentStep] = await database
    .select()
    .from(workflowStepHistory)
    .where(and(eq(workflowStepHistory.sessionId, sessionId), eq(workflowStepHistory.stepIndex, completedStepIndex)));

  if (currentStep) {
    await database
      .update(workflowStepHistory)
      .set({
        status: "completed",
        outputData: outputData || null,
        linkedEntityType: linkedEntity?.type,
        linkedEntityId: linkedEntity?.id,
        completedAt: now,
      })
      .where(eq(workflowStepHistory.id, currentStep.id));
  }

  // Get session to check total steps
  const [session] = await database
    .select()
    .from(workflowSessions)
    .where(eq(workflowSessions.id, sessionId));

  if (!session) return null;

  const nextStepIndex = completedStepIndex + 1;

  if (nextStepIndex >= session.totalSteps) {
    // Workflow complete
    await database
      .update(workflowSessions)
      .set({
        currentStepIndex: completedStepIndex,
        status: "completed",
        lastActivityAt: now,
        completedAt: now,
      })
      .where(eq(workflowSessions.id, sessionId));
  } else {
    // Advance to next step
    await database
      .update(workflowSessions)
      .set({
        currentStepIndex: nextStepIndex,
        lastActivityAt: now,
      })
      .where(eq(workflowSessions.id, sessionId));

    // Mark next step as in_progress
    const [nextStep] = await database
      .select()
      .from(workflowStepHistory)
      .where(and(eq(workflowStepHistory.sessionId, sessionId), eq(workflowStepHistory.stepIndex, nextStepIndex)));

    if (nextStep) {
      await database
        .update(workflowStepHistory)
        .set({ status: "in_progress", startedAt: now })
        .where(eq(workflowStepHistory.id, nextStep.id));
    }
  }

  return getWorkflowSession(sessionId);
}

export async function updateStepData(sessionId: number, stepIndex: number, inputData: Record<string, any>) {
  const database = await getDb();
  if (!database) throw new Error("Database not available");
  const now = Date.now();

  await database
    .update(workflowStepHistory)
    .set({ inputData })
    .where(and(eq(workflowStepHistory.sessionId, sessionId), eq(workflowStepHistory.stepIndex, stepIndex)));

  // Also update session-level step data
  const [session] = await database
    .select()
    .from(workflowSessions)
    .where(eq(workflowSessions.id, sessionId));

  if (session) {
    const existingData = (session.stepData as Record<string, any>) || {};
    existingData[`step_${stepIndex}`] = inputData;

    await database
      .update(workflowSessions)
      .set({ stepData: existingData, lastActivityAt: now })
      .where(eq(workflowSessions.id, sessionId));
  }
}

export async function abandonWorkflow(sessionId: number) {
  const database = await getDb();
  if (!database) throw new Error("Database not available");
  const now = Date.now();
  await database
    .update(workflowSessions)
    .set({ status: "abandoned", lastActivityAt: now })
    .where(eq(workflowSessions.id, sessionId));
}

export async function getWorkflowHistory(userId: string, limit = 20) {
  const database = await getDb();
  if (!database) throw new Error("Database not available");
  return database
    .select()
    .from(workflowSessions)
    .where(eq(workflowSessions.userId, userId))
    .orderBy(desc(workflowSessions.lastActivityAt))
    .limit(limit);
}
