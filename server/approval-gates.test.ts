import { describe, it, expect, beforeEach } from "vitest";

/**
 * Tests for:
 * 1. Auto-approve credential tests after first manual approval (precedent-based)
 * 2. Stale approval gate dismissal after server restart
 */

// Minimal mock of EngagementOpsState for testing shouldAutoApprove logic
interface MockApprovalGate {
  id: string;
  status: "pending" | "approved" | "denied";
  riskTier: string;
  resolvedBy?: string;
  resolvedAt?: number;
  title: string;
  phase: string;
  description: string;
  createdAt: number;
}

interface MockOpsState {
  trainingLabMode?: boolean;
  approvalGates: MockApprovalGate[];
  roeScopeGuard?: { roeStatus: string };
  isPaused: boolean;
  engagementId: number;
}

// Replicate the shouldAutoApprove logic from engagement-orchestrator.ts
function shouldAutoApprove(state: MockOpsState, riskTier: string): boolean {
  if (state.trainingLabMode === true) return true;

  const TIER_ORDER: Record<string, number> = { yellow: 0, orange: 1, red: 2 };
  const currentTierIdx = TIER_ORDER[riskTier] ?? -1;
  const hasManualPrecedent = state.approvalGates.some(g =>
    g.status === 'approved' &&
    g.resolvedBy &&
    !g.resolvedBy.startsWith('auto-') &&
    (TIER_ORDER[g.riskTier] ?? -1) >= currentTierIdx
  );
  if (hasManualPrecedent) return true;

  const roeStatus = state.roeScopeGuard?.roeStatus;
  if (roeStatus !== 'signed') return false;
  if (riskTier === 'red') return false;
  return true;
}

describe("Auto-Approve Credential Tests (Precedent-Based)", () => {
  let state: MockOpsState;

  beforeEach(() => {
    state = {
      approvalGates: [],
      roeScopeGuard: { roeStatus: 'unsigned' },
      isPaused: false,
      engagementId: 1,
    };
  });

  it("should NOT auto-approve orange tier when RoE is unsigned and no precedent", () => {
    expect(shouldAutoApprove(state, "orange")).toBe(false);
  });

  it("should auto-approve orange tier when RoE is signed", () => {
    state.roeScopeGuard = { roeStatus: 'signed' };
    expect(shouldAutoApprove(state, "orange")).toBe(true);
  });

  it("should NOT auto-approve red tier even when RoE is signed", () => {
    state.roeScopeGuard = { roeStatus: 'signed' };
    expect(shouldAutoApprove(state, "red")).toBe(false);
  });

  it("should auto-approve orange tier after operator manually approved an orange gate", () => {
    // Simulate: operator manually approved one credential test (orange tier)
    state.approvalGates.push({
      id: "gate-1",
      status: "approved",
      riskTier: "orange",
      resolvedBy: "operator-john",  // Manual approval (no 'auto-' prefix)
      resolvedAt: Date.now(),
      title: "Credential Test: SSH default creds",
      phase: "credential_testing",
      description: "Test SSH default credentials",
      createdAt: Date.now() - 5000,
    });

    // Next orange gate should be auto-approved
    expect(shouldAutoApprove(state, "orange")).toBe(true);
  });

  it("should auto-approve yellow tier after operator manually approved an orange gate (higher tier covers lower)", () => {
    state.approvalGates.push({
      id: "gate-1",
      status: "approved",
      riskTier: "orange",
      resolvedBy: "operator-john",
      resolvedAt: Date.now(),
      title: "Credential Test: SSH default creds",
      phase: "credential_testing",
      description: "Test SSH default credentials",
      createdAt: Date.now() - 5000,
    });

    // Yellow is lower tier than orange, so it should also be auto-approved
    expect(shouldAutoApprove(state, "yellow")).toBe(true);
  });

  it("should NOT auto-approve red tier even after operator approved orange gate", () => {
    state.approvalGates.push({
      id: "gate-1",
      status: "approved",
      riskTier: "orange",
      resolvedBy: "operator-john",
      resolvedAt: Date.now(),
      title: "Credential Test: SSH default creds",
      phase: "credential_testing",
      description: "Test SSH default credentials",
      createdAt: Date.now() - 5000,
    });

    // Red is higher tier than orange — NOT auto-approved
    expect(shouldAutoApprove(state, "red")).toBe(false);
  });

  it("should auto-approve red tier after operator manually approved a red gate", () => {
    state.approvalGates.push({
      id: "gate-1",
      status: "approved",
      riskTier: "red",
      resolvedBy: "operator-john",
      resolvedAt: Date.now(),
      title: "Exploit: CVE-2024-1234",
      phase: "exploitation",
      description: "Execute exploit",
      createdAt: Date.now() - 5000,
    });

    // After manually approving a red gate, subsequent red gates auto-approve
    expect(shouldAutoApprove(state, "red")).toBe(true);
    // And lower tiers too
    expect(shouldAutoApprove(state, "orange")).toBe(true);
    expect(shouldAutoApprove(state, "yellow")).toBe(true);
  });

  it("should NOT count auto-approved gates as manual precedent", () => {
    state.approvalGates.push({
      id: "gate-1",
      status: "approved",
      riskTier: "orange",
      resolvedBy: "auto-approval:signed-roe",  // Auto-approved, not manual
      resolvedAt: Date.now(),
      title: "Credential Test: SSH default creds",
      phase: "credential_testing",
      description: "Test SSH default credentials",
      createdAt: Date.now() - 5000,
    });

    // RoE is unsigned, so auto-approval from RoE shouldn't count as precedent
    expect(shouldAutoApprove(state, "orange")).toBe(false);
  });

  it("should auto-approve all tiers in training lab mode", () => {
    state.trainingLabMode = true;
    expect(shouldAutoApprove(state, "yellow")).toBe(true);
    expect(shouldAutoApprove(state, "orange")).toBe(true);
    expect(shouldAutoApprove(state, "red")).toBe(true);
  });
});

describe("Stale Approval Gate Dismissal", () => {
  // Replicate the dismissStaleApproval logic
  function dismissStaleApproval(
    state: MockOpsState,
    gateId: string,
    activeResolvers: Set<string>,
    resolvedBy?: string
  ): boolean {
    if (activeResolvers.has(gateId)) return false;

    const gate = state.approvalGates.find(g => g.id === gateId && g.status === 'pending');
    if (!gate) return false;

    gate.status = 'denied';
    gate.resolvedAt = Date.now();
    gate.resolvedBy = resolvedBy || 'dismissed:stale-gate';

    const hasOtherPending = state.approvalGates.some(g => g.id !== gateId && g.status === 'pending');
    if (!hasOtherPending) {
      state.isPaused = false;
    }

    return true;
  }

  it("should dismiss a stale pending gate with no active resolver", () => {
    const state: MockOpsState = {
      approvalGates: [{
        id: "stale-gate-1",
        status: "pending",
        riskTier: "orange",
        title: "Credential Test: SSH",
        phase: "credential_testing",
        description: "Test SSH creds",
        createdAt: Date.now() - 60000,
      }],
      isPaused: true,
      engagementId: 1,
    };

    const activeResolvers = new Set<string>(); // Empty — server restarted
    const result = dismissStaleApproval(state, "stale-gate-1", activeResolvers, "operator-john");

    expect(result).toBe(true);
    expect(state.approvalGates[0].status).toBe("denied");
    expect(state.approvalGates[0].resolvedBy).toBe("operator-john");
    expect(state.isPaused).toBe(false);
  });

  it("should NOT dismiss a gate that has an active resolver", () => {
    const state: MockOpsState = {
      approvalGates: [{
        id: "active-gate-1",
        status: "pending",
        riskTier: "orange",
        title: "Credential Test: SSH",
        phase: "credential_testing",
        description: "Test SSH creds",
        createdAt: Date.now() - 5000,
      }],
      isPaused: true,
      engagementId: 1,
    };

    const activeResolvers = new Set<string>(["active-gate-1"]); // Has resolver
    const result = dismissStaleApproval(state, "active-gate-1", activeResolvers);

    expect(result).toBe(false);
    expect(state.approvalGates[0].status).toBe("pending"); // Unchanged
    expect(state.isPaused).toBe(true); // Still paused
  });

  it("should NOT dismiss an already resolved gate", () => {
    const state: MockOpsState = {
      approvalGates: [{
        id: "resolved-gate-1",
        status: "approved",
        riskTier: "orange",
        resolvedBy: "operator-john",
        title: "Credential Test: SSH",
        phase: "credential_testing",
        description: "Test SSH creds",
        createdAt: Date.now() - 60000,
      }],
      isPaused: false,
      engagementId: 1,
    };

    const activeResolvers = new Set<string>();
    const result = dismissStaleApproval(state, "resolved-gate-1", activeResolvers);

    expect(result).toBe(false);
    expect(state.approvalGates[0].status).toBe("approved"); // Unchanged
  });

  it("should keep engagement paused if other pending gates remain", () => {
    const state: MockOpsState = {
      approvalGates: [
        {
          id: "stale-gate-1",
          status: "pending",
          riskTier: "orange",
          title: "Credential Test: SSH",
          phase: "credential_testing",
          description: "Test SSH creds",
          createdAt: Date.now() - 60000,
        },
        {
          id: "active-gate-2",
          status: "pending",
          riskTier: "red",
          title: "Exploit: CVE-2024-1234",
          phase: "exploitation",
          description: "Execute exploit",
          createdAt: Date.now() - 30000,
        },
      ],
      isPaused: true,
      engagementId: 1,
    };

    const activeResolvers = new Set<string>(["active-gate-2"]); // Only gate-2 has resolver
    const result = dismissStaleApproval(state, "stale-gate-1", activeResolvers, "operator-john");

    expect(result).toBe(true);
    expect(state.approvalGates[0].status).toBe("denied");
    // Still paused because active-gate-2 is still pending
    expect(state.isPaused).toBe(true);
  });
});
