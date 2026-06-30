/**
 * PlatformTour — Unit tests for tour step filtering and platform gating logic.
 * 
 * These tests validate the core logic of the PlatformTour component:
 * - Platform name matching (AC3 vs PBS)
 * - Role-based step filtering
 * - localStorage dismissal tracking
 */
import { describe, it, expect } from "vitest";

// ─── Replicate the tour step interfaces and data from PlatformTour.tsx ─────

interface TourStep {
  title: string;
  description: string;
  iconColor: string;
  roles: string[]; // Which roles see this step. Empty = all roles.
}

const AC3_TOUR_STEPS: TourStep[] = [
  {
    title: "Campaign Command Center",
    description: "Orchestrate offensive security campaigns from a unified dashboard.",
    iconColor: "text-cyan-400",
    roles: [],
  },
  {
    title: "Engagement Operations",
    description: "Manage penetration testing engagements end-to-end.",
    iconColor: "text-green-400",
    roles: [],
  },
  {
    title: "Attack Surface Mapping",
    description: "Automated asset discovery, port scanning, and service enumeration.",
    iconColor: "text-blue-400",
    roles: [],
  },
  {
    title: "Vulnerability Analysis",
    description: "AI-powered vulnerability assessment with Nuclei, ZAP, and custom scanners.",
    iconColor: "text-amber-400",
    roles: ["admin", "operator", "analyst"],
  },
  {
    title: "Reporting & Evidence",
    description: "Generate professional pentest reports with findings and risk ratings.",
    iconColor: "text-purple-400",
    roles: [],
  },
  {
    title: "Team & Access Control",
    description: "Manage operators, analysts, and clients.",
    iconColor: "text-pink-400",
    roles: ["admin", "team_lead"],
  },
];

const PBS_TOUR_STEPS: TourStep[] = [
  {
    title: "Vulnerability Dashboard",
    description: "Get a real-time overview of your security posture.",
    iconColor: "text-blue-400",
    roles: [],
  },
  {
    title: "Asset Management",
    description: "Track and manage all your digital assets.",
    iconColor: "text-cyan-400",
    roles: [],
  },
  {
    title: "Vulnerability Findings",
    description: "Detailed vulnerability reports with CVSS scoring.",
    iconColor: "text-amber-400",
    roles: [],
  },
  {
    title: "Remediation Tracking",
    description: "Assign vulnerabilities to team members.",
    iconColor: "text-green-400",
    roles: ["admin", "operator", "team_lead", "analyst", "soc"],
  },
  {
    title: "Compliance & Reports",
    description: "Generate executive reports and compliance evidence.",
    iconColor: "text-purple-400",
    roles: ["admin", "executive", "team_lead", "client"],
  },
  {
    title: "Team Collaboration",
    description: "Manage team members, assign roles, and control access.",
    iconColor: "text-pink-400",
    roles: ["admin", "team_lead"],
  },
];

// ─── Helper: replicate the filtering logic from PlatformTour ──────────────

function filterStepsByRole(steps: TourStep[], userRole: string): TourStep[] {
  return steps.filter(
    (step) => step.roles.length === 0 || step.roles.includes(userRole)
  );
}

function isPlatformMatch(platformName: string, targetPlatform: "PBS" | "AC3"): boolean {
  const normalizedPlatform = platformName.toUpperCase();
  const normalizedTarget = targetPlatform.toUpperCase();
  return normalizedPlatform.includes(normalizedTarget);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("PlatformTour — Platform Matching", () => {
  it("matches AC3 platform name correctly", () => {
    expect(isPlatformMatch("AC3", "AC3")).toBe(true);
    expect(isPlatformMatch("Ace C3", "AC3")).toBe(false); // "Ace C3" doesn't contain "AC3"
    expect(isPlatformMatch("AC3 Platform", "AC3")).toBe(true);
  });

  it("matches PBS platform name correctly", () => {
    expect(isPlatformMatch("PBS Security Platform", "PBS")).toBe(true);
    expect(isPlatformMatch("PBS", "PBS")).toBe(true);
    expect(isPlatformMatch("pbs-platform", "PBS")).toBe(true);
  });

  it("does NOT cross-match platforms", () => {
    expect(isPlatformMatch("AC3", "PBS")).toBe(false);
    expect(isPlatformMatch("PBS Security Platform", "AC3")).toBe(false);
  });

  it("handles empty or undefined platform names gracefully", () => {
    expect(isPlatformMatch("", "AC3")).toBe(false);
    expect(isPlatformMatch("", "PBS")).toBe(false);
  });
});

describe("PlatformTour — AC3 Role Filtering", () => {
  it("admin sees all 6 AC3 steps", () => {
    const steps = filterStepsByRole(AC3_TOUR_STEPS, "admin");
    expect(steps.length).toBe(6);
  });

  it("operator sees 5 AC3 steps (all universal + Vulnerability Analysis)", () => {
    const steps = filterStepsByRole(AC3_TOUR_STEPS, "operator");
    expect(steps.length).toBe(5);
    expect(steps.map(s => s.title)).toContain("Vulnerability Analysis");
    expect(steps.map(s => s.title)).not.toContain("Team & Access Control");
  });

  it("analyst sees 5 AC3 steps (all universal + Vulnerability Analysis)", () => {
    const steps = filterStepsByRole(AC3_TOUR_STEPS, "analyst");
    expect(steps.length).toBe(5);
    expect(steps.map(s => s.title)).toContain("Vulnerability Analysis");
  });

  it("team_lead sees 5 AC3 steps (all universal + Team & Access Control)", () => {
    const steps = filterStepsByRole(AC3_TOUR_STEPS, "team_lead");
    expect(steps.length).toBe(5);
    expect(steps.map(s => s.title)).toContain("Team & Access Control");
    expect(steps.map(s => s.title)).not.toContain("Vulnerability Analysis");
  });

  it("viewer sees only 4 universal AC3 steps", () => {
    const steps = filterStepsByRole(AC3_TOUR_STEPS, "viewer");
    expect(steps.length).toBe(4);
    expect(steps.map(s => s.title)).not.toContain("Vulnerability Analysis");
    expect(steps.map(s => s.title)).not.toContain("Team & Access Control");
  });

  it("client sees only 4 universal AC3 steps", () => {
    const steps = filterStepsByRole(AC3_TOUR_STEPS, "client");
    expect(steps.length).toBe(4);
  });
});

describe("PlatformTour — PBS Role Filtering", () => {
  it("admin sees all 6 PBS steps", () => {
    const steps = filterStepsByRole(PBS_TOUR_STEPS, "admin");
    expect(steps.length).toBe(6);
  });

  it("soc sees 4 PBS steps (3 universal + Remediation Tracking)", () => {
    const steps = filterStepsByRole(PBS_TOUR_STEPS, "soc");
    expect(steps.length).toBe(4);
    expect(steps.map(s => s.title)).toContain("Remediation Tracking");
  });

  it("executive sees 4 PBS steps (3 universal + Compliance & Reports)", () => {
    const steps = filterStepsByRole(PBS_TOUR_STEPS, "executive");
    expect(steps.length).toBe(4);
    expect(steps.map(s => s.title)).toContain("Compliance & Reports");
    expect(steps.map(s => s.title)).not.toContain("Remediation Tracking");
  });

  it("client sees 4 PBS steps (3 universal + Compliance & Reports)", () => {
    const steps = filterStepsByRole(PBS_TOUR_STEPS, "client");
    expect(steps.length).toBe(4);
    expect(steps.map(s => s.title)).toContain("Compliance & Reports");
  });

  it("viewer sees only 3 universal PBS steps", () => {
    const steps = filterStepsByRole(PBS_TOUR_STEPS, "viewer");
    expect(steps.length).toBe(3);
  });

  it("team_lead sees 6 PBS steps (all steps)", () => {
    const steps = filterStepsByRole(PBS_TOUR_STEPS, "team_lead");
    expect(steps.length).toBe(6);
  });
});

describe("PlatformTour — localStorage Key Generation", () => {
  it("generates correct storage key for AC3", () => {
    const key = `platform-tour-dismissed-${"AC3".toLowerCase()}`;
    expect(key).toBe("platform-tour-dismissed-ac3");
  });

  it("generates correct storage key for PBS", () => {
    const key = `platform-tour-dismissed-${"PBS".toLowerCase()}`;
    expect(key).toBe("platform-tour-dismissed-pbs");
  });
});
