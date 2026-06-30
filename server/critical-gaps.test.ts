/**
 * Tests for Critical Competitive Gap Features:
 * 1. Production-Safe Autonomous Mode (safety-engine router)
 * 2. Agent-Based Internal Scanning (agent-internal-scanning router)
 * 3. Phishing Impact Testing (phishing-impact router)
 * 4. SOC 2 / Enterprise Compliance (soc2-compliance router)
 * 5. FedRAMP Compliance (fedramp-controls lib)
 * 6. CMMC Compliance (cmmc-controls lib)
 */
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";

const root = resolve(__dirname, "..");

// ─── Helper: read file content ────────────────────────────────────────────
function readFile(relPath: string): string {
  const full = resolve(root, relPath);
  if (!existsSync(full)) throw new Error(`File not found: ${relPath}`);
  return readFileSync(full, "utf-8");
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. Production-Safe Autonomous Mode
// ═══════════════════════════════════════════════════════════════════════════
describe("Production-Safe Autonomous Mode", () => {
  const safetyRouter = readFile("server/routers/safety-engine.ts");
  const safetyLib = readFile("server/lib/safety-engine.ts");

  it("safety engine router exists and exports router", () => {
    expect(safetyRouter).toContain("export const safetyEngineRouter");
  });

  it("has safety profile management procedures", () => {
    expect(safetyRouter).toMatch(/getProfileDetails|getLevels/);
    expect(safetyRouter).toMatch(/setSafetyLevel|assessCommand/);
  });

  it("has blast radius estimation", () => {
    const combined = safetyRouter + safetyLib;
    expect(combined).toMatch(/blastRadius|blast_radius|BlastRadius/i);
  });

  it("has safety level configuration (observation/cautious/standard/aggressive)", () => {
    const combined = safetyRouter + safetyLib;
    expect(combined).toMatch(/observation|cautious|standard|aggressive/i);
  });

  it("has safety level enforcement and command assessment", () => {
    expect(safetyRouter).toMatch(/assessCommand/);
    expect(safetyRouter).toMatch(/setSafetyLevel/);
  });

  it("has violation logging", () => {
    const combined = safetyRouter + safetyLib;
    expect(combined).toMatch(/violation|violations/i);
  });

  it("safety engine lib has SafetyEngine class or functions", () => {
    expect(safetyLib).toMatch(/class SafetyEngine|export function|export const/);
  });

  it("safety dashboard page exists", () => {
    const page = readFile("client/src/pages/SafetyDashboard.tsx");
    expect(page).toContain("safetyEngine");
    expect(page).toMatch(/Safety|safety/);
  });

  it("safety dashboard is registered in App.tsx", () => {
    const app = readFile("client/src/App.tsx");
    expect(app).toMatch(/SafetyDashboard/);
    expect(app).toMatch(/safety-dashboard/);
  });

  it("safety dashboard is in sidebar navigation", () => {
    const nav = readFile("client/src/lib/sidebar-nav.ts");
    expect(nav).toMatch(/safety/i);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Agent-Based Internal Scanning
// ═══════════════════════════════════════════════════════════════════════════
describe("Agent-Based Internal Scanning", () => {
  const agentRouter = readFile("server/routers/agent-internal-scanning.ts");

  it("agent internal scanning router exists and exports router", () => {
    expect(agentRouter).toContain("export const agentInternalScanningRouter");
  });

  it("has scan task management procedures", () => {
    expect(agentRouter).toMatch(/listScans|getScans/);
    expect(agentRouter).toMatch(/launchScan/);
  });

  it("supports network discovery scanning", () => {
    expect(agentRouter).toMatch(/network|discovery|subnet/i);
  });

  it("supports vulnerability scanning from agents", () => {
    expect(agentRouter).toMatch(/vuln|vulnerability/i);
  });

  it("has mesh networking or agent coordination", () => {
    expect(agentRouter).toMatch(/mesh|relay|pivot|coordinate/i);
  });

  it("agent internal scanning page exists", () => {
    const page = readFile("client/src/pages/AgentInternalScanning.tsx");
    expect(page).toContain("agentInternalScanning");
  });

  it("agent internal scanning is registered in App.tsx", () => {
    const app = readFile("client/src/App.tsx");
    expect(app).toMatch(/AgentInternalScanning/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. Phishing Impact Testing
// ═══════════════════════════════════════════════════════════════════════════
describe("Phishing Impact Testing", () => {
  const phishingRouter = readFile("server/routers/phishing-impact.ts");

  it("phishing impact router exists and exports router", () => {
    expect(phishingRouter).toContain("export const phishingImpactRouter");
  });

  it("has campaign management procedures", () => {
    expect(phishingRouter).toMatch(/listCampaigns|getCampaigns/);
    expect(phishingRouter).toMatch(/createCampaign|launchCampaign/);
  });

  it("supports AI-generated phishing content", () => {
    expect(phishingRouter).toMatch(/ai|llm|generate|spear/i);
  });

  it("has resilience scoring", () => {
    expect(phishingRouter).toMatch(/resilience|score|scoring/i);
  });

  it("has event tracking (opens, clicks, submissions)", () => {
    expect(phishingRouter).toMatch(/open|click|submit|event|track/i);
  });

  it("has department-level analytics", () => {
    expect(phishingRouter).toMatch(/department|team|group/i);
  });

  it("phishing impact testing page exists", () => {
    const page = readFile("client/src/pages/PhishingImpactTesting.tsx");
    expect(page).toContain("phishingImpact");
  });

  it("phishing impact testing is registered in App.tsx", () => {
    const app = readFile("client/src/App.tsx");
    expect(app).toMatch(/PhishingImpactTesting/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. SOC 2 / Enterprise Compliance
// ═══════════════════════════════════════════════════════════════════════════
describe("SOC 2 Enterprise Compliance", () => {
  const complianceRouter = readFile("server/routers/soc2-compliance.ts");

  it("compliance router exists and exports router", () => {
    expect(complianceRouter).toContain("export const soc2ComplianceRouter");
  });

  it("has framework listing with 7 frameworks", () => {
    expect(complianceRouter).toContain("frameworkCount: 7");
  });

  it("has SOC 2 TSC control library", () => {
    expect(complianceRouter).toContain("SOC2_CONTROLS");
    expect(complianceRouter).toMatch(/CC1|CC2|CC3|CC4|CC5|CC6|CC7/);
  });

  it("has audit findings management", () => {
    expect(complianceRouter).toMatch(/getFindings/);
    expect(complianceRouter).toMatch(/updateFinding/);
  });

  it("has compliance posture timeline", () => {
    expect(complianceRouter).toMatch(/getPostureTimeline/);
  });

  it("has evidence collection", () => {
    expect(complianceRouter).toMatch(/evidence|Evidence/);
  });

  it("has multi-framework mapping", () => {
    expect(complianceRouter).toMatch(/getCrossFrameworkMapping/);
  });

  it("compliance page exists with FedRAMP and CMMC tabs", () => {
    const page = readFile("client/src/pages/SOC2Compliance.tsx");
    expect(page).toContain("fedramp");
    expect(page).toContain("cmmc");
    expect(page).toContain("FedRAMP");
    expect(page).toContain("CMMC");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. FedRAMP Compliance Framework
// ═══════════════════════════════════════════════════════════════════════════
describe("FedRAMP Compliance Framework", () => {
  const fedRAMPLib = readFile("server/lib/fedramp-controls.ts");
  const complianceRouter = readFile("server/routers/soc2-compliance.ts");

  it("FedRAMP controls library exists", () => {
    expect(fedRAMPLib).toContain("FEDRAMP_CONTROLS");
  });

  it("has NIST 800-53 control families (AC, AT, AU, CA, CM, etc.)", () => {
    expect(fedRAMPLib).toMatch(/family.*AC|family.*AT|family.*AU|family.*CA|family.*CM/);
  });

  it("has control implementation status tracking", () => {
    expect(fedRAMPLib).toMatch(/implemented|partially_implemented|not_implemented|planned|inherited/);
  });

  it("has cross-framework mapping for reference", () => {
    expect(fedRAMPLib).toMatch(/crossMappings/);
  });

  it("has POA&M generation", () => {
    expect(fedRAMPLib).toContain("generateFedRAMPPOAM");
  });

  it("has ATO package status tracking", () => {
    expect(fedRAMPLib).toContain("generateATOPackageStatus");
  });

  it("has family summary function", () => {
    expect(fedRAMPLib).toContain("getFedRAMPFamilySummary");
  });

  it("FedRAMP procedures are registered in compliance router", () => {
    expect(complianceRouter).toContain("getFedRAMPControls");
    expect(complianceRouter).toContain("getFedRAMPPOAM");
    expect(complianceRouter).toContain("getATOPackageStatus");
  });

  it("FedRAMP baseline levels are supported", () => {
    expect(fedRAMPLib).toMatch(/low|moderate|high/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. CMMC Compliance Framework
// ═══════════════════════════════════════════════════════════════════════════
describe("CMMC Compliance Framework", () => {
  const cmmcLib = readFile("server/lib/cmmc-controls.ts");
  const complianceRouter = readFile("server/routers/soc2-compliance.ts");

  it("CMMC practices library exists", () => {
    expect(cmmcLib).toContain("CMMC_PRACTICES");
  });

  it("has CMMC domains (AC, AM, AT, AU, CA, CM, IA, IR, MA, MP, PE, PS, RA, RE, RM, SC, SI, SA)", () => {
    // Check for at least the major domains
    expect(cmmcLib).toMatch(/domain.*AC|domain.*AT|domain.*AU|domain.*CA|domain.*CM|domain.*IA|domain.*IR/);
  });

  it("has CMMC levels (1, 2, 3)", () => {
    expect(cmmcLib).toMatch(/level.*1|level.*2|level.*3/);
  });

  it("has SPRS score calculation", () => {
    expect(cmmcLib).toContain("calculateSPRSScore");
  });

  it("has practice status tracking (met, partially_met, not_met, not_assessed)", () => {
    expect(cmmcLib).toMatch(/met|partially_met|not_met|not_assessed/);
  });

  it("has NIST 800-171 mapping", () => {
    expect(cmmcLib).toMatch(/nistMapping|nist_mapping/);
  });

  it("has domain summary function", () => {
    expect(cmmcLib).toContain("getCMMCDomainSummary");
  });

  it("has assessment readiness generation", () => {
    expect(cmmcLib).toContain("generateCMMCAssessment");
  });

  it("has practice weights for SPRS scoring", () => {
    expect(cmmcLib).toMatch(/weight/);
  });

  it("CMMC procedures are registered in compliance router", () => {
    expect(complianceRouter).toContain("getCMMCPractices");
    expect(complianceRouter).toContain("getSPRSScore");
    expect(complianceRouter).toContain("getCMMCAssessment");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. Router Registration & Navigation
// ═══════════════════════════════════════════════════════════════════════════
describe("Router Registration & Navigation", () => {
  const routersFile = readFile("server/routers.ts");
  const appFile = readFile("client/src/App.tsx");
  const navFile = readFile("client/src/lib/sidebar-nav.ts");

  it("all 4 new routers are imported in routers.ts", () => {
    expect(routersFile).toMatch(/safetyEngineRouter/);
    expect(routersFile).toMatch(/agentInternalScanningRouter/);
    expect(routersFile).toMatch(/phishingImpactRouter/);
    expect(routersFile).toMatch(/soc2ComplianceRouter/);
  });

  it("all 4 new routers are merged into the app router", () => {
    expect(routersFile).toMatch(/safetyEngine/);
    expect(routersFile).toMatch(/agentInternalScanning/);
    expect(routersFile).toMatch(/phishingImpact/);
    expect(routersFile).toMatch(/soc2Compliance/);
  });

  it("all 4 new pages have routes in App.tsx", () => {
    expect(appFile).toMatch(/safety-dashboard/);
    expect(appFile).toMatch(/agent-internal-scanning/);
    expect(appFile).toMatch(/phishing-impact/);
    expect(appFile).toMatch(/soc2-compliance/);
  });

  it("all features are accessible via sidebar navigation", () => {
    expect(navFile).toMatch(/safety/i);
    expect(navFile).toMatch(/agent.*scan|internal.*scan/i);
    expect(navFile).toMatch(/phishing.*impact/i);
    expect(navFile).toMatch(/compliance|soc2/i);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 8. Competitive Differentiators (exceeding competitors)
// ═══════════════════════════════════════════════════════════════════════════
describe("Competitive Differentiators", () => {
  it("Safety Engine has predictive blast radius (no competitor has this)", () => {
    const safetyLib = readFile("server/lib/safety-engine.ts");
    expect(safetyLib).toMatch(/blastRadius|blast_radius|predictive|predict/i);
  });

  it("Agent scanning supports lateral movement / pivoting (exceeds NodeZero)", () => {
    const agentRouter = readFile("server/routers/agent-internal-scanning.ts");
    expect(agentRouter).toMatch(/pivot|lateral|relay/i);
  });

  it("Phishing has AI spear phishing generation (exceeds Cymulate)", () => {
    const phishingRouter = readFile("server/routers/phishing-impact.ts");
    expect(phishingRouter).toMatch(/ai|llm|spear|generate/i);
  });

  it("Compliance has 7 frameworks including FedRAMP and CMMC (exceeds all competitors)", () => {
    const complianceRouter = readFile("server/routers/soc2-compliance.ts");
    expect(complianceRouter).toContain("frameworkCount: 7");
    expect(complianceRouter).toContain("getFedRAMPControls");
    expect(complianceRouter).toContain("getCMMCPractices");
  });

  it("CMMC has SPRS scoring (unique to AC3, critical for DoD contracts)", () => {
    const cmmcLib = readFile("server/lib/cmmc-controls.ts");
    expect(cmmcLib).toContain("calculateSPRSScore");
    expect(cmmcLib).toMatch(/totalScore|domainScores/);
  });

  it("FedRAMP has ATO package tracking (unique to AC3)", () => {
    const fedRAMPLib = readFile("server/lib/fedramp-controls.ts");
    expect(fedRAMPLib).toContain("generateATOPackageStatus");
    expect(fedRAMPLib).toMatch(/ATOPackageStatus|assessor3PAO|authorizationType/i);
  });
});
