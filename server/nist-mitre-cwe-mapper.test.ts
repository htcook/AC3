/**
 * Tests for the centralized NIST 800-53 / MITRE ATT&CK / CWE mapping engine.
 *
 * Covers:
 *   1. CWE → NIST 800-53 control mapping
 *   2. CWE → MITRE ATT&CK technique mapping
 *   3. MITRE → NIST control mapping
 *   4. Finding enrichment (combined CWE + MITRE + title inference)
 *   5. NIST gap summary generation
 *   6. Impacted families aggregation
 *   7. Edge cases (unknown CWEs, empty inputs, severity mapping)
 */

import { describe, it, expect } from "vitest";
import {
  enrichFinding,
  getNistControlsForCwe,
  getMitreTechniquesForCwe,
  getNistControlsForMitre,
  getCweDefinition,
  severityToNistPriority,
  getNistControlFamilies,
  getImpactedNistFamilies,
  generateNistGapSummary,
  CWE_TO_NIST,
  CWE_TO_MITRE,
  MITRE_TO_NIST,
  CWE_DEFINITIONS,
  NIST_CONTROL_FAMILIES,
} from "./lib/nist-mitre-cwe-mapper";

// ─── CWE → NIST Mapping ────────────────────────────────────────────────

describe("CWE → NIST 800-53 Mapping", () => {
  it("maps SQL injection (CWE-89) to SI-10, SI-16, SA-11", () => {
    const controls = getNistControlsForCwe("CWE-89");
    const ids = controls.map(c => c.controlId);
    expect(ids).toContain("SI-10");
    expect(ids).toContain("SA-11");
    expect(controls.length).toBeGreaterThanOrEqual(2);
  });

  it("maps XSS (CWE-79) to SI-10, SI-15, SC-18", () => {
    const controls = getNistControlsForCwe("CWE-79");
    const ids = controls.map(c => c.controlId);
    expect(ids).toContain("SI-10");
    expect(ids).toContain("SI-15");
    expect(ids).toContain("SC-18");
  });

  it("maps SSRF (CWE-918) to SC-7, SI-10, AC-4", () => {
    const controls = getNistControlsForCwe("CWE-918");
    const ids = controls.map(c => c.controlId);
    expect(ids).toContain("SC-7");
    expect(ids).toContain("SI-10");
  });

  it("maps hard-coded credentials (CWE-798) to IA-5, SC-12", () => {
    const controls = getNistControlsForCwe("CWE-798");
    const ids = controls.map(c => c.controlId);
    expect(ids).toContain("IA-5");
    expect(ids).toContain("SC-12");
  });

  it("maps missing authorization (CWE-862) to AC-3, AC-6", () => {
    const controls = getNistControlsForCwe("CWE-862");
    const ids = controls.map(c => c.controlId);
    expect(ids).toContain("AC-3");
    expect(ids).toContain("AC-6");
  });

  it("normalizes CWE IDs without prefix", () => {
    const controls = getNistControlsForCwe("89");
    expect(controls.length).toBeGreaterThanOrEqual(2);
    expect(controls[0].controlId).toBe("SI-10");
  });

  it("returns empty array for unknown CWE", () => {
    const controls = getNistControlsForCwe("CWE-99999");
    expect(controls).toEqual([]);
  });

  it("includes correct family metadata", () => {
    const controls = getNistControlsForCwe("CWE-89");
    const si10 = controls.find(c => c.controlId === "SI-10");
    expect(si10).toBeDefined();
    expect(si10!.family).toBe("System and Information Integrity");
    expect(si10!.familyCode).toBe("SI");
    expect(si10!.baseline).toBe("moderate");
  });

  it("covers all OWASP Top 10 categories", () => {
    // A01: Broken Access Control
    expect(getNistControlsForCwe("CWE-284").length).toBeGreaterThan(0);
    // A02: Cryptographic Failures
    expect(getNistControlsForCwe("CWE-327").length).toBeGreaterThan(0);
    // A03: Injection
    expect(getNistControlsForCwe("CWE-89").length).toBeGreaterThan(0);
    // A04: Insecure Design (via CWE-502 deserialization)
    expect(getNistControlsForCwe("CWE-502").length).toBeGreaterThan(0);
    // A05: Security Misconfiguration
    expect(getNistControlsForCwe("CWE-16").length).toBeGreaterThan(0);
    // A06: Vulnerable Components
    expect(getNistControlsForCwe("CWE-1104").length).toBeGreaterThan(0);
    // A07: Auth Failures
    expect(getNistControlsForCwe("CWE-287").length).toBeGreaterThan(0);
    // A08: Software/Data Integrity (via CWE-502)
    expect(getNistControlsForCwe("CWE-502").length).toBeGreaterThan(0);
    // A09: Logging Failures
    expect(getNistControlsForCwe("CWE-778").length).toBeGreaterThan(0);
    // A10: SSRF
    expect(getNistControlsForCwe("CWE-918").length).toBeGreaterThan(0);
  });
});

// ─── CWE → MITRE ATT&CK Mapping ────────────────────────────────────────

describe("CWE → MITRE ATT&CK Mapping", () => {
  it("maps SQL injection (CWE-89) to T1190 (Exploit Public-Facing Application)", () => {
    const techniques = getMitreTechniquesForCwe("CWE-89");
    const ids = techniques.map(t => t.techniqueId);
    expect(ids).toContain("T1190");
  });

  it("maps OS command injection (CWE-78) to T1059 and T1190", () => {
    const techniques = getMitreTechniquesForCwe("CWE-78");
    const ids = techniques.map(t => t.techniqueId);
    expect(ids).toContain("T1059");
    expect(ids).toContain("T1190");
  });

  it("maps XSS (CWE-79) to T1189 (Drive-by Compromise)", () => {
    const techniques = getMitreTechniquesForCwe("CWE-79");
    const ids = techniques.map(t => t.techniqueId);
    expect(ids).toContain("T1189");
  });

  it("maps hard-coded credentials (CWE-798) to T1552.001 and T1078", () => {
    const techniques = getMitreTechniquesForCwe("CWE-798");
    const ids = techniques.map(t => t.techniqueId);
    expect(ids).toContain("T1552.001");
    expect(ids).toContain("T1078");
  });

  it("maps SSRF (CWE-918) to T1090 and T1552.005", () => {
    const techniques = getMitreTechniquesForCwe("CWE-918");
    const ids = techniques.map(t => t.techniqueId);
    expect(ids).toContain("T1090");
    expect(ids).toContain("T1552.005");
  });

  it("includes tactic information", () => {
    const techniques = getMitreTechniquesForCwe("CWE-89");
    const t1190 = techniques.find(t => t.techniqueId === "T1190");
    expect(t1190).toBeDefined();
    expect(t1190!.tactic).toBe("Initial Access");
    expect(t1190!.techniqueName).toBe("Exploit Public-Facing Application");
  });

  it("includes sub-technique parent references", () => {
    const techniques = getMitreTechniquesForCwe("CWE-798");
    const subTech = techniques.find(t => t.techniqueId === "T1552.001");
    expect(subTech).toBeDefined();
    expect(subTech!.parentId).toBe("T1552");
  });

  it("returns empty array for unknown CWE", () => {
    const techniques = getMitreTechniquesForCwe("CWE-99999");
    expect(techniques).toEqual([]);
  });
});

// ─── MITRE → NIST Mapping ───────────────────────────────────────────────

describe("MITRE ATT&CK → NIST 800-53 Mapping", () => {
  it("maps T1190 (Exploit Public-Facing Application) to SI-10, SC-7, SI-2, RA-5, SA-11", () => {
    const controls = getNistControlsForMitre("T1190");
    expect(controls).toContain("SI-10");
    expect(controls).toContain("SC-7");
    expect(controls).toContain("SA-11");
  });

  it("maps T1110 (Brute Force) to AC-7, IA-5, IA-2", () => {
    const controls = getNistControlsForMitre("T1110");
    expect(controls).toContain("AC-7");
    expect(controls).toContain("IA-5");
  });

  it("maps T1059 (Command and Scripting Interpreter) to CM-7, SI-10, AC-6", () => {
    const controls = getNistControlsForMitre("T1059");
    expect(controls).toContain("CM-7");
    expect(controls).toContain("SI-10");
  });

  it("maps sub-techniques like T1552.001 to NIST controls", () => {
    const controls = getNistControlsForMitre("T1552.001");
    expect(controls).toContain("IA-5");
    expect(controls).toContain("CM-6");
  });

  it("returns empty array for unknown technique", () => {
    const controls = getNistControlsForMitre("T9999");
    expect(controls).toEqual([]);
  });
});

// ─── CWE Definitions ───────────────────────────────────────────────────

describe("CWE Definitions", () => {
  it("returns definition for known CWE", () => {
    const def = getCweDefinition("CWE-89");
    expect(def).toBeDefined();
    expect(def!.cweName).toContain("SQL");
    expect(def!.category).toBe("Injection");
  });

  it("normalizes CWE IDs without prefix", () => {
    const def = getCweDefinition("79");
    expect(def).toBeDefined();
    expect(def!.cweId).toBe("CWE-79");
  });

  it("returns null for unknown CWE", () => {
    const def = getCweDefinition("CWE-99999");
    expect(def).toBeNull();
  });

  it("has definitions for all mapped CWEs", () => {
    const allMappedCwes = new Set([
      ...Object.keys(CWE_TO_NIST),
      ...Object.keys(CWE_TO_MITRE),
    ]);
    for (const cweId of allMappedCwes) {
      const def = CWE_DEFINITIONS[cweId];
      expect(def, `Missing definition for ${cweId}`).toBeDefined();
    }
  });
});

// ─── Severity → NIST Priority ───────────────────────────────────────────

describe("Severity to NIST Priority", () => {
  it("maps critical to P1", () => {
    expect(severityToNistPriority("critical")).toBe("P1");
  });

  it("maps high to P2", () => {
    expect(severityToNistPriority("high")).toBe("P2");
  });

  it("maps medium to P3", () => {
    expect(severityToNistPriority("medium")).toBe("P3");
  });

  it("maps moderate to P3", () => {
    expect(severityToNistPriority("moderate")).toBe("P3");
  });

  it("maps low to P4", () => {
    expect(severityToNistPriority("low")).toBe("P4");
  });

  it("maps informational to P4", () => {
    expect(severityToNistPriority("informational")).toBe("P4");
  });

  it("maps undefined to P4", () => {
    expect(severityToNistPriority(undefined)).toBe("P4");
  });
});

// ─── Finding Enrichment ─────────────────────────────────────────────────

describe("Finding Enrichment", () => {
  it("enriches a finding with CWE-89 (SQL Injection)", () => {
    const result = enrichFinding({
      cwes: ["CWE-89"],
      severity: "critical",
    });

    expect(result.cwes.length).toBe(1);
    expect(result.cwes[0].cweId).toBe("CWE-89");
    expect(result.nistControls.length).toBeGreaterThan(0);
    expect(result.mitreTechniques.length).toBeGreaterThan(0);
    expect(result.nistPriority).toBe("P1");

    // Should include SI-10 from CWE mapping
    expect(result.nistControls.some(c => c.controlId === "SI-10")).toBe(true);
    // Should include T1190 from CWE mapping
    expect(result.mitreTechniques.some(t => t.techniqueId === "T1190")).toBe(true);
  });

  it("enriches a finding with multiple CWEs", () => {
    const result = enrichFinding({
      cwes: ["CWE-89", "CWE-79"],
      severity: "high",
    });

    expect(result.cwes.length).toBe(2);
    expect(result.nistPriority).toBe("P2");
    // Should have controls from both CWEs
    expect(result.nistControls.some(c => c.controlId === "SI-10")).toBe(true);
    expect(result.nistControls.some(c => c.controlId === "SI-15")).toBe(true); // from CWE-79
  });

  it("enriches a finding with MITRE technique IDs", () => {
    const result = enrichFinding({
      techniqueIds: ["T1190", "T1059"],
      severity: "high",
    });

    // Should resolve NIST controls from MITRE mapping
    expect(result.nistControls.length).toBeGreaterThan(0);
    expect(result.nistControls.some(c => c.controlId === "SI-10")).toBe(true); // from T1190
    expect(result.nistControls.some(c => c.controlId === "CM-7")).toBe(true); // from T1059
  });

  it("enriches a finding with both CWEs and MITRE techniques", () => {
    const result = enrichFinding({
      cwes: ["CWE-89"],
      techniqueIds: ["T1059"],
      severity: "critical",
    });

    // Should have controls from both sources (deduplicated)
    expect(result.nistControls.some(c => c.controlId === "SI-10")).toBe(true); // from CWE-89 and T1190
    expect(result.nistControls.some(c => c.controlId === "CM-7")).toBe(true); // from T1059
  });

  it("falls back to title/category inference when no CWE/technique data", () => {
    const result = enrichFinding({
      title: "SQL Injection in login form",
      severity: "high",
    });

    // Should infer from title keywords
    expect(result.nistControls.length).toBeGreaterThan(0);
    expect(result.nistControls.some(c => c.controlId === "SI-10")).toBe(true);
  });

  it("infers SSRF from title", () => {
    const result = enrichFinding({
      title: "Server-Side Request Forgery (SSRF) in API endpoint",
      severity: "high",
    });

    expect(result.nistControls.some(c => c.controlId === "SC-7")).toBe(true);
  });

  it("infers authentication issues from title", () => {
    const result = enrichFinding({
      title: "Weak password policy allows brute force attacks",
      severity: "medium",
    });

    expect(result.nistControls.some(c => c.controlId === "IA-2" || c.controlId === "IA-5" || c.controlId === "AC-7")).toBe(true);
  });

  it("handles unknown CWE gracefully", () => {
    const result = enrichFinding({
      cwes: ["CWE-99999"],
      severity: "low",
    });

    expect(result.cwes.length).toBe(1);
    expect(result.cwes[0].cweId).toBe("CWE-99999");
    expect(result.cwes[0].category).toBe("Unknown");
    expect(result.nistPriority).toBe("P4");
  });

  it("handles empty input gracefully", () => {
    const result = enrichFinding({});
    expect(result.cwes).toEqual([]);
    expect(result.nistControls).toEqual([]);
    expect(result.mitreTechniques).toEqual([]);
    expect(result.nistPriority).toBe("P4");
  });
});

// ─── NIST Control Families ──────────────────────────────────────────────

describe("NIST Control Families", () => {
  it("returns all 20 NIST 800-53 control families", () => {
    const families = getNistControlFamilies();
    expect(Object.keys(families).length).toBe(20);
    expect(families.AC).toBe("Access Control");
    expect(families.SI).toBe("System and Information Integrity");
    expect(families.SC).toBe("System and Communications Protection");
    expect(families.IA).toBe("Identification and Authentication");
    expect(families.SR).toBe("Supply Chain Risk Management");
  });
});

// ─── Impacted Families Aggregation ──────────────────────────────────────

describe("Impacted NIST Families", () => {
  it("aggregates impacted families from multiple findings", () => {
    const families = getImpactedNistFamilies([
      { cwes: ["CWE-89"] },  // SI, SA
      { cwes: ["CWE-287"] }, // IA
      { cwes: ["CWE-284"] }, // AC
    ]);

    expect(families.length).toBeGreaterThanOrEqual(3);
    expect(families.some(f => f.familyCode === "SI")).toBe(true);
    expect(families.some(f => f.familyCode === "IA")).toBe(true);
    expect(families.some(f => f.familyCode === "AC")).toBe(true);
  });

  it("sorts by control count descending", () => {
    const families = getImpactedNistFamilies([
      { cwes: ["CWE-89", "CWE-79", "CWE-78", "CWE-22"] }, // SI should have many controls
    ]);

    // First family should have the most controls
    if (families.length > 1) {
      expect(families[0].controlCount).toBeGreaterThanOrEqual(families[1].controlCount);
    }
  });

  it("handles empty findings array", () => {
    const families = getImpactedNistFamilies([]);
    expect(families).toEqual([]);
  });
});

// ─── NIST Gap Summary ──────────────────────────────────────────────────

describe("NIST Gap Summary", () => {
  it("generates gap summary for critical findings", () => {
    const summary = generateNistGapSummary([
      { cwes: ["CWE-89"], severity: "critical" },
      { cwes: ["CWE-287"], severity: "high" },
    ]);

    expect(summary.totalControlsImpacted).toBeGreaterThan(0);
    expect(summary.criticalGaps.length).toBeGreaterThan(0);
    expect(summary.byFamily.length).toBeGreaterThan(0);
    expect(summary.coverageScore).toBeGreaterThan(0);
  });

  it("critical gaps include controls at moderate baseline with critical/high findings", () => {
    const summary = generateNistGapSummary([
      { cwes: ["CWE-89"], severity: "critical" },
    ]);

    // SI-10 is at moderate baseline and has a critical finding
    expect(summary.criticalGaps.some(c => c.controlId === "SI-10")).toBe(true);
  });

  it("byFamily includes priority levels", () => {
    const summary = generateNistGapSummary([
      { cwes: ["CWE-89"], severity: "critical" },
      { cwes: ["CWE-778"], severity: "low" },
    ]);

    const siFamily = summary.byFamily.find(f => f.familyCode === "SI");
    expect(siFamily).toBeDefined();
    expect(siFamily!.highestPriority).toBe("P1"); // critical → P1
  });

  it("handles empty findings", () => {
    const summary = generateNistGapSummary([]);
    expect(summary.totalControlsImpacted).toBe(0);
    expect(summary.criticalGaps).toEqual([]);
    expect(summary.byFamily).toEqual([]);
    expect(summary.coverageScore).toBe(0);
  });

  it("respects baseline parameter", () => {
    const lowSummary = generateNistGapSummary(
      [{ cwes: ["CWE-89"], severity: "critical" }],
      "low"
    );
    const highSummary = generateNistGapSummary(
      [{ cwes: ["CWE-89"], severity: "critical" }],
      "high"
    );

    // Low baseline has fewer total controls → higher coverage score for same findings
    expect(lowSummary.coverageScore).toBeGreaterThanOrEqual(highSummary.coverageScore);
  });
});

// ─── Data Integrity ─────────────────────────────────────────────────────

describe("Data Integrity", () => {
  it("all CWE_TO_NIST entries have valid family codes", () => {
    for (const [cweId, controls] of Object.entries(CWE_TO_NIST)) {
      for (const ctrl of controls) {
        expect(
          NIST_CONTROL_FAMILIES[ctrl.familyCode],
          `Invalid family code ${ctrl.familyCode} in ${cweId} mapping`
        ).toBeDefined();
      }
    }
  });

  it("all CWE_TO_MITRE entries have non-empty technique IDs", () => {
    for (const [cweId, techniques] of Object.entries(CWE_TO_MITRE)) {
      for (const tech of techniques) {
        expect(
          tech.techniqueId.startsWith("T"),
          `Invalid technique ID ${tech.techniqueId} in ${cweId} mapping`
        ).toBe(true);
        expect(tech.techniqueName.length).toBeGreaterThan(0);
        expect(tech.tactic.length).toBeGreaterThan(0);
      }
    }
  });

  it("all MITRE_TO_NIST entries have valid control IDs", () => {
    for (const [techId, controlIds] of Object.entries(MITRE_TO_NIST)) {
      for (const ctrlId of controlIds) {
        const familyCode = ctrlId.split("-")[0];
        expect(
          NIST_CONTROL_FAMILIES[familyCode],
          `Invalid control ${ctrlId} in ${techId} mapping`
        ).toBeDefined();
      }
    }
  });

  it("CWE_TO_NIST and CWE_TO_MITRE have significant overlap", () => {
    const nistCwes = new Set(Object.keys(CWE_TO_NIST));
    const mitreCwes = new Set(Object.keys(CWE_TO_MITRE));
    const overlap = [...nistCwes].filter(c => mitreCwes.has(c));
    // Most CWEs should have both NIST and MITRE mappings
    expect(overlap.length).toBeGreaterThan(20);
  });
});
