import { describe, it, expect } from "vitest";
import {
  getNistControlsForSignal,
  getFedrampTimeline,
  calculateFedrampDeadline,
  getPrimaryNistControl,
  getSignalToNistMappings,
  aggregateNistControls,
} from "./lib/nist-control-mapper";
import {
  getReportBlueprint,
  buildSectionOutline,
  REPORT_BLUEPRINTS,
} from "./lib/report-section-blueprints";

// ─── NIST Control Mapper ────────────────────────────────────────────────────

describe("NIST Control Mapper", () => {
  it("maps credential_exposure to IA-5 controls", () => {
    const controls = getNistControlsForSignal("credential_exposure");
    expect(controls).toBeDefined();
    expect(controls.length).toBeGreaterThan(0);
    expect(controls.some((c) => c.controlId.startsWith("IA-5"))).toBe(true);
  });

  it("maps high_volume_breach to IA-5 controls", () => {
    const controls = getNistControlsForSignal("high_volume_breach");
    expect(controls).toBeDefined();
    expect(controls.some((c) => c.controlId.startsWith("IA-5"))).toBe(true);
  });

  it("maps admin_panel_exposed to AC controls", () => {
    const controls = getNistControlsForSignal("admin_panel_exposed");
    expect(controls).toBeDefined();
    expect(controls.some((c) => c.familyCode === "AC")).toBe(true);
  });

  it("maps expired_cert to SC controls", () => {
    const controls = getNistControlsForSignal("expired_cert");
    expect(controls).toBeDefined();
    expect(controls.some((c) => c.familyCode === "SC")).toBe(true);
  });

  it("maps missing_spf to SC controls", () => {
    const controls = getNistControlsForSignal("missing_spf");
    expect(controls).toBeDefined();
    expect(controls.some((c) => c.familyCode === "SC")).toBe(true);
  });

  it("returns empty array for unknown signal types", () => {
    const controls = getNistControlsForSignal("nonexistent_signal_type");
    expect(controls).toEqual([]);
  });

  it("has mappings for all major signal categories", () => {
    const expectedTypes = [
      "credential_exposure",
      "high_volume_breach",
      "admin_panel_exposed",
      "expired_cert",
      "missing_spf",
      "subdomain_takeover",
    ];
    for (const type of expectedTypes) {
      const controls = getNistControlsForSignal(type);
      expect(controls.length).toBeGreaterThan(0);
    }
  });

  it("getPrimaryNistControl returns first mapped control", () => {
    const primary = getPrimaryNistControl("credential_exposure");
    expect(primary).toBe("IA-5");
  });

  it("getPrimaryNistControl returns null for unknown type", () => {
    const primary = getPrimaryNistControl("nonexistent");
    expect(primary).toBeNull();
  });

  it("getSignalToNistMappings returns a mapping object", () => {
    const mappings = getSignalToNistMappings();
    expect(mappings).toBeDefined();
    expect(Object.keys(mappings).length).toBeGreaterThan(0);
    expect(mappings["credential_exposure"]).toBeDefined();
    expect(mappings["credential_exposure"]).toContain("IA-5");
  });
});

// ─── FedRAMP Deadlines ──────────────────────────────────────────────────────

describe("FedRAMP Remediation Timelines", () => {
  it("returns 30-day timeline for critical severity", () => {
    const timeline = getFedrampTimeline("critical");
    expect(timeline).toBeDefined();
    expect(timeline.remediationDays).toBe(30);
  });

  it("returns 30-day timeline for high severity", () => {
    const timeline = getFedrampTimeline("high");
    expect(timeline).toBeDefined();
    expect(timeline.remediationDays).toBe(30);
  });

  it("returns 90-day timeline for medium severity", () => {
    const timeline = getFedrampTimeline("medium");
    expect(timeline).toBeDefined();
    expect(timeline.remediationDays).toBe(90);
  });

  it("returns 180-day timeline for low severity", () => {
    const timeline = getFedrampTimeline("low");
    expect(timeline).toBeDefined();
    expect(timeline.remediationDays).toBe(180);
  });

  it("returns 365-day timeline for info severity", () => {
    const timeline = getFedrampTimeline("info");
    expect(timeline).toBeDefined();
    expect(timeline.remediationDays).toBe(365);
  });

  it("calculateFedrampDeadline returns correct due date for high", () => {
    const dueDate = calculateFedrampDeadline(new Date("2025-06-15"), "high");
    expect(dueDate).toBeDefined();
    // 30 days after June 15 = ~July 15
    expect(dueDate.getTime()).toBeGreaterThan(new Date("2025-07-10").getTime());
    expect(dueDate.getTime()).toBeLessThan(new Date("2025-07-20").getTime());
  });

  it("calculateFedrampDeadline returns correct due date for low", () => {
    const dueDate = calculateFedrampDeadline(new Date("2025-06-15"), "low");
    expect(dueDate).toBeDefined();
    // 180 days after June 15 = ~Dec 12
    expect(dueDate.getTime()).toBeGreaterThan(new Date("2025-11-01").getTime());
  });

  it("timeline label includes severity", () => {
    const timeline = getFedrampTimeline("critical");
    expect(timeline.label).toContain("Critical");
    expect(timeline.label).toContain("30");
  });
});

// ─── FedRAMP SAR Blueprint ──────────────────────────────────────────────────

describe("FedRAMP SAR Report Blueprint", () => {
  it("is registered in REPORT_BLUEPRINTS", () => {
    expect(REPORT_BLUEPRINTS.fedramp_sar).toBeDefined();
    expect(REPORT_BLUEPRINTS.fedramp_sar.assessmentType).toBe("fedramp_sar");
  });

  it("has the correct display name", () => {
    const bp = REPORT_BLUEPRINTS.fedramp_sar;
    expect(bp.displayName).toContain("FedRAMP");
  });

  it("includes FedRAMP and NIST frameworks", () => {
    const bp = REPORT_BLUEPRINTS.fedramp_sar;
    expect(bp.defaultFrameworks).toContain("FedRAMP");
    expect(bp.defaultFrameworks.some((f: string) => f.includes("NIST"))).toBe(true);
  });

  it("has NIST 800-53 Control Assessment section", () => {
    const bp = REPORT_BLUEPRINTS.fedramp_sar;
    const nistSection = bp.sections.find((s: any) => s.id === "nist_control_assessment");
    expect(nistSection).toBeDefined();
    expect(nistSection!.subsections).toBeDefined();
    expect(nistSection!.subsections!.length).toBeGreaterThanOrEqual(5);
  });

  it("has POA&M Summary section with severity-based subsections", () => {
    const bp = REPORT_BLUEPRINTS.fedramp_sar;
    const poamSection = bp.sections.find((s: any) => s.id === "poam_summary");
    expect(poamSection).toBeDefined();
    expect(poamSection!.required).toBe(true);
    expect(poamSection!.subsections).toBeDefined();
    const subIds = poamSection!.subsections!.map((s: any) => s.id);
    expect(subIds).toContain("critical_high_poam");
    expect(subIds).toContain("moderate_poam");
    expect(subIds).toContain("low_poam");
  });

  it("has KSI Alignment section", () => {
    const bp = REPORT_BLUEPRINTS.fedramp_sar;
    const ksiSection = bp.sections.find((s: any) => s.id === "ksi_alignment");
    expect(ksiSection).toBeDefined();
  });

  it("has Credential Exposure Assessment section", () => {
    const bp = REPORT_BLUEPRINTS.fedramp_sar;
    const credSection = bp.sections.find((s: any) => s.id === "credential_exposure_assessment");
    expect(credSection).toBeDefined();
  });

  it("is accessible via getReportBlueprint with fedramp_sar", () => {
    const bp = getReportBlueprint("fedramp_sar");
    expect(bp.assessmentType).toBe("fedramp_sar");
  });

  it("buildSectionOutline generates valid outline for fedramp_sar", () => {
    const outline = buildSectionOutline("fedramp_sar");
    expect(outline).toContain("NIST");
    expect(outline).toContain("POA&M");
  });
});

// ─── Integration: Signal → NIST Controls → FedRAMP Deadline ─────────────────

describe("End-to-end: Signal → NIST → FedRAMP", () => {
  it("credential_exposure signal maps to IA-5 with 30-day critical deadline", () => {
    const controls = getNistControlsForSignal("credential_exposure");
    expect(controls.some((c) => c.controlId.startsWith("IA-5"))).toBe(true);
    const timeline = getFedrampTimeline("critical");
    expect(timeline.remediationDays).toBe(30);
  });

  it("expired_cert signal maps to SC controls with 90-day medium deadline", () => {
    const controls = getNistControlsForSignal("expired_cert");
    expect(controls.some((c) => c.familyCode === "SC")).toBe(true);
    const timeline = getFedrampTimeline("medium");
    expect(timeline.remediationDays).toBe(90);
  });

  it("aggregateNistControls combines controls from multiple signals", () => {
    const aggregated = aggregateNistControls(["credential_exposure", "expired_cert"]);
    expect(aggregated.length).toBeGreaterThan(0);
    // Should have controls from both IA and SC families
    const families = new Set(aggregated.map((c) => c.familyCode));
    expect(families.has("IA")).toBe(true);
    expect(families.has("SC")).toBe(true);
  });

  it("aggregateNistControls counts overlapping controls", () => {
    // Both credential_exposure and high_volume_breach map to IA-5
    const aggregated = aggregateNistControls(["credential_exposure", "high_volume_breach"]);
    const ia5 = aggregated.find((c) => c.controlId === "IA-5");
    expect(ia5).toBeDefined();
    expect(ia5!.hitCount).toBe(2);
  });
});

// ─── Signal Classifier → NIST Control Attachment ────────────────────────────

describe("Signal Classifier — NIST Control Attachment", () => {
  it("getNistControlsForSignal returns objects with controlId, controlName, family", () => {
    const controls = getNistControlsForSignal("credential_exposure");
    expect(controls.length).toBeGreaterThan(0);
    const first = controls[0];
    expect(first).toHaveProperty("controlId");
    expect(first).toHaveProperty("controlName");
    expect(first).toHaveProperty("family");
    expect(first).toHaveProperty("familyCode");
    expect(typeof first.controlId).toBe("string");
    expect(typeof first.controlName).toBe("string");
    expect(typeof first.family).toBe("string");
  });

  it("NIST controls for credential_exposure include IA-5 with proper name", () => {
    const controls = getNistControlsForSignal("credential_exposure");
    const ia5 = controls.find(c => c.controlId === "IA-5");
    expect(ia5).toBeDefined();
    expect(ia5!.controlName).toBe("Authenticator Management");
    expect(ia5!.family).toBe("Identification and Authentication");
    expect(ia5!.familyCode).toBe("IA");
  });

  it("NIST controls for missing_spf include SC-8 with proper name", () => {
    const controls = getNistControlsForSignal("missing_spf");
    const sc8 = controls.find(c => c.controlId === "SC-8");
    expect(sc8).toBeDefined();
    expect(sc8!.controlName).toBeDefined();
    expect(sc8!.family).toBe("System and Communications Protection");
    expect(sc8!.familyCode).toBe("SC");
  });

  it("aggregateNistControls deduplicates and counts controls", () => {
    const result = aggregateNistControls([
      "credential_exposure",
      "high_volume_breach",
      "missing_spf",
      "expired_cert",
    ]);
    expect(result.length).toBeGreaterThan(0);
    // Each entry should have controlId, controlName, family, signalCount
    const first = result[0];
    expect(first).toHaveProperty("controlId");
    expect(first).toHaveProperty("controlName");
    expect(first).toHaveProperty("hitCount");
    expect(first.hitCount).toBeGreaterThanOrEqual(1);
    // IA-5 should appear (from credential_exposure + high_volume_breach)
    const ia5 = result.find(r => r.controlId === "IA-5");
    expect(ia5).toBeDefined();
    expect(ia5!.hitCount).toBeGreaterThanOrEqual(2);
  });

  it("calculateFedrampDeadline returns a Date in the future", () => {
    const now = new Date();
    const deadline = calculateFedrampDeadline(now, "critical");
    expect(deadline instanceof Date).toBe(true);
    expect(deadline.getTime()).toBeGreaterThan(now.getTime());
    // Critical = 30 days
    const diffDays = Math.round((deadline.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    expect(diffDays).toBe(30);
  });
});
