import { describe, it, expect } from "vitest";

// Test the APT Scenarios data module
describe("APT Scenarios Data", () => {
  it("should export all APT and ransomware scenarios", async () => {
    const mod = await import("../client/src/data/apt-scenarios");
    expect(mod.APT_SCENARIOS.length).toBeGreaterThanOrEqual(21);
  });

  it("should have required fields for each APT scenario", async () => {
    const { APT_SCENARIOS } = await import("../client/src/data/apt-scenarios");
    for (const apt of APT_SCENARIOS) {
      expect(apt.id).toBeTruthy();
      expect(apt.name).toBeTruthy();
      expect(apt.alias).toBeTruthy();
      expect(apt.origin).toBeTruthy();
      expect(apt.description).toBeTruthy();
      expect(apt.objective).toBeTruthy();
      expect(apt.color).toBeTruthy();
      expect(apt.borderColor).toBeTruthy();
      expect(apt.techniques.length).toBeGreaterThan(0);
    }
  });

  it("should include APT29, APT28, Sandworm, and APT41", async () => {
    const { APT_SCENARIOS } = await import("../client/src/data/apt-scenarios");
    const ids = APT_SCENARIOS.map(s => s.id);
    expect(ids).toContain("apt29");
    expect(ids).toContain("apt28");
    expect(ids).toContain("sandworm");
    expect(ids).toContain("apt41");
  });

  it("should have valid ATT&CK technique IDs", async () => {
    const { APT_SCENARIOS } = await import("../client/src/data/apt-scenarios");
    for (const apt of APT_SCENARIOS) {
      for (const tech of apt.techniques) {
        expect(tech.id).toMatch(/^T\d{4}(\.\d{3})?$/);
        expect(tech.name).toBeTruthy();
        expect(tech.tactic).toBeTruthy();
        expect(tech.score).toBeGreaterThan(0);
      }
    }
  });

  it("should have Caldera profiles for APT29 and Sandworm", async () => {
    const { APT_SCENARIOS } = await import("../client/src/data/apt-scenarios");
    const apt29 = APT_SCENARIOS.find(s => s.id === "apt29");
    const sandworm = APT_SCENARIOS.find(s => s.id === "sandworm");
    expect(apt29?.calderaProfile).toBeDefined();
    expect(apt29?.calderaProfile?.atomicOrdering.length).toBeGreaterThan(0);
    expect(sandworm?.calderaProfile).toBeDefined();
    expect(sandworm?.calderaProfile?.atomicOrdering.length).toBeGreaterThan(0);
  });

  it("should have valid Navigator layers for all APT and ransomware groups", async () => {
    const { NAVIGATOR_LAYERS } = await import("../client/src/data/apt-scenarios");
    expect(Object.keys(NAVIGATOR_LAYERS).length).toBeGreaterThanOrEqual(21);
    for (const [key, layer] of Object.entries(NAVIGATOR_LAYERS)) {
      expect(layer.version).toBe("4.3");
      expect(layer.domain).toBe("enterprise-attack");
      expect(layer.techniques.length).toBeGreaterThan(0);
      for (const tech of layer.techniques) {
        expect(tech.techniqueID).toMatch(/^T\d{4}(\.\d{3})?$/);
        expect(tech.score).toBeGreaterThan(0);
      }
    }
  });

  it("should have a valid STIX bundle", async () => {
    const { STIX_BUNDLE } = await import("../client/src/data/apt-scenarios");
    expect(STIX_BUNDLE.type).toBe("bundle");
    expect(STIX_BUNDLE.id).toMatch(/^bundle--/);
    expect(STIX_BUNDLE.objects.length).toBeGreaterThan(0);
    const types = STIX_BUNDLE.objects.map(o => o.type);
    expect(types).toContain("identity");
    expect(types).toContain("campaign");
    expect(types).toContain("attack-pattern");
  });
});

// Test the Compliance Data module
describe("Compliance Data", () => {
  it("should export FedRAMP controls", async () => {
    const { FEDRAMP_CONTROLS } = await import("../client/src/data/compliance-data");
    expect(FEDRAMP_CONTROLS.length).toBeGreaterThan(0);
    for (const ctrl of FEDRAMP_CONTROLS) {
      expect(ctrl.family).toBeTruthy();
      expect(ctrl.moderate).toBeTruthy();
      expect(ctrl.high).toBeTruthy();
    }
  });

  it("should export FedRAMP requirements with all sections", async () => {
    const { FEDRAMP_REQUIREMENTS } = await import("../client/src/data/compliance-data");
    expect(FEDRAMP_REQUIREMENTS.authorization.length).toBeGreaterThan(0);
    expect(FEDRAMP_REQUIREMENTS.dataHandling.length).toBeGreaterThan(0);
    expect(FEDRAMP_REQUIREMENTS.infraIsolation.length).toBeGreaterThan(0);
    expect(FEDRAMP_REQUIREMENTS.auditReporting.length).toBeGreaterThan(0);
    expect(FEDRAMP_REQUIREMENTS.postEngagement.length).toBeGreaterThan(0);
  });

  it("should export 3 CMMC levels", async () => {
    const { CMMC_LEVELS } = await import("../client/src/data/compliance-data");
    expect(CMMC_LEVELS).toHaveLength(3);
    const levels = CMMC_LEVELS.map(l => l.level);
    expect(levels).toContain("Level 1");
    expect(levels).toContain("Level 2");
    expect(levels).toContain("Level 3");
  });

  it("should export impersonation matrix with 6 rules", async () => {
    const { IMPERSONATION_MATRIX } = await import("../client/src/data/compliance-data");
    expect(IMPERSONATION_MATRIX).toHaveLength(6);
    for (const rule of IMPERSONATION_MATRIX) {
      expect(rule.theme).toBeTruthy();
      expect(["Yes", "No"]).toContain(rule.allowed);
      expect(["Yes", "No"]).toContain(rule.requiresApproval);
      expect(["Yes", "No"]).toContain(rule.prohibited);
    }
  });

  it("should have prohibited items for classified and operational themes", async () => {
    const { IMPERSONATION_MATRIX } = await import("../client/src/data/compliance-data");
    const classified = IMPERSONATION_MATRIX.find(r => r.theme === "Classified Reference");
    const operational = IMPERSONATION_MATRIX.find(r => r.theme === "Operational Orders");
    expect(classified?.prohibited).toBe("Yes");
    expect(operational?.prohibited).toBe("Yes");
  });

  it("should export GoPhish policy template", async () => {
    const { GOPHISH_POLICY_TEMPLATE } = await import("../client/src/data/compliance-data");
    expect(GOPHISH_POLICY_TEMPLATE.subject).toBeTruthy();
    expect(GOPHISH_POLICY_TEMPLATE.body).toContain("{{.FirstName}}");
    expect(GOPHISH_POLICY_TEMPLATE.category).toBe("Governance");
    expect(GOPHISH_POLICY_TEMPLATE.riskLevel).toBe("Low");
  });

  it("should export engagement infrastructure with 4 components", async () => {
    const { ENGAGEMENT_INFRA } = await import("../client/src/data/compliance-data");
    expect(ENGAGEMENT_INFRA).toHaveLength(4);
    const names = ENGAGEMENT_INFRA.map(c => c.name);
    expect(names).toContain("Bastion");
    expect(names).toContain("App Server");
    expect(names).toContain("Mail Server");
    expect(names).toContain("Log Sink");
  });

  it("should export Terraform requirements", async () => {
    const { INFRA_REQUIREMENTS } = await import("../client/src/data/compliance-data");
    expect(INFRA_REQUIREMENTS.terraform).toBeTruthy();
    expect(INFRA_REQUIREMENTS.provider).toBeTruthy();
    expect(INFRA_REQUIREMENTS.variables.length).toBeGreaterThan(0);
    const doToken = INFRA_REQUIREMENTS.variables.find(v => v.name === "do_token");
    expect(doToken?.sensitive).toBe(true);
  });

  it("should support 4 industries", async () => {
    const { SUPPORTED_INDUSTRIES } = await import("../client/src/data/compliance-data");
    expect(SUPPORTED_INDUSTRIES).toHaveLength(4);
    expect(SUPPORTED_INDUSTRIES).toContain("Government");
    expect(SUPPORTED_INDUSTRIES).toContain("Enterprise");
  });
});
