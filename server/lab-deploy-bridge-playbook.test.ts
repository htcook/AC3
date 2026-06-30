import { describe, it, expect } from "vitest";

// ─── Test Lab Deployer ───────────────────────────────────────────────────────

describe("Test Lab Deployer", () => {
  it("should export deployment functions", async () => {
    const mod = await import("./lib/test-lab-deployer");
    expect(mod.deployTestLab).toBeDefined();
    expect(mod.destroyTestLab).toBeDefined();
    expect(mod.getLatestDeployment).toBeDefined();
    expect(mod.getEngagementDeployments).toBeDefined();
    expect(mod.getDeploymentLogs).toBeDefined();
  });

  it("getLatestDeployment returns undefined for unknown engagement", async () => {
    const { getLatestDeployment } = await import("./lib/test-lab-deployer");
    const result = getLatestDeployment(999999);
    expect(result).toBeUndefined();
  });

  it("getEngagementDeployments returns empty array for unknown engagement", async () => {
    const { getEngagementDeployments } = await import("./lib/test-lab-deployer");
    const result = getEngagementDeployments(999999);
    expect(result).toEqual([]);
  });

  it("getDeploymentLogs returns empty array for unknown deployment", async () => {
    const { getDeploymentLogs } = await import("./lib/test-lab-deployer");
    const result = getDeploymentLogs("nonexistent-id");
    expect(result).toEqual([]);
  });

  it("destroyTestLab returns null for unknown deployment", async () => {
    const { destroyTestLab } = await import("./lib/test-lab-deployer");
    const result = await destroyTestLab("nonexistent-id");
    expect(result).toBeNull();
  });
});

// ─── Burp ↔ Test Lab Bridge ─────────────────────────────────────────────────

describe("Burp-TestLab Bridge", () => {
  it("should export bridge functions", async () => {
    const mod = await import("./lib/burp-testlab-bridge");
    expect(mod.listScanProfiles).toBeDefined();
    expect(mod.preflightCheck).toBeDefined();
    expect(mod.launchProfileScan).toBeDefined();
    expect(mod.launchFullLabScan).toBeDefined();
    expect(mod.getTotalScanTargets).toBeDefined();
  });

  it("listScanProfiles returns non-empty array of profiles", async () => {
    const { listScanProfiles } = await import("./lib/burp-testlab-bridge");
    const profiles = listScanProfiles();
    expect(profiles.length).toBeGreaterThan(0);
    profiles.forEach((p) => {
      expect(p.name).toBeTruthy();
      expect(p.description).toBeTruthy();
      expect(p.targetUrls.length).toBeGreaterThan(0);
      expect(["strict_passive", "standard", "active"]).toContain(p.scanMode);
      expect(p.priority).toBeGreaterThanOrEqual(1);
      expect(p.priority).toBeLessThanOrEqual(3);
    });
  });

  it("scan profiles have valid CWE references", async () => {
    const { listScanProfiles } = await import("./lib/burp-testlab-bridge");
    const profiles = listScanProfiles();
    profiles.forEach((p) => {
      p.targetCwes.forEach((cwe) => {
        expect(cwe).toMatch(/^CWE-\d+$/);
      });
    });
  });

  it("scan profiles have valid ATT&CK technique references", async () => {
    const { listScanProfiles } = await import("./lib/burp-testlab-bridge");
    const profiles = listScanProfiles();
    profiles.forEach((p) => {
      p.attackTechniques.forEach((t) => {
        expect(t).toMatch(/^T\d{4}/);
      });
    });
  });

  it("preflightCheck returns structured result", async () => {
    const { preflightCheck } = await import("./lib/burp-testlab-bridge");
    const result = preflightCheck(1);
    expect(result).toHaveProperty("ready");
    expect(result).toHaveProperty("labStatus");
    expect(result).toHaveProperty("issues");
    expect(result).toHaveProperty("scanTargetCount");
    expect(result).toHaveProperty("estimatedDuration");
    expect(Array.isArray(result.issues)).toBe(true);
    expect(["running", "stopped", "not_deployed", "unknown"]).toContain(result.labStatus);
  });

  it("getTotalScanTargets returns a positive number", async () => {
    const { getTotalScanTargets } = await import("./lib/burp-testlab-bridge");
    const total = getTotalScanTargets();
    expect(total).toBeGreaterThan(0);
  });
});

// ─── Nextcloud Attack Playbook ──────────────────────────────────────────────

describe("Nextcloud Attack Playbook", () => {
  it("should export playbook functions", async () => {
    const mod = await import("./lib/nextcloud-attack-playbook");
    expect(mod.generateAttackPlaybook).toBeDefined();
    expect(mod.generatePlaybookForEngagement).toBeDefined();
    expect(mod.getPlaybookStats).toBeDefined();
    expect(mod.getPhase).toBeDefined();
    expect(mod.getAutomatedTestCases).toBeDefined();
    expect(mod.getAllAttackTechniques).toBeDefined();
  });

  it("generateAttackPlaybook returns structured playbook", async () => {
    const { generateAttackPlaybook } = await import("./lib/nextcloud-attack-playbook");
    const playbook = generateAttackPlaybook("localhost:8443");
    expect(playbook).toHaveProperty("target", "localhost:8443");
    expect(playbook).toHaveProperty("phases");
    expect(playbook).toHaveProperty("totalPhases");
    expect(playbook).toHaveProperty("totalTestCases");
    expect(playbook).toHaveProperty("estimatedTotalHours");
    expect(playbook).toHaveProperty("maxBounty");
    expect(playbook.phases.length).toBeGreaterThan(0);
    expect(playbook.totalTestCases).toBeGreaterThan(0);
    expect(playbook.maxBounty).toBeGreaterThan(0);
  });

  it("playbook phases have valid structure", async () => {
    const { generateAttackPlaybook } = await import("./lib/nextcloud-attack-playbook");
    const playbook = generateAttackPlaybook("localhost:8443");
    playbook.phases.forEach((phase) => {
      expect(phase.id).toBeTruthy();
      expect(phase.name).toBeTruthy();
      expect(phase.description).toBeTruthy();
      expect(["critical", "high", "medium", "low"]).toContain(phase.priority);
      expect(phase.testCases.length).toBeGreaterThan(0);
      expect(phase.attackTechniques.length).toBeGreaterThan(0);
      expect(phase.targetCwes.length).toBeGreaterThan(0);
      expect(phase.tools.length).toBeGreaterThan(0);
      expect(phase.estimatedHours).toBeGreaterThan(0);
      expect(phase.bountyRange.min).toBeLessThanOrEqual(phase.bountyRange.max);
    });
  });

  it("test cases have valid structure", async () => {
    const { generateAttackPlaybook } = await import("./lib/nextcloud-attack-playbook");
    const playbook = generateAttackPlaybook("localhost:8443");
    playbook.phases.forEach((phase) => {
      phase.testCases.forEach((tc) => {
        expect(tc.id).toBeTruthy();
        expect(tc.name).toBeTruthy();
        expect(tc.description).toBeTruthy();
        expect(["critical", "high", "medium", "low", "informational"]).toContain(tc.severity);
        expect(tc.steps.length).toBeGreaterThan(0);
        expect(tc.expectedResult).toBeTruthy();
        expect(typeof tc.automated).toBe("boolean");
      });
    });
  });

  it("attack techniques have valid MITRE ATT&CK format", async () => {
    const { getAllAttackTechniques } = await import("./lib/nextcloud-attack-playbook");
    const techniques = getAllAttackTechniques();
    expect(techniques.length).toBeGreaterThan(0);
    techniques.forEach((t) => {
      expect(t.id).toMatch(/^T\d{4}/);
      expect(t.name).toBeTruthy();
      expect(t.tactic).toBeTruthy();
    });
  });

  it("getPhase returns correct phase by ID", async () => {
    const { generateAttackPlaybook, getPhase } = await import("./lib/nextcloud-attack-playbook");
    const playbook = generateAttackPlaybook("localhost:8443");
    const firstPhase = playbook.phases[0];
    const retrieved = getPhase(firstPhase.id);
    expect(retrieved).toBeTruthy();
    expect(retrieved!.name).toBe(firstPhase.name);
  });

  it("getPhase returns undefined for unknown phase", async () => {
    const { getPhase } = await import("./lib/nextcloud-attack-playbook");
    const result = getPhase("nonexistent-phase");
    expect(result).toBeUndefined();
  });

  it("getAutomatedTestCases returns only automated tests", async () => {
    const { getAutomatedTestCases } = await import("./lib/nextcloud-attack-playbook");
    const automated = getAutomatedTestCases();
    expect(automated.length).toBeGreaterThan(0);
    automated.forEach((tc) => {
      expect(tc.automated).toBe(true);
    });
  });

  it("getPlaybookStats returns comprehensive stats", async () => {
    const { getPlaybookStats } = await import("./lib/nextcloud-attack-playbook");
    const stats = getPlaybookStats();
    expect(stats).toHaveProperty("totalPhases");
    expect(stats).toHaveProperty("totalTestCases");
    expect(stats).toHaveProperty("automatedTestCases");
    expect(stats).toHaveProperty("manualTestCases");
    expect(stats).toHaveProperty("uniqueAttackTechniques");
    expect(stats).toHaveProperty("uniqueCwes");
    expect(stats).toHaveProperty("totalBountyRange");
    expect(stats.totalPhases).toBeGreaterThan(0);
    expect(stats.automatedTestCases + stats.manualTestCases).toBe(stats.totalTestCases);
  });

  it("generatePlaybookForEngagement customizes target host", async () => {
    const { generatePlaybookForEngagement } = await import("./lib/nextcloud-attack-playbook");
    const playbook = generatePlaybookForEngagement({
      targetDomain: "test.example.com",
    });
    // target includes port from lab config
    expect(playbook.target).toContain("test.example.com");
  });

  it("generatePlaybookForEngagement uses targetDomain when notes are provided", async () => {
    const { generatePlaybookForEngagement } = await import("./lib/nextcloud-attack-playbook");
    const playbook = generatePlaybookForEngagement({
      targetDomain: "scanserver.local",
      notes: "Test Lab URL: https://nc.scanserver.local:8443\nScan Server: scanserver.local",
    });
    expect(playbook.target).toContain("scanserver");
  });

  it("playbook covers high-value Nextcloud attack surfaces", async () => {
    const { generateAttackPlaybook } = await import("./lib/nextcloud-attack-playbook");
    const playbook = generateAttackPlaybook("localhost:8443");
    const phaseNames = playbook.phases.map((p) => p.name.toLowerCase());
    const allNames = phaseNames.join(" ");
    // Should cover key attack surfaces
    expect(allNames).toMatch(/auth|login|session/i);
    expect(allNames).toMatch(/file|share|upload/i);
    expect(allNames).toMatch(/encrypt|e2e|crypto/i);
  });
});
