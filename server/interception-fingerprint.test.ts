import { describe, it, expect } from "vitest";

/**
 * Tests for the Interception Fingerprinting Engine, Ember Interception Knowledge,
 * EDR Evasion Catalog, and DI Scan Live Stream infrastructure.
 */

const importEngine = () => import("./lib/interception-fingerprint-engine");
const importEmber = () => import("./lib/ember-interception-knowledge");
const importCatalog = () => import("./lib/edr-evasion-catalog");

// ═══════════════════════════════════════════════════════════════════
// Interception Fingerprinting Engine
// ═══════════════════════════════════════════════════════════════════

describe("Interception Fingerprint Engine", () => {
  describe("fingerprintInterceptions — process-based detection", () => {
    it("should detect CrowdStrike Falcon from process list", async () => {
      const { fingerprintInterceptions } = await importEngine();
      const report = fingerprintInterceptions({
        target: "test-host",
        processes: [
          { name: "CSFalconService.exe", pid: 1234, path: "C:\\Program Files\\CrowdStrike\\CSFalconService.exe" },
          { name: "csagent.exe", pid: 1235 },
        ],
      });
      expect(report.findings.length).toBeGreaterThan(0);
      const csFinding = report.findings.find(f => f.vendor.toLowerCase().includes("crowdstrike"));
      expect(csFinding).toBeDefined();
      expect(csFinding!.confidence.score).toBeGreaterThan(0.5);
      expect(csFinding!.domain).toBe("endpoint");
    });

    it("should detect Microsoft Defender from process list", async () => {
      const { fingerprintInterceptions } = await importEngine();
      const report = fingerprintInterceptions({
        target: "test-host",
        processes: [
          { name: "MsSense.exe", pid: 2000 },
          { name: "MsMpEng.exe", pid: 2001 },
        ],
      });
      const defenderFinding = report.findings.find(f =>
        f.vendor.toLowerCase().includes("microsoft") && f.product.toLowerCase().includes("defender")
      );
      expect(defenderFinding).toBeDefined();
      expect(defenderFinding!.confidence.score).toBeGreaterThan(0.5);
    });

    it("should detect SentinelOne from process list", async () => {
      const { fingerprintInterceptions } = await importEngine();
      const report = fingerprintInterceptions({
        target: "test-host",
        processes: [
          { name: "SentinelAgent.exe", pid: 3000 },
          { name: "SentinelStaticEngine.exe", pid: 3001 },
        ],
      });
      const s1Finding = report.findings.find(f => f.vendor.toLowerCase().includes("sentinelone"));
      expect(s1Finding).toBeDefined();
    });

    it("should return empty findings for clean process list", async () => {
      const { fingerprintInterceptions } = await importEngine();
      const report = fingerprintInterceptions({
        target: "test-host",
        processes: [
          { name: "chrome.exe", pid: 100 },
          { name: "explorer.exe", pid: 101 },
          { name: "notepad.exe", pid: 102 },
        ],
      });
      expect(report.findings.length).toBe(0);
    });
  });

  describe("fingerprintInterceptions — HTTP header detection", () => {
    it("should detect Cloudflare WAF from headers", async () => {
      const { fingerprintInterceptions } = await importEngine();
      const report = fingerprintInterceptions({
        target: "example.com",
        httpHeaders: [
          { name: "server", value: "cloudflare", url: "https://example.com" },
          { name: "cf-ray", value: "abc123-IAD", url: "https://example.com" },
        ],
      });
      // Cloudflare is detected as part of "Various" WAF vendor entry
      const cfFinding = report.findings.find(f => f.category === "WAF" || f.domain === "network");
      expect(cfFinding).toBeDefined();
      expect(cfFinding!.domain).toBe("network");
    });

    it("should detect Akamai from headers", async () => {
      const { fingerprintInterceptions } = await importEngine();
      const report = fingerprintInterceptions({
        target: "example.com",
        httpHeaders: [
          { name: "x-akamai-transformed", value: "9 - 0 pmb=mRUM,3", url: "https://example.com" },
        ],
      });
      // Akamai is detected as part of "Various" WAF vendor entry
      const akamaiFinding = report.findings.find(f => f.category === "WAF" || f.domain === "network");
      expect(akamaiFinding).toBeDefined();
    });
  });

  describe("fingerprintInterceptions — service-based detection", () => {
    it("should detect Carbon Black from services", async () => {
      const { fingerprintInterceptions } = await importEngine();
      const report = fingerprintInterceptions({
        target: "test-host",
        services: [
          { name: "CbDefense", displayName: "Carbon Black Cloud Sensor", status: "Running" },
        ],
      });
      const cbFinding = report.findings.find(f => f.vendor.toLowerCase().includes("carbon black") || f.vendor.toLowerCase().includes("vmware"));
      expect(cbFinding).toBeDefined();
    });
  });

  describe("fingerprintInterceptions — driver-based detection", () => {
    it("should detect Sysmon from drivers", async () => {
      const { fingerprintInterceptions } = await importEngine();
      const report = fingerprintInterceptions({
        target: "test-host",
        drivers: [
          { name: "SysmonDrv", path: "C:\\Windows\\SysmonDrv.sys" },
        ],
      });
      const sysmonFinding = report.findings.find(f =>
        f.product.toLowerCase().includes("sysmon") || f.vendor.toLowerCase().includes("microsoft")
      );
      expect(sysmonFinding).toBeDefined();
      expect(sysmonFinding!.domain).toBe("host");
    });
  });

  describe("fingerprintInterceptions — report structure", () => {
    it("should return a complete InterceptionReport with summary and evasion strategy", async () => {
      const { fingerprintInterceptions } = await importEngine();
      const report = fingerprintInterceptions({
        target: "test-host",
        processes: [
          { name: "CSFalconService.exe", pid: 1234 },
          { name: "MsSense.exe", pid: 2000 },
        ],
      });
      expect(report.scanId).toBeDefined();
      expect(report.target).toBe("test-host");
      expect(report.scanTimestamp).toBeGreaterThan(0);
      expect(report.summary).toBeDefined();
      expect(report.summary.totalFindings).toBeGreaterThan(0);
      expect(report.evasionStrategy).toBeDefined();
      expect(report.evasionStrategy.approach).toBeDefined();
      expect(report.evasionStrategy.priorities).toBeDefined();
      expect(report.evasionStrategy.priorities.length).toBeGreaterThan(0);
    });

    it("should include MITRE ATT&CK mappings in findings", async () => {
      const { fingerprintInterceptions } = await importEngine();
      const report = fingerprintInterceptions({
        target: "test-host",
        processes: [{ name: "CSFalconService.exe", pid: 1234 }],
      });
      const finding = report.findings[0];
      expect(finding.mitre).toBeDefined();
      expect(finding.mitre.length).toBeGreaterThan(0);
      expect(finding.mitre[0].techniqueId).toMatch(/^T\d{4}/);
    });

    it("should include evasion playbook in findings", async () => {
      const { fingerprintInterceptions } = await importEngine();
      const report = fingerprintInterceptions({
        target: "test-host",
        processes: [{ name: "CSFalconService.exe", pid: 1234 }],
      });
      const finding = report.findings[0];
      expect(finding.evasionPlaybook).toBeDefined();
      expect(finding.evasionPlaybook.length).toBeGreaterThan(0);
    });

    it("should include OPSEC recommendations in findings", async () => {
      const { fingerprintInterceptions } = await importEngine();
      const report = fingerprintInterceptions({
        target: "test-host",
        processes: [{ name: "CSFalconService.exe", pid: 1234 }],
      });
      const finding = report.findings[0];
      expect(finding.opsecRecommendations).toBeDefined();
      expect(finding.opsecRecommendations.length).toBeGreaterThan(0);
    });
  });

  describe("buildFingerprintInputFromDIScan", () => {
    it("should extract HTTP headers and technologies from DI scan assets", async () => {
      const { buildFingerprintInputFromDIScan } = await importEngine();
      const input = buildFingerprintInputFromDIScan({
        assets: [
          {
            hostname: "www.example.com",
            headers: { server: "cloudflare", "cf-ray": "abc123" },
            technologies: ["Cloudflare", "React", "nginx"],
          },
        ],
        scan: { id: "scan-1", primaryDomain: "example.com" },
      });
      expect(input.httpHeaders).toBeDefined();
      expect(input.httpHeaders!.length).toBeGreaterThan(0);
      expect(input.technologies).toContain("Cloudflare");
      expect(input.target).toBe("example.com");
    });
  });

  describe("Confidence scoring", () => {
    it("should give higher confidence when multiple indicators match", async () => {
      const { fingerprintInterceptions } = await importEngine();
      // Single indicator
      const singleReport = fingerprintInterceptions({
        target: "test-host",
        processes: [{ name: "CSFalconService.exe", pid: 1234 }],
      });
      // Multiple indicators
      const multiReport = fingerprintInterceptions({
        target: "test-host",
        processes: [
          { name: "CSFalconService.exe", pid: 1234 },
          { name: "csagent.exe", pid: 1235 },
        ],
        services: [
          { name: "CSFalconService", displayName: "CrowdStrike Falcon Sensor Service", status: "Running" },
        ],
        drivers: [
          { name: "csagent", path: "C:\\Windows\\System32\\drivers\\CrowdStrike\\csagent.sys" },
        ],
      });
      const singleCS = singleReport.findings.find(f => f.vendor.toLowerCase().includes("crowdstrike"));
      const multiCS = multiReport.findings.find(f => f.vendor.toLowerCase().includes("crowdstrike"));
      expect(multiCS!.confidence.score).toBeGreaterThanOrEqual(singleCS!.confidence.score);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// Ember Interception Knowledge Module
// ═══════════════════════════════════════════════════════════════════

describe("Ember Interception Knowledge", () => {
  describe("generateDefenseProfileFromDIScan", () => {
    it("should generate a defense profile from DI scan data", async () => {
      const { generateDefenseProfileFromDIScan } = await importEmber();
      const profile = generateDefenseProfileFromDIScan({
        assets: [
          {
            hostname: "www.example.com",
            headers: { server: "cloudflare" },
            technologies: ["Cloudflare"],
          },
        ],
        scan: { id: "scan-1", primaryDomain: "example.com" },
        target: "example.com",
      });
      expect(profile.profileId).toBeDefined();
      expect(profile.target).toBe("example.com");
      expect(profile.source).toBe("di_scan");
      expect(profile.report).toBeDefined();
      expect(profile.emberConfigOverrides).toBeDefined();
      expect(profile.opsecAssessment).toBeDefined();
    });
  });

  describe("generateDefenseProfileFromAgentRecon", () => {
    it("should enable EDR evasion when CrowdStrike is detected", async () => {
      const { generateDefenseProfileFromAgentRecon } = await importEmber();
      const profile = generateDefenseProfileFromAgentRecon({
        target: "workstation-01",
        processes: [
          { name: "CSFalconService.exe", pid: 1234 },
          { name: "csagent.exe", pid: 1235 },
        ],
      });
      expect(profile.emberConfigOverrides.evasion.edrEvasion).toBe(true);
      expect(profile.emberConfigOverrides.evasion.memoryEncryption).toBe(true);
      expect(profile.emberConfigOverrides.evasion.sleepObfuscation).toBe(true);
    });

    it("should recommend ghost posture for heavy defense environments", async () => {
      const { generateDefenseProfileFromAgentRecon } = await importEmber();
      const profile = generateDefenseProfileFromAgentRecon({
        target: "server-01",
        processes: [
          { name: "CSFalconService.exe", pid: 1234 },
          { name: "MsSense.exe", pid: 2000 },
          { name: "SentinelAgent.exe", pid: 3000 },
        ],
        services: [
          { name: "CSFalconService", status: "Running" },
          { name: "Sense", displayName: "Windows Defender Advanced Threat Protection Service", status: "Running" },
        ],
      });
      expect(profile.opsecAssessment.riskBand).toMatch(/critical|high/);
      expect(profile.opsecAssessment.recommendedPosture).toMatch(/ghost|stealth/);
    });

    it("should recommend aggressive posture for minimal defenses", async () => {
      const { generateDefenseProfileFromAgentRecon } = await importEmber();
      const profile = generateDefenseProfileFromAgentRecon({
        target: "dev-server",
        processes: [
          { name: "node", pid: 100 },
          { name: "nginx", pid: 101 },
        ],
      });
      expect(profile.opsecAssessment.riskBand).toBe("low");
      expect(profile.opsecAssessment.recommendedPosture).toBe("aggressive");
    });
  });

  describe("getModuleEvasionRecommendations", () => {
    it("should recommend AMSI bypass before credential access when EDR detected", async () => {
      const { generateDefenseProfileFromAgentRecon, getModuleEvasionRecommendations } = await importEmber();
      const profile = generateDefenseProfileFromAgentRecon({
        target: "workstation-01",
        processes: [{ name: "MsSense.exe", pid: 2000 }],
      });
      const recs = getModuleEvasionRecommendations(profile, "ember.credential.mimikatz");
      expect(recs.preExecutionSteps.length).toBeGreaterThan(0);
      expect(recs.risk).toMatch(/high|critical/);
    });
  });

  describe("calculateOpsecAdjustment", () => {
    it("should return positive score modifier when defenses detected", async () => {
      const { generateDefenseProfileFromAgentRecon, calculateOpsecAdjustment } = await importEmber();
      const profile = generateDefenseProfileFromAgentRecon({
        target: "workstation-01",
        processes: [
          { name: "CSFalconService.exe", pid: 1234 },
          { name: "MsSense.exe", pid: 2000 },
        ],
      });
      const adjustment = calculateOpsecAdjustment(profile);
      expect(adjustment.scoreModifier).toBeGreaterThan(0);
      expect(adjustment.recommendations.length).toBeGreaterThan(0);
    });

    it("should return zero modifier when no defenses detected", async () => {
      const { generateDefenseProfileFromAgentRecon, calculateOpsecAdjustment } = await importEmber();
      const profile = generateDefenseProfileFromAgentRecon({
        target: "dev-server",
        processes: [{ name: "node", pid: 100 }],
      });
      const adjustment = calculateOpsecAdjustment(profile);
      expect(adjustment.scoreModifier).toBe(0);
    });
  });

  describe("C2 recommendations", () => {
    it("should recommend domain fronting when network monitoring detected", async () => {
      const { generateDefenseProfileFromAgentRecon } = await importEmber();
      const profile = generateDefenseProfileFromAgentRecon({
        target: "example.com",
        httpHeaders: [
          { name: "server", value: "cloudflare" },
        ],
        networkBehaviors: [
          { type: "ssl_inspection", description: "SSL inspection detected" },
        ],
      });
      // Network monitoring should trigger C2 recommendations
      expect(profile.c2Recommendations.length).toBeGreaterThan(0);
    });
  });

  describe("Beacon timing", () => {
    it("should use slow beacons when multiple EDRs detected", async () => {
      const { generateDefenseProfileFromAgentRecon } = await importEmber();
      const profile = generateDefenseProfileFromAgentRecon({
        target: "server-01",
        processes: [
          { name: "CSFalconService.exe", pid: 1234 },
          { name: "MsSense.exe", pid: 2000 },
          { name: "SentinelAgent.exe", pid: 3000 },
        ],
      });
      expect(profile.emberConfigOverrides.beacon.minInterval).toBeGreaterThanOrEqual(120000);
      expect(profile.emberConfigOverrides.beacon.jitterPercent).toBeGreaterThanOrEqual(30);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════
// EDR Evasion Catalog
// ═══════════════════════════════════════════════════════════════════

describe("EDR Evasion Catalog", () => {
  describe("getEvasionTechniquesForProduct", () => {
    it("should return techniques for CrowdStrike", async () => {
      const { getEvasionTechniquesForProduct } = await importCatalog();
      const techniques = getEvasionTechniquesForProduct("CrowdStrike");
      expect(techniques.length).toBeGreaterThan(0);
      expect(techniques.some(t => t.category === "memory")).toBe(true);
    });

    it("should return techniques for Microsoft Defender", async () => {
      const { getEvasionTechniquesForProduct } = await importCatalog();
      const techniques = getEvasionTechniquesForProduct("Microsoft Defender");
      expect(techniques.length).toBeGreaterThan(0);
    });

    it("should return empty array for unknown product", async () => {
      const { getEvasionTechniquesForProduct } = await importCatalog();
      const techniques = getEvasionTechniquesForProduct("NonExistentProduct12345");
      expect(techniques.length).toBe(0);
    });
  });

  describe("getEvasionTechniquesForGroup", () => {
    it("should return techniques for APT29", async () => {
      const { getEvasionTechniquesForGroup } = await importCatalog();
      const techniques = getEvasionTechniquesForGroup("APT29");
      expect(techniques.length).toBeGreaterThan(3);
    });

    it("should return techniques for Lazarus Group", async () => {
      const { getEvasionTechniquesForGroup } = await importCatalog();
      const techniques = getEvasionTechniquesForGroup("Lazarus");
      expect(techniques.length).toBeGreaterThan(0);
    });
  });

  describe("getEvasionTechniquesByCategory", () => {
    it("should return memory techniques", async () => {
      const { getEvasionTechniquesByCategory } = await importCatalog();
      const techniques = getEvasionTechniquesByCategory("memory");
      expect(techniques.length).toBeGreaterThan(0);
      expect(techniques.every(t => t.category === "memory")).toBe(true);
    });

    it("should return network techniques", async () => {
      const { getEvasionTechniquesByCategory } = await importCatalog();
      const techniques = getEvasionTechniquesByCategory("network");
      expect(techniques.length).toBeGreaterThan(0);
    });
  });

  describe("getEvasionTechniquesByMitre", () => {
    it("should return techniques for T1055 (Process Injection)", async () => {
      const { getEvasionTechniquesByMitre } = await importCatalog();
      const techniques = getEvasionTechniquesByMitre("T1055");
      expect(techniques.length).toBeGreaterThan(0);
    });
  });

  describe("crossReferenceEvasionStrategy", () => {
    it("should return techniques covering multiple detected products", async () => {
      const { crossReferenceEvasionStrategy } = await importCatalog();
      const result = crossReferenceEvasionStrategy(["CrowdStrike Falcon", "Microsoft Defender"]);
      expect(result.techniques.length).toBeGreaterThan(0);
      expect(result.overallCoverage).toBeGreaterThan(0);
    });

    it("should prioritize techniques that cover more products", async () => {
      const { crossReferenceEvasionStrategy } = await importCatalog();
      const result = crossReferenceEvasionStrategy(["CrowdStrike Falcon", "SentinelOne Singularity", "Microsoft Defender"]);
      // First technique should cover more products than last
      if (result.techniques.length >= 2) {
        expect(result.techniques[0].coverageScore).toBeGreaterThanOrEqual(
          result.techniques[result.techniques.length - 1].coverageScore
        );
      }
    });
  });

  describe("getEvasionCatalogSummaryForLLM", () => {
    it("should return a formatted string for LLM context", async () => {
      const { getEvasionCatalogSummaryForLLM } = await importCatalog();
      const summary = getEvasionCatalogSummaryForLLM(["CrowdStrike Falcon"]);
      expect(summary).toContain("EDR Evasion Cross-Reference");
      expect(summary).toContain("Top Evasion Techniques");
      expect(summary.length).toBeGreaterThan(100);
    });
  });

  describe("Catalog data integrity", () => {
    it("all entries should have valid MITRE IDs", async () => {
      const { EDR_EVASION_CATALOG } = await importCatalog();
      for (const entry of EDR_EVASION_CATALOG) {
        for (const mitreId of entry.mitreIds) {
          expect(mitreId).toMatch(/^T\d{4}(\.\d{3})?$/);
        }
      }
    });

    it("all entries should have non-empty required fields", async () => {
      const { EDR_EVASION_CATALOG } = await importCatalog();
      for (const entry of EDR_EVASION_CATALOG) {
        expect(entry.id).toBeTruthy();
        expect(entry.name).toBeTruthy();
        expect(entry.description).toBeTruthy();
        expect(entry.bypassesProducts.length).toBeGreaterThan(0);
        expect(entry.usedByGroups.length).toBeGreaterThan(0);
        expect(entry.implementation).toBeTruthy();
      }
    });
  });
});
