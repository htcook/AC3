import { describe, expect, it } from "vitest";

// ── Cloud Attack Paths Library Tests ─────────────────────────────────────────
describe("Cloud Attack Paths Library", () => {
  it("exports AWS, Azure, and GCP attack catalogs", async () => {
    const lib = await import("./lib/cloud-attack-paths");
    expect(lib.AWS_ATTACK_CATALOG).toBeDefined();
    expect(lib.AZURE_ATTACK_CATALOG).toBeDefined();
    expect(lib.GCP_ATTACK_CATALOG).toBeDefined();
    expect(Array.isArray(lib.AWS_ATTACK_CATALOG)).toBe(true);
    expect(Array.isArray(lib.AZURE_ATTACK_CATALOG)).toBe(true);
    expect(Array.isArray(lib.GCP_ATTACK_CATALOG)).toBe(true);
  });

  it("AWS catalog has expected attack definitions", async () => {
    const { AWS_ATTACK_CATALOG } = await import("./lib/cloud-attack-paths");
    expect(AWS_ATTACK_CATALOG.length).toBeGreaterThan(0);
    const first = AWS_ATTACK_CATALOG[0];
    expect(first).toHaveProperty("id");
    expect(first).toHaveProperty("name");
    expect(first).toHaveProperty("provider", "aws");
    expect(first).toHaveProperty("description");
    expect(first).toHaveProperty("mitreTechniques");
  });

  it("Azure catalog has expected attack definitions", async () => {
    const { AZURE_ATTACK_CATALOG } = await import("./lib/cloud-attack-paths");
    expect(AZURE_ATTACK_CATALOG.length).toBeGreaterThan(0);
    const first = AZURE_ATTACK_CATALOG[0];
    expect(first).toHaveProperty("provider", "azure");
  });

  it("GCP catalog has expected attack definitions", async () => {
    const { GCP_ATTACK_CATALOG } = await import("./lib/cloud-attack-paths");
    expect(GCP_ATTACK_CATALOG.length).toBeGreaterThan(0);
    const first = GCP_ATTACK_CATALOG[0];
    expect(first).toHaveProperty("provider", "gcp");
  });

  it("IAM misconfig checks are defined for all 3 providers", async () => {
    const { IAM_MISCONFIG_CHECKS } = await import("./lib/cloud-attack-paths");
    expect(IAM_MISCONFIG_CHECKS).toBeDefined();
    expect(typeof IAM_MISCONFIG_CHECKS).toBe("object");
    expect(IAM_MISCONFIG_CHECKS).toHaveProperty("aws");
    expect(IAM_MISCONFIG_CHECKS).toHaveProperty("azure");
    expect(IAM_MISCONFIG_CHECKS).toHaveProperty("gcp");
    expect(Array.isArray(IAM_MISCONFIG_CHECKS.aws)).toBe(true);
    expect(IAM_MISCONFIG_CHECKS.aws.length).toBeGreaterThan(0);
  });

  it("analyzeCloudProvider returns attack paths and misconfig checks", async () => {
    const { analyzeCloudProvider } = await import("./lib/cloud-attack-paths");
    const result = analyzeCloudProvider("aws", {});
    expect(result).toHaveProperty("attackPaths");
    expect(result).toHaveProperty("misconfigurations");
    expect(Array.isArray(result.attackPaths)).toBe(true);
    expect(result.attackPaths.length).toBeGreaterThan(0);
  });
});

// ── AD Attack Engine Tests ───────────────────────────────────────────────────
describe("AD Attack Engine Library", () => {
  it("exports AD attack definitions via FULL_AD_CATALOG", async () => {
    const lib = await import("./lib/ad-attack-engine");
    expect(lib.FULL_AD_CATALOG).toBeDefined();
    expect(Array.isArray(lib.FULL_AD_CATALOG)).toBe(true);
    expect(lib.FULL_AD_CATALOG.length).toBeGreaterThan(0);
  });

  it("AD attack definitions have required fields", async () => {
    const { FULL_AD_CATALOG } = await import("./lib/ad-attack-engine");
    const first = FULL_AD_CATALOG[0];
    expect(first).toHaveProperty("id");
    expect(first).toHaveProperty("name");
    expect(first).toHaveProperty("attackType");
    expect(first).toHaveProperty("mitreTechniques");
    expect(first).toHaveProperty("description");
    expect(first).toHaveProperty("prerequisites");
  });

  it("covers kerberos, credential, persistence, and delegation attack types", async () => {
    const { KERBEROS_ATTACKS, CREDENTIAL_ATTACKS, PERSISTENCE_ATTACKS, DELEGATION_ATTACKS } = await import("./lib/ad-attack-engine");
    expect(KERBEROS_ATTACKS.length).toBeGreaterThan(0);
    expect(CREDENTIAL_ATTACKS.length).toBeGreaterThan(0);
    expect(PERSISTENCE_ATTACKS.length).toBeGreaterThan(0);
    expect(DELEGATION_ATTACKS.length).toBeGreaterThan(0);
  });

  it("analyzeADEnvironment returns analysis data", async () => {
    const { analyzeADEnvironment } = await import("./lib/ad-attack-engine");
    const result = analyzeADEnvironment({ domainName: "test.local", functionalLevel: "2016" });
    expect(result).toHaveProperty("totalAttackVectors");
    expect(result).toHaveProperty("criticalCount");
    expect(result).toHaveProperty("attacks");
    expect(Array.isArray(result.attacks)).toBe(true);
    expect(result.totalAttackVectors).toBeGreaterThan(0);
  });
});

// ── EDR Validation Engine Tests ──────────────────────────────────────────────
describe("EDR Validation Engine Library", () => {
  it("exports EDR test catalog", async () => {
    const lib = await import("./lib/edr-validation");
    expect(lib.EDR_TEST_CATALOG).toBeDefined();
    expect(Array.isArray(lib.EDR_TEST_CATALOG)).toBe(true);
    expect(lib.EDR_TEST_CATALOG.length).toBeGreaterThan(0);
  });

  it("EDR test definitions have required fields", async () => {
    const { EDR_TEST_CATALOG } = await import("./lib/edr-validation");
    const first = EDR_TEST_CATALOG[0];
    expect(first).toHaveProperty("id");
    expect(first).toHaveProperty("testName");
    expect(first).toHaveProperty("category");
    expect(first).toHaveProperty("mitreTechniqueId");
    expect(first).toHaveProperty("description");
    expect(first).toHaveProperty("riskLevel");
  });

  it("covers multiple MITRE ATT&CK categories", async () => {
    const { EDR_TEST_CATALOG } = await import("./lib/edr-validation");
    const categories = new Set(EDR_TEST_CATALOG.map(t => t.category));
    expect(categories.size).toBeGreaterThanOrEqual(5);
    expect(categories.has("process_injection")).toBe(true);
    expect(categories.has("credential_access")).toBe(true);
  });

  it("exports known EDR products list", async () => {
    const { KNOWN_EDR_PRODUCTS } = await import("./lib/edr-validation");
    expect(KNOWN_EDR_PRODUCTS).toBeDefined();
    expect(Array.isArray(KNOWN_EDR_PRODUCTS)).toBe(true);
    expect(KNOWN_EDR_PRODUCTS.length).toBeGreaterThan(0);
  });

  it("calculateEDRCoverage returns valid coverage data", async () => {
    const { calculateEDRCoverage } = await import("./lib/edr-validation");
    const coverage = calculateEDRCoverage([
      { detectionResult: "detected", category: "process_injection" },
      { detectionResult: "missed", category: "credential_access" },
      { detectionResult: "partial", category: "defense_evasion" },
    ]);
    expect(coverage).toHaveProperty("detected");
    expect(coverage).toHaveProperty("missed");
    expect(typeof coverage.detected).toBe("number");
    expect(typeof coverage.missed).toBe("number");
  });
});

// ── Compliance Mapper Tests ──────────────────────────────────────────────────
describe("Compliance Mapper Library", () => {
  it("exports ALL_FRAMEWORKS with 7 frameworks", async () => {
    const lib = await import("./lib/compliance-mapper");
    expect(lib.ALL_FRAMEWORKS).toBeDefined();
    const keys = Object.keys(lib.ALL_FRAMEWORKS);
    expect(keys).toContain("soc2");
    expect(keys).toContain("iso27001");
    expect(keys).toContain("nist_csf");
    expect(keys).toContain("pci_dss");
    expect(keys).toContain("fedramp");
    expect(keys).toContain("dod_stig");
    expect(keys).toContain("cmmc");
    expect(keys.length).toBe(7);
  });

  it("SOC 2 framework has controls with required fields", async () => {
    const { ALL_FRAMEWORKS } = await import("./lib/compliance-mapper");
    const soc2 = ALL_FRAMEWORKS.soc2;
    expect(soc2.name).toBe("SOC 2 Type II");
    expect(soc2.controls.length).toBeGreaterThan(0);
    const first = soc2.controls[0];
    expect(first).toHaveProperty("controlId");
    expect(first).toHaveProperty("controlName");
    expect(first).toHaveProperty("category");
    expect(first).toHaveProperty("description");
    expect(first).toHaveProperty("testProcedures");
  });

  it("FedRAMP framework has controls", async () => {
    const { ALL_FRAMEWORKS } = await import("./lib/compliance-mapper");
    const fedramp = ALL_FRAMEWORKS.fedramp;
    expect(fedramp.name).toContain("FedRAMP");
    expect(fedramp.controls.length).toBeGreaterThan(0);
  });

  it("DoD STIG framework has controls", async () => {
    const { ALL_FRAMEWORKS } = await import("./lib/compliance-mapper");
    const stig = ALL_FRAMEWORKS.dod_stig;
    expect(stig.name).toContain("DoD STIG");
    expect(stig.controls.length).toBeGreaterThan(0);
  });

  it("CMMC 2.0 framework has 3 maturity levels", async () => {
    const { ALL_FRAMEWORKS } = await import("./lib/compliance-mapper");
    const cmmc = ALL_FRAMEWORKS.cmmc;
    expect(cmmc.name).toContain("CMMC");
    expect(cmmc.controls.length).toBeGreaterThan(0);
    // CMMC categories use "Level N - Domain" format
    const categories = new Set(cmmc.controls.map(c => c.category));
    const catArray = Array.from(categories);
    const hasLevel1 = catArray.some(c => c.includes("Level 1"));
    const hasLevel2 = catArray.some(c => c.includes("Level 2"));
    const hasLevel3 = catArray.some(c => c.includes("Level 3"));
    expect(hasLevel1).toBe(true);
    expect(hasLevel2).toBe(true);
    expect(hasLevel3).toBe(true);
  });

  it("calculateComplianceScore returns valid score", async () => {
    const { calculateComplianceScore } = await import("./lib/compliance-mapper");
    const score = calculateComplianceScore([
      { status: "covered" },
      { status: "gap" },
      { status: "partial" },
      { status: "not_applicable" },
    ]);
    expect(score).toHaveProperty("score");
    expect(score).toHaveProperty("covered");
    expect(score).toHaveProperty("gap");
    expect(typeof score.score).toBe("number");
    expect(score.score).toBeGreaterThanOrEqual(0);
    expect(score.score).toBeLessThanOrEqual(100);
  });
});

// ── API Security Engine Tests ────────────────────────────────────────────────
describe("API Security Engine Library", () => {
  it("exports OWASP API Top 10 reference", async () => {
    const lib = await import("./lib/api-security-engine");
    expect(lib.OWASP_API_TOP_10).toBeDefined();
    const keys = Object.keys(lib.OWASP_API_TOP_10);
    expect(keys.length).toBe(10);
    expect(keys).toContain("API1_BOLA");
    expect(keys).toContain("API10_UNSAFE_API_CONSUMPTION");
  });

  it("exports API security test catalog", async () => {
    const { API_SECURITY_TESTS } = await import("./lib/api-security-engine");
    expect(API_SECURITY_TESTS).toBeDefined();
    expect(Array.isArray(API_SECURITY_TESTS)).toBe(true);
    expect(API_SECURITY_TESTS.length).toBeGreaterThan(0);
  });

  it("API security tests have required fields", async () => {
    const { API_SECURITY_TESTS } = await import("./lib/api-security-engine");
    const first = API_SECURITY_TESTS[0];
    expect(first).toHaveProperty("id");
    expect(first).toHaveProperty("testName");
    expect(first).toHaveProperty("owaspCategory");
    expect(first).toHaveProperty("severity");
    expect(first).toHaveProperty("testPayload");
    expect(first).toHaveProperty("expectedResult");
  });

  it("exports fuzzing strategies", async () => {
    const { FUZZING_STRATEGIES } = await import("./lib/api-security-engine");
    expect(FUZZING_STRATEGIES).toBeDefined();
    expect(FUZZING_STRATEGIES).toHaveProperty("parameter_mutation");
    expect(FUZZING_STRATEGIES).toHaveProperty("injection");
    expect(FUZZING_STRATEGIES).toHaveProperty("auth_bypass");
  });

  it("calculateAPISecurityScore returns valid score", async () => {
    const { calculateAPISecurityScore } = await import("./lib/api-security-engine");
    const score = calculateAPISecurityScore([
      { result: "vulnerable", severity: "critical" },
      { result: "secure", severity: "low" },
      { result: "inconclusive", severity: "medium" },
    ]);
    expect(score).toHaveProperty("score");
    expect(typeof score.score).toBe("number");
  });
});
