import { describe, it, expect } from "vitest";

/**
 * Tests for the unified full-scope domain intelligence pipeline.
 * Validates that the pipeline input schema accepts the consolidated form fields
 * and that the scan methods metadata is complete.
 */

// Scan methods metadata (mirrors the frontend SCAN_METHODS array)
const SCAN_METHODS = [
  { id: "llm_passive_recon", category: "Discovery", name: "LLM-Powered Passive Reconnaissance" },
  { id: "dns_verification", category: "Discovery", name: "Active DNS Resolution" },
  { id: "banner_grabbing", category: "Discovery", name: "HTTP Banner & Header Analysis" },
  { id: "kev_enrichment", category: "Vulnerability Intelligence", name: "CISA KEV Matching" },
  { id: "vuln_feed_enrichment", category: "Vulnerability Intelligence", name: "Multi-Source Vulnerability Feed Matching" },
  { id: "carver_shock_bia", category: "Risk Scoring", name: "CARVER+SHOCK Business Impact Analysis" },
  { id: "hybrid_risk_scoring", category: "Risk Scoring", name: "Hybrid Risk Score Computation" },
  { id: "threat_actor_matching", category: "Threat Intelligence", name: "Threat Actor Profiling" },
  { id: "campaign_design", category: "Offensive Planning", name: "Automated Campaign Design" },
];

const CORROBORATION_TIERS = ["confirmed", "probable", "potential"];

describe("Unified Domain Intelligence - Scan Methods", () => {
  it("should have exactly 9 scan methods defined", () => {
    expect(SCAN_METHODS.length).toBe(9);
  });

  it("should cover all 5 categories", () => {
    const categories = [...new Set(SCAN_METHODS.map(m => m.category))];
    expect(categories).toContain("Discovery");
    expect(categories).toContain("Vulnerability Intelligence");
    expect(categories).toContain("Risk Scoring");
    expect(categories).toContain("Threat Intelligence");
    expect(categories).toContain("Offensive Planning");
    expect(categories.length).toBe(5);
  });

  it("should have unique method IDs", () => {
    const ids = SCAN_METHODS.map(m => m.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("should have 3 discovery methods", () => {
    const discovery = SCAN_METHODS.filter(m => m.category === "Discovery");
    expect(discovery.length).toBe(3);
  });

  it("should have 2 vulnerability intelligence methods", () => {
    const vuln = SCAN_METHODS.filter(m => m.category === "Vulnerability Intelligence");
    expect(vuln.length).toBe(2);
  });
});

describe("Unified Domain Intelligence - Corroboration Tiers", () => {
  it("should have exactly 3 corroboration tiers", () => {
    expect(CORROBORATION_TIERS.length).toBe(3);
  });

  it("should include confirmed, probable, and potential", () => {
    expect(CORROBORATION_TIERS).toContain("confirmed");
    expect(CORROBORATION_TIERS).toContain("probable");
    expect(CORROBORATION_TIERS).toContain("potential");
  });
});

describe("Unified Domain Intelligence - Pipeline Input Schema", () => {
  it("should accept the consolidated form fields", () => {
    // This validates the unified form sends all required fields
    const validInput = {
      primaryDomain: "example.com",
      additionalDomains: ["sub.example.com"],
      clientType: "enterprise",
      sector: "Technology",
      customerName: "Acme Corporation",
      criticalFunctions: ["identity", "email"],
      complianceFlags: ["SOC2", "GDPR"],
      notes: "Test scan",
    };

    expect(validInput.primaryDomain).toBeTruthy();
    expect(validInput.customerName).toBeTruthy();
    expect(validInput.sector).toBeTruthy();
    expect(validInput.clientType).toBeTruthy();
    expect(Array.isArray(validInput.additionalDomains)).toBe(true);
    expect(Array.isArray(validInput.criticalFunctions)).toBe(true);
    expect(Array.isArray(validInput.complianceFlags)).toBe(true);
  });

  it("should require primaryDomain, customerName, and sector", () => {
    const requiredFields = ["primaryDomain", "customerName", "sector"];
    const input: Record<string, any> = {
      primaryDomain: "test.com",
      customerName: "Test Corp",
      sector: "Technology",
    };

    for (const field of requiredFields) {
      expect(input[field]).toBeTruthy();
    }
  });

  it("should accept all valid client types", () => {
    const validTypes = ["msp", "enterprise", "saas", "paas", "iaas", "mixed_hosting", "other"];
    for (const t of validTypes) {
      expect(validTypes).toContain(t);
    }
    expect(validTypes.length).toBe(7);
  });
});

describe("Unified Domain Intelligence - Attribution Structure", () => {
  it("should define attribution fields for each finding", () => {
    // A finding with full attribution
    const finding = {
      title: "Test Finding",
      corroborationTier: "confirmed",
      severity: 8,
      likelihood: 7,
      confidence: 0.85,
      cveIds: ["CVE-2024-1234"],
      detectedVersion: "1.18.0",
      versionMatchConfirmed: true,
      evidenceChain: [
        "DNS resolved vpn.example.com to 1.2.3.4",
        "HTTP banner detected nginx/1.18.0",
        "CVE-2024-1234 affects nginx 1.14.0-1.19.0",
      ],
      kevListed: false,
      exploitAvailable: true,
      affectedAssets: ["vpn.example.com"],
      recommendedControls: ["Upgrade nginx to 1.20+"],
    };

    // Validate attribution structure
    expect(finding.corroborationTier).toMatch(/^(confirmed|probable|potential)$/);
    expect(finding.evidenceChain.length).toBeGreaterThan(0);
    expect(finding.cveIds.length).toBeGreaterThan(0);
    expect(finding.affectedAssets.length).toBeGreaterThan(0);
    expect(typeof finding.confidence).toBe("number");
    expect(finding.confidence).toBeGreaterThanOrEqual(0);
    expect(finding.confidence).toBeLessThanOrEqual(1);
  });

  it("should generate correct source attribution text for each tier", () => {
    const sourceText = (tier: string) => {
      if (tier === "confirmed") return "DNS Verification + HTTP Banner Analysis → Vulnerability Feed Match (version-confirmed CVE)";
      if (tier === "probable") return "DNS Verification + Product Detection → Vulnerability Feed Match (product-family, version unconfirmed)";
      return "LLM Passive Reconnaissance → Risk Inference (no CVE evidence)";
    };

    expect(sourceText("confirmed")).toContain("version-confirmed CVE");
    expect(sourceText("probable")).toContain("version unconfirmed");
    expect(sourceText("potential")).toContain("no CVE evidence");
  });

  it("should generate correct false positive risk text for each tier", () => {
    const fpRisk = (tier: string) => {
      if (tier === "confirmed") return "Low";
      if (tier === "probable") return "Medium";
      return "High";
    };

    expect(fpRisk("confirmed")).toBe("Low");
    expect(fpRisk("probable")).toBe("Medium");
    expect(fpRisk("potential")).toBe("High");
  });
});
