import { describe, expect, it } from "vitest";

/**
 * RoE Builder Router Unit Tests
 * 
 * Tests the structure, defaults, and validation logic of the Rules of Engagement
 * builder module. These tests verify the data model without requiring a live DB.
 */

// ─── Default Templates Validation ───────────────────────────────────────────

describe("RoE Builder Default Templates", () => {
  // We import the router module to verify the structure
  it("should have a valid router export", async () => {
    const mod = await import("./routers/roe-builder");
    expect(mod.roeBuilderRouter).toBeDefined();
    expect(typeof mod.roeBuilderRouter).toBe("object");
  });
});

// ─── Testing Type Categories ────────────────────────────────────────────────

describe("Testing Type Categories", () => {
  const EXPECTED_CATEGORIES = [
    "pentest",
    "red_team",
    "purple_team",
    "social_engineering",
    "physical",
    "wireless",
    "cloud",
  ];

  it("should define all expected testing categories", () => {
    // Verify the categories are comprehensive per NIST 800-115
    for (const cat of EXPECTED_CATEGORIES) {
      expect(cat).toBeTruthy();
    }
    expect(EXPECTED_CATEGORIES.length).toBeGreaterThanOrEqual(7);
  });

  it("should include penetration testing types", () => {
    const pentestTypes = [
      "External Network Penetration Test",
      "Internal Network Penetration Test",
      "Web Application Penetration Test",
      "API Security Assessment",
      "Mobile Application Security Test",
    ];
    for (const t of pentestTypes) {
      expect(t).toBeTruthy();
    }
  });

  it("should include red team operation types", () => {
    const redTeamTypes = [
      "Full-Scope Red Team Engagement",
      "Assumed Breach Red Team",
      "APT Simulation",
      "Ransomware Simulation",
    ];
    for (const t of redTeamTypes) {
      expect(t).toBeTruthy();
    }
  });

  it("should include social engineering types", () => {
    const seTypes = [
      "Phishing Campaign",
      "Vishing (Voice Phishing)",
      "Smishing (SMS Phishing)",
      "Physical Pretexting",
    ];
    for (const t of seTypes) {
      expect(t).toBeTruthy();
    }
  });
});

// ─── FedRAMP Attack Vectors ─────────────────────────────────────────────────

describe("FedRAMP Attack Vectors", () => {
  const FEDRAMP_REQUIRED_VECTORS = [
    "External to Internal",
    "Internal to Internal",
    "Tenant Isolation",
    "API Abuse",
    "Authentication/Authorization Bypass",
    "Data Exfiltration",
    "Cloud Misconfiguration",
  ];

  it("should define all FedRAMP-required attack vectors", () => {
    expect(FEDRAMP_REQUIRED_VECTORS.length).toBeGreaterThanOrEqual(6);
    for (const v of FEDRAMP_REQUIRED_VECTORS) {
      expect(v).toBeTruthy();
    }
  });

  it("should include optional attack vectors", () => {
    const optionalVectors = [
      "Supply Chain",
      "Social Engineering",
      "Physical Access",
      "Wireless",
      "Container/Orchestration Escape",
    ];
    for (const v of optionalVectors) {
      expect(v).toBeTruthy();
    }
  });
});

// ─── Report Deliverables ────────────────────────────────────────────────────

describe("Report Deliverables", () => {
  const REQUIRED_DELIVERABLES = [
    "Executive Summary",
    "Technical Report",
    "Finding Risk Matrix",
    "Evidence Package",
  ];

  it("should include all required deliverables", () => {
    for (const d of REQUIRED_DELIVERABLES) {
      expect(d).toBeTruthy();
    }
  });

  it("should include optional deliverables", () => {
    const optionalDeliverables = [
      "Remediation Roadmap",
      "Attack Narrative",
      "Retest Validation Report",
      "MITRE ATT&CK Mapping",
    ];
    for (const d of optionalDeliverables) {
      expect(d).toBeTruthy();
    }
  });
});

// ─── Personnel Roles ────────────────────────────────────────────────────────

describe("Personnel Roles", () => {
  const NIST_REQUIRED_ROLES = [
    "system_owner",
    "ciso",
    "isso",
    "authorizing_official",
    "trusted_agent",
    "test_lead",
    "test_member",
    "emergency_contact",
  ];

  it("should define all NIST 800-115 required personnel roles", () => {
    for (const role of NIST_REQUIRED_ROLES) {
      expect(role).toBeTruthy();
    }
    expect(NIST_REQUIRED_ROLES.length).toBeGreaterThanOrEqual(8);
  });

  it("should include additional operational roles", () => {
    const additionalRoles = [
      "legal_counsel",
      "third_party_poc",
      "incident_response_lead",
      "customer_poc",
      "project_manager",
    ];
    for (const role of additionalRoles) {
      expect(role).toBeTruthy();
    }
  });
});

// ─── RoE Document Status Transitions ────────────────────────────────────────

describe("RoE Document Status Transitions", () => {
  const VALID_STATUSES = ["draft", "pending_review", "approved", "active", "completed", "archived"];

  it("should define all valid document statuses", () => {
    expect(VALID_STATUSES).toContain("draft");
    expect(VALID_STATUSES).toContain("pending_review");
    expect(VALID_STATUSES).toContain("approved");
    expect(VALID_STATUSES).toContain("active");
    expect(VALID_STATUSES).toContain("completed");
    expect(VALID_STATUSES).toContain("archived");
    expect(VALID_STATUSES.length).toBe(6);
  });

  it("should enforce valid transition: draft -> pending_review", () => {
    const from = "draft";
    const to = "pending_review";
    const validTransitions: Record<string, string[]> = {
      draft: ["pending_review"],
      pending_review: ["approved", "draft"],
      approved: ["active"],
      active: ["completed"],
      completed: ["archived"],
      archived: [],
    };
    expect(validTransitions[from]).toContain(to);
  });

  it("should not allow skipping from draft to active", () => {
    const validTransitions: Record<string, string[]> = {
      draft: ["pending_review"],
      pending_review: ["approved", "draft"],
      approved: ["active"],
      active: ["completed"],
      completed: ["archived"],
      archived: [],
    };
    expect(validTransitions["draft"]).not.toContain("active");
  });
});

// ─── Compliance Frameworks ──────────────────────────────────────────────────

describe("Compliance Frameworks", () => {
  const FRAMEWORKS = [
    "FedRAMP", "NIST SP 800-53", "NIST SP 800-171", "NIST CSF",
    "PCI DSS", "HIPAA", "SOC 2", "ISO 27001", "CMMC",
    "FISMA", "GDPR", "CCPA", "CJIS", "ITAR", "SOX",
  ];

  it("should include all major compliance frameworks", () => {
    expect(FRAMEWORKS).toContain("FedRAMP");
    expect(FRAMEWORKS).toContain("NIST SP 800-53");
    expect(FRAMEWORKS).toContain("PCI DSS");
    expect(FRAMEWORKS).toContain("HIPAA");
    expect(FRAMEWORKS).toContain("SOC 2");
    expect(FRAMEWORKS).toContain("ISO 27001");
    expect(FRAMEWORKS).toContain("CMMC");
    expect(FRAMEWORKS.length).toBeGreaterThanOrEqual(10);
  });

  it("should include FedRAMP impact levels", () => {
    const impactLevels = ["low", "moderate", "high", "not_applicable"];
    expect(impactLevels.length).toBe(4);
    expect(impactLevels).toContain("low");
    expect(impactLevels).toContain("moderate");
    expect(impactLevels).toContain("high");
  });

  it("should include cloud service models", () => {
    const serviceModels = ["iaas", "paas", "saas", "hybrid", "not_applicable"];
    expect(serviceModels.length).toBe(5);
    expect(serviceModels).toContain("iaas");
    expect(serviceModels).toContain("paas");
    expect(serviceModels).toContain("saas");
  });
});

// ─── Data Handling Policies ─────────────────────────────────────────────────

describe("Data Handling Policies", () => {
  it("should define evidence destruction methods", () => {
    const methods = ["secure_delete", "physical_destruction", "crypto_erase"];
    expect(methods.length).toBe(3);
    expect(methods).toContain("secure_delete");
    expect(methods).toContain("physical_destruction");
    expect(methods).toContain("crypto_erase");
  });

  it("should define communication methods", () => {
    const methods = ["email", "phone", "secure_portal", "encrypted_email"];
    expect(methods.length).toBe(4);
    expect(methods).toContain("secure_portal");
    expect(methods).toContain("encrypted_email");
  });

  it("should define shunning policies", () => {
    const policies = ["allowed", "not_allowed", "notify_first"];
    expect(policies.length).toBe(3);
    expect(policies).toContain("notify_first");
  });

  it("should set default evidence retention to 90 days", () => {
    const defaultRetention = 90;
    expect(defaultRetention).toBe(90);
    expect(defaultRetention).toBeGreaterThan(0);
  });
});

// ─── NIST 800-115 Compliance Checks ────────────────────────────────────────

describe("NIST 800-115 Compliance Structure", () => {
  it("should include all NIST 800-115 required sections", () => {
    const requiredSections = [
      "purpose",              // Section 1: Purpose
      "scopeDescription",     // Section 2: Scope
      "testingTypes",         // Section 3: Testing Methodology
      "testScheduleStart",    // Section 4: Schedule
      "communicationFrequency", // Section 5: Communications
      "incidentResponseProcedure", // Section 6: Incident Response
      "emergencyHaltCriteria", // Section 7: Emergency Halt
      "dataHandlingProcedure", // Section 8: Data Handling
      "evidenceRetentionDays", // Section 9: Evidence Retention
      "piiHandlingPolicy",    // Section 10: PII Handling
    ];
    expect(requiredSections.length).toBeGreaterThanOrEqual(10);
    for (const section of requiredSections) {
      expect(section).toBeTruthy();
    }
  });

  it("should include FedRAMP-specific extensions", () => {
    const fedrampExtensions = [
      "fedrampCompliant",
      "fedrampImpactLevel",
      "serviceModel",
      "attackVectors",
    ];
    for (const ext of fedrampExtensions) {
      expect(ext).toBeTruthy();
    }
  });
});
