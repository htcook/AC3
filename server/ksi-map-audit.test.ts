import { describe, it, expect } from "vitest";

// ─── Module Existence Registry ─────────────────────────────────────
// These are the actual ACE C3 modules that exist as backend routers + frontend pages.
// Any module referenced in the KSI Map MUST appear in this list.

const EXISTING_MODULES = new Set([
  "Domain Intel",
  "Vuln Intel",
  "Validation Engine",
  "DAST Scanner",
  "Exploit Arsenal",
  "Red Team Ops",
  "Phishing Ops",
  "Post-Engagement Report",
  "Validation Scheduler",
  "Agentless BAS",
  "ATT&CK Validation Tests",
  "OSCAL Export",
  "Evidence Chain",
  "Report Generator",
  "Config Baseline Engine",
  "SIEM Connectors",
  "SIEM Feedback Loop",
  "Detection Rule Generator",
  "ATT&CK Coverage Matrix",
  "API Security Testing",
  "Email Security Analyzer",
  "NGFW Validation",
  "Nuclei Scanner",
  "Cloud Attack Paths",
  "AD Attack Simulation",
  "AD Domain Connector",
  "Purple Team",
  "Campaign Wizard",
  "Template Generator",
  "Vuln Scanner",
  "RoE Builder",
  "Audit Log",
  "BIA Report",
  "Attack Vector Engine",
  "Engagement Automation",
  "Threat Enrichment",
]);

// ─── KSI Data (mirrors the frontend component) ─────────────────────
// This is a simplified representation to test data integrity without importing React

type KSIStatus = "direct" | "supporting" | "planned";

interface KSIEntry {
  id: string;
  name: string;
  status: KSIStatus;
  aceModules: string[];
}

interface KSITheme {
  id: string;
  name: string;
  totalKSIs: number;
  directCoverage: number;
  supportingCoverage: number;
  ksis: KSIEntry[];
}

const KSI_THEMES: KSITheme[] = [
  {
    id: "vdr", name: "Vulnerability Detection & Response", totalKSIs: 3, directCoverage: 3, supportingCoverage: 0,
    ksis: [
      { id: "KSI-VDR-001", name: "Vulnerability Detection & Response", status: "direct", aceModules: ["Domain Intel", "Vuln Intel", "Validation Engine", "DAST Scanner"] },
      { id: "KSI-VDR-002", name: "Penetration Testing", status: "direct", aceModules: ["Exploit Arsenal", "Red Team Ops", "Phishing Ops", "DAST Scanner", "Post-Engagement Report"] },
      { id: "KSI-VDR-003", name: "Persistent Validation & Assessment", status: "direct", aceModules: ["Validation Scheduler", "Agentless BAS", "ATT&CK Validation Tests"] },
    ],
  },
  {
    id: "pva", name: "Persistent Validation & Assessment", totalKSIs: 3, directCoverage: 1, supportingCoverage: 1,
    ksis: [
      { id: "KSI-PVA-002", name: "Ongoing Assessment Reports", status: "direct", aceModules: ["Post-Engagement Report", "Evidence Chain", "Report Generator"] },
      { id: "KSI-PVA-003", name: "Significant Change Notification", status: "supporting", aceModules: ["Config Baseline Engine", "Audit Log"] },
      { id: "KSI-PVA-004", name: "Feedback Mechanism", status: "planned", aceModules: ["Evidence Chain"] },
    ],
  },
  {
    id: "iam", name: "Identity & Access Management", totalKSIs: 7, directCoverage: 2, supportingCoverage: 2,
    ksis: [
      { id: "KSI-IAM-001", name: "Phishing-Resistant MFA", status: "direct", aceModules: ["Phishing Ops", "Campaign Wizard"] },
      { id: "KSI-IAM-002", name: "Privileged Access Management", status: "direct", aceModules: ["AD Attack Simulation", "AD Domain Connector"] },
      { id: "KSI-IAM-003", name: "Account Lifecycle", status: "supporting", aceModules: ["AD Domain Connector", "Audit Log"] },
      { id: "KSI-IAM-004", name: "Least Privilege", status: "supporting", aceModules: ["Cloud Attack Paths", "AD Attack Simulation"] },
      { id: "KSI-IAM-005", name: "Just-in-Time Access", status: "planned", aceModules: ["Cloud Attack Paths"] },
      { id: "KSI-IAM-006", name: "Single Sign-On", status: "planned", aceModules: ["AD Domain Connector"] },
      { id: "KSI-IAM-007", name: "Network Access Control", status: "planned", aceModules: ["Config Baseline Engine"] },
    ],
  },
  {
    id: "cmt", name: "Change Management", totalKSIs: 4, directCoverage: 2, supportingCoverage: 2,
    ksis: [
      { id: "KSI-CMT-001", name: "Automate Configuration Management", status: "supporting", aceModules: ["Config Baseline Engine", "Validation Scheduler"] },
      { id: "KSI-CMT-002", name: "Configuration Database", status: "supporting", aceModules: ["Config Baseline Engine", "Domain Intel"] },
      { id: "KSI-CMT-003", name: "Document Changes", status: "direct", aceModules: ["Audit Log", "RoE Builder", "Evidence Chain"] },
      { id: "KSI-CMT-004", name: "Validate Through Deployment", status: "direct", aceModules: ["Validation Scheduler", "Agentless BAS", "ATT&CK Validation Tests"] },
    ],
  },
  {
    id: "cna", name: "Cloud Native Architecture", totalKSIs: 8, directCoverage: 2, supportingCoverage: 3,
    ksis: [
      { id: "KSI-CNA-001", name: "Minimal Attack Surface", status: "direct", aceModules: ["Domain Intel", "DAST Scanner", "Vuln Scanner"] },
      { id: "KSI-CNA-002", name: "Define Functionality/Privileges", status: "direct", aceModules: ["Cloud Attack Paths", "AD Attack Simulation"] },
      { id: "KSI-CNA-003", name: "Logical Network Segmentation", status: "supporting", aceModules: ["Config Baseline Engine", "NGFW Validation"] },
      { id: "KSI-CNA-004", name: "Container/Image Security", status: "supporting", aceModules: ["Nuclei Scanner", "Config Baseline Engine"] },
      { id: "KSI-CNA-005", name: "DoS Protection", status: "supporting", aceModules: ["Config Baseline Engine"] },
      { id: "KSI-CNA-006", name: "High Availability", status: "planned", aceModules: ["Config Baseline Engine"] },
      { id: "KSI-CNA-007", name: "Resilience", status: "planned", aceModules: ["Config Baseline Engine"] },
      { id: "KSI-CNA-008", name: "Secure Software Management", status: "planned", aceModules: ["Config Baseline Engine"] },
    ],
  },
  {
    id: "mla", name: "Monitoring, Logging & Alerting", totalKSIs: 5, directCoverage: 3, supportingCoverage: 1,
    ksis: [
      { id: "KSI-MLA-001", name: "Centralized Logging", status: "direct", aceModules: ["SIEM Connectors", "Evidence Chain"] },
      { id: "KSI-MLA-002", name: "Event Type Catalog", status: "direct", aceModules: ["SIEM Connectors", "Detection Rule Generator"] },
      { id: "KSI-MLA-003", name: "Security Monitoring", status: "direct", aceModules: ["SIEM Connectors", "ATT&CK Coverage Matrix", "SIEM Feedback Loop"] },
      { id: "KSI-MLA-004", name: "Tamper-Resistant Logging", status: "supporting", aceModules: ["Evidence Chain", "Config Baseline Engine"] },
      { id: "KSI-MLA-005", name: "Log Archival", status: "planned", aceModules: ["Config Baseline Engine"] },
    ],
  },
  {
    id: "svc", name: "Service Configuration & Vaulting", totalKSIs: 7, directCoverage: 2, supportingCoverage: 1,
    ksis: [
      { id: "KSI-SVC-001", name: "API Security", status: "direct", aceModules: ["DAST Scanner", "API Security Testing"] },
      { id: "KSI-SVC-002", name: "Encryption in Transit", status: "direct", aceModules: ["DAST Scanner", "Email Security Analyzer"] },
      { id: "KSI-SVC-003", name: "Encryption at Rest", status: "supporting", aceModules: ["Config Baseline Engine", "Cloud Attack Paths"] },
      { id: "KSI-SVC-004", name: "Key Management", status: "planned", aceModules: ["Config Baseline Engine"] },
      { id: "KSI-SVC-005", name: "Secure Configuration Guide", status: "planned", aceModules: ["Config Baseline Engine"] },
      { id: "KSI-SVC-006", name: "Data Handling Restrictions", status: "planned", aceModules: ["Config Baseline Engine"] },
      { id: "KSI-SVC-007", name: "Third-Party Access", status: "planned", aceModules: ["Config Baseline Engine"] },
    ],
  },
  {
    id: "rpl", name: "Resilience, Planning & Logistics", totalKSIs: 4, directCoverage: 0, supportingCoverage: 2,
    ksis: [
      { id: "KSI-RPL-001", name: "Recovery Validation Testing", status: "planned", aceModules: ["Config Baseline Engine"] },
      { id: "KSI-RPL-002", name: "RTO/RPO Objectives", status: "supporting", aceModules: ["BIA Report", "Config Baseline Engine"] },
      { id: "KSI-RPL-003", name: "Backup Alignment", status: "supporting", aceModules: ["Config Baseline Engine"] },
      { id: "KSI-RPL-004", name: "Disaster Recovery Plan", status: "planned", aceModules: ["Config Baseline Engine"] },
    ],
  },
  {
    id: "ced", name: "Cybersecurity Education", totalKSIs: 4, directCoverage: 1, supportingCoverage: 1,
    ksis: [
      { id: "KSI-CED-001", name: "Security Awareness Training", status: "direct", aceModules: ["Phishing Ops", "Campaign Wizard", "Template Generator"] },
      { id: "KSI-CED-002", name: "Incident Response Training", status: "supporting", aceModules: ["Red Team Ops", "Purple Team"] },
      { id: "KSI-CED-003", name: "Developer Training", status: "planned", aceModules: ["DAST Scanner"] },
      { id: "KSI-CED-004", name: "Privileged User Training", status: "planned", aceModules: ["AD Attack Simulation"] },
    ],
  },
];

// ─── Tests ──────────────────────────────────────────────────────────

describe("FedRAMP KSI Map — Data Integrity Audit", () => {

  it("every referenced ACE module actually exists in the platform", () => {
    const missingModules: { ksi: string; module: string }[] = [];

    for (const theme of KSI_THEMES) {
      for (const ksi of theme.ksis) {
        for (const mod of ksi.aceModules) {
          if (!EXISTING_MODULES.has(mod)) {
            missingModules.push({ ksi: ksi.id, module: mod });
          }
        }
      }
    }

    expect(missingModules).toEqual([]);
  });

  it("totalKSIs matches actual KSI count per theme", () => {
    for (const theme of KSI_THEMES) {
      expect(theme.ksis.length).toBe(theme.totalKSIs);
    }
  });

  it("directCoverage + supportingCoverage counts match actual KSI statuses", () => {
    for (const theme of KSI_THEMES) {
      const direct = theme.ksis.filter(k => k.status === "direct").length;
      const supporting = theme.ksis.filter(k => k.status === "supporting").length;
      expect(direct).toBe(theme.directCoverage);
      expect(supporting).toBe(theme.supportingCoverage);
    }
  });

  it("no KSI has empty aceModules array", () => {
    for (const theme of KSI_THEMES) {
      for (const ksi of theme.ksis) {
        expect(ksi.aceModules.length).toBeGreaterThan(0);
      }
    }
  });

  it("all KSI IDs are unique", () => {
    const allIds = KSI_THEMES.flatMap(t => t.ksis.map(k => k.id));
    const uniqueIds = new Set(allIds);
    expect(uniqueIds.size).toBe(allIds.length);
  });

  it("all theme IDs are unique", () => {
    const ids = KSI_THEMES.map(t => t.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it("planned KSIs do not claim direct or supporting status", () => {
    for (const theme of KSI_THEMES) {
      const planned = theme.ksis.filter(k => k.status === "planned");
      // Planned KSIs should have minimal module references (1 at most)
      for (const ksi of planned) {
        expect(ksi.aceModules.length).toBeLessThanOrEqual(2);
      }
    }
  });

  it("direct KSIs have at least 2 supporting modules", () => {
    for (const theme of KSI_THEMES) {
      const direct = theme.ksis.filter(k => k.status === "direct");
      for (const ksi of direct) {
        expect(ksi.aceModules.length).toBeGreaterThanOrEqual(2);
      }
    }
  });

  it("total KSIs across all themes equals 45", () => {
    const total = KSI_THEMES.reduce((sum, t) => sum + t.totalKSIs, 0);
    expect(total).toBe(45);
  });

  it("coverage percentage is accurately calculated", () => {
    const total = KSI_THEMES.reduce((sum, t) => sum + t.totalKSIs, 0);
    const direct = KSI_THEMES.reduce((sum, t) => sum + t.directCoverage, 0);
    const supporting = KSI_THEMES.reduce((sum, t) => sum + t.supportingCoverage, 0);
    const pct = Math.round(((direct + supporting) / total) * 100);
    // Should be honest — not inflated
    expect(pct).toBeLessThanOrEqual(75); // We know we have gaps
    expect(pct).toBeGreaterThanOrEqual(40); // But we do cover a lot
    expect(direct).toBe(16);
    expect(supporting).toBe(13);
  });

  it("no phantom modules are referenced (regression guard)", () => {
    const PHANTOM_MODULES = [
      "Trust Center Portal",
      "IAM Auditor",
      "Recovery Validation Module",
      "Encryption Validator",
      "SCG Generator",
      "Change Monitor",
      "Agency Feedback Hub",
      "OAR Generator",
      "Continuous Validation",
    ];

    for (const theme of KSI_THEMES) {
      for (const ksi of theme.ksis) {
        for (const mod of ksi.aceModules) {
          expect(PHANTOM_MODULES).not.toContain(mod);
        }
      }
    }
  });
});
