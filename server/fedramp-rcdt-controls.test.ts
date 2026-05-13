import { describe, it, expect } from "vitest";

// ── RCDT Helper Functions (extracted for testing) ──

const mapSeverityToFedRAMP = (sev: string, cvss?: string | null): string => {
  if (cvss) {
    const score = parseFloat(cvss);
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Moderate';
    if (score > 0) return 'Low';
  }
  switch (sev) {
    case 'critical': return 'Critical';
    case 'high': return 'High';
    case 'moderate': return 'Moderate';
    case 'low': return 'Low';
    case 'informational': return 'Warning';
    default: return 'Moderate';
  }
};

const getRemediationTimeline = (sev: string, cvss?: string | null): string => {
  if (cvss) {
    const score = parseFloat(cvss);
    if (score >= 9.0) return '30 days (Critical)';
    if (score >= 7.0) return '30 days (High)';
    if (score >= 4.0) return '90 days (Moderate)';
    if (score > 0) return '180 days (Low)';
  }
  switch (sev) {
    case 'critical': return '30 days (Critical)';
    case 'high': return '30 days (High)';
    case 'moderate': return '90 days (Moderate)';
    case 'low': return '180 days (Low)';
    case 'informational': return 'N/A (Advisory)';
    default: return '90 days';
  }
};

const getRecommendedDisposition = (f: any): string => {
  const sev = f.rfSeverity;
  if (sev === 'informational') return 'Accept';
  if (sev === 'critical' || sev === 'high') return 'Mitigate';
  const title = (f.rfTitle || '').toLowerCase();
  if (title.includes('header') || title.includes('cookie') || title.includes('disclosure')) return 'Mitigate';
  return 'Mitigate';
};

const getCompensatingControls = (f: any): string => {
  const title = (f.rfTitle || '').toLowerCase();
  if (title.includes('xss') || title.includes('injection')) return 'WAF rules, input validation, CSP headers';
  if (title.includes('auth') || title.includes('credential') || title.includes('password')) return 'MFA enforcement, account lockout policies';
  if (title.includes('tls') || title.includes('ssl') || title.includes('crypto')) return 'TLS 1.2+ enforcement, HSTS preloading';
  if (title.includes('header') || title.includes('cookie')) return 'Security header enforcement via reverse proxy';
  if (title.includes('patch') || title.includes('outdated') || title.includes('version')) return 'Vulnerability management program, virtual patching';
  if (title.includes('config') || title.includes('misconfiguration')) return 'Configuration baseline enforcement, CIS benchmarks';
  if (title.includes('network') || title.includes('port') || title.includes('exposure')) return 'Network segmentation, firewall rules, zero-trust architecture';
  const controls = (f.rfControls as any[] || []);
  if (controls.length > 0) return `Compensating controls for ${controls.map((c: any) => c.id).join(', ')}`;
  return 'To be determined by CSP';
};

// ── NIST Control Families (same as in ac3-reports.ts) ──

const NIST_CONTROL_FAMILIES: Record<string, string> = {
  "AC": "Access Control",
  "AT": "Awareness and Training",
  "AU": "Audit and Accountability",
  "CA": "Assessment, Authorization, and Monitoring",
  "CM": "Configuration Management",
  "CP": "Contingency Planning",
  "IA": "Identification and Authentication",
  "IR": "Incident Response",
  "MA": "Maintenance",
  "MP": "Media Protection",
  "PE": "Physical and Environmental Protection",
  "PL": "Planning",
  "PM": "Program Management",
  "PS": "Personnel Security",
  "PT": "PII Processing and Transparency",
  "RA": "Risk Assessment",
  "SA": "System and Services Acquisition",
  "SC": "System and Communications Protection",
  "SI": "System and Information Integrity",
  "SR": "Supply Chain Risk Management",
};

// ── RCDT Tests ──

describe("RCDT - Remediation Timeline", () => {
  it("returns 30 days for critical CVSS scores (9.0+)", () => {
    expect(getRemediationTimeline("critical", "9.5")).toBe("30 days (Critical)");
    expect(getRemediationTimeline("high", "9.0")).toBe("30 days (Critical)");
  });

  it("returns 30 days for high CVSS scores (7.0-8.9)", () => {
    expect(getRemediationTimeline("high", "7.5")).toBe("30 days (High)");
    expect(getRemediationTimeline("moderate", "8.5")).toBe("30 days (High)");
  });

  it("returns 90 days for moderate CVSS scores (4.0-6.9)", () => {
    expect(getRemediationTimeline("moderate", "5.5")).toBe("90 days (Moderate)");
    expect(getRemediationTimeline("low", "4.0")).toBe("90 days (Moderate)");
  });

  it("returns 180 days for low CVSS scores (0.1-3.9)", () => {
    expect(getRemediationTimeline("low", "2.5")).toBe("180 days (Low)");
    expect(getRemediationTimeline("informational", "1.0")).toBe("180 days (Low)");
  });

  it("falls back to severity when no CVSS score", () => {
    expect(getRemediationTimeline("critical")).toBe("30 days (Critical)");
    expect(getRemediationTimeline("high")).toBe("30 days (High)");
    expect(getRemediationTimeline("moderate")).toBe("90 days (Moderate)");
    expect(getRemediationTimeline("low")).toBe("180 days (Low)");
    expect(getRemediationTimeline("informational")).toBe("N/A (Advisory)");
  });

  it("returns 90 days for unknown severity", () => {
    expect(getRemediationTimeline("unknown")).toBe("90 days");
  });
});

describe("RCDT - Recommended Disposition", () => {
  it("returns Accept for informational findings", () => {
    expect(getRecommendedDisposition({ rfSeverity: "informational", rfTitle: "Info disclosure" })).toBe("Accept");
  });

  it("returns Mitigate for critical findings", () => {
    expect(getRecommendedDisposition({ rfSeverity: "critical", rfTitle: "SQL Injection" })).toBe("Mitigate");
  });

  it("returns Mitigate for high findings", () => {
    expect(getRecommendedDisposition({ rfSeverity: "high", rfTitle: "Authentication Bypass" })).toBe("Mitigate");
  });

  it("returns Mitigate for moderate findings", () => {
    expect(getRecommendedDisposition({ rfSeverity: "moderate", rfTitle: "Missing Security Headers" })).toBe("Mitigate");
  });

  it("returns Mitigate for low findings", () => {
    expect(getRecommendedDisposition({ rfSeverity: "low", rfTitle: "Cookie without Secure flag" })).toBe("Mitigate");
  });
});

describe("RCDT - Compensating Controls", () => {
  it("suggests WAF for XSS findings", () => {
    expect(getCompensatingControls({ rfTitle: "Reflected XSS in Search", rfControls: [] })).toBe("WAF rules, input validation, CSP headers");
  });

  it("suggests WAF for injection findings", () => {
    expect(getCompensatingControls({ rfTitle: "SQL Injection in Login", rfControls: [] })).toBe("WAF rules, input validation, CSP headers");
  });

  it("suggests MFA for auth findings", () => {
    expect(getCompensatingControls({ rfTitle: "Weak Authentication Mechanism", rfControls: [] })).toBe("MFA enforcement, account lockout policies");
  });

  it("suggests MFA for credential findings", () => {
    expect(getCompensatingControls({ rfTitle: "Default Credentials Found", rfControls: [] })).toBe("MFA enforcement, account lockout policies");
  });

  it("suggests TLS enforcement for crypto findings", () => {
    expect(getCompensatingControls({ rfTitle: "Weak TLS Configuration", rfControls: [] })).toBe("TLS 1.2+ enforcement, HSTS preloading");
  });

  it("suggests header enforcement for header findings", () => {
    expect(getCompensatingControls({ rfTitle: "Missing Security Headers", rfControls: [] })).toBe("Security header enforcement via reverse proxy");
  });

  it("suggests patching for outdated software", () => {
    expect(getCompensatingControls({ rfTitle: "Outdated Apache Version", rfControls: [] })).toBe("Vulnerability management program, virtual patching");
  });

  it("suggests CIS benchmarks for config findings", () => {
    expect(getCompensatingControls({ rfTitle: "Server Misconfiguration", rfControls: [] })).toBe("Configuration baseline enforcement, CIS benchmarks");
  });

  it("suggests network controls for exposure findings", () => {
    expect(getCompensatingControls({ rfTitle: "Unnecessary Port Exposure", rfControls: [] })).toBe("Network segmentation, firewall rules, zero-trust architecture");
  });

  it("references existing controls when no keyword match", () => {
    expect(getCompensatingControls({ rfTitle: "Unknown Issue", rfControls: [{ id: "AC-2" }, { id: "SI-10" }] })).toBe("Compensating controls for AC-2, SI-10");
  });

  it("returns CSP placeholder when no context available", () => {
    expect(getCompensatingControls({ rfTitle: "Generic Finding", rfControls: [] })).toBe("To be determined by CSP");
  });
});

// ── NIST Control Mapping Validation Tests ──

describe("NIST Control ID Validation", () => {
  it("validates correct NIST control ID format", () => {
    const validIds = ["AC-2", "SI-10", "SC-7", "IA-5", "CM-6", "AU-2", "RA-5"];
    for (const id of validIds) {
      expect(/^[A-Z]{2}-\d+/.test(id)).toBe(true);
    }
  });

  it("rejects invalid control ID formats", () => {
    const invalidIds = ["ac-2", "S-10", "SC7", "123", "", "ABCD-1"];
    for (const id of invalidIds) {
      expect(/^[A-Z]{2}-\d+/.test(id)).toBe(false);
    }
  });

  it("maps control family prefixes to names", () => {
    expect(NIST_CONTROL_FAMILIES["AC"]).toBe("Access Control");
    expect(NIST_CONTROL_FAMILIES["SI"]).toBe("System and Information Integrity");
    expect(NIST_CONTROL_FAMILIES["SC"]).toBe("System and Communications Protection");
    expect(NIST_CONTROL_FAMILIES["IA"]).toBe("Identification and Authentication");
    expect(NIST_CONTROL_FAMILIES["CM"]).toBe("Configuration Management");
    expect(NIST_CONTROL_FAMILIES["RA"]).toBe("Risk Assessment");
    expect(NIST_CONTROL_FAMILIES["AU"]).toBe("Audit and Accountability");
  });

  it("extracts family prefix from control ID", () => {
    const extractFamily = (id: string) => NIST_CONTROL_FAMILIES[id.split("-")[0]] || "Unknown";
    expect(extractFamily("AC-2")).toBe("Access Control");
    expect(extractFamily("SI-10")).toBe("System and Information Integrity");
    expect(extractFamily("SC-7")).toBe("System and Communications Protection");
    expect(extractFamily("XX-1")).toBe("Unknown");
  });
});

describe("NIST Control Merge Logic", () => {
  it("merges new controls without overwriting existing ones", () => {
    const existing = [{ id: "AC-2", family: "Access Control" }];
    const newControls = [
      { id: "AC-2", family: "Access Control", title: "Account Management", rationale: "test" },
      { id: "SI-10", family: "System and Information Integrity", title: "Input Validation", rationale: "test" },
    ];
    const existingIds = new Set(existing.map(c => c.id));
    const merged = [...existing, ...newControls.filter(c => !existingIds.has(c.id))];
    expect(merged).toHaveLength(2);
    expect(merged[0].id).toBe("AC-2");
    expect(merged[1].id).toBe("SI-10");
  });

  it("handles empty existing controls", () => {
    const existing: any[] = [];
    const newControls = [
      { id: "AC-2", family: "Access Control" },
      { id: "SI-10", family: "System and Information Integrity" },
    ];
    const existingIds = new Set(existing.map((c: any) => c.id));
    const merged = [...existing, ...newControls.filter(c => !existingIds.has(c.id))];
    expect(merged).toHaveLength(2);
  });

  it("handles duplicate new controls", () => {
    const existing = [{ id: "AC-2" }, { id: "SI-10" }];
    const newControls = [{ id: "AC-2" }, { id: "SI-10" }, { id: "SC-7" }];
    const existingIds = new Set(existing.map(c => c.id));
    const merged = [...existing, ...newControls.filter(c => !existingIds.has(c.id))];
    expect(merged).toHaveLength(3);
    expect(merged[2].id).toBe("SC-7");
  });
});

// ── FedRAMP Severity to Risk Rating (shared with RET) ──

describe("FedRAMP Risk Rating Mapping", () => {
  it("maps CVSS 9.0+ to Critical", () => {
    expect(mapSeverityToFedRAMP("high", "9.8")).toBe("Critical");
    expect(mapSeverityToFedRAMP("moderate", "9.0")).toBe("Critical");
  });

  it("maps CVSS 7.0-8.9 to High", () => {
    expect(mapSeverityToFedRAMP("moderate", "7.5")).toBe("High");
    expect(mapSeverityToFedRAMP("low", "8.9")).toBe("High");
  });

  it("maps CVSS 4.0-6.9 to Moderate", () => {
    expect(mapSeverityToFedRAMP("low", "5.0")).toBe("Moderate");
    expect(mapSeverityToFedRAMP("high", "6.9")).toBe("Moderate");
  });

  it("maps CVSS 0.1-3.9 to Low", () => {
    expect(mapSeverityToFedRAMP("moderate", "2.0")).toBe("Low");
    expect(mapSeverityToFedRAMP("high", "3.9")).toBe("Low");
  });

  it("falls back to severity label when no CVSS", () => {
    expect(mapSeverityToFedRAMP("critical")).toBe("Critical");
    expect(mapSeverityToFedRAMP("high")).toBe("High");
    expect(mapSeverityToFedRAMP("moderate")).toBe("Moderate");
    expect(mapSeverityToFedRAMP("low")).toBe("Low");
    expect(mapSeverityToFedRAMP("informational")).toBe("Warning");
  });
});

// ── PT-ID Generation ──

describe("PT-ID Generation", () => {
  it("generates zero-padded PT identifiers", () => {
    const ptId = (idx: number) => `PT-${String(idx + 1).padStart(3, '0')}`;
    expect(ptId(0)).toBe("PT-001");
    expect(ptId(9)).toBe("PT-010");
    expect(ptId(99)).toBe("PT-100");
    expect(ptId(999)).toBe("PT-1000");
  });

  it("generates matching POAM references", () => {
    const poamRef = (idx: number) => `POAM-${String(idx + 1).padStart(3, '0')}`;
    expect(poamRef(0)).toBe("POAM-001");
    expect(poamRef(9)).toBe("POAM-010");
    expect(poamRef(99)).toBe("POAM-100");
  });
});
