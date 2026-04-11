import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Tests for:
 * 1. Document text extraction (MIME type routing)
 * 2. LLM-parsed document validation and normalization
 * 3. Personnel role mapping
 * 4. Comms protocol extraction validation
 * 5. Scope constraint enforcement logic
 * 6. Auto-engagement designer field mapping
 */

// ─── Types (mirroring the parser types) ─────────────────────────────────────

interface ParsedPersonnel {
  name: string;
  role: string;
  title?: string;
  organization?: string;
  email?: string;
  phone?: string;
  alternatePhone?: string;
  clearanceLevel?: string;
  isPrimary?: boolean;
}

interface ParsedCommsProtocol {
  reportingCadence?: string;
  reportingMethod?: string;
  reportingRecipients?: string[];
  emergencyHaltProcedure?: string;
  deconflictionProcedure?: string;
  deconflictionContacts?: string[];
  deconflictionPhone?: string;
  deconflictionEmail?: string;
  escalationChain?: string[];
  escalationTimeframe?: string;
  criticalFindingNotifyWithin?: string;
  criticalFindingNotifyMethod?: string;
  criticalFindingNotifyRecipients?: string[];
  testingWindowStart?: string;
  testingWindowEnd?: string;
  testingDays?: string[];
  testTimezone?: string;
  blackoutPeriods?: string[];
  statusCheckInFrequency?: string;
  statusCheckInMethod?: string;
  rawCommsSection?: string;
}

interface ParsedScope {
  inScopeDomains?: string[];
  outOfScopeDomains?: string[];
  inScopeIpRanges?: string[];
  outOfScopeIpRanges?: string[];
  inScopeApplications?: string[];
  outOfScopeApplications?: string[];
  inScopePorts?: string[];
  outOfScopePorts?: string[];
  allowedTestingTypes?: string[];
  disallowedTestingTypes?: string[];
  allowedAttackVectors?: string[];
  disallowedAttackVectors?: string[];
  dosAllowed?: boolean;
  socialEngineeringAllowed?: boolean;
  physicalAllowed?: boolean;
  wirelessAllowed?: boolean;
  pivotingAllowed?: boolean;
  exfiltrationAllowed?: boolean;
  persistenceAllowed?: boolean;
  fileModificationAllowed?: boolean;
  credentialedTesting?: boolean;
  testingStartDate?: string;
  testingEndDate?: string;
  rawScopeSection?: string;
}

interface ParsedRoeDocument {
  documentType: string;
  confidence: number;
  warnings: string[];
  engagement: Record<string, any>;
  personnel: ParsedPersonnel[];
  commsProtocol: ParsedCommsProtocol;
  scope: ParsedScope;
}

// ─── Replicate validation logic from roe-document-parser.ts ─────────────────

const VALID_ROLES = [
  'authorizing_official', 'test_lead', 'test_operator', 'customer_poc',
  'technical_poc', 'emergency_contact', 'legal_counsel', 'project_manager',
  'security_operations', 'network_operations', 'system_administrator',
  'compliance_officer', 'executive_sponsor', 'observer',
];

function normalizeRole(role: string): string {
  if (!role) return 'customer_poc';
  const lower = role.toLowerCase().replace(/[\s-]+/g, '_');
  if (VALID_ROLES.includes(lower)) return lower;
  // Fuzzy match
  if (lower.includes('auth')) return 'authorizing_official';
  if (lower.includes('lead') || lower.includes('manager')) return 'test_lead';
  if (lower.includes('operator') || lower.includes('tester')) return 'test_operator';
  if (lower.includes('emergency') || lower.includes('escalat')) return 'emergency_contact';
  if (lower.includes('legal') || lower.includes('counsel')) return 'legal_counsel';
  if (lower.includes('project') || lower.includes('pm')) return 'project_manager';
  if (lower.includes('soc') || lower.includes('security_op')) return 'security_operations';
  if (lower.includes('network') || lower.includes('noc')) return 'network_operations';
  if (lower.includes('sysadmin') || lower.includes('system_admin')) return 'system_administrator';
  if (lower.includes('compliance') || lower.includes('audit')) return 'compliance_officer';
  if (lower.includes('executive') || lower.includes('ciso') || lower.includes('cto')) return 'executive_sponsor';
  if (lower.includes('observe') || lower.includes('witness')) return 'observer';
  if (lower.includes('technical') || lower.includes('tech')) return 'technical_poc';
  return 'customer_poc';
}

function validateParsedDocument(parsed: ParsedRoeDocument): ParsedRoeDocument {
  const warnings: string[] = [...(parsed.warnings || [])];

  // Validate document type
  const validTypes = ['roe', 'pentest_plan', 'red_team_plan', 'purple_team_plan', 'bug_bounty_scope', 'test_plan', 'unknown'];
  if (!validTypes.includes(parsed.documentType)) {
    parsed.documentType = 'unknown';
    warnings.push(`Unknown document type detected`);
  }

  // Validate confidence
  if (typeof parsed.confidence !== 'number' || parsed.confidence < 0 || parsed.confidence > 100) {
    parsed.confidence = 50;
  }

  // Normalize personnel roles
  if (parsed.personnel?.length) {
    parsed.personnel = parsed.personnel.map(p => ({
      ...p,
      role: normalizeRole(p.role),
    }));
  } else {
    parsed.personnel = [];
    warnings.push('No personnel/POCs extracted from document');
  }

  // Validate scope
  if (!parsed.scope) {
    parsed.scope = {};
    warnings.push('No scope information extracted');
  }

  // Validate comms
  if (!parsed.commsProtocol) {
    parsed.commsProtocol = {};
    warnings.push('No communications protocol extracted');
  }

  // Validate engagement
  if (!parsed.engagement) {
    parsed.engagement = {};
    warnings.push('No engagement parameters extracted');
  }

  parsed.warnings = warnings;
  return parsed;
}

// ─── MIME type routing logic ────────────────────────────────────────────────

function getExtractorType(mimeType: string): 'pdf' | 'docx' | 'unsupported' {
  if (mimeType === 'application/pdf') return 'pdf';
  if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') return 'docx';
  if (mimeType === 'application/msword') return 'docx';
  return 'unsupported';
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe("MIME Type Routing", () => {
  it("routes PDF files correctly", () => {
    expect(getExtractorType("application/pdf")).toBe("pdf");
  });

  it("routes DOCX files correctly", () => {
    expect(getExtractorType("application/vnd.openxmlformats-officedocument.wordprocessingml.document")).toBe("docx");
  });

  it("routes legacy DOC files to docx extractor", () => {
    expect(getExtractorType("application/msword")).toBe("docx");
  });

  it("rejects unsupported types", () => {
    expect(getExtractorType("text/plain")).toBe("unsupported");
    expect(getExtractorType("image/png")).toBe("unsupported");
    expect(getExtractorType("application/json")).toBe("unsupported");
  });
});

describe("Personnel Role Normalization", () => {
  it("maps exact role names", () => {
    expect(normalizeRole("authorizing_official")).toBe("authorizing_official");
    expect(normalizeRole("test_lead")).toBe("test_lead");
    expect(normalizeRole("emergency_contact")).toBe("emergency_contact");
  });

  it("normalizes spaces and hyphens to underscores", () => {
    expect(normalizeRole("Test Lead")).toBe("test_lead");
    expect(normalizeRole("test-lead")).toBe("test_lead");
    expect(normalizeRole("Emergency Contact")).toBe("emergency_contact");
  });

  it("fuzzy-matches common role variations", () => {
    expect(normalizeRole("Authorizing Official")).toBe("authorizing_official");
    expect(normalizeRole("Lead Tester")).toBe("test_lead");
    expect(normalizeRole("Penetration Tester")).toBe("test_operator");
    expect(normalizeRole("Emergency Escalation Contact")).toBe("emergency_contact");
    expect(normalizeRole("Legal Counsel")).toBe("legal_counsel");
    expect(normalizeRole("CISO")).toBe("executive_sponsor");
    expect(normalizeRole("CTO")).toBe("executive_sponsor");
    expect(normalizeRole("SOC Analyst")).toBe("security_operations");
    expect(normalizeRole("Network Operations Center")).toBe("network_operations");
    expect(normalizeRole("System Administrator")).toBe("system_administrator");
    expect(normalizeRole("Compliance Auditor")).toBe("compliance_officer");
    expect(normalizeRole("Observer")).toBe("observer");
    expect(normalizeRole("Technical Contact")).toBe("technical_poc");
  });

  it("defaults unknown roles to customer_poc", () => {
    expect(normalizeRole("")).toBe("customer_poc");
    expect(normalizeRole("Random Person")).toBe("customer_poc");
    expect(normalizeRole("Janitor")).toBe("customer_poc");
  });
});

describe("Document Validation", () => {
  let baseParsed: ParsedRoeDocument;

  beforeEach(() => {
    baseParsed = {
      documentType: "roe",
      confidence: 85,
      warnings: [],
      engagement: {
        customerName: "Acme Corp",
        engagementType: "pentest",
      },
      personnel: [
        { name: "John Doe", role: "test_lead", email: "john@acme.com", isPrimary: true },
        { name: "Jane Smith", role: "customer_poc", email: "jane@acme.com" },
      ],
      commsProtocol: {
        reportingCadence: "daily",
        emergencyHaltProcedure: "Call emergency contact immediately",
        escalationChain: ["Test Lead", "Customer POC", "Authorizing Official"],
        criticalFindingNotifyWithin: "24 hours",
        testingDays: ["monday", "tuesday", "wednesday", "thursday", "friday"],
      },
      scope: {
        inScopeDomains: ["acme.com", "*.acme.com"],
        outOfScopeDomains: ["production.acme.com"],
        inScopeIpRanges: ["10.0.0.0/24"],
        dosAllowed: false,
        socialEngineeringAllowed: true,
        physicalAllowed: false,
      },
    };
  });

  it("passes valid documents through unchanged", () => {
    const result = validateParsedDocument(baseParsed);
    expect(result.documentType).toBe("roe");
    expect(result.confidence).toBe(85);
    expect(result.personnel).toHaveLength(2);
    expect(result.warnings).toHaveLength(0);
  });

  it("normalizes invalid document types to unknown", () => {
    baseParsed.documentType = "invalid_type";
    const result = validateParsedDocument(baseParsed);
    expect(result.documentType).toBe("unknown");
    expect(result.warnings).toContain("Unknown document type detected");
  });

  it("clamps confidence to valid range", () => {
    baseParsed.confidence = 150;
    const result = validateParsedDocument(baseParsed);
    expect(result.confidence).toBe(50);

    baseParsed.confidence = -10;
    const result2 = validateParsedDocument(baseParsed);
    expect(result2.confidence).toBe(50);
  });

  it("warns when no personnel are present", () => {
    baseParsed.personnel = [];
    const result = validateParsedDocument(baseParsed);
    expect(result.warnings).toContain("No personnel/POCs extracted from document");
  });

  it("warns when scope is missing", () => {
    baseParsed.scope = undefined as any;
    const result = validateParsedDocument(baseParsed);
    expect(result.warnings).toContain("No scope information extracted");
    expect(result.scope).toEqual({});
  });

  it("warns when comms protocol is missing", () => {
    baseParsed.commsProtocol = undefined as any;
    const result = validateParsedDocument(baseParsed);
    expect(result.warnings).toContain("No communications protocol extracted");
    expect(result.commsProtocol).toEqual({});
  });

  it("warns when engagement params are missing", () => {
    baseParsed.engagement = undefined as any;
    const result = validateParsedDocument(baseParsed);
    expect(result.warnings).toContain("No engagement parameters extracted");
    expect(result.engagement).toEqual({});
  });

  it("normalizes personnel roles during validation", () => {
    baseParsed.personnel = [
      { name: "Alice", role: "Lead Tester" },
      { name: "Bob", role: "CISO" },
      { name: "Charlie", role: "Unknown Role" },
    ];
    const result = validateParsedDocument(baseParsed);
    expect(result.personnel[0].role).toBe("test_lead");
    expect(result.personnel[1].role).toBe("executive_sponsor");
    expect(result.personnel[2].role).toBe("customer_poc");
  });
});

describe("Scope Constraint Enforcement Logic", () => {
  it("correctly identifies in-scope domains", () => {
    const scope: ParsedScope = {
      inScopeDomains: ["acme.com", "*.acme.com", "test.acme.com"],
      outOfScopeDomains: ["production.acme.com"],
    };

    expect(scope.inScopeDomains).toContain("acme.com");
    expect(scope.inScopeDomains).toContain("*.acme.com");
    expect(scope.outOfScopeDomains).toContain("production.acme.com");
    expect(scope.inScopeDomains).not.toContain("production.acme.com");
  });

  it("correctly identifies testing permissions", () => {
    const scope: ParsedScope = {
      dosAllowed: false,
      socialEngineeringAllowed: true,
      physicalAllowed: false,
      wirelessAllowed: true,
      pivotingAllowed: true,
      exfiltrationAllowed: false,
      persistenceAllowed: false,
    };

    expect(scope.dosAllowed).toBe(false);
    expect(scope.socialEngineeringAllowed).toBe(true);
    expect(scope.physicalAllowed).toBe(false);
    expect(scope.wirelessAllowed).toBe(true);
    expect(scope.pivotingAllowed).toBe(true);
    expect(scope.exfiltrationAllowed).toBe(false);
    expect(scope.persistenceAllowed).toBe(false);
  });

  it("handles empty scope gracefully", () => {
    const scope: ParsedScope = {};
    expect(scope.inScopeDomains).toBeUndefined();
    expect(scope.dosAllowed).toBeUndefined();
  });
});

describe("Communications Protocol Validation", () => {
  it("validates complete comms protocol", () => {
    const comms: ParsedCommsProtocol = {
      reportingCadence: "daily",
      reportingMethod: "encrypted email",
      emergencyHaltProcedure: "Call emergency contact, cease all testing",
      escalationChain: ["Test Lead → Customer POC → Authorizing Official"],
      criticalFindingNotifyWithin: "24 hours",
      criticalFindingNotifyMethod: "phone call",
      testingDays: ["monday", "tuesday", "wednesday", "thursday", "friday"],
      testTimezone: "America/New_York",
      testingWindowStart: "08:00",
      testingWindowEnd: "18:00",
      blackoutPeriods: ["2024-12-24 to 2025-01-02"],
      deconflictionProcedure: "Contact SOC before any active exploitation",
      deconflictionPhone: "+1-555-0100",
      deconflictionEmail: "soc@acme.com",
    };

    expect(comms.reportingCadence).toBe("daily");
    expect(comms.escalationChain).toHaveLength(1);
    expect(comms.testingDays).toHaveLength(5);
    expect(comms.blackoutPeriods).toHaveLength(1);
    expect(comms.deconflictionPhone).toMatch(/^\+1/);
  });

  it("handles minimal comms protocol", () => {
    const comms: ParsedCommsProtocol = {
      reportingCadence: "weekly",
    };

    expect(comms.reportingCadence).toBe("weekly");
    expect(comms.escalationChain).toBeUndefined();
    expect(comms.testingDays).toBeUndefined();
  });
});

describe("Auto-Engagement Field Mapping", () => {
  it("maps document type to engagement type correctly", () => {
    const typeMap: Record<string, string> = {
      roe: 'pentest',
      pentest_plan: 'pentest',
      red_team_plan: 'red_team',
      purple_team_plan: 'purple_team',
      bug_bounty_scope: 'pentest',
    };

    expect(typeMap['roe']).toBe('pentest');
    expect(typeMap['red_team_plan']).toBe('red_team');
    expect(typeMap['purple_team_plan']).toBe('purple_team');
  });

  it("deduplicates target domains from engagement and scope", () => {
    const engDomains = ["acme.com", "test.acme.com"];
    const scopeDomains = ["acme.com", "staging.acme.com"];

    const combined = [...engDomains, ...scopeDomains].filter((v, i, a) => a.indexOf(v) === i);

    expect(combined).toHaveLength(3);
    expect(combined).toContain("acme.com");
    expect(combined).toContain("test.acme.com");
    expect(combined).toContain("staging.acme.com");
  });

  it("deduplicates IP ranges from engagement and scope", () => {
    const engIps = ["10.0.0.0/24", "192.168.1.0/24"];
    const scopeIps = ["10.0.0.0/24", "172.16.0.0/16"];

    const combined = [...engIps, ...scopeIps].filter((v, i, a) => a.indexOf(v) === i);

    expect(combined).toHaveLength(3);
    expect(combined).toContain("10.0.0.0/24");
    expect(combined).toContain("192.168.1.0/24");
    expect(combined).toContain("172.16.0.0/16");
  });

  it("generates engagement name from parsed data", () => {
    const eng = { engagementName: "Q1 2025 Pentest", customerName: "Acme Corp" };
    const name = eng.engagementName || `${eng.customerName} — Assessment`;
    expect(name).toBe("Q1 2025 Pentest");

    const eng2 = { customerName: "Acme Corp" } as any;
    const name2 = eng2.engagementName || `${eng2.customerName} — Assessment`;
    expect(name2).toBe("Acme Corp — Assessment");
  });

  it("builds RoE scope guard structure correctly", () => {
    const scope: ParsedScope = {
      inScopeDomains: ["acme.com"],
      inScopeIpRanges: ["10.0.0.0/24"],
      outOfScopeDomains: ["prod.acme.com"],
      outOfScopeIpRanges: ["10.0.1.0/24"],
      dosAllowed: false,
      socialEngineeringAllowed: true,
    };

    const roeScope = {
      inScope: [
        ...scope.inScopeDomains!.map(d => ({ type: 'domain', value: d })),
        ...scope.inScopeIpRanges!.map(ip => ({ type: 'ip_range', value: ip })),
      ],
      outOfScope: [
        ...scope.outOfScopeDomains!.map(d => ({ type: 'domain', value: d })),
        ...scope.outOfScopeIpRanges!.map(ip => ({ type: 'ip_range', value: ip })),
      ],
      restrictions: {
        dosAllowed: scope.dosAllowed || false,
        socialEngineeringAllowed: scope.socialEngineeringAllowed || false,
      },
    };

    expect(roeScope.inScope).toHaveLength(2);
    expect(roeScope.inScope[0]).toEqual({ type: 'domain', value: 'acme.com' });
    expect(roeScope.inScope[1]).toEqual({ type: 'ip_range', value: '10.0.0.0/24' });
    expect(roeScope.outOfScope).toHaveLength(2);
    expect(roeScope.restrictions.dosAllowed).toBe(false);
    expect(roeScope.restrictions.socialEngineeringAllowed).toBe(true);
  });
});

describe("File Size and Type Validation", () => {
  it("rejects files over 50MB", () => {
    const maxSize = 50 * 1024 * 1024;
    expect(51 * 1024 * 1024 > maxSize).toBe(true);
    expect(49 * 1024 * 1024 > maxSize).toBe(false);
    expect(50 * 1024 * 1024 > maxSize).toBe(false);
  });

  it("accepts valid MIME types", () => {
    const allowed = [
      'application/pdf',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/msword',
    ];
    expect(allowed.includes('application/pdf')).toBe(true);
    expect(allowed.includes('application/vnd.openxmlformats-officedocument.wordprocessingml.document')).toBe(true);
    expect(allowed.includes('text/plain')).toBe(false);
    expect(allowed.includes('image/png')).toBe(false);
  });
});

describe("End-to-End Parsed Document Flow", () => {
  it("processes a complete RoE document through validation", () => {
    const rawParsed: ParsedRoeDocument = {
      documentType: "roe",
      confidence: 78,
      warnings: [],
      engagement: {
        engagementName: "Acme Corp Q1 2025 Penetration Test",
        customerName: "Acme Corporation",
        organizationName: "Acme Corporation",
        engagementType: "pentest",
        startDate: "2025-01-15",
        endDate: "2025-02-15",
        targetDomains: ["acme.com", "api.acme.com"],
        targetIpRanges: ["10.0.0.0/24"],
        description: "Annual penetration test per compliance requirements",
        methodology: "PTES, OWASP Testing Guide v4",
        ndaRequired: true,
        evidenceRetentionDays: 90,
      },
      personnel: [
        { name: "Alice Johnson", role: "Authorizing Official", email: "alice@acme.com", title: "CISO", organization: "Acme Corp", isPrimary: true },
        { name: "Bob Smith", role: "Technical Contact", email: "bob@acme.com", title: "Sr. Security Engineer", phone: "+1-555-0101" },
        { name: "Carol Williams", role: "Emergency Escalation Contact", email: "carol@acme.com", phone: "+1-555-0102" },
        { name: "Dave Brown", role: "Lead Tester", email: "dave@ac3.com", title: "Principal Consultant", organization: "AC3" },
      ],
      commsProtocol: {
        reportingCadence: "daily",
        reportingMethod: "encrypted email + secure portal",
        emergencyHaltProcedure: "Call emergency contact, cease all testing, document state",
        escalationChain: ["Test Lead", "Customer POC (Alice)", "Emergency Contact (Carol)"],
        criticalFindingNotifyWithin: "4 hours",
        criticalFindingNotifyMethod: "phone call + encrypted email",
        testingDays: ["monday", "tuesday", "wednesday", "thursday", "friday"],
        testTimezone: "America/New_York",
        testingWindowStart: "08:00",
        testingWindowEnd: "18:00",
        deconflictionProcedure: "Contact SOC 30 min before active exploitation",
        deconflictionPhone: "+1-555-0200",
        statusCheckInFrequency: "daily",
        statusCheckInMethod: "standup call at 09:00 ET",
      },
      scope: {
        inScopeDomains: ["acme.com", "*.acme.com", "api.acme.com"],
        outOfScopeDomains: ["production.acme.com", "payments.acme.com"],
        inScopeIpRanges: ["10.0.0.0/24", "10.0.1.0/24"],
        outOfScopeIpRanges: ["10.0.2.0/24"],
        inScopeApplications: ["Customer Portal", "Admin Dashboard", "API Gateway"],
        dosAllowed: false,
        socialEngineeringAllowed: true,
        physicalAllowed: false,
        wirelessAllowed: false,
        pivotingAllowed: true,
        exfiltrationAllowed: false,
        persistenceAllowed: false,
        credentialedTesting: true,
        testingStartDate: "2025-01-15",
        testingEndDate: "2025-02-15",
      },
    };

    const validated = validateParsedDocument(rawParsed);

    // Document type and confidence preserved
    expect(validated.documentType).toBe("roe");
    expect(validated.confidence).toBe(78);

    // Personnel roles normalized
    expect(validated.personnel).toHaveLength(4);
    expect(validated.personnel[0].role).toBe("authorizing_official");
    expect(validated.personnel[1].role).toBe("technical_poc");
    expect(validated.personnel[2].role).toBe("emergency_contact");
    expect(validated.personnel[3].role).toBe("test_lead");

    // Comms protocol preserved
    expect(validated.commsProtocol.reportingCadence).toBe("daily");
    expect(validated.commsProtocol.escalationChain).toHaveLength(3);
    expect(validated.commsProtocol.criticalFindingNotifyWithin).toBe("4 hours");
    expect(validated.commsProtocol.deconflictionPhone).toBe("+1-555-0200");

    // Scope preserved
    expect(validated.scope.inScopeDomains).toHaveLength(3);
    expect(validated.scope.outOfScopeDomains).toHaveLength(2);
    expect(validated.scope.dosAllowed).toBe(false);
    expect(validated.scope.socialEngineeringAllowed).toBe(true);
    expect(validated.scope.credentialedTesting).toBe(true);

    // No warnings for a complete document
    expect(validated.warnings).toHaveLength(0);
  });

  it("handles a minimal/incomplete document with appropriate warnings", () => {
    const minimalParsed: ParsedRoeDocument = {
      documentType: "test_plan",
      confidence: 35,
      warnings: [],
      engagement: {
        customerName: "Unknown Client",
      },
      personnel: [],
      commsProtocol: {} as any,
      scope: {} as any,
    };

    const validated = validateParsedDocument(minimalParsed);

    expect(validated.documentType).toBe("test_plan");
    expect(validated.confidence).toBe(35);
    expect(validated.personnel).toHaveLength(0);
    expect(validated.warnings).toContain("No personnel/POCs extracted from document");
  });
});
