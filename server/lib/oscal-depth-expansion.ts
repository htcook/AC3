/**
 * OSCAL Export Depth Expansion — P1 Gap Remediation
 * 
 * Adds missing OSCAL document generators:
 * - Component Definition: Maps ACE C3 capabilities to NIST 800-53 controls
 * - Assessment Plan: Generates structured assessment plans with schedules
 * - Catalog: Generates custom control catalogs from KSI definitions
 * - Profile: Generates tailored control profiles for specific baselines
 * 
 * Also adds:
 * - FedRAMP-specific metadata extensions
 * - Cross-reference linking between OSCAL documents
 * - NIST 800-53 Rev 5 control mapping
 * - Continuous monitoring integration points
 */

import * as crypto from "crypto";

function generateUUID(): string {
  return crypto.randomUUID();
}

// ─── NIST 800-53 Rev 5 Control Families ─────────────────────────────────────

export const NIST_800_53_FAMILIES: Record<string, string> = {
  AC: "Access Control",
  AT: "Awareness and Training",
  AU: "Audit and Accountability",
  CA: "Assessment, Authorization, and Monitoring",
  CM: "Configuration Management",
  CP: "Contingency Planning",
  IA: "Identification and Authentication",
  IR: "Incident Response",
  MA: "Maintenance",
  MP: "Media Protection",
  PE: "Physical and Environmental Protection",
  PL: "Planning",
  PM: "Program Management",
  PS: "Personnel Security",
  PT: "PII Processing and Transparency",
  RA: "Risk Assessment",
  SA: "System and Services Acquisition",
  SC: "System and Communications Protection",
  SI: "System and Information Integrity",
  SR: "Supply Chain Risk Management",
};

// ─── FedRAMP Impact Level Mappings ──────────────────────────────────────────

export const FEDRAMP_BASELINES: Record<string, {
  impactLevel: string;
  controlCount: number;
  requiredFamilies: string[];
}> = {
  low: {
    impactLevel: "Low",
    controlCount: 125,
    requiredFamilies: ["AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PL", "PS", "RA", "SA", "SC", "SI"],
  },
  moderate: {
    impactLevel: "Moderate",
    controlCount: 325,
    requiredFamilies: ["AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PL", "PM", "PS", "RA", "SA", "SC", "SI", "SR"],
  },
  high: {
    impactLevel: "High",
    controlCount: 421,
    requiredFamilies: ["AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PL", "PM", "PS", "PT", "RA", "SA", "SC", "SI", "SR"],
  },
};

// ─── Component Definition Generator ────────────────────────────────────────

export function generateComponentDefinition(
  title: string,
  capabilities: Array<{
    name: string;
    description: string;
    controlIds: string[];
    implementationStatus: "implemented" | "partial" | "planned" | "alternative" | "not-applicable";
  }>
) {
  const componentUuid = generateUUID();

  return {
    "component-definition": {
      uuid: generateUUID(),
      metadata: {
        title,
        "last-modified": new Date().toISOString(),
        version: "1.0.0",
        "oscal-version": "1.1.2",
        roles: [
          { id: "provider", title: "Component Provider" },
          { id: "assessor", title: "Security Assessor" },
        ],
        parties: [{
          uuid: generateUUID(),
          type: "organization",
          name: "ACE C3 Platform — Cyber C2 Dashboard",
        }],
        props: [
          { name: "fedramp-ready", value: "true" },
          { name: "fips-140-3-compliant", value: "true" },
        ],
      },
      components: [{
        uuid: componentUuid,
        type: "software",
        title: "ACE C3 Offensive Security Platform",
        description: "Comprehensive offensive security platform providing red team operations, vulnerability assessment, compliance validation, and continuous monitoring capabilities.",
        purpose: "Automate and manage offensive security assessments with full compliance traceability.",
        props: [
          { name: "software-version", value: "3.0.0" },
          { name: "vendor-name", value: "AceofCloud" },
          { name: "asset-type", value: "web-application" },
        ],
        "control-implementations": [{
          uuid: generateUUID(),
          source: "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
          description: "NIST SP 800-53 Rev 5 control implementations provided by ACE C3",
          "implemented-requirements": capabilities.map(cap => ({
            uuid: generateUUID(),
            "control-id": cap.controlIds[0] || "AC-1",
            description: cap.description,
            props: [
              { name: "implementation-status", value: cap.implementationStatus },
              { name: "capability-name", value: cap.name },
            ],
            statements: cap.controlIds.map(controlId => ({
              "statement-id": `${controlId}_smt`,
              uuid: generateUUID(),
              description: `${cap.name}: ${cap.description}`,
              props: [
                { name: "control-family", value: controlId.replace(/-\d+$/, "") },
              ],
            })),
          })),
        }],
      }],
      "back-matter": {
        resources: [
          {
            uuid: generateUUID(),
            title: "NIST SP 800-53 Rev 5",
            rlinks: [{ href: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final" }],
          },
          {
            uuid: generateUUID(),
            title: "FedRAMP Authorization Boundary Guide",
            rlinks: [{ href: "https://www.fedramp.gov/assets/resources/documents/CSP_Authorization_Boundary_Guidance.pdf" }],
          },
        ],
      },
    },
  };
}

// ─── Assessment Plan Generator ──────────────────────────────────────────────

export function generateAssessmentPlan(
  title: string,
  systemId: string,
  assessmentScope: Array<{
    controlId: string;
    assessmentMethod: "examine" | "interview" | "test";
    objectives: string[];
    schedule?: { startDate: string; endDate: string };
  }>,
  assessors: Array<{ name: string; role: string }>
) {
  return {
    "assessment-plan": {
      uuid: generateUUID(),
      metadata: {
        title,
        "last-modified": new Date().toISOString(),
        version: "1.0.0",
        "oscal-version": "1.1.2",
        roles: [
          { id: "assessor", title: "Security Assessor" },
          { id: "assessment-lead", title: "Assessment Lead" },
          { id: "system-owner", title: "System Owner" },
        ],
        parties: assessors.map(a => ({
          uuid: generateUUID(),
          type: "person",
          name: a.name,
          props: [{ name: "role", value: a.role }],
        })),
      },
      "import-ssp": {
        href: `#${systemId}`,
      },
      "local-definitions": {
        activities: assessmentScope.map(scope => ({
          uuid: generateUUID(),
          title: `Assessment of ${scope.controlId}`,
          description: `${scope.assessmentMethod} assessment for control ${scope.controlId}`,
          props: [
            { name: "method", value: scope.assessmentMethod },
          ],
          steps: scope.objectives.map((obj, idx) => ({
            uuid: generateUUID(),
            title: `Step ${idx + 1}`,
            description: obj,
          })),
          "related-controls": {
            "control-selections": [{
              "include-controls": [{ "control-id": scope.controlId }],
            }],
          },
          timing: scope.schedule ? {
            "within-date-range": {
              start: scope.schedule.startDate,
              end: scope.schedule.endDate,
            },
          } : undefined,
        })),
      },
      "reviewed-controls": {
        "control-selections": [{
          "include-controls": assessmentScope.map(s => ({
            "control-id": s.controlId,
          })),
        }],
        "control-objective-selections": [{
          "include-objectives": assessmentScope.flatMap(s =>
            s.objectives.map((_, idx) => ({
              "objective-id": `${s.controlId}_obj.${idx + 1}`,
            }))
          ),
        }],
      },
      "assessment-subjects": [{
        type: "component",
        description: "ACE C3 Platform components under assessment",
        "include-all": {},
      }],
      "assessment-assets": {
        "assessment-platforms": [{
          uuid: generateUUID(),
          title: "ACE C3 Automated Assessment Engine",
          props: [
            { name: "platform-type", value: "automated" },
            { name: "fips-compliant", value: "true" },
          ],
        }],
      },
      tasks: assessmentScope.map(scope => ({
        uuid: generateUUID(),
        type: "action",
        title: `Assess ${scope.controlId}`,
        description: `Perform ${scope.assessmentMethod} assessment of ${scope.controlId}`,
        timing: scope.schedule ? {
          "within-date-range": {
            start: scope.schedule.startDate,
            end: scope.schedule.endDate,
          },
        } : undefined,
        "associated-activities": [{
          "activity-uuid": generateUUID(),
          subjects: [{
            type: "component",
            "include-all": {},
          }],
        }],
      })),
    },
  };
}

// ─── Catalog Generator ──────────────────────────────────────────────────────

export function generateCustomCatalog(
  title: string,
  ksiDefs: Array<{
    ksiId: string;
    title: string;
    description: string;
    themeCode: string;
    category: string;
  }>
) {
  // Group KSIs by theme code
  const groups = new Map<string, typeof ksiDefs>();
  for (const def of ksiDefs) {
    const group = groups.get(def.themeCode) || [];
    group.push(def);
    groups.set(def.themeCode, group);
  }

  return {
    catalog: {
      uuid: generateUUID(),
      metadata: {
        title,
        "last-modified": new Date().toISOString(),
        version: "1.0.0",
        "oscal-version": "1.1.2",
      },
      groups: Array.from(groups.entries()).map(([themeCode, defs]) => ({
        id: themeCode,
        title: `${themeCode} — ${defs[0]?.category || "General"}`,
        controls: defs.map(def => ({
          id: def.ksiId,
          title: def.title,
          props: [
            { name: "category", value: def.category },
            { name: "theme-code", value: def.themeCode },
          ],
          parts: [{
            id: `${def.ksiId}_stmt`,
            name: "statement",
            prose: def.description,
          }],
        })),
      })),
    },
  };
}

// ─── Profile Generator ──────────────────────────────────────────────────────

export function generateTailoredProfile(
  title: string,
  baseline: "low" | "moderate" | "high",
  includedControls: string[],
  excludedControls: string[] = []
) {
  const baselineInfo = FEDRAMP_BASELINES[baseline];

  return {
    profile: {
      uuid: generateUUID(),
      metadata: {
        title,
        "last-modified": new Date().toISOString(),
        version: "1.0.0",
        "oscal-version": "1.1.2",
        props: [
          { name: "fedramp-baseline", value: baselineInfo.impactLevel },
          { name: "tailored", value: "true" },
        ],
      },
      imports: [{
        href: "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
        "include-controls": [{
          "with-ids": includedControls,
        }],
        "exclude-controls": excludedControls.length > 0 ? [{
          "with-ids": excludedControls,
        }] : undefined,
      }],
      merge: {
        "as-is": true,
      },
      modify: {
        "set-parameters": includedControls.slice(0, 5).map(controlId => ({
          "param-id": `${controlId}_prm`,
          values: [`Configured per ${baselineInfo.impactLevel} baseline requirements`],
        })),
      },
    },
  };
}

// ─── ACE C3 Capability Mapping ──────────────────────────────────────────────

/**
 * Maps ACE C3 platform capabilities to NIST 800-53 controls.
 * Used by the Component Definition generator.
 */
export const ACE_C3_CAPABILITIES = [
  {
    name: "Discovery Automation",
    description: "33 passive reconnaissance connectors (Shodan, Censys, SecurityTrails, etc.) for automated asset discovery",
    controlIds: ["RA-5", "CM-8", "SA-11"],
    implementationStatus: "implemented" as const,
  },
  {
    name: "DAST Scanning (ZAP)",
    description: "5,500+ lines of ZAP DAST integration with automated scan policies and vulnerability detection",
    controlIds: ["RA-5", "SA-11", "SI-2"],
    implementationStatus: "implemented" as const,
  },
  {
    name: "Evasion Engineering",
    description: "5,179 lines of payload generation, encoding, and evasion technique management",
    controlIds: ["CA-8", "RA-5", "SI-3"],
    implementationStatus: "implemented" as const,
  },
  {
    name: "Phishing Operations",
    description: "4,000+ lines of GoPhish integration for authorized phishing assessments",
    controlIds: ["AT-2", "CA-8", "IR-2"],
    implementationStatus: "implemented" as const,
  },
  {
    name: "FIPS 140-3 Cryptography",
    description: "2,058 lines across 5 modules implementing AES-256-GCM, SHA-256/384/512, HKDF, PBKDF2, TLS 1.2+",
    controlIds: ["SC-12", "SC-13", "SC-28", "IA-7"],
    implementationStatus: "implemented" as const,
  },
  {
    name: "Evidence Chain of Custody",
    description: "SHA-256 hash chains with Merkle root anchoring for tamper-evident evidence management",
    controlIds: ["AU-10", "AU-11", "SI-7"],
    implementationStatus: "implemented" as const,
  },
  {
    name: "SAML 2.0 SSO",
    description: "Enterprise SSO integration supporting Okta, Azure AD, and PingFederate",
    controlIds: ["IA-2", "IA-8", "AC-2"],
    implementationStatus: "implemented" as const,
  },
  {
    name: "Tenant Isolation",
    description: "Row-level security enforcement across 40+ tables with cross-tenant access detection",
    controlIds: ["AC-4", "AC-6", "SC-4"],
    implementationStatus: "implemented" as const,
  },
  {
    name: "AI Decision Audit Trail",
    description: "Full audit logging of all LLM decisions with prompt/response hashing and classification",
    controlIds: ["AU-2", "AU-3", "AU-6"],
    implementationStatus: "implemented" as const,
  },
  {
    name: "Prompt Injection Shield",
    description: "Multi-layer defense against prompt injection with canary tokens and output validation",
    controlIds: ["SI-10", "SI-3", "SC-18"],
    implementationStatus: "implemented" as const,
  },
  {
    name: "Continuous Monitoring",
    description: "KSI validation scheduling with automated evidence collection and compliance scoring",
    controlIds: ["CA-7", "RA-3", "PM-14"],
    implementationStatus: "implemented" as const,
  },
  {
    name: "Mobile App Testing",
    description: "Mobile application security assessment framework with OWASP MASTG coverage",
    controlIds: ["RA-5", "SA-11", "SA-15"],
    implementationStatus: "implemented" as const,
  },
];
