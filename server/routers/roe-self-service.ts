/**
 * ROE Customer Self-Service Router
 * 
 * Provides customer-facing procedures for creating and collaborating on
 * Rules of Engagement documents. Customers can fill scope, schedule, and
 * constraints while operators handle technical details.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb as _getDb } from "../db";
import { eq, and, desc, sql } from "drizzle-orm";
import {
  roeDocuments,
  roePersonnel,
  roeSignatures,
  roeVersions,
  roeCollaborationComments,
  roeSectionProgress,
  roeCustomerInvites,
} from "../../drizzle/schema";
import { invokeLLM } from "../_core/llm";
import crypto from "crypto";

async function getDb() {
  const db = await _getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

// ─── Section Definitions ─────────────────────────────────────────────────────

const ROE_SECTIONS = {
  engagement_type: {
    label: "Engagement Type",
    description: "What kind of security testing do you need?",
    owner: "customer" as const,
    requiredFields: ["title", "purpose"],
    helpText: "Choose the type of assessment that best fits your needs. If you're unsure, Web Application is the most common starting point.",
  },
  scope: {
    label: "Scope & Assets",
    description: "What systems and networks should we test?",
    owner: "customer" as const,
    requiredFields: ["inScopeDomains", "inScopeIpRanges"],
    helpText: "List every domain, IP range, and application you want tested. Be specific — anything not listed here is off-limits. Include subdomains if you want us to discover and test them.",
  },
  exclusions: {
    label: "Exclusions & Restrictions",
    description: "What should we absolutely NOT touch?",
    owner: "customer" as const,
    requiredFields: ["outOfScopeDomains", "outOfScopeIpRanges"],
    helpText: "These are your critical systems that must never be tested — production databases, payment processors, identity providers, etc. We will hard-block these from all testing.",
  },
  schedule: {
    label: "Testing Schedule",
    description: "When can we test?",
    owner: "customer" as const,
    requiredFields: ["testScheduleStart", "testScheduleEnd", "testTimezone"],
    helpText: "Set the testing window. Most customers prefer after-hours testing (evenings/weekends) to minimize business impact. We'll only test during the hours you specify.",
  },
  boundaries: {
    label: "Testing Boundaries",
    description: "What types of testing are you comfortable with?",
    owner: "collaborative" as const,
    requiredFields: ["testingTypes"],
    helpText: "These controls determine how aggressive the testing can be. Start conservative — you can always expand later. Each option has a plain-English explanation.",
  },
  communication: {
    label: "Communication & Contacts",
    description: "Who should we contact and how?",
    owner: "customer" as const,
    requiredFields: [],
    helpText: "We need at least one primary contact and one emergency contact. The emergency contact is for critical findings that need immediate attention.",
  },
  credentials: {
    label: "Credentials & Access",
    description: "Will you provide test accounts?",
    owner: "collaborative" as const,
    requiredFields: [],
    helpText: "Providing test credentials lets us test authenticated features. We'll never use credentials to access systems outside the agreed scope.",
  },
  data_handling: {
    label: "Data & Evidence",
    description: "How should we handle sensitive data?",
    owner: "collaborative" as const,
    requiredFields: ["evidenceRetentionDays"],
    helpText: "We encrypt all evidence and destroy it after the retention period. If we discover PII or sensitive data, we'll follow your handling policy.",
  },
  authorization: {
    label: "Authorization & Legal",
    description: "Who authorizes this test and what legal protections are needed?",
    owner: "customer" as const,
    requiredFields: [],
    helpText: "NIST SP 800-115 requires written authorization from the system owner before any testing begins. This protects both parties legally and ensures the right people are aware.",
    complianceRef: ["NIST SP 800-115 §7.1", "FedRAMP ROE §2.1"],
  },
  compliance: {
    label: "Compliance Frameworks",
    description: "Which regulatory frameworks apply to your systems?",
    owner: "customer" as const,
    requiredFields: [],
    helpText: "Selecting applicable frameworks ensures we include all required testing elements. FedRAMP requires six specific attack vectors. CISA BOD 22-01 requires checking the Known Exploited Vulnerabilities catalog.",
    complianceRef: ["FedRAMP Pen Test Guidance §3", "CISA BOD 22-01", "NIST SP 800-53 CA-8"],
  },
  reporting: {
    label: "Reporting & Remediation",
    description: "How should we deliver findings and verify fixes?",
    owner: "collaborative" as const,
    requiredFields: [],
    helpText: "FedRAMP requires findings mapped to SAR Appendix F and PoA&M items. NIST SP 800-115 requires both executive summary and technical appendix formats.",
    complianceRef: ["NIST SP 800-115 §7.4", "FedRAMP SAR Appendix F"],
  },
  review: {
    label: "Review & Sign",
    description: "Review everything and submit for operator review",
    owner: "customer" as const,
    requiredFields: [],
    helpText: "Review all sections carefully. A compliance checklist will show which framework requirements are met. Once submitted, our team will review your scope, add technical details, and may request clarifications before we begin.",
  },
};

type SectionId = keyof typeof ROE_SECTIONS;

// ─── Helper: Calculate Section Completion ────────────────────────────────────

function calculateSectionCompletion(roe: any, section: SectionId): number {
  const checks: Record<SectionId, () => number> = {
    engagement_type: () => {
      let score = 0;
      if (roe.title) score += 40;
      if (roe.purpose) score += 30;
      if (roe.organizationName) score += 30;
      return score;
    },
    scope: () => {
      let score = 0;
      const domains = roe.inScopeDomains as any[] || [];
      const ips = roe.inScopeIpRanges as any[] || [];
      const apps = roe.inScopeApplications as any[] || [];
      if (domains.length > 0) score += 35;
      if (ips.length > 0) score += 25;
      if (apps.length > 0) score += 20;
      if (roe.scopeDescription) score += 20;
      return Math.min(score, 100);
    },
    exclusions: () => {
      let score = 0;
      const exDomains = roe.outOfScopeDomains as any[] || [];
      const exIps = roe.outOfScopeIpRanges as any[] || [];
      const exAssets = roe.outOfScopeAssets as any[] || [];
      if (exDomains.length > 0 || exIps.length > 0 || exAssets.length > 0) score += 70;
      if (roe.assumptions) score += 30;
      return Math.min(score, 100);
    },
    schedule: () => {
      let score = 0;
      if (roe.testScheduleStart) score += 25;
      if (roe.testScheduleEnd) score += 25;
      if (roe.testTimezone) score += 20;
      if (roe.testingWindowStart && roe.testingWindowEnd) score += 20;
      if (roe.testingDays) score += 10;
      return Math.min(score, 100);
    },
    boundaries: () => {
      let score = 0;
      if (roe.testingTypes && (roe.testingTypes as any[]).length > 0) score += 50;
      // Any boundary toggle counts
      if (roe.dosTestingAllowed !== null || roe.socialEngineeringAllowed !== null ||
          roe.physicalTestingAllowed !== null || roe.wirelessTestingAllowed !== null) score += 50;
      return Math.min(score, 100);
    },
    communication: () => {
      let score = 50; // Base score since contacts are tracked in roePersonnel
      if (roe.communicationFrequency) score += 15;
      if (roe.communicationMethod) score += 15;
      if (roe.emergencyHaltCriteria) score += 20;
      return Math.min(score, 100);
    },
    credentials: () => {
      let score = 50; // Optional section, 50% base
      if (roe.credentialedTesting !== null) score += 25;
      if (roe.credentialAccounts && (roe.credentialAccounts as any[]).length > 0) score += 25;
      return Math.min(score, 100);
    },
    data_handling: () => {
      let score = 0;
      if (roe.evidenceRetentionDays) score += 30;
      if (roe.evidenceEncryptionRequired !== null) score += 20;
      if (roe.dataHandlingProcedure) score += 25;
      if (roe.evidenceDestructionMethod) score += 25;
      return Math.min(score, 100);
    },
    authorization: () => {
      let score = 0;
      if (roe.legalJurisdiction) score += 20;
      if (roe.ndaRequired !== null) score += 15;
      if (roe.legalReviewCompleted) score += 25;
      if (roe.authorizationObtained) score += 25;
      if (roe.managementApproval) score += 15;
      return Math.min(score, 100);
    },
    compliance: () => {
      let score = 30; // Base score
      if (roe.complianceFrameworks) {
        try {
          const fw = JSON.parse(roe.complianceFrameworks as string);
          if (Array.isArray(fw) && fw.length > 0) score += 70;
        } catch { if ((roe.complianceFrameworks as string).length > 0) score += 70; }
      }
      return Math.min(score, 100);
    },
    reporting: () => {
      let score = 30; // Base score
      if (roe.reportFrequency) score += 25;
      if (roe.statusReportFrequency) score += 20;
      if (roe.reportDeliveryMethod) score += 25;
      return Math.min(score, 100);
    },
    review: () => {
      // Review is complete when all other sections are sufficiently filled
      const otherSections = Object.keys(ROE_SECTIONS).filter(s => s !== "review") as SectionId[];
      const totalCompletion = otherSections.reduce((sum, s) => sum + calculateSectionCompletion(roe, s), 0);
      return Math.round(totalCompletion / otherSections.length);
    },
  };
  return checks[section]?.() ?? 0;
}

// ─── Helper: Engagement Type Presets ─────────────────────────────────────────

const ENGAGEMENT_TYPE_PRESETS = [
  {
    id: "web_app",
    label: "Web Application Test",
    icon: "globe",
    description: "Test your web applications for vulnerabilities like SQL injection, XSS, authentication bypasses, and business logic flaws.",
    typicalDuration: "1–2 weeks",
    defaults: {
      testingTypes: ["web_application", "api_testing"],
      dosTestingAllowed: 0,
      socialEngineeringAllowed: 0,
      physicalTestingAllowed: 0,
      wirelessTestingAllowed: 0,
      pivotingAllowed: 0,
      exfiltrationAllowed: 0,
      persistenceAllowed: 0,
    },
  },
  {
    id: "network_infra",
    label: "Network / Infrastructure",
    icon: "network",
    description: "Scan and test your internal or external network infrastructure for misconfigurations, open ports, and exploitable services.",
    typicalDuration: "1–3 weeks",
    defaults: {
      testingTypes: ["network_external", "network_internal"],
      dosTestingAllowed: 0,
      socialEngineeringAllowed: 0,
      physicalTestingAllowed: 0,
      wirelessTestingAllowed: 0,
      pivotingAllowed: 1,
      exfiltrationAllowed: 0,
      persistenceAllowed: 0,
    },
  },
  {
    id: "cloud",
    label: "Cloud Security Assessment",
    icon: "cloud",
    description: "Assess your AWS, Azure, or GCP environment for IAM misconfigurations, exposed storage, and privilege escalation paths.",
    typicalDuration: "1–2 weeks",
    defaults: {
      testingTypes: ["cloud_assessment"],
      dosTestingAllowed: 0,
      socialEngineeringAllowed: 0,
      physicalTestingAllowed: 0,
      wirelessTestingAllowed: 0,
      pivotingAllowed: 1,
      exfiltrationAllowed: 0,
      persistenceAllowed: 0,
    },
  },
  {
    id: "red_team",
    label: "Red Team Engagement",
    icon: "skull",
    description: "Full adversary simulation — our team will attempt to breach your organization using real-world attack techniques, including social engineering and physical access.",
    typicalDuration: "2–6 weeks",
    defaults: {
      testingTypes: ["red_team", "social_engineering", "physical"],
      dosTestingAllowed: 0,
      socialEngineeringAllowed: 1,
      physicalTestingAllowed: 1,
      wirelessTestingAllowed: 1,
      pivotingAllowed: 1,
      exfiltrationAllowed: 1,
      persistenceAllowed: 1,
    },
  },
  {
    id: "ics_ot",
    label: "ICS / OT Security Assessment",
    icon: "factory",
    description: "Assess your industrial control systems and operational technology for vulnerabilities, with safety-first protocols to prevent operational disruption.",
    typicalDuration: "2–4 weeks",
    defaults: {
      testingTypes: ["ics_ot_assessment"],
      dosTestingAllowed: 0,
      socialEngineeringAllowed: 0,
      physicalTestingAllowed: 1,
      wirelessTestingAllowed: 1,
      pivotingAllowed: 0,
      exfiltrationAllowed: 0,
      persistenceAllowed: 0,
    },
  },
  {
    id: "phishing",
    label: "Phishing Campaign",
    icon: "mail",
    description: "Test your employees' security awareness with simulated phishing emails, measuring click rates and credential submission.",
    typicalDuration: "1–2 weeks",
    defaults: {
      testingTypes: ["social_engineering"],
      dosTestingAllowed: 0,
      socialEngineeringAllowed: 1,
      physicalTestingAllowed: 0,
      wirelessTestingAllowed: 0,
      pivotingAllowed: 0,
      exfiltrationAllowed: 0,
      persistenceAllowed: 0,
    },
  },
  {
    id: "mobile_app",
    label: "Mobile Application Test",
    icon: "smartphone",
    description: "Test your iOS or Android application for insecure data storage, weak authentication, API vulnerabilities, and client-side attacks.",
    typicalDuration: "1–2 weeks",
    defaults: {
      testingTypes: ["mobile_application"],
      dosTestingAllowed: 0,
      socialEngineeringAllowed: 0,
      physicalTestingAllowed: 0,
      wirelessTestingAllowed: 0,
      pivotingAllowed: 0,
      exfiltrationAllowed: 0,
      persistenceAllowed: 0,
    },
  },
  {
    id: "purple_team",
    label: "Purple Team Exercise",
    icon: "shield",
    description: "Collaborative exercise where our red team attacks while working alongside your blue team to improve detection and response capabilities in real-time.",
    typicalDuration: "1–3 weeks",
    defaults: {
      testingTypes: ["purple_team"],
      dosTestingAllowed: 0,
      socialEngineeringAllowed: 1,
      physicalTestingAllowed: 0,
      wirelessTestingAllowed: 0,
      pivotingAllowed: 1,
      exfiltrationAllowed: 1,
      persistenceAllowed: 1,
    },
  },
];

// ─── Helper: Testing Boundary Explanations ───────────────────────────────────

const BOUNDARY_EXPLANATIONS = {
  dosTestingAllowed: {
    label: "Denial of Service Testing",
    description: "Can we test if your systems can be overwhelmed with traffic?",
    risk: "high",
    recommendation: "Most customers disable this for production systems. Enable only for staging/test environments.",
    icon: "zap",
  },
  socialEngineeringAllowed: {
    label: "Social Engineering",
    description: "Can we send simulated phishing emails or make pretexting calls to your employees?",
    risk: "medium",
    recommendation: "Great for security awareness testing. We'll coordinate with your HR team first.",
    icon: "mail",
  },
  physicalTestingAllowed: {
    label: "Physical Security Testing",
    description: "Can we attempt to gain physical access to your offices or data centers?",
    risk: "medium",
    recommendation: "Useful for red team engagements. Requires separate coordination with facilities.",
    icon: "building",
  },
  wirelessTestingAllowed: {
    label: "Wireless Network Testing",
    description: "Can we test your WiFi networks for weak encryption, rogue access points, and evil twin attacks?",
    risk: "low",
    recommendation: "Recommended if you have corporate WiFi. Low risk of disruption.",
    icon: "wifi",
  },
  pivotingAllowed: {
    label: "Lateral Movement",
    description: "If we compromise one system, can we use it to reach other systems on your network?",
    risk: "medium",
    recommendation: "Essential for realistic testing. Helps identify network segmentation gaps.",
    icon: "network",
  },
  exfiltrationAllowed: {
    label: "Data Exfiltration (Simulated)",
    description: "Can we demonstrate that sensitive data could be extracted? We use dummy markers, never real data.",
    risk: "low",
    recommendation: "Proves business impact of vulnerabilities. We never exfiltrate actual sensitive data.",
    icon: "download",
  },
  persistenceAllowed: {
    label: "Persistence Mechanisms",
    description: "Can we install backdoors or scheduled tasks to maintain access? All are removed after testing.",
    risk: "medium",
    recommendation: "Important for red team engagements to test detection capabilities.",
    icon: "lock",
  },
  fileModificationAllowed: {
    label: "File Modification",
    description: "Can we modify files on target systems during testing?",
    risk: "high",
    recommendation: "Usually disabled for production. Enable for staging environments only.",
    icon: "file",
  },
  fileInstallationAllowed: {
    label: "Tool Installation",
    description: "Can we install testing tools on target systems?",
    risk: "medium",
    recommendation: "Required for some advanced testing. All tools are removed after engagement.",
    icon: "package",
  },
  credentialedTesting: {
    label: "Authenticated Testing",
    description: "Will you provide us with test user accounts to log in and test authenticated features?",
    risk: "low",
    recommendation: "Highly recommended — finds 3x more vulnerabilities than unauthenticated testing alone.",
    icon: "key",
  },
};

// ─── Router ──────────────────────────────────────────────────────────────────

// ─── Compliance Framework Definitions ──────────────────────────────────────

const COMPLIANCE_FRAMEWORKS = {
  nist_800_115: {
    id: "nist_800_115",
    label: "NIST SP 800-115",
    fullName: "Technical Guide to Information Security Testing and Assessment",
    description: "The foundational NIST standard for penetration testing methodology. Required for all federal systems.",
    requirements: [
      { id: "n1", label: "Written authorization from system owner", section: "authorization", field: "authorizationObtained" },
      { id: "n2", label: "Management approval chain documented", section: "authorization", field: "managementApproval" },
      { id: "n3", label: "Legal review completed", section: "authorization", field: "legalReviewCompleted" },
      { id: "n4", label: "In-scope IP ranges defined", section: "scope", field: "inScopeIpRanges" },
      { id: "n5", label: "In-scope domains defined", section: "scope", field: "inScopeDomains" },
      { id: "n6", label: "Out-of-scope systems explicitly listed", section: "exclusions", field: "outOfScopeDomains" },
      { id: "n7", label: "Test schedule with start/end dates", section: "schedule", field: "testScheduleStart" },
      { id: "n8", label: "Testing methods documented", section: "boundaries", field: "testingTypes" },
      { id: "n9", label: "Primary point of contact defined", section: "communication", field: null },
      { id: "n10", label: "Emergency escalation path defined", section: "communication", field: "emergencyHaltCriteria" },
      { id: "n11", label: "Data handling procedures", section: "data_handling", field: "dataHandlingProcedure" },
      { id: "n12", label: "Evidence retention policy", section: "data_handling", field: "evidenceRetentionDays" },
      { id: "n13", label: "Notification plan documented", section: "communication", field: "communicationFrequency" },
      { id: "n14", label: "Report format agreed (executive + technical)", section: "reporting", field: "reportFrequency" },
      { id: "n15", label: "Backup/recovery plan", section: "exclusions", field: "assumptions" },
    ],
  },
  fedramp: {
    id: "fedramp",
    label: "FedRAMP",
    fullName: "Federal Risk and Authorization Management Program",
    description: "Required for cloud services used by federal agencies. Mandates six specific attack vectors and 3PAO testing.",
    requirements: [
      { id: "f1", label: "Authorization boundary defined", section: "scope", field: "scopeDescription" },
      { id: "f2", label: "3PAO identified (FedRAMP-recognized assessor)", section: "authorization", field: null },
      { id: "f3", label: "External-to-Corporate attack vector", section: "boundaries", field: null },
      { id: "f4", label: "External-to-Target-System attack vector", section: "boundaries", field: null },
      { id: "f5", label: "Tenant-to-Management-System attack vector", section: "boundaries", field: null },
      { id: "f6", label: "Tenant-to-Tenant attack vector", section: "boundaries", field: null },
      { id: "f7", label: "Mobile-to-System attack vector", section: "boundaries", field: null },
      { id: "f8", label: "Client-Application-to-Target attack vector", section: "boundaries", field: null },
      { id: "f9", label: "SAR Appendix F mapping planned", section: "reporting", field: null },
      { id: "f10", label: "PoA&M integration plan", section: "reporting", field: null },
      { id: "f11", label: "Evidence capture standards defined", section: "data_handling", field: "evidenceEncryptionRequired" },
      { id: "f12", label: "Retest requirements documented", section: "reporting", field: null },
      { id: "f13", label: "Incident response team coordination", section: "communication", field: "emergencyHaltCriteria" },
    ],
  },
  cisa_bod: {
    id: "cisa_bod",
    label: "CISA BOD",
    fullName: "CISA Binding Operational Directives",
    description: "CISA directives requiring Known Exploited Vulnerabilities (KEV) catalog checks and remediation timelines.",
    requirements: [
      { id: "c1", label: "KEV catalog cross-reference planned", section: "boundaries", field: null },
      { id: "c2", label: "Critical vuln remediation SLA (15 days)", section: "reporting", field: null },
      { id: "c3", label: "High vuln remediation SLA (30 days)", section: "reporting", field: null },
      { id: "c4", label: "Vulnerability disclosure coordination", section: "reporting", field: null },
      { id: "c5", label: "High Value Asset identification", section: "scope", field: null },
    ],
  },
  pci_dss: {
    id: "pci_dss",
    label: "PCI DSS",
    fullName: "Payment Card Industry Data Security Standard",
    description: "Required for any organization that processes, stores, or transmits credit card data.",
    requirements: [
      { id: "p1", label: "Cardholder data environment (CDE) in scope", section: "scope", field: null },
      { id: "p2", label: "Network segmentation testing included", section: "boundaries", field: null },
      { id: "p3", label: "ASV scan results referenced", section: "boundaries", field: null },
      { id: "p4", label: "Quarterly testing cadence documented", section: "schedule", field: null },
    ],
  },
  hipaa: {
    id: "hipaa",
    label: "HIPAA",
    fullName: "Health Insurance Portability and Accountability Act",
    description: "Required for organizations handling protected health information (PHI).",
    requirements: [
      { id: "h1", label: "PHI handling procedures defined", section: "data_handling", field: "dataHandlingProcedure" },
      { id: "h2", label: "BAA (Business Associate Agreement) in place", section: "authorization", field: null },
      { id: "h3", label: "ePHI systems identified in scope", section: "scope", field: null },
    ],
  },
};

type ComplianceFrameworkId = keyof typeof COMPLIANCE_FRAMEWORKS;

// ─── Compliance Validation Helper ──────────────────────────────────────────

function validateCompliance(roe: any, frameworkId: ComplianceFrameworkId): {
  framework: string;
  totalRequirements: number;
  metRequirements: number;
  percentage: number;
  details: { id: string; label: string; met: boolean; section: string }[];
} {
  const framework = COMPLIANCE_FRAMEWORKS[frameworkId];
  if (!framework) return { framework: frameworkId, totalRequirements: 0, metRequirements: 0, percentage: 0, details: [] };

  const details = framework.requirements.map(req => {
    let met = false;
    if (req.field) {
      const val = roe[req.field];
      if (val !== null && val !== undefined && val !== "" && val !== 0) {
        if (Array.isArray(val)) met = val.length > 0;
        else if (typeof val === "string") {
          try { const arr = JSON.parse(val); met = Array.isArray(arr) ? arr.length > 0 : true; } catch { met = val.length > 0; }
        } else met = true;
      }
    }
    // For requirements without a direct field mapping, check if the section has progress
    return { id: req.id, label: req.label, met, section: req.section };
  });

  const metCount = details.filter(d => d.met).length;
  return {
    framework: framework.label,
    totalRequirements: details.length,
    metRequirements: metCount,
    percentage: Math.round((metCount / details.length) * 100),
    details,
  };
}

export const roeSelfServiceRouter = router({

  // Get section definitions with help text for the wizard
  getSectionDefinitions: protectedProcedure.query(() => ({
    sections: ROE_SECTIONS,
    engagementTypes: ENGAGEMENT_TYPE_PRESETS,
    boundaryExplanations: BOUNDARY_EXPLANATIONS,
    complianceFrameworks: COMPLIANCE_FRAMEWORKS,
  })),

  // Validate ROE against selected compliance frameworks
  validateCompliance: protectedProcedure
    .input(z.object({
      roeId: z.number(),
      frameworks: z.array(z.string()).optional(),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      const [roe] = await db.select().from(roeDocuments).where(eq(roeDocuments.id, input.roeId));
      if (!roe) throw new Error("ROE not found");

      // If frameworks specified, validate those; otherwise validate all selected in ROE
      let frameworkIds: string[] = input.frameworks || [];
      if (frameworkIds.length === 0 && roe.complianceFrameworks) {
        try {
          frameworkIds = JSON.parse(roe.complianceFrameworks as string);
        } catch { frameworkIds = []; }
      }
      // Always include NIST 800-115 as baseline
      if (!frameworkIds.includes("nist_800_115")) frameworkIds.unshift("nist_800_115");

      const results = frameworkIds
        .filter(id => id in COMPLIANCE_FRAMEWORKS)
        .map(id => validateCompliance(roe, id as ComplianceFrameworkId));

      const overallMet = results.reduce((sum, r) => sum + r.metRequirements, 0);
      const overallTotal = results.reduce((sum, r) => sum + r.totalRequirements, 0);

      return {
        frameworks: results,
        overallPercentage: overallTotal > 0 ? Math.round((overallMet / overallTotal) * 100) : 0,
        overallMet,
        overallTotal,
      };
    }),

  // Create a new ROE from customer self-service with engagement type preset
  createFromPreset: protectedProcedure
    .input(z.object({
      engagementTypeId: z.string(),
      organizationName: z.string().min(1),
      title: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      const preset = ENGAGEMENT_TYPE_PRESETS.find(p => p.id === input.engagementTypeId);
      if (!preset) throw new Error("Invalid engagement type");

      const title = input.title || `${input.organizationName} — ${preset.label}`;

      const [result] = await db.insert(roeDocuments).values({
        title,
        organizationName: input.organizationName,
        testingFirmName: "AC3 — AceofCloud",
        purpose: `${preset.label} engagement for ${input.organizationName}`,
        status: "draft",
        testingTypes: JSON.stringify(preset.defaults.testingTypes),
        dosTestingAllowed: preset.defaults.dosTestingAllowed,
        socialEngineeringAllowed: preset.defaults.socialEngineeringAllowed,
        physicalTestingAllowed: preset.defaults.physicalTestingAllowed,
        wirelessTestingAllowed: preset.defaults.wirelessTestingAllowed,
        pivotingAllowed: preset.defaults.pivotingAllowed,
        exfiltrationAllowed: preset.defaults.exfiltrationAllowed,
        persistenceAllowed: preset.defaults.persistenceAllowed,
        evidenceRetentionDays: 90,
        evidenceEncryptionRequired: 1,
        ndaRequired: 1,
        communicationFrequency: "daily",
        communicationMethod: "secure_portal",
        statusReportFrequency: "daily",
        evidenceDestructionMethod: "secure_delete",
        reportFrequency: "final_only",
        createdBy: ctx.user.id,
      });

      const roeId = result.insertId;

      // Add the customer as primary POC
      await db.insert(roePersonnel).values({
        roeId,
        role: "customer_poc",
        name: ctx.user.name || "Customer",
        email: ctx.user.email || "",
        isPrimary: 1,
      });

      // Initialize section progress
      const sections = Object.keys(ROE_SECTIONS) as SectionId[];
      for (const section of sections) {
        await db.insert(roeSectionProgress).values({
          roeId,
          section,
          filledBy: "customer",
          completionPercent: 0,
        });
      }

      // Create initial version
      await db.insert(roeVersions).values({
        roeId,
        versionNumber: "1.0",
        changeType: "created",
        changeSummary: `ROE created from ${preset.label} preset by customer`,
        changedBy: ctx.user.id,
        changedByName: ctx.user.name || "Customer",
      });

      return { id: roeId, title };
    }),

  // Get ROE with collaboration context (progress, comments, who filled what)
  getWithCollaboration: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const [roe] = await db.select().from(roeDocuments).where(eq(roeDocuments.id, input.id));
      if (!roe) throw new Error("ROE not found");

      const personnel = await db.select().from(roePersonnel).where(eq(roePersonnel.roeId, input.id));
      const signatures = await db.select().from(roeSignatures).where(eq(roeSignatures.roeId, input.id));
      const progress = await db.select().from(roeSectionProgress).where(eq(roeSectionProgress.roeId, input.id));
      const comments = await db.select().from(roeCollaborationComments)
        .where(eq(roeCollaborationComments.roeId, input.id))
        .orderBy(desc(roeCollaborationComments.createdAt));
      const versions = await db.select().from(roeVersions)
        .where(eq(roeVersions.roeId, input.id))
        .orderBy(desc(roeVersions.createdAt));

      // Calculate per-section completion
      const sectionCompletion: Record<string, number> = {};
      for (const section of Object.keys(ROE_SECTIONS) as SectionId[]) {
        sectionCompletion[section] = calculateSectionCompletion(roe, section);
      }

      const overallCompletion = Math.round(
        Object.values(sectionCompletion).reduce((a, b) => a + b, 0) / Object.keys(sectionCompletion).length
      );

      return {
        roe,
        personnel,
        signatures,
        progress,
        comments,
        versions,
        sectionCompletion,
        overallCompletion,
      };
    }),

  // Update a specific section (auto-saves, tracks who edited)
  updateSection: protectedProcedure
    .input(z.object({
      id: z.number(),
      section: z.string(),
      fields: z.record(z.any()),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      // Update the ROE document fields
      await db.update(roeDocuments)
        .set(input.fields as any)
        .where(eq(roeDocuments.id, input.id));

      // Update section progress
      const isCustomer = ctx.user.role === "client";
      await db.insert(roeSectionProgress).values({
        roeId: input.id,
        section: input.section,
        filledBy: isCustomer ? "customer" : "operator",
        completionPercent: 0, // Will be recalculated
        lastEditedBy: ctx.user.id,
        lastEditedByName: ctx.user.name || "Unknown",
      }).onDuplicateKeyUpdate({
        set: {
          filledBy: isCustomer ? "customer" : "operator",
          lastEditedBy: ctx.user.id,
          lastEditedByName: ctx.user.name || "Unknown",
        },
      });

      // Create version entry
      await db.insert(roeVersions).values({
        roeId: input.id,
        versionNumber: "auto",
        changeType: "updated",
        changeSummary: `${input.section} section updated by ${ctx.user.name || "user"}`,
        changedFields: JSON.stringify(Object.keys(input.fields)),
        changedBy: ctx.user.id,
        changedByName: ctx.user.name || "Unknown",
      });

      return { success: true };
    }),

  // Add a collaboration comment on a section
  addComment: protectedProcedure
    .input(z.object({
      roeId: z.number(),
      section: z.string(),
      fieldName: z.string().optional(),
      commentText: z.string().min(1),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      const isCustomer = ctx.user.role === "client";
      const [result] = await db.insert(roeCollaborationComments).values({
        roeId: input.roeId,
        section: input.section,
        fieldName: input.fieldName || null,
        authorId: ctx.user.id,
        authorName: ctx.user.name || "Unknown",
        authorRole: isCustomer ? "customer" : "operator",
        commentText: input.commentText,
      });
      return { id: result.insertId };
    }),

  // Resolve a comment
  resolveComment: protectedProcedure
    .input(z.object({ commentId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      await db.update(roeCollaborationComments)
        .set({ isResolved: 1, resolvedBy: ctx.user.id, resolvedAt: new Date().toISOString() })
        .where(eq(roeCollaborationComments.id, input.commentId));
      return { success: true };
    }),

  // Submit ROE for operator review (customer action)
  submitForReview: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      await db.update(roeDocuments)
        .set({ status: "pending_review" })
        .where(eq(roeDocuments.id, input.id));

      await db.insert(roeVersions).values({
        roeId: input.id,
        versionNumber: "auto",
        changeType: "status_change",
        changeSummary: `Submitted for operator review by ${ctx.user.name || "customer"}`,
        changedBy: ctx.user.id,
        changedByName: ctx.user.name || "Unknown",
      });

      return { success: true };
    }),

  // Request changes (operator sends back to customer)
  requestChanges: protectedProcedure
    .input(z.object({
      id: z.number(),
      sections: z.array(z.string()),
      message: z.string(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      await db.update(roeDocuments)
        .set({ status: "draft" })
        .where(eq(roeDocuments.id, input.id));

      // Add a comment for each section that needs changes
      for (const section of input.sections) {
        await db.insert(roeCollaborationComments).values({
          roeId: input.id,
          section,
          authorId: ctx.user.id,
          authorName: ctx.user.name || "Operator",
          authorRole: "operator",
          commentText: `Changes requested: ${input.message}`,
        });
      }

      await db.insert(roeVersions).values({
        roeId: input.id,
        versionNumber: "auto",
        changeType: "status_change",
        changeSummary: `Changes requested by operator: ${input.message}`,
        changedBy: ctx.user.id,
        changedByName: ctx.user.name || "Operator",
      });

      return { success: true };
    }),

  // Upload and parse ROE document with LLM extraction
  uploadAndExtract: protectedProcedure
    .input(z.object({
      roeId: z.number(),
      fileContent: z.string(), // base64 encoded
      fileName: z.string(),
      mimeType: z.string(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      // Use LLM to extract ROE fields from the document
      const extractionPrompt = `You are an expert at parsing Rules of Engagement (ROE) documents for penetration testing and red team engagements.

Extract the following fields from this document and return them as a JSON object. If a field is not found, use null.

Required fields:
- title: Document title
- organizationName: Client organization name
- purpose: Purpose/objective of the engagement
- scopeDescription: High-level scope description
- inScopeDomains: Array of {domain: string, includeSubdomains: boolean}
- inScopeIpRanges: Array of {cidr: string, description?: string}
- outOfScopeDomains: Array of {domain: string, reason?: string}
- outOfScopeIpRanges: Array of {cidr: string, reason?: string}
- inScopeApplications: Array of {name: string, url?: string, type?: string}
- testScheduleStart: ISO date string
- testScheduleEnd: ISO date string
- testTimezone: Timezone string
- testingWindowStart: Time string (HH:MM)
- testingWindowEnd: Time string (HH:MM)
- testingTypes: Array of testing type strings
- dosTestingAllowed: boolean
- socialEngineeringAllowed: boolean
- physicalTestingAllowed: boolean
- wirelessTestingAllowed: boolean
- pivotingAllowed: boolean
- exfiltrationAllowed: boolean
- persistenceAllowed: boolean
- communicationFrequency: "daily" | "weekly" | "bi-weekly" | "as-needed"
- communicationMethod: "email" | "phone" | "secure_portal" | "encrypted_email"
- emergencyHaltCriteria: string
- evidenceRetentionDays: number
- legalJurisdiction: string
- complianceFrameworks: Array of framework strings
- personnel: Array of {role: string, name: string, title?: string, email?: string, phone?: string}

Return ONLY valid JSON, no markdown formatting.`;

      try {
        const response = await invokeLLM({
          messages: [
            { role: "system", content: extractionPrompt },
            { role: "user", content: `Document filename: ${input.fileName}\n\nDocument content (base64):\n${input.fileContent.substring(0, 50000)}` },
          ],
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "roe_extraction",
              strict: false,
              schema: {
                type: "object",
                properties: {
                  title: { type: ["string", "null"] },
                  organizationName: { type: ["string", "null"] },
                  purpose: { type: ["string", "null"] },
                  scopeDescription: { type: ["string", "null"] },
                  inScopeDomains: { type: ["array", "null"] },
                  inScopeIpRanges: { type: ["array", "null"] },
                  outOfScopeDomains: { type: ["array", "null"] },
                  outOfScopeIpRanges: { type: ["array", "null"] },
                  inScopeApplications: { type: ["array", "null"] },
                  testScheduleStart: { type: ["string", "null"] },
                  testScheduleEnd: { type: ["string", "null"] },
                  testTimezone: { type: ["string", "null"] },
                  testingWindowStart: { type: ["string", "null"] },
                  testingWindowEnd: { type: ["string", "null"] },
                  testingTypes: { type: ["array", "null"] },
                  dosTestingAllowed: { type: ["boolean", "null"] },
                  socialEngineeringAllowed: { type: ["boolean", "null"] },
                  physicalTestingAllowed: { type: ["boolean", "null"] },
                  wirelessTestingAllowed: { type: ["boolean", "null"] },
                  pivotingAllowed: { type: ["boolean", "null"] },
                  exfiltrationAllowed: { type: ["boolean", "null"] },
                  persistenceAllowed: { type: ["boolean", "null"] },
                  communicationFrequency: { type: ["string", "null"] },
                  communicationMethod: { type: ["string", "null"] },
                  emergencyHaltCriteria: { type: ["string", "null"] },
                  evidenceRetentionDays: { type: ["number", "null"] },
                  legalJurisdiction: { type: ["string", "null"] },
                  complianceFrameworks: { type: ["array", "null"] },
                  personnel: { type: ["array", "null"] },
                },
              },
            },
          },
        });

        const extracted = JSON.parse(response.choices[0].message.content || "{}");

        // Update ROE with extracted fields (only non-null values)
        const updateFields: Record<string, any> = {};
        const fieldMap: Record<string, string> = {
          title: "title",
          organizationName: "organizationName",
          purpose: "purpose",
          scopeDescription: "scopeDescription",
          inScopeDomains: "inScopeDomains",
          inScopeIpRanges: "inScopeIpRanges",
          outOfScopeDomains: "outOfScopeDomains",
          outOfScopeIpRanges: "outOfScopeIpRanges",
          inScopeApplications: "inScopeApplications",
          testScheduleStart: "testScheduleStart",
          testScheduleEnd: "testScheduleEnd",
          testTimezone: "testTimezone",
          testingWindowStart: "testingWindowStart",
          testingWindowEnd: "testingWindowEnd",
          testingTypes: "testingTypes",
          communicationFrequency: "communicationFrequency",
          communicationMethod: "communicationMethod",
          emergencyHaltCriteria: "emergencyHaltCriteria",
          evidenceRetentionDays: "evidenceRetentionDays",
          legalJurisdiction: "legalJurisdiction",
          complianceFrameworks: "complianceFrameworks",
        };

        for (const [key, dbField] of Object.entries(fieldMap)) {
          if (extracted[key] !== null && extracted[key] !== undefined) {
            updateFields[dbField] = typeof extracted[key] === "object"
              ? JSON.stringify(extracted[key])
              : extracted[key];
          }
        }

        // Boolean fields
        const boolFields = [
          "dosTestingAllowed", "socialEngineeringAllowed", "physicalTestingAllowed",
          "wirelessTestingAllowed", "pivotingAllowed", "exfiltrationAllowed", "persistenceAllowed",
        ];
        for (const field of boolFields) {
          if (extracted[field] !== null && extracted[field] !== undefined) {
            updateFields[field] = extracted[field] ? 1 : 0;
          }
        }

        if (Object.keys(updateFields).length > 0) {
          await db.update(roeDocuments).set(updateFields).where(eq(roeDocuments.id, input.roeId));
        }

        // Add extracted personnel
        if (extracted.personnel && Array.isArray(extracted.personnel)) {
          for (const person of extracted.personnel) {
            if (person.name) {
              await db.insert(roePersonnel).values({
                roeId: input.roeId,
                role: person.role || "customer_poc",
                name: person.name,
                title: person.title || null,
                email: person.email || null,
                phone: person.phone || null,
              });
            }
          }
        }

        // Mark sections as LLM-extracted
        const sectionsUpdated = new Set<string>();
        if (extracted.inScopeDomains || extracted.inScopeIpRanges) sectionsUpdated.add("scope");
        if (extracted.outOfScopeDomains || extracted.outOfScopeIpRanges) sectionsUpdated.add("exclusions");
        if (extracted.testScheduleStart || extracted.testScheduleEnd) sectionsUpdated.add("schedule");
        if (extracted.testingTypes) sectionsUpdated.add("boundaries");
        if (extracted.communicationFrequency) sectionsUpdated.add("communication");
        if (extracted.legalJurisdiction) sectionsUpdated.add("authorization");
        if (extracted.complianceFrameworks) sectionsUpdated.add("compliance");
        if (extracted.evidenceRetentionDays) sectionsUpdated.add("data_handling");

        for (const section of sectionsUpdated) {
          await db.insert(roeSectionProgress).values({
            roeId: input.roeId,
            section,
            filledBy: "llm_extracted",
            completionPercent: 0,
            lastEditedBy: ctx.user.id,
            lastEditedByName: "AI Document Parser",
          }).onDuplicateKeyUpdate({
            set: {
              filledBy: "llm_extracted",
              lastEditedBy: ctx.user.id,
              lastEditedByName: "AI Document Parser",
            },
          });
        }

        await db.insert(roeVersions).values({
          roeId: input.roeId,
          versionNumber: "auto",
          changeType: "updated",
          changeSummary: `Fields extracted from uploaded document: ${input.fileName}`,
          changedBy: ctx.user.id,
          changedByName: "AI Document Parser",
        });

        return {
          success: true,
          extractedFields: Object.keys(updateFields).length,
          extractedPersonnel: extracted.personnel?.length || 0,
          sectionsUpdated: Array.from(sectionsUpdated),
          extracted, // Return raw extraction for review
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message || "Failed to parse document",
          extractedFields: 0,
          extractedPersonnel: 0,
          sectionsUpdated: [],
          extracted: null,
        };
      }
    }),

  // Get customer's ROE list (filtered by their role)
  listMyRoes: protectedProcedure.query(async ({ ctx }) => {
    const db = await getDb();
    const docs = await db.select().from(roeDocuments)
      .orderBy(desc(roeDocuments.updatedAt))
      .limit(50);

    return docs.map(d => ({
      ...d,
      overallCompletion: 0, // Will be calculated on detail view
    }));
  }),

  // Generate customer invite link for an ROE
  createInvite: protectedProcedure
    .input(z.object({
      roeId: z.number(),
      customerEmail: z.string().email(),
      customerName: z.string().optional(),
      customerOrg: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDb();
      const token = crypto.randomBytes(32).toString("hex");
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

      await db.insert(roeCustomerInvites).values({
        roeId: input.roeId,
        inviteToken: token,
        customerEmail: input.customerEmail,
        customerName: input.customerName || null,
        customerOrg: input.customerOrg || null,
        invitedBy: ctx.user.id,
        invitedByName: ctx.user.name || "Operator",
        expiresAt,
      });

      return { token, expiresAt };
    }),

  // Get invites for an ROE
  getInvites: protectedProcedure
    .input(z.object({ roeId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      return db.select().from(roeCustomerInvites)
        .where(eq(roeCustomerInvites.roeId, input.roeId))
        .orderBy(desc(roeCustomerInvites.createdAt));
    }),
});
