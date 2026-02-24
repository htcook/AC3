import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb as _getDb } from "../db";
import { roeDocuments, roePersonnel, roeSignatures } from "../../drizzle/schema";
import { eq, desc, and, sql } from "drizzle-orm";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

// ─── Zod Schemas ───────────────────────────────────────────────────────────────

const assetSchema = z.object({
  name: z.string(),
  type: z.enum(["server", "workstation", "network_device", "application", "database", "cloud_resource", "iot_device", "mobile_device", "other"]),
  ipAddress: z.string().optional(),
  hostname: z.string().optional(),
  os: z.string().optional(),
  description: z.string().optional(),
  criticality: z.enum(["critical", "high", "medium", "low"]).optional(),
  owner: z.string().optional(),
});

const ipRangeSchema = z.object({
  cidr: z.string(),
  description: z.string().optional(),
  vlan: z.string().optional(),
  location: z.string().optional(),
});

const domainSchema = z.object({
  domain: z.string(),
  includeSubdomains: z.boolean().default(true),
  description: z.string().optional(),
});

const applicationSchema = z.object({
  name: z.string(),
  url: z.string().optional(),
  type: z.enum(["web", "api", "mobile", "desktop", "thick_client"]).optional(),
  authRequired: z.boolean().default(false),
  description: z.string().optional(),
});

const cloudEnvSchema = z.object({
  provider: z.enum(["aws", "azure", "gcp", "oracle", "other"]),
  accountId: z.string().optional(),
  region: z.string().optional(),
  services: z.array(z.string()).optional(),
  description: z.string().optional(),
});

const credentialAccountSchema = z.object({
  username: z.string(),
  role: z.string(),
  accessLevel: z.string(),
  system: z.string().optional(),
  notes: z.string().optional(),
});

const testingTypeSchema = z.object({
  id: z.string(),
  name: z.string(),
  category: z.enum(["pentest", "red_team", "purple_team", "social_engineering", "physical", "wireless", "cloud"]),
  description: z.string(),
  enabled: z.boolean().default(false),
});

const attackVectorSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  enabled: z.boolean().default(false),
  fedrampRequired: z.boolean().default(false),
});

const personnelSchema = z.object({
  role: z.enum([
    "system_owner", "ciso", "cio", "isso", "authorizing_official",
    "trusted_agent", "test_lead", "test_member", "emergency_contact",
    "legal_counsel", "third_party_poc", "incident_response_lead",
    "customer_poc", "project_manager"
  ]),
  name: z.string().min(1),
  title: z.string().optional(),
  organization: z.string().optional(),
  email: z.string().email().optional(),
  phone: z.string().optional(),
  alternatePhone: z.string().optional(),
  clearanceLevel: z.string().optional(),
  isPrimary: z.boolean().default(false),
});

const signatureSchema = z.object({
  signerName: z.string().min(1),
  signerTitle: z.string().optional(),
  signerOrganization: z.string().optional(),
  signerRole: z.enum(["customer_executive", "customer_technical", "testing_lead", "authorizing_official", "legal_counsel"]),
  signatureData: z.string().optional(),
});

// ─── Default Templates ─────────────────────────────────────────────────────────

const DEFAULT_TESTING_TYPES: z.infer<typeof testingTypeSchema>[] = [
  // Penetration Testing
  { id: "ext_network", name: "External Network Penetration Test", category: "pentest", description: "Testing external-facing network infrastructure for vulnerabilities exploitable from the internet", enabled: false },
  { id: "int_network", name: "Internal Network Penetration Test", category: "pentest", description: "Testing internal network infrastructure assuming an insider or compromised host position", enabled: false },
  { id: "web_app", name: "Web Application Penetration Test", category: "pentest", description: "OWASP Top 10 and beyond testing of web applications including authentication, authorization, injection, and business logic", enabled: false },
  { id: "api_test", name: "API Security Assessment", category: "pentest", description: "Testing REST/GraphQL/SOAP APIs for authentication bypass, injection, rate limiting, and data exposure", enabled: false },
  { id: "mobile_app", name: "Mobile Application Security Test", category: "pentest", description: "Static and dynamic analysis of iOS/Android applications including data storage, network communication, and authentication", enabled: false },
  { id: "cloud_config", name: "Cloud Configuration Review", category: "cloud", description: "Assessment of cloud infrastructure (AWS/Azure/GCP) for misconfigurations, excessive permissions, and insecure defaults", enabled: false },
  { id: "cloud_pentest", name: "Cloud Penetration Test", category: "cloud", description: "Active exploitation of cloud services including IAM, storage, compute, and serverless functions", enabled: false },
  // Red Team
  { id: "full_red_team", name: "Full-Scope Red Team Engagement", category: "red_team", description: "Objective-based adversary simulation across all attack surfaces with minimal rules, emulating real threat actors", enabled: false },
  { id: "assumed_breach", name: "Assumed Breach Red Team", category: "red_team", description: "Red team starting from an assumed compromised position to test detection and response capabilities", enabled: false },
  { id: "apt_simulation", name: "APT Simulation", category: "red_team", description: "Emulation of specific Advanced Persistent Threat group TTPs mapped to MITRE ATT&CK", enabled: false },
  { id: "ransomware_sim", name: "Ransomware Simulation", category: "red_team", description: "Simulated ransomware attack chain including initial access, lateral movement, and encryption simulation (non-destructive)", enabled: false },
  // Purple Team
  { id: "purple_team", name: "Purple Team Exercise", category: "purple_team", description: "Collaborative red/blue team exercise to test and improve detection and response capabilities in real-time", enabled: false },
  { id: "detection_validation", name: "Detection Engineering Validation", category: "purple_team", description: "Systematic testing of SIEM rules, EDR detections, and alert pipelines against known attack techniques", enabled: false },
  // Social Engineering
  { id: "phishing", name: "Phishing Campaign", category: "social_engineering", description: "Email-based social engineering targeting employees with crafted pretexts to test security awareness", enabled: false },
  { id: "vishing", name: "Vishing (Voice Phishing)", category: "social_engineering", description: "Phone-based social engineering to test employee susceptibility to voice-based pretexts", enabled: false },
  { id: "smishing", name: "Smishing (SMS Phishing)", category: "social_engineering", description: "SMS-based social engineering targeting mobile devices", enabled: false },
  { id: "pretexting", name: "Physical Pretexting", category: "social_engineering", description: "In-person social engineering using crafted pretexts to gain physical access or information", enabled: false },
  // Physical
  { id: "physical_access", name: "Physical Access Testing", category: "physical", description: "Attempting to gain unauthorized physical access to facilities through tailgating, lock picking, badge cloning", enabled: false },
  { id: "dumpster_diving", name: "Dumpster Diving", category: "physical", description: "Searching discarded materials for sensitive information", enabled: false },
  // Wireless
  { id: "wireless_assess", name: "Wireless Security Assessment", category: "wireless", description: "Testing wireless networks for rogue APs, weak encryption, evil twin attacks, and client-side vulnerabilities", enabled: false },
  { id: "bluetooth_test", name: "Bluetooth/BLE Testing", category: "wireless", description: "Assessment of Bluetooth and BLE devices for pairing vulnerabilities and data interception", enabled: false },
];

const FEDRAMP_ATTACK_VECTORS: z.infer<typeof attackVectorSchema>[] = [
  { id: "ext_to_int", name: "External to Internal", description: "Attacks originating from the internet targeting external-facing assets to gain internal network access", enabled: false, fedrampRequired: true },
  { id: "int_to_int", name: "Internal to Internal", description: "Attacks from within the internal network simulating an insider threat or compromised host", enabled: false, fedrampRequired: true },
  { id: "tenant_isolation", name: "Tenant Isolation", description: "Attempting to break multi-tenant isolation boundaries to access other tenants' data", enabled: false, fedrampRequired: true },
  { id: "api_abuse", name: "API Abuse", description: "Exploiting API endpoints for unauthorized data access, privilege escalation, or denial of service", enabled: false, fedrampRequired: true },
  { id: "auth_bypass", name: "Authentication/Authorization Bypass", description: "Attempting to bypass authentication mechanisms or escalate privileges beyond authorized levels", enabled: false, fedrampRequired: true },
  { id: "data_exfil", name: "Data Exfiltration", description: "Testing the ability to extract sensitive data through various channels (HTTP, DNS, encrypted tunnels)", enabled: false, fedrampRequired: true },
  { id: "supply_chain", name: "Supply Chain", description: "Testing third-party integrations, dependencies, and supply chain attack vectors", enabled: false, fedrampRequired: false },
  { id: "social_eng", name: "Social Engineering", description: "Human-targeted attacks including phishing, vishing, and pretexting", enabled: false, fedrampRequired: false },
  { id: "physical", name: "Physical Access", description: "Attempting unauthorized physical access to data centers, offices, or network infrastructure", enabled: false, fedrampRequired: false },
  { id: "wireless", name: "Wireless", description: "Attacking wireless networks and protocols to gain unauthorized access", enabled: false, fedrampRequired: false },
  { id: "cloud_misconfig", name: "Cloud Misconfiguration", description: "Exploiting cloud service misconfigurations including IAM, storage, and network policies", enabled: false, fedrampRequired: true },
  { id: "container_escape", name: "Container/Orchestration Escape", description: "Attempting to escape container boundaries or exploit Kubernetes/orchestration vulnerabilities", enabled: false, fedrampRequired: false },
];

const DEFAULT_REPORT_DELIVERABLES = [
  { id: "exec_summary", name: "Executive Summary", description: "High-level overview of findings, risk ratings, and strategic recommendations for leadership", required: true },
  { id: "technical_report", name: "Technical Report", description: "Detailed technical findings with evidence, reproduction steps, and remediation guidance", required: true },
  { id: "finding_matrix", name: "Finding Risk Matrix", description: "Tabular summary of all findings with CVSS scores, risk ratings, and remediation priorities", required: true },
  { id: "remediation_plan", name: "Remediation Roadmap", description: "Prioritized remediation plan with effort estimates and quick wins", required: false },
  { id: "attack_narrative", name: "Attack Narrative", description: "Step-by-step narrative of attack chains and kill chain progression", required: false },
  { id: "evidence_package", name: "Evidence Package", description: "Screenshots, logs, and proof-of-concept artifacts supporting each finding", required: true },
  { id: "retest_report", name: "Retest Validation Report", description: "Verification report confirming remediation effectiveness after fixes are applied", required: false },
  { id: "attck_mapping", name: "MITRE ATT&CK Mapping", description: "Mapping of all techniques used and detected to the MITRE ATT&CK framework", required: false },
];

// ─── Router ────────────────────────────────────────────────────────────────────

export const roeBuilderRouter = router({
  // List all RoE documents
  list: protectedProcedure
    .input(z.object({
      status: z.enum(["draft", "pending_review", "approved", "active", "completed", "archived"]).optional(),
      engagementId: z.number().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input?.status) conditions.push(eq(roeDocuments.status, input.status));
      if (input?.engagementId) conditions.push(eq(roeDocuments.engagementId, input.engagementId));

      const docs = await db
        .select()
        .from(roeDocuments)
        .where(conditions.length > 0 ? and(...conditions) : undefined)
        .orderBy(desc(roeDocuments.updatedAt));

      return docs;
    }),

  // Get single RoE document with personnel and signatures
  getById: protectedProcedure
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [doc] = await db.select().from(roeDocuments).where(eq(roeDocuments.id, input.id));
      if (!doc) throw new Error("RoE document not found");

      const personnel = await db.select().from(roePersonnel).where(eq(roePersonnel.roeId, input.id));
      const signatures = await db.select().from(roeSignatures).where(eq(roeSignatures.roeId, input.id));

      return { ...doc, personnel, signatures };
    }),

  // Create new RoE document
  create: protectedProcedure
    .input(z.object({
      title: z.string().min(1),
      engagementId: z.number().optional(),
      organizationName: z.string().optional(),
      testingFirmName: z.string().optional(),
      fedrampCompliant: z.boolean().default(false),
      fedrampImpactLevel: z.enum(["low", "moderate", "high", "not_applicable"]).default("not_applicable"),
      serviceModel: z.enum(["iaas", "paas", "saas", "hybrid", "not_applicable"]).default("not_applicable"),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [result] = await db.insert(roeDocuments).values({
        title: input.title,
        engagementId: input.engagementId ?? null,
        organizationName: input.organizationName ?? null,
        testingFirmName: input.testingFirmName ?? "ACE C3 — AceofCloud",
        fedrampCompliant: input.fedrampCompliant,
        fedrampImpactLevel: input.fedrampImpactLevel,
        serviceModel: input.serviceModel,
        testingTypes: DEFAULT_TESTING_TYPES,
        attackVectors: FEDRAMP_ATTACK_VECTORS,
        reportDeliverables: DEFAULT_REPORT_DELIVERABLES,
        testingDays: ["monday", "tuesday", "wednesday", "thursday", "friday"],
        testTimezone: "America/New_York",
        createdBy: ctx.user.id,
        lastModifiedBy: ctx.user.id,
        purpose: "This Rules of Engagement (RoE) document establishes the terms, conditions, scope, and limitations for the authorized security assessment to be conducted by the testing firm on behalf of the organization. This document is prepared in accordance with NIST SP 800-115 Technical Guide to Information Security Testing and Assessment.",
        dataHandlingProcedure: "All assessment data, including but not limited to vulnerability findings, exploitation evidence, credentials, and network diagrams, shall be encrypted at rest using AES-256 and in transit using TLS 1.2+. Data shall be stored only on encrypted, access-controlled systems operated by the testing team. No assessment data shall be stored on personal devices or unencrypted media.",
        piiHandlingPolicy: "If Personally Identifiable Information (PII) or Protected Health Information (PHI) is encountered during testing, the testing team shall: (1) Not exfiltrate or copy the data, (2) Document the access path and evidence of exposure without capturing actual PII/PHI content, (3) Immediately notify the customer POC, (4) Include the finding in the final report with sanitized evidence.",
        evidenceRetentionDays: 90,
        evidenceEncryptionRequired: true,
        evidenceDestructionMethod: "secure_delete",
        emergencyHaltCriteria: "Testing shall be immediately halted if any of the following conditions occur: (1) Unintended system outage or service disruption, (2) Discovery of active threat actor presence, (3) Accidental access to systems outside the defined scope, (4) Request from the emergency contact or authorizing official, (5) Discovery of illegal content or activity.",
        incidentResponseProcedure: "In the event of an incident during testing: (1) Testing team immediately ceases the activity that caused the incident, (2) Test lead contacts the emergency contact within 15 minutes, (3) Both parties assess the situation and determine root cause, (4) A joint decision is made to continue, modify scope, or terminate testing, (5) All incidents are documented in the final report.",
        criticalFindingNotification: "Critical and high-severity findings that pose immediate risk to the organization shall be reported to the customer POC within 24 hours of discovery via the agreed-upon secure communication channel.",
        ndaRequired: true,
        communicationFrequency: "daily",
        communicationMethod: "secure_portal",
        statusReportFrequency: "daily",
        shunningPolicy: "notify_first",
        reportFrequency: "final_only",
      });

      return { id: result.insertId };
    }),

  // Update RoE document (section-by-section)
  update: protectedProcedure
    .input(z.object({
      id: z.number(),
      // All fields optional for partial updates
      title: z.string().optional(),
      version: z.string().optional(),
      status: z.enum(["draft", "pending_review", "approved", "active", "completed", "archived"]).optional(),
      organizationName: z.string().optional(),
      organizationAddress: z.string().optional(),
      testingFirmName: z.string().optional(),
      testingFirmAddress: z.string().optional(),
      purpose: z.string().optional(),
      scopeDescription: z.string().optional(),
      assumptions: z.string().optional(),
      limitations: z.string().optional(),
      risks: z.string().optional(),
      testScheduleStart: z.string().optional(),
      testScheduleEnd: z.string().optional(),
      testingWindowStart: z.string().optional(),
      testingWindowEnd: z.string().optional(),
      testingDays: z.array(z.string()).optional(),
      testTimezone: z.string().optional(),
      testSiteLocations: z.array(z.string()).optional(),
      remoteTestingAllowed: z.boolean().optional(),
      vpnRequired: z.boolean().optional(),
      badgeEscortRequired: z.boolean().optional(),
      testEquipment: z.array(z.string()).optional(),
      communicationFrequency: z.enum(["daily", "weekly", "bi-weekly", "as-needed"]).optional(),
      communicationMethod: z.enum(["email", "phone", "secure_portal", "encrypted_email"]).optional(),
      statusReportFrequency: z.enum(["daily", "weekly", "milestone-based"]).optional(),
      incidentDefinition: z.string().optional(),
      incidentResponseProcedure: z.string().optional(),
      emergencyHaltCriteria: z.string().optional(),
      resumptionProcedure: z.string().optional(),
      inScopeAssets: z.array(assetSchema).optional(),
      outOfScopeAssets: z.array(assetSchema).optional(),
      inScopeIpRanges: z.array(ipRangeSchema).optional(),
      outOfScopeIpRanges: z.array(ipRangeSchema).optional(),
      inScopeDomains: z.array(domainSchema).optional(),
      outOfScopeDomains: z.array(domainSchema).optional(),
      inScopeApplications: z.array(applicationSchema).optional(),
      cloudEnvironments: z.array(cloudEnvSchema).optional(),
      wirelessNetworks: z.array(z.object({ ssid: z.string(), location: z.string().optional(), description: z.string().optional() })).optional(),
      physicalLocations: z.array(z.object({ name: z.string(), address: z.string().optional(), description: z.string().optional() })).optional(),
      testingTypes: z.array(testingTypeSchema).optional(),
      attackVectors: z.array(attackVectorSchema).optional(),
      socialEngineeringPretexts: z.array(z.object({ name: z.string(), description: z.string(), channel: z.string() })).optional(),
      dosTestingAllowed: z.boolean().optional(),
      physicalTestingAllowed: z.boolean().optional(),
      wirelessTestingAllowed: z.boolean().optional(),
      socialEngineeringAllowed: z.boolean().optional(),
      credentialedTesting: z.boolean().optional(),
      credentialAccounts: z.array(credentialAccountSchema).optional(),
      fileModificationAllowed: z.boolean().optional(),
      fileInstallationAllowed: z.boolean().optional(),
      pivotingAllowed: z.boolean().optional(),
      exfiltrationAllowed: z.boolean().optional(),
      persistenceAllowed: z.boolean().optional(),
      shunningPolicy: z.enum(["allowed", "not_allowed", "notify_first"]).optional(),
      fedrampCompliant: z.boolean().optional(),
      fedrampAttackVectors: z.array(attackVectorSchema).optional(),
      fedrampImpactLevel: z.enum(["low", "moderate", "high", "not_applicable"]).optional(),
      serviceModel: z.enum(["iaas", "paas", "saas", "hybrid", "not_applicable"]).optional(),
      dataHandlingProcedure: z.string().optional(),
      evidenceRetentionDays: z.number().optional(),
      evidenceEncryptionRequired: z.boolean().optional(),
      piiHandlingPolicy: z.string().optional(),
      evidenceDestructionMethod: z.enum(["secure_delete", "physical_destruction", "crypto_erase"]).optional(),
      reportDeliverables: z.array(z.object({ id: z.string(), name: z.string(), description: z.string(), required: z.boolean() })).optional(),
      reportFrequency: z.enum(["daily", "weekly", "final_only"]).optional(),
      criticalFindingNotification: z.string().optional(),
      legalJurisdiction: z.string().optional(),
      thirdPartyAgreements: z.array(z.object({ name: z.string(), description: z.string() })).optional(),
      liabilityWaiver: z.string().optional(),
      ndaRequired: z.boolean().optional(),
      ndaReference: z.string().optional(),
      complianceFrameworks: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const { id, ...updates } = input;
      const updateData: Record<string, unknown> = { lastModifiedBy: ctx.user.id };

      // Map all provided fields
      for (const [key, value] of Object.entries(updates)) {
        if (value !== undefined) {
          // Convert date strings to Date objects for timestamp fields
          if ((key === "testScheduleStart" || key === "testScheduleEnd") && typeof value === "string") {
            updateData[key] = new Date(value);
          } else {
            updateData[key] = value;
          }
        }
      }

      await db.update(roeDocuments).set(updateData as any).where(eq(roeDocuments.id, id));
      return { success: true };
    }),

  // Delete RoE document
  delete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(roeSignatures).where(eq(roeSignatures.roeId, input.id));
      await db.delete(roePersonnel).where(eq(roePersonnel.roeId, input.id));
      await db.delete(roeDocuments).where(eq(roeDocuments.id, input.id));
      return { success: true };
    }),

  // ─── Personnel Management ─────────────────────────────────────────────────

  addPersonnel: protectedProcedure
    .input(z.object({ roeId: z.number() }).merge(personnelSchema))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [result] = await db.insert(roePersonnel).values({
        roeId: input.roeId,
        role: input.role,
        name: input.name,
        title: input.title ?? null,
        organization: input.organization ?? null,
        email: input.email ?? null,
        phone: input.phone ?? null,
        alternatePhone: input.alternatePhone ?? null,
        clearanceLevel: input.clearanceLevel ?? null,
        isPrimary: input.isPrimary,
      });
      return { id: result.insertId };
    }),

  updatePersonnel: protectedProcedure
    .input(z.object({ id: z.number() }).merge(personnelSchema.partial()))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const { id, ...updates } = input;
      await db.update(roePersonnel).set(updates as any).where(eq(roePersonnel.id, id));
      return { success: true };
    }),

  removePersonnel: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(roePersonnel).where(eq(roePersonnel.id, input.id));
      return { success: true };
    }),

  // ─── Signatures ───────────────────────────────────────────────────────────

  addSignature: protectedProcedure
    .input(z.object({ roeId: z.number() }).merge(signatureSchema))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [result] = await db.insert(roeSignatures).values({
        roeId: input.roeId,
        signerName: input.signerName,
        signerTitle: input.signerTitle ?? null,
        signerOrganization: input.signerOrganization ?? null,
        signerRole: input.signerRole,
        signedAt: new Date(),
        signatureData: input.signatureData ?? null,
      });
      return { id: result.insertId };
    }),

  removeSignature: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      await db.delete(roeSignatures).where(eq(roeSignatures.id, input.id));
      return { success: true };
    }),

  // ─── Templates & Defaults ─────────────────────────────────────────────────

  getDefaults: protectedProcedure.query(() => ({
    testingTypes: DEFAULT_TESTING_TYPES,
    attackVectors: FEDRAMP_ATTACK_VECTORS,
    reportDeliverables: DEFAULT_REPORT_DELIVERABLES,
    personnelRoles: [
      { value: "system_owner", label: "System Owner" },
      { value: "ciso", label: "CISO" },
      { value: "cio", label: "CIO" },
      { value: "isso", label: "ISSO" },
      { value: "authorizing_official", label: "Authorizing Official" },
      { value: "trusted_agent", label: "Trusted Agent" },
      { value: "test_lead", label: "Test Lead" },
      { value: "test_member", label: "Test Team Member" },
      { value: "emergency_contact", label: "Emergency Contact" },
      { value: "legal_counsel", label: "Legal Counsel" },
      { value: "third_party_poc", label: "Third-Party POC" },
      { value: "incident_response_lead", label: "Incident Response Lead" },
      { value: "customer_poc", label: "Customer POC" },
      { value: "project_manager", label: "Project Manager" },
    ],
    complianceFrameworks: [
      "FedRAMP", "NIST SP 800-53", "NIST SP 800-171", "NIST CSF",
      "PCI DSS", "HIPAA", "SOC 2", "ISO 27001", "CMMC",
      "FISMA", "GDPR", "CCPA", "CJIS", "ITAR", "SOX",
    ],
    timezones: [
      "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
      "America/Anchorage", "Pacific/Honolulu", "UTC", "Europe/London", "Europe/Berlin",
      "Asia/Tokyo", "Asia/Shanghai", "Australia/Sydney",
    ],
  })),

  // ─── Status Transitions ───────────────────────────────────────────────────

  submitForReview: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      await db.update(roeDocuments).set({
        status: "pending_review",
        lastModifiedBy: ctx.user.id,
      }).where(and(eq(roeDocuments.id, input.id), eq(roeDocuments.status, "draft")));
      return { success: true };
    }),

  approve: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      await db.update(roeDocuments).set({
        status: "approved",
        approvedBy: ctx.user.id,
        approvedAt: new Date(),
        lastModifiedBy: ctx.user.id,
      }).where(and(eq(roeDocuments.id, input.id), eq(roeDocuments.status, "pending_review")));
      return { success: true };
    }),

  activate: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      await db.update(roeDocuments).set({
        status: "active",
        lastModifiedBy: ctx.user.id,
      }).where(and(eq(roeDocuments.id, input.id), eq(roeDocuments.status, "approved")));
      return { success: true };
    }),

  complete: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      await db.update(roeDocuments).set({
        status: "completed",
        lastModifiedBy: ctx.user.id,
      }).where(and(eq(roeDocuments.id, input.id), eq(roeDocuments.status, "active")));
      return { success: true };
    }),

  archive: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      await db.update(roeDocuments).set({
        status: "archived",
        lastModifiedBy: ctx.user.id,
      }).where(eq(roeDocuments.id, input.id));
      return { success: true };
    }),

  // ─── Duplicate ────────────────────────────────────────────────────────────

  duplicate: protectedProcedure
    .input(z.object({ id: z.number(), newTitle: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const [source] = await db.select().from(roeDocuments).where(eq(roeDocuments.id, input.id));
      if (!source) throw new Error("Source RoE not found");

      const { id, createdAt, updatedAt, approvedAt, approvedBy, pdfUrl, status, ...fields } = source;
      const [result] = await db.insert(roeDocuments).values({
        ...fields,
        title: input.newTitle,
        status: "draft",
        version: "1.0",
        createdBy: ctx.user.id,
        lastModifiedBy: ctx.user.id,
        approvedBy: null,
        approvedAt: null,
        pdfUrl: null,
      });

      // Copy personnel
      const personnel = await db.select().from(roePersonnel).where(eq(roePersonnel.roeId, input.id));
      for (const p of personnel) {
        const { id: pid, roeId, createdAt: pca, ...pFields } = p;
        await db.insert(roePersonnel).values({ ...pFields, roeId: result.insertId });
      }

      return { id: result.insertId };
    }),

  // ─── Stats ────────────────────────────────────────────────────────────────

  getStats: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const allDocs = await db.select({
      status: roeDocuments.status,
      count: sql<number>`count(*)`,
    }).from(roeDocuments).groupBy(roeDocuments.status);

    const statusMap: Record<string, number> = {};
    for (const row of allDocs) {
      statusMap[row.status] = Number(row.count);
    }

    return {
      total: Object.values(statusMap).reduce((a, b) => a + b, 0),
      draft: statusMap["draft"] || 0,
      pendingReview: statusMap["pending_review"] || 0,
      approved: statusMap["approved"] || 0,
      active: statusMap["active"] || 0,
      completed: statusMap["completed"] || 0,
      archived: statusMap["archived"] || 0,
    };
  }),
});
