import * as db from "../db";
import { z } from "zod";
import { protectedProcedure, publicProcedure, router } from "../_core/trpc";
import { getDb as _getDb } from "../db";
import {
  ksiDefinitions,
  ksiEvidence,
  ksiEvidenceChains,
  ksiControlMappings,
} from "../../drizzle/schema";
import { eq, desc, and, sql, inArray, like } from "drizzle-orm";
import crypto from "crypto";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

// ─── Constants: All 58 FedRAMP KSIs ────────────────────────────────────────

export const KSI_CATALOG = [
  // Theme 1: Authorization by FedRAMP (AFR)
  { ksiId: "KSI-AFR-ADS", themeCode: "AFR", themeName: "Authorization by FedRAMP", title: "Authorization Data Sharing", validationType: "human" as const, frequency: "Ongoing", coverageStatus: "supporting" as const, ac3Module: "OSCAL Export Engine, Evidence Chain" },
  { ksiId: "KSI-AFR-CCM", themeCode: "AFR", themeName: "Authorization by FedRAMP", title: "Continuous Compliance Monitoring", validationType: "tbd" as const, frequency: "TBD", coverageStatus: "direct" as const, ac3Module: "KSI Validation Scheduler" },
  { ksiId: "KSI-AFR-FSI", themeCode: "AFR", themeName: "Authorization by FedRAMP", title: "FedRAMP Security Inbox", validationType: "mixed" as const, frequency: "Ongoing", coverageStatus: "supporting" as const, ac3Module: "Notification Engine" },
  { ksiId: "KSI-AFR-ICP", themeCode: "AFR", themeName: "Authorization by FedRAMP", title: "Initial Compliance Posture", validationType: "tbd" as const, frequency: "TBD", coverageStatus: "supporting" as const, ac3Module: "Compliance Dashboard" },
  { ksiId: "KSI-AFR-MAS", themeCode: "AFR", themeName: "Authorization by FedRAMP", title: "Minimum Assessment Scope", validationType: "human" as const, frequency: "Ongoing", coverageStatus: "direct" as const, ac3Module: "Asset Inventory, Scope Management" },
  { ksiId: "KSI-AFR-PVA", themeCode: "AFR", themeName: "Authorization by FedRAMP", title: "Periodic Vulnerability Assessment", validationType: "tbd" as const, frequency: "TBD", coverageStatus: "direct" as const, ac3Module: "Vulnerability Scanner Integration" },
  { ksiId: "KSI-AFR-SCG", themeCode: "AFR", themeName: "Authorization by FedRAMP", title: "Secure Configuration Guide", validationType: "mixed" as const, frequency: "Ongoing", coverageStatus: "direct" as const, ac3Module: "Configuration Baseline, SCG Generator" },
  { ksiId: "KSI-AFR-SCN", themeCode: "AFR", themeName: "Authorization by FedRAMP", title: "Significant Change Notifications", validationType: "human" as const, frequency: "Ongoing", coverageStatus: "supporting" as const, ac3Module: "Change Management, Notification Engine" },

  // Theme 2: Change Management (CMT)
  { ksiId: "KSI-CMT-LMC", themeCode: "CMT", themeName: "Change Management", title: "Log and Monitor Modifications", validationType: "machine" as const, frequency: "Continuous", coverageStatus: "direct" as const, ac3Module: "SIEM Integration, Audit Logging" },
  { ksiId: "KSI-CMT-RMV", themeCode: "CMT", themeName: "Change Management", title: "Redeployment of Version-Controlled Immutable Resources", validationType: "machine" as const, frequency: "Per Change", coverageStatus: "supporting" as const, ac3Module: "IaC Validation, CI/CD Pipeline Monitor" },
  { ksiId: "KSI-CMT-RVP", themeCode: "CMT", themeName: "Change Management", title: "Review Change Management Procedures", validationType: "human" as const, frequency: "Persistent", coverageStatus: "supporting" as const, ac3Module: "Change Review Dashboard, Evidence Chain" },
  { ksiId: "KSI-CMT-VTD", themeCode: "CMT", themeName: "Change Management", title: "Validate Changes Throughout Deployment", validationType: "machine" as const, frequency: "Continuous", coverageStatus: "direct" as const, ac3Module: "CI/CD Pipeline Monitor, Automated Testing" },

  // Theme 3: Cloud Native Architecture (CNA)
  { ksiId: "KSI-CNA-DFP", themeCode: "CNA", themeName: "Cloud Native Architecture", title: "Define Functionality and Privileges", validationType: "machine" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Configuration Baseline, IAM Audit" },
  { ksiId: "KSI-CNA-EDE", themeCode: "CNA", themeName: "Cloud Native Architecture", title: "Encrypt Data at Rest and In Transit (FIPS)", validationType: "machine" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Encryption Validator, FIPS Compliance" },
  { ksiId: "KSI-CNA-MAS", themeCode: "CNA", themeName: "Cloud Native Architecture", title: "Minimal Attack Surface", validationType: "machine" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Attack Surface Monitor, Network Segmentation" },
  { ksiId: "KSI-CNA-OFA", themeCode: "CNA", themeName: "Cloud Native Architecture", title: "Optimize for High Availability", validationType: "machine" as const, frequency: "Ongoing", coverageStatus: "supporting" as const, ac3Module: "Recovery Planning, HA Monitoring" },
  { ksiId: "KSI-CNA-RNT", themeCode: "CNA", themeName: "Cloud Native Architecture", title: "Restrict Network Traffic", validationType: "machine" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Network Flow Analysis, Firewall Audit" },
  { ksiId: "KSI-CNA-RVP", themeCode: "CNA", themeName: "Cloud Native Architecture", title: "Review DoS Protection Effectiveness", validationType: "human" as const, frequency: "Persistent", coverageStatus: "supporting" as const, ac3Module: "DDoS Protection Review, WAF Monitoring" },
  { ksiId: "KSI-CNA-SBD", themeCode: "CNA", themeName: "Cloud Native Architecture", title: "Secure By Design Architecture", validationType: "mixed" as const, frequency: "Ongoing", coverageStatus: "supporting" as const, ac3Module: "Architecture Review, Threat Modeling" },
  { ksiId: "KSI-CNA-ULN", themeCode: "CNA", themeName: "Cloud Native Architecture", title: "Use Logical Networking Controls", validationType: "machine" as const, frequency: "Ongoing", coverageStatus: "supporting" as const, ac3Module: "Network Topology Mapper, VPC Audit" },

  // Theme 4: Cybersecurity Education (CED)
  { ksiId: "KSI-CED-DET", themeCode: "CED", themeName: "Cybersecurity Education", title: "Developer/Engineering Training Effectiveness", validationType: "human" as const, frequency: "Persistent", coverageStatus: "supporting" as const, ac3Module: "Training Tracker, Phishing Simulation" },
  { ksiId: "KSI-CED-RGT", themeCode: "CED", themeName: "Cybersecurity Education", title: "General Employee Training Effectiveness", validationType: "human" as const, frequency: "Persistent", coverageStatus: "supporting" as const, ac3Module: "Training Tracker, Security Awareness" },
  { ksiId: "KSI-CED-RRT", themeCode: "CED", themeName: "Cybersecurity Education", title: "IR/DR Staff Training Effectiveness", validationType: "human" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Training Tracker, IR Tabletop Exercises" },
  { ksiId: "KSI-CED-RST", themeCode: "CED", themeName: "Cybersecurity Education", title: "High-Risk Role Training Effectiveness", validationType: "human" as const, frequency: "Persistent", coverageStatus: "supporting" as const, ac3Module: "Training Tracker, Privileged Access Reviews" },

  // Theme 5: Identity and Access Management (IAM)
  { ksiId: "KSI-IAM-AAM", themeCode: "IAM", themeName: "Identity and Access Management", title: "Automated Account Lifecycle Management", validationType: "machine" as const, frequency: "Continuous", coverageStatus: "direct" as const, ac3Module: "IAM Lifecycle Manager, Account Audit" },
  { ksiId: "KSI-IAM-APM", themeCode: "IAM", themeName: "Identity and Access Management", title: "Authentication Policy Management", validationType: "machine" as const, frequency: "Ongoing", coverageStatus: "direct" as const, ac3Module: "Authentication Audit, Password Policy" },
  { ksiId: "KSI-IAM-ELP", themeCode: "IAM", themeName: "Identity and Access Management", title: "Enforce Least Privilege", validationType: "mixed" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Least Privilege Analyzer, RBAC Audit" },
  { ksiId: "KSI-IAM-JIT", themeCode: "IAM", themeName: "Identity and Access Management", title: "Just-In-Time Authorization", validationType: "machine" as const, frequency: "Ongoing", coverageStatus: "supporting" as const, ac3Module: "JIT Access Manager, Privilege Escalation Monitor" },
  { ksiId: "KSI-IAM-MFA", themeCode: "IAM", themeName: "Identity and Access Management", title: "Phishing-Resistant MFA Enforcement", validationType: "machine" as const, frequency: "Continuous", coverageStatus: "direct" as const, ac3Module: "MFA Compliance Checker, FIDO2 Validator" },
  { ksiId: "KSI-IAM-SNU", themeCode: "IAM", themeName: "Identity and Access Management", title: "Secure Non-User Authentication", validationType: "machine" as const, frequency: "Ongoing", coverageStatus: "direct" as const, ac3Module: "Service Account Audit, API Key Manager" },
  { ksiId: "KSI-IAM-SUS", themeCode: "IAM", themeName: "Identity and Access Management", title: "Suspend Suspicious Privileged Accounts", validationType: "machine" as const, frequency: "Real-time", coverageStatus: "direct" as const, ac3Module: "Anomaly Detection, Auto-Lockout Engine" },

  // Theme 6: Incident Response (INR)
  { ksiId: "KSI-INR-AAR", themeCode: "INR", themeName: "Incident Response", title: "After-Action Reports and Lessons Learned", validationType: "human" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Incident Report Generator, Lessons Learned DB" },
  { ksiId: "KSI-INR-RIR", themeCode: "INR", themeName: "Incident Response", title: "Review IR Procedures Effectiveness", validationType: "human" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "IR Procedure Reviewer, Tabletop Exercise Tracker" },
  { ksiId: "KSI-INR-RPI", themeCode: "INR", themeName: "Incident Response", title: "Review Past Incidents for Patterns", validationType: "human" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Incident Pattern Analyzer, Threat Intelligence" },

  // Theme 7: Monitoring, Logging, and Auditing (MLA)
  { ksiId: "KSI-MLA-ALA", themeCode: "MLA", themeName: "Monitoring, Logging, and Auditing", title: "Access Controls for Log Data", validationType: "machine" as const, frequency: "Ongoing", coverageStatus: "supporting" as const, ac3Module: "Log Access Control, RBAC for Logs" },
  { ksiId: "KSI-MLA-EVC", themeCode: "MLA", themeName: "Monitoring, Logging, and Auditing", title: "Evaluate and Test Configuration", validationType: "machine" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Configuration Drift Detector, IaC Scanner" },
  { ksiId: "KSI-MLA-LET", themeCode: "MLA", themeName: "Monitoring, Logging, and Auditing", title: "Log Event Types Catalog", validationType: "machine" as const, frequency: "Continuous", coverageStatus: "direct" as const, ac3Module: "Log Policy Manager, Event Catalog" },
  { ksiId: "KSI-MLA-OSM", themeCode: "MLA", themeName: "Monitoring, Logging, and Auditing", title: "Operate SIEM for Centralized Logging", validationType: "machine" as const, frequency: "Continuous", coverageStatus: "direct" as const, ac3Module: "SIEM Integration, Evidence Chain (SHA-256)" },
  { ksiId: "KSI-MLA-RVL", themeCode: "MLA", themeName: "Monitoring, Logging, and Auditing", title: "Review and Audit Logs", validationType: "human" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Log Review Dashboard, Audit Trail" },

  // Theme 8: Policy and Inventory (PIY)
  { ksiId: "KSI-PIY-GIV", themeCode: "PIY", themeName: "Policy and Inventory", title: "Generate Real-Time Inventories", validationType: "machine" as const, frequency: "When Needed", coverageStatus: "direct" as const, ac3Module: "Asset Discovery, CMDB Integration" },
  { ksiId: "KSI-PIY-RES", themeCode: "PIY", themeName: "Policy and Inventory", title: "Review Executive Support for Security", validationType: "human" as const, frequency: "Persistent", coverageStatus: "planned" as const, ac3Module: "Executive Dashboard, Governance Tracker" },
  { ksiId: "KSI-PIY-RIS", themeCode: "PIY", themeName: "Policy and Inventory", title: "Review Security Investment Effectiveness", validationType: "human" as const, frequency: "Persistent", coverageStatus: "planned" as const, ac3Module: "Security ROI Dashboard, Investment Tracker" },
  { ksiId: "KSI-PIY-RSD", themeCode: "PIY", themeName: "Policy and Inventory", title: "Review SDLC Security (CISA Secure By Design)", validationType: "human" as const, frequency: "Persistent", coverageStatus: "supporting" as const, ac3Module: "SDLC Security Review, DevSecOps Dashboard" },
  { ksiId: "KSI-PIY-RVD", themeCode: "PIY", themeName: "Policy and Inventory", title: "Review Vulnerability Disclosure Program", validationType: "human" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "VDP Manager, Bug Bounty Tracker" },

  // Theme 9: Recovery Planning (RPL)
  { ksiId: "KSI-RPL-ABO", themeCode: "RPL", themeName: "Recovery Planning", title: "Recovery Planning Alignment", validationType: "tbd" as const, frequency: "TBD", coverageStatus: "planned" as const, ac3Module: "Recovery Plan Manager" },
  { ksiId: "KSI-RPL-ARP", themeCode: "RPL", themeName: "Recovery Planning", title: "Align Recovery Plans with Objectives", validationType: "human" as const, frequency: "Persistent", coverageStatus: "planned" as const, ac3Module: "Recovery Plan Reviewer, RTO/RPO Tracker" },
  { ksiId: "KSI-RPL-RRO", themeCode: "RPL", themeName: "Recovery Planning", title: "Review RTO and RPO Objectives", validationType: "human" as const, frequency: "Persistent", coverageStatus: "planned" as const, ac3Module: "RTO/RPO Dashboard, SLA Monitor" },
  { ksiId: "KSI-RPL-TRC", themeCode: "RPL", themeName: "Recovery Planning", title: "Test Recovery Capabilities", validationType: "human" as const, frequency: "Persistent", coverageStatus: "planned" as const, ac3Module: "DR Testing Scheduler, Recovery Drill Tracker" },

  // Theme 10: Service Configuration (SVC)
  { ksiId: "KSI-SVC-ACM", themeCode: "SVC", themeName: "Service Configuration", title: "Automated Configuration Management", validationType: "machine" as const, frequency: "Continuous", coverageStatus: "direct" as const, ac3Module: "Configuration Automation, IaC Manager" },
  { ksiId: "KSI-SVC-ASM", themeCode: "SVC", themeName: "Service Configuration", title: "Attack Surface Management", validationType: "machine" as const, frequency: "TBD", coverageStatus: "direct" as const, ac3Module: "Attack Surface Monitor, Recon Engine" },
  { ksiId: "KSI-SVC-EIS", themeCode: "SVC", themeName: "Service Configuration", title: "Endpoint/Infrastructure Security", validationType: "machine" as const, frequency: "TBD", coverageStatus: "supporting" as const, ac3Module: "Endpoint Security Validator" },
  { ksiId: "KSI-SVC-PRR", themeCode: "SVC", themeName: "Service Configuration", title: "Post-Change Residual Review", validationType: "human" as const, frequency: "Persistent", coverageStatus: "supporting" as const, ac3Module: "Post-Change Review, Residual Risk Tracker" },
  { ksiId: "KSI-SVC-RUD", themeCode: "SVC", themeName: "Service Configuration", title: "Remove Unwanted Federal Data", validationType: "human" as const, frequency: "Promptly", coverageStatus: "planned" as const, ac3Module: "Data Sanitization Manager" },
  { ksiId: "KSI-SVC-SNT", themeCode: "SVC", themeName: "Service Configuration", title: "Service Notification/Transparency", validationType: "tbd" as const, frequency: "TBD", coverageStatus: "supporting" as const, ac3Module: "Notification Engine" },
  { ksiId: "KSI-SVC-VCM", themeCode: "SVC", themeName: "Service Configuration", title: "Vulnerability/Configuration Management", validationType: "machine" as const, frequency: "TBD", coverageStatus: "direct" as const, ac3Module: "Vulnerability Scanner, Config Drift Detector" },
  { ksiId: "KSI-SVC-VRI", themeCode: "SVC", themeName: "Service Configuration", title: "Vulnerability Risk Identification", validationType: "machine" as const, frequency: "TBD", coverageStatus: "direct" as const, ac3Module: "Risk Scoring Engine, CVE Tracker" },

  // Theme 11: Supply Chain Risk (SCR)
  { ksiId: "KSI-SCR-MIT", themeCode: "SCR", themeName: "Supply Chain Risk", title: "Mitigate Supply Chain Risks", validationType: "human" as const, frequency: "Persistent", coverageStatus: "supporting" as const, ac3Module: "SBOM Analyzer, Supply Chain Risk Dashboard" },
  { ksiId: "KSI-SCR-MON", themeCode: "SCR", themeName: "Supply Chain Risk", title: "Monitor Third-Party Software Vulnerabilities", validationType: "machine" as const, frequency: "Continuous", coverageStatus: "direct" as const, ac3Module: "Dependency Monitor, CVE Feed Integration" },
  { ksiId: "KSI-SCR-SAT", themeCode: "SCR", themeName: "Supply Chain Risk", title: "Security Awareness Testing", validationType: "mixed" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Phishing Simulation, GoPhish Integration" },
  { ksiId: "KSI-SCR-PEN", themeCode: "SCR", themeName: "Supply Chain Risk", title: "Penetration Testing", validationType: "mixed" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Unified Pentest Pipeline, Caldera" },
  { ksiId: "KSI-SCR-APT", themeCode: "SCR", themeName: "Supply Chain Risk", title: "Advanced Persistent Threat Simulation", validationType: "machine" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "Caldera, Atomic Red Team, Exploit Arsenal" },

  // Theme 12: Secure Development (SDE) — Added by KSI audit
  { ksiId: "KSI-SDE-SST", themeCode: "SDE", themeName: "Secure Development", title: "Secure Software Testing", validationType: "machine" as const, frequency: "Per Change", coverageStatus: "direct" as const, ac3Module: "SAST/DAST Integration, Web App Scanner" },

  // Theme 13: Policy & Procedure Management (PPM) — Added by KSI audit
  { ksiId: "KSI-PPM-PPR", themeCode: "PPM", themeName: "Policy & Procedure Management", title: "Policy & Procedure Review", validationType: "human" as const, frequency: "Persistent", coverageStatus: "supporting" as const, ac3Module: "Compliance Mapper, Evidence Chain" },
  { ksiId: "KSI-PPM-PPI", themeCode: "PPM", themeName: "Policy & Procedure Management", title: "Policy & Procedure Implementation", validationType: "human" as const, frequency: "Persistent", coverageStatus: "supporting" as const, ac3Module: "Compliance Mapper, Document Management" },

  // Additional KSIs from source module mappings — Added by KSI audit
  { ksiId: "KSI-SVC-VSR", themeCode: "SVC", themeName: "Service Configuration", title: "Vulnerability Scanning Results", validationType: "machine" as const, frequency: "Continuous", coverageStatus: "direct" as const, ac3Module: "Vulnerability Scanner, ZAP Integration" },
  { ksiId: "KSI-SVC-VRM", themeCode: "SVC", themeName: "Service Configuration", title: "Vulnerability Remediation Management", validationType: "machine" as const, frequency: "Ongoing", coverageStatus: "direct" as const, ac3Module: "Vulnerability Tracker, Remediation Workflow" },
  { ksiId: "KSI-CNA-HCI", themeCode: "CNA", themeName: "Cloud Native Architecture", title: "Harden Cloud Infrastructure", validationType: "machine" as const, frequency: "Continuous", coverageStatus: "direct" as const, ac3Module: "Cloud Misconfiguration Scanner, CIS Benchmarks" },
  { ksiId: "KSI-CNA-NSD", themeCode: "CNA", themeName: "Cloud Native Architecture", title: "Network Segmentation & Defense", validationType: "machine" as const, frequency: "Continuous", coverageStatus: "direct" as const, ac3Module: "NGFW Validation, Network Flow Analysis" },
  { ksiId: "KSI-MLA-ALE", themeCode: "MLA", themeName: "Monitoring, Logging, and Auditing", title: "Alert Engineering & Response", validationType: "machine" as const, frequency: "Continuous", coverageStatus: "direct" as const, ac3Module: "SIEM Alerts, EDR Integration, Atomic Red Team" },
  { ksiId: "KSI-IAM-PRA", themeCode: "IAM", themeName: "Identity and Access Management", title: "Privileged Access Reviews & Auditing", validationType: "mixed" as const, frequency: "Persistent", coverageStatus: "direct" as const, ac3Module: "AD Attack Simulation, Privilege Audit" },
];

// ─── Helper: SHA-256 hash ──────────────────────────────────────────────────────

function computeHash(data: string, previousHash?: string): string {
  const payload = previousHash ? `${previousHash}:${data}` : data;
  return crypto.createHash("sha256").update(payload).digest("hex");
}

function generateId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
}

// ─── Router ────────────────────────────────────────────────────────────────────

export const ksiEvidenceChainRouter = router({
  // ── KSI Definitions ──────────────────────────────────────────────────────────

  /** Seed the KSI catalog into the database */
  seedCatalog: protectedProcedure.mutation(async () => {
    const db = await getDbSafe();
    let seeded = 0;
    for (const ksi of KSI_CATALOG) {
      const existing = await db.select().from(ksiDefinitions).where(eq(ksiDefinitions.ksiId, ksi.ksiId));
      if (existing.length === 0) {
        await db.insert(ksiDefinitions).values({
          ksiId: ksi.ksiId,
          themeCode: ksi.themeCode,
          themeName: ksi.themeName,
          title: ksi.title,
          validationType: ksi.validationType,
          frequency: ksi.frequency,
          coverageStatus: ksi.coverageStatus,
          ac3Module: ksi.ac3Module,
        });
        seeded++;
      }
    }
    return { seeded, total: KSI_CATALOG.length };
  }),

  /** Get all KSI definitions */
  listDefinitions: protectedProcedure
    .input(z.object({
      themeCode: z.string().optional(),
      coverageStatus: z.enum(["direct", "supporting", "planned", "not_applicable"]).optional(),
      validationType: z.enum(["machine", "human", "mixed", "tbd"]).optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      let query = db.select().from(ksiDefinitions);
      const conditions = [];
      if (input?.themeCode) conditions.push(eq(ksiDefinitions.themeCode, input.themeCode));
      if (input?.coverageStatus) conditions.push(eq(ksiDefinitions.coverageStatus, input.coverageStatus));
      if (input?.validationType) conditions.push(eq(ksiDefinitions.validationType, input.validationType));
      if (conditions.length > 0) {
        query = query.where(and(...conditions)) as any;
      }
      return query.orderBy(ksiDefinitions.ksiId);
    }),

  /** Get KSI coverage summary statistics */
  getCoverageSummary: protectedProcedure.query(async () => {
    const db = await getDbSafe();
    const allDefs = await db.select().from(ksiDefinitions);

    // If catalog not seeded yet, return from static data
    const defs = allDefs.length > 0 ? allDefs : KSI_CATALOG.map((k, i) => ({ ...k, id: i + 1 }));

    const themes = Array.from(new Set(defs.map(d => d.themeCode)));
    const themeStats = themes.map(code => {
      const themeDefs = defs.filter(d => d.themeCode === code);
      const direct = themeDefs.filter(d => d.coverageStatus === "direct").length;
      const supporting = themeDefs.filter(d => d.coverageStatus === "supporting").length;
      const planned = themeDefs.filter(d => d.coverageStatus === "planned").length;
      return {
        themeCode: code,
        themeName: themeDefs[0]?.themeName || code,
        total: themeDefs.length,
        direct,
        supporting,
        planned,
        coveragePercent: Math.round(((direct + supporting) / themeDefs.length) * 100),
      };
    });

    const totalKSIs = defs.length;
    const directCount = defs.filter(d => d.coverageStatus === "direct").length;
    const supportingCount = defs.filter(d => d.coverageStatus === "supporting").length;
    const plannedCount = defs.filter(d => d.coverageStatus === "planned").length;
    const machineCount = defs.filter(d => d.validationType === "machine").length;
    const humanCount = defs.filter(d => d.validationType === "human").length;

    return {
      totalKSIs,
      directCount,
      supportingCount,
      plannedCount,
      overallCoverage: Math.round(((directCount + supportingCount) / totalKSIs) * 100),
      machineValidated: machineCount,
      humanValidated: humanCount,
      themeStats,
      definitions: defs,
    };
  }),

  // ── Evidence Collection ──────────────────────────────────────────────────────

  /** Collect a new piece of evidence for a KSI */
  collectEvidence: protectedProcedure
    .input(z.object({
      ksiId: z.string(),
      engagementId: z.string().optional(),
      title: z.string(),
      description: z.string().optional(),
      evidenceType: z.enum([
        "scan_result", "configuration_check", "log_entry", "screenshot",
        "document", "api_response", "test_result", "attestation",
        "policy_document", "training_record", "incident_report", "audit_log"
      ]),
      sourceModule: z.string(),
      sourceId: z.string().optional(),
      collectionMethod: z.enum(["automated", "manual", "hybrid"]).default("automated"),
      rawData: z.any().optional(),
      metadata: z.any().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const evidenceId = generateId("EVD");

      // Get the last evidence for this KSI to chain hashes
      const lastEvidence = await db.select()
        .from(ksiEvidence)
        .where(eq(ksiEvidence.ksiId, input.ksiId))
        .orderBy(desc(ksiEvidence.createdAt))
        .limit(1);

      const previousHash = lastEvidence[0]?.integrityHash || null;
      const dataToHash = JSON.stringify({
        evidenceId,
        ksiId: input.ksiId,
        title: input.title,
        sourceModule: input.sourceModule,
        rawData: input.rawData,
        timestamp: new Date().toISOString(),
      });
      const integrityHash = computeHash(dataToHash, previousHash || undefined);

      await db.insert(ksiEvidence).values({
        evidenceId,
        ksiId: input.ksiId,
        engagementId: input.engagementId,
        title: input.title,
        description: input.description,
        evidenceType: input.evidenceType,
        sourceModule: input.sourceModule,
        sourceId: input.sourceId,
        collectionMethod: input.collectionMethod,
        rawData: input.rawData,
        metadata: input.metadata,
        integrityHash,
        previousHash,
        status: "collected",
        collectedBy: ctx.user?.id,
        collectedByName: ctx.user?.name || "System",
      });

      return { evidenceId, integrityHash, previousHash };
    }),

  /** List evidence for a KSI or engagement */
  listEvidence: protectedProcedure
    .input(z.object({
      ksiId: z.string().optional(),
      engagementId: z.string().optional(),
      status: z.enum(["collected", "verified", "validated", "expired", "rejected"]).optional(),
      evidenceType: z.string().optional(),
      limit: z.number().min(1).max(500).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input?.ksiId) conditions.push(eq(ksiEvidence.ksiId, input.ksiId));
      if (input?.engagementId) conditions.push(eq(ksiEvidence.engagementId, input.engagementId));
      if (input?.status) conditions.push(eq(ksiEvidence.status, input.status));

      let query = db.select().from(ksiEvidence);
      if (conditions.length > 0) {
        query = query.where(and(...conditions)) as any;
      }
      const results = await (query as any).orderBy(desc(ksiEvidence.createdAt)).limit(input?.limit || 50).offset(input?.offset || 0);

      const countResult = await db.select({ count: sql<number>`count(*)` }).from(ksiEvidence)
        .where(conditions.length > 0 ? and(...conditions) : undefined);

      return { evidence: results, total: countResult[0]?.count || 0 };
    }),

  /** Validate/verify a piece of evidence */
  validateEvidence: protectedProcedure
    .input(z.object({
      evidenceId: z.string(),
      status: z.enum(["verified", "validated", "rejected"]),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      await db.update(ksiEvidence)
        .set({
          status: input.status,
          validatedBy: ctx.user?.name || "Unknown",
          validatedAt: new Date(),
        })
        .where(eq(ksiEvidence.evidenceId, input.evidenceId));
      return { success: true };
    }),

  // ── Evidence Chains ──────────────────────────────────────────────────────────

  /** Create a new evidence chain for a KSI */
  createChain: protectedProcedure
    .input(z.object({
      ksiId: z.string(),
      engagementId: z.string().optional(),
      name: z.string(),
      description: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const chainId = generateId("CHN");
      await db.insert(ksiEvidenceChains).values({
        chainId,
        ksiId: input.ksiId,
        engagementId: input.engagementId,
        name: input.name,
        description: input.description,
        createdBy: ctx.user?.id,
        createdByName: ctx.user?.name || "System",
      });
      return { chainId };
    }),

  /** List evidence chains */
  listChains: protectedProcedure
    .input(z.object({
      ksiId: z.string().optional(),
      engagementId: z.string().optional(),
      status: z.enum(["active", "complete", "broken", "archived"]).optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input?.ksiId) conditions.push(eq(ksiEvidenceChains.ksiId, input.ksiId));
      if (input?.engagementId) conditions.push(eq(ksiEvidenceChains.engagementId, input.engagementId));
      if (input?.status) conditions.push(eq(ksiEvidenceChains.status, input.status));

      let query = db.select().from(ksiEvidenceChains);
      if (conditions.length > 0) {
        query = query.where(and(...conditions)) as any;
      }
      return (query as any).orderBy(desc(ksiEvidenceChains.createdAt));
    }),

  /** Verify the integrity of an evidence chain */
  verifyChain: protectedProcedure
    .input(z.object({ chainId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const chain = await db.select().from(ksiEvidenceChains).where(eq(ksiEvidenceChains.chainId, input.chainId));
      if (!chain[0]) throw new Error("Chain not found");

      const evidence = await db.select()
        .from(ksiEvidence)
        .where(eq(ksiEvidence.ksiId, chain[0].ksiId))
        .orderBy(ksiEvidence.createdAt);

      let valid = true;
      let brokenAt: string | null = null;

      for (let i = 1; i < evidence.length; i++) {
        if (evidence[i].previousHash !== evidence[i - 1].integrityHash) {
          valid = false;
          brokenAt = evidence[i].evidenceId;
          break;
        }
      }

      await db.update(ksiEvidenceChains)
        .set({
          chainValid: valid,
          lastVerifiedAt: new Date(),
          evidenceCount: evidence.length,
          chainHash: evidence.length > 0 ? evidence[evidence.length - 1].integrityHash : null,
          status: valid ? chain[0].status : "broken",
        })
        .where(eq(ksiEvidenceChains.chainId, input.chainId));

      return { valid, evidenceCount: evidence.length, brokenAt };
    }),

  // ── Control Mappings ─────────────────────────────────────────────────────────

  /** Add a control mapping */
  addControlMapping: protectedProcedure
    .input(z.object({
      ksiId: z.string(),
      controlId: z.string(),
      controlFamily: z.string().optional(),
      controlTitle: z.string().optional(),
      mappingStrength: z.enum(["direct", "supporting", "partial"]).default("direct"),
      ac3Module: z.string().optional(),
      automationLevel: z.enum(["full", "partial", "manual"]).default("manual"),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();
      const [result] = await db.insert(ksiControlMappings).values(input);
      return { id: result.insertId };
    }),

  /** List control mappings for a KSI */
  listControlMappings: protectedProcedure
    .input(z.object({
      ksiId: z.string().optional(),
      controlFamily: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const conditions = [];
      if (input?.ksiId) conditions.push(eq(ksiControlMappings.ksiId, input.ksiId));
      if (input?.controlFamily) conditions.push(eq(ksiControlMappings.controlFamily, input.controlFamily));

      let query = db.select().from(ksiControlMappings);
      if (conditions.length > 0) {
        query = query.where(and(...conditions)) as any;
      }
      return query;
    }),

  // ── Dashboard Stats ──────────────────────────────────────────────────────────

  /** Get evidence collection stats for the dashboard */
  getDashboardStats: protectedProcedure
    .input(z.object({ engagementId: z.string().optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDbSafe();

      const evidenceCount = await db.select({ count: sql<number>`count(*)` }).from(ksiEvidence);
      const chainCount = await db.select({ count: sql<number>`count(*)` }).from(ksiEvidenceChains);
      const validChains = await db.select({ count: sql<number>`count(*)` }).from(ksiEvidenceChains)
        .where(eq(ksiEvidenceChains.chainValid, true));
      const brokenChains = await db.select({ count: sql<number>`count(*)` }).from(ksiEvidenceChains)
        .where(eq(ksiEvidenceChains.chainValid, false));

      // Evidence by status
      const byStatus = await db.select({
        status: ksiEvidence.status,
        count: sql<number>`count(*)`,
      }).from(ksiEvidence).groupBy(ksiEvidence.status);

      // Evidence by type
      const byType = await db.select({
        type: ksiEvidence.evidenceType,
        count: sql<number>`count(*)`,
      }).from(ksiEvidence).groupBy(ksiEvidence.evidenceType);

      // Evidence by KSI theme
      const byKsi = await db.select({
        ksiId: ksiEvidence.ksiId,
        count: sql<number>`count(*)`,
      }).from(ksiEvidence).groupBy(ksiEvidence.ksiId);

      return {
        totalEvidence: evidenceCount[0]?.count || 0,
        totalChains: chainCount[0]?.count || 0,
        validChains: validChains[0]?.count || 0,
        brokenChains: brokenChains[0]?.count || 0,
        byStatus,
        byType,
        byKsi,
      };
    }),
});
