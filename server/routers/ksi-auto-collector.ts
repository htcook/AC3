import * as db from "../db";
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { getDb as _getDb } from "../db";
import {
  ksiEvidence,
  ksiDefinitions,
  vulnScanFindings,
  vulnScanImports,
  webAppScans,
  webAppFindings,
  osintFindings,
  phishingDrafts,
  siemConnections,
  edrTestResults,
  ngfwValidationTests,
  adAttackSimulations,
  cloudMisconfigurations,
  threatActors,
  threatActorAbilities,
  unifiedExploitCatalog,
  atomicTests,
  atomicTestExecutions,
} from "../../drizzle/schema";
import { eq, desc, sql, and, gte, isNotNull, count } from "drizzle-orm";
import crypto from "crypto";
import {
  collectCalderaEvidence,
  collectGophishEvidence,
  collectZapEvidence,
  checkAllScannerHealth,
  crossRefThreatCatalog,
  crossRefTtpKnowledge,
} from "../lib/live-scanner-api";
import {
  collectCloudMisconfigs,
  collectNgfwValidation,
  collectAdAttackSims,
  collectEdrValidation,
  collectAtomicRedTeam,
  collectSiemConnectors,
  collectThreatIntel,
} from "../lib/ksi-live-collectors";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

function computeHash(data: string, previousHash?: string | null): string {
  const payload = previousHash ? `${previousHash}:${data}` : data;
  return crypto.createHash("sha256").update(payload).digest("hex");
}

function generateId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
}

// ─── Source-to-KSI Mapping ────────────────────────────────────────────────────

interface SourceMapping {
  sourceModule: string;
  ksiIds: string[];
  evidenceType: "scan_result" | "configuration_check" | "log_entry" | "test_result" | "document" | "api_response" | "incident_report" | "audit_log";
  description: string;
}

const SOURCE_KSI_MAP: SourceMapping[] = [
  // Vulnerability Scanner → Vulnerability Scanning & Remediation KSIs
  { sourceModule: "vuln-scanner", ksiIds: ["KSI-SVC-VSR", "KSI-SVC-VRM", "KSI-AFR-PVA"], evidenceType: "scan_result", description: "Vulnerability scan findings from imported scanner results" },
  // Web App Scanner → Vulnerability Scanning + Secure Development
  { sourceModule: "web-app-scanning", ksiIds: ["KSI-SVC-VSR", "KSI-SVC-VRM", "KSI-SDE-SST"], evidenceType: "scan_result", description: "Web application security scan findings from ZAP" },
  // Nuclei Scanner → Vulnerability Scanning + Configuration
  { sourceModule: "nuclei-scanner", ksiIds: ["KSI-SVC-VSR", "KSI-CNA-HCI", "KSI-SDE-SST"], evidenceType: "scan_result", description: "Nuclei template-based vulnerability scan results" },
  // OSINT/Recon → Threat Intelligence
  { sourceModule: "osint-recon", ksiIds: ["KSI-INR-TIF", "KSI-INR-TIU", "KSI-INR-IOC"], evidenceType: "api_response", description: "OSINT reconnaissance findings including subdomains, emails, credential leaks" },
  // Phishing Campaigns → Security Awareness Training
  { sourceModule: "phishing-ops", ksiIds: ["KSI-SCR-SAT", "KSI-SCR-PEN"], evidenceType: "test_result", description: "Phishing campaign results measuring user security awareness" },
  // SIEM Connectors → Monitoring, Logging, Auditing
  { sourceModule: "siem-connectors", ksiIds: ["KSI-MLA-LET", "KSI-MLA-OSM", "KSI-MLA-ALE"], evidenceType: "log_entry", description: "SIEM alert data from Wazuh/Elastic connectors" },
  // EDR Validation → Endpoint Detection
  { sourceModule: "edr-validation", ksiIds: ["KSI-MLA-OSM", "KSI-MLA-ALE", "KSI-SVC-VSR"], evidenceType: "test_result", description: "EDR product validation test results" },
  // NGFW Validation → Network Security
  { sourceModule: "ngfw-validation", ksiIds: ["KSI-CNA-NSD", "KSI-MLA-ALE"], evidenceType: "test_result", description: "Next-gen firewall validation test results" },
  // AD Attack Simulation → Identity & Access Management
  { sourceModule: "ad-attack-sim", ksiIds: ["KSI-IAM-MFA", "KSI-IAM-AAM", "KSI-IAM-PRA"], evidenceType: "test_result", description: "Active Directory attack simulation results" },
  // Cloud Misconfigurations → Cloud Native Architecture
  { sourceModule: "cloud-misconfigs", ksiIds: ["KSI-CNA-HCI", "KSI-CNA-EDE", "KSI-CNA-NSD"], evidenceType: "configuration_check", description: "Cloud infrastructure misconfiguration findings" },
  // Threat Intel → Incident Response & Threat Intelligence
  { sourceModule: "threat-intel", ksiIds: ["KSI-INR-TIF", "KSI-INR-TIU", "KSI-INR-IOC", "KSI-INR-IRP"], evidenceType: "api_response", description: "Threat actor intelligence and IOC data" },
  // Penetration Testing (Unified Pipeline) → Penetration Testing KSIs
  { sourceModule: "unified-pipeline", ksiIds: ["KSI-SCR-PEN", "KSI-SCR-APT"], evidenceType: "test_result", description: "Unified pentest pipeline engagement results" },
  // Atomic Red Team → Adversary Simulation
  { sourceModule: "atomic-red-team", ksiIds: ["KSI-SCR-APT", "KSI-SCR-PEN", "KSI-MLA-ALE"], evidenceType: "test_result", description: "Atomic Red Team test execution results" },
  // Exploit Arsenal → Penetration Testing + Vulnerability Scanning
  { sourceModule: "exploit-arsenal", ksiIds: ["KSI-SCR-PEN", "KSI-SVC-VSR", "KSI-SCR-APT"], evidenceType: "test_result", description: "Exploit catalog entries with CVE and MITRE ATT&CK mappings" },
  // Darkweb Intel → Threat Intelligence
  { sourceModule: "darkweb-intel", ksiIds: ["KSI-INR-TIF", "KSI-INR-IOC"], evidenceType: "api_response", description: "Darkweb intelligence feed data" },
  // Credential Alerts → Identity & Access Management
  { sourceModule: "credential-alerts", ksiIds: ["KSI-IAM-AAM", "KSI-IAM-MFA", "KSI-INR-IOC"], evidenceType: "incident_report", description: "Credential exposure and breach alert data" },
  // Compliance Mapper → Policy & Procedure
  { sourceModule: "compliance-mapper", ksiIds: ["KSI-PPM-PPR", "KSI-PPM-PPI", "KSI-AFR-ADS"], evidenceType: "document", description: "Compliance framework mapping and control evidence" },
];

// ─── Helper: Insert KSI evidence with hash chaining ──────────────────────────

async function insertKsiEvidence(
  db: any,
  ksiId: string,
  title: string,
  description: string,
  evidenceType: string,
  sourceModule: string,
  sourceId: string,
  rawData: any,
  collectedBy?: number | null,
  collectedByName?: string | null,
) {
  const evidenceId = generateId("EVD");
  const lastEvidence = await db.select()
    .from(ksiEvidence)
    .where(eq(ksiEvidence.ksiId, ksiId))
    .orderBy(desc(ksiEvidence.createdAt))
    .limit(1);

  const previousHash = lastEvidence[0]?.integrityHash || null;
  const dataToHash = JSON.stringify({
    evidenceId,
    ksiId,
    title,
    sourceModule,
    rawData,
    timestamp: new Date().toISOString(),
  });
  const integrityHash = computeHash(dataToHash, previousHash);

  await db.insert(ksiEvidence).values({
    evidenceId,
    ksiId,
    title,
    description,
    evidenceType,
    sourceModule,
    sourceId,
    collectionMethod: "automated",
    rawData,
    integrityHash,
    previousHash,
    status: "collected",
    collectedBy,
    collectedByName: collectedByName ?? "Auto-Collector",
  });

  return { evidenceId, integrityHash };
}

// ─── Router ───────────────────────────────────────────────────────────────────

export const ksiAutoCollectorRouter = router({

  /** Get the source-to-KSI mapping catalog */
  getSourceMappings: protectedProcedure.query(() => {
    return SOURCE_KSI_MAP.map(m => ({
      sourceModule: m.sourceModule,
      ksiIds: m.ksiIds,
      evidenceType: m.evidenceType,
      description: m.description,
    }));
  }),

  /** Get collection statistics */
  getCollectionStats: protectedProcedure.query(async () => {
    const db = await getDbSafe();

    const totalEvidence = await db.select({ count: count() }).from(ksiEvidence);
    const autoCollected = await db.select({ count: count() }).from(ksiEvidence)
      .where(eq(ksiEvidence.collectionMethod, "automated"));

    const bySource = await db.select({
      sourceModule: ksiEvidence.sourceModule,
      count: count(),
    }).from(ksiEvidence).groupBy(ksiEvidence.sourceModule);

    const byKsi = await db.select({
      ksiId: ksiEvidence.ksiId,
      count: count(),
    }).from(ksiEvidence).groupBy(ksiEvidence.ksiId);

    // Last collection time
    const lastCollection = await db.select()
      .from(ksiEvidence)
      .where(eq(ksiEvidence.collectionMethod, "automated"))
      .orderBy(desc(ksiEvidence.createdAt))
      .limit(1);

    return {
      totalEvidence: totalEvidence[0]?.count || 0,
      autoCollected: autoCollected[0]?.count || 0,
      manualCollected: (totalEvidence[0]?.count || 0) - (autoCollected[0]?.count || 0),
      bySource,
      byKsi,
      lastCollectionAt: lastCollection[0]?.createdAt || null,
      sourceMappingCount: SOURCE_KSI_MAP.length,
    };
  }),

  /** Collect evidence from vulnerability scanner findings */
  collectFromVulnScanner: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const findings = await db.select().from(vulnScanFindings)
      .orderBy(desc(vulnScanFindings.createdAt))
      .limit(100);

    for (const finding of findings) {
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "vuln-scanner")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `Vuln Finding: ${finding.title}`,
          `Severity: ${finding.severity} | CVE: ${finding.cveId || "N/A"} | Host: ${finding.hostIp || "N/A"} | CVSS: ${finding.cvssScore || "N/A"}`,
          mapping.evidenceType,
          mapping.sourceModule,
          `vsf-${finding.id}`,
          {
            findingId: finding.id,
            cveId: finding.cveId,
            severity: finding.severity,
            cvssScore: finding.cvssScore,
            hostIp: finding.hostIp,
            hostName: finding.hostName,
            port: finding.port,
            exploitAvailable: finding.exploitAvailable,
            corroborationScore: finding.corroborationScore,
          },
          ctx.user?.id,
          ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "vuln-scanner", findingsProcessed: findings.length };
  }),

  /** Collect evidence from web application scan findings */
  collectFromWebAppScanner: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const findings = await db.select().from(webAppFindings)
      .orderBy(desc(webAppFindings.createdAt))
      .limit(100);

    for (const finding of findings) {
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "web-app-scanning")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `Web App Finding: ${finding.alertName || "Unknown"}`,
          `Severity: ${finding.severity} | URL: ${finding.url || "N/A"} | CWE: ${finding.cweId || "N/A"} | MITRE: ${finding.mitreAttackId || "N/A"}`,
          mapping.evidenceType,
          mapping.sourceModule,
          `waf-${finding.id}`,
          {
            findingId: finding.id,
            alertName: finding.alertName,
            severity: finding.severity,
            url: finding.url,
            cweId: finding.cweId,
            mitreAttackId: finding.mitreAttackId,
            mitreAttackName: finding.mitreAttackName,
            exploitAvailable: finding.exploitAvailable,
            exploitModulePath: finding.exploitModulePath,
            aiTriageVerdict: finding.aiTriageVerdict,
          },
          ctx.user?.id,
          ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "web-app-scanning", findingsProcessed: findings.length };
  }),

  /** Collect evidence from OSINT reconnaissance findings */
  collectFromOsint: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const findings = await db.select().from(osintFindings)
      .orderBy(desc(osintFindings.createdAt))
      .limit(100);

    for (const finding of findings) {
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "osint-recon")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `OSINT: ${finding.title}`,
          `Category: ${finding.category} | Severity: ${finding.severity} | Source: ${finding.source || "N/A"}`,
          mapping.evidenceType,
          mapping.sourceModule,
          `osint-${finding.id}`,
          {
            findingId: finding.id,
            category: finding.category,
            severity: finding.severity,
            source: finding.source,
            campaignRelevance: finding.campaignRelevance,
          },
          ctx.user?.id,
          ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "osint-recon", findingsProcessed: findings.length };
  }),

  /** Collect evidence from phishing campaign results */
  collectFromPhishing: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const drafts = await db.select().from(phishingDrafts)
      .where(eq(phishingDrafts.status, "completed"))
      .orderBy(desc(phishingDrafts.createdAt))
      .limit(50);

    for (const draft of drafts) {
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "phishing-ops")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `Phishing Campaign: ${draft.campaignName}`,
          `Type: ${draft.campaignType || "N/A"} | Priority: ${draft.priority} | Target: ${draft.targetDomain || "N/A"}`,
          mapping.evidenceType,
          mapping.sourceModule,
          `phish-${draft.id}`,
          {
            draftId: draft.id,
            campaignName: draft.campaignName,
            campaignType: draft.campaignType,
            priority: draft.priority,
            targetDomain: draft.targetDomain,
            status: draft.status,
          },
          ctx.user?.id,
          ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "phishing-ops", campaignsProcessed: drafts.length };
  }),

  /** Collect evidence from EDR validation test results */
  collectFromEdr: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const results = await db.select().from(edrTestResults)
      .orderBy(desc(edrTestResults.createdAt))
      .limit(100);

      for (const result of results) {
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "edr-validation")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `EDR Test: ${result.alertTitle || "Test #" + result.id}`,
          `Result: ${result.detectionResult || "pending"} | Status: ${result.executionStatus} | Product: ${result.edrProductId}`,
          mapping.evidenceType,
          mapping.sourceModule,
          `edr-${result.id}`,
          {
            resultId: result.id,
            alertTitle: result.alertTitle,
            detectionResult: result.detectionResult,
            executionStatus: result.executionStatus,
            edrProductId: result.edrProductId,
            detectionTimeMs: result.detectionTimeMs,
          },
          ctx.user?.id,
          ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "edr-validation", resultsProcessed: results.length };
  }),

  /** Collect evidence from NGFW validation tests */
  collectFromNgfw: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const tests = await db.select().from(ngfwValidationTests)
      .orderBy(desc(ngfwValidationTests.createdAt))
      .limit(100);

      for (const test of tests) {
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "ngfw-validation")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `NGFW Test: ${test.name}`,
          `Type: ${test.testType} | Expected: ${test.expectedResult} | Actual: ${test.actualResult || "pending"} | Target: ${test.targetIp || "N/A"}:${test.targetPort || "N/A"}`,
          mapping.evidenceType,
          mapping.sourceModule,
          `ngfw-${test.id}`,
          {
            testId: test.id,
            name: test.name,
            testType: test.testType,
            expectedResult: test.expectedResult,
            actualResult: test.actualResult,
            targetIp: test.targetIp,
            targetPort: test.targetPort,
            firewallVendor: test.firewallVendor,
          },
          ctx.user?.id,
          ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "ngfw-validation", testsProcessed: tests.length };
  }),

  /** Collect evidence from AD attack simulations */
  collectFromAdAttackSim: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const sims = await db.select().from(adAttackSimulations)
      .orderBy(desc(adAttackSimulations.createdAt))
      .limit(50);

      for (const sim of sims) {
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "ad-attack-sim")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `AD Attack Sim: ${sim.attackType}`,
          `Status: ${sim.status} | Severity: ${sim.severity} | Target: ${sim.targetObject || "N/A"} | Risk: ${sim.riskScore || "N/A"}`,
          mapping.evidenceType,
          mapping.sourceModule,
          `adsim-${sim.id}`,
          {
            simId: sim.id,
            attackType: sim.attackType,
            status: sim.status,
            severity: sim.severity,
            targetObject: sim.targetObject,
            riskScore: sim.riskScore,
            mitreTechniques: sim.mitreTechniques,
          },
          ctx.user?.id,
          ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "ad-attack-sim", simsProcessed: sims.length };
  }),

  /** Collect evidence from cloud misconfiguration findings */
  collectFromCloudMisconfigs: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const misconfigs = await db.select().from(cloudMisconfigurations)
      .orderBy(desc(cloudMisconfigurations.createdAt))
      .limit(100);

    for (const mc of misconfigs) {
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "cloud-misconfigs")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `Cloud Misconfig: ${mc.misconfigType}`,
          `Severity: ${mc.severity} | Resource: ${mc.resourceType} | Status: ${mc.status}`,
          mapping.evidenceType,
          mapping.sourceModule,
          `cloud-${mc.id}`,
          {
            misconfigId: mc.id,
            resourceType: mc.resourceType,
            resourceArn: mc.resourceArn,
            misconfigType: mc.misconfigType,
            severity: mc.severity,
            status: mc.status,
            currentValue: mc.currentValue,
            expectedValue: mc.expectedValue,
          },
          ctx.user?.id,
          ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "cloud-misconfigs", misconfigsProcessed: misconfigs.length };
  }),

  /** Collect evidence from Atomic Red Team test executions */
  collectFromAtomicRedTeam: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const executions = await db.select().from(atomicTestExecutions)
      .orderBy(desc(atomicTestExecutions.createdAt))
      .limit(100);

    for (const exec of executions) {
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "atomic-red-team")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `Atomic Test: ${exec.testName}`,
          `Technique: ${exec.techniqueId} | Status: ${exec.status} | Detection: ${exec.detectionTriggered ? "Yes" : "No"}`,
          mapping.evidenceType,
          mapping.sourceModule,
          `atomic-${exec.id}`,
          {
            executionId: exec.id,
            testName: exec.testName,
            techniqueId: exec.techniqueId,
            status: exec.status,
            detectionTriggered: exec.detectionTriggered,
            exitCode: exec.exitCode,
            durationMs: exec.durationMs,
          },
          ctx.user?.id,
          ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "atomic-red-team", executionsProcessed: executions.length };
  }),

  /** Collect evidence from threat intelligence data */
  collectFromThreatIntel: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const actors = await db.select().from(threatActors)
      .orderBy(desc(threatActors.updatedAt))
      .limit(50);

    for (const actor of actors) {
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "threat-intel")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `Threat Actor: ${actor.name}`,
          `Type: ${actor.actorType} | Origin: ${actor.origin || "Unknown"} | Level: ${actor.threatLevel} | Techniques: ${Array.isArray(actor.techniques) ? actor.techniques.length : 0}`,
          mapping.evidenceType,
          mapping.sourceModule,
          `threat-${actor.actorId}`,
          {
            actorId: actor.actorId,
            name: actor.name,
            type: actor.actorType,
            origin: actor.origin,
            threatLevel: actor.threatLevel,
            sophistication: actor.sophistication,
            techniqueCount: Array.isArray(actor.techniques) ? actor.techniques.length : 0,
            toolCount: Array.isArray(actor.tools) ? actor.tools.length : 0,
          },
          ctx.user?.id,
          ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "threat-intel", actorsProcessed: actors.length };
  }),

  /** Check live scanner connection health */
  checkScannerHealth: protectedProcedure.query(async () => {
    return checkAllScannerHealth();
  }),

  /** Collect evidence from live Caldera API with threat catalog cross-referencing */
  collectFromCalderaLive: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;
    const liveEvidence = await collectCalderaEvidence();

    for (const ev of liveEvidence) {
      // Cross-reference with threat catalog
      let threatActorMatches: any[] = [];
      if (ev.techniqueIds?.length) {
        threatActorMatches = await crossRefThreatCatalog(ev.techniqueIds, db);
      }

      for (const ksiId of ev.ksiIds) {
        await insertKsiEvidence(
          db, ksiId, ev.title, ev.description,
          "scan_result", "caldera-live",
          `caldera-${ev.evidenceData.operationId}-${Date.now()}`,
          {
            ...ev.evidenceData,
            threatActorMatches: threatActorMatches.slice(0, 5),
            liveCollection: true,
          },
          ctx.user?.id, ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "caldera-live", operationsProcessed: liveEvidence.length };
  }),

  /** Collect evidence from live GoPhish API with threat catalog cross-referencing */
  collectFromGophishLive: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;
    const liveEvidence = await collectGophishEvidence();

    for (const ev of liveEvidence) {
      let threatActorMatches: any[] = [];
      if (ev.techniqueIds?.length) {
        threatActorMatches = await crossRefThreatCatalog(ev.techniqueIds, db);
      }

      for (const ksiId of ev.ksiIds) {
        await insertKsiEvidence(
          db, ksiId, ev.title, ev.description,
          "test_result", "gophish-live",
          `gophish-${ev.evidenceData.campaignId}-${Date.now()}`,
          {
            ...ev.evidenceData,
            threatActorMatches: threatActorMatches.slice(0, 5),
            liveCollection: true,
          },
          ctx.user?.id, ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "gophish-live", campaignsProcessed: liveEvidence.length };
  }),

  /** Collect evidence from live ZAP API with threat catalog cross-referencing */
  collectFromZapLive: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;
    const liveEvidence = await collectZapEvidence();

    for (const ev of liveEvidence) {
      let threatActorMatches: any[] = [];
      if (ev.techniqueIds?.length) {
        threatActorMatches = await crossRefThreatCatalog(ev.techniqueIds, db);
      }

      for (const ksiId of ev.ksiIds) {
        await insertKsiEvidence(
          db, ksiId, ev.title, ev.description,
          "scan_result", "zap-live",
          `zap-${ev.evidenceData.riskLevel}-${Date.now()}`,
          {
            ...ev.evidenceData,
            threatActorMatches: threatActorMatches.slice(0, 5),
            liveCollection: true,
          },
          ctx.user?.id, ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "zap-live", riskGroupsProcessed: liveEvidence.length };
  }),

  /** Cross-reference collected evidence techniques with threat catalog */
  crossRefEvidence: protectedProcedure
    .input(z.object({ techniqueIds: z.array(z.string()) }))
    .query(async ({ input }) => {
      const db = await getDbSafe();
      const [actorMatches, ttpMatches] = await Promise.all([
        crossRefThreatCatalog(input.techniqueIds, db),
        crossRefTtpKnowledge(input.techniqueIds, db),
      ]);
      return {
        threatActors: actorMatches,
        ttpKnowledge: ttpMatches,
        totalTechniques: input.techniqueIds.length,
        actorsMatched: actorMatches.length,
        ttpsMatched: ttpMatches.length,
      };
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // LIVE API COLLECTORS — Real external API integrations
  // ═══════════════════════════════════════════════════════════════════════════

  /** Live: Collect cloud misconfigurations from DigitalOcean API */
  collectCloudMisconfigsLive: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const misconfigs = await collectCloudMisconfigs();

    // Ensure a cloud provider record exists
    let providerId: number;
    const existing = await db.select().from(cloudMisconfigurations).limit(1);
    if (existing.length > 0) {
      providerId = existing[0].providerId;
    } else {
      // Create a DigitalOcean provider record — schema requires aws/azure/gcp enum,
      // so we use the closest match and note it in the alias
      const { cloudProviders } = await import("../../drizzle/schema");
      const [inserted] = await db.insert(cloudProviders).values({
        provider: "aws", // Schema enum limitation — this is actually DigitalOcean
        accountId: "digitalocean-live",
        accountAlias: "DigitalOcean (Live API)",
        region: "nyc1",
        status: "active",
      });
      providerId = inserted.insertId;
    }

    for (const mc of misconfigs) {
      // Insert into cloud_misconfigurations table
      await db.insert(cloudMisconfigurations).values({
        providerId,
        resourceType: mc.resourceType,
        resourceArn: mc.resourceArn,
        resourceName: mc.resourceName,
        misconfigType: mc.misconfigType,
        severity: mc.severity,
        description: mc.description,
        currentValue: mc.currentValue,
        expectedValue: mc.expectedValue,
        remediationSteps: mc.remediationSteps,
        complianceFrameworks: mc.complianceFrameworks,
        status: "open",
      });

      // Generate KSI evidence
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "cloud-misconfigs")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `Cloud Misconfig: ${mc.misconfigType}`,
          `${mc.severity.toUpperCase()} | ${mc.resourceType}: ${mc.resourceName} | ${mc.description.slice(0, 200)}`,
          mapping.evidenceType, "cloud-misconfigs-live",
          `cloud-live-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
          { ...mc, liveCollection: true, source: "DigitalOcean API" },
          ctx.user?.id, ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "cloud-misconfigs-live", misconfigsFound: misconfigs.length };
  }),

  /** Live: Collect NGFW validation results from DigitalOcean Firewall API */
  collectNgfwLive: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const tests = await collectNgfwValidation();

    for (const test of tests) {
      // Insert into ngfw_validation_tests table
      await db.insert(ngfwValidationTests).values({
        name: test.name,
        testType: test.testType,
        sourceIp: test.sourceIp,
        targetIp: test.targetIp,
        targetPort: test.targetPort,
        protocol: test.protocol,
        expectedResult: test.expectedResult,
        actualResult: test.actualResult,
        status: "completed",
        firewallVendor: test.firewallVendor,
        ruleMatched: test.ruleMatched,
        durationMs: test.durationMs,
        executedAt: new Date(),
        createdBy: ctx.user?.name || "Auto-Collector",
      });

      // Generate KSI evidence
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "ngfw-validation")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `NGFW Test: ${test.name}`,
          `Expected: ${test.expectedResult} | Actual: ${test.actualResult} | ${test.actualResult === test.expectedResult ? "PASS" : "FAIL"} | Port: ${test.targetPort}`,
          mapping.evidenceType, "ngfw-validation-live",
          `ngfw-live-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
          { ...test, liveCollection: true, source: "DigitalOcean Firewall API" },
          ctx.user?.id, ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "ngfw-validation-live", testsRun: tests.length, passed: tests.filter(t => t.actualResult === t.expectedResult).length, failed: tests.filter(t => t.actualResult !== t.expectedResult).length };
  }),

  /** Live: Collect AD attack simulation data from Cyber C2 API */
  collectAdAttackSimLive: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const sims = await collectAdAttackSims();

    // Ensure an AD environment record exists
    const { adEnvironments } = await import("../../drizzle/schema");
    let envId: number;
    const existingEnv = await db.select().from(adEnvironments).limit(1);
    if (existingEnv.length > 0) {
      envId = existingEnv[0].id;
    } else {
      const [inserted] = await db.insert(adEnvironments).values({
        domainName: "caldera-sim.local",
        domainController: "Caldera API (Simulated AD)",
        forestName: "caldera-sim.local",
        functionalLevel: "Caldera 4.x",
        status: "connected",
      });
      envId = inserted.insertId;
    }

    for (const sim of sims) {
      // Map attackType string to enum value
      const validTypes = ["kerberoasting", "as_rep_roasting", "dcsync", "golden_ticket", "silver_ticket", "pass_the_hash", "pass_the_ticket", "overpass_the_hash", "skeleton_key", "dcshadow", "sid_history_injection", "gpo_abuse", "certificate_abuse", "constrained_delegation", "unconstrained_delegation", "resource_based_constrained_delegation", "ad_enumeration"];
      const attackType = validTypes.includes(sim.attackType) ? sim.attackType : "ad_enumeration";

      await db.insert(adAttackSimulations).values({
        environmentId: envId,
        attackType: attackType as any,
        targetObject: sim.targetObject,
        sourceObject: sim.sourceObject,
        status: sim.status as any,
        riskScore: sim.riskScore,
        severity: sim.severity as any,
        description: sim.description,
        mitreTechniques: sim.mitreTechniques,
        evidence: sim.evidence,
        executedAt: new Date(),
      });

      // Generate KSI evidence
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "ad-attack-sim")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `AD Attack Sim: ${sim.attackType}`,
          `Status: ${sim.status} | Severity: ${sim.severity} | Risk: ${sim.riskScore} | Target: ${sim.targetObject}`,
          mapping.evidenceType, "ad-attack-sim-live",
          `adsim-live-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
          { ...sim, liveCollection: true, source: "Caldera API" },
          ctx.user?.id, ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "ad-attack-sim-live", simsFound: sims.length };
  }),

  /** Live: Collect EDR validation data from Cyber C2 operation results */
  collectEdrLive: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const results = await collectEdrValidation();

    // Ensure an EDR product record exists
    const { edrProducts, edrTestCatalog } = await import("../../drizzle/schema");
    let productId: number;
    const existingProduct = await db.select().from(edrProducts).limit(1);
    if (existingProduct.length > 0) {
      productId = existingProduct[0].id;
    } else {
      const [inserted] = await db.insert(edrProducts).values({
        productName: "Caldera Detection Coverage",
        vendor: "MITRE Caldera",
        version: "4.x",
        deploymentType: "endpoint",
        status: "active",
      });
      productId = inserted.insertId;
    }

    for (const result of results) {
      // Ensure a test catalog entry exists
      let catalogId: number;
      const existingCatalog = await db.select().from(edrTestCatalog).limit(1);
      if (existingCatalog.length > 0) {
        catalogId = existingCatalog[0].id;
      } else {
        const [inserted] = await db.insert(edrTestCatalog).values({
          testName: "Caldera Ability Execution",
          category: "execution",
          mitreTechniqueId: result.techniqueId,
          description: "Caldera-based detection coverage test",
          riskLevel: "safe",
        });
        catalogId = inserted.insertId;
      }

      await db.insert(edrTestResults).values({
        edrProductId: productId,
        testCatalogId: catalogId,
        executionStatus: result.executionStatus as any,
        detectionResult: result.detectionResult as any,
        detectionTimeMs: result.detectionTimeMs,
        alertSeverity: result.alertSeverity,
        alertTitle: result.alertTitle,
        evidence: result.evidence,
        executedAt: new Date(),
      });

      // Generate KSI evidence
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "edr-validation")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `EDR Test: ${result.alertTitle}`,
          `Detection: ${result.detectionResult} | Technique: ${result.techniqueId} | Time: ${result.detectionTimeMs}ms`,
          mapping.evidenceType, "edr-validation-live",
          `edr-live-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
          { ...result, liveCollection: true, source: "Caldera API" },
          ctx.user?.id, ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "edr-validation-live", testsProcessed: results.length, detected: results.filter(r => r.detectionResult === "detected" || r.detectionResult === "blocked").length, missed: results.filter(r => r.detectionResult === "missed").length };
  }),

  /** Live: Collect Atomic Red Team test results from Cyber C2 */
  collectAtomicRedTeamLive: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const executions = await collectAtomicRedTeam();

    for (const exec of executions) {
      // Ensure an atomic test record exists
      const existingTest = await db.select().from(atomicTests).limit(1);
      let testId: number;
      if (existingTest.length > 0) {
        testId = existingTest[0].id;
      } else {
        const [inserted] = await db.insert(atomicTests).values({
          guid: `caldera-${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`,
          techniqueId: exec.techniqueId,
          techniqueName: exec.testName,
          testName: exec.testName,
          description: `Caldera-executed test for ${exec.techniqueId}`,
          supportedPlatforms: exec.targetPlatform,
          executorType: exec.executorType,
        });
        testId = inserted.insertId;
      }

      await db.insert(atomicTestExecutions).values({
        atomicTestId: testId,
        guid: `caldera-exec-${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`,
        techniqueId: exec.techniqueId,
        testName: exec.testName,
        executedBy: exec.executedBy,
        targetHost: exec.targetHost,
        targetPlatform: exec.targetPlatform,
        status: exec.status as any,
        executorType: exec.executorType,
        commandExecuted: exec.commandExecuted,
        exitCode: exec.exitCode,
        detectionTriggered: exec.detectionTriggered,
        durationMs: exec.durationMs,
        startedAt: new Date(),
        completedAt: new Date(),
      });

      // Generate KSI evidence
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "atomic-red-team")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `Atomic Test: ${exec.testName}`,
          `Technique: ${exec.techniqueId} | Status: ${exec.status} | Detection: ${exec.detectionTriggered ? "Yes" : "No"} | Host: ${exec.targetHost}`,
          mapping.evidenceType, "atomic-red-team-live",
          `atomic-live-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
          { ...exec, liveCollection: true, source: "Caldera API" },
          ctx.user?.id, ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "atomic-red-team-live", executionsProcessed: executions.length };
  }),

  /** Live: Collect SIEM connection data from Wazuh/Elastic */
  collectSiemLive: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const connections = await collectSiemConnectors();

    for (const conn of connections) {
      // Insert into siem_connections table
      await db.insert(siemConnections).values({
        name: conn.name,
        backend: conn.backend,
        baseUrl: conn.baseUrl || "unknown",
        connected: conn.connected,
        version: conn.version || null,
        clusterName: conn.clusterName || null,
        alertCount: conn.alertCount || 0,
        errorMessage: conn.errorMessage || null,
        enabled: true,
        lastTestedAt: new Date(),
        createdBy: ctx.user?.id,
      });

      // Generate KSI evidence
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "siem-connectors")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `SIEM: ${conn.name}`,
          `Backend: ${conn.backend} | Connected: ${conn.connected} | Alerts: ${conn.alertCount} | Version: ${conn.version || "N/A"}`,
          mapping.evidenceType, "siem-connectors-live",
          `siem-live-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
          { ...conn, liveCollection: true },
          ctx.user?.id, ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "siem-connectors-live", connectionsFound: connections.length, connected: connections.filter(c => c.connected).length };
  }),

  /** Live: Collect threat intelligence from abuse.ch, Shodan, SecurityTrails */
  collectThreatIntelLive: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    let collected = 0;

    const intel = await collectThreatIntel();

    for (const item of intel) {
      // Generate KSI evidence directly (threat intel doesn't need intermediate table)
      const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === "threat-intel")!;
      for (const ksiId of mapping.ksiIds) {
        await insertKsiEvidence(
          db, ksiId,
          `Threat Intel: ${item.title}`,
          `Source: ${item.source} | Category: ${item.category} | Severity: ${item.severity} | IOCs: ${item.iocs.length}`,
          mapping.evidenceType, "threat-intel-live",
          `ti-live-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
          { ...item, liveCollection: true },
          ctx.user?.id, ctx.user?.name,
        );
        collected++;
      }
    }
    return { collected, source: "threat-intel-live", feedsProcessed: intel.length, totalIocs: intel.reduce((sum, i) => sum + i.iocs.length, 0) };
  }),

  /** Run full LIVE collection sweep across all 7 real API sources */
  runLiveCollectionSweep: protectedProcedure.mutation(async ({ ctx }) => {
    const results: { source: string; collected: number; error?: string; details?: any }[] = [];

    const collectors = [
      { name: "cloud-misconfigs-live", fn: async () => {
        const db = await getDbSafe();
        const misconfigs = await collectCloudMisconfigs();
        return { count: misconfigs.length, details: { misconfigsFound: misconfigs.length } };
      }},
      { name: "ngfw-validation-live", fn: async () => {
        const tests = await collectNgfwValidation();
        return { count: tests.length, details: { testsRun: tests.length, passed: tests.filter(t => t.actualResult === t.expectedResult).length } };
      }},
      { name: "ad-attack-sim-live", fn: async () => {
        const sims = await collectAdAttackSims();
        return { count: sims.length, details: { simsFound: sims.length } };
      }},
      { name: "edr-validation-live", fn: async () => {
        const results = await collectEdrValidation();
        return { count: results.length, details: { testsProcessed: results.length } };
      }},
      { name: "atomic-red-team-live", fn: async () => {
        const execs = await collectAtomicRedTeam();
        return { count: execs.length, details: { executionsProcessed: execs.length } };
      }},
      { name: "siem-connectors-live", fn: async () => {
        const conns = await collectSiemConnectors();
        return { count: conns.length, details: { connectionsFound: conns.length, connected: conns.filter(c => c.connected).length } };
      }},
      { name: "threat-intel-live", fn: async () => {
        const intel = await collectThreatIntel();
        return { count: intel.length, details: { feedsProcessed: intel.length, totalIocs: intel.reduce((sum, i) => sum + i.iocs.length, 0) } };
      }},
    ];

    for (const c of collectors) {
      try {
        const result = await c.fn();
        results.push({ source: c.name, collected: result.count, details: result.details });
      } catch (err: any) {
        results.push({ source: c.name, collected: 0, error: err.message });
      }
    }

    return {
      totalSources: results.length,
      totalCollected: results.reduce((sum, r) => sum + r.collected, 0),
      results,
      sweepTime: new Date().toISOString(),
    };
  }),

  /** Run full collection sweep across all sources — DB + Live APIs */
  runFullCollection: protectedProcedure.mutation(async ({ ctx }) => {
    const db = await getDbSafe();
    const results: { source: string; collected: number; live: boolean; error?: string; threatActorsMatched?: number }[] = [];

    // Phase 1: Collect from local DB tables
    const dbSources = [
      { name: "vuln-scanner", table: vulnScanFindings, orderCol: vulnScanFindings.createdAt },
      { name: "web-app-scanning", table: webAppFindings, orderCol: webAppFindings.createdAt },
      { name: "osint-recon", table: osintFindings, orderCol: osintFindings.createdAt },
      { name: "edr-validation", table: edrTestResults, orderCol: edrTestResults.createdAt },
      { name: "cloud-misconfigs", table: cloudMisconfigurations, orderCol: cloudMisconfigurations.createdAt },
    ];

    for (const src of dbSources) {
      try {
        const rows = await db.select({ count: count() }).from(src.table);
        const rowCount = rows[0]?.count || 0;
        const mapping = SOURCE_KSI_MAP.find(m => m.sourceModule === src.name);
        if (mapping && rowCount > 0) {
          for (const ksiId of mapping.ksiIds) {
            await insertKsiEvidence(
              db, ksiId,
              `Auto-Collection Sweep: ${src.name}`,
              `${rowCount} records found in ${src.name} — auto-collected as ${mapping.evidenceType}`,
              mapping.evidenceType, src.name,
              `sweep-${src.name}-${Date.now()}`,
              { sourceModule: src.name, recordCount: rowCount, sweepTime: new Date().toISOString() },
              ctx.user?.id, ctx.user?.name,
            );
          }
          results.push({ source: src.name, collected: mapping.ksiIds.length, live: false });
        } else {
          results.push({ source: src.name, collected: 0, live: false });
        }
      } catch (err: any) {
        results.push({ source: src.name, collected: 0, live: false, error: err.message });
      }
    }

    // Phase 2: Collect from live scanner APIs with threat catalog cross-referencing
    const liveCollectors = [
      { name: "caldera-live", fn: collectCalderaEvidence },
      { name: "gophish-live", fn: collectGophishEvidence },
      { name: "zap-live", fn: collectZapEvidence },
    ];

    for (const lc of liveCollectors) {
      try {
        const liveEvidence = await lc.fn();
        let collected = 0;
        let actorsMatched = 0;

        for (const ev of liveEvidence) {
          // Cross-reference each evidence item with threat catalog
          let threatActorMatches: any[] = [];
          if (ev.techniqueIds?.length) {
            threatActorMatches = await crossRefThreatCatalog(ev.techniqueIds, db);
            actorsMatched += threatActorMatches.length;
          }

          for (const ksiId of ev.ksiIds) {
            await insertKsiEvidence(
              db, ksiId, ev.title, ev.description,
              "scan_result", lc.name,
              `${lc.name}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`,
              {
                ...ev.evidenceData,
                threatActorMatches: threatActorMatches.slice(0, 5),
                liveCollection: true,
              },
              ctx.user?.id, ctx.user?.name,
            );
            collected++;
          }
        }
        results.push({ source: lc.name, collected, live: true, threatActorsMatched: actorsMatched });
      } catch (err: any) {
        results.push({ source: lc.name, collected: 0, live: true, error: err.message });
      }
    }

    const totalCollected = results.reduce((sum, r) => sum + r.collected, 0);
    const totalThreatActorsMatched = results.reduce((sum, r) => sum + (r.threatActorsMatched || 0), 0);
    return { totalCollected, totalThreatActorsMatched, results, sweepTime: new Date().toISOString() };
  }),
});
