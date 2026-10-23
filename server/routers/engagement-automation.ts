import * as db from "../db";
// @ts-nocheck
/**
 * Engagement Workflow Automation Router
 * Pipes attack vectors from the Attack Vector Engine into the engagement pipeline,
 * auto-creating engagements with pre-loaded emulation abilities and Metasploit modules.
 * Cross-references the threat catalog for threat-informed engagement planning.
 */
import { router, protectedProcedure, tenantProcedure } from "../_core/trpc";
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { getDb as _getDb } from "../db";
import {
  engagements,
  engagementPipelines,
  attackVectors,
  attackPlaybooks,
  attackPlaybookExecutions,
  threatActors,
  threatActorAbilities,
  unifiedExploitCatalog,
  ttpKnowledge,
  customerStackProfiles,
} from "../../drizzle/schema";
import { eq, desc, sql, and, or, inArray, isNull, count, like, gte } from "drizzle-orm";
import { createEngagement, createEngagementPipeline, updateEngagementPipeline } from "../db";
import { assertActiveEngagementAuthorization, getEngagementForTenant } from "../lib/engagement-tenant-access";
import { assertLiveEngagementExecutionAllowed } from "../lib/live-engagement-execution-gate";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

async function getPipelineForTenant(db: any, pipelineId: number, tenantId: number) {
  const [pipeline] = await db
    .select()
    .from(engagementPipelines)
    .where(eq(engagementPipelines.id, pipelineId))
    .limit(1);
  if (!pipeline || !pipeline.engagementId) throw new Error("Pipeline not found");
  await getEngagementForTenant(db, Number(pipeline.engagementId), tenantId);
  return pipeline;
}

async function assertLinkedResourceTenant(
  db: any,
  linkedEngagementId: number | string | null | undefined,
  tenantId: number,
) {
  if (linkedEngagementId === null || linkedEngagementId === undefined) return;
  await getEngagementForTenant(db, Number(linkedEngagementId), tenantId);
}

// ─── Threat-Informed Engagement Templates ─────────────────────────────────
// Maps engagement types to recommended emulation abilities and MSF modules
const ENGAGEMENT_TEMPLATES: Record<string, {
  name: string;
  description: string;
  type: string;
  killChainPhases: string[];
  recommendedTechniques: string[];
  calderaAbilityPatterns: string[];
  msfModulePatterns: string[];
}> = {
  full_pentest: {
    name: "Full Penetration Test",
    description: "Comprehensive assessment covering all kill chain phases from recon through exfiltration",
    type: "pentest",
    killChainPhases: ["reconnaissance", "resource_development", "initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection", "exfiltration"],
    recommendedTechniques: ["T1595", "T1190", "T1059", "T1053", "T1068", "T1003", "T1021", "T1005", "T1041"],
    calderaAbilityPatterns: ["discovery", "credential", "lateral", "exfil"],
    msfModulePatterns: ["exploit/", "post/", "auxiliary/scanner"],
  },
  red_team: {
    name: "Red Team Exercise",
    description: "Adversary emulation focused on specific threat actor TTPs with stealth objectives",
    type: "red_team",
    killChainPhases: ["initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "lateral_movement", "collection", "exfiltration"],
    recommendedTechniques: ["T1566", "T1059.001", "T1547", "T1068", "T1070", "T1003", "T1021.002", "T1560", "T1041"],
    calderaAbilityPatterns: ["persist", "escalat", "evad", "credential", "lateral"],
    msfModulePatterns: ["exploit/multi", "post/windows", "post/linux"],
  },
  phishing_assessment: {
    name: "Phishing Assessment",
    description: "Social engineering campaign testing user awareness and email security controls",
    type: "phishing",
    killChainPhases: ["reconnaissance", "resource_development", "initial_access"],
    recommendedTechniques: ["T1598", "T1566", "T1566.001", "T1566.002", "T1204"],
    calderaAbilityPatterns: ["phish", "social", "user"],
    msfModulePatterns: ["auxiliary/gather", "exploit/multi/browser"],
  },
  web_app_test: {
    name: "Web Application Test",
    description: "Web application security assessment targeting OWASP Top 10 and business logic flaws",
    type: "web_app",
    killChainPhases: ["reconnaissance", "initial_access", "execution", "credential_access"],
    recommendedTechniques: ["T1190", "T1059", "T1552", "T1003"],
    calderaAbilityPatterns: ["web", "inject", "sql"],
    msfModulePatterns: ["exploit/multi/http", "auxiliary/scanner/http"],
  },
  cloud_assessment: {
    name: "Cloud Security Assessment",
    description: "Cloud infrastructure assessment targeting misconfigurations, IAM, and data exposure",
    type: "cloud",
    killChainPhases: ["reconnaissance", "initial_access", "privilege_escalation", "credential_access", "discovery", "collection"],
    recommendedTechniques: ["T1580", "T1078", "T1098", "T1530", "T1619"],
    calderaAbilityPatterns: ["cloud", "aws", "azure", "gcp"],
    msfModulePatterns: ["auxiliary/cloud", "post/multi/gather"],
  },
  apt_emulation: {
    name: "APT Emulation",
    description: "Targeted adversary emulation based on specific threat group TTPs from the threat catalog",
    type: "apt_emulation",
    killChainPhases: ["initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "lateral_movement", "collection", "command_and_control", "exfiltration"],
    recommendedTechniques: ["T1566", "T1059", "T1547", "T1068", "T1070", "T1003", "T1021", "T1074", "T1071", "T1041"],
    calderaAbilityPatterns: ["apt", "adversary", "emulat"],
    msfModulePatterns: ["exploit/", "post/"],
  },
  ics_ot_assessment: {
    name: "ICS/OT Security Assessment",
    description: "Industrial Control System and Operational Technology security assessment targeting PLCs, RTUs, HMIs, and SCADA protocols with safety-aware testing methodology",
    type: "ics_ot",
    killChainPhases: ["reconnaissance", "initial_access", "execution", "persistence", "lateral_movement", "collection", "command_and_control"],
    recommendedTechniques: ["T0846", "T0886", "T0855", "T0831", "T0826", "T0813", "T0821", "T0836", "T0862", "T0887"],
    calderaAbilityPatterns: ["ics", "scada", "plc", "modbus", "dnp3", "ot"],
    msfModulePatterns: ["auxiliary/scanner/scada", "exploit/multi/scada", "auxiliary/scanner/modbus"],
  },
  ics_adversary_emulation: {
    name: "ICS Adversary Emulation",
    description: "Emulate ICS-targeting threat actors (Sandworm, XENOTIME, CHERNOVITE, Dragonfly) using documented ICS malware TTPs against OT environments",
    type: "ics_adversary",
    killChainPhases: ["initial_access", "execution", "persistence", "privilege_escalation", "lateral_movement", "collection", "command_and_control", "exfiltration"],
    recommendedTechniques: ["T0866", "T0855", "T0831", "T0826", "T0813", "T0821", "T0836", "T0843", "T0857", "T0827"],
    calderaAbilityPatterns: ["ics", "scada", "industroyer", "triton", "pipedream", "sandworm"],
    msfModulePatterns: ["exploit/multi/scada", "auxiliary/scanner/scada", "post/multi/gather"],
  },
};

export const engagementAutomationRouter = router({

  /** Get available engagement templates */
  getTemplates: protectedProcedure.query(() => {
    return Object.entries(ENGAGEMENT_TEMPLATES).map(([key, template]) => ({
      templateId: key,
      ...template,
    }));
  }),

  /** Create engagement from attack vectors with pre-loaded modules */
  createFromVectors: tenantProcedure
    .input(z.object({
      templateId: z.string(),
      name: z.string().min(1),
      customerName: z.string().min(1),
      targetDomain: z.string().optional(),
      targetIpRange: z.string().optional(),
      vectorIds: z.array(z.string()).min(1),
      playbookId: z.string().optional(),
      threatActorIds: z.array(z.number()).optional(),
      stackProfileId: z.number().optional(),
      includePostExploit: z.boolean().default(true),
      includeCleanup: z.boolean().default(true),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement: log target domain/IP for audit trail ──
      // Note: this mutation creates the engagement, so no engagementId exists yet.
      // Targets are validated when the pipeline dispatches active tools.
      const launchTargets = [input.targetDomain, input.targetIpRange].filter(Boolean);
      if (launchTargets.length > 0) {
        console.log(`[ScopeGuard] Engagement launch targets logged: ${launchTargets.join(", ")}`);
      }

      const db = await getDbSafe();
      const template = ENGAGEMENT_TEMPLATES[input.templateId];
      if (!template) throw new Error(`Unknown template: ${input.templateId}`);

      // Fetch the attack vectors
      const vectors = await db.select().from(attackVectors)
        .where(inArray(attackVectors.id, input.vectorIds));

      if (vectors.length === 0) throw new Error("No valid attack vectors found");
      await Promise.all(vectors.map((vector) =>
        assertLinkedResourceTenant(db, vector.engagementId, ctx.tenant.tenantId)
      ));

      // Collect all MITRE techniques from vectors
      const allTechniques = new Set<string>();
      for (const v of vectors) {
        const techs = v.mitreTechniqueIds as string[] | null;
        if (techs) techs.forEach(t => allTechniques.add(t));
      }
      // Add template-recommended techniques
      template.recommendedTechniques.forEach(t => allTechniques.add(t));

      // Cross-reference with threat catalog if threat actors specified
      let threatActorData: any[] = [];
      if (input.threatActorIds?.length) {
        threatActorData = await db.select().from(threatActors)
          .where(inArray(threatActors.id, input.threatActorIds));

        // Add threat actor techniques to the technique set
        for (const actor of threatActorData) {
          const techniques = (actor as any).techniques as string[] | null;
          if (techniques) techniques.forEach(t => allTechniques.add(t));
        }
      }

      // Fetch matching emulation abilities from the threat catalog
      const techniqueArray = Array.from(allTechniques);
      let calderaAbilities: any[] = [];
      if (techniqueArray.length > 0) {
        calderaAbilities = await db.select().from(threatActorAbilities)
          .where(inArray(threatActorAbilities.techniqueId, techniqueArray))
          .limit(50);
      }

      // Fetch matching exploit scripts
      let exploitScripts: any[] = [];
      try {
        exploitScripts = await db.select().from(unifiedExploitCatalog)
          .where(inArray(unifiedExploitCatalog.exploitMitreId, techniqueArray))
          .limit(30);
      } catch { /* table may not have data */ }

      // Fetch TTP knowledge for engagement briefing
      let ttpKnowledgeData: any[] = [];
      try {
        ttpKnowledgeData = await db.select().from(ttpKnowledge)
          .where(inArray(ttpKnowledge.techniqueId, techniqueArray))
          .limit(30);
      } catch { /* table may not have data */ }

      // Calculate risk level from vectors
      const maxRisk = Math.max(...vectors.map(v => v.overallRiskScore ?? 0));
      const riskLevel = maxRisk >= 9 ? "critical" : maxRisk >= 7 ? "high" : maxRisk >= 5 ? "medium" : "low";

      // Create the engagement
      const engagementId = await createEngagement({
        name: input.name,
        customerName: input.customerName,
        engagementType: template.type as any,
        status: "planning",
        targetDomain: input.targetDomain || null,
        targetIpRange: input.targetIpRange || null,
        engTenantId: ctx.tenant.tenantId,
        createdBy: ctx.user.id,
        notes: JSON.stringify({
          autoGenerated: true,
          templateId: input.templateId,
          vectorCount: vectors.length,
          techniqueCount: techniqueArray.length,
          calderaAbilityCount: calderaAbilities.length,
          exploitScriptCount: exploitScripts.length,
          threatActors: threatActorData.map(a => ({ id: a.id, name: a.name, aliases: a.aliases })),
          riskLevel,
          notes: input.notes,
        }),
      });

      // Create the engagement pipeline
      const pipelineId = await createEngagementPipeline({
        userId: ctx.user.id,
        name: `${input.name} - Automated Pipeline`,
        status: "intel_scan",
        targetDomains: input.targetDomain ? [input.targetDomain] : [],
        clientType: template.type,
        orgProfile: {
          riskLevel,
          vectorCount: vectors.length,
          threatActors: threatActorData.map(a => a.name),
          killChainCoverage: template.killChainPhases,
        },
        recommendedActors: threatActorData.map(a => String(a.id)),
        engagementId,
        currentStep: 1,
        totalSteps: 6,
        stepLog: [{
          step: 1,
          status: "completed",
          message: `Auto-generated from ${vectors.length} attack vectors with ${techniqueArray.length} MITRE techniques`,
          timestamp: new Date().toISOString(),
        }],
      });

      // Source playbooks are either global catalog records (unlinked) or already
      // owned by a tenant engagement. Never relink or mutate them here.
      if (input.playbookId) {
        const [playbook] = await db.select().from(attackPlaybooks)
          .where(eq(attackPlaybooks.id, input.playbookId)).limit(1);
        if (!playbook) throw new Error("Playbook not found");
        await assertLinkedResourceTenant(db, playbook.engagementId, ctx.tenant.tenantId);
      }

      // Existing stack profiles are read-only inputs. A linked profile must
      // already belong to the current tenant; an unlinked profile is not claimed.
      if (input.stackProfileId) {
        const [profile] = await db.select().from(customerStackProfiles)
          .where(eq(customerStackProfiles.id, input.stackProfileId)).limit(1);
        if (!profile) throw new Error("Stack profile not found");
        await assertLinkedResourceTenant(db, profile.engagementId, ctx.tenant.tenantId);
      }

      // Do not mutate global or linked vector source records from this workflow.

      return {
        engagementId,
        pipelineId,
        name: input.name,
        templateId: input.templateId,
        vectorCount: vectors.length,
        techniqueCount: techniqueArray.length,
        calderaAbilityCount: calderaAbilities.length,
        exploitScriptCount: exploitScripts.length,
        threatActorsLinked: threatActorData.length,
        ttpKnowledgeEntries: ttpKnowledgeData.length,
        riskLevel,
        killChainCoverage: template.killChainPhases,
      };
    }),

  /** Get threat-informed engagement brief for a set of vectors */
  getEngagementBrief: tenantProcedure
    .input(z.object({
      vectorIds: z.array(z.string()).min(1),
      templateId: z.string().optional(),
    }))
    .query(async ({ input, ctx }) => {
      const db = await getDbSafe();

      const vectors = await db.select().from(attackVectors)
        .where(inArray(attackVectors.id, input.vectorIds));
      await Promise.all(vectors.map((vector) =>
        assertLinkedResourceTenant(db, vector.engagementId, ctx.tenant.tenantId)
      ));

      // Collect techniques
      const allTechniques = new Set<string>();
      for (const v of vectors) {
        const techs = v.mitreTechniqueIds as string[] | null;
        if (techs) techs.forEach(t => allTechniques.add(t));
      }
      const techniqueArray = Array.from(allTechniques);

      // Cross-reference threat actors
      let matchedActors: any[] = [];
      if (techniqueArray.length > 0) {
        const actors = await db.select().from(threatActors).limit(200);
        matchedActors = actors.filter(a => {
          const actorTechs = a.techniques as string[] | null;
          if (!actorTechs) return false;
          return techniqueArray.some(t => actorTechs.includes(t));
        }).map(a => ({
          id: a.id,
          name: a.name,
          aliases: a.aliases,
          country: a.origin,
          motivation: a.motivation,
          matchedTechniques: ((a.techniques as string[]) || []).filter(t => techniqueArray.includes(t)),
        }));
      }

      // Fetch available emulation abilities
      let calderaAbilities: any[] = [];
      if (techniqueArray.length > 0) {
        calderaAbilities = await db.select().from(threatActorAbilities)
          .where(inArray(threatActorAbilities.techniqueId, techniqueArray))
          .limit(50);
      }

      // Fetch matching exploits
      let exploits: any[] = [];
      try {
        exploits = await db.select().from(unifiedExploitCatalog)
          .where(inArray(unifiedExploitCatalog.exploitMitreId, techniqueArray))
          .limit(30);
      } catch { /* */ }

      // Fetch TTP knowledge
      let ttpData: any[] = [];
      try {
        ttpData = await db.select().from(ttpKnowledge)
          .where(inArray(ttpKnowledge.techniqueId, techniqueArray))
          .limit(30);
      } catch { /* */ }

      // Risk assessment
      const maxRisk = Math.max(...vectors.map(v => v.overallRiskScore ?? 0), 0);
      const avgRisk = vectors.length > 0
        ? vectors.reduce((sum, v) => sum + (v.overallRiskScore ?? 0), 0) / vectors.length
        : 0;

      // Kill chain coverage
      const coveredPhases = Array.from(new Set(vectors.map(v => v.killChainPhase).filter(Boolean)));

      // Recommended template
      const template = input.templateId
        ? ENGAGEMENT_TEMPLATES[input.templateId]
        : Object.values(ENGAGEMENT_TEMPLATES).find(t =>
          t.killChainPhases.length <= coveredPhases.length + 3
        ) || ENGAGEMENT_TEMPLATES.full_pentest;

      return {
        vectorSummary: {
          total: vectors.length,
          maxRisk,
          avgRisk: Math.round(avgRisk * 10) / 10,
          riskLevel: maxRisk >= 9 ? "critical" : maxRisk >= 7 ? "high" : maxRisk >= 5 ? "medium" : "low",
          killChainCoverage: coveredPhases,
          byCategory: vectors.reduce((acc, v) => {
            const cat = v.category || "unknown";
            acc[cat] = (acc[cat] || 0) + 1;
            return acc;
          }, {} as Record<string, number>),
        },
        techniques: techniqueArray,
        threatActors: matchedActors.slice(0, 10),
        calderaAbilities: calderaAbilities.map(a => ({
          id: a.id,
          name: a.abilityName,
          techniqueId: a.techniqueId,
          tactic: a.tactic,
          description: a.description,
        })),
        exploits: exploits.map(e => ({
          id: e.id,
          name: e.name,
          cve: e.cveId,
          platform: e.platform,
          mitreId: e.mitreTechniqueId,
          reliability: e.reliability,
        })),
        ttpKnowledge: ttpData.map(t => ({
          techniqueId: t.techniqueId,
          techniqueName: t.techniqueName,
          tactic: t.tactic,
          description: t.description,
        })),
        recommendedTemplate: template ? {
          name: template.name,
          description: template.description,
          killChainPhases: template.killChainPhases,
        } : null,
      };
    }),

  /** Auto-generate engagement from playbook with full module loading */
  createFromPlaybook: tenantProcedure
    .input(z.object({
      playbookId: z.string(),
      customerName: z.string().min(1),
      targetDomain: z.string().optional(),
      targetIpRange: z.string().optional(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();

      // Fetch the playbook
      const [playbook] = await db.select().from(attackPlaybooks)
        .where(eq(attackPlaybooks.id, input.playbookId));

      if (!playbook) throw new Error("Playbook not found");
      await assertLinkedResourceTenant(db, playbook.engagementId, ctx.tenant.tenantId);

      const calderaAbilities = (playbook.calderaAbilities as any[]) || [];
      const msfModules = (playbook.msfModules as any[]) || [];
      const killChainCoverage = (playbook.killChainCoverage as string[]) || [];

      // Create the engagement
      const engagementId = await createEngagement({
        name: playbook.name,
        customerName: input.customerName,
        engagementType: "pentest",
        status: "planning",
        targetDomain: input.targetDomain || null,
        targetIpRange: input.targetIpRange || null,
        engTenantId: ctx.tenant.tenantId,
        createdBy: ctx.user.id,
        notes: JSON.stringify({
          autoGenerated: true,
          fromPlaybook: input.playbookId,
          calderaAbilityCount: calderaAbilities.length,
          msfModuleCount: msfModules.length,
          killChainCoverage,
          riskLevel: playbook.riskLevel,
          notes: input.notes,
        }),
      });

      // The playbook remains a read-only source record. Do not claim a global
      // catalog item or relink a pre-existing tenant resource as a side effect.

      // Create pipeline
      const pipelineId = await createEngagementPipeline({
        userId: ctx.user.id,
        name: `${playbook.name} - Auto Pipeline`,
        status: "caldera_setup",
        targetDomains: input.targetDomain ? [input.targetDomain] : [],
        clientType: "pentest",
        orgProfile: {
          riskLevel: playbook.riskLevel,
          killChainCoverage,
        },
        engagementId,
        currentStep: 3,
        totalSteps: 6,
        stepLog: [
          { step: 1, status: "completed", message: "Playbook loaded", timestamp: new Date().toISOString() },
          { step: 2, status: "completed", message: `${calderaAbilities.length} emulation abilities + ${msfModules.length} MSF modules pre-loaded`, timestamp: new Date().toISOString() },
          { step: 3, status: "in_progress", message: "Setting up Cyber C2 operation", timestamp: new Date().toISOString() },
        ],
      });

      return {
        engagementId,
        pipelineId,
        playbookName: playbook.name,
        calderaAbilityCount: calderaAbilities.length,
        msfModuleCount: msfModules.length,
        killChainCoverage,
        riskLevel: playbook.riskLevel,
      };
    }),

  /** List automated engagements with their pipeline status */
  listAutomatedEngagements: tenantProcedure
    .input(z.object({
      limit: z.number().default(20),
    }))
    .query(async ({ input, ctx }) => {
      const db = await getDbSafe();

      const engs = await db.select().from(engagements)
        .where(eq(engagements.engTenantId, ctx.tenant.tenantId))
        .orderBy(desc(engagements.createdAt))
        .limit(input.limit);

      // Filter to auto-generated engagements and enrich with pipeline data
      const results = [];
      for (const eng of engs) {
        let isAutoGenerated = false;
        let metadata: any = {};
        try {
          metadata = typeof eng.notes === "string" ? JSON.parse(eng.notes) : {};
          isAutoGenerated = metadata.autoGenerated === true;
        } catch { /* not JSON notes */ }

        if (!isAutoGenerated) continue;

        // Get pipeline
        const [pipeline] = await db.select().from(engagementPipelines)
          .where(eq(engagementPipelines.engagementId, eng.id));

        // Get linked playbooks
        const playbooks = await db.select().from(attackPlaybooks)
          .where(eq(attackPlaybooks.engagementId, eng.id));

        results.push({
          engagement: {
            id: eng.id,
            name: eng.name,
            customerName: eng.customerName,
            type: eng.engagementType,
            status: eng.status,
            targetDomain: eng.targetDomain,
            roeStatus: eng.roeStatus,
            createdAt: eng.createdAt,
          },
          pipeline: pipeline ? {
            id: pipeline.id,
            status: pipeline.status,
            currentStep: pipeline.currentStep,
            totalSteps: pipeline.totalSteps,
            calderaOperationId: pipeline.calderaOperationId,
            gophishCampaignId: pipeline.gophishCampaignId,
          } : null,
          metadata: {
            templateId: metadata.templateId,
            vectorCount: metadata.vectorCount,
            techniqueCount: metadata.techniqueCount,
            calderaAbilityCount: metadata.calderaAbilityCount,
            exploitScriptCount: metadata.exploitScriptCount,
            threatActors: metadata.threatActors,
            riskLevel: metadata.riskLevel,
          },
          playbooks: playbooks.map(p => ({
            id: p.id,
            name: p.name,
            status: p.status,
            riskLevel: p.riskLevel,
          })),
        });
      }

      return results;
    }),

  /** Get engagement automation dashboard stats */
  getDashboardStats: tenantProcedure.query(async ({ ctx }) => {
    const db = await getDbSafe();

    const tenantEngagements = await db.select({ id: engagements.id }).from(engagements)
      .where(eq(engagements.engTenantId, ctx.tenant.tenantId));
    const tenantEngagementIds = tenantEngagements.map((eng: any) => eng.id);

    const totalEngagements = { count: tenantEngagementIds.length };
    const [totalPipelines] = tenantEngagementIds.length > 0
      ? await db.select({ count: count() }).from(engagementPipelines)
        .where(inArray(engagementPipelines.engagementId, tenantEngagementIds))
      : [{ count: 0 }];
    const [totalPlaybooks] = tenantEngagementIds.length > 0
      ? await db.select({ count: count() }).from(attackPlaybooks)
        .where(inArray(attackPlaybooks.engagementId, tenantEngagementIds))
      : [{ count: 0 }];

    // Pipeline status breakdown
    const pipelinesByStatus = await db.select({
      status: engagementPipelines.status,
      count: count(),
    }).from(engagementPipelines)
      .where(tenantEngagementIds.length > 0
        ? inArray(engagementPipelines.engagementId, tenantEngagementIds)
        : sql`1 = 0`)
      .groupBy(engagementPipelines.status);

    // Recent automated engagements
    const recentEngagements = await db.select().from(engagements)
      .where(eq(engagements.engTenantId, ctx.tenant.tenantId))
      .orderBy(desc(engagements.createdAt))
      .limit(5);

    // Attack-vector tables have no tenant foreign key. Do not expose their global
    // aggregate until they receive the same tenant contract as engagements.
    const totalVectors = { count: 0 };
    const vectorsByStatus: Array<{ status: string; count: number }> = [];

    return {
      totalEngagements: totalEngagements?.count || 0,
      totalPipelines: totalPipelines?.count || 0,
      totalPlaybooks: totalPlaybooks?.count || 0,
      totalVectors: totalVectors?.count || 0,
      pipelinesByStatus,
      vectorsByStatus,
      recentEngagements: recentEngagements.map(e => ({
        id: e.id,
        name: e.name,
        status: e.status,
        type: e.engagementType,
        createdAt: e.createdAt,
      })),
      templates: Object.entries(ENGAGEMENT_TEMPLATES).map(([key, t]) => ({
        id: key,
        name: t.name,
        type: t.type,
        phaseCount: t.killChainPhases.length,
      })),
    };
  }),

  /** Advance pipeline to next step with module loading */
  advancePipeline: tenantProcedure
    .input(z.object({
      pipelineId: z.number(),
      action: z.enum(["next", "complete", "fail"]),
      message: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();

      const pipeline = await getPipelineForTenant(db, input.pipelineId, ctx.tenant.tenantId);

      const stepLog = (pipeline.stepLog as any[]) || [];
      const currentStep = pipeline.currentStep || 0;

      if (input.action === "fail") {
        await updateEngagementPipeline(input.pipelineId, {
          status: "failed",
          errorMessage: input.message || "Pipeline failed",
          stepLog: [...stepLog, {
            step: currentStep,
            status: "failed",
            message: input.message || "Pipeline failed",
            timestamp: new Date().toISOString(),
          }],
        });
        return { status: "failed", step: currentStep };
      }

      if (input.action === "complete") {
        await updateEngagementPipeline(input.pipelineId, {
          status: "completed",
          currentStep: pipeline.totalSteps,
          completedAt: new Date(),
          stepLog: [...stepLog, {
            step: currentStep,
            status: "completed",
            message: input.message || "Pipeline completed",
            timestamp: new Date().toISOString(),
          }],
        });

        // Also update the linked engagement status
        if (pipeline.engagementId) {
          await db.update(engagements).set({
            status: "completed",
          }).where(and(
            eq(engagements.id, Number(pipeline.engagementId)),
            eq(engagements.engTenantId, ctx.tenant.tenantId),
          ));
        }

        return { status: "completed", step: pipeline.totalSteps };
      }

      // Advance to next step
      const nextStep = currentStep + 1;
      const PIPELINE_STATUSES = ["pending", "intel_scan", "risk_scoring", "campaign_design", "caldera_setup", "gophish_setup", "ready", "running", "completed"];
      const nextStatus = PIPELINE_STATUSES[Math.min(nextStep, PIPELINE_STATUSES.length - 1)] || "running";

      await updateEngagementPipeline(input.pipelineId, {
        status: nextStatus as any,
        currentStep: nextStep,
        stepLog: [...stepLog, {
          step: nextStep,
          status: "in_progress",
          message: input.message || `Advanced to step ${nextStep}: ${nextStatus}`,
          timestamp: new Date().toISOString(),
        }],
      });

      return { status: nextStatus, step: nextStep };
    }),

  // ── Training execution (fail closed pending dedicated authorization) ───────
  launchTrainingLab: tenantProcedure
    .input(z.object({
      target: z.string().min(1).describe('Training lab domain or IP (e.g., demo.testfire.net)'),
      name: z.string().optional(),
      engagementType: z.enum(['pentest', 'red_team']).default('pentest'),
      scanMode: z.enum(['strict_passive', 'standard', 'active']).default('active'),
    }))
    .mutation(async () => {
      throw new TRPCError({
        code: "PRECONDITION_FAILED",
        message: "Automated training-lab execution is disabled until it uses a distinct, audited, expiry-bounded training authorization instead of self-minting a signed RoE.",
      });
    }),

  batchTrainingRun: tenantProcedure
    .input(z.object({
      targets: z.array(z.object({
        domain: z.string(),
        name: z.string().optional(),
        engagementType: z.enum(['pentest', 'red_team']).default('pentest'),
        scanProfile: z.enum(['quick', 'standard', 'deep', 'stealth']).default('standard'),
      })).min(1).max(20),
      scanMode: z.enum(['strict_passive', 'standard', 'active']).default('active'),
      injectDfirKnowledge: z.boolean().default(true),
      autoExecute: z.boolean().default(true),
      runGraduationAfter: z.boolean().default(true),
    }))
    .mutation(async () => {
      throw new TRPCError({
        code: "PRECONDITION_FAILED",
        message: "Automated batch training execution is disabled until it uses a distinct, audited, expiry-bounded training authorization instead of self-minting a signed RoE.",
      });
    }),

  /**
   * Get batch training run status — checks all active training lab engagements
   */
  getBatchTrainingStatus: tenantProcedure
    .query(async ({ ctx }) => {
      const dbConn = await getDbSafe();
      // Find all training lab engagements
      const trainingEngagements = await dbConn.select({
        id: engagements.id,
        name: engagements.name,
        targetDomain: engagements.targetDomain,
        status: engagements.status,
        createdAt: engagements.createdAt,
      }).from(engagements)
        .where(and(
          eq(engagements.customerName, 'Training Lab (Authorized)'),
          eq(engagements.engTenantId, ctx.tenant.tenantId),
        ))
        .orderBy(desc(engagements.id))
        .limit(50);

      // Get ops state for each
      const { getOpsState, getOpsStateWithRecovery } = await import('../lib/engagement-orchestrator');
      const statuses = await Promise.all(trainingEngagements.map(async eng => {
        let state = getOpsState(eng.id);
        if (!state) state = await getOpsStateWithRecovery(eng.id);
        return {
          engagementId: eng.id,
          name: eng.name,
          target: eng.targetDomain,
          dbStatus: eng.status,
          opsPhase: state?.phase || 'unknown',
          isRunning: state?.isRunning || false,
          progress: state?.progress || 0,
          vulnsFound: state?.stats?.vulnsFound || 0,
          exploitsRun: state?.stats?.exploitsRun || 0,
          exploitsSucceeded: state?.stats?.exploitsSucceeded || 0,
          assetsDiscovered: state?.assets?.length || 0,
          error: state?.error,
          createdAt: eng.createdAt,
        };
      }));

      // Get training data stats
      let trainingStats = { totalExamples: 0, totalDecisions: 0, callerBreakdown: {} as Record<string, number> };
      try {
        const { getTrainingStats } = await import('../lib/engagement-training-bridge');
        trainingStats = await getTrainingStats();
      } catch { /* bridge may not have data */ }

      // Get graduation summary (telemetry-based tiers)
      let graduationSummary = { totalCallers: 0, tier1: 0, tier2: 0, tier3: 0, tier4: 0, tier5: 0 };
      try {
        const { llmTelemetry } = await import('../../drizzle/schema');
        const cutoff = new Date(Date.now() - 30 * 86400000);
        const rows = await dbConn.select({
          caller: llmTelemetry.caller,
          totalCalls: sql<number>`COUNT(*)`,
          successCount: sql<number>`SUM(CASE WHEN ${llmTelemetry.llmStatus} = 'success' THEN 1 ELSE 0 END)`,
        }).from(llmTelemetry)
          .where(gte(llmTelemetry.calledAt, cutoff.toISOString().slice(0, 19).replace('T', ' ')))
          .groupBy(llmTelemetry.caller);
        graduationSummary.totalCallers = rows.length;
        for (const row of rows) {
          const rate = Number(row.totalCalls) > 0 ? (Number(row.successCount) / Number(row.totalCalls)) * 100 : 0;
          const calls = Number(row.totalCalls);
          if (rate >= 97 && calls >= 500) graduationSummary.tier1++;
          else if (rate >= 90 && calls >= 200) graduationSummary.tier2++;
          else if (rate >= 80 && calls >= 50) graduationSummary.tier3++;
          else graduationSummary.tier4++;
        }
      } catch { /* telemetry may be empty */ }

      // Get full graduation lab summary from the bridge
      let labSummary: any = null;
      try {
        const { getGraduationLabSummary } = await import('../lib/graduation-lab-bridge');
        labSummary = getGraduationLabSummary();
      } catch { /* bridge may not have data yet */ }

      return {
        engagements: statuses,
        activeCount: statuses.filter(s => s.isRunning).length,
        completedCount: statuses.filter(s => s.opsPhase === 'completed').length,
        errorCount: statuses.filter(s => s.opsPhase === 'error' || s.error).length,
        totalVulns: statuses.reduce((s, e) => s + e.vulnsFound, 0),
        totalExploits: statuses.reduce((s, e) => s + e.exploitsRun, 0),
        totalExploitSuccesses: statuses.reduce((s, e) => s + e.exploitsSucceeded, 0),
        trainingStats,
        graduationSummary,
        labSummary,
      };
    }),

  /** Suggest stack profiles for engagement creation based on customer name */
  suggestStackProfiles: tenantProcedure
    .input(z.object({
      customerName: z.string().optional(),
      engagementId: z.number().optional(),
    }))
    .query(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const tenantEngagementRows = await db.select({ id: engagements.id }).from(engagements)
        .where(eq(engagements.engTenantId, ctx.tenant.tenantId));
      const tenantEngagementIds = tenantEngagementRows.map((eng: any) => eng.id);
      const profiles = await db.select().from(customerStackProfiles)
        .where(tenantEngagementIds.length > 0
          ? or(
            isNull(customerStackProfiles.engagementId),
            inArray(customerStackProfiles.engagementId, tenantEngagementIds),
          )
          : isNull(customerStackProfiles.engagementId))
        .orderBy(desc(customerStackProfiles.createdAt))
        .limit(50);

      // Score profiles by relevance to customer name
      const scored = profiles.map(p => {
        let relevanceScore = 0;
        const profileName = (p.customerName || '').toLowerCase();
        const searchName = (input.customerName || '').toLowerCase();
        if (searchName && profileName.includes(searchName)) relevanceScore = 100;
        else if (searchName && profileName.split(/\s+/).some((w: string) => searchName.includes(w))) relevanceScore = 50;
        // Boost unlinked profiles
        if (!p.engagementId) relevanceScore += 10;
        return { ...p, relevanceScore };
      }).sort((a, b) => b.relevanceScore - a.relevanceScore);

      return {
        profiles: scored.slice(0, 10).map(p => ({
          id: p.id,
          customerName: p.customerName,
          technologies: p.technologies,
          technologyVersions: p.technologyVersions,
          engagementId: p.engagementId,
          relevanceScore: p.relevanceScore,
          isLinked: !!p.engagementId,
        })),
        totalAvailable: profiles.length,
        unlinkedCount: profiles.filter(p => !p.engagementId).length,
      };
    }),

  /** Recommend ICS/SCADA tools for OT engagements based on target protocols and engagement type */
  getIcsToolRecommendations: protectedProcedure
    .input(z.object({
      templateId: z.string(),
      targetProtocols: z.array(z.string()).optional(),
      targetVendors: z.array(z.string()).optional(),
      engagementPhase: z.enum(['recon', 'assessment', 'exploitation', 'monitoring', 'all']).default('all'),
    }))
    .query(({ input }) => {
      const { ICS_OPEN_SOURCE_TOOLS, ICS_MALWARE_FAMILIES } = require('../lib/ics-scada-intel');
      const isIcsTemplate = input.templateId.includes('ics');
      if (!isIcsTemplate) return { tools: [], malwareFamilies: [], isIcsEngagement: false };

      // Map engagement phase to tool categories
      const phaseToCategories: Record<string, string[]> = {
        recon: ['monitoring', 'protocol_analysis'],
        assessment: ['assessment', 'framework'],
        exploitation: ['framework', 'simulation'],
        monitoring: ['monitoring', 'honeypot', 'forensics'],
        all: ['honeypot', 'assessment', 'monitoring', 'simulation', 'framework', 'protocol_analysis', 'forensics'],
      };
      const relevantCategories = phaseToCategories[input.engagementPhase] || phaseToCategories.all;

      // Filter tools by category and optionally by protocol
      let tools = ICS_OPEN_SOURCE_TOOLS.filter((t: any) => relevantCategories.includes(t.category));
      if (input.targetProtocols && input.targetProtocols.length > 0) {
        const protos = input.targetProtocols.map((p: string) => p.toLowerCase());
        tools = tools.filter((t: any) => t.protocols.some((p: string) => protos.includes(p)));
      }

      // Filter malware families by vendor if specified
      let malwareFamilies = [...ICS_MALWARE_FAMILIES];
      if (input.targetVendors && input.targetVendors.length > 0) {
        const vendors = input.targetVendors.map((v: string) => v.toLowerCase());
        malwareFamilies = malwareFamilies.filter((m: any) =>
          m.targetedVendors.some((v: string) => vendors.some(tv => v.toLowerCase().includes(tv)))
        );
      }

      return {
        tools: tools.map((t: any) => ({
          name: t.name,
          category: t.category,
          description: t.description,
          githubUrl: t.githubUrl,
          license: t.license,
          protocols: t.protocols,
          useCase: t.useCase,
          recommended: true,
        })),
        malwareFamilies: malwareFamilies.map((m: any) => ({
          name: m.name,
          attribution: m.attribution,
          year: m.year,
          targetedProtocols: m.targetedProtocols,
          targetedVendors: m.targetedVendors,
          mitreIcsTechniques: m.mitreIcsTechniques,
          description: m.description,
        })),
        isIcsEngagement: true,
        recommendedProtocols: [...new Set(tools.flatMap((t: any) => t.protocols))],
      };
    }),
});
