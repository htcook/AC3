/**
 * Engagement Workflow Automation Router
 * Pipes attack vectors from the Attack Vector Engine into the engagement pipeline,
 * auto-creating engagements with pre-loaded Caldera abilities and Metasploit modules.
 * Cross-references the threat catalog for threat-informed engagement planning.
 */
import { router, protectedProcedure } from "../_core/trpc";
import { z } from "zod";
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
} from "../../drizzle/schema";
import { eq, desc, sql, and, inArray, count, like } from "drizzle-orm";
import { createEngagement, createEngagementPipeline, updateEngagementPipeline } from "../db";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new Error("Database not available");
  return db;
}

// ─── Threat-Informed Engagement Templates ─────────────────────────────────
// Maps engagement types to recommended Caldera abilities and MSF modules
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
  createFromVectors: protectedProcedure
    .input(z.object({
      templateId: z.string(),
      name: z.string().min(1),
      customerName: z.string().min(1),
      targetDomain: z.string().optional(),
      targetIpRange: z.string().optional(),
      vectorIds: z.array(z.string()).min(1),
      playbookId: z.string().optional(),
      threatActorIds: z.array(z.number()).optional(),
      includePostExploit: z.boolean().default(true),
      includeCleanup: z.boolean().default(true),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();
      const template = ENGAGEMENT_TEMPLATES[input.templateId];
      if (!template) throw new Error(`Unknown template: ${input.templateId}`);

      // Fetch the attack vectors
      const vectors = await db.select().from(attackVectors)
        .where(inArray(attackVectors.id, input.vectorIds));

      if (vectors.length === 0) throw new Error("No valid attack vectors found");

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
          const techniques = actor.techniques as string[] | null;
          if (techniques) techniques.forEach(t => allTechniques.add(t));
        }
      }

      // Fetch matching Caldera abilities from the threat catalog
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
          .where(inArray(unifiedExploitCatalog.mitreAttackId, techniqueArray))
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

      // If a playbook was specified, link it to the engagement
      if (input.playbookId) {
        await db.update(attackPlaybooks).set({
          engagementId: String(engagementId),
          status: "approved",
          updatedAt: Date.now(),
        }).where(eq(attackPlaybooks.id, input.playbookId));
      }

      // Update vectors to link them to this engagement
      for (const v of vectors) {
        await db.update(attackVectors).set({
          status: "exploiting",
          updatedAt: Date.now(),
        }).where(eq(attackVectors.id, v.id));
      }

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
  getEngagementBrief: protectedProcedure
    .input(z.object({
      vectorIds: z.array(z.string()).min(1),
      templateId: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const db = await getDbSafe();

      const vectors = await db.select().from(attackVectors)
        .where(inArray(attackVectors.id, input.vectorIds));

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
          country: a.country,
          motivation: a.motivation,
          matchedTechniques: ((a.techniques as string[]) || []).filter(t => techniqueArray.includes(t)),
        }));
      }

      // Fetch available Caldera abilities
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
          .where(inArray(unifiedExploitCatalog.mitreAttackId, techniqueArray))
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
          mitreId: e.mitreAttackId,
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
  createFromPlaybook: protectedProcedure
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

      // Link playbook to engagement
      await db.update(attackPlaybooks).set({
        engagementId: String(engagementId),
        status: "approved",
        updatedAt: Date.now(),
      }).where(eq(attackPlaybooks.id, input.playbookId));

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
          { step: 2, status: "completed", message: `${calderaAbilities.length} Caldera abilities + ${msfModules.length} MSF modules pre-loaded`, timestamp: new Date().toISOString() },
          { step: 3, status: "in_progress", message: "Setting up Caldera operation", timestamp: new Date().toISOString() },
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
  listAutomatedEngagements: protectedProcedure
    .input(z.object({
      limit: z.number().default(20),
    }))
    .query(async ({ input }) => {
      const db = await getDbSafe();

      const engs = await db.select().from(engagements)
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
          .where(eq(attackPlaybooks.engagementId, String(eng.id)));

        // Get linked vectors
        const vectors = await db.select().from(attackVectors)
          .where(eq(attackVectors.status, "exploiting"))
          .limit(20);

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
  getDashboardStats: protectedProcedure.query(async () => {
    const db = await getDbSafe();

    const [totalEngagements] = await db.select({ count: count() }).from(engagements);
    const [totalPipelines] = await db.select({ count: count() }).from(engagementPipelines);
    const [totalPlaybooks] = await db.select({ count: count() }).from(attackPlaybooks);
    const [totalVectors] = await db.select({ count: count() }).from(attackVectors);

    // Pipeline status breakdown
    const pipelinesByStatus = await db.select({
      status: engagementPipelines.status,
      count: count(),
    }).from(engagementPipelines).groupBy(engagementPipelines.status);

    // Recent automated engagements
    const recentEngagements = await db.select().from(engagements)
      .orderBy(desc(engagements.createdAt))
      .limit(5);

    // Vector status breakdown
    const vectorsByStatus = await db.select({
      status: attackVectors.status,
      count: count(),
    }).from(attackVectors).groupBy(attackVectors.status);

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
  advancePipeline: protectedProcedure
    .input(z.object({
      pipelineId: z.number(),
      action: z.enum(["next", "complete", "fail"]),
      message: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbSafe();

      const [pipeline] = await db.select().from(engagementPipelines)
        .where(eq(engagementPipelines.id, input.pipelineId));

      if (!pipeline) throw new Error("Pipeline not found");

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
          }).where(eq(engagements.id, pipeline.engagementId));
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
});
