import * as db from "../db";
// @ts-nocheck
/**
 * Engagement Workflow Automation Router
 * Pipes attack vectors from the Attack Vector Engine into the engagement pipeline,
 * auto-creating engagements with pre-loaded emulation abilities and Metasploit modules.
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
import { eq, desc, sql, and, inArray, count, like, gte } from "drizzle-orm";
import { createEngagement, createEngagementPipeline, updateEngagementPipeline } from "../db";

async function getDbSafe() {
  const db = await _getDb();
  if (!db) throw new Error("Database not available");
  return db;
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
          status: "exploited",
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
          .where(eq(attackVectors.status, "exploited"))
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

  // ── Training Lab Auto-Runner ──────────────────────────────────────────────
  // Creates an engagement for a known training lab target and runs the full
  // pipeline (recon → enumeration → vuln detection → exploitation) with all
  // approval gates auto-approved. Results feed into the engagement findings.
  launchTrainingLab: protectedProcedure
    .input(z.object({
      target: z.string().min(1).describe('Training lab domain or IP (e.g., demo.testfire.net)'),
      name: z.string().optional(),
      engagementType: z.enum(['pentest', 'red_team']).default('pentest'),
      scanMode: z.enum(['strict_passive', 'standard', 'active']).default('active'),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbSafe();

      // Known training lab profiles with expected vulns
      const TRAINING_LABS: Record<string, { name: string; description: string; expectedVulns: string[] }> = {
        'demo.testfire.net': {
          name: 'Altoro Mutual (IBM AppScan)',
          description: 'Intentionally vulnerable banking application with SQL injection, XSS, authentication bypass, and session management flaws.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'XSS - Stored', 'Authentication Bypass', 'Session Fixation', 'Insecure Direct Object Reference', 'Path Traversal'],
        },
        'zero.webappsecurity.com': {
          name: 'Zero Bank (Micro Focus)',
          description: 'Intentionally vulnerable banking application with SQL injection, XSS, CSRF, and broken authentication.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'CSRF', 'Broken Authentication', 'Insecure Direct Object Reference'],
        },
        'testphp.vulnweb.com': {
          name: 'Acunetix Test PHP',
          description: 'PHP-based vulnerable web application with SQL injection, XSS, file inclusion, and command injection.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'XSS - Stored', 'File Inclusion', 'Command Injection', 'Directory Traversal', 'File Upload'],
        },
        'dvwa.co.uk': {
          name: 'DVWA (Damn Vulnerable Web Application)',
          description: 'Classic training lab with 14 vulnerability exercises including SQL injection, XSS, command injection, CSRF, and file upload.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'XSS - Stored', 'Command Injection', 'CSRF', 'File Upload', 'File Inclusion', 'Brute Force', 'Insecure CAPTCHA'],
        },
        'juiceshop.lab.aceofcloud.io': {
          name: 'OWASP Juice Shop (AceOfCloud Lab)',
          description: 'Self-hosted OWASP Juice Shop instance with 42+ vulnerability challenges including SQL injection, XSS, SSTI, XXE, SSRF, NoSQL injection, and broken authentication.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'XSS - Stored', 'XSS - DOM', 'NoSQL Injection', 'SSTI', 'XXE', 'SSRF', 'Broken Authentication', 'CSRF', 'Directory Traversal', 'Sensitive Data Exposure', 'Unvalidated Redirect'],
        },
        'bwapp.lab.aceofcloud.io': {
          name: 'bWAPP (AceOfCloud Lab)',
          description: 'Self-hosted bWAPP instance with 100+ vulnerability exercises including SQL injection, XSS, OS command injection, PHP code injection, XXE, SSRF, and Shellshock.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'XSS - Stored', 'OS Command Injection', 'PHP Code Injection', 'SSI Injection', 'XXE', 'SSRF', 'CSRF', 'File Upload', 'File Inclusion', 'Directory Traversal', 'Shellshock', 'LDAP Injection'],
        },
        'mutillidae.lab.aceofcloud.io': {
          name: 'Mutillidae (AceOfCloud Lab)',
          description: 'Self-hosted Mutillidae II instance with OWASP Top 10 vulnerability exercises including SQL injection, XSS, XXE, file inclusion, command injection, and log injection.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'XSS - Stored', 'XSS - DOM', 'Command Injection', 'XXE', 'File Inclusion', 'Directory Traversal', 'CSRF', 'Clickjacking', 'Log Injection', 'HTTP Parameter Pollution'],
        },
        'crapi.lab.aceofcloud.io': {
          name: 'crAPI (AceOfCloud Lab)',
          description: 'Self-hosted crAPI (Completely Ridiculous API) instance for testing API-specific vulnerabilities including BOLA, mass assignment, rate limiting bypass, SSRF, and broken authentication.',
          expectedVulns: ['BOLA', 'Mass Assignment', 'Excessive Data Exposure', 'Rate Limiting Bypass', 'SSRF', 'Broken Authentication', 'SQL Injection', 'NoSQL Injection', 'JWT Vulnerabilities', 'IDOR'],
        },
      };

      const labProfile = TRAINING_LABS[input.target.toLowerCase()] || {
        name: `Training Lab: ${input.target}`,
        description: `Custom training lab target: ${input.target}`,
        expectedVulns: [],
      };

      const engagementName = input.name || `${labProfile.name} - Training Lab Run`;

      // 1. Create the engagement
      const engagementId = await createEngagement({
        name: engagementName,
        customerName: 'Training Lab (Authorized)',
        engagementType: input.engagementType,
        status: 'active',
        targetDomain: input.target,
        targetIpRange: null,
        roeStatus: 'signed',
        roeSignedDate: new Date(),
        createdBy: ctx.user.id,
        notes: JSON.stringify({
          trainingLab: true,
          labProfile: labProfile.name,
          expectedVulns: labProfile.expectedVulns,
          description: labProfile.description,
          scanMode: input.scanMode,
          autoApproveAll: true,
          launchedAt: new Date().toISOString(),
        }),
      });

      // 2. Create the engagement pipeline
      const pipelineId = await createEngagementPipeline({
        userId: ctx.user.id,
        name: `${engagementName} - Auto Pipeline`,
        status: 'intel_scan',
        targetDomains: [input.target],
        clientType: input.engagementType,
        orgProfile: {
          riskLevel: 'high',
          trainingLab: true,
          expectedVulns: labProfile.expectedVulns,
        },
        recommendedActors: [],
        engagementId,
        currentStep: 1,
        totalSteps: 6,
        stepLog: [{
          step: 1,
          status: 'completed',
          message: `Training lab engagement created for ${labProfile.name}. Full auto-run pipeline starting.`,
          timestamp: new Date().toISOString(),
        }],
      });

      // 3. Initialize ops state with training lab mode (auto-approve all gates)
      const { initOpsState, getOpsState, broadcastOpsUpdate, addLog, persistOpsStateNow } = await import('../lib/engagement-orchestrator');
      let state = getOpsState(engagementId);
      if (!state) state = initOpsState(engagementId, input.engagementType);

      // Enable training lab mode — auto-approves ALL approval gates including red tier
      state.trainingLabMode = true;

      // Auto-sign the RoE for training lab targets
      state.roeScopeGuard = {
        authorizedDomains: [input.target],
        authorizedIps: [],
        roeStatus: 'signed',
        signedBy: ctx.user.name || 'Training Lab Auto-Runner',
        signedAt: Date.now(),
      };

      // Pre-populate the asset
      state.assets.push({
        hostname: input.target,
        type: 'web_server',
        ports: [],
        vulns: [],
        zapFindings: [],
        exploitAttempts: [],
        toolResults: [],
        status: 'pending',
        technologies: [],
      });

      state.isRunning = true;
      state.phase = 'recon';
      state.startedAt = Date.now();

      addLog(state, {
        phase: 'recon',
        type: 'phase_complete',
        title: `\uD83C\uDFAF Training Lab Launched: ${labProfile.name}`,
        detail: `Full auto-run pipeline started for ${input.target} in ${input.scanMode} mode. All approval gates auto-approved. Expected vulns: ${labProfile.expectedVulns.join(', ') || 'unknown'}.`,
      });

      broadcastOpsUpdate(engagementId, { type: 'phase_change', phase: 'recon' });
      await persistOpsStateNow(engagementId);

      // 4. Auto-execute the full pipeline (like batchTrainingRun does)
      // The pipeline is initialized with trainingLabMode=true and RoE signed.
      // Auto-run the full pipeline instead of waiting for manual trigger.
      await persistOpsStateNow(engagementId);

      addLog(state, {
        phase: 'recon',
        type: 'info',
        title: '\u2705 Training Lab Auto-Executing',
        detail: `Full pipeline auto-started for ${input.target} in ${input.scanMode} mode. All approval gates auto-approved.`,
      });

      // Fire-and-forget: launch the full pipeline execution
      const { executeEngagement } = await import('../lib/engagement-orchestrator');
      executeEngagement(
        engagementId,
        { id: ctx.user.id, name: ctx.user.name || ctx.user.username },
        { startPhase: 'recon', scanProfile: 'standard' },
      ).catch((err: any) => {
        console.error(`[LaunchTrainingLab] Pipeline execution error for #${engagementId}:`, err.message);
      });

      return {
        engagementId,
        pipelineId,
        target: input.target,
        labProfile: labProfile.name,
        scanMode: input.scanMode,
        message: `Training lab engagement launched for ${labProfile.name}. Full pipeline running in ${input.scanMode} mode with all approval gates auto-approved.`,
      };
    }),

  /**
   * Batch Training Run — creates multiple lab engagements and auto-executes the full pipeline.
   * Each engagement runs recon → scan → vuln analysis → exploitation → post-exploit.
   * Injects DFIR knowledge context so the LLM can demonstrate learned intelligence.
   * After all engagements complete, triggers graduation engine evaluation.
   */
  batchTrainingRun: protectedProcedure
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
    .mutation(async ({ input, ctx }) => {
      const dbConn = await getDbSafe();
      const TRAINING_LABS: Record<string, { name: string; description: string; expectedVulns: string[] }> = {
        'demo.testfire.net': {
          name: 'Altoro Mutual (IBM AppScan)',
          description: 'Intentionally vulnerable banking application with SQL injection, XSS, authentication bypass, and session management flaws.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'XSS - Stored', 'Authentication Bypass', 'Session Fixation', 'Insecure Direct Object Reference', 'Path Traversal'],
        },
        'zero.webappsecurity.com': {
          name: 'Zero Bank (Micro Focus)',
          description: 'Intentionally vulnerable banking application with SQL injection, XSS, CSRF, and broken authentication.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'CSRF', 'Broken Authentication', 'Insecure Direct Object Reference'],
        },
        'testphp.vulnweb.com': {
          name: 'Acunetix Test PHP',
          description: 'PHP-based vulnerable web application with SQL injection, XSS, file inclusion, and command injection.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'XSS - Stored', 'File Inclusion', 'Command Injection', 'Directory Traversal', 'File Upload'],
        },
        'dvwa.co.uk': {
          name: 'DVWA (Damn Vulnerable Web Application)',
          description: 'Classic training lab with 14 vulnerability exercises.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'XSS - Stored', 'Command Injection', 'CSRF', 'File Upload', 'File Inclusion', 'Brute Force'],
        },
        'ginandjuice.shop': {
          name: 'Gin & Juice Shop (PortSwigger)',
          description: 'PortSwigger\'s intentionally vulnerable e-commerce application.',
          expectedVulns: ['XSS', 'SQL Injection', 'SSRF', 'XXE', 'OS Command Injection', 'Path Traversal', 'Access Control'],
        },
        'brokencrystals.com': {
          name: 'Broken Crystals (NeuraLegion)',
          description: 'Modern Node.js/React benchmark app with 30+ vuln classes: JWT bypass, prototype pollution, GraphQL introspection, SSTI, SSRF, LDAP injection, OS command injection.',
          expectedVulns: ['JWT Bypass', 'SQL Injection', 'XSS', 'SSRF', 'SSTI', 'CSRF', 'IDOR', 'XXE', 'LDAP Injection', 'OS Command Injection', 'Prototype Pollution', 'GraphQL Introspection', 'File Upload', 'Mass Assignment', 'Default Login', 'Insecure Deserialization'],
        },
        'brokencrystals.lab.aceofcloud.io': {
          name: 'Broken Crystals (AceOfCloud Lab)',
          description: 'Self-hosted Broken Crystals instance with 30+ vuln classes: JWT bypass (kid-sql, jku, jwk, x5c, x5u, hmac, weak-key), prototype pollution, GraphQL introspection, SSTI, SSRF, LDAP injection, OS command injection, Keycloak OIDC, gRPC, and AI chat.',
          expectedVulns: ['JWT Bypass', 'SQL Injection', 'XSS', 'SSRF', 'SSTI', 'CSRF', 'IDOR', 'XXE', 'LDAP Injection', 'OS Command Injection', 'Prototype Pollution', 'GraphQL Introspection', 'File Upload', 'Mass Assignment', 'Default Login', 'Email Header Injection', 'HTTP Method Tampering', 'Unvalidated Redirect', 'Cookie Security', 'Header Security', 'Full Path Disclosure', 'Version Control', 'Business Constraint Bypass', 'Date Manipulation', 'ID Enumeration', 'Brute Force', 'Open Database', 'Secret Tokens', 'Common Files', 'HTML Injection'],
        },
        'hackazon.webscantest.com': {
          name: 'Hackazon (Rapid7)',
          description: 'Modern vulnerable web application mimicking an e-commerce site.',
          expectedVulns: ['SQL Injection', 'XSS', 'CSRF', 'Command Injection', 'File Upload', 'Authentication Bypass'],
        },
        'dvwa.aceofcloud.io': {
          name: 'DVWA (AceOfCloud Lab)',
          description: 'Self-hosted DVWA instance for internal training.',
          expectedVulns: ['SQL Injection', 'XSS', 'Command Injection', 'CSRF', 'File Upload', 'File Inclusion'],
        },
        'juiceshop.lab.aceofcloud.io': {
          name: 'OWASP Juice Shop (AceOfCloud Lab)',
          description: 'Self-hosted OWASP Juice Shop instance with 42+ vulnerability challenges including SQL injection, XSS, SSTI, XXE, SSRF, NoSQL injection, and broken authentication.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'XSS - Stored', 'XSS - DOM', 'NoSQL Injection', 'SSTI', 'XXE', 'SSRF', 'Broken Authentication', 'CSRF', 'Directory Traversal', 'Sensitive Data Exposure', 'Unvalidated Redirect'],
        },
        'bwapp.lab.aceofcloud.io': {
          name: 'bWAPP (AceOfCloud Lab)',
          description: 'Self-hosted bWAPP instance with 100+ vulnerability exercises including SQL injection, XSS, OS command injection, PHP code injection, XXE, SSRF, and Shellshock.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'XSS - Stored', 'OS Command Injection', 'PHP Code Injection', 'SSI Injection', 'XXE', 'SSRF', 'CSRF', 'File Upload', 'File Inclusion', 'Directory Traversal', 'Shellshock', 'LDAP Injection'],
        },
        'mutillidae.lab.aceofcloud.io': {
          name: 'Mutillidae (AceOfCloud Lab)',
          description: 'Self-hosted Mutillidae II instance with OWASP Top 10 vulnerability exercises including SQL injection, XSS, XXE, file inclusion, command injection, and log injection.',
          expectedVulns: ['SQL Injection', 'XSS - Reflected', 'XSS - Stored', 'XSS - DOM', 'Command Injection', 'XXE', 'File Inclusion', 'Directory Traversal', 'CSRF', 'Clickjacking', 'Log Injection', 'HTTP Parameter Pollution'],
        },
        'crapi.lab.aceofcloud.io': {
          name: 'crAPI (AceOfCloud Lab)',
          description: 'Self-hosted crAPI (Completely Ridiculous API) instance for testing API-specific vulnerabilities including BOLA, mass assignment, rate limiting bypass, SSRF, and broken authentication.',
          expectedVulns: ['BOLA', 'Mass Assignment', 'Excessive Data Exposure', 'Rate Limiting Bypass', 'SSRF', 'Broken Authentication', 'SQL Injection', 'NoSQL Injection', 'JWT Vulnerabilities', 'IDOR'],
        },
      };

      // ─── Gather DFIR knowledge for LLM context injection ───
      let dfirKnowledgeContext: any[] = [];
      if (input.injectDfirKnowledge) {
        try {
          const { dfirReports: dfirTable } = await import('../../drizzle/schema');
          const reports = await dbConn.select({
            title: dfirTable.title,
            threatActors: dfirTable.threatActors,
            malwareFamilies: dfirTable.malwareFamilies,
            mitreAttackTechniques: dfirTable.mitreAttackTechniques,
            killChainPhases: dfirTable.killChainPhases,
            summary: dfirTable.summary,
          }).from(dfirTable)
            .where(eq(dfirTable.status, 'enriched'))
            .limit(20);
          dfirKnowledgeContext = reports.map(r => ({
            title: r.title,
            threatActors: r.threatActors || [],
            malware: r.malwareFamilies || [],
            techniques: (r.mitreAttackTechniques || []).map((t: any) => `${t.techniqueId}: ${t.name}`),
            killChain: r.killChainPhases || [],
            summary: (r.summary || '').slice(0, 500),
          }));
        } catch { /* DFIR table may be empty */ }
      }

      const results: Array<{
        engagementId: number;
        pipelineId: number;
        target: string;
        labName: string;
        status: string;
      }> = [];

      for (const target of input.targets) {
        const labProfile = TRAINING_LABS[target.domain.toLowerCase()] || {
          name: `Training Lab: ${target.domain}`,
          description: `Custom training lab target: ${target.domain}`,
          expectedVulns: [],
        };
        const engagementName = target.name || `${labProfile.name} - Batch Training ${new Date().toISOString().slice(0, 10)}`;

        try {
          // 1. Create engagement
          const engagementId = await createEngagement({
            name: engagementName,
            customerName: 'Training Lab (Authorized)',
            engagementType: target.engagementType,
            status: 'active',
            targetDomain: target.domain,
            targetIpRange: null,
            createdBy: ctx.user.id,
            scanMode: input.scanMode === 'active' ? 'active' : input.scanMode === 'standard' ? 'standard' : 'strict_passive',
            roeStatus: 'signed',
            roeSignedDate: new Date(),
            notes: JSON.stringify({
              trainingLab: true,
              batchRun: true,
              labProfile: labProfile.name,
              expectedVulns: labProfile.expectedVulns,
              description: labProfile.description,
              scanMode: input.scanMode,
              scanProfile: target.scanProfile,
              autoApproveAll: true,
              dfirKnowledgeInjected: dfirKnowledgeContext.length > 0,
              dfirReportsCount: dfirKnowledgeContext.length,
              launchedAt: new Date().toISOString(),
            }),
          });

          // 2. Create pipeline
          const pipelineId = await createEngagementPipeline({
            userId: ctx.user.id,
            name: `${engagementName} - Auto Pipeline`,
            status: 'intel_scan',
            targetDomains: [target.domain],
            clientType: target.engagementType,
            orgProfile: {
              riskLevel: 'high',
              trainingLab: true,
              expectedVulns: labProfile.expectedVulns,
              dfirKnowledge: dfirKnowledgeContext.slice(0, 5),
            },
            recommendedActors: [],
            engagementId,
            currentStep: 1,
            totalSteps: 6,
            stepLog: [{
              step: 1,
              status: 'completed',
              message: `Batch training engagement created for ${labProfile.name}. Auto-execute: ${input.autoExecute}.`,
              timestamp: new Date().toISOString(),
            }],
          });

          // 3. Initialize ops state with training lab mode
          const { initOpsState, getOpsState, addLog, persistOpsStateNow, executeEngagement } = await import('../lib/engagement-orchestrator');
          let state = getOpsState(engagementId);
          if (!state) state = initOpsState(engagementId, target.engagementType);
          state.trainingLabMode = true;
          (state as any).dfirKnowledgeContext = dfirKnowledgeContext;
          state.roeScopeGuard = {
            authorizedDomains: [target.domain],
            authorizedIps: [],
            roeStatus: 'signed',
            signedBy: ctx.user.name || 'Batch Training Runner',
            signedAt: Date.now(),
          };
          state.assets.push({
            hostname: target.domain,
            type: 'web_server',
            ports: [],
            vulns: [],
            zapFindings: [],
            exploitAttempts: [],
            toolResults: [],
            status: 'pending',
            technologies: [],
          });

          addLog(state, {
            phase: 'recon', type: 'info',
            title: `\uD83C\uDFAF Batch Training: ${labProfile.name}`,
            detail: `Target: ${target.domain} | Profile: ${target.scanProfile} | DFIR knowledge: ${dfirKnowledgeContext.length} reports injected | Expected vulns: ${labProfile.expectedVulns.length}`,
          });

          if (dfirKnowledgeContext.length > 0) {
            const techniques = dfirKnowledgeContext.flatMap(d => d.techniques || []).slice(0, 10);
            addLog(state, {
              phase: 'recon', type: 'info',
              title: '\uD83D\uDCDA DFIR Knowledge Injected',
              detail: `${dfirKnowledgeContext.length} DFIR reports loaded. Techniques to watch: ${techniques.join(', ') || 'none'}. Threat actors: ${dfirKnowledgeContext.flatMap(d => d.threatActors || []).filter((v: string, i: number, a: string[]) => a.indexOf(v) === i).join(', ') || 'none'}.`,
            });
          }

          await persistOpsStateNow(engagementId);

          // 4. Auto-execute if requested
          if (input.autoExecute) {
            executeEngagement(engagementId, { id: String(ctx.user.id), name: ctx.user.name || undefined }, {
              scanProfile: target.scanProfile,
            }).catch(async (err: any) => {
              console.error(`[BatchTraining] Engagement #${engagementId} crashed:`, err.message);
              const { addLog: addOpsLog, persistOpsStateNow: persist } = await import('../lib/engagement-orchestrator');
              const s = getOpsState(engagementId);
              if (s) {
                s.isRunning = false;
                s.phase = 'error' as any;
                s.error = err.message;
                addOpsLog(s, { phase: 'recon', type: 'error', title: '\u274c Batch Training Failed', detail: err.message });
                await persist(engagementId).catch(() => {});
              }
            });
          }

          results.push({
            engagementId,
            pipelineId,
            target: target.domain,
            labName: labProfile.name,
            status: input.autoExecute ? 'executing' : 'ready',
          });
        } catch (err: any) {
          results.push({
            engagementId: 0,
            pipelineId: 0,
            target: target.domain,
            labName: labProfile.name,
            status: `error: ${err.message}`,
          });
        }
      }

      // Log the batch run
      await db.logActivity({
        userId: ctx.user.id,
        action: 'batch_training_run',
        details: `Launched ${results.filter(r => r.status !== 'error').length}/${input.targets.length} training engagements. Auto-execute: ${input.autoExecute}. DFIR knowledge: ${dfirKnowledgeContext.length} reports.`,
      });

      return {
        launched: results.filter(r => r.engagementId > 0).length,
        failed: results.filter(r => r.engagementId === 0).length,
        engagements: results,
        dfirKnowledgeInjected: dfirKnowledgeContext.length,
        runGraduationAfter: input.runGraduationAfter,
        message: `Batch training run: ${results.filter(r => r.engagementId > 0).length} engagements launched across ${input.targets.length} targets.`,
      };
    }),

  /**
   * Get batch training run status — checks all active training lab engagements
   */
  getBatchTrainingStatus: protectedProcedure
    .query(async () => {
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
      });

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
});
