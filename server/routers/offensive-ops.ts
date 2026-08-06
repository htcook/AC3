/**
 * Offensive Operations Router
 * 
 * Integrates:
 * 1. Automated Attack Chain Synthesis
 * 2. Universal Exploit Validation Feedback Loop
 * 3. Predictive Vulnerability Targeting
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  synthesizeAttackChain,
  synthesizeChainVariants,
  getAvailableTechniques,
  type ClientEnvironment,
  type SynthesisOptions,
} from "../lib/attack-chain-synthesis";
import {
  startValidationSession,
  getValidationSessions,
  getRegisteredAdapters,
  type TechType,
  type ValidationTarget,
} from "../lib/exploit-validation-engine";
import {
  predictVulnerabilityTargeting,
  getAllCampaignMomentum,
  predictSingleCve,
  predictActorForTechStack,
  generatePredictiveLandscape,
} from "../lib/predictive-vuln-targeting";
import {
  processValidationResult,
  batchProcessValidations,
  getValidationSummary,
  getValidationSummaries,
  getValidationHistory,
  getExploitsByValidationStatus,
  getValidationTrend,
  getGlobalValidationStats,
  getExploitsNeedingRevalidation,
  onValidationComplete,
  type ArsenalValidationStatus,
} from "../lib/validation-arsenal-bridge";

export const offensiveOpsRouter = router({
  // ─── Attack Chain Synthesis ──────────────────────────────────────────────────

  synthesizeChain: protectedProcedure
    .input(z.object({
      environment: z.object({
        clientId: z.string().optional(),
        targetSectors: z.array(z.string()),
        technologies: z.array(z.string()),
        networkSegments: z.array(z.object({
          name: z.string(),
          technologies: z.array(z.string()),
          connectivity: z.enum(["internet_facing", "dmz", "internal", "air_gapped"]),
        })),
        knownVulnerabilities: z.array(z.object({
          cve: z.string(),
          product: z.string(),
          segment: z.string(),
        })).optional(),
        securityControls: z.array(z.string()).optional(),
      }),
      constraints: z.object({
        maxSteps: z.number().min(2).max(20).default(8),
        stealthRequired: z.boolean().default(false),
        targetObjective: z.enum(["data_exfil", "disruption", "persistence", "lateral_movement", "privilege_escalation", "full_compromise"]).default("full_compromise"),
        actorEmulation: z.string().optional(),
      }).optional(),
    }))
    .mutation(async ({ input }) => {
      const environment: ClientEnvironment = {
        engagementId: `eng_${Date.now()}`,
        clientName: input.environment.clientId || "target",
        discoveredAssets: input.environment.technologies.map((tech, i) => ({
          id: `asset_${i}`,
          type: tech.includes("plc") ? "plc" as const : tech.includes("web") ? "web_app" as const : "endpoint" as const,
          vendor: tech,
          networkSegment: input.environment.networkSegments[0]?.name || "default",
        })),
        discoveredVulnerabilities: input.environment.knownVulnerabilities?.map((v, i) => ({
          id: `vuln_${i}`,
          cve: v.cve,
          assetId: `asset_0`,
          severity: "high" as const,
          exploitAvailable: true,
        })) || [],
        networkTopology: input.environment.networkSegments.map(seg => ({
          id: seg.name.toLowerCase().replace(/\s+/g, "_"),
          name: seg.name,
          connectivity: seg.connectivity,
          assets: [],
        })),
        securityControls: (input.environment.securityControls || []).map((c, i) => ({
          id: `ctrl_${i}`,
          type: c,
          coverage: "partial" as const,
        })),
      };

      const options: SynthesisOptions = {
        targetObjective: (input.constraints?.targetObjective === "data_exfil" ? "data_exfiltration" : input.constraints?.targetObjective === "disruption" ? "process_disruption" : "sabotage") as any,
        maxSteps: input.constraints?.maxSteps || 8,
        preferredActorStyle: input.constraints?.actorEmulation,
        avoidDetection: input.constraints?.stealthRequired,
        includeAlternatives: true,
        evidenceComprehensiveness: "forensic_grade",
      };

      const chain = synthesizeAttackChain(environment, options);
      return chain;
    }),

  getChainVariants: protectedProcedure
    .input(z.object({
      environment: z.object({
        targetSectors: z.array(z.string()),
        technologies: z.array(z.string()),
        networkSegments: z.array(z.object({
          name: z.string(),
          technologies: z.array(z.string()),
          connectivity: z.enum(["internet_facing", "dmz", "internal", "air_gapped"]),
        })),
      }),
      variantCount: z.number().min(1).max(5).default(3),
    }))
    .mutation(async ({ input }) => {
      const environment: ClientEnvironment = {
        engagementId: `eng_${Date.now()}`,
        clientName: "target",
        discoveredAssets: input.environment.technologies.map((tech, i) => ({
          id: `asset_${i}`,
          type: "endpoint" as const,
          vendor: tech,
          networkSegment: input.environment.networkSegments[0]?.name || "default",
        })),
        discoveredVulnerabilities: [],
        networkTopology: input.environment.networkSegments.map(seg => ({
          id: seg.name.toLowerCase().replace(/\s+/g, "_"),
          name: seg.name,
          connectivity: seg.connectivity,
          assets: [],
        })),
        securityControls: [],
      };

      const options: SynthesisOptions = {
        targetObjective: "sabotage",
        maxSteps: 8,
        includeAlternatives: true,
        evidenceComprehensiveness: "forensic_grade",
      };

      const variants = synthesizeChainVariants(environment, options, input.variantCount);
      return variants;
    }),

  listAvailableTechniques: protectedProcedure
    .query(async () => {
      return getAvailableTechniques();
    }),

  // ─── Exploit Validation Feedback Loop ────────────────────────────────────────

  executeValidation: protectedProcedure
    .input(z.object({
      exploitId: z.string(),
      targetHost: z.string(),
      targetPort: z.number().optional(),
      techType: z.enum(["plc_ics", "web_application", "network_infrastructure", "cloud_saas", "active_directory", "endpoint", "iot_embedded", "mobile"]),
      protocol: z.string().optional(),
      credentials: z.object({
        username: z.string().optional(),
        password: z.string().optional(),
        token: z.string().optional(),
      }).optional(),
      validationMode: z.enum(["passive", "active", "destructive"]).default("active"),
      captureEvidence: z.boolean().default(true),
      evidenceTypes: z.array(z.enum([
        "packet_capture", "register_snapshot", "http_response", "process_tree",
        "memory_dump", "api_response", "ldap_state", "firmware_hash",
        "network_traffic", "file_system_changes", "screenshot", "log_entries"
      ])).optional(),
      timeout: z.number().min(5000).max(300000).default(30000),
    }))
    .mutation(async ({ input }) => {
      const target: ValidationTarget = {
        id: `tgt_${Date.now()}`,
        host: input.targetHost,
        port: input.targetPort || 0,
        protocol: input.protocol || "tcp",
      };

      const session = await startValidationSession(
        input.exploitId,
        input.exploitId, // use exploitId as name fallback
        input.techType as TechType,
        target,
        { timeoutMs: input.timeout, evidenceLevel: input.captureEvidence ? "forensic_grade" : "minimal" }
      );
      return session;
    }),

  getValidationHistory: protectedProcedure
    .input(z.object({
      exploitId: z.string().optional(),
      techType: z.string().optional(),
      status: z.enum(["confirmed", "failed", "partial", "crashed", "timeout"]).optional(),
      limit: z.number().min(1).max(100).default(50),
    }))
    .query(async ({ input }) => {
      const sessions = getValidationSessions();
      let filtered = sessions;
      if (input.exploitId) filtered = filtered.filter(s => s.exploitId === input.exploitId);
      if (input.techType) filtered = filtered.filter(s => s.target.techType === input.techType);
      if (input.status) filtered = filtered.filter(s => s.result === input.status);
      return filtered.slice(0, input.limit).map(s => ({
        exploitId: s.exploitId,
        target: `${s.target.host}:${s.target.port}`,
        status: s.result || 'pending',
        evidence: s.evidence || [],
        timestamp: s.startedAt,
      }));
    }),

  getAdapters: protectedProcedure
    .query(async () => {
      return getRegisteredAdapters().map(a => ({
        techType: a.techType,
        name: a.name,
        description: a.description,
        status: 'active',
      }));
    }),

  // ─── Predictive Vulnerability Targeting ──────────────────────────────────────

  predictTargets: protectedProcedure
    .input(z.object({
      candidates: z.array(z.object({
        cve: z.string(),
        cvssScore: z.number(),
        vendor: z.string(),
        product: z.string(),
        techType: z.string(),
        affectedSectors: z.array(z.string()),
        internetFacing: z.boolean(),
        hasDefaultCreds: z.boolean(),
        noAuthRequired: z.boolean(),
        isRce: z.boolean(),
        deploymentScale: z.number().min(1).max(10),
        complexity: z.enum(["low", "medium", "high"]),
        publicPocExists: z.boolean(),
        knownExploited: z.boolean(),
        mediaAttention: z.boolean(),
        avgPatchDays: z.number(),
        chainable: z.boolean(),
        disclosureDate: z.number(),
      })),
      actorFilter: z.array(z.string()).optional(),
      sectorFilter: z.array(z.string()).optional(),
      minProbability: z.number().min(0).max(100).optional(),
    }))
    .mutation(async ({ input }) => {
      return predictVulnerabilityTargeting(input.candidates, {
        actorFilter: input.actorFilter,
        sectorFilter: input.sectorFilter,
        minProbability: input.minProbability,
      });
    }),

  predictSingleCve: protectedProcedure
    .input(z.object({
      cve: z.string(),
      cvssScore: z.number(),
      vendor: z.string(),
      product: z.string(),
      techType: z.string(),
      affectedSectors: z.array(z.string()),
      internetFacing: z.boolean(),
      hasDefaultCreds: z.boolean(),
      noAuthRequired: z.boolean(),
      isRce: z.boolean(),
      deploymentScale: z.number().min(1).max(10),
      complexity: z.enum(["low", "medium", "high"]),
      publicPocExists: z.boolean(),
      knownExploited: z.boolean(),
      mediaAttention: z.boolean(),
      avgPatchDays: z.number(),
      chainable: z.boolean(),
      disclosureDate: z.number(),
    }))
    .query(async ({ input }) => {
      return predictSingleCve(input);
    }),

  getCampaignMomentum: protectedProcedure
    .query(async () => {
      return getAllCampaignMomentum();
    }),

  predictActorForStack: protectedProcedure
    .input(z.object({
      technologies: z.array(z.string()),
      sectors: z.array(z.string()),
    }))
    .query(async ({ input }) => {
      return predictActorForTechStack(input.technologies, input.sectors);
    }),

  getPredictiveLandscape: protectedProcedure
    .query(async () => {
      return generatePredictiveLandscape();
    }),

  // ─── Validation → Arsenal Feedback Bridge ────────────────────────────────────

  getArsenalValidationStats: protectedProcedure
    .query(async () => {
      return getGlobalValidationStats();
    }),

  getExploitValidationSummary: protectedProcedure
    .input(z.object({ exploitScriptId: z.number() }))
    .query(async ({ input }) => {
      return getValidationSummary(input.exploitScriptId);
    }),

  getExploitValidationHistory: protectedProcedure
    .input(z.object({ exploitScriptId: z.number() }))
    .query(async ({ input }) => {
      return getValidationHistory(input.exploitScriptId);
    }),

  getExploitValidationTrend: protectedProcedure
    .input(z.object({ exploitScriptId: z.number(), periodDays: z.number().default(30) }))
    .query(async ({ input }) => {
      return getValidationTrend(input.exploitScriptId, input.periodDays);
    }),

  getExploitsByStatus: protectedProcedure
    .input(z.object({ status: z.enum(["confirmed_working", "partial_success", "failed", "untested", "mixed"]) }))
    .query(async ({ input }) => {
      return getExploitsByValidationStatus(input.status as ArsenalValidationStatus);
    }),

  getExploitsNeedingRevalidation: protectedProcedure
    .input(z.object({ staleDays: z.number().default(30) }))
    .query(async ({ input }) => {
      return getExploitsNeedingRevalidation(input.staleDays);
    }),

  getBulkValidationSummaries: protectedProcedure
    .input(z.object({ exploitScriptIds: z.array(z.number()) }))
    .query(async ({ input }) => {
      const summaries = getValidationSummaries(input.exploitScriptIds);
      return Object.fromEntries(summaries);
    }),

  // ─── Impacket atexec Lateral Movement Endpoints ─────────────────────────────
  getAtexecPlaybook: protectedProcedure
    .query(async () => {
      const { ATEXEC_PLAYBOOK_ENTRIES, ATEXEC_EXPLOIT_DOCUMENTS } = await import("../lib/impacket-atexec-playbook");
      return {
        authMethods: ATEXEC_PLAYBOOK_ENTRIES.map(entry => ({
          id: entry.id,
          name: entry.name,
          authMethod: entry.authMethod,
          description: entry.description,
          commandTemplate: entry.commandTemplate,
          prerequisites: entry.prerequisites,
          iocCount: entry.iocs.length,
          detectionRules: entry.detectionRules?.length || 0,
        })),
        exploitDocuments: ATEXEC_EXPLOIT_DOCUMENTS.map(doc => ({
          id: doc.id,
          title: doc.title,
          description: doc.description,
          mitreAttackId: doc.mitreAttackId,
          platform: doc.platform,
          language: doc.language,
          successRate: doc.successRate,
          timesDeployed: doc.timesDeployed,
          lastDeployed: doc.lastDeployed,
        })),
        totalVariants: ATEXEC_PLAYBOOK_ENTRIES.length,
        technique: "T1053.005",
        tool: "impacket-atexec",
        mitreTactic: "Lateral Movement",
      };
    }),

  getAtexecValidationChecks: protectedProcedure
    .query(async () => {
      const { ATEXEC_VALIDATION_CHECKS } = await import("../lib/impacket-atexec-playbook");
      return {
        checks: ATEXEC_VALIDATION_CHECKS.map(check => ({
          id: check.id,
          name: check.name,
          description: check.description,
          expectedEvidence: check.expectedEvidence,
          confirmationCriteria: check.confirmationCriteria,
          failureIndicators: check.failureIndicators,
        })),
        totalChecks: ATEXEC_VALIDATION_CHECKS.length,
      };
    }),

  getAtexecDetectionRules: protectedProcedure
    .query(async () => {
      const { ATEXEC_DETECTION_RULES } = await import("../lib/impacket-atexec-playbook");
      return {
        rules: ATEXEC_DETECTION_RULES.map(rule => ({
          id: rule.id,
          name: rule.name,
          type: rule.type,
          description: rule.description,
          content: rule.content,
        })),
        totalRules: ATEXEC_DETECTION_RULES.length,
      };
    }),
});
