/**
 * Ability Graph Router
 * tRPC procedures for creating, managing, and simulating ability graphs.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import {
  createGraph,
  getGraph,
  listGraphs,
  deleteGraph,
  updateGraphStatus,
  updateNodeStatus,
  getGraphStats,
  generateGraphFromTtpChain,
  decomposeTechniquesToGraph,
  walkGraph,
  topologicalSort,
  assignLayers,
  filterNodesBySafetyTier,
  computeGraphSafetyTier,
  type AbilityNodeData,
  type AbilityEdgeData,
  type EnvironmentContext,
  type SafetyTier,
  type NodeStatus,
  type EdgeCondition,
} from "../lib/ability-graph-engine";
import type { ScanMode } from "../lib/scan-policy-engine";
import {
  getC2Registry,
  type C2FrameworkType,
} from "../lib/c2-abstraction";
import {
  processExecutionFeedback,
  getLearningStats,
  getExecutionHistory,
  calculateTechniqueReliability,
} from "../lib/c2-learning-engine";
import {
  matchExploitsToScan,
  llmRecommendExploits,
  generateTargetedGraph,
} from "../lib/exploit-asset-matcher";
import {
  executeGraph,
  abortExecution,
  pauseExecution,
  resumeExecution,
  getExecutionState,
  getExecutionLog,
  getCalderaAgents,
  buildEnvironmentFromAgent,
  type ExecutionConfig,
} from "../lib/caldera-graph-executor";
import {
  generateGraphFromActorProfile,
  getAvailableActorTemplates,
} from "../lib/actor-graph-templates";
import {
  compareGraphs,
  computeOverlapMatrix,
} from "../lib/graph-diff-engine";
import {
  createOrchestrationPlan,
  executeOrchestrationPlan,
  getOrchestrationPlan,
  listOrchestrationPlans,
  abortOrchestrationPlan,
  getOrchestrationStats,
  type OrchestrationPlan,
} from "../lib/c2-orchestrator";
import {
  generateModuleCode,
  generateDynamicModules,
  buildModule,
  pushModulesToC2,
  getModuleTemplates,
  type ModuleSpec,
  type GeneratedModule,
} from "../lib/c2-module-builder";
import {
  runIntelligenceCrawl,
  runTargetedEnrichment,
  analyzeDataGaps,
  getCrawlerStats,
  getCrawlHistory,
  getCrawlSources,
  toggleCrawlSource,
  isCrawlRunning,
} from "../lib/threat-actor-crawler";
import {
  startScheduler,
  stopScheduler,
  pauseScheduler,
  resumeScheduler,
  updateSchedulerConfig,
  getSchedulerStatus,
  getSchedulePresets,
  enqueueJob,
  cancelJob,
  forceRunJob,
  getJobHistory,
  getQueueStatus,
  type SchedulePreset,
  type JobType,
  type JobPriority,
} from "../lib/crawler-scheduler";
import {
  generateComplianceReport,
  listKeys as listFipsKeys,
  generateKey as generateFipsKey,
  rotateKey as rotateFipsKey,
  revokeKey as revokeFipsKey,
  getAuditLog as getFipsAuditLog,
  getAlgorithmUsageStats,
  validateOperation,
  getKeysNeedingRotation,
  isAlgorithmApproved,
} from "../lib/fips-compliance";

// ─── Input schemas ──────────────────────────────────────────────────────

const preconditionSchema = z.object({
  type: z.enum(["os", "privilege", "network", "software", "file", "service", "registry", "custom"]),
  key: z.string(),
  operator: z.enum(["eq", "neq", "in", "not_in", "exists", "gt", "lt", "contains", "regex"]),
  value: z.union([z.string(), z.array(z.string()), z.number(), z.boolean()]),
  description: z.string(),
  required: z.boolean(),
});

const exitCriteriaSchema = z.object({
  type: z.enum(["output_contains", "exit_code", "file_exists", "process_running", "custom"]),
  key: z.string(),
  operator: z.enum(["eq", "neq", "contains", "regex", "gt", "lt"]),
  value: z.union([z.string(), z.number(), z.boolean()]),
  description: z.string(),
});

const nodeInputSchema = z.object({
  label: z.string(),
  description: z.string().default(""),
  techniqueId: z.string(),
  techniqueName: z.string(),
  tactic: z.string(),
  calderaAbilityId: z.string().optional(),
  executor: z.string().optional(),
  platform: z.string().optional(),
  command: z.string().optional(),
  cleanupCommand: z.string().optional(),
  preconditions: z.array(preconditionSchema).default([]),
  exitCriteria: z.array(exitCriteriaSchema).default([]),
  safetyTier: z.enum(["passive", "low_impact", "medium_impact", "high_impact", "critical_impact"]).default("medium_impact"),
  timeout: z.number().default(300),
  retryCount: z.number().default(1),
});

const edgeInputSchema = z.object({
  sourceNodeIndex: z.number(),
  targetNodeIndex: z.number(),
  condition: z.enum(["always", "on_success", "on_failure", "on_output_match", "on_precondition", "conditional"]).default("on_success"),
  conditionExpression: z.string().optional(),
  outputMatchPattern: z.string().optional(),
  weight: z.number().default(1),
  label: z.string().optional(),
});

const environmentContextSchema = z.object({
  os: z.string(),
  osVersion: z.string().optional(),
  hostname: z.string().optional(),
  privilegeLevel: z.string(),
  networkAccess: z.string(),
  installedSoftware: z.array(z.string()).default([]),
  runningServices: z.array(z.string()).default([]),
  openPorts: z.array(z.number()).default([]),
  registryKeys: z.array(z.string()).optional(),
  files: z.array(z.string()).optional(),
  customFacts: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).default({}),
});

// ─── Router ─────────────────────────────────────────────────────────────

export const abilityGraphRouter = router({
  // ─── List graphs ───
  list: protectedProcedure
    .input(z.object({
      status: z.string().optional(),
      sourceType: z.string().optional(),
      limit: z.number().min(1).max(100).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      return listGraphs({
        status: input?.status,
        sourceType: input?.sourceType,
        limit: input?.limit,
        offset: input?.offset,
      });
    }),

  // ─── Get single graph with nodes and edges ───
  get: protectedProcedure
    .input(z.object({ graphId: z.string() }))
    .query(async ({ input }) => {
      const result = await getGraph(input.graphId);
      if (!result) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Graph not found" });
      }
      return result;
    }),

  // ─── Create graph manually ───
  create: protectedProcedure
    .input(z.object({
      name: z.string(),
      description: z.string().default(""),
      sourceType: z.enum(["manual", "technique_chain", "actor_profile", "incident_report", "playbook"]).default("manual"),
      sourceId: z.string().optional(),
      actorName: z.string().optional(),
      scanMode: z.enum(["passive", "active-low", "active-standard", "active-aggressive"]).optional(),
      nodes: z.array(nodeInputSchema),
      edges: z.array(edgeInputSchema),
    }))
    .mutation(async ({ input, ctx }) => {
      // Generate IDs for nodes
      const nodeIdPrefix = `agn-${Date.now().toString(36)}`;
      const nodes: AbilityNodeData[] = input.nodes.map((n, idx) => ({
        id: `${nodeIdPrefix}-${idx}`,
        graphId: "",
        label: n.label,
        description: n.description,
        techniqueId: n.techniqueId,
        techniqueName: n.techniqueName,
        tactic: n.tactic,
        calderaAbilityId: n.calderaAbilityId,
        executor: n.executor,
        platform: n.platform,
        command: n.command,
        cleanupCommand: n.cleanupCommand,
        preconditions: n.preconditions,
        exitCriteria: n.exitCriteria,
        safetyTier: n.safetyTier as SafetyTier,
        timeout: n.timeout,
        retryCount: n.retryCount,
        status: "pending" as NodeStatus,
        order: idx,
        layer: 0,
      }));

      // Build edges using node indices
      const edgeIdPrefix = `age-${Date.now().toString(36)}`;
      const edges: AbilityEdgeData[] = input.edges.map((e, idx) => ({
        id: `${edgeIdPrefix}-${idx}`,
        graphId: "",
        sourceNodeId: nodes[e.sourceNodeIndex]?.id || nodes[0]?.id || "",
        targetNodeId: nodes[e.targetNodeIndex]?.id || nodes[nodes.length - 1]?.id || "",
        condition: e.condition as EdgeCondition,
        conditionExpression: e.conditionExpression,
        outputMatchPattern: e.outputMatchPattern,
        weight: e.weight,
        label: e.label,
      }));

      return createGraph({
        name: input.name,
        description: input.description,
        sourceType: input.sourceType,
        sourceId: input.sourceId,
        actorName: input.actorName,
        scanMode: input.scanMode as ScanMode,
        nodes,
        edges,
        createdBy: ctx.user?.name || ctx.user?.openId,
      });
    }),

  // ─── Generate graph from TTP knowledge chain ───
  generateFromChain: protectedProcedure
    .input(z.object({
      name: z.string(),
      techniqueIds: z.array(z.string()).min(1),
      targetEnvironment: z.string().default("hybrid"),
      actorName: z.string().optional(),
      scanMode: z.enum(["passive", "active-low", "active-standard", "active-aggressive"]).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      return generateGraphFromTtpChain({
        techniqueIds: input.techniqueIds,
        name: input.name,
        targetEnvironment: input.targetEnvironment,
        actorName: input.actorName,
        scanMode: input.scanMode as ScanMode,
        createdBy: ctx.user?.name || ctx.user?.openId,
      });
    }),

  // ─── Generate graph from LLM decomposition ───
  generateFromLLM: protectedProcedure
    .input(z.object({
      name: z.string(),
      techniques: z.array(z.object({
        id: z.string(),
        name: z.string(),
        tactic: z.string(),
      })).min(1),
      targetEnvironment: z.string().default("hybrid"),
      actorName: z.string().optional(),
      objective: z.string().optional(),
      scanMode: z.enum(["passive", "active-low", "active-standard", "active-aggressive"]).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { nodes, edges } = await decomposeTechniquesToGraph({
        techniques: input.techniques,
        targetEnvironment: input.targetEnvironment,
        actorName: input.actorName,
        objective: input.objective,
      });

      return createGraph({
        name: input.name,
        description: `LLM-generated graph for ${input.actorName || "custom"} emulation`,
        sourceType: "technique_chain",
        actorName: input.actorName,
        scanMode: input.scanMode as ScanMode,
        nodes,
        edges,
        createdBy: ctx.user?.name || ctx.user?.openId,
      });
    }),

  // ─── Simulate graph execution (walk) ───
  simulate: protectedProcedure
    .input(z.object({
      graphId: z.string(),
      environment: environmentContextSchema,
      scanMode: z.enum(["passive", "active-low", "active-standard", "active-aggressive"]).default("active-standard"),
    }))
    .mutation(async ({ input }) => {
      const graphData = await getGraph(input.graphId);
      if (!graphData) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Graph not found" });
      }

      return walkGraph(
        graphData.nodes,
        graphData.edges,
        input.environment as EnvironmentContext,
        input.scanMode as ScanMode,
      );
    }),

  // ─── Validate graph (check DAG, preconditions, safety) ───
  validate: protectedProcedure
    .input(z.object({ graphId: z.string() }))
    .mutation(async ({ input }) => {
      const graphData = await getGraph(input.graphId);
      if (!graphData) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Graph not found" });
      }

      const issues: string[] = [];

      // Check DAG validity
      try {
        topologicalSort(graphData.nodes, graphData.edges);
      } catch (e: any) {
        issues.push(`DAG validation failed: ${e.message}`);
      }

      // Check for orphan nodes (no incoming or outgoing edges)
      const connectedNodes = new Set<string>();
      for (const edge of graphData.edges) {
        connectedNodes.add(edge.sourceNodeId);
        connectedNodes.add(edge.targetNodeId);
      }
      if (graphData.nodes.length > 1) {
        for (const node of graphData.nodes) {
          if (!connectedNodes.has(node.id)) {
            issues.push(`Orphan node: "${node.label}" (${node.techniqueId}) has no connections`);
          }
        }
      }

      // Check safety tiers
      const maxTier = computeGraphSafetyTier(graphData.nodes);
      const criticalNodes = graphData.nodes.filter(n => n.safetyTier === "critical_impact");
      if (criticalNodes.length > 0) {
        issues.push(`${criticalNodes.length} node(s) have critical_impact safety tier — requires explicit approval`);
      }

      // Check for nodes without technique mapping
      const unmappedNodes = graphData.nodes.filter(n => !n.calderaAbilityId);
      if (unmappedNodes.length > 0) {
        issues.push(`${unmappedNodes.length} node(s) not mapped to emulation abilities`);
      }

      const valid = issues.length === 0;
      if (valid) {
        await updateGraphStatus(input.graphId, "validated");
      }

      return {
        valid,
        issues,
        maxSafetyTier: maxTier,
        nodeCount: graphData.nodes.length,
        edgeCount: graphData.edges.length,
      };
    }),

  // ─── Update graph status ───
  updateStatus: protectedProcedure
    .input(z.object({
      graphId: z.string(),
      status: z.enum(["draft", "validated", "ready", "running", "completed", "failed", "aborted"]),
    }))
    .mutation(async ({ input }) => {
      await updateGraphStatus(input.graphId, input.status);
      return { success: true };
    }),

  // ─── Update node status ───
  updateNodeStatus: protectedProcedure
    .input(z.object({
      nodeId: z.string(),
      status: z.enum(["pending", "ready", "running", "success", "failed", "skipped", "blocked"]),
      executionResult: z.object({
        exitCode: z.number(),
        stdout: z.string(),
        stderr: z.string(),
        startedAt: z.string(),
        completedAt: z.string(),
        agentId: z.string().optional(),
      }).optional(),
    }))
    .mutation(async ({ input }) => {
      await updateNodeStatus(input.nodeId, input.status as NodeStatus, input.executionResult);
      return { success: true };
    }),

  // ─── Delete graph ───
  delete: protectedProcedure
    .input(z.object({ graphId: z.string() }))
    .mutation(async ({ input }) => {
      await deleteGraph(input.graphId);
      return { success: true };
    }),

  // ─── Get graph statistics ───
  stats: protectedProcedure.query(async () => {
    return getGraphStats();
  }),

  // ─── Get available Caldera agents ───
  agents: protectedProcedure.query(async () => {
    return getCalderaAgents();
  }),

  // ─── Execute graph against a Caldera agent ───
  execute: protectedProcedure
    .input(z.object({
      graphId: z.string(),
      agentPaw: z.string(),
      scanMode: z.enum(["passive", "active-low", "active-standard", "active-aggressive"]).default("active-standard"),
      dryRun: z.boolean().default(false),
      operationName: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const agents = await getCalderaAgents();
      const agent = agents.find(a => a.paw === input.agentPaw);
      if (!agent) throw new TRPCError({ code: "NOT_FOUND", message: "Agent not found" });

      const environment = buildEnvironmentFromAgent(agent);
      const config: ExecutionConfig = {
        graphId: input.graphId,
        agentPawId: input.agentPaw,
        scanMode: input.scanMode as ScanMode,
        environment,
        dryRun: input.dryRun,
        operationName: input.operationName,
      };

      const state = await executeGraph(config);
      return state;
    }),

  // ─── Get execution state ───
  executionState: protectedProcedure
    .input(z.object({ graphId: z.string() }))
    .query(({ input }) => {
      return getExecutionState(input.graphId);
    }),

  // ─── Get execution log ───
  executionLog: protectedProcedure
    .input(z.object({
      graphId: z.string(),
      since: z.string().optional(),
    }))
    .query(({ input }) => {
      return getExecutionLog(input.graphId, input.since);
    }),

  // ─── Abort execution ───
  abortExecution: protectedProcedure
    .input(z.object({ graphId: z.string() }))
    .mutation(async ({ input }) => {
      const state = await abortExecution(input.graphId);
      if (!state) throw new TRPCError({ code: "NOT_FOUND", message: "No active execution" });
      return state;
    }),

  // ─── Pause execution ───
  pauseExecution: protectedProcedure
    .input(z.object({ graphId: z.string() }))
    .mutation(async ({ input }) => {
      const state = await pauseExecution(input.graphId);
      if (!state) throw new TRPCError({ code: "NOT_FOUND", message: "No active execution or not running" });
      return state;
    }),

  // ─── Resume execution ───
  resumeExecution: protectedProcedure
    .input(z.object({ graphId: z.string() }))
    .mutation(async ({ input }) => {
      const state = await resumeExecution(input.graphId);
      if (!state) throw new TRPCError({ code: "NOT_FOUND", message: "No paused execution" });
      return state;
    }),

  // ─── Generate graph from threat actor profile ───
  generateFromActor: protectedProcedure
    .input(z.object({
      actorId: z.string(),
      targetEnvironment: z.string().default("enterprise-windows"),
      includeAlternatives: z.boolean().default(true),
    }))
    .mutation(async ({ input, ctx }) => {
      const result = await generateGraphFromActorProfile({
        actorId: input.actorId,
        targetEnvironment: input.targetEnvironment,
        includeAlternatives: input.includeAlternatives,
        createdBy: ctx.user?.openId,
      });
      return result;
    }),

  // ─── Get available actor templates ───
  actorTemplates: protectedProcedure
    .input(z.object({
      type: z.enum(["apt", "cybercrime", "ransomware", "hacktivist", "unknown"]).optional(),
      limit: z.number().default(50),
    }).optional())
    .query(async ({ input }) => {
      return getAvailableActorTemplates({
        type: input?.type,
        limit: input?.limit,
      });
    }),

  // ─── Compare two graphs ───
  compare: protectedProcedure
    .input(z.object({
      graphIdA: z.string(),
      graphIdB: z.string(),
    }))
    .query(async ({ input }) => {
      const result = await compareGraphs(input.graphIdA, input.graphIdB);
      if (!result) throw new TRPCError({ code: "NOT_FOUND", message: "One or both graphs not found" });
      return result;
    }),

  // ─── Compute overlap matrix for multiple graphs ───
  overlapMatrix: protectedProcedure
    .input(z.object({
      graphIds: z.array(z.string()).min(2).max(10),
    }))
    .query(async ({ input }) => {
      return computeOverlapMatrix(input.graphIds);
    }),

  // ─── Multi-C2 Health Check ───
  c2Health: protectedProcedure.query(async () => {
    const registry = getC2Registry();
    return registry.healthCheckAll();
  }),

  // ─── Multi-C2 Aggregate Stats ───
  c2Stats: protectedProcedure.query(async () => {
    const registry = getC2Registry();
    return registry.getAggregateStats();
  }),

  // ─── Multi-C2 List All Agents ───
  c2Agents: protectedProcedure
    .input(z.object({
      framework: z.enum(["caldera", "metasploit", "sliver", "empire", "cobaltstrike", "manjusaka"]).optional(),
    }).optional())
    .query(async ({ input }) => {
      const registry = getC2Registry();
      if (input?.framework) {
        const adapter = registry.get(input.framework as C2FrameworkType);
        return adapter ? adapter.listAgents() : [];
      }
      return registry.listAllAgents();
    }),

  // ─── Multi-C2 Search Modules ───
  c2Modules: protectedProcedure
    .input(z.object({
      query: z.string(),
      framework: z.enum(["caldera", "metasploit", "sliver", "empire", "cobaltstrike", "manjusaka"]).optional(),
    }))
    .query(async ({ input }) => {
      const registry = getC2Registry();
      if (input.framework) {
        const adapter = registry.get(input.framework as C2FrameworkType);
        return adapter ? adapter.searchModules(input.query) : [];
      }
      return registry.searchAllModules(input.query);
    }),

  // ─── Multi-C2 Dispatch Task ───
  c2Dispatch: protectedProcedure
    .input(z.object({
      framework: z.enum(["caldera", "metasploit", "sliver", "empire", "cobaltstrike", "manjusaka"]),
      agentId: z.string(),
      moduleId: z.string(),
      options: z.record(z.string(), z.any()).optional(),
      timeout: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const registry = getC2Registry();
      const result = await registry.dispatch({
        framework: input.framework as C2FrameworkType,
        agentId: input.agentId,
        moduleId: input.moduleId,
        options: input.options,
        timeout: input.timeout,
      });

      // Feed result into learning engine
      if (result.status === "success" || result.status === "failed") {
        await processExecutionFeedback({
          techniqueId: input.moduleId,
          framework: input.framework as C2FrameworkType,
          taskResult: result,
          targetContext: {
            platform: "unknown",
            architecture: "x64",
            hostname: "unknown",
            privileges: "user",
          },
        }).catch(() => {});
      }

      return result;
    }),

  // ─── Multi-C2 Poll Task Result ───
  c2PollResult: protectedProcedure
    .input(z.object({
      framework: z.enum(["caldera", "metasploit", "sliver", "empire", "cobaltstrike", "manjusaka"]),
      taskId: z.string(),
      agentId: z.string(),
    }))
    .query(async ({ input }) => {
      const registry = getC2Registry();
      const adapter = registry.get(input.framework as C2FrameworkType);
      if (!adapter) throw new TRPCError({ code: "NOT_FOUND", message: `No adapter for ${input.framework}` });
      const result = await adapter.pollResult(input.taskId, input.agentId);

      // Feed completed results into learning engine
      if (result.status === "success" || result.status === "failed") {
        await processExecutionFeedback({
          techniqueId: result.moduleId || "",
          framework: input.framework as C2FrameworkType,
          taskResult: result,
          targetContext: {
            platform: "unknown",
            architecture: "x64",
            hostname: "unknown",
            privileges: "user",
          },
        }).catch(() => {});
      }

      return result;
    }),

  // ─── Multi-C2 Kill Agent ───
  c2KillAgent: protectedProcedure
    .input(z.object({
      framework: z.enum(["caldera", "metasploit", "sliver", "empire", "cobaltstrike", "manjusaka"]),
      agentId: z.string(),
    }))
    .mutation(async ({ input }) => {
      const registry = getC2Registry();
      const adapter = registry.get(input.framework as C2FrameworkType);
      if (!adapter) throw new TRPCError({ code: "NOT_FOUND", message: `No adapter for ${input.framework}` });
      const success = await adapter.killAgent(input.agentId);
      return { success };
    }),

  // ─── C2 Learning Stats ───
  learningStats: protectedProcedure.query(async () => {
    return getLearningStats();
  }),

  // ─── C2 Learning History ───
  learningHistory: protectedProcedure
    .input(z.object({
      limit: z.number().default(50),
      techniqueId: z.string().optional(),
      framework: z.enum(["caldera", "metasploit", "sliver", "empire", "cobaltstrike", "manjusaka"]).optional(),
    }).optional())
    .query(async ({ input }) => {
      return getExecutionHistory({
        limit: input?.limit,
        techniqueId: input?.techniqueId,
        framework: input?.framework as C2FrameworkType | undefined,
      });
    }),

  // ─── C2 Technique Reliability ───
  techniqueReliability: protectedProcedure
    .input(z.object({
      techniqueId: z.string(),
    }))
    .query(async ({ input }) => {
      return calculateTechniqueReliability(input.techniqueId);
    }),

  // ─── Exploit Matching: Match by Scan ───
  matchExploitsByScan: protectedProcedure
    .input(z.object({
      scanId: z.number(),
    }))
    .query(async ({ input }) => {
      return matchExploitsToScan(input.scanId);
    }),

  // ─── Generate Targeted Graph from Scan ───
  generateTargetedGraph: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      maxNodes: z.number().default(30),
      engagementContext: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      return generateTargetedGraph({
        scanId: input.scanId,
        maxNodes: input.maxNodes,
        engagementContext: input.engagementContext,
      });
    }),

  // ─── Get visualization data (nodes + edges with layout) ───
  // ─── Cross-C2 Orchestration ───
  createOrchestration: protectedProcedure
    .input(z.object({
      name: z.string(),
      description: z.string().default(""),
      graphId: z.string(),
      targetHost: z.string(),
      frameworkAssignments: z.record(z.string(), z.string()).default({}),
      phishingCampaignId: z.string().optional(),
      enableLearning: z.boolean().default(true),
      maxParallel: z.number().default(3),
      scanMode: z.enum(["passive", "active-low", "active-standard", "active-aggressive"]).default("active-standard"),
    }))
    .mutation(async ({ input }) => {
      const graphData = await getGraph(input.graphId);
      if (!graphData) throw new TRPCError({ code: "NOT_FOUND", message: "Graph not found" });

      return createOrchestrationPlan({
        name: input.name,
        description: input.description,
        nodes: graphData.nodes || [],
        edges: graphData.edges || [],
        scanMode: input.scanMode as ScanMode,
        maxParallel: input.maxParallel,
      });
    }),

  startOrchestration: protectedProcedure
    .input(z.object({ orchestrationId: z.string() }))
    .mutation(async ({ input }) => {
      return executeOrchestrationPlan(input.orchestrationId, {
        os: "windows",
        hostname: "target",
        privilegeLevel: "user",
        networkAccess: "internal",
        installedSoftware: [],
        runningServices: [],
        openPorts: [],
        customFacts: {},
      });
    }),

  orchestrationStatus: protectedProcedure
    .input(z.object({ orchestrationId: z.string() }))
    .query(async ({ input }) => {
      return getOrchestrationPlan(input.orchestrationId);
    }),

  orchestrationStats: protectedProcedure.query(async () => {
    return getOrchestrationStats();
  }),

  listOrchestrations: protectedProcedure.query(async () => {
    return listOrchestrationPlans();
  }),

  abortOrchestration: protectedProcedure
    .input(z.object({ orchestrationId: z.string() }))
    .mutation(async ({ input }) => {
      return abortOrchestrationPlan(input.orchestrationId);
    }),

  // ─── C2 Module Builder ───
  generateModule: protectedProcedure
    .input(z.object({
      framework: z.enum(["caldera", "metasploit", "sliver", "empire", "cobaltstrike", "manjusaka"]),
      techniqueId: z.string(),
      techniqueName: z.string(),
      platform: z.string().default("windows"),
      targetService: z.string().optional(),
      targetVersion: z.string().optional(),
      cveId: z.string().optional(),
      customPayload: z.string().optional(),
      evasionLevel: z.enum(["none", "basic", "advanced", "maximum"]).default("basic"),
    }))
    .mutation(async ({ input }) => {
      const spec: ModuleSpec = {
        name: input.techniqueName,
        description: `Module for ${input.techniqueId}: ${input.techniqueName}`,
        author: "Ace C3 Auto-Generator",
        category: "exploitation" as any,
        platforms: [input.platform as any],
        techniqueIds: [input.techniqueId],
        language: input.framework === "metasploit" ? "ruby" : input.framework === "sliver" ? "go" : input.framework === "manjusaka" ? "rust" : "python",
        targetFrameworks: [input.framework as any],
        requiresAdmin: false,
        requiresNetwork: true,
        opsecRating: 5,
        safetyTier: "medium_risk",
        parameters: [],
      };
      return generateModuleCode(spec);
    }),

  generateModulesFromAssets: protectedProcedure
    .input(z.object({
      scanId: z.number(),
      frameworks: z.array(z.enum(["caldera", "metasploit", "sliver", "empire", "cobaltstrike", "manjusaka"])).default(["caldera", "metasploit", "cobaltstrike"]),
      evasionLevel: z.enum(["none", "basic", "advanced", "maximum"]).default("basic"),
    }))
    .mutation(async ({ input }) => {
      return generateDynamicModules({
        assets: [],
        killChainPhase: "exploitation",
        objective: `Generate modules from scan ${input.scanId}`,
        constraints: {
          maxSafetyTier: "medium_risk",
          requireStealth: input.evasionLevel !== "none",
          allowedPlatforms: ["windows", "linux"],
          preferredFrameworks: input.frameworks as any[],
        },
      });
    }),

  moduleTemplates: protectedProcedure.query(async () => {
    return getModuleTemplates();
  }),

  pushModules: protectedProcedure
    .input(z.object({
      modules: z.array(z.object({
        code: z.string(),
        filename: z.string(),
      })),
      framework: z.enum(["caldera", "metasploit", "sliver", "empire", "cobaltstrike", "manjusaka"]),
    }))
    .mutation(async ({ input }) => {
      return pushModulesToC2(input.modules.map(m => ({
        code: m.code,
        filename: m.filename,
        framework: input.framework as any,
        language: "python" as any,
        metadata: {},
      })));
    }),

  // ─── Threat Actor Intelligence Crawler ───
  crawlIntel: protectedProcedure
    .input(z.object({
      actorNames: z.array(z.string()).optional(),
      maxResults: z.number().default(50),
    }).optional())
    .mutation(async ({ input }) => {
      return runIntelligenceCrawl({
        actorFocus: input?.actorNames,
        maxArticlesPerSource: input?.maxResults,
      });
    }),

  enrichActors: protectedProcedure
    .input(z.object({
      actorNames: z.array(z.string()).optional(),
    }).optional())
    .mutation(async ({ input }) => {
      return runTargetedEnrichment({
        actorIds: input?.actorNames,
      });
    }),

  analyzeGaps: protectedProcedure
    .input(z.object({
      actorIds: z.array(z.string()).optional(),
    }).optional())
    .query(async ({ input }) => {
      return analyzeDataGaps(input?.actorIds);
    }),

  crawlerStats: protectedProcedure.query(async () => {
    return getCrawlerStats();
  }),

  crawlHistory: protectedProcedure.query(async () => {
    return getCrawlHistory();
  }),

  crawlSources: protectedProcedure.query(async () => {
    return getCrawlSources();
  }),

  toggleCrawlSource: protectedProcedure
    .input(z.object({
      sourceId: z.string(),
      enabled: z.boolean(),
    }))
    .mutation(async ({ input }) => {
      return toggleCrawlSource(input.sourceId, input.enabled);
    }),

  isCrawlRunning: protectedProcedure.query(async () => {
    return isCrawlRunning();
  }),

  // ─── Crawler Scheduler ───
  schedulerStatus: protectedProcedure.query(async () => {
    return getSchedulerStatus();
  }),

  schedulerPresets: protectedProcedure.query(async () => {
    return getSchedulePresets();
  }),

  startScheduler: protectedProcedure
    .input(z.object({
      preset: z.enum(["realtime", "aggressive", "standard", "conservative", "manual"]).optional(),
      crawlIntervalMinutes: z.number().min(0).optional(),
      enrichmentIntervalMinutes: z.number().min(0).optional(),
      maxConcurrentJobs: z.number().min(1).max(5).optional(),
      autoEnrichAfterCrawl: z.boolean().optional(),
      maxActorsPerEnrichment: z.number().min(1).max(100).optional(),
      retryFailedJobs: z.boolean().optional(),
      maxRetries: z.number().min(0).max(10).optional(),
      focusActors: z.array(z.string()).optional(),
      notifyOnComplete: z.boolean().optional(),
      notifyOnFailure: z.boolean().optional(),
    }).optional())
    .mutation(async ({ input }) => {
      return startScheduler(input || undefined);
    }),

  stopScheduler: protectedProcedure.mutation(async () => {
    return stopScheduler();
  }),

  pauseScheduler: protectedProcedure.mutation(async () => {
    return pauseScheduler();
  }),

  resumeScheduler: protectedProcedure.mutation(async () => {
    return resumeScheduler();
  }),

  updateSchedulerConfig: protectedProcedure
    .input(z.object({
      preset: z.enum(["realtime", "aggressive", "standard", "conservative", "manual"]).optional(),
      crawlIntervalMinutes: z.number().min(0).optional(),
      enrichmentIntervalMinutes: z.number().min(0).optional(),
      maxConcurrentJobs: z.number().min(1).max(5).optional(),
      autoEnrichAfterCrawl: z.boolean().optional(),
      maxActorsPerEnrichment: z.number().min(1).max(100).optional(),
      retryFailedJobs: z.boolean().optional(),
      maxRetries: z.number().min(0).max(10).optional(),
      focusActors: z.array(z.string()).optional(),
      notifyOnComplete: z.boolean().optional(),
      notifyOnFailure: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      return updateSchedulerConfig(input);
    }),

  enqueueJob: protectedProcedure
    .input(z.object({
      type: z.enum(["full_crawl", "targeted_enrichment", "gap_analysis", "source_check"]),
      priority: z.enum(["critical", "high", "normal", "low"]).default("normal"),
    }))
    .mutation(async ({ input }) => {
      return enqueueJob(input.type as JobType, input.priority as JobPriority);
    }),

  cancelJob: protectedProcedure
    .input(z.object({ jobId: z.string() }))
    .mutation(async ({ input }) => {
      return cancelJob(input.jobId);
    }),

  forceRunJob: protectedProcedure
    .input(z.object({
      type: z.enum(["full_crawl", "targeted_enrichment", "gap_analysis", "source_check"]),
    }))
    .mutation(async ({ input }) => {
      return forceRunJob(input.type as JobType);
    }),

  jobHistory: protectedProcedure
    .input(z.object({ limit: z.number().default(50) }).optional())
    .query(async ({ input }) => {
      return getJobHistory(input?.limit);
    }),

  queueStatus: protectedProcedure.query(async () => {
    return getQueueStatus();
  }),

  // ─── FIPS Compliance ───
  fipsReport: protectedProcedure.query(async () => {
    return generateComplianceReport();
  }),

  fipsKeys: protectedProcedure
    .input(z.object({
      status: z.enum(["active", "expired", "revoked", "pending-rotation"]).optional(),
      purpose: z.enum(["encryption", "signing", "authentication", "key-wrapping", "derivation"]).optional(),
    }).optional())
    .query(async ({ input }) => {
      return listFipsKeys(input || {});
    }),

  fipsGenerateKey: protectedProcedure
    .input(z.object({
      algorithm: z.string(),
      keyLength: z.number(),
      purpose: z.enum(["encryption", "signing", "authentication", "key-wrapping", "derivation"]),
      expiresInDays: z.number().default(365),
    }))
    .mutation(async ({ input, ctx }) => {
      return generateFipsKey({
        ...input,
        owner: ctx.user?.name || "system",
      });
    }),

  fipsRotateKey: protectedProcedure
    .input(z.object({ keyId: z.string() }))
    .mutation(async ({ input, ctx }) => {
      return rotateFipsKey(input.keyId, ctx.user?.name || "system");
    }),

  fipsRevokeKey: protectedProcedure
    .input(z.object({ keyId: z.string() }))
    .mutation(async ({ input, ctx }) => {
      revokeFipsKey(input.keyId, ctx.user?.name || "system");
      return { success: true };
    }),

  fipsAuditLog: protectedProcedure
    .input(z.object({
      operation: z.enum(["encrypt", "decrypt", "sign", "verify", "hash", "derive", "generate", "rotate", "revoke", "validate"]).optional(),
      keyId: z.string().optional(),
      limit: z.number().default(100),
    }).optional())
    .query(async ({ input }) => {
      return getFipsAuditLog(input || {});
    }),

  fipsAlgorithmUsage: protectedProcedure.query(async () => {
    return getAlgorithmUsageStats();
  }),

  fipsValidateOperation: protectedProcedure
    .input(z.object({
      algorithm: z.string(),
      keyLength: z.number().optional(),
      operation: z.enum(["encrypt", "decrypt", "sign", "verify", "hash", "derive"]),
    }))
    .query(async ({ input }) => {
      return validateOperation(input);
    }),

  fipsKeysNeedingRotation: protectedProcedure
    .input(z.object({ daysBeforeExpiry: z.number().default(30) }).optional())
    .query(async ({ input }) => {
      return getKeysNeedingRotation(input?.daysBeforeExpiry || 30);
    }),

  // ─── Get visualization data (nodes + edges with layout) ───
  visualize: protectedProcedure
    .input(z.object({
      graphId: z.string(),
      scanMode: z.enum(["passive", "active-low", "active-standard", "active-aggressive"]).default("active-standard"),
    }))
    .query(async ({ input }) => {
      const graphData = await getGraph(input.graphId);
      if (!graphData) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Graph not found" });
      }

      // Assign layers for visualization
      assignLayers(graphData.nodes, graphData.edges);

      // Filter by safety tier
      const { allowed, blocked } = filterNodesBySafetyTier(graphData.nodes, input.scanMode as ScanMode);

      // Compute layout positions
      const layerGroups = new Map<number, AbilityNodeData[]>();
      for (const node of graphData.nodes) {
        const layer = node.layer || 0;
        if (!layerGroups.has(layer)) layerGroups.set(layer, []);
        layerGroups.get(layer)!.push(node);
      }

      const LAYER_SPACING = 200;
      const NODE_SPACING = 160;

      for (const [layer, layerNodes] of layerGroups) {
        const totalWidth = (layerNodes.length - 1) * NODE_SPACING;
        const startX = -totalWidth / 2;
        layerNodes.forEach((node, idx) => {
          node.x = startX + idx * NODE_SPACING;
          node.y = layer * LAYER_SPACING;
        });
      }

      return {
        graph: graphData.graph,
        nodes: graphData.nodes,
        edges: graphData.edges,
        allowedNodes: allowed.map(n => n.id),
        blockedNodes: blocked.map(n => n.id),
        layers: Array.from(layerGroups.entries()).map(([layer, nodes]) => ({
          layer,
          nodeIds: nodes.map(n => n.id),
          tactic: nodes[0]?.tactic || "unknown",
        })),
      };
    }),
});
