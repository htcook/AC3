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
  customFacts: z.record(z.union([z.string(), z.number(), z.boolean()])).default({}),
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
        issues.push(`${unmappedNodes.length} node(s) not mapped to Caldera abilities`);
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
