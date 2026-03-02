import { fetchCalderaAPI, CALDERA_BASE_URL, CALDERA_API_KEY } from "../lib/api-helpers";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, publicProcedure, router } from "../_core/trpc";
import { z } from "zod";
import * as db from "../db";
import { and, count, min, not, sql } from "drizzle-orm";
import * as schema from "../../drizzle/schema";

export const calderaProxyRouter = router({
    // Direct stats from C2 server
    getStats: publicProcedure.query(async () => {
      const [adversaries, abilities, operations, agents] = await Promise.all([
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/adversaries'),
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities'),
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations'),
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/agents'),
      ]);

      return {
        totalAdversaries: Array.isArray(adversaries) ? adversaries.length : 0,
        totalThreatActors: await db.getThreatActorCount(),
        totalAbilities: Array.isArray(abilities) ? abilities.length : 0,
        activeOperations: Array.isArray(operations) ? operations.filter((o: any) => o.state === 'running').length : 0,
        totalAgents: Array.isArray(agents) ? agents.length : 0,
      };
    }),

    // Get all adversaries from DigitalOcean Caldera
    getAdversaries: publicProcedure.query(async () => {
      const adversaries = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/adversaries');
      return Array.isArray(adversaries) ? adversaries : [];
    }),

    // Get single adversary by ID
    getAdversary: publicProcedure
      .input(z.object({ adversaryId: z.string() }))
      .query(async ({ input }) => {
        return fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, `/api/v2/adversaries/${input.adversaryId}`);
      }),

    // Get all abilities from DigitalOcean Caldera
    getAbilities: publicProcedure.query(async () => {
      const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
      return Array.isArray(abilities) ? abilities : [];
    }),

    // Get abilities by tactic
    getAbilitiesByTactic: publicProcedure
      .input(z.object({ tactic: z.string() }))
      .query(async ({ input }) => {
        const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
        if (!Array.isArray(abilities)) return [];
        return abilities.filter((a: any) => a.tactic === input.tactic);
      }),

    // Get all tactics (derived from abilities)
    getTactics: publicProcedure.query(async () => {
      const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
      if (!Array.isArray(abilities)) return [];

      const tacticCounts: Record<string, number> = {};
      abilities.forEach((a: any) => {
        const tactic = a.tactic || 'unknown';
        tacticCounts[tactic] = (tacticCounts[tactic] || 0) + 1;
      });

      return Object.entries(tacticCounts).map(([name, count]) => ({ name, count })).sort((a, b) => a.name.localeCompare(b.name));
    }),

    // Get all operations from DigitalOcean Caldera
    getOperations: publicProcedure.query(async () => {
      const operations = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations');
      return Array.isArray(operations) ? operations : [];
    }),

    // Get all agents from DigitalOcean Caldera
    getAgents: publicProcedure.query(async () => {
      const agents = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/agents');
      return Array.isArray(agents) ? agents : [];
    }),

    // Get single agent by paw (agent ID)
    getAgent: publicProcedure
      .input(z.object({ paw: z.string() }))
      .query(async ({ input }) => {
        return fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, `/api/v2/agents/${input.paw}`);
      }),

    // Kill an agent
    killAgent: protectedProcedure
      .input(z.object({ paw: z.string() }))
      .mutation(async ({ input }) => {
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/agents/${input.paw}`, {
            method: 'DELETE',
            headers: { 'KEY': CALDERA_API_KEY },
          });
          return { success: response.ok };
        } catch {
          return { success: false };
        }
      }),

    // Update agent trust level
    updateAgentTrust: protectedProcedure
      .input(z.object({ paw: z.string(), trusted: z.boolean() }))
      .mutation(async ({ input }) => {
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/agents/${input.paw}`, {
            method: 'PATCH',
            headers: { 
              'KEY': CALDERA_API_KEY,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ trusted: input.trusted }),
          });
          return { success: response.ok };
        } catch {
          return { success: false };
        }
      }),

    // Get agent deployable commands
    getDeployCommands: publicProcedure.query(async () => {
      const deploy = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/deploy_commands');
      return deploy || {};
    }),

    // Check C2 server health
    checkHealth: publicProcedure.query(async () => {
      try {
        const response = await fetch(`${CALDERA_BASE_URL}/api/v2/health`, {
          headers: { 'KEY': CALDERA_API_KEY },
          signal: AbortSignal.timeout(5000),
        });
        return response.ok;
      } catch {
        return false;
      }
    }),

    // Create a new ability on the C2 server
    createAbility: protectedProcedure
      .input(z.object({
        ability_id: z.string(),
        name: z.string(),
        description: z.string(),
        tactic: z.string(),
        technique_id: z.string(),
        technique_name: z.string(),
        executors: z.array(z.object({
          platform: z.string(),
          name: z.string(),
          command: z.string(),
          cleanup: z.string().optional(),
          timeout: z.number().optional(),
        })),
        singleton: z.boolean().optional(),
        repeatable: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/abilities`, {
            method: 'POST',
            headers: {
              'KEY': CALDERA_API_KEY,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              ability_id: input.ability_id,
              name: input.name,
              description: input.description,
              tactic: input.tactic,
              technique_id: input.technique_id,
              technique_name: input.technique_name,
              executors: input.executors,
              singleton: input.singleton ?? false,
              repeatable: input.repeatable ?? true,
            }),
            signal: AbortSignal.timeout(15000),
          });
          if (!response.ok) {
            const errText = await response.text();
            return { success: false, error: `HTTP ${response.status}: ${errText}` };
          }
          const result = await response.json();
          return { success: true, ability: result };
        } catch (err: any) {
          return { success: false, error: err.message };
        }
      }),

    // Create a new adversary profile on the C2 server
    createAdversary: protectedProcedure
      .input(z.object({
        adversary_id: z.string(),
        name: z.string(),
        description: z.string(),
        atomic_ordering: z.array(z.string()),
        objective: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/adversaries`, {
            method: 'POST',
            headers: {
              'KEY': CALDERA_API_KEY,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              adversary_id: input.adversary_id,
              name: input.name,
              description: input.description,
              atomic_ordering: input.atomic_ordering,
              objective: input.objective || '',
            }),
            signal: AbortSignal.timeout(15000),
          });
          if (!response.ok) {
            const errText = await response.text();
            return { success: false, error: `HTTP ${response.status}: ${errText}` };
          }
          const result = await response.json();
          return { success: true, adversary: result };
        } catch (err: any) {
          return { success: false, error: err.message };
        }
      }),

    // Deploy a full ransomware ability profile to Caldera (abilities + adversary)
    deployRansomwareProfile: protectedProcedure
      .input(z.object({
        groupId: z.string(),
        groupName: z.string(),
        adversaryId: z.string(),
        description: z.string(),
        abilities: z.array(z.object({
          ability_id: z.string(),
          name: z.string(),
          description: z.string(),
          tactic: z.string(),
          technique_id: z.string(),
          technique_name: z.string(),
          platforms: z.record(z.string(), z.record(z.string(), z.object({
            command: z.string(),
            cleanup: z.string().optional(),
            timeout: z.number().optional(),
          }))),
        })),
      }))
      .mutation(async ({ input }) => {
        const results: Array<{ ability_id: string; name: string; success: boolean; error?: string }> = [];

        // Step 1: Create each ability
        for (const ability of input.abilities) {
          const executors: Array<{ platform: string; name: string; command: string; cleanup?: string; timeout?: number }> = [];
          for (const [platform, execs] of Object.entries(ability.platforms)) {
            for (const [executor, config] of Object.entries(execs as Record<string, { command: string; cleanup?: string; timeout?: number }>)) {
              executors.push({
                platform,
                name: executor,
                command: config.command,
                cleanup: config.cleanup,
                timeout: config.timeout,
              });
            }
          }

          try {
            const response = await fetch(`${CALDERA_BASE_URL}/api/v2/abilities`, {
              method: 'POST',
              headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                ability_id: ability.ability_id,
                name: `[${input.groupName}] ${ability.name}`,
                description: ability.description,
                tactic: ability.tactic,
                technique_id: ability.technique_id,
                technique_name: ability.technique_name,
                executors,
                singleton: false,
                repeatable: true,
              }),
              signal: AbortSignal.timeout(15000),
            });
            results.push({
              ability_id: ability.ability_id,
              name: ability.name,
              success: response.ok,
              error: response.ok ? undefined : `HTTP ${response.status}`,
            });
          } catch (err: any) {
            results.push({ ability_id: ability.ability_id, name: ability.name, success: false, error: err.message });
          }
        }

        // Step 2: Create the adversary profile
        let adversaryResult: { success: boolean; error?: string } = { success: false };
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/adversaries`, {
            method: 'POST',
            headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              adversary_id: input.adversaryId,
              name: `${input.groupName} Simulation`,
              description: input.description,
              atomic_ordering: input.abilities.map(a => a.ability_id),
            }),
            signal: AbortSignal.timeout(15000),
          });
          adversaryResult = { success: response.ok, error: response.ok ? undefined : `HTTP ${response.status}` };
        } catch (err: any) {
          adversaryResult = { success: false, error: err.message };
        }

        return {
          abilitiesDeployed: results.filter(r => r.success).length,
          abilitiesFailed: results.filter(r => !r.success).length,
          abilityResults: results,
          adversaryCreated: adversaryResult.success,
          adversaryError: adversaryResult.error,
        };
      }),

    // ─── Campaign Execution Dashboard Endpoints ───
    // Get detailed operation with chain analysis
    getOperationDetail: publicProcedure
      .input(z.object({ operationId: z.string() }))
      .query(async ({ input }) => {
        const operations = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations');
        const op = Array.isArray(operations) ? operations.find((o: any) => o.id === input.operationId) : null;
        if (!op) return null;

        const chain = op.chain || [];
        const totalSteps = chain.length;
        const completedSteps = chain.filter((s: any) => s.finish).length;
        const successSteps = chain.filter((s: any) => s.status === 0 && s.finish).length;
        const failedSteps = chain.filter((s: any) => s.status !== 0 && s.finish).length;

        // Group by technique
        const techniqueMap: Record<string, { id: string; name: string; status: string; steps: any[] }> = {};
        for (const step of chain) {
          const ab = step.ability || {};
          const techId = ab.technique_id || 'unknown';
          if (!techniqueMap[techId]) {
            techniqueMap[techId] = {
              id: techId,
              name: ab.technique_name || ab.name || techId,
              status: 'pending',
              steps: [],
            };
          }
          techniqueMap[techId].steps.push({
            id: step.id,
            abilityName: ab.name,
            abilityId: ab.ability_id,
            status: step.finish ? (step.status === 0 ? 'success' : 'failed') : 'running',
            paw: step.paw,
            executor: step.executor?.name || step.executor,
            command: step.command,
            output: step.output,
            decide: step.decide,
            finish: step.finish,
            score: step.score,
          });
          // Update technique status
          const statuses = techniqueMap[techId].steps.map((s: any) => s.status);
          if (statuses.includes('running')) techniqueMap[techId].status = 'running';
          else if (statuses.every((s: string) => s === 'success')) techniqueMap[techId].status = 'success';
          else if (statuses.some((s: string) => s === 'failed')) techniqueMap[techId].status = 'partial';
          else techniqueMap[techId].status = 'pending';
        }

        // Timeline events
        const timeline = chain.map((step: any) => ({
          time: step.decide || step.finish,
          finishTime: step.finish,
          abilityName: step.ability?.name || 'Unknown',
          techniqueId: step.ability?.technique_id || 'Unknown',
          status: step.finish ? (step.status === 0 ? 'success' : 'failed') : 'running',
          paw: step.paw,
        })).sort((a: any, b: any) => new Date(a.time).getTime() - new Date(b.time).getTime());

        return {
          id: op.id,
          name: op.name,
          state: op.state,
          start: op.start,
          adversary: op.adversary,
          planner: op.planner,
          group: op.group,
          jitter: op.jitter,
          objective: op.objective,
          // Metrics
          metrics: {
            totalSteps,
            completedSteps,
            successSteps,
            failedSteps,
            pendingSteps: totalSteps - completedSteps,
            successRate: totalSteps > 0 ? Math.round((successSteps / totalSteps) * 100) : 0,
            detectionRate: totalSteps > 0 ? Math.round((failedSteps / totalSteps) * 100) : 0,
            progress: totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0,
          },
          techniques: Object.values(techniqueMap),
          timeline,
          agentPaws: Array.from(new Set(chain.map((s: any) => s.paw))),
        };
      }),

    // Get all operations summary for dashboard
    getOperationsSummary: publicProcedure.query(async () => {
      const [operations, agents] = await Promise.all([
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations'),
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/agents'),
      ]);
      const ops = Array.isArray(operations) ? operations : [];
      const agentList = Array.isArray(agents) ? agents : [];

      const summary = ops.map((op: any) => {
        const chain = op.chain || [];
        const totalSteps = chain.length;
        const completedSteps = chain.filter((s: any) => s.finish).length;
        const successSteps = chain.filter((s: any) => s.status === 0 && s.finish).length;
        const failedSteps = chain.filter((s: any) => s.status !== 0 && s.finish).length;
        const uniqueTechniques = new Set(chain.map((s: any) => s.ability?.technique_id).filter(Boolean));
        return {
          id: op.id,
          name: op.name,
          state: op.state,
          start: op.start,
          adversaryName: op.adversary?.name || 'Unknown',
          totalSteps,
          completedSteps,
          successSteps,
          failedSteps,
          uniqueTechniques: uniqueTechniques.size,
          progress: totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0,
          successRate: completedSteps > 0 ? Math.round((successSteps / completedSteps) * 100) : 0,
          agentPaws: Array.from(new Set(chain.map((s: any) => s.paw).filter(Boolean))),
        };
      });

      // Agent summary
      const agentSummary = agentList.map((a: any) => {
        const now = Date.now();
        const lastSeen = new Date(a.last_seen).getTime();
        const isAlive = (now - lastSeen) < 5 * 60 * 1000; // 5 min threshold
        return {
          paw: a.paw,
          host: a.host,
          platform: a.platform,
          username: a.username,
          privilege: a.privilege,
          contact: a.contact,
          lastSeen: a.last_seen,
          created: a.created,
          status: isAlive ? 'alive' : 'dead',
          executors: a.executors || [],
          hostIpAddrs: a.host_ip_addrs || [],
          displayName: a.display_name || a.host,
        };
      });

      return {
        operations: summary,
        agents: agentSummary,
        totals: {
          totalOperations: ops.length,
          runningOperations: ops.filter((o: any) => o.state === 'running').length,
          pausedOperations: ops.filter((o: any) => o.state === 'paused').length,
          finishedOperations: ops.filter((o: any) => o.state === 'finished').length,
          totalAgents: agentList.length,
          aliveAgents: agentSummary.filter((a: any) => a.status === 'alive').length,
        },
      };
    }),

    // Control operation (pause, resume, stop)
    controlOperation: protectedProcedure
      .input(z.object({
        operationId: z.string(),
        action: z.enum(['pause', 'resume', 'stop', 'cleanup']),
      }))
      .mutation(async ({ input }) => {
        const stateMap: Record<string, string> = {
          pause: 'paused',
          resume: 'running',
          stop: 'finished',
          cleanup: 'cleanup',
        };
        const response = await fetch(`${CALDERA_BASE_URL}/api/v2/operations/${input.operationId}`, {
          method: 'PATCH',
          headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
          body: JSON.stringify({ state: stateMap[input.action] }),
        });
        if (!response.ok) throw new Error(`Failed to ${input.action} operation: ${response.status}`);
        return { success: true, newState: stateMap[input.action] };
      }),

    // Build intelligent attack chain for a specific operation
    buildChain: protectedProcedure
      .input(z.object({
        operationId: z.string(),
        scanId: z.number().optional(),
        campaignIndex: z.number().optional(),
      }))
      .mutation(async ({ input }) => {
        const { buildOperationChain } = await import('../lib/chain-builder');
        const { matchTechnologiesAgainstAllFeeds, getVulnFeedChainSteps } = await import('../lib/vuln-feeds');
        const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
        let scanData: any = null;
        if (input.scanId) {
          const scan = await db.getDomainIntelScanById(input.scanId);
          scanData = scan?.pipelineOutput;
        }
        const campaigns = scanData?.campaignRecommendations || [];
        const actorMatches = scanData?.threatActorMatches?.topMatches || [];
        const kevChainSteps = scanData?.kevEnrichment?.chainSteps || [];
        const campaign = input.campaignIndex !== undefined ? campaigns[input.campaignIndex] : undefined;

        // Enrich with vulnerability feed data from discovered technologies
        // Only confirmed/probable findings are included to prevent false-positive noise in adversary emulation
        let vulnSteps: Array<{ techniqueId: string; priority: number; source: "vuln_feed"; context: string; corroborationTier?: string }> = [];
        try {
          if (input.scanId) {
            const scanForTech = await db.getDomainIntelScanById(input.scanId);
            const pipelineAssets = (scanForTech?.pipelineOutput as any)?.assets || [];
            const techs = new Set<string>();
            const detectedVersions: Record<string, string> = {};
            pipelineAssets.forEach((a: any) => {
              const asset = a?.asset || a;
              ((asset.technologies || []) as string[]).forEach((t: string) => techs.add(t));
              // Collect detected versions for corroboration
              if (asset.technologyVersions) {
                Object.entries(asset.technologyVersions).forEach(([tech, ver]) => {
                  if (ver) detectedVersions[tech] = ver as string;
                });
              }
            });
            if (techs.size > 0) {
              const vulnMatches = await matchTechnologiesAgainstAllFeeds(Array.from(techs));
              vulnSteps = getVulnFeedChainSteps(vulnMatches.matches, Object.keys(detectedVersions).length > 0 ? detectedVersions : undefined);
            }
          }
        } catch (e) {
          console.warn('[Chain Builder] Vuln feed enrichment failed, continuing without:', e);
        }

        const result = await buildOperationChain({
          operationId: input.operationId,
          scanId: input.scanId,
          campaignRecommendation: campaign,
          threatActorMatches: actorMatches,
          kevSteps: kevChainSteps,
          vulnSteps,
          allAbilities: abilities || [],
          calderaBaseUrl: CALDERA_BASE_URL,
          calderaApiKey: CALDERA_API_KEY,
        });
        return result;
      }),

    // Auto-build chains for ALL paused operations without chains
    autoBuildAllChains: protectedProcedure
      .input(z.object({ scanId: z.number().optional() }))
      .mutation(async ({ input }) => {
        const { autoBuildAllChains } = await import('../lib/chain-builder');
        const { matchTechnologiesAgainstAllFeeds, getVulnFeedChainSteps } = await import('../lib/vuln-feeds');
        let scanData: any = undefined;
        let vulnSteps: Array<{ techniqueId: string; priority: number; source: "vuln_feed"; context: string; corroborationTier?: string }> = [];
        if (input.scanId) {
          const scan = await db.getDomainIntelScanById(input.scanId);
          if (scan) {
            scanData = { pipelineOutput: scan.pipelineOutput, findings: [] };
            // Extract technologies and match against vuln feeds with version corroboration
            try {
              const pipelineAssets = (scan.pipelineOutput as any)?.assets || [];
              const techs = new Set<string>();
              const detectedVersions: Record<string, string> = {};
              pipelineAssets.forEach((a: any) => {
                const asset = a?.asset || a;
                ((asset.technologies || []) as string[]).forEach((t: string) => techs.add(t));
                if (asset.technologyVersions) {
                  Object.entries(asset.technologyVersions).forEach(([tech, ver]) => {
                    if (ver) detectedVersions[tech] = ver as string;
                  });
                }
              });
              if (techs.size > 0) {
                const vulnMatches = await matchTechnologiesAgainstAllFeeds(Array.from(techs));
                vulnSteps = getVulnFeedChainSteps(vulnMatches.matches, Object.keys(detectedVersions).length > 0 ? detectedVersions : undefined);
              }
            } catch (e) {
              console.warn('[Auto Chain Builder] Vuln feed enrichment failed:', e);
            }
          }
        }
        const results = await autoBuildAllChains({
          calderaBaseUrl: CALDERA_BASE_URL,
          calderaApiKey: CALDERA_API_KEY,
          scanData,
          vulnSteps,
        });
        return {
          totalOperations: results.length,
          results: results.map(r => ({
            operationId: r.operationId,
            operationName: r.operationName,
            adversaryName: r.adversaryName,
            totalAbilities: r.totalAbilities,
            techniquesCovered: r.techniquesCovered.length,
            techniquesNotCovered: r.techniquesNotCovered.length,
          })),
        };
      }),

    // Build chain with LLM intelligence
    buildChainWithLLM: protectedProcedure
      .input(z.object({
        operationId: z.string(),
        scanId: z.number(),
        campaignIndex: z.number(),
      }))
      .mutation(async ({ input }) => {
        const { buildChainWithLLM, buildOperationChain } = await import('../lib/chain-builder');
        const { matchTechnologiesAgainstAllFeeds, getVulnFeedChainSteps } = await import('../lib/vuln-feeds');
        const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
        const scan = await db.getDomainIntelScanById(input.scanId);
        const scanData = scan?.pipelineOutput as any;
        const campaigns = scanData?.campaignRecommendations || [];
        const actorMatches = scanData?.threatActorMatches?.topMatches || [];
        const campaign = campaigns[input.campaignIndex];
        if (!campaign) throw new TRPCError({ code: 'NOT_FOUND', message: 'Campaign recommendation not found' });

        // Enrich with vuln feed data — only confirmed/probable findings to prevent false-positive noise
        let vulnSteps: Array<{ techniqueId: string; priority: number; source: "vuln_feed"; context: string; corroborationTier?: string }> = [];
        try {
          const pipelineAssets = scanData?.assets || [];
          const techs = new Set<string>();
          const detectedVersions: Record<string, string> = {};
          pipelineAssets.forEach((a: any) => {
            const asset = a?.asset || a;
            ((asset.technologies || []) as string[]).forEach((t: string) => techs.add(t));
            if (asset.technologyVersions) {
              Object.entries(asset.technologyVersions).forEach(([tech, ver]) => {
                if (ver) detectedVersions[tech] = ver as string;
              });
            }
          });
          if (techs.size > 0) {
            const vulnMatches = await matchTechnologiesAgainstAllFeeds(Array.from(techs));
            vulnSteps = getVulnFeedChainSteps(vulnMatches.matches, Object.keys(detectedVersions).length > 0 ? detectedVersions : undefined);
          }
        } catch (e) {
          console.warn('[LLM Chain Builder] Vuln feed enrichment failed:', e);
        }
        const llmResult = await buildChainWithLLM({
          campaignRecommendation: campaign,
          orgProfile: (scanData as any)?.orgProfile,
          findings: [],
          threatActors: actorMatches,
          availableAbilities: abilities || [],
        });
        if (llmResult.selectedAbilities.length > 0) {
          const adversaryName = `llm-${campaign.name.replace(/[^a-zA-Z0-9]/g, '-').toLowerCase().substring(0, 40)}-${Date.now().toString(36)}`;
          const advResponse = await fetch(`${CALDERA_BASE_URL}/api/v2/adversaries`, {
            method: 'POST',
            headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name: adversaryName,
              description: `LLM-designed adversary. ${llmResult.reasoning}`,
              atomic_ordering: llmResult.selectedAbilities,
              tags: ['llm-generated', 'chain-builder'],
            }),
          });
          if (advResponse.ok) {
            const adv = await advResponse.json() as any;
            await fetch(`${CALDERA_BASE_URL}/api/v2/operations/${input.operationId}`, {
              method: 'PATCH',
              headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
              body: JSON.stringify({ adversary: { adversary_id: adv.adversary_id } }),
            });
            return { success: true, method: 'llm' as const, adversaryName, totalAbilities: llmResult.selectedAbilities.length, reasoning: llmResult.reasoning, attackNarrative: llmResult.attackNarrative };
          }
        }
        const kevChainSteps2 = (scanData as any)?.kevEnrichment?.chainSteps || [];
        const result = await buildOperationChain({
          operationId: input.operationId,
          scanId: input.scanId,
          campaignRecommendation: campaign,
          threatActorMatches: actorMatches,
          kevSteps: kevChainSteps2,
          vulnSteps,
          allAbilities: abilities || [],
          calderaBaseUrl: CALDERA_BASE_URL,
          calderaApiKey: CALDERA_API_KEY,
        });
        return { success: true, method: 'rule-based' as const, adversaryName: result.adversaryName, totalAbilities: result.totalAbilities, reasoning: 'Rule-based selection from campaign attack chain', attackNarrative: '' };
      }),

    // ─── Sigma/YARA Rule Validation Engine ───
    validateRule: protectedProcedure
      .input(z.object({
        ruleType: z.enum(['sigma', 'yara', 'suricata', 'splunk', 'kql']),
        ruleContent: z.string(),
        ruleName: z.string().optional(),
        techniqueId: z.string().optional(),
        sampleData: z.string().optional(),
        useLLM: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { validateRule } = await import('../lib/rule-validator');
        return validateRule({
          ruleType: input.ruleType,
          ruleContent: input.ruleContent,
          ruleName: input.ruleName,
          techniqueId: input.techniqueId,
          sampleData: input.sampleData,
        }, input.useLLM ?? true);
      }),

    validateRuleBatch: protectedProcedure
      .input(z.object({
        rules: z.array(z.object({
          ruleType: z.enum(['sigma', 'yara', 'suricata', 'splunk', 'kql']),
          ruleContent: z.string(),
          ruleName: z.string().optional(),
          techniqueId: z.string().optional(),
        })),
        useLLM: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { validateRuleBatch } = await import('../lib/rule-validator');
        return validateRuleBatch(input.rules, input.useLLM ?? false);
      }),

    generateSampleLog: protectedProcedure
      .input(z.object({ techniqueId: z.string() }))
      .query(async ({ input }) => {
        const { generateSampleLogData } = await import('../lib/rule-validator');
        return { sampleData: generateSampleLogData(input.techniqueId) };
      }),

    // ─── Detection Rule Generator ───
    generateActorRules: protectedProcedure
      .input(z.object({
        actorId: z.string(),
        useLLM: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { generateRulesForActor, generateRulesWithLLM } = await import('../lib/rule-generator');
        const actor = await db.getThreatActor(input.actorId);
        if (!actor) throw new TRPCError({ code: 'NOT_FOUND', message: 'Threat actor not found' });
        const techniques = (actor.techniques as Array<{ id: string; name: string; tactic: string }>) || [];
        const tools = (actor.tools as string[]) || [];
        const malware = (actor.malware as string[]) || [];
        if (input.useLLM) {
          return generateRulesWithLLM({
            actorName: actor.name,
            techniques,
            tools,
            malware,
            description: actor.description || undefined,
          });
        }
        return generateRulesForActor({ actorName: actor.name, techniques, tools, malware });
      }),

    // ─── Detection Coverage Matrix ───
    getDetectionCoverageMatrix: protectedProcedure
      .input(z.object({
        operationId: z.string().optional(),
      }))
      .query(async ({ input }) => {
        const { generateRulesForActor } = await import('../lib/rule-generator');

        // Get all operations
        const operations = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations');
        const ops = Array.isArray(operations) ? operations : [];
        const targetOps = input.operationId ? ops.filter((o: any) => o.id === input.operationId) : ops;

        // Collect all techniques used across operations
        const techniqueUsage: Record<string, {
          id: string; name: string; tactic: string;
          operations: Array<{ opId: string; opName: string; status: string }>;
        }> = {};

        for (const op of targetOps) {
          const chain = op.chain || [];
          for (const step of chain) {
            const ab = step.ability || {};
            const techId = ab.technique_id || 'unknown';
            if (techId === 'unknown') continue;
            if (!techniqueUsage[techId]) {
              techniqueUsage[techId] = {
                id: techId,
                name: ab.technique_name || ab.name || techId,
                tactic: ab.tactic || 'unknown',
                operations: [],
              };
            }
            const stepStatus = step.finish ? (step.status === 0 ? 'success' : 'failed') : 'running';
            const existing = techniqueUsage[techId].operations.find((o: any) => o.opId === op.id);
            if (!existing) {
              techniqueUsage[techId].operations.push({ opId: op.id, opName: op.name, status: stepStatus });
            }
          }
        }

        // Get all threat actors to generate rules
        const actorResult = await db.listThreatActors();
        const actors = actorResult.actors || [];
        const allActorTechniques: Array<{ id: string; name: string; tactic: string }> = [];
        for (const actor of actors) {
          const techs = (actor.techniques as Array<{ id: string; name: string; tactic: string }>) || [];
          allActorTechniques.push(...techs);
        }

        // Deduplicate techniques
        const uniqueTechMap = new Map<string, { id: string; name: string; tactic: string }>();
        for (const t of allActorTechniques) {
          if (!uniqueTechMap.has(t.id)) uniqueTechMap.set(t.id, t);
        }

        // Generate rules for coverage analysis
        const genResult = generateRulesForActor({
          actorName: 'All Actors',
          techniques: Array.from(uniqueTechMap.values()),
        });

        // Build coverage matrix
        const matrix: Array<{
          techniqueId: string;
          techniqueName: string;
          tactic: string;
          operationCoverage: Array<{ opId: string; opName: string; status: string }>;
          rulesCoverage: Array<{ ruleType: string; confidence: number; severity: string }>;
          coverageStatus: 'full' | 'partial' | 'rules-only' | 'ops-only' | 'none';
        }> = [];

        // Merge techniques from both operations and rules
        const allTechIds = new Set([
          ...Object.keys(techniqueUsage),
          ...genResult.rules.map(r => r.techniqueId),
        ]);

        for (const techId of Array.from(allTechIds)) {
          const opData = techniqueUsage[techId];
          const ruleData = genResult.rules.filter(r => r.techniqueId === techId);
          const techInfo = opData || uniqueTechMap.get(techId) || { id: techId, name: techId, tactic: 'unknown' };

          const hasOps = !!opData && opData.operations.length > 0;
          const hasRules = ruleData.length > 0;
          const hasHighConfRules = ruleData.some(r => r.confidence >= 65);

          let coverageStatus: 'full' | 'partial' | 'rules-only' | 'ops-only' | 'none' = 'none';
          if (hasOps && hasHighConfRules) coverageStatus = 'full';
          else if (hasOps && hasRules) coverageStatus = 'partial';
          else if (hasRules) coverageStatus = 'rules-only';
          else if (hasOps) coverageStatus = 'ops-only';

          matrix.push({
            techniqueId: techId,
            techniqueName: (techInfo as any).name || techId,
            tactic: (techInfo as any).tactic || 'unknown',
            operationCoverage: opData?.operations || [],
            rulesCoverage: ruleData.map(r => ({
              ruleType: r.ruleType,
              confidence: r.confidence,
              severity: r.severity,
            })),
            coverageStatus,
          });
        }

        // Sort by tactic order then technique ID
        const tacticOrder = ['reconnaissance','resource-development','initial-access','execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','exfiltration','impact'];
        matrix.sort((a, b) => {
          const aIdx = tacticOrder.indexOf(a.tactic);
          const bIdx = tacticOrder.indexOf(b.tactic);
          if (aIdx !== bIdx) return (aIdx === -1 ? 99 : aIdx) - (bIdx === -1 ? 99 : bIdx);
          return a.techniqueId.localeCompare(b.techniqueId);
        });

        // Summary stats
        const summary = {
          totalTechniques: matrix.length,
          fullCoverage: matrix.filter(m => m.coverageStatus === 'full').length,
          partialCoverage: matrix.filter(m => m.coverageStatus === 'partial').length,
          rulesOnly: matrix.filter(m => m.coverageStatus === 'rules-only').length,
          opsOnly: matrix.filter(m => m.coverageStatus === 'ops-only').length,
          noCoverage: matrix.filter(m => m.coverageStatus === 'none').length,
          totalOperations: targetOps.length,
          totalRules: genResult.totalRules,
          byTactic: Object.fromEntries(
            tacticOrder.map(t => [t, {
              total: matrix.filter(m => m.tactic === t).length,
              covered: matrix.filter(m => m.tactic === t && (m.coverageStatus === 'full' || m.coverageStatus === 'partial')).length,
            }])
          ),
        };

        return {
          matrix,
          summary,
          operations: targetOps.map((o: any) => ({ id: o.id, name: o.name, state: o.state })),
        };
      }),

    // ─── Post-Engagement Report Generator ───
    generateReport: protectedProcedure
      .input(z.object({
        operationId: z.string(),
        clientName: z.string().optional(),
        engagementType: z.string().optional(),
        customNotes: z.string().optional(),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input }) => {
        const { generateReport, renderReportHTML } = await import('../lib/report-generator');

        // Get operation detail
        const operations = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations');
        const op = Array.isArray(operations) ? operations.find((o: any) => o.id === input.operationId) : null;
        if (!op) throw new TRPCError({ code: 'NOT_FOUND', message: 'Operation not found' });

        const chain = op.chain || [];
        const totalSteps = chain.length;
        const completedSteps = chain.filter((s: any) => s.finish).length;
        const successSteps = chain.filter((s: any) => s.status === 0 && s.finish).length;
        const failedSteps = chain.filter((s: any) => s.status !== 0 && s.finish).length;

        // Build technique map
        const techniqueMap: Record<string, any> = {};
        for (const step of chain) {
          const ab = step.ability || {};
          const techId = ab.technique_id || 'unknown';
          if (!techniqueMap[techId]) {
            techniqueMap[techId] = {
              id: techId, name: ab.technique_name || ab.name || techId,
              tactic: ab.tactic || 'unknown', status: 'pending', steps: [],
            };
          }
          techniqueMap[techId].steps.push({
            id: step.id, abilityName: ab.name, abilityId: ab.ability_id,
            status: step.finish ? (step.status === 0 ? 'success' : 'failed') : 'running',
            paw: step.paw, finish: step.finish,
          });
          const statuses = techniqueMap[techId].steps.map((s: any) => s.status);
          if (statuses.includes('running')) techniqueMap[techId].status = 'running';
          else if (statuses.every((s: string) => s === 'success')) techniqueMap[techId].status = 'success';
          else if (statuses.some((s: string) => s === 'failed')) techniqueMap[techId].status = 'partial';
        }

        const timeline = chain.map((step: any) => ({
          time: step.decide || step.finish,
          finishTime: step.finish,
          abilityName: step.ability?.name || 'Unknown',
          techniqueId: step.ability?.technique_id || 'Unknown',
          status: step.finish ? (step.status === 0 ? 'success' : 'failed') : 'running',
          paw: step.paw,
        })).sort((a: any, b: any) => new Date(a.time).getTime() - new Date(b.time).getTime());

        const operationData = {
          ...op,
          techniques: Object.values(techniqueMap),
          timeline,
          metrics: {
            totalSteps, completedSteps, successSteps, failedSteps,
            pendingSteps: totalSteps - completedSteps,
            successRate: totalSteps > 0 ? Math.round((successSteps / totalSteps) * 100) : 0,
            detectionRate: totalSteps > 0 ? Math.round((failedSteps / totalSteps) * 100) : 0,
            progress: totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0,
          },
        };

        // Get coverage data
        let coverageData = null;
        try {
          const { generateRulesForActor } = await import('../lib/rule-generator');
          const actorResult = await db.listThreatActors();
          const actors = actorResult.actors || [];
          const allTechs: Array<{ id: string; name: string; tactic: string }> = [];
          for (const actor of actors) {
            const techs = (actor.techniques as Array<{ id: string; name: string; tactic: string }>) || [];
            allTechs.push(...techs);
          }
          const uniqueTechMap = new Map<string, { id: string; name: string; tactic: string }>();
          for (const t of allTechs) { if (!uniqueTechMap.has(t.id)) uniqueTechMap.set(t.id, t); }
          const genResult = generateRulesForActor({ actorName: 'All Actors', techniques: Array.from(uniqueTechMap.values()) });

          const techUsage: Record<string, any> = {};
          for (const step of chain) {
            const ab = step.ability || {};
            const techId = ab.technique_id || 'unknown';
            if (techId === 'unknown') continue;
            if (!techUsage[techId]) techUsage[techId] = { operations: [] };
            if (!techUsage[techId].operations.find((o: any) => o.opId === op.id)) {
              techUsage[techId].operations.push({ opId: op.id, opName: op.name, status: step.finish ? (step.status === 0 ? 'success' : 'failed') : 'running' });
            }
          }

          const allTechIds = new Set([...Object.keys(techUsage), ...genResult.rules.map(r => r.techniqueId)]);
          const matrix: any[] = [];
          for (const techId of Array.from(allTechIds)) {
            const opData = techUsage[techId];
            const ruleData = genResult.rules.filter(r => r.techniqueId === techId);
            const hasOps = !!opData && opData.operations.length > 0;
            const hasRules = ruleData.length > 0;
            const hasHighConf = ruleData.some(r => r.confidence >= 65);
            let coverageStatus = 'none';
            if (hasOps && hasHighConf) coverageStatus = 'full';
            else if (hasOps && hasRules) coverageStatus = 'partial';
            else if (hasRules) coverageStatus = 'rules-only';
            else if (hasOps) coverageStatus = 'ops-only';
            matrix.push({ techniqueId: techId, techniqueName: (uniqueTechMap.get(techId) as any)?.name || techId, tactic: (uniqueTechMap.get(techId) as any)?.tactic || 'unknown', coverageStatus });
          }
          coverageData = {
            matrix,
            summary: {
              totalTechniques: matrix.length,
              fullCoverage: matrix.filter(m => m.coverageStatus === 'full').length,
              partialCoverage: matrix.filter(m => m.coverageStatus === 'partial').length,
              opsOnly: matrix.filter(m => m.coverageStatus === 'ops-only').length,
              noCoverage: matrix.filter(m => m.coverageStatus === 'none').length,
            },
          };
        } catch (e) { console.error('Coverage data fetch failed:', e); }

        // Get threat actors
        let threatActors: Array<{ name: string; techniques: number; type: string }> = [];
        try {
          const actorResult = await db.listThreatActors();
          threatActors = (actorResult.actors || []).map((a: any) => ({
            name: a.name, techniques: Array.isArray(a.techniques) ? a.techniques.length : 0, type: a.type,
          }));
        } catch (e) { /* ignore */ }

        // Fetch engagement ops data if engagementId provided
        let engagementOpsData: any = undefined;
        if (input.engagementId) {
          const { getOpsState } = await import('../lib/engagement-orchestrator');
          const opsState = getOpsState(input.engagementId);
          if (opsState) {
            engagementOpsData = {
              assets: opsState.assets.map(a => ({
                hostname: a.hostname,
                ip: a.ip,
                type: a.type,
                status: a.status,
                knownPorts: a.knownPorts,
                passiveRecon: a.passiveRecon,
                toolResults: a.toolResults,
              })),
              scanPlan: opsState.scanPlan,
              passiveReconResults: opsState.passiveReconResults,
            };
          }
        }

        const report = await generateReport({
          operationId: input.operationId,
          operationData,
          coverageData,
          threatActors,
          clientName: input.clientName,
          engagementType: input.engagementType,
          customNotes: input.customNotes,
          engagementOpsData,
        });

        const html = renderReportHTML(report);
        return { report, html };
      }),

    generateAndValidateActorRules: protectedProcedure
      .input(z.object({
        actorId: z.string(),
        useLLM: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { generateRulesForActor } = await import('../lib/rule-generator');
        const { validateRule } = await import('../lib/rule-validator');
        const actor = await db.getThreatActor(input.actorId);
        if (!actor) throw new TRPCError({ code: 'NOT_FOUND', message: 'Threat actor not found' });
        const techniques = (actor.techniques as Array<{ id: string; name: string; tactic: string }>) || [];
        const tools = (actor.tools as string[]) || [];
        const malware = (actor.malware as string[]) || [];
        const genResult = generateRulesForActor({ actorName: actor.name, techniques, tools, malware });
        // Validate each rule (no LLM to keep it fast)
        const validated = await Promise.all(
          genResult.rules.map(async (rule) => {
            const validation = await validateRule({
              ruleType: rule.ruleType,
              ruleContent: rule.ruleContent,
              ruleName: rule.ruleName,
              techniqueId: rule.techniqueId,
            }, false);
            return { ...rule, validation };
          })
        );
        return { ...genResult, rules: validated };
      }),

    // ─── CISA KEV Endpoints ───
    getKevCatalog: protectedProcedure
      .query(async () => {
        const { fetchKevCatalog, getKevStats } = await import('../lib/kev-service');
        const catalog = await fetchKevCatalog();
        const stats = getKevStats(catalog);
        const vulns = catalog.vulnerabilities || [];
        return {
          totalVulnerabilities: vulns.length,
          catalogVersion: catalog.catalogVersion,
          dateReleased: catalog.dateReleased,
          vulnerabilities: vulns.slice(0, 500),
          ransomwareCount: stats.ransomwareLinked,
          recentlyAdded: stats.recentlyAdded,
          topVendors: stats.topVendors,
          topProducts: stats.topProducts,
        };
      }),

    searchKev: protectedProcedure
      .input(z.object({
        query: z.string().optional(),
        vendor: z.string().optional(),
        product: z.string().optional(),
        ransomwareOnly: z.boolean().optional(),
        limit: z.number().optional(),
      }))
      .query(async ({ input }) => {
        const { fetchKevCatalog } = await import('../lib/kev-service');
        const catalog = await fetchKevCatalog();
        let results = catalog.vulnerabilities || [];
        if (input.query) {
          const q = input.query.toLowerCase();
          results = results.filter((v) =>
            v.cveID?.toLowerCase().includes(q) ||
            v.vulnerabilityName?.toLowerCase().includes(q) ||
            v.vendorProject?.toLowerCase().includes(q) ||
            v.product?.toLowerCase().includes(q) ||
            v.shortDescription?.toLowerCase().includes(q)
          );
        }
        if (input.vendor) {
          results = results.filter((v) => v.vendorProject?.toLowerCase().includes(input.vendor!.toLowerCase()));
        }
        if (input.product) {
          results = results.filter((v) => v.product?.toLowerCase().includes(input.product!.toLowerCase()));
        }
        if (input.ransomwareOnly) {
          results = results.filter((v) => v.knownRansomwareCampaignUse === 'Known');
        }
        return { total: results.length, results: results.slice(0, input.limit || 100) };
      }),

    matchKevToScan: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const { fetchKevCatalog, matchTechnologiesAgainstKev, calculateKevRiskBoost, getKevChainSteps } = await import('../lib/kev-service');
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        const pipeline = scan.pipelineOutput as any;
        const allTechs = (pipeline?.assets || []).flatMap((a: any) => a?.asset?.technologies || []);
        const uniqueTechs = Array.from(new Set(allTechs.filter(Boolean))) as string[];
        const catalog = await fetchKevCatalog();
        const matches = matchTechnologiesAgainstKev(uniqueTechs, catalog);
        const boost = calculateKevRiskBoost(matches);
        const chainSteps = getKevChainSteps(matches);
        return {
          scanId: input.scanId,
          domain: scan.primaryDomain,
          technologiesScanned: uniqueTechs.length,
          kevMatches: matches,
          riskBoost: boost,
          chainSteps,
        };
      }),

    // ─── Unified Vulnerability Feed Endpoints ───
    getVulnFeedStats: protectedProcedure
      .query(async () => {
        const { getVulnFeedStats } = await import('../lib/vuln-feeds');
        return getVulnFeedStats();
      }),

    getVulnTrendData: protectedProcedure
      .input(z.object({ days: z.number().optional() }).optional())
      .query(async ({ input }) => {
        const { getVulnTrendData } = await import('../lib/vuln-feeds');
        return getVulnTrendData(input?.days || 7);
      }),

    getRecentZeroDays: protectedProcedure
      .input(z.object({ limit: z.number().optional() }).optional())
      .query(async ({ input }) => {
        const { getRecentZeroDays } = await import('../lib/vuln-feeds');
        return getRecentZeroDays(input?.limit || 50);
      }),

    getWeaponizedCves: protectedProcedure
      .input(z.object({ limit: z.number().optional() }).optional())
      .query(async ({ input }) => {
        const { getWeaponizedCves } = await import('../lib/vuln-feeds');
        return getWeaponizedCves(input?.limit || 50);
      }),

    getCveDetail: protectedProcedure
      .input(z.object({ cveId: z.string() }))
      .query(async ({ input }) => {
        const { searchVulnerabilities } = await import('../lib/vuln-feeds');
        const results = await searchVulnerabilities(input.cveId, {}, 1);
        const vuln = results.find(r => r.cveId === input.cveId) || results[0] || null;
        if (!vuln) return null;

        // Enrich with exploit matching
        let exploitMatches: any = null;
        try {
          const { matchExploitsToFindings } = await import('../lib/exploit-matcher');
          const matches = await matchExploitsToFindings([{
            title: vuln.title || vuln.cveId,
            cveIds: [vuln.cveId],
            severity: vuln.cvssScore || 7,
            corroborationTier: 'confirmed',
          }]);
          if (matches.matches.length > 0) {
            exploitMatches = matches.matches[0];
          }
        } catch (e) {
          // Exploit matching is optional enrichment
        }

        // Check for threat actor associations from local DB
        let associatedActors: any[] = [];
        try {
          const dbConn = await (await import('../db')).getDb();
          if (dbConn) {
            const { threatActors } = await import('../../drizzle/schema');
            const { sql } = await import('drizzle-orm');
            const actors = await dbConn.select({
              actorId: threatActors.actorId,
              name: threatActors.name,
              type: threatActors.type,
              origin: threatActors.origin,
              threatLevel: threatActors.threatLevel,
            }).from(threatActors)
              .where(sql`JSON_CONTAINS(${threatActors.techniques}, JSON_QUOTE(${input.cveId}))`)
              .limit(10);
            associatedActors = actors;
          }
        } catch (e) {
          // Actor association is optional enrichment
        }

        return {
          ...vuln,
          exploitMatches,
          associatedActors,
        };
      }),

    searchVulnerabilities: protectedProcedure
      .input(z.object({
        query: z.string(),
        severity: z.string().optional(),
        source: z.enum(['cisa_kev', 'project_zero', 'nvd', 'circl', 'exploit_db']).optional(),
        exploitOnly: z.boolean().optional(),
        kevOnly: z.boolean().optional(),
        zeroDayOnly: z.boolean().optional(),
        limit: z.number().optional(),
      }))
      .query(async ({ input }) => {
        const { searchVulnerabilities } = await import('../lib/vuln-feeds');
        const { query, limit, ...filters } = input;
        return searchVulnerabilities(query, filters, limit || 100);
      }),

    matchTechVulns: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const { matchTechnologiesAgainstAllFeeds } = await import('../lib/vuln-feeds');
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new Error('Scan not found');
        const output = scan.pipelineOutput as any;
        const techs = new Set<string>();
        (output?.assets || []).forEach((a: any) => {
          // Handle both nested (a.asset.technologies) and flat (a.technologies) structures
          const techList = a.technologies || a.asset?.technologies || [];
          (Array.isArray(techList) ? techList : []).forEach((t: string) => techs.add(t));
        });
        // Also pull technologies from discovered_assets DB rows as fallback
        const dbAssets = await db.getDiscoveredAssetsByScan(input.scanId);
        dbAssets.forEach((a: any) => {
          const techList = a.technologies || [];
          (Array.isArray(techList) ? techList : []).forEach((t: string) => techs.add(t));
        });
        // Extract detected versions from scan data for tier classification
        const detectedVersions: Record<string, string> = {};
        (output?.assets || []).forEach((a: any) => {
          const versions = a.detectedVersions || a.asset?.detectedVersions || {};
          if (typeof versions === 'object') {
            Object.entries(versions).forEach(([k, v]) => { if (typeof v === 'string') detectedVersions[k] = v; });
          }
        });
        return matchTechnologiesAgainstAllFeeds(Array.from(techs), detectedVersions);
      }),

    enrichCve: protectedProcedure
      .input(z.object({ cveId: z.string() }))
      .query(async ({ input }) => {
        const { enrichCve } = await import('../lib/vuln-feeds');
        return enrichCve(input.cveId);
      }),

    triggerSync: protectedProcedure
      .mutation(async () => {
        const { runVulnFeedSync } = await import('../lib/vuln-feed-sync');
        return runVulnFeedSync('manual');
      }),
  });
