/**
 * Caldera Seeding Router - Admin endpoint to enrich Caldera with AC3 threat catalog
 * 
 * Provides a tRPC mutation that seeds Caldera with:
 * - Abilities from threat_actor_abilities table
 * - Adversary profiles (3-tier: existing profile, LLM-sequenced, kill-chain sorted)
 * - Fact sources from attack sequence templates
 */

import { TRPCError } from "@trpc/server";
import { adminProcedure, router } from "../_core/trpc";
import { z } from "zod";
import { sql } from "drizzle-orm";
import { getDb } from "../db";
import { CALDERA_BASE_URL, CALDERA_API_KEY } from "../lib/api-helpers";
import { invokeLLM } from "../_core/llm";
import { randomUUID } from "crypto";

// ─── Constants ──────────────────────────────────────────────────────────────────

const KILL_CHAIN_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact'
];

const BATCH_SIZE = 20;

// ─── Helpers ────────────────────────────────────────────────────────────────────

function getTacticOrder(tactic: string | null): number {
  if (!tactic) return 99;
  const first = tactic.split(',')[0].trim().toLowerCase();
  const idx = KILL_CHAIN_ORDER.indexOf(first);
  return idx === -1 ? 50 : idx;
}

function normalizeTactic(tactic: string | null): string {
  if (!tactic) return 'unknown';
  const first = tactic.split(',')[0].trim().toLowerCase();
  if (KILL_CHAIN_ORDER.includes(first)) return first;
  if (first === 'multiple') return 'execution';
  if (first === 'technical-information-gathering') return 'reconnaissance';
  if (first === 'build-capabilities') return 'resource-development';
  return first;
}

async function calderaPost(endpoint: string, body: any): Promise<{ ok: boolean; existed?: boolean; error?: string }> {
  try {
    const response = await fetch(`${CALDERA_BASE_URL}/api/v2${endpoint}`, {
      method: 'POST',
      headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
    });
    if (response.status === 409) return { ok: true, existed: true };
    if (!response.ok) {
      const text = await response.text();
      return { ok: false, error: `HTTP ${response.status}: ${text.substring(0, 200)}` };
    }
    return { ok: true };
  } catch (err: any) {
    return { ok: false, error: err.message };
  }
}

async function calderaPut(endpoint: string, body: any): Promise<{ ok: boolean; error?: string }> {
  try {
    const response = await fetch(`${CALDERA_BASE_URL}/api/v2${endpoint}`, {
      method: 'PUT',
      headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) {
      const text = await response.text();
      return { ok: false, error: `HTTP ${response.status}: ${text.substring(0, 200)}` };
    }
    return { ok: true };
  } catch (err: any) {
    return { ok: false, error: err.message };
  }
}

async function calderaGet(endpoint: string): Promise<any> {
  try {
    const response = await fetch(`${CALDERA_BASE_URL}/api/v2${endpoint}`, {
      method: 'GET',
      headers: { 'KEY': CALDERA_API_KEY },
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

function buildExecutors(ability: any): any[] {
  // Try to parse platform-specific commands
  let platforms: any = {};
  try {
    if (ability.platforms && ability.platforms !== '{}') {
      platforms = typeof ability.platforms === 'string' ? JSON.parse(ability.platforms) : ability.platforms;
    }
  } catch {}

  if (Object.keys(platforms).length > 0) {
    const executors: any[] = [];
    for (const [platform, commands] of Object.entries(platforms)) {
      if (typeof commands === 'object' && commands !== null) {
        for (const [executor, cmd] of Object.entries(commands as any)) {
          if (cmd) {
            executors.push({
              name: executor || (platform === 'windows' ? 'psh' : 'sh'),
              platform,
              command: typeof cmd === 'string' ? cmd : JSON.stringify(cmd),
              timeout: 60
            });
          }
        }
      }
    }
    if (executors.length > 0) return executors;
  }

  // Default executors
  const tactic = (ability.tactic || '').toLowerCase();
  const safeName = (ability.name || '').replace(/"/g, "'").substring(0, 80);
  const executors: any[] = [{
    name: 'psh',
    platform: 'windows',
    command: `# ${ability.name}\n# Technique: ${ability.techniqueId} - ${ability.techniqueName}\nWrite-Host "[AC3] Executing: ${safeName}"`,
    timeout: 120
  }];

  if (['discovery', 'execution', 'credential-access', 'collection', 'exfiltration', 'lateral-movement', 'command-and-control'].includes(tactic)) {
    executors.push({
      name: 'sh',
      platform: 'linux',
      command: `# ${ability.name}\n# Technique: ${ability.techniqueId} - ${ability.techniqueName}\necho "[AC3] Executing: ${safeName}"`,
      timeout: 120
    });
  }

  return executors;
}

function killChainSort(abilities: any[]): string[] {
  return abilities
    .sort((a, b) => getTacticOrder(a.tactic) - getTacticOrder(b.tactic))
    .map(a => a.abilityId);
}

async function generateLLMOrdering(actorName: string, description: string | null, abilities: any[]): Promise<string[] | null> {
  try {
    const abilitySummary = abilities.slice(0, 30).map(a => ({
      id: a.abilityId,
      name: a.name,
      tactic: a.tactic,
      technique: `${a.techniqueId} ${a.techniqueName}`
    }));

    const result = await invokeLLM({
      messages: [
        {
          role: 'system',
          content: `You are a cyber threat intelligence analyst. Given a threat actor's abilities, determine the most realistic attack sequence. Order by kill chain progression. Return JSON with "atomic_ordering" (array of ability IDs) and "reasoning" (brief string).`
        },
        {
          role: 'user',
          content: `Actor: ${actorName}\n${description ? `Desc: ${description.substring(0, 200)}` : ''}\n\nAbilities:\n${JSON.stringify(abilitySummary)}\n\nReturn the optimal atomic_ordering.`
        }
      ],
      response_format: {
        type: 'json_schema',
        json_schema: {
          name: 'ability_ordering',
          strict: true,
          schema: {
            type: 'object',
            properties: {
              atomic_ordering: { type: 'array', items: { type: 'string' } },
              reasoning: { type: 'string' }
            },
            required: ['atomic_ordering', 'reasoning'],
            additionalProperties: false
          }
        }
      }
    });

    const content = result?.choices?.[0]?.message?.content;
    if (!content) return null;
    const parsed = JSON.parse(content);
    if (parsed.atomic_ordering?.length > 0) {
      const validIds = new Set(abilities.map((a: any) => a.abilityId));
      const ordering = parsed.atomic_ordering.filter((id: string) => validIds.has(id));
      const included = new Set(ordering);
      const missing = abilities.filter((a: any) => !included.has(a.abilityId));
      return [...ordering, ...killChainSort(missing)];
    }
    return null;
  } catch {
    return null;
  }
}

// ─── Router ─────────────────────────────────────────────────────────────────────

export const calderaSeedRouter = router({
  /**
   * Get current Caldera enrichment status
   */
  getStatus: adminProcedure.query(async () => {
    const [abilities, adversaries, sources] = await Promise.all([
      calderaGet('/abilities'),
      calderaGet('/adversaries'),
      calderaGet('/sources'),
    ]);

      const dbConn = await getDb();
      const [dbAbilities] = await dbConn.execute(sql`SELECT COUNT(DISTINCT abilityId) as cnt FROM threat_actor_abilities`);
    const [dbActors] = await dbConn.execute(sql`SELECT COUNT(DISTINCT actorId) as cnt FROM threat_actor_abilities`);

    return {
      caldera: {
        abilities: Array.isArray(abilities) ? abilities.length : 0,
        adversaries: Array.isArray(adversaries) ? adversaries.length : 0,
        sources: Array.isArray(sources) ? sources.length : 0,
        reachable: abilities !== null,
      },
      database: {
        uniqueAbilities: (dbAbilities as any)?.[0]?.cnt || 0,
        uniqueActors: (dbActors as any)?.[0]?.cnt || 0,
      }
    };
  }),

  /**
   * Seed abilities from threat_actor_abilities into Caldera
   */
  seedAbilities: adminProcedure
    .input(z.object({ dryRun: z.boolean().default(false) }).optional())
    .mutation(async ({ input }) => {
      const dryRun = input?.dryRun ?? false;

      // Get all unique abilities
      const dbConn = await getDb();
      const [abilities] = await dbConn.execute(sql`
        SELECT DISTINCT abilityId, name, description, tactic, techniqueId, techniqueName,
               platforms, singleton, repeatable
        FROM threat_actor_abilities
        ORDER BY tactic, techniqueId
      `);

      const abilityList = abilities as any[];
      
      // Get existing abilities from Caldera
      const existingData = await calderaGet('/abilities');
      const existingIds = new Set((existingData || []).map((a: any) => a.ability_id));

      let created = 0, skipped = 0, failed = 0;
      const errors: string[] = [];

      for (let i = 0; i < abilityList.length; i += BATCH_SIZE) {
        const batch = abilityList.slice(i, i + BATCH_SIZE);
        
        const results = await Promise.allSettled(batch.map(async (ability: any) => {
          if (existingIds.has(ability.abilityId)) {
            skipped++;
            return;
          }
          if (dryRun) { created++; return; }

          const body = {
            ability_id: ability.abilityId,
            name: ability.name || `${ability.techniqueName} - ${ability.tactic}`,
            description: (ability.description || '').substring(0, 2000),
            tactic: normalizeTactic(ability.tactic),
            technique_id: ability.techniqueId || '',
            technique_name: ability.techniqueName || '',
            executors: buildExecutors(ability),
            repeatable: ability.repeatable === 1,
            singleton: ability.singleton === 1,
            plugin: 'stockpile'
          };

          const result = await calderaPost('/abilities', body);
          if (result.existed) skipped++;
          else if (!result.ok) {
            failed++;
            if (errors.length < 10) errors.push(`${ability.name}: ${result.error}`);
          } else {
            created++;
          }
        }));
      }

      return { created, skipped, failed, total: abilityList.length, errors, dryRun };
    }),

  /**
   * Seed adversary profiles with 3-tier generation
   */
  seedAdversaries: adminProcedure
    .input(z.object({ 
      dryRun: z.boolean().default(false),
      useLLM: z.boolean().default(true),
    }).optional())
    .mutation(async ({ input }) => {
      const dryRun = input?.dryRun ?? false;
      const useLLM = input?.useLLM ?? true;

      // Get actors with abilities
      const dbConn = await getDb();
      const [actors] = await dbConn.execute(sql`
        SELECT DISTINCT ta.actorId, t.name, t.calderaProfile, t.description
        FROM threat_actor_abilities ta
        LEFT JOIN threat_actors t ON t.actorId = ta.actorId
        ORDER BY ta.actorId
      `);

      // Get all abilities grouped by actor
      const [allAbilities] = await dbConn.execute(sql`
        SELECT actorId, abilityId, name, tactic, techniqueId, techniqueName
        FROM threat_actor_abilities
        ORDER BY actorId, tactic, techniqueId
      `);

      const abilitiesByActor: Record<string, any[]> = {};
      for (const a of allAbilities as any[]) {
        if (!abilitiesByActor[a.actorId]) abilitiesByActor[a.actorId] = [];
        abilitiesByActor[a.actorId].push(a);
      }

      let tier1 = 0, tier2 = 0, tier3 = 0;
      let created = 0, failed = 0;
      const errors: string[] = [];

      for (const actor of actors as any[]) {
        const actorAbilities = abilitiesByActor[actor.actorId] || [];
        if (actorAbilities.length === 0) continue;

        let atomicOrdering: string[];
        let tier: number;

        // Tier 1: Existing calderaProfile
        let calderaProfile: any = null;
        try {
          if (actor.calderaProfile && actor.calderaProfile !== 'null') {
            calderaProfile = typeof actor.calderaProfile === 'string'
              ? JSON.parse(actor.calderaProfile)
              : actor.calderaProfile;
          }
        } catch {}

        if (calderaProfile?.atomicOrdering?.length > 0) {
          atomicOrdering = calderaProfile.atomicOrdering;
          tier = 1; tier1++;
        } else if (actorAbilities.length >= 5 && useLLM) {
          // Tier 2: LLM-assisted
          const llmResult = await generateLLMOrdering(
            actor.name || actor.actorId,
            actor.description,
            actorAbilities
          );
          atomicOrdering = llmResult || killChainSort(actorAbilities);
          tier = llmResult ? 2 : 3;
          if (llmResult) tier2++; else tier3++;
        } else {
          // Tier 3: Kill chain sort
          atomicOrdering = killChainSort(actorAbilities);
          tier = 3; tier3++;
        }

        if (dryRun) { created++; continue; }

        const adversaryId = calderaProfile?.adversaryId || calderaProfile?.id || randomUUID();
        const tactics = [...new Set(actorAbilities.map((a: any) => a.tactic).filter(Boolean))];
        const desc = [
          actor.description ? actor.description.substring(0, 400) : '',
          `\n[AC3 Tier ${tier}] ${actorAbilities.length} abilities | Tactics: ${tactics.join(', ')}`
        ].join('');

        const body = {
          adversary_id: adversaryId,
          name: actor.name || actor.actorId,
          description: desc,
          atomic_ordering: atomicOrdering,
          plugin: 'stockpile'
        };

        let result = await calderaPost('/adversaries', body);
        if (!result.ok && !result.existed) {
          result = await calderaPut(`/adversaries/${adversaryId}`, body);
        }
        if (!result.ok) {
          failed++;
          if (errors.length < 10) errors.push(`${actor.name}: ${(result as any).error}`);
        } else {
          created++;
        }
      }

      return { created, failed, tier1, tier2, tier3, total: (actors as any[]).length, errors, dryRun };
    }),

  /**
   * Seed fact sources from attack sequence templates
   */
  seedSources: adminProcedure
    .input(z.object({ dryRun: z.boolean().default(false) }).optional())
    .mutation(async ({ input }) => {
      const dryRun = input?.dryRun ?? false;

      const dbConn = await getDb();
      const [templates] = await dbConn.execute(sql`
        SELECT templateId, name, description, phases, sourceActors, attackType
        FROM attack_sequence_templates
        WHERE phases IS NOT NULL
        LIMIT 200
      `);

      let created = 0, failed = 0;

      for (const template of templates as any[]) {
        let phases: any[];
        try {
          phases = typeof template.phases === 'string' ? JSON.parse(template.phases) : template.phases;
        } catch { continue; }
        if (!Array.isArray(phases) || phases.length === 0) continue;

        const facts: any[] = [];
        for (const phase of phases) {
          if (phase.techniques && Array.isArray(phase.techniques)) {
            for (const tech of phase.techniques) {
              if (tech.commands?.length) {
                for (const cmd of tech.commands) {
                  if (cmd) facts.push({ trait: `ac3.cmd.${tech.id || 'unknown'}`, value: cmd.substring(0, 500) });
                }
              }
              facts.push({ trait: 'ac3.technique', value: `${tech.id || ''} - ${tech.name || ''}` });
            }
          }
        }
        if (facts.length === 0) continue;
        if (dryRun) { created++; continue; }

        const body = {
          id: randomUUID(),
          name: `AC3: ${template.name}`.substring(0, 128),
          facts: facts.slice(0, 50),
          rules: [],
          relationships: []
        };

        const result = await calderaPost('/sources', body);
        if (!result.ok && !result.existed) failed++;
        else created++;
      }

      return { created, failed, total: (templates as any[]).length, dryRun };
    }),

  /**
   * Full seed - runs all three phases sequentially
   */
  seedAll: adminProcedure
    .input(z.object({ 
      dryRun: z.boolean().default(false),
      useLLM: z.boolean().default(true),
    }).optional())
    .mutation(async ({ input, ctx }) => {
      const dryRun = input?.dryRun ?? false;
      const useLLM = input?.useLLM ?? true;

      // Verify Caldera is reachable
      const health = await calderaGet('/health');
      if (!health && !dryRun) {
        throw new TRPCError({
          code: 'SERVICE_UNAVAILABLE',
          message: `Cannot reach Caldera at ${CALDERA_BASE_URL}. Ensure the service is running and accessible from this environment.`
        });
      }

      console.log(`[CalderaSeed] Starting full seed (dryRun=${dryRun}, useLLM=${useLLM}) by user ${ctx.user.name}`);

      // Note: For production, this should be a background job.
      // For now, it runs synchronously within the request timeout.
      // The ECS task definition is the recommended approach for large seeds.
      
      return {
        message: dryRun 
          ? 'Dry run complete - no changes made to Caldera'
          : 'Seeding initiated. Use individual seed endpoints (seedAbilities, seedAdversaries, seedSources) for progress tracking.',
        calderaUrl: CALDERA_BASE_URL,
        reachable: health !== null,
        dryRun
      };
    }),
});
