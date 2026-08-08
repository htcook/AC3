#!/usr/bin/env node
/**
 * AC3 Caldera Seeding Script
 * 
 * Pulls threat intelligence data from the AC3 database and pushes it to the
 * internal Caldera instance to fully enrich it with:
 * - 1,940 unique abilities (mapped from threat_actor_abilities)
 * - 190 adversary profiles (from threat actors with mapped abilities)
 * - Attack sequence templates as operation blueprints
 * 
 * Three-tier adversary profile generation:
 * - Tier 1: Actors with existing calderaProfile (use stored atomic ordering)
 * - Tier 2: Actors with 5+ abilities (LLM-assisted kill chain sequencing)
 * - Tier 3: Actors with <5 abilities (simple kill chain sort)
 */

import mysql from 'mysql2/promise';
import { randomUUID } from 'crypto';

// ─── Configuration ──────────────────────────────────────────────────────────────
const CALDERA_BASE_URL = process.env.CALDERA_BASE_URL || 'http://caldera.ac3-dev.local:8888';
const CALDERA_API_KEY = process.env.CALDERA_API_KEY || 'ADMIN123';
const DATABASE_URL = process.env.DATABASE_URL;
const FORGE_API_URL = process.env.BUILT_IN_FORGE_API_URL;
const FORGE_API_KEY = process.env.BUILT_IN_FORGE_API_KEY;

const BATCH_SIZE = 50; // abilities per batch
const LLM_BATCH_SIZE = 5; // actors per LLM batch
const CONCURRENCY = 3; // parallel API calls
const RETRY_ATTEMPTS = 3;
const RETRY_DELAY_MS = 1000;

// MITRE ATT&CK Kill Chain ordering (for Tier 3 sorting)
const KILL_CHAIN_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact'
];

// ─── Helpers ────────────────────────────────────────────────────────────────────

function getTacticOrder(tactic) {
  if (!tactic) return 99;
  // Handle "multiple" tactic by taking the first one
  const firstTactic = tactic.split(',')[0].trim().toLowerCase();
  const idx = KILL_CHAIN_ORDER.indexOf(firstTactic);
  return idx === -1 ? 50 : idx;
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function retryFetch(url, options, attempts = RETRY_ATTEMPTS) {
  for (let i = 0; i < attempts; i++) {
    try {
      const response = await fetch(url, options);
      if (response.status === 409) {
        // Already exists - not an error
        return { status: 409, data: null, existed: true };
      }
      if (!response.ok) {
        const text = await response.text();
        if (i === attempts - 1) {
          return { status: response.status, data: null, error: text };
        }
        await sleep(RETRY_DELAY_MS * (i + 1));
        continue;
      }
      const data = await response.json();
      return { status: response.status, data, existed: false };
    } catch (err) {
      if (i === attempts - 1) {
        return { status: 0, data: null, error: err.message };
      }
      await sleep(RETRY_DELAY_MS * (i + 1));
    }
  }
}

async function calderaPost(endpoint, body) {
  return retryFetch(`${CALDERA_BASE_URL}/api/v2${endpoint}`, {
    method: 'POST',
    headers: {
      'KEY': CALDERA_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
}

async function calderaPut(endpoint, body) {
  return retryFetch(`${CALDERA_BASE_URL}/api/v2${endpoint}`, {
    method: 'PUT',
    headers: {
      'KEY': CALDERA_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
}

async function calderaGet(endpoint) {
  return retryFetch(`${CALDERA_BASE_URL}/api/v2${endpoint}`, {
    method: 'GET',
    headers: {
      'KEY': CALDERA_API_KEY,
    }
  });
}

async function invokeLLM(messages) {
  if (!FORGE_API_URL || !FORGE_API_KEY) {
    return null;
  }
  try {
    const response = await fetch(`${FORGE_API_URL}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${FORGE_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        messages,
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: 'ability_ordering',
            strict: true,
            schema: {
              type: 'object',
              properties: {
                atomic_ordering: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Ordered list of ability IDs representing the attack sequence'
                },
                reasoning: {
                  type: 'string',
                  description: 'Brief explanation of the ordering logic'
                }
              },
              required: ['atomic_ordering', 'reasoning'],
              additionalProperties: false
            }
          }
        }
      })
    });
    if (!response.ok) return null;
    const data = await response.json();
    return JSON.parse(data.choices[0].message.content);
  } catch (err) {
    console.error(`  [LLM] Error: ${err.message}`);
    return null;
  }
}

// ─── Database Connection ────────────────────────────────────────────────────────

async function getDbConnection() {
  if (!DATABASE_URL) {
    throw new Error('DATABASE_URL environment variable is required');
  }
  const connection = await mysql.createConnection(DATABASE_URL);
  return connection;
}

// ─── Phase 1: Seed Abilities ────────────────────────────────────────────────────

async function seedAbilities(db) {
  console.log('\n══════════════════════════════════════════════════════════════');
  console.log('  PHASE 1: Seeding Abilities');
  console.log('══════════════════════════════════════════════════════════════\n');

  // Get all unique abilities from the database
  const [abilities] = await db.execute(`
    SELECT DISTINCT abilityId, name, description, tactic, techniqueId, techniqueName,
           platforms, singleton, repeatable
    FROM threat_actor_abilities
    ORDER BY tactic, techniqueId
  `);

  console.log(`  Found ${abilities.length} unique abilities in database`);

  // Check what already exists in Caldera
  const existingRes = await calderaGet('/abilities');
  const existingAbilities = new Set();
  if (existingRes.data) {
    for (const a of existingRes.data) {
      existingAbilities.add(a.ability_id);
    }
    console.log(`  Caldera already has ${existingAbilities.size} abilities`);
  }

  let created = 0;
  let skipped = 0;
  let failed = 0;

  // Process in batches
  for (let i = 0; i < abilities.length; i += BATCH_SIZE) {
    const batch = abilities.slice(i, i + BATCH_SIZE);
    const promises = batch.map(async (ability) => {
      if (existingAbilities.has(ability.abilityId)) {
        skipped++;
        return;
      }

      // Determine platform and executor based on tactic
      const executors = buildExecutors(ability);
      
      const body = {
        ability_id: ability.abilityId,
        name: ability.name || `${ability.techniqueName} - ${ability.tactic}`,
        description: (ability.description || '').substring(0, 2000),
        tactic: normalizeTactic(ability.tactic),
        technique_id: ability.techniqueId || '',
        technique_name: ability.techniqueName || '',
        executors: executors,
        repeatable: ability.repeatable === 1,
        singleton: ability.singleton === 1,
        plugin: 'stockpile'
      };

      const result = await calderaPost('/abilities', body);
      if (result.existed) {
        skipped++;
      } else if (result.error) {
        failed++;
        if (failed <= 5) {
          console.error(`  [FAIL] ${ability.name}: ${result.error?.substring(0, 100)}`);
        }
      } else {
        created++;
      }
    });

    // Process batch with concurrency limit
    const chunks = [];
    for (let j = 0; j < promises.length; j += CONCURRENCY) {
      chunks.push(promises.slice(j, j + CONCURRENCY));
    }
    for (const chunk of chunks) {
      await Promise.all(chunk);
    }

    if ((i + BATCH_SIZE) % 200 === 0 || i + BATCH_SIZE >= abilities.length) {
      console.log(`  Progress: ${Math.min(i + BATCH_SIZE, abilities.length)}/${abilities.length} | Created: ${created} | Skipped: ${skipped} | Failed: ${failed}`);
    }
  }

  console.log(`\n  ✓ Abilities complete: ${created} created, ${skipped} skipped, ${failed} failed`);
  return { created, skipped, failed };
}

function normalizeTactic(tactic) {
  if (!tactic) return 'unknown';
  // Take first tactic if multiple
  const first = tactic.split(',')[0].trim().toLowerCase();
  if (KILL_CHAIN_ORDER.includes(first)) return first;
  // Map non-standard tactics
  if (first === 'multiple') return 'execution';
  if (first === 'technical-information-gathering') return 'reconnaissance';
  if (first === 'build-capabilities') return 'resource-development';
  return first;
}

function buildExecutors(ability) {
  // Parse platforms if available
  let platforms = {};
  try {
    if (ability.platforms && ability.platforms !== '{}') {
      platforms = JSON.parse(ability.platforms);
    }
  } catch (e) {}

  // If we have platform-specific commands, use them
  if (Object.keys(platforms).length > 0) {
    const executors = [];
    for (const [platform, commands] of Object.entries(platforms)) {
      if (typeof commands === 'object' && commands !== null) {
        for (const [executor, cmd] of Object.entries(commands)) {
          if (cmd) {
            executors.push({
              name: executor || (platform === 'windows' ? 'psh' : 'sh'),
              platform: platform,
              command: typeof cmd === 'string' ? cmd : JSON.stringify(cmd),
              timeout: 60
            });
          }
        }
      }
    }
    if (executors.length > 0) return executors;
  }

  // Default: create manual executors for common platforms
  const tactic = (ability.tactic || '').toLowerCase();
  const executors = [];

  // Windows executor (most abilities target Windows)
  executors.push({
    name: 'psh',
    platform: 'windows',
    command: `# ${ability.name}\n# Technique: ${ability.techniqueId} - ${ability.techniqueName}\n# Tactic: ${tactic}\nWrite-Host "[AC3] Executing: ${(ability.name || '').replace(/"/g, "'").substring(0, 80)}"`,
    timeout: 120
  });

  // Linux executor for relevant tactics
  if (['discovery', 'execution', 'credential-access', 'collection', 'exfiltration', 'lateral-movement', 'command-and-control'].includes(tactic)) {
    executors.push({
      name: 'sh',
      platform: 'linux',
      command: `# ${ability.name}\n# Technique: ${ability.techniqueId} - ${ability.techniqueName}\n# Tactic: ${tactic}\necho "[AC3] Executing: ${(ability.name || '').replace(/"/g, "'").substring(0, 80)}"`,
      timeout: 120
    });
  }

  return executors;
}

// ─── Phase 2: Seed Adversary Profiles ───────────────────────────────────────────

async function seedAdversaries(db) {
  console.log('\n══════════════════════════════════════════════════════════════');
  console.log('  PHASE 2: Seeding Adversary Profiles');
  console.log('══════════════════════════════════════════════════════════════\n');

  // Get all actors that have abilities mapped
  const [actorsWithAbilities] = await db.execute(`
    SELECT DISTINCT ta.actorId, t.name, t.calderaProfile, t.description
    FROM threat_actor_abilities ta
    LEFT JOIN threat_actors t ON t.actorId = ta.actorId
    ORDER BY ta.actorId
  `);

  console.log(`  Found ${actorsWithAbilities.length} actors with mapped abilities`);

  // Get all abilities grouped by actor for ordering
  const [allAbilities] = await db.execute(`
    SELECT actorId, abilityId, name, tactic, techniqueId, techniqueName
    FROM threat_actor_abilities
    ORDER BY actorId, tactic, techniqueId
  `);

  // Group abilities by actor
  const abilitiesByActor = {};
  for (const a of allAbilities) {
    if (!abilitiesByActor[a.actorId]) abilitiesByActor[a.actorId] = [];
    abilitiesByActor[a.actorId].push(a);
  }

  let tier1Count = 0, tier2Count = 0, tier3Count = 0;
  let created = 0, failed = 0;

  for (const actor of actorsWithAbilities) {
    const actorAbilities = abilitiesByActor[actor.actorId] || [];
    if (actorAbilities.length === 0) continue;

    let atomicOrdering;
    let tier;

    // ─── Tier 1: Use existing calderaProfile ────────────────────────────
    let calderaProfile = null;
    try {
      if (actor.calderaProfile && actor.calderaProfile !== 'null') {
        calderaProfile = typeof actor.calderaProfile === 'string' 
          ? JSON.parse(actor.calderaProfile) 
          : actor.calderaProfile;
      }
    } catch (e) {}

    if (calderaProfile && calderaProfile.atomicOrdering && calderaProfile.atomicOrdering.length > 0) {
      atomicOrdering = calderaProfile.atomicOrdering;
      tier = 1;
      tier1Count++;
    }
    // ─── Tier 2: LLM-assisted sequencing (5+ abilities) ────────────────
    else if (actorAbilities.length >= 5 && FORGE_API_URL) {
      atomicOrdering = await generateLLMOrdering(actor, actorAbilities);
      if (!atomicOrdering) {
        // Fallback to kill chain sort
        atomicOrdering = killChainSort(actorAbilities);
      }
      tier = 2;
      tier2Count++;
    }
    // ─── Tier 3: Simple kill chain sort ────────────────────────────────
    else {
      atomicOrdering = killChainSort(actorAbilities);
      tier = 3;
      tier3Count++;
    }

    // Create the adversary profile
    const adversaryId = calderaProfile?.adversaryId || calderaProfile?.id || randomUUID();
    const body = {
      adversary_id: adversaryId,
      name: actor.name || actor.actorId,
      description: buildAdversaryDescription(actor, actorAbilities, tier),
      atomic_ordering: atomicOrdering,
      plugin: 'stockpile'
    };

    const result = await calderaPost('/adversaries', body);
    if (result.error && result.status !== 409) {
      // Try PUT instead (create or update)
      const putResult = await calderaPut(`/adversaries/${adversaryId}`, body);
      if (putResult.error) {
        failed++;
        if (failed <= 5) {
          console.error(`  [FAIL] ${actor.name || actor.actorId}: ${putResult.error?.substring(0, 100)}`);
        }
      } else {
        created++;
      }
    } else {
      created++;
    }

    if (created % 20 === 0) {
      console.log(`  Progress: ${created + failed}/${actorsWithAbilities.length} | Tier1: ${tier1Count} | Tier2: ${tier2Count} | Tier3: ${tier3Count}`);
    }
  }

  console.log(`\n  ✓ Adversaries complete: ${created} created, ${failed} failed`);
  console.log(`    Tier 1 (existing profile): ${tier1Count}`);
  console.log(`    Tier 2 (LLM-sequenced): ${tier2Count}`);
  console.log(`    Tier 3 (kill chain sort): ${tier3Count}`);
  return { created, failed, tier1Count, tier2Count, tier3Count };
}

function killChainSort(abilities) {
  return abilities
    .sort((a, b) => getTacticOrder(a.tactic) - getTacticOrder(b.tactic))
    .map(a => a.abilityId);
}

function buildAdversaryDescription(actor, abilities, tier) {
  const tactics = [...new Set(abilities.map(a => a.tactic).filter(Boolean))];
  const techniques = [...new Set(abilities.map(a => a.techniqueId).filter(Boolean))];
  
  let desc = actor.description || '';
  if (desc.length > 500) desc = desc.substring(0, 500) + '...';
  
  const meta = [
    `[AC3 Auto-Generated | Tier ${tier}]`,
    `Abilities: ${abilities.length}`,
    `Tactics: ${tactics.join(', ')}`,
    `Techniques: ${techniques.length} unique`
  ].join(' | ');

  return desc ? `${desc}\n\n${meta}` : meta;
}

async function generateLLMOrdering(actor, abilities) {
  const abilitySummary = abilities.map(a => ({
    id: a.abilityId,
    name: a.name,
    tactic: a.tactic,
    technique: `${a.techniqueId} ${a.techniqueName}`
  }));

  const messages = [
    {
      role: 'system',
      content: `You are a cyber threat intelligence analyst specializing in adversary emulation. 
Given a list of MITRE ATT&CK abilities for a threat actor, determine the most realistic attack sequence (atomic ordering) based on known tradecraft patterns.

Rules:
- Order abilities following the typical kill chain progression
- Group related techniques that would logically execute together
- Consider dependencies (e.g., discovery before lateral movement)
- If the actor is known for specific TTPs, prioritize those patterns
- Return ALL ability IDs in the ordering (don't skip any)`
    },
    {
      role: 'user',
      content: `Threat Actor: ${actor.name || actor.actorId}
${actor.description ? `Description: ${actor.description.substring(0, 300)}` : ''}

Abilities to sequence (${abilities.length} total):
${JSON.stringify(abilitySummary, null, 1).substring(0, 3000)}

Generate the optimal atomic_ordering for this adversary's emulation profile.`
    }
  ];

  const result = await invokeLLM(messages);
  if (result && result.atomic_ordering && result.atomic_ordering.length > 0) {
    // Validate that all returned IDs exist in our abilities
    const validIds = new Set(abilities.map(a => a.abilityId));
    const ordering = result.atomic_ordering.filter(id => validIds.has(id));
    
    // Add any missing abilities at the end (sorted by kill chain)
    const included = new Set(ordering);
    const missing = abilities.filter(a => !included.has(a.abilityId));
    const missingSorted = killChainSort(missing);
    
    return [...ordering, ...missingSorted];
  }
  return null;
}

// ─── Phase 3: Seed Attack Sequence Templates as Sources ─────────────────────────

async function seedSources(db) {
  console.log('\n══════════════════════════════════════════════════════════════');
  console.log('  PHASE 3: Seeding Fact Sources from Attack Sequences');
  console.log('══════════════════════════════════════════════════════════════\n');

  // Get attack sequence templates with phases (these have technique/command data)
  const [templates] = await db.execute(`
    SELECT templateId, name, description, phases, sourceActors, attackType,
           ast_complexity, targetEnvironment
    FROM attack_sequence_templates
    WHERE phases IS NOT NULL
    LIMIT 100
  `);

  console.log(`  Found ${templates.length} attack sequence templates`);

  let created = 0;
  let failed = 0;

  for (const template of templates) {
    let phases;
    try {
      phases = typeof template.phases === 'string' ? JSON.parse(template.phases) : template.phases;
    } catch (e) { continue; }

    if (!phases || !Array.isArray(phases) || phases.length === 0) continue;

    // Create a Caldera source with facts derived from the template
    const sourceId = randomUUID();
    const facts = [];

    for (const phase of phases) {
      if (phase.techniques && Array.isArray(phase.techniques)) {
        for (const tech of phase.techniques) {
          if (tech.commands && Array.isArray(tech.commands)) {
            for (const cmd of tech.commands) {
              if (cmd) {
                facts.push({
                  trait: `ac3.attack_command.${tech.id || 'unknown'}`,
                  value: cmd.substring(0, 500)
                });
              }
            }
          }
          // Add technique as a fact
          facts.push({
            trait: 'ac3.technique',
            value: `${tech.id || ''} - ${tech.name || ''}`
          });
        }
      }
    }

    if (facts.length === 0) continue;

    const body = {
      id: sourceId,
      name: `AC3: ${template.name}`.substring(0, 128),
      facts: facts.slice(0, 50), // Caldera has limits on facts per source
      rules: [],
      relationships: []
    };

    const result = await calderaPost('/sources', body);
    if (result.error && result.status !== 409) {
      failed++;
    } else {
      created++;
    }
  }

  console.log(`\n  ✓ Sources complete: ${created} created, ${failed} failed`);
  return { created, failed };
}

// ─── Phase 4: Verify and Report ─────────────────────────────────────────────────

async function verify() {
  console.log('\n══════════════════════════════════════════════════════════════');
  console.log('  PHASE 4: Verification');
  console.log('══════════════════════════════════════════════════════════════\n');

  const [abilitiesRes, adversariesRes, sourcesRes] = await Promise.all([
    calderaGet('/abilities'),
    calderaGet('/adversaries'),
    calderaGet('/sources')
  ]);

  const abilities = abilitiesRes.data?.length || 0;
  const adversaries = adversariesRes.data?.length || 0;
  const sources = sourcesRes.data?.length || 0;

  console.log(`  Caldera now has:`);
  console.log(`    • ${abilities} abilities`);
  console.log(`    • ${adversaries} adversary profiles`);
  console.log(`    • ${sources} fact sources`);

  return { abilities, adversaries, sources };
}

// ─── Main ───────────────────────────────────────────────────────────────────────

async function main() {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║         AC3 Caldera Enrichment - Full Seed Script           ║');
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log(`║  Caldera: ${CALDERA_BASE_URL.padEnd(48)}║`);
  console.log(`║  LLM:     ${FORGE_API_URL ? 'Enabled'.padEnd(48) : 'Disabled (Tier 2 will fallback to Tier 3)'.padEnd(48)}║`);
  console.log('╚══════════════════════════════════════════════════════════════╝');

  // Test Caldera connectivity
  console.log('\n  Testing Caldera connectivity...');
  const healthCheck = await retryFetch(`${CALDERA_BASE_URL}/api/v2/health`, {
    method: 'GET',
    headers: { 'KEY': CALDERA_API_KEY }
  });
  
  if (healthCheck.error) {
    console.error(`  ✗ Cannot reach Caldera at ${CALDERA_BASE_URL}: ${healthCheck.error}`);
    console.error('  Make sure the script is running from within the VPC (ECS task or VPN)');
    process.exit(1);
  }
  console.log('  ✓ Caldera is reachable');

  // Connect to database
  const db = await getDbConnection();
  console.log('  ✓ Database connected');

  try {
    const abilityResults = await seedAbilities(db);
    const adversaryResults = await seedAdversaries(db);
    const sourceResults = await seedSources(db);
    const verification = await verify();

    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║                    SEEDING COMPLETE                          ║');
    console.log('╠══════════════════════════════════════════════════════════════╣');
    console.log(`║  Abilities:   ${String(abilityResults.created).padStart(5)} created, ${String(abilityResults.skipped).padStart(5)} skipped    ║`);
    console.log(`║  Adversaries: ${String(adversaryResults.created).padStart(5)} created (T1:${adversaryResults.tier1Count} T2:${adversaryResults.tier2Count} T3:${adversaryResults.tier3Count})    ║`);
    console.log(`║  Sources:     ${String(sourceResults.created).padStart(5)} created                        ║`);
    console.log('╠══════════════════════════════════════════════════════════════╣');
    console.log(`║  Total in Caldera: ${verification.abilities} abilities, ${verification.adversaries} adversaries  ║`);
    console.log('╚══════════════════════════════════════════════════════════════╝');
  } finally {
    await db.end();
  }
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
