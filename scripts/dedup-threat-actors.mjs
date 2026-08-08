/**
 * Threat Actor Deduplication Script
 * 
 * Handles 3 categories of duplicates:
 * 1. G-code duplicates: "APT28 (G0007)" → merge into "APT28"
 * 2. IAB prefix duplicates: "iab-prophet-spider" → merge into "prophet-spider"
 * 3. LLM-enriched duplicates: "scattered_spider" → merge into "scattered-spider"
 * 4. Exact name duplicates: same name, different actorId
 * 
 * Also removes AceofCloud IDP Compromise entries (caldera engagement artifacts)
 * 
 * Strategy: Keep canonical (oldest/most-sourced), merge all unique data from duplicates
 */

import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: join(__dirname, '..', '.env') });

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL not set');
  process.exit(1);
}

// Parse the connection URL
function parseDbUrl(url) {
  const u = new URL(url);
  return {
    host: u.hostname,
    port: parseInt(u.port) || 3306,
    user: u.username,
    password: decodeURIComponent(u.password),
    database: u.pathname.slice(1),
    ssl: { rejectUnauthorized: true },
  };
}

// Parse JSON safely, handling double-encoding
function parseJsonArray(val) {
  if (!val) return [];
  if (Array.isArray(val)) return val;
  if (typeof val === 'string') {
    try {
      let parsed = JSON.parse(val);
      // Handle double-encoded: "\"[...]\"" 
      if (typeof parsed === 'string') {
        try { parsed = JSON.parse(parsed); } catch {}
      }
      return Array.isArray(parsed) ? parsed : [];
    } catch { return []; }
  }
  return [];
}

// Merge JSON arrays, deduplicating by value
function mergeJsonArrays(a, b) {
  const setA = new Set();
  const result = [];
  
  for (const item of parseJsonArray(a)) {
    const key = typeof item === 'object' ? JSON.stringify(item) : String(item);
    if (!setA.has(key)) {
      setA.add(key);
      result.push(item);
    }
  }
  for (const item of parseJsonArray(b)) {
    const key = typeof item === 'object' ? JSON.stringify(item) : String(item);
    if (!setA.has(key)) {
      setA.add(key);
      result.push(item);
    }
  }
  return result;
}

// Merge JSON objects (shallow merge, prefer non-null values)
function mergeJsonObjects(a, b) {
  const parseObj = (val) => {
    if (!val) return {};
    if (typeof val === 'string') {
      try { return JSON.parse(val); } catch { return {}; }
    }
    return typeof val === 'object' ? val : {};
  };
  return { ...parseObj(a), ...parseObj(b) };
}

// Pick the "better" scalar value (prefer non-null, longer, more specific)
function pickBetter(a, b) {
  if (!a && !b) return null;
  if (!a) return b;
  if (!b) return a;
  // Prefer the longer/more specific value
  if (String(a).length > String(b).length) return a;
  return b;
}

// Merge two threat actor records, keeping canonical as base
function mergeActors(canonical, duplicate) {
  const merged = { ...canonical };
  
  // Merge JSON array fields
  const arrayFields = ['aliases', 'targetSectors', 'targetRegions', 'techniques', 'tools', 'malware', 'activityTimeline', 'enrichment_sources'];
  for (const field of arrayFields) {
    merged[field] = JSON.stringify(mergeJsonArrays(canonical[field], duplicate[field]));
  }
  
  // Merge JSON object fields
  const objectFields = ['calderaProfile'];
  for (const field of objectFields) {
    merged[field] = JSON.stringify(mergeJsonObjects(canonical[field], duplicate[field]));
  }
  
  // Pick better scalar values (prefer non-null, more specific)
  merged.description = pickBetter(canonical.description, duplicate.description);
  merged.motivation = pickBetter(canonical.motivation, duplicate.motivation);
  merged.origin = pickBetter(canonical.origin, duplicate.origin);
  merged.firstSeen = pickBetter(canonical.firstSeen, duplicate.firstSeen);
  merged.stixId = pickBetter(canonical.stixId, duplicate.stixId);
  merged.logoUrl = pickBetter(canonical.logoUrl, duplicate.logoUrl);
  
  // For lastActive, pick the most recent
  if (duplicate.lastActive && (!canonical.lastActive || duplicate.lastActive > canonical.lastActive)) {
    merged.lastActive = duplicate.lastActive;
  }
  
  // For threatLevel, pick the higher severity
  const levels = { critical: 4, high: 3, medium: 2, low: 1 };
  if (levels[duplicate.threatLevel] > levels[canonical.threatLevel]) {
    merged.threatLevel = duplicate.threatLevel;
  }
  
  // For sophistication, pick the higher
  const sophLevels = { 'nation-state': 4, advanced: 3, intermediate: 2, basic: 1 };
  if (sophLevels[duplicate.sophistication] > sophLevels[canonical.sophistication]) {
    merged.sophistication = duplicate.sophistication;
  }
  
  // For confidence, pick the higher
  if (duplicate.confidence && (!canonical.confidence || duplicate.confidence > canonical.confidence)) {
    merged.confidence = duplicate.confidence;
  }
  
  // Merge dataSource strings
  const sources = new Set([
    ...(canonical.dataSource || '').split(',').map(s => s.trim()).filter(Boolean),
    ...(duplicate.dataSource || '').split(',').map(s => s.trim()).filter(Boolean),
  ]);
  merged.dataSource = [...sources].join(',');
  
  // Add the duplicate's actorId as an alias if different
  const aliases = mergeJsonArrays(canonical.aliases, duplicate.aliases);
  if (duplicate.actorId !== canonical.actorId && !aliases.includes(duplicate.actorId)) {
    aliases.push(duplicate.actorId);
  }
  if (duplicate.name !== canonical.name && !aliases.includes(duplicate.name)) {
    aliases.push(duplicate.name);
  }
  merged.aliases = JSON.stringify(aliases);
  
  return merged;
}

async function main() {
  const conn = await mysql.createConnection(parseDbUrl(DATABASE_URL));
  console.log('Connected to database');
  
  let totalMerged = 0;
  let totalDeleted = 0;
  let totalEventsUpdated = 0;
  
  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 0: Remove AceofCloud IDP Compromise entries (caldera engagement artifacts)
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n═══ STEP 0: Removing AceofCloud IDP Compromise entries ═══');
  
  const aceofcloudIds = [150001, 150002, 150003, 210001];
  const aceofcloudActorIds = [
    'aceofcloud-idp-compromise-apt29-profile',
    'auto-chain-aceofcloud-purple-team-idp-compromise-2026-mlm038w8',
    'auto-chain-aceofcloud-purple-team-idp-compromise-2026-mlm039ua',
    'aceofcloud_idp_compromise_apt29_profile',
  ];
  
  // Remove any events referencing these
  for (const actorId of aceofcloudActorIds) {
    const [evResult] = await conn.execute(
      'DELETE FROM threat_group_events WHERE tgeActorId = ?', [actorId]
    );
    if (evResult.affectedRows > 0) {
      console.log(`  Deleted ${evResult.affectedRows} events for ${actorId}`);
      totalEventsUpdated += evResult.affectedRows;
    }
  }
  
  // Delete the actors
  const [delResult] = await conn.execute(
    'DELETE FROM threat_actors WHERE id IN (?, ?, ?, ?)', aceofcloudIds
  );
  console.log(`  Deleted ${delResult.affectedRows} AceofCloud IDP entries`);
  totalDeleted += delResult.affectedRows;
  
  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 1: G-code duplicates — "APT28 (G0007)" → merge into "APT28"
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n═══ STEP 1: Merging G-code duplicates ═══');
  
  const [gCodeDups] = await conn.execute(`
    SELECT t1.id as dup_id, t1.actorId as dup_actorId, t1.name as dup_name,
           t2.id as canon_id, t2.actorId as canon_actorId, t2.name as canon_name
    FROM threat_actors t1 
    JOIN threat_actors t2 ON REPLACE(REPLACE(t1.name, CONCAT(' (', SUBSTRING_INDEX(t1.name, '(', -1)), ''), ' ', '') = REPLACE(t2.name, ' ', '')
    WHERE t1.name REGEXP '\\\\(G[0-9]+\\\\)$' AND t2.name NOT REGEXP '\\\\(G[0-9]+\\\\)$' AND t1.id != t2.id
  `);
  
  console.log(`  Found ${gCodeDups.length} G-code duplicates to merge`);
  
  for (const pair of gCodeDups) {
    // Fetch full records
    const [[canonical]] = await conn.execute('SELECT * FROM threat_actors WHERE id = ?', [pair.canon_id]);
    const [[duplicate]] = await conn.execute('SELECT * FROM threat_actors WHERE id = ?', [pair.dup_id]);
    
    if (!canonical || !duplicate) continue;
    
    const merged = mergeActors(canonical, duplicate);
    
    // Update canonical with merged data
    await conn.execute(`
      UPDATE threat_actors SET 
        aliases = ?, description = ?, motivation = ?, origin = ?, firstSeen = ?, lastActive = ?,
        threatLevel = ?, sophistication = ?, targetSectors = ?, targetRegions = ?,
        techniques = ?, tools = ?, malware = ?, calderaProfile = ?, activityTimeline = ?,
        stixId = ?, dataSource = ?, confidence = ?, logoUrl = ?, enrichment_sources = ?
      WHERE id = ?
    `, [
      merged.aliases, merged.description, merged.motivation, merged.origin, merged.firstSeen, merged.lastActive,
      merged.threatLevel, merged.sophistication, merged.targetSectors, merged.targetRegions,
      merged.techniques, merged.tools, merged.malware, merged.calderaProfile, merged.activityTimeline,
      merged.stixId, merged.dataSource, merged.confidence, merged.logoUrl, merged.enrichment_sources || merged.enrichmentSources || null,
      pair.canon_id
    ]);
    
    // Update events referencing the duplicate
    const [evUpdate] = await conn.execute(
      'UPDATE threat_group_events SET tgeActorId = ? WHERE tgeActorId = ?',
      [pair.canon_actorId, pair.dup_actorId]
    );
    if (evUpdate.affectedRows > 0) totalEventsUpdated += evUpdate.affectedRows;
    
    // Delete the duplicate
    await conn.execute('DELETE FROM threat_actors WHERE id = ?', [pair.dup_id]);
    totalMerged++;
    totalDeleted++;
  }
  console.log(`  Merged ${gCodeDups.length} G-code entries into canonical records`);
  
  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 2: IAB prefix duplicates — "iab-prophet-spider" → merge into "prophet-spider"
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n═══ STEP 2: Merging IAB prefix duplicates ═══');
  
  const [iabDups] = await conn.execute(`
    SELECT t1.id as dup_id, t1.actorId as dup_actorId, t1.name as dup_name,
           t2.id as canon_id, t2.actorId as canon_actorId, t2.name as canon_name
    FROM threat_actors t1 
    JOIN threat_actors t2 ON LOWER(REPLACE(t1.name, ' ', '-')) = LOWER(REPLACE(t2.name, ' ', '-'))
    WHERE t1.actorId LIKE 'iab-%' AND t2.actorId NOT LIKE 'iab-%' AND t1.id != t2.id
  `);
  
  console.log(`  Found ${iabDups.length} IAB prefix duplicates`);
  
  for (const pair of iabDups) {
    const [[canonical]] = await conn.execute('SELECT * FROM threat_actors WHERE id = ?', [pair.canon_id]);
    const [[duplicate]] = await conn.execute('SELECT * FROM threat_actors WHERE id = ?', [pair.dup_id]);
    
    if (!canonical || !duplicate) continue;
    
    const merged = mergeActors(canonical, duplicate);
    
    // If the IAB entry has access_broker type, add that info to the canonical
    if (duplicate.actorType === 'access_broker' && canonical.actorType !== 'access_broker') {
      // Keep the canonical type but note the IAB role in aliases/description
      const aliases = JSON.parse(merged.aliases || '[]');
      if (!aliases.includes('Initial Access Broker')) {
        aliases.push('Initial Access Broker');
        merged.aliases = JSON.stringify(aliases);
      }
    }
    
    await conn.execute(`
      UPDATE threat_actors SET 
        aliases = ?, description = ?, motivation = ?, origin = ?, firstSeen = ?, lastActive = ?,
        threatLevel = ?, sophistication = ?, targetSectors = ?, targetRegions = ?,
        techniques = ?, tools = ?, malware = ?, calderaProfile = ?, activityTimeline = ?,
        stixId = ?, dataSource = ?, confidence = ?, logoUrl = ?, enrichment_sources = ?
      WHERE id = ?
    `, [
      merged.aliases, merged.description, merged.motivation, merged.origin, merged.firstSeen, merged.lastActive,
      merged.threatLevel, merged.sophistication, merged.targetSectors, merged.targetRegions,
      merged.techniques, merged.tools, merged.malware, merged.calderaProfile, merged.activityTimeline,
      merged.stixId, merged.dataSource, merged.confidence, merged.logoUrl, merged.enrichment_sources || merged.enrichmentSources || null,
      pair.canon_id
    ]);
    
    const [evUpdate] = await conn.execute(
      'UPDATE threat_group_events SET tgeActorId = ? WHERE tgeActorId = ?',
      [pair.canon_actorId, pair.dup_actorId]
    );
    if (evUpdate.affectedRows > 0) totalEventsUpdated += evUpdate.affectedRows;
    
    await conn.execute('DELETE FROM threat_actors WHERE id = ?', [pair.dup_id]);
    totalMerged++;
    totalDeleted++;
  }
  console.log(`  Merged ${iabDups.length} IAB entries into canonical records`);
  
  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 3: LLM-enriched and exact name duplicates
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n═══ STEP 3: Merging LLM-enriched and exact name duplicates ═══');
  
  const [nameDups] = await conn.execute(`
    SELECT t1.id as id1, t1.actorId as actorId1, t1.name as name1, t1.dataSource as ds1,
           t2.id as id2, t2.actorId as actorId2, t2.name as name2, t2.dataSource as ds2
    FROM threat_actors t1
    JOIN threat_actors t2 ON LOWER(REPLACE(t1.name, '-', ' ')) = LOWER(REPLACE(t2.name, '-', ' '))
    WHERE t1.id < t2.id
      AND t1.actorId NOT LIKE 'iab-%' AND t2.actorId NOT LIKE 'iab-%'
      AND t1.name NOT REGEXP '\\\\(G[0-9]+\\\\)$' AND t2.name NOT REGEXP '\\\\(G[0-9]+\\\\)$'
  `);
  
  console.log(`  Found ${nameDups.length} name-based duplicates`);
  
  // Track already-deleted IDs to avoid double-processing
  const deletedIds = new Set();
  
  for (const pair of nameDups) {
    if (deletedIds.has(pair.id1) || deletedIds.has(pair.id2)) continue;
    
    // Determine canonical: prefer mitre/caldera source, then older ID
    let canonId, dupId, canonActorId, dupActorId;
    const ds1Priority = (pair.ds1 || '').includes('mitre') || (pair.ds1 || '').includes('caldera') ? 2 : 1;
    const ds2Priority = (pair.ds2 || '').includes('mitre') || (pair.ds2 || '').includes('caldera') ? 2 : 1;
    
    if (ds1Priority >= ds2Priority) {
      canonId = pair.id1; dupId = pair.id2;
      canonActorId = pair.actorId1; dupActorId = pair.actorId2;
    } else {
      canonId = pair.id2; dupId = pair.id1;
      canonActorId = pair.actorId2; dupActorId = pair.actorId1;
    }
    
    const [[canonical]] = await conn.execute('SELECT * FROM threat_actors WHERE id = ?', [canonId]);
    const [[duplicate]] = await conn.execute('SELECT * FROM threat_actors WHERE id = ?', [dupId]);
    
    if (!canonical || !duplicate) continue;
    
    const merged = mergeActors(canonical, duplicate);
    
    await conn.execute(`
      UPDATE threat_actors SET 
        aliases = ?, description = ?, motivation = ?, origin = ?, firstSeen = ?, lastActive = ?,
        threatLevel = ?, sophistication = ?, targetSectors = ?, targetRegions = ?,
        techniques = ?, tools = ?, malware = ?, calderaProfile = ?, activityTimeline = ?,
        stixId = ?, dataSource = ?, confidence = ?, logoUrl = ?, enrichment_sources = ?
      WHERE id = ?
    `, [
      merged.aliases, merged.description, merged.motivation, merged.origin, merged.firstSeen, merged.lastActive,
      merged.threatLevel, merged.sophistication, merged.targetSectors, merged.targetRegions,
      merged.techniques, merged.tools, merged.malware, merged.calderaProfile, merged.activityTimeline,
      merged.stixId, merged.dataSource, merged.confidence, merged.logoUrl, merged.enrichment_sources || merged.enrichmentSources || null,
      canonId
    ]);
    
    const [evUpdate] = await conn.execute(
      'UPDATE threat_group_events SET tgeActorId = ? WHERE tgeActorId = ?',
      [canonActorId, dupActorId]
    );
    if (evUpdate.affectedRows > 0) totalEventsUpdated += evUpdate.affectedRows;
    
    await conn.execute('DELETE FROM threat_actors WHERE id = ?', [dupId]);
    deletedIds.add(dupId);
    totalMerged++;
    totalDeleted++;
  }
  console.log(`  Merged ${nameDups.length} name-based duplicates`);
  
  // ═══════════════════════════════════════════════════════════════════════════
  // STEP 4: Clean up malformed aliases (some have double-encoded JSON)
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n═══ STEP 4: Cleaning up malformed aliases ═══');
  
  const [malformed] = await conn.execute(`
    SELECT id, aliases FROM threat_actors 
    WHERE aliases LIKE '"%' OR aliases LIKE '"[%'
    LIMIT 500
  `);
  
  let fixedCount = 0;
  for (const row of malformed) {
    let cleaned = row.aliases;
    // Double-encoded: "\"[\\\"APT28\\\"]\"" → ["APT28"]
    try {
      if (typeof cleaned === 'string' && cleaned.startsWith('"')) {
        cleaned = JSON.parse(cleaned); // unwrap one layer
      }
      if (typeof cleaned === 'string') {
        cleaned = JSON.parse(cleaned); // unwrap second layer if needed
      }
      if (Array.isArray(cleaned)) {
        // Filter out garbage single-char entries
        cleaned = cleaned.filter(a => typeof a === 'string' && a.length > 1);
        await conn.execute('UPDATE threat_actors SET aliases = ? WHERE id = ?', [JSON.stringify(cleaned), row.id]);
        fixedCount++;
      }
    } catch {
      // Skip if we can't parse it
    }
  }
  console.log(`  Fixed ${fixedCount} malformed alias entries`);
  
  // ═══════════════════════════════════════════════════════════════════════════
  // SUMMARY
  // ═══════════════════════════════════════════════════════════════════════════
  const [[{ total }]] = await conn.execute('SELECT COUNT(*) as total FROM threat_actors');
  
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log(`DEDUPLICATION COMPLETE`);
  console.log(`  Records merged: ${totalMerged}`);
  console.log(`  Records deleted: ${totalDeleted}`);
  console.log(`  Events reassigned: ${totalEventsUpdated}`);
  console.log(`  Aliases fixed: ${fixedCount}`);
  console.log(`  Final threat actor count: ${total}`);
  console.log('═══════════════════════════════════════════════════════════════');
  
  await conn.end();
}

main().catch(err => {
  console.error('FATAL:', err);
  process.exit(1);
});
