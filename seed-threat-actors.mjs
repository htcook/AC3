/**
 * Seed script: Inserts 403 threat actors into the threat_actors table.
 * Run with: node seed-threat-actors.mjs
 * 
 * Reads the comprehensive actor JSON, transforms it, and inserts via raw SQL.
 */
import { readFileSync } from 'fs';
import mysql from 'mysql2/promise';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL is required');
  process.exit(1);
}

const actors = JSON.parse(readFileSync('/home/ubuntu/spicytip_analysis/all_actors_complete.json', 'utf-8'));

function slugify(name) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, 120);
}

function getMotivation(type) {
  switch (type) {
    case 'apt': return 'espionage';
    case 'cybercrime': return 'financial';
    case 'ransomware': return 'financial';
    case 'hacktivist': return 'disruption';
    default: return 'unknown';
  }
}

function getSophistication(type, techniqueCount) {
  if (type === 'apt' && techniqueCount > 30) return 'nation-state';
  if (techniqueCount > 20) return 'advanced';
  if (techniqueCount > 10) return 'intermediate';
  return 'basic';
}

function getThreatLevel(techniqueCount) {
  if (techniqueCount > 35) return 'critical';
  if (techniqueCount > 20) return 'high';
  if (techniqueCount > 10) return 'medium';
  return 'low';
}

function getTargetRegions(origin) {
  const regionMap = {
    'China': ['Asia-Pacific', 'North America', 'Europe'],
    'Russia': ['Europe', 'North America', 'Ukraine'],
    'Iran': ['Middle East', 'North America', 'Europe'],
    'North Korea': ['South Korea', 'Asia-Pacific', 'North America'],
    'India': ['South Asia', 'China'],
    'Pakistan': ['South Asia', 'India'],
    'Israel': ['Middle East', 'Iran'],
    'Vietnam': ['Asia-Pacific'],
    'South Korea': ['North Korea', 'Asia-Pacific'],
    'Turkey': ['Middle East', 'Europe'],
    'Belarus': ['Europe', 'Ukraine'],
    'Ukraine': ['Russia'],
  };
  return regionMap[origin] || ['Global'];
}

async function main() {
  console.log(`Connecting to database...`);
  const connection = await mysql.createConnection(DATABASE_URL);
  
  console.log(`Processing ${actors.length} threat actors...`);
  
  let inserted = 0;
  let skipped = 0;
  let errors = 0;
  
  for (const actor of actors) {
    const actorId = slugify(actor.name);
    const techniques = (actor.techniques || []).map(t => ({
      id: t.technique_id || t.id || '',
      name: t.technique_name || t.name || '',
      tactic: t.tactic || '',
      score: t.score || 50,
      description: ''
    }));
    
    // Build activity timeline from description and known events
    const activityTimeline = [];
    if (actor.description) {
      // Extract years from description for timeline
      const yearMatches = actor.description.match(/\b(20\d{2}|19\d{2})\b/g);
      if (yearMatches) {
        const uniqueYears = [...new Set(yearMatches)].sort();
        if (uniqueYears.length > 0) {
          activityTimeline.push({
            date: uniqueYears[0],
            event: `First observed activity`,
            source: 'MITRE ATT&CK / OSINT'
          });
        }
        if (uniqueYears.length > 1) {
          activityTimeline.push({
            date: uniqueYears[uniqueYears.length - 1],
            event: `Most recent known activity`,
            source: 'MITRE ATT&CK / OSINT'
          });
        }
      }
    }
    
    const row = {
      actorId,
      name: actor.name,
      aliases: JSON.stringify(actor.aliases || []),
      actorType: actor.type || 'unknown',
      origin: actor.origin || 'Unknown',
      description: actor.description || '',
      motivation: getMotivation(actor.type),
      firstSeen: '',
      lastActive: '',
      threatLevel: getThreatLevel(actor.technique_count || 0),
      sophistication: getSophistication(actor.type, actor.technique_count || 0),
      targetSectors: JSON.stringify(actor.sectors || []),
      targetRegions: JSON.stringify(getTargetRegions(actor.origin)),
      techniques: JSON.stringify(techniques),
      tools: JSON.stringify([]),
      malware: JSON.stringify([]),
      calderaProfile: JSON.stringify(null),
      activityTimeline: JSON.stringify(activityTimeline),
      stixId: actor.mitre_id || '',
      dataSource: actor.mitre_id ? 'mitre' : 'osint',
      confidence: actor.mitre_id ? 90 : actor.technique_count > 20 ? 75 : 60,
    };
    
    try {
      await connection.execute(
        `INSERT INTO threat_actors (actorId, name, aliases, actorType, origin, description, motivation, firstSeen, lastActive, threatLevel, sophistication, targetSectors, targetRegions, techniques, tools, malware, calderaProfile, activityTimeline, stixId, dataSource, confidence)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           name = VALUES(name),
           aliases = VALUES(aliases),
           description = VALUES(description),
           origin = VALUES(origin),
           actorType = VALUES(actorType),
           motivation = VALUES(motivation),
           threatLevel = VALUES(threatLevel),
           sophistication = VALUES(sophistication),
           targetSectors = VALUES(targetSectors),
           targetRegions = VALUES(targetRegions),
           techniques = VALUES(techniques),
           activityTimeline = VALUES(activityTimeline),
           stixId = VALUES(stixId),
           dataSource = VALUES(dataSource),
           confidence = VALUES(confidence)`,
        [
          row.actorId, row.name, row.aliases, row.actorType, row.origin,
          row.description, row.motivation, row.firstSeen, row.lastActive,
          row.threatLevel, row.sophistication, row.targetSectors, row.targetRegions,
          row.techniques, row.tools, row.malware, row.calderaProfile,
          row.activityTimeline, row.stixId, row.dataSource, row.confidence
        ]
      );
      inserted++;
    } catch (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        skipped++;
      } else {
        console.error(`Error inserting ${actor.name}:`, err.message);
        errors++;
      }
    }
  }
  
  console.log(`\nSeed complete:`);
  console.log(`  Inserted/Updated: ${inserted}`);
  console.log(`  Skipped (duplicate): ${skipped}`);
  console.log(`  Errors: ${errors}`);
  console.log(`  Total processed: ${actors.length}`);
  
  // Verify count
  const [rows] = await connection.execute('SELECT COUNT(*) as count FROM threat_actors');
  console.log(`\nTotal actors in database: ${rows[0].count}`);
  
  // Show breakdown
  const [typeBreakdown] = await connection.execute('SELECT actorType, COUNT(*) as count FROM threat_actors GROUP BY actorType ORDER BY count DESC');
  console.log('\nBreakdown by type:');
  for (const row of typeBreakdown) {
    console.log(`  ${row.actorType}: ${row.count}`);
  }
  
  const [originBreakdown] = await connection.execute('SELECT origin, COUNT(*) as count FROM threat_actors GROUP BY origin ORDER BY count DESC LIMIT 10');
  console.log('\nTop 10 origins:');
  for (const row of originBreakdown) {
    console.log(`  ${row.origin}: ${row.count}`);
  }
  
  await connection.end();
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
