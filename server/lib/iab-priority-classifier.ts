/**
 * IAB Priority Classifier
 * 
 * Classifies IAB listings into priority categories based on keyword matching
 * against verified data. NO LLM generation — purely deterministic classification.
 * 
 * Priority Categories:
 *   - CRITICAL: US Government credentials (.gov, federal agencies, military)
 *   - CRITICAL: ICS/SCADA access (industrial control systems, OT networks)
 *   - HIGH: Defense contractor credentials (DIB sector, cleared contractors)
 *   - MEDIUM: Other high-value targets (healthcare, finance, energy)
 *   - LOW: General/unclassified
 * 
 * Every classification includes:
 *   - matched keywords (for audit trail)
 *   - priority score (0-100)
 *   - category tags
 */

import mysql from 'mysql2/promise';

export type PriorityCategory = 'us_gov' | 'ics_scada' | 'defense_contractor' | 'critical_infrastructure' | 'general';
export type PriorityLevel = 'critical' | 'high' | 'medium' | 'low';

export interface ClassificationResult {
  priorityLevel: PriorityLevel;
  priorityScore: number; // 0-100
  categories: PriorityCategory[];
  matchedKeywords: string[];
  tags: string[];
}

// ── Keyword dictionaries (all lowercase) ──────────────────────────────

const US_GOV_KEYWORDS = [
  // Domain patterns
  '.gov', '.mil',
  // Federal agencies
  'government', 'federal', 'us government', 'u.s. government',
  'department of defense', 'department of energy', 'department of homeland security',
  'department of state', 'department of justice', 'department of treasury',
  'department of health', 'department of education', 'department of commerce',
  'department of interior', 'department of agriculture', 'department of labor',
  'department of transportation', 'department of veterans',
  'dod', 'doe', 'dhs', 'doj', 'dot', 'hhs', 'usda', 'doi',
  'fbi', 'cia', 'nsa', 'dia', 'nro', 'nga',
  'pentagon', 'white house', 'congress', 'senate',
  'secret service', 'us marshals', 'atf', 'dea', 'ice',
  'tsa', 'fema', 'cisa', 'fcc', 'sec', 'ftc', 'epa', 'fda',
  'nasa', 'noaa', 'usps', 'irs', 'gsa', 'opm', 'sba',
  // State/local
  'state government', 'county government', 'municipal', 'city government',
  'state agency', 'public sector',
  // Military branches
  'us army', 'us navy', 'us air force', 'us marine', 'us coast guard',
  'space force', 'national guard', 'military',
  // Classification markings
  'classified', 'top secret', 'ts/sci', 'secret clearance',
  'fouo', 'cui', 'noforn', 'controlled unclassified',
];

const ICS_SCADA_KEYWORDS = [
  // Systems
  'ics', 'scada', 'plc', 'hmi', 'dcs', 'rtu', 'ot network',
  'operational technology', 'industrial control',
  'programmable logic controller', 'human machine interface',
  'distributed control system', 'remote terminal unit',
  'supervisory control', 'process control',
  // Protocols
  'modbus', 'dnp3', 'opc ua', 'opc da', 'bacnet', 'ethernet/ip',
  'profinet', 'hart', 'foundation fieldbus', 'iec 61850',
  'iec 62351', 'codesys',
  // Sectors
  'water treatment', 'water utility', 'wastewater',
  'power grid', 'power plant', 'electric utility', 'electricity',
  'oil and gas', 'oil & gas', 'pipeline', 'refinery', 'chemical plant',
  'nuclear', 'hydroelectric', 'solar farm', 'wind farm',
  'smart grid', 'substation', 'transformer',
  'natural gas', 'lng', 'petroleum',
  // Vendors
  'siemens', 'rockwell automation', 'allen-bradley', 'schneider electric',
  'abb', 'honeywell', 'emerson', 'yokogawa', 'ge digital',
  'mitsubishi electric', 'omron', 'beckhoff', 'wago',
  'aveva', 'wonderware', 'ignition', 'factorytalk',
  // Infrastructure
  'critical infrastructure', 'dam', 'levee', 'bridge control',
  'traffic control', 'rail', 'railway', 'transit system',
  'building automation', 'hvac control', 'bms',
];

const DEFENSE_CONTRACTOR_KEYWORDS = [
  // General terms
  'defense contractor', 'defence contractor', 'defense industrial base', 'dib',
  'cleared contractor', 'cleared defense contractor', 'cdc',
  'security clearance', 'cleared facility', 'cleared personnel',
  'itar', 'ear', 'export controlled', 'cmmc', 'dfars',
  'dod contractor', 'military contractor', 'defense subcontractor',
  // Major primes
  'lockheed martin', 'lockheed', 'raytheon', 'rtx',
  'northrop grumman', 'northrop', 'boeing defense', 'boeing military',
  'general dynamics', 'bae systems', 'l3harris', 'l3 harris',
  'leidos', 'saic', 'booz allen', 'booz allen hamilton',
  'mantech', 'caci', 'parsons', 'kbr',
  'huntington ingalls', 'textron', 'general atomics',
  'elbit systems', 'thales', 'leonardo drs',
  'perspecta', 'engility', 'dxc technology',
  // DoD agencies
  'disa', 'dcsa', 'darpa', 'nsa contractor', 'dod contractor',
  'afrl', 'nrl', 'arl', 'onr',
  // Systems
  'weapons system', 'missile', 'satellite', 'radar', 'sonar',
  'military communications', 'tactical network', 'c4isr',
  'electronic warfare', 'cyber command', 'sigint', 'elint',
  'unmanned', 'uav', 'drone', 'f-35', 'f-22', 'b-21',
  'patriot', 'thaad', 'aegis', 'javelin', 'stinger',
];

const CRITICAL_INFRASTRUCTURE_KEYWORDS = [
  'healthcare', 'hospital', 'medical center', 'health system',
  'financial', 'banking', 'bank of', 'credit union',
  'insurance', 'stock exchange',
  'telecommunications', 'telecom', 'isp',
  'transportation', 'airport', 'port authority', 'shipping',
  'food supply', 'agriculture', 'farming',
  'emergency services', '911', 'fire department', 'police',
  'education', 'university', 'school district',
];

// ── Classification engine ─────────────────────────────────────────────

function matchKeywords(text: string, keywords: string[]): string[] {
  const lower = text.toLowerCase();
  return keywords.filter(kw => lower.includes(kw));
}

export function classifyListing(listing: {
  brokerName?: string | null;
  victimOrg?: string | null;
  victimSector?: string | null;
  victimCountry?: string | null;
  accessType?: string | null;
  listingType?: string | null;
  iabDescription?: string | null;
  linkedRansomwareGroups?: string | null;
  dataSource?: string | null;
}): ClassificationResult {
  // Combine all text fields for keyword matching
  const searchText = [
    listing.brokerName,
    listing.victimOrg,
    listing.victimSector,
    listing.victimCountry,
    listing.accessType,
    listing.listingType,
    listing.iabDescription,
    listing.linkedRansomwareGroups,
  ].filter(Boolean).join(' ');

  const categories: PriorityCategory[] = [];
  const allMatchedKeywords: string[] = [];
  const tags: string[] = [];
  let score = 0;

  // Check US Government
  const govMatches = matchKeywords(searchText, US_GOV_KEYWORDS);
  if (govMatches.length > 0) {
    categories.push('us_gov');
    allMatchedKeywords.push(...govMatches);
    tags.push('US Government');
    // Score: base 60 + 10 per additional keyword match, max contribution 40
    score += Math.min(60 + govMatches.length * 10, 100);
  }

  // Check ICS/SCADA
  const icsMatches = matchKeywords(searchText, ICS_SCADA_KEYWORDS);
  if (icsMatches.length > 0) {
    categories.push('ics_scada');
    allMatchedKeywords.push(...icsMatches);
    tags.push('ICS/SCADA');
    score += Math.min(60 + icsMatches.length * 10, 100);
  }

  // Check Defense Contractor
  const defenseMatches = matchKeywords(searchText, DEFENSE_CONTRACTOR_KEYWORDS);
  if (defenseMatches.length > 0) {
    categories.push('defense_contractor');
    allMatchedKeywords.push(...defenseMatches);
    tags.push('Defense Contractor');
    score += Math.min(50 + defenseMatches.length * 10, 90);
  }

  // Check Critical Infrastructure (lower priority)
  const ciMatches = matchKeywords(searchText, CRITICAL_INFRASTRUCTURE_KEYWORDS);
  if (ciMatches.length > 0 && categories.length === 0) {
    categories.push('critical_infrastructure');
    allMatchedKeywords.push(...ciMatches);
    tags.push('Critical Infrastructure');
    score += Math.min(30 + ciMatches.length * 10, 60);
  }

  // Default category
  if (categories.length === 0) {
    categories.push('general');
    score = 10;
  }

  // Cap score at 100
  score = Math.min(score, 100);

  // Determine priority level
  let priorityLevel: PriorityLevel;
  if (categories.includes('us_gov') || categories.includes('ics_scada')) {
    priorityLevel = 'critical';
  } else if (categories.includes('defense_contractor')) {
    priorityLevel = 'high';
  } else if (categories.includes('critical_infrastructure')) {
    priorityLevel = 'medium';
  } else {
    priorityLevel = 'low';
  }

  // Deduplicate keywords
  const uniqueKeywords = [...new Set(allMatchedKeywords)];

  return {
    priorityLevel,
    priorityScore: score,
    categories,
    matchedKeywords: uniqueKeywords,
    tags,
  };
}

/**
 * Classify all listings in the database and update their priority fields.
 * Returns a summary of classifications applied.
 */
export async function classifyAllListings(db: any): Promise<{
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  updated: number;
}> {
  // Use raw mysql2 connection to avoid Drizzle's prepared statement issues
  const conn = await mysql.createConnection(process.env.DATABASE_URL!);
  
  try {
    // Fetch all listings (DB uses camelCase column names)
    const [rows] = await conn.execute(
      'SELECT id, brokerName, victimSector, victimCountry, accessType, listingType, iabDescription, linkedRansomwareGroups, iabDataSource FROM access_broker_listings'
    );

    const listings = rows as any[];
    let critical = 0, high = 0, medium = 0, low = 0, updated = 0;

    for (const row of listings) {
      const result = classifyListing({
        brokerName: row.brokerName,
        victimOrg: null,
        victimSector: row.victimSector,
        victimCountry: row.victimCountry,
        accessType: row.accessType,
        listingType: row.listingType,
        iabDescription: row.iabDescription,
        linkedRansomwareGroups: row.linkedRansomwareGroups,
        dataSource: row.iabDataSource,
      });

      // Update the database row with raw mysql2 connection
      await conn.execute(
        `UPDATE access_broker_listings 
         SET priority_level = ?, priority_score = ?, priority_tags = ?
         WHERE id = ?`,
        [result.priorityLevel, result.priorityScore, JSON.stringify({
          categories: result.categories,
          matchedKeywords: result.matchedKeywords,
          tags: result.tags,
        }), row.id]
      );

      updated++;
      switch (result.priorityLevel) {
        case 'critical': critical++; break;
        case 'high': high++; break;
        case 'medium': medium++; break;
        case 'low': low++; break;
      }
    }

    return { total: listings.length, critical, high, medium, low, updated };
  } finally {
    await conn.end();
  }
}

/**
 * Classify a single listing (for use during ingestion).
 * Call this when inserting new listings to set priority fields immediately.
 */
export function classifyForInsert(listing: {
  brokerName?: string | null;
  victimOrg?: string | null;
  victimSector?: string | null;
  victimCountry?: string | null;
  accessType?: string | null;
  listingType?: string | null;
  iabDescription?: string | null;
  linkedRansomwareGroups?: string | null;
}): { priorityLevel: string; priorityScore: number; priorityTags: string } {
  const result = classifyListing(listing);
  return {
    priorityLevel: result.priorityLevel,
    priorityScore: result.priorityScore,
    priorityTags: JSON.stringify({
      categories: result.categories,
      matchedKeywords: result.matchedKeywords,
      tags: result.tags,
    }),
  };
}
