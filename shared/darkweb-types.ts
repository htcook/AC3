/**
 * Darkweb Intelligence & Ransomware Group Types
 * Shared between server and client for type-safe data flow.
 */

// ─── Ransomware Group Profile ────────────────────────────────────────────
export interface RansomwareGroupProfile {
  groupName: string;
  aliases: string[];
  activityScore: number;           // 0-100 composite
  trend: 'surging' | 'active' | 'declining' | 'dormant';
  victims7d: number;
  victims30d: number;
  totalVictims: number;
  topSectors: string[];
  topCountries: string[];
  associatedMalware: string[];
  mitreTechniques: string[];       // T-codes
  description: string;
  firstSeen: string;               // ISO date or year
  lastActive: string;              // ISO date
  ransomwareFamily: string;        // e.g. "LockBit 3.0", "BlackCat/ALPHV"
  extortionModel: 'single' | 'double' | 'triple' | 'unknown';
  affiliateProgram: boolean;
  knownInfrastructure: string[];   // .onion sites, leak sites
  notableAttacks: NotableAttack[];
  calderaActorId?: string;         // link to threatActors table
}

export interface NotableAttack {
  victimName: string;
  sector: string;
  country: string;
  date: string;
  impactDescription: string;
  ransomDemand?: string;
}

// ─── Darkweb IOC ─────────────────────────────────────────────────────────
export interface DarkwebIOC {
  iocType: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  iocValue: string;
  malwareFamily: string;
  threatType: string;
  confidenceLevel: number;         // 0-100
  firstSeen: string;               // ISO date
  lastSeen: string;
  tags: string[];
  source: 'threatfox' | 'malware_bazaar' | 'otx' | 'abuse_ch' | 'cisa_kev' | 'llm_enriched';
  linkedGroups: string[];          // ransomware group names
}

// ─── Corroboration Match ─────────────────────────────────────────────────
export interface CorroborationMatch {
  asset: string;                    // discovered asset from OSINT
  matchedIOC: DarkwebIOC;
  corroborationTier: 'confirmed' | 'probable' | 'potential';
  impactOnChain: string;           // how this affects the Caldera chain
}

// ─── Activity Rating ─────────────────────────────────────────────────────
export interface ActivityRating {
  groupName: string;
  activityScore: number;           // 0-100
  trend: 'surging' | 'active' | 'declining' | 'dormant';
  victims7d: number;
  victims30d: number;
  lastAttack: string;              // ISO date
  primarySectors: string[];
  threatLevel: 'critical' | 'high' | 'medium' | 'low';
}

// ─── Ransomware Event (Victim Report) ────────────────────────────────────
export interface RansomwareEvent {
  id: number;
  groupName: string;
  victimName: string;
  victimUrl?: string;
  country: string;
  sector: string;
  publishedAt: string;             // ISO date
  source: string;
  description?: string;
}

// ─── CISA KEV Entry ──────────────────────────────────────────────────────
export interface CISAKEVEntry {
  cveId: string;
  vendor: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  ransomwareUse: 'known' | 'unknown';
  linkedGroups: string[];
  description: string;
}

// ─── Darkweb Dashboard Stats ─────────────────────────────────────────────
export interface DarkwebDashboardStats {
  totalGroups: number;
  activeGroups: number;
  surgingGroups: number;
  totalVictims30d: number;
  totalIOCs: number;
  kevWithRansomware: number;
  topSectors: { sector: string; count: number }[];
  topCountries: { country: string; count: number }[];
  recentEvents: RansomwareEvent[];
}

// ─── Sector/Country Heatmap Data ─────────────────────────────────────────
export interface TargetingHeatmapData {
  sectors: { name: string; groups: string[]; victimCount: number }[];
  countries: { name: string; groups: string[]; victimCount: number }[];
}

// ─── Intelligence Enrichment (for domain intel results) ──────────────────
export interface IntelligenceEnrichment {
  matchedGroups: {
    groupName: string;
    activityScore: number;
    trend: 'surging' | 'active' | 'declining' | 'dormant';
    relevance: string;             // why this group is relevant to the target
    matchedTechniques: string[];   // MITRE techniques that overlap
    recentVictimsSameSector: number;
  }[];
  matchedIOCs: CorroborationMatch[];
  kevMatches: CISAKEVEntry[];
  riskElevation: string;           // LLM-generated summary of how darkweb intel affects risk
}
