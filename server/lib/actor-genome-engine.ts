/**
 * Actor Genome Engine — Behavioral Attribution Scoring
 *
 * Moves from signature-based attribution to behavioral attribution by
 * computing high-dimensional "DNA profiles" for threat actors and scoring
 * incidents against them using weighted cosine similarity.
 *
 * Core capabilities:
 * 1. Actor DNA Profiles — normalized vector of hundreds of attributes
 * 2. Weighted Matching — configurable feature weights for scoring
 * 3. Tradecraft Fingerprints — attack sequence chain matching
 * 4. Three-Layer Attribution — operator / persona / state sponsor separation
 * 5. Confidence Engine — supporting + conflicting evidence tracking
 * 6. Explainability — point-by-point scoring breakdown
 * 7. Campaign Clustering — behavioral similarity across campaigns
 * 8. Temporal Analysis — UTC offset, operational tempo, geopolitical correlation
 * 9. Infrastructure Reuse — ASN, VPS, TLS, DNS, JA3/JA4 overlap detection
 * 10. Malware Lineage — code genealogy and family evolution tracking
 *
 * Author: Harrison Cook / AC3 Platform
 */

// ─── Types ──────────────────────────────────────────────────────────────────────

/** Attribution layers — always separated for analytical rigor */
export type AttributionLayer = "technical_operator" | "public_persona" | "state_sponsor";

/** Evidence disposition */
export type EvidenceDisposition = "supporting" | "conflicting" | "neutral" | "inconclusive";

/** Feature categories for the DNA vector */
export type FeatureCategory =
  | "malware_family"
  | "attack_technique"
  | "initial_access"
  | "persistence_method"
  | "c2_infrastructure"
  | "victim_sector"
  | "victim_geography"
  | "plc_vendor"
  | "ics_protocol"
  | "tool_usage"
  | "operational_timing"
  | "language_indicator"
  | "infrastructure_provider"
  | "tls_fingerprint"
  | "credential_behavior"
  | "lateral_movement"
  | "exfiltration_method"
  | "impact_type"
  | "propaganda_behavior"
  | "dwell_time_pattern";

/** A single feature in the DNA vector */
export interface GenomeFeature {
  category: FeatureCategory;
  name: string;
  value: number; // 0.0 - 1.0 normalized
  confidence: number; // 0.0 - 1.0
  source: string; // where this data came from
  lastObserved: number; // Unix ms
  observationCount: number;
}

/** Complete Actor DNA Profile */
export interface ActorGenomeProfile {
  actorId: string;
  name: string;
  aliases: string[];

  // Three-layer attribution
  attribution: {
    technicalOperator: { name: string; confidence: number; evidence: string[] };
    publicPersona: { name: string | null; confidence: number; evidence: string[] };
    stateSponsor: { name: string | null; confidence: number; evidence: string[] };
  };

  // Core metadata
  origin: string;
  motivation: string[];
  sophistication: "nation-state" | "advanced" | "intermediate" | "basic";
  firstSeen: number;
  lastActive: number;
  operationalTempo: OperationalTempo;

  // The DNA vector — hundreds of normalized features
  genome: GenomeFeature[];

  // Tradecraft fingerprints — ordered attack sequences
  tradecraftFingerprints: TradecraftFingerprint[];

  // Infrastructure patterns
  infrastructurePatterns: InfrastructurePattern[];

  // Malware lineage
  malwareLineage: MalwareLineageEntry[];

  // Campaign history
  campaigns: CampaignRecord[];

  // Computed metrics
  profileCompleteness: number; // 0-100
  lastUpdated: number;
}

/** Operational tempo analysis */
export interface OperationalTempo {
  /** Primary UTC offset (most active hours) */
  primaryUtcOffset: number;
  /** Secondary UTC offset (if split operations) */
  secondaryUtcOffset: number | null;
  /** Active hours distribution (24 buckets, 0-1 normalized) */
  hourlyDistribution: number[];
  /** Active days distribution (7 buckets, Mon=0) */
  dailyDistribution: number[];
  /** Average days between campaigns */
  avgCampaignIntervalDays: number;
  /** Campaign duration pattern */
  avgCampaignDurationDays: number;
  /** Holiday avoidance patterns */
  holidayCorrelation: { holiday: string; avoidance: boolean; confidence: number }[];
  /** Geopolitical event correlation */
  geopoliticalTriggers: { event: string; responseDelayHours: number; confidence: number }[];
}

/** Attack sequence chain */
export interface TradecraftFingerprint {
  id: string;
  name: string;
  /** Ordered sequence of actions */
  sequence: TradecraftStep[];
  /** How many times this exact sequence has been observed */
  observationCount: number;
  /** Campaigns where this fingerprint was seen */
  campaignIds: string[];
  confidence: number;
}

export interface TradecraftStep {
  order: number;
  action: string;
  mitreTechnique: string | null;
  detail: string;
  /** Typical dwell time before next step (ms) */
  typicalDwellMs: number | null;
}

/** Infrastructure reuse pattern */
export interface InfrastructurePattern {
  type: "asn" | "vps_provider" | "tls_cert" | "domain_registrar" | "dns_provider" | "hosting" | "tor_exit" | "vpn_provider" | "jarm_hash" | "ja3_hash" | "ssh_key";
  value: string;
  firstSeen: number;
  lastSeen: number;
  campaigns: string[];
  confidence: number;
}

/** Malware family evolution tracking */
export interface MalwareLineageEntry {
  familyName: string;
  variant: string;
  /** Parent variant (if known) */
  parentVariant: string | null;
  /** Shared code indicators */
  sharedIndicators: {
    encryptionRoutine: boolean;
    mutex: boolean;
    configFormat: boolean;
    c2Protocol: boolean;
    stringTable: boolean;
    packerSignature: boolean;
  };
  firstSeen: number;
  lastSeen: number;
  source: string;
}

/** Campaign record */
export interface CampaignRecord {
  id: string;
  name: string;
  startDate: number;
  endDate: number | null;
  victimSectors: string[];
  victimCountries: string[];
  techniques: string[];
  malware: string[];
  infrastructure: string[];
  impactType: string;
  source: string;
}

// ─── Incident Scoring ───────────────────────────────────────────────────────────

/** An incident to be scored against actor profiles */
export interface IncidentObservation {
  id: string;
  title: string;
  timestamp: number;

  // Victim context
  victimSector: string;
  victimCountry: string;
  victimTechnology: string[];

  // Technical indicators
  initialAccess: string[];
  techniques: string[]; // MITRE ATT&CK IDs
  malwareObserved: string[];
  toolsUsed: string[];
  persistenceMethods: string[];
  c2Methods: string[];
  lateralMovement: string[];
  exfiltrationMethods: string[];
  impactType: string;

  // Infrastructure
  sourceIps: string[];
  domains: string[];
  jarmHashes: string[];
  ja3Hashes: string[];
  tlsCerts: string[];
  asnNumbers: string[];

  // ICS/OT specific
  plcVendors: string[];
  icsProtocols: string[];
  safetySystemTargeted: boolean;
  hmiModified: boolean;
  plcLogicChanged: boolean;

  // Behavioral
  credentialReuse: boolean;
  propagandaLeft: boolean;
  propagandaText: string | null;
  dwellTimeDays: number | null;
  operatingHoursUtc: number[] | null; // hours of activity observed

  // Context
  publicClaims: { persona: string; platform: string; timestamp: number }[];
  relatedAdvisories: string[];
}

/** Attribution result for a single actor */
export interface AttributionScore {
  actorId: string;
  actorName: string;
  overallScore: number; // 0-100
  confidence: "high" | "moderate" | "low";

  // Three-layer breakdown
  layers: {
    technicalOperator: { score: number; confidence: number };
    publicPersona: { score: number; confidence: number };
    stateSponsor: { score: number; confidence: number };
  };

  // Evidence chain (explainability)
  evidence: EvidenceItem[];

  // Category scores
  categoryScores: { category: FeatureCategory; score: number; maxPossible: number; weight: number }[];

  // Conflicting indicators
  conflictingEvidence: EvidenceItem[];

  // Alternative explanations
  alternativeHypotheses: string[];
}

/** Single evidence item in the chain */
export interface EvidenceItem {
  category: FeatureCategory;
  indicator: string;
  pointsAwarded: number;
  maxPoints: number;
  disposition: EvidenceDisposition;
  explanation: string;
  source: string;
  confidence: number;
}

/** Full attribution report */
export interface AttributionReport {
  incidentId: string;
  incidentTitle: string;
  scoredAt: number;
  rankings: AttributionScore[];
  topCandidate: AttributionScore;
  narrativeExplanation: string;
  analystNotes: string[];
  campaignSimilarity: CampaignSimilarityResult[];
}

/** Campaign similarity result */
export interface CampaignSimilarityResult {
  campaignId: string;
  campaignName: string;
  actorId: string;
  actorName: string;
  similarityPercent: number;
  matchingFeatures: string[];
  divergentFeatures: string[];
}

// ─── Feature Weights ────────────────────────────────────────────────────────────

/** Default feature weights — configurable per analysis */
export const DEFAULT_FEATURE_WEIGHTS: Record<FeatureCategory, number> = {
  malware_family: 30,
  attack_technique: 20,
  plc_vendor: 20,
  initial_access: 15,
  victim_sector: 10,
  victim_geography: 5,
  c2_infrastructure: 18,
  persistence_method: 12,
  tool_usage: 14,
  operational_timing: 16,
  language_indicator: 8,
  infrastructure_provider: 15,
  tls_fingerprint: 12,
  credential_behavior: 10,
  lateral_movement: 8,
  exfiltration_method: 8,
  impact_type: 10,
  propaganda_behavior: 12,
  ics_protocol: 15,
  dwell_time_pattern: 6,
};

/** ICS/OT-weighted profile (for utility/ICS incidents) */
export const ICS_FEATURE_WEIGHTS: Record<FeatureCategory, number> = {
  ...DEFAULT_FEATURE_WEIGHTS,
  plc_vendor: 30,
  ics_protocol: 25,
  attack_technique: 22,
  malware_family: 25,
  victim_sector: 15,
  operational_timing: 18,
  propaganda_behavior: 15,
  credential_behavior: 14,
};

// ─── Actor Genome Database (In-Memory + DB-backed) ──────────────────────────────

/** Pre-built actor genomes based on public threat intelligence */
const ACTOR_GENOME_DB: ActorGenomeProfile[] = [
  // ─── CyberAv3ngers (IRGC-CEC) ───────────────────────────────────────────
  {
    actorId: "cyberav3ngers",
    name: "CyberAv3ngers",
    aliases: ["CyberAv3ngers", "IRGC-CEC Cyber Unit", "Shahid Kaveh"],
    attribution: {
      technicalOperator: { name: "CyberAv3ngers", confidence: 0.92, evidence: ["CISA AA23-335A", "FBI flash alert", "Treasury sanctions (6 individuals)", "IOCONTROL malware attribution"] },
      publicPersona: { name: "CyberAv3ngers", confidence: 0.95, evidence: ["Telegram channel claims", "X/Twitter posts", "Propaganda screenshots"] },
      stateSponsor: { name: "IRGC Cyber-Electronic Command (IRGC-CEC)", confidence: 0.90, evidence: ["Treasury OFAC sanctions", "NSA/CISA joint advisory", "DOJ indictment references"] },
    },
    origin: "Iran",
    motivation: ["disruption", "propaganda", "deterrence", "retaliation"],
    sophistication: "advanced",
    firstSeen: Date.parse("2020-01-01"),
    lastActive: Date.parse("2026-07-27"),
    operationalTempo: {
      primaryUtcOffset: 3.5, // Iran Standard Time (IRST)
      secondaryUtcOffset: null,
      hourlyDistribution: [0,0,0,0,0,0.1,0.3,0.6,0.8,0.9,1.0,0.9,0.7,0.8,0.9,0.8,0.6,0.4,0.2,0.1,0,0,0,0],
      dailyDistribution: [0.2,0.9,0.9,0.8,0.9,0.1,0.05], // Sun-Thu active (Iranian work week)
      avgCampaignIntervalDays: 45,
      avgCampaignDurationDays: 3,
      holidayCorrelation: [
        { holiday: "Nowruz (Iranian New Year)", avoidance: true, confidence: 0.8 },
        { holiday: "US holidays", avoidance: false, confidence: 0.7 },
        { holiday: "Ramadan", avoidance: false, confidence: 0.6 },
      ],
      geopoliticalTriggers: [
        { event: "US sanctions on Iran", responseDelayHours: 72, confidence: 0.75 },
        { event: "Israeli military operations", responseDelayHours: 48, confidence: 0.82 },
        { event: "IRGC commander assassination", responseDelayHours: 24, confidence: 0.70 },
      ],
    },
    genome: [
      // Victim targeting
      { category: "victim_sector", name: "water_utility", value: 0.95, confidence: 0.95, source: "CISA AA23-335A + AA26-097A", lastObserved: Date.parse("2026-07-27"), observationCount: 37 },
      { category: "victim_sector", name: "energy", value: 0.6, confidence: 0.7, source: "CISA advisories", lastObserved: Date.parse("2025-03-01"), observationCount: 8 },
      { category: "victim_sector", name: "government", value: 0.4, confidence: 0.6, source: "Unit 42 reporting", lastObserved: Date.parse("2024-06-01"), observationCount: 5 },
      { category: "victim_geography", name: "united_states", value: 0.85, confidence: 0.9, source: "FBI PSA July 2026", lastObserved: Date.parse("2026-07-27"), observationCount: 30 },
      { category: "victim_geography", name: "israel", value: 0.9, confidence: 0.9, source: "Multiple campaigns 2020-2024", lastObserved: Date.parse("2024-12-01"), observationCount: 25 },

      // PLC/ICS targeting
      { category: "plc_vendor", name: "unitronics", value: 0.95, confidence: 0.95, source: "CISA AA23-335A", lastObserved: Date.parse("2024-01-01"), observationCount: 15 },
      { category: "plc_vendor", name: "rockwell_automation", value: 0.9, confidence: 0.88, source: "CISA AA26-097A + FBI PSA", lastObserved: Date.parse("2026-07-27"), observationCount: 30 },
      { category: "plc_vendor", name: "schneider_electric", value: 0.5, confidence: 0.6, source: "Dragos reporting", lastObserved: Date.parse("2025-06-01"), observationCount: 4 },
      { category: "ics_protocol", name: "modbus_tcp", value: 0.85, confidence: 0.85, source: "Technical analysis", lastObserved: Date.parse("2026-07-27"), observationCount: 20 },
      { category: "ics_protocol", name: "ethernet_ip", value: 0.7, confidence: 0.75, source: "Rockwell campaign analysis", lastObserved: Date.parse("2026-07-27"), observationCount: 12 },

      // Initial access
      { category: "initial_access", name: "default_credentials", value: 0.95, confidence: 0.95, source: "CISA AA23-335A", lastObserved: Date.parse("2026-07-27"), observationCount: 35 },
      { category: "initial_access", name: "vpn_exploitation", value: 0.7, confidence: 0.75, source: "FBI flash alert", lastObserved: Date.parse("2026-07-27"), observationCount: 12 },
      { category: "initial_access", name: "internet_facing_plc", value: 0.95, confidence: 0.95, source: "All campaigns", lastObserved: Date.parse("2026-07-27"), observationCount: 40 },

      // Malware
      { category: "malware_family", name: "iocontrol", value: 0.9, confidence: 0.85, source: "Claroty Team82", lastObserved: Date.parse("2025-12-01"), observationCount: 8 },
      { category: "malware_family", name: "muddyc2", value: 0.4, confidence: 0.5, source: "Shared IRGC tooling", lastObserved: Date.parse("2024-06-01"), observationCount: 3 },

      // Techniques
      { category: "attack_technique", name: "T0803", value: 0.95, confidence: 0.95, source: "All PLC campaigns", lastObserved: Date.parse("2026-07-27"), observationCount: 35 },
      { category: "attack_technique", name: "T0814", value: 0.85, confidence: 0.85, source: "HMI modification campaigns", lastObserved: Date.parse("2026-07-27"), observationCount: 20 },
      { category: "attack_technique", name: "T0842", value: 0.8, confidence: 0.8, source: "Network sniffing for creds", lastObserved: Date.parse("2025-06-01"), observationCount: 10 },
      { category: "attack_technique", name: "T0843", value: 0.9, confidence: 0.9, source: "IP/password changes", lastObserved: Date.parse("2026-07-27"), observationCount: 30 },
      { category: "attack_technique", name: "T0816", value: 0.7, confidence: 0.7, source: "Device restart/shutdown", lastObserved: Date.parse("2026-07-27"), observationCount: 15 },

      // Behavioral
      { category: "credential_behavior", name: "password_change_lockout", value: 0.95, confidence: 0.95, source: "FBI PSA July 2026", lastObserved: Date.parse("2026-07-27"), observationCount: 30 },
      { category: "propaganda_behavior", name: "anti_israel_messaging", value: 0.9, confidence: 0.9, source: "Telegram claims", lastObserved: Date.parse("2026-07-27"), observationCount: 25 },
      { category: "propaganda_behavior", name: "leaves_propaganda_on_hmi", value: 0.85, confidence: 0.85, source: "Unitronics campaign", lastObserved: Date.parse("2024-01-01"), observationCount: 12 },
      { category: "impact_type", name: "operational_disruption", value: 0.95, confidence: 0.95, source: "All campaigns", lastObserved: Date.parse("2026-07-27"), observationCount: 35 },
      { category: "impact_type", name: "no_ransomware", value: 0.95, confidence: 0.95, source: "No ransomware ever deployed", lastObserved: Date.parse("2026-07-27"), observationCount: 40 },
      { category: "dwell_time_pattern", name: "minimal_dwell", value: 0.9, confidence: 0.85, source: "Rapid in-and-out operations", lastObserved: Date.parse("2026-07-27"), observationCount: 30 },

      // Infrastructure
      { category: "c2_infrastructure", name: "vps_providers", value: 0.7, confidence: 0.7, source: "Infrastructure analysis", lastObserved: Date.parse("2026-01-01"), observationCount: 10 },
      { category: "c2_infrastructure", name: "telegram_c2", value: 0.6, confidence: 0.6, source: "IOCONTROL analysis", lastObserved: Date.parse("2025-12-01"), observationCount: 5 },
      { category: "infrastructure_provider", name: "iranian_hosting", value: 0.5, confidence: 0.5, source: "ASN analysis", lastObserved: Date.parse("2025-06-01"), observationCount: 6 },

      // Timing
      { category: "operational_timing", name: "iranian_work_hours", value: 0.85, confidence: 0.8, source: "Temporal analysis of attacks", lastObserved: Date.parse("2026-07-27"), observationCount: 25 },
    ],
    tradecraftFingerprints: [
      {
        id: "ca3-plc-lockout-v2",
        name: "PLC Credential Lockout (Phase 4 - 2026)",
        sequence: [
          { order: 1, action: "Identify internet-facing PLC", mitreTechnique: "T0846", detail: "Shodan/Censys scanning for Rockwell MicroLogix on port 44818", typicalDwellMs: null },
          { order: 2, action: "Exploit default/weak credentials", mitreTechnique: "T0812", detail: "Default factory passwords or brute-force common credentials", typicalDwellMs: 3600000 },
          { order: 3, action: "Change PLC IP address", mitreTechnique: "T0843", detail: "Redirect to attacker-controlled IP, operators lose visibility", typicalDwellMs: 300000 },
          { order: 4, action: "Change PLC password", mitreTechnique: "T0843", detail: "Lock out legitimate operators from device management", typicalDwellMs: 60000 },
          { order: 5, action: "Modify HMI display (optional)", mitreTechnique: "T0814", detail: "Anti-Israel/anti-US propaganda on operator screens", typicalDwellMs: 300000 },
          { order: 6, action: "Cause operational disruption", mitreTechnique: "T0816", detail: "Pressure loss, flooding, or plant shutdown", typicalDwellMs: null },
          { order: 7, action: "Exit — no persistence", mitreTechnique: null, detail: "Minimal dwell time, no ransomware, no data exfiltration", typicalDwellMs: null },
        ],
        observationCount: 30,
        campaignIds: ["minnesota-water-2026", "pennsylvania-water-2023", "israel-water-2020"],
        confidence: 0.95,
      },
      {
        id: "ca3-unitronics-v1",
        name: "Unitronics Default Password (Phase 3 - 2023)",
        sequence: [
          { order: 1, action: "Scan for Unitronics Vision/Samba PLCs", mitreTechnique: "T0846", detail: "Port 20256 (PCOM protocol)", typicalDwellMs: null },
          { order: 2, action: "Login with default password '1111'", mitreTechnique: "T0812", detail: "Factory default on all Unitronics devices", typicalDwellMs: 1800000 },
          { order: 3, action: "Deface HMI screen", mitreTechnique: "T0814", detail: "'You have been hacked. Down with Israel.'", typicalDwellMs: 120000 },
          { order: 4, action: "Disable device (optional)", mitreTechnique: "T0816", detail: "Some devices powered off or reset", typicalDwellMs: 60000 },
          { order: 5, action: "Post claim on Telegram", mitreTechnique: null, detail: "Screenshot of defaced HMI posted within hours", typicalDwellMs: null },
        ],
        observationCount: 15,
        campaignIds: ["aliquippa-water-2023", "ireland-water-2023", "multi-state-unitronics-2023"],
        confidence: 0.95,
      },
    ],
    infrastructurePatterns: [
      { type: "vps_provider", value: "DigitalOcean", firstSeen: Date.parse("2023-01-01"), lastSeen: Date.parse("2025-06-01"), campaigns: ["aliquippa-water-2023"], confidence: 0.6 },
      { type: "vps_provider", value: "Hetzner", firstSeen: Date.parse("2024-01-01"), lastSeen: Date.parse("2025-12-01"), campaigns: ["iocontrol-campaign"], confidence: 0.5 },
    ],
    malwareLineage: [
      {
        familyName: "IOCONTROL",
        variant: "v1",
        parentVariant: null,
        sharedIndicators: { encryptionRoutine: true, mutex: true, configFormat: true, c2Protocol: true, stringTable: true, packerSignature: false },
        firstSeen: Date.parse("2024-06-01"),
        lastSeen: Date.parse("2025-12-01"),
        source: "Claroty Team82 / CISA",
      },
    ],
    campaigns: [
      { id: "minnesota-water-2026", name: "Minnesota Water Utility Campaign", startDate: Date.parse("2026-07-23"), endDate: Date.parse("2026-07-27"), victimSectors: ["water"], victimCountries: ["US"], techniques: ["T0803", "T0843", "T0814", "T0816"], malware: [], infrastructure: [], impactType: "operational_disruption", source: "FBI PSA / CISA AA26-097A" },
      { id: "seven-states-2026", name: "Seven-State Water Infrastructure Campaign", startDate: Date.parse("2026-07-23"), endDate: Date.parse("2026-07-30"), victimSectors: ["water", "wastewater"], victimCountries: ["US"], techniques: ["T0803", "T0843", "T0816"], malware: [], infrastructure: [], impactType: "operational_disruption", source: "FBI / NBC News" },
      { id: "aliquippa-water-2023", name: "Aliquippa Municipal Water Authority", startDate: Date.parse("2023-11-25"), endDate: Date.parse("2023-11-25"), victimSectors: ["water"], victimCountries: ["US"], techniques: ["T0812", "T0814"], malware: [], infrastructure: [], impactType: "hmi_defacement", source: "CISA AA23-335A" },
      { id: "iocontrol-campaign", name: "IOCONTROL Malware Deployment", startDate: Date.parse("2024-06-01"), endDate: Date.parse("2025-12-01"), victimSectors: ["water", "energy"], victimCountries: ["US", "IL"], techniques: ["T0803", "T0843", "T0814"], malware: ["IOCONTROL"], infrastructure: ["Hetzner VPS"], impactType: "persistent_access", source: "Claroty Team82" },
    ],
    profileCompleteness: 92,
    lastUpdated: Date.now(),
  },

  // ─── Sandworm (GRU Unit 74455) ───────────────────────────────────────────
  {
    actorId: "sandworm",
    name: "Sandworm",
    aliases: ["Sandworm Team", "ELECTRUM", "Voodoo Bear", "IRIDIUM", "Telebots", "Iron Viking", "GRU Unit 74455"],
    attribution: {
      technicalOperator: { name: "GRU Unit 74455", confidence: 0.95, evidence: ["DOJ indictments (2020)", "Multiple government attributions", "Olympic Destroyer forensics"] },
      publicPersona: { name: null, confidence: 0, evidence: [] },
      stateSponsor: { name: "Russian Federation (GRU)", confidence: 0.97, evidence: ["DOJ indictment Oct 2020", "UK NCSC attribution", "EU Council attribution"] },
    },
    origin: "Russia",
    motivation: ["disruption", "destruction", "espionage", "military_support"],
    sophistication: "nation-state",
    firstSeen: Date.parse("2009-01-01"),
    lastActive: Date.parse("2026-03-01"),
    operationalTempo: {
      primaryUtcOffset: 3, // Moscow Time
      secondaryUtcOffset: null,
      hourlyDistribution: [0,0,0,0,0,0.1,0.2,0.5,0.8,0.9,1.0,0.9,0.8,0.9,1.0,0.9,0.7,0.5,0.3,0.2,0.1,0,0,0],
      dailyDistribution: [0.9,0.9,0.9,0.9,0.8,0.3,0.1], // Mon-Fri active
      avgCampaignIntervalDays: 90,
      avgCampaignDurationDays: 14,
      holidayCorrelation: [
        { holiday: "Russian national holidays", avoidance: true, confidence: 0.7 },
        { holiday: "Ukrainian holidays", avoidance: false, confidence: 0.8 },
      ],
      geopoliticalTriggers: [
        { event: "Russian military operations", responseDelayHours: 12, confidence: 0.9 },
        { event: "Ukrainian counter-offensive", responseDelayHours: 24, confidence: 0.8 },
      ],
    },
    genome: [
      { category: "victim_sector", name: "energy", value: 0.95, confidence: 0.95, source: "Industroyer/Industroyer2", lastObserved: Date.parse("2022-04-01"), observationCount: 10 },
      { category: "victim_sector", name: "government", value: 0.8, confidence: 0.85, source: "NotPetya, Olympic Destroyer", lastObserved: Date.parse("2022-01-01"), observationCount: 15 },
      { category: "victim_sector", name: "transportation", value: 0.5, confidence: 0.6, source: "Ukraine rail attacks", lastObserved: Date.parse("2022-03-01"), observationCount: 3 },
      { category: "victim_geography", name: "ukraine", value: 0.95, confidence: 0.95, source: "Primary target since 2015", lastObserved: Date.parse("2026-03-01"), observationCount: 50 },
      { category: "plc_vendor", name: "siemens", value: 0.85, confidence: 0.85, source: "Industroyer analysis", lastObserved: Date.parse("2022-04-01"), observationCount: 5 },
      { category: "plc_vendor", name: "abb", value: 0.6, confidence: 0.6, source: "Industroyer2 targeting", lastObserved: Date.parse("2022-04-01"), observationCount: 3 },
      { category: "ics_protocol", name: "iec_104", value: 0.9, confidence: 0.9, source: "Industroyer", lastObserved: Date.parse("2022-04-01"), observationCount: 5 },
      { category: "ics_protocol", name: "iec_61850", value: 0.7, confidence: 0.7, source: "Industroyer", lastObserved: Date.parse("2017-12-01"), observationCount: 2 },
      { category: "ics_protocol", name: "opc_da", value: 0.6, confidence: 0.6, source: "Industroyer", lastObserved: Date.parse("2017-12-01"), observationCount: 2 },
      { category: "malware_family", name: "industroyer", value: 0.95, confidence: 0.95, source: "ESET/Dragos analysis", lastObserved: Date.parse("2022-04-01"), observationCount: 3 },
      { category: "malware_family", name: "notpetya", value: 0.9, confidence: 0.95, source: "Global attribution", lastObserved: Date.parse("2017-06-01"), observationCount: 1 },
      { category: "malware_family", name: "cyclops_blink", value: 0.85, confidence: 0.85, source: "NCSC/CISA", lastObserved: Date.parse("2022-02-01"), observationCount: 2 },
      { category: "malware_family", name: "caddywiper", value: 0.8, confidence: 0.8, source: "ESET", lastObserved: Date.parse("2022-03-01"), observationCount: 4 },
      { category: "attack_technique", name: "T0831", value: 0.9, confidence: 0.9, source: "Industroyer — manipulation of control", lastObserved: Date.parse("2022-04-01"), observationCount: 5 },
      { category: "attack_technique", name: "T1486", value: 0.85, confidence: 0.85, source: "Wiper campaigns (NotPetya, CaddyWiper)", lastObserved: Date.parse("2022-03-01"), observationCount: 8 },
      { category: "impact_type", name: "destruction", value: 0.9, confidence: 0.9, source: "NotPetya, wipers", lastObserved: Date.parse("2022-04-01"), observationCount: 10 },
      { category: "impact_type", name: "power_outage", value: 0.85, confidence: 0.9, source: "Ukraine 2015, 2016, 2022", lastObserved: Date.parse("2022-04-01"), observationCount: 3 },
      { category: "dwell_time_pattern", name: "long_dwell", value: 0.8, confidence: 0.8, source: "Months of preparation before destructive payload", lastObserved: Date.parse("2022-04-01"), observationCount: 5 },
      { category: "operational_timing", name: "moscow_work_hours", value: 0.8, confidence: 0.75, source: "Temporal analysis", lastObserved: Date.parse("2022-04-01"), observationCount: 20 },
    ],
    tradecraftFingerprints: [
      {
        id: "sandworm-grid-attack",
        name: "Electric Grid Disruption (Industroyer Pattern)",
        sequence: [
          { order: 1, action: "Spearphish corporate IT network", mitreTechnique: "T1566", detail: "Targeted phishing to energy company employees", typicalDwellMs: null },
          { order: 2, action: "Lateral movement to OT network", mitreTechnique: "T0866", detail: "Pivot from IT to OT via shared credentials or jump hosts", typicalDwellMs: 2592000000 },
          { order: 3, action: "Map SCADA/ICS environment", mitreTechnique: "T0846", detail: "Identify RTUs, protocol gateways, and substation topology", typicalDwellMs: 1209600000 },
          { order: 4, action: "Deploy custom ICS malware", mitreTechnique: "T0831", detail: "Industroyer/Industroyer2 with protocol-specific payloads", typicalDwellMs: 604800000 },
          { order: 5, action: "Execute coordinated grid disruption", mitreTechnique: "T0813", detail: "Open breakers across multiple substations simultaneously", typicalDwellMs: null },
          { order: 6, action: "Deploy wiper on IT systems", mitreTechnique: "T1485", detail: "CaddyWiper/KillDisk to destroy forensic evidence", typicalDwellMs: 3600000 },
        ],
        observationCount: 3,
        campaignIds: ["ukraine-grid-2015", "ukraine-grid-2016", "ukraine-grid-2022"],
        confidence: 0.95,
      },
    ],
    infrastructurePatterns: [],
    malwareLineage: [
      { familyName: "Industroyer", variant: "v1", parentVariant: null, sharedIndicators: { encryptionRoutine: true, mutex: false, configFormat: true, c2Protocol: true, stringTable: false, packerSignature: false }, firstSeen: Date.parse("2016-12-01"), lastSeen: Date.parse("2017-12-01"), source: "ESET" },
      { familyName: "Industroyer", variant: "v2", parentVariant: "v1", sharedIndicators: { encryptionRoutine: true, mutex: false, configFormat: true, c2Protocol: true, stringTable: false, packerSignature: false }, firstSeen: Date.parse("2022-04-01"), lastSeen: Date.parse("2022-04-01"), source: "ESET/CERT-UA" },
    ],
    campaigns: [
      { id: "ukraine-grid-2015", name: "Ukraine Power Grid Attack (BlackEnergy)", startDate: Date.parse("2015-12-23"), endDate: Date.parse("2015-12-23"), victimSectors: ["energy"], victimCountries: ["UA"], techniques: ["T0831", "T0813"], malware: ["BlackEnergy", "KillDisk"], infrastructure: [], impactType: "power_outage", source: "SANS ICS / E-ISAC" },
      { id: "ukraine-grid-2016", name: "Ukraine Power Grid Attack (Industroyer)", startDate: Date.parse("2016-12-17"), endDate: Date.parse("2016-12-17"), victimSectors: ["energy"], victimCountries: ["UA"], techniques: ["T0831", "T0813"], malware: ["Industroyer"], infrastructure: [], impactType: "power_outage", source: "ESET / Dragos" },
      { id: "ukraine-grid-2022", name: "Ukraine Grid Attack (Industroyer2)", startDate: Date.parse("2022-04-08"), endDate: Date.parse("2022-04-08"), victimSectors: ["energy"], victimCountries: ["UA"], techniques: ["T0831", "T0813", "T1485"], malware: ["Industroyer2", "CaddyWiper"], infrastructure: [], impactType: "attempted_power_outage", source: "CERT-UA / ESET" },
    ],
    profileCompleteness: 88,
    lastUpdated: Date.now(),
  },

  // ─── Volt Typhoon (PRC MSS) ──────────────────────────────────────────────
  {
    actorId: "volt-typhoon",
    name: "Volt Typhoon",
    aliases: ["VANGUARD PANDA", "Bronze Silhouette", "DEV-0391", "Insidious Taurus", "UNC3236"],
    attribution: {
      technicalOperator: { name: "Volt Typhoon", confidence: 0.9, evidence: ["Microsoft attribution May 2023", "CISA AA24-038A", "Five Eyes joint advisory"] },
      publicPersona: { name: null, confidence: 0, evidence: [] },
      stateSponsor: { name: "People's Republic of China (PRC)", confidence: 0.92, evidence: ["Five Eyes joint advisory", "CISA/NSA/FBI attribution", "Microsoft Threat Intelligence"] },
    },
    origin: "China",
    motivation: ["pre-positioning", "espionage", "disruption_preparation"],
    sophistication: "nation-state",
    firstSeen: Date.parse("2021-06-01"),
    lastActive: Date.parse("2026-06-01"),
    operationalTempo: {
      primaryUtcOffset: 8, // China Standard Time
      secondaryUtcOffset: null,
      hourlyDistribution: [0,0,0,0,0,0.1,0.3,0.5,0.7,0.9,1.0,0.9,0.8,0.9,1.0,0.9,0.7,0.5,0.3,0.1,0,0,0,0],
      dailyDistribution: [0.9,0.9,0.9,0.9,0.8,0.2,0.1],
      avgCampaignIntervalDays: 0, // Continuous/persistent
      avgCampaignDurationDays: 365, // Long-term access
      holidayCorrelation: [
        { holiday: "Chinese New Year", avoidance: true, confidence: 0.7 },
        { holiday: "Golden Week", avoidance: true, confidence: 0.6 },
      ],
      geopoliticalTriggers: [
        { event: "Taiwan Strait tensions", responseDelayHours: 168, confidence: 0.7 },
        { event: "US-China trade actions", responseDelayHours: 336, confidence: 0.5 },
      ],
    },
    genome: [
      { category: "victim_sector", name: "critical_infrastructure", value: 0.95, confidence: 0.9, source: "CISA AA24-038A", lastObserved: Date.parse("2026-06-01"), observationCount: 20 },
      { category: "victim_sector", name: "water", value: 0.7, confidence: 0.7, source: "CISA advisory", lastObserved: Date.parse("2025-01-01"), observationCount: 5 },
      { category: "victim_sector", name: "energy", value: 0.8, confidence: 0.8, source: "CISA advisory", lastObserved: Date.parse("2025-06-01"), observationCount: 8 },
      { category: "victim_sector", name: "transportation", value: 0.7, confidence: 0.7, source: "CISA advisory", lastObserved: Date.parse("2025-01-01"), observationCount: 4 },
      { category: "victim_sector", name: "communications", value: 0.8, confidence: 0.8, source: "CISA advisory", lastObserved: Date.parse("2025-06-01"), observationCount: 6 },
      { category: "victim_geography", name: "united_states", value: 0.95, confidence: 0.95, source: "All reporting", lastObserved: Date.parse("2026-06-01"), observationCount: 25 },
      { category: "victim_geography", name: "guam", value: 0.8, confidence: 0.8, source: "Microsoft initial report", lastObserved: Date.parse("2023-05-01"), observationCount: 3 },
      { category: "initial_access", name: "edge_device_exploitation", value: 0.95, confidence: 0.9, source: "Fortinet, Ivanti, Cisco exploitation", lastObserved: Date.parse("2026-06-01"), observationCount: 20 },
      { category: "initial_access", name: "soho_router_compromise", value: 0.9, confidence: 0.9, source: "KV Botnet (SOHO routers)", lastObserved: Date.parse("2024-12-01"), observationCount: 15 },
      { category: "persistence_method", name: "living_off_the_land", value: 0.99, confidence: 0.95, source: "Defining characteristic", lastObserved: Date.parse("2026-06-01"), observationCount: 25 },
      { category: "tool_usage", name: "ntdsutil", value: 0.8, confidence: 0.8, source: "AD credential harvesting", lastObserved: Date.parse("2025-06-01"), observationCount: 10 },
      { category: "tool_usage", name: "netsh", value: 0.85, confidence: 0.85, source: "Port forwarding/proxy", lastObserved: Date.parse("2025-06-01"), observationCount: 12 },
      { category: "tool_usage", name: "wmic", value: 0.8, confidence: 0.8, source: "Discovery/execution", lastObserved: Date.parse("2025-06-01"), observationCount: 10 },
      { category: "tool_usage", name: "powershell", value: 0.7, confidence: 0.7, source: "Minimal usage to avoid detection", lastObserved: Date.parse("2025-06-01"), observationCount: 8 },
      { category: "malware_family", name: "none_lotl_only", value: 0.95, confidence: 0.9, source: "No custom malware — LOTL exclusively", lastObserved: Date.parse("2026-06-01"), observationCount: 25 },
      { category: "attack_technique", name: "T1059.001", value: 0.7, confidence: 0.7, source: "PowerShell (minimal)", lastObserved: Date.parse("2025-06-01"), observationCount: 8 },
      { category: "attack_technique", name: "T1003.003", value: 0.85, confidence: 0.85, source: "NTDS.dit extraction", lastObserved: Date.parse("2025-06-01"), observationCount: 10 },
      { category: "attack_technique", name: "T1090", value: 0.9, confidence: 0.9, source: "Multi-hop proxy via SOHO routers", lastObserved: Date.parse("2025-06-01"), observationCount: 15 },
      { category: "c2_infrastructure", name: "soho_router_proxy", value: 0.95, confidence: 0.9, source: "KV Botnet infrastructure", lastObserved: Date.parse("2024-12-01"), observationCount: 15 },
      { category: "impact_type", name: "pre_positioning", value: 0.95, confidence: 0.9, source: "No destructive action observed — access maintenance", lastObserved: Date.parse("2026-06-01"), observationCount: 25 },
      { category: "dwell_time_pattern", name: "extreme_long_dwell", value: 0.95, confidence: 0.9, source: "5+ years in some networks", lastObserved: Date.parse("2026-06-01"), observationCount: 10 },
      { category: "operational_timing", name: "beijing_work_hours", value: 0.75, confidence: 0.7, source: "Temporal analysis", lastObserved: Date.parse("2025-06-01"), observationCount: 15 },
    ],
    tradecraftFingerprints: [
      {
        id: "vt-lotl-preposition",
        name: "Living-off-the-Land Pre-Positioning",
        sequence: [
          { order: 1, action: "Exploit edge device (Fortinet/Ivanti/Cisco)", mitreTechnique: "T1190", detail: "Zero-day or N-day on internet-facing appliance", typicalDwellMs: null },
          { order: 2, action: "Establish SOHO router proxy chain", mitreTechnique: "T1090", detail: "Compromised home routers as C2 relay (KV Botnet)", typicalDwellMs: 604800000 },
          { order: 3, action: "Harvest AD credentials via LOTL", mitreTechnique: "T1003.003", detail: "ntdsutil, secretsdump — no malware dropped", typicalDwellMs: 2592000000 },
          { order: 4, action: "Map OT/ICS network from IT side", mitreTechnique: "T0846", detail: "Identify OT assets without crossing air gap", typicalDwellMs: 7776000000 },
          { order: 5, action: "Maintain persistent access (years)", mitreTechnique: "T1078", detail: "Valid accounts, scheduled tasks, no custom implants", typicalDwellMs: null },
        ],
        observationCount: 10,
        campaignIds: ["guam-preposition-2023", "us-ci-preposition-2024"],
        confidence: 0.9,
      },
    ],
    infrastructurePatterns: [
      { type: "hosting", value: "Compromised SOHO routers (Netgear, Cisco, DrayTek)", firstSeen: Date.parse("2022-01-01"), lastSeen: Date.parse("2024-12-01"), campaigns: ["kv-botnet"], confidence: 0.9 },
    ],
    malwareLineage: [],
    campaigns: [
      { id: "guam-preposition-2023", name: "Guam Critical Infrastructure Pre-Positioning", startDate: Date.parse("2021-06-01"), endDate: null, victimSectors: ["communications", "energy", "water", "transportation"], victimCountries: ["US"], techniques: ["T1190", "T1090", "T1003.003", "T1078"], malware: [], infrastructure: ["KV Botnet SOHO routers"], impactType: "pre_positioning", source: "Microsoft / CISA" },
    ],
    profileCompleteness: 82,
    lastUpdated: Date.now(),
  },

  // ─── XENOTIME / TRITON ───────────────────────────────────────────────────
  {
    actorId: "xenotime",
    name: "XENOTIME",
    aliases: ["TEMP.Veles", "TRITON Actor", "TRISIS Actor"],
    attribution: {
      technicalOperator: { name: "Central Scientific Research Institute of Chemistry and Mechanics (TsNIIKhM)", confidence: 0.85, evidence: ["FireEye/Mandiant attribution", "DOJ references", "IP address trace to Moscow institute"] },
      publicPersona: { name: null, confidence: 0, evidence: [] },
      stateSponsor: { name: "Russian Federation (likely GRU or FSB-adjacent)", confidence: 0.8, evidence: ["TsNIIKhM is Russian government research institute", "FireEye attribution report", "US Treasury sanctions"] },
    },
    origin: "Russia",
    motivation: ["destruction", "safety_system_compromise", "deterrence"],
    sophistication: "nation-state",
    firstSeen: Date.parse("2017-08-01"),
    lastActive: Date.parse("2025-01-01"),
    operationalTempo: {
      primaryUtcOffset: 3,
      secondaryUtcOffset: null,
      hourlyDistribution: [0,0,0,0,0,0.1,0.2,0.5,0.8,0.9,1.0,0.9,0.8,0.9,0.8,0.7,0.5,0.3,0.1,0,0,0,0,0],
      dailyDistribution: [0.8,0.9,0.9,0.9,0.8,0.2,0.1],
      avgCampaignIntervalDays: 180,
      avgCampaignDurationDays: 60,
      holidayCorrelation: [],
      geopoliticalTriggers: [],
    },
    genome: [
      { category: "victim_sector", name: "oil_gas", value: 0.95, confidence: 0.9, source: "Saudi Aramco TRITON incident", lastObserved: Date.parse("2017-12-01"), observationCount: 2 },
      { category: "victim_sector", name: "energy", value: 0.8, confidence: 0.7, source: "Dragos scanning activity", lastObserved: Date.parse("2019-06-01"), observationCount: 5 },
      { category: "victim_geography", name: "saudi_arabia", value: 0.9, confidence: 0.9, source: "TRITON incident", lastObserved: Date.parse("2017-12-01"), observationCount: 1 },
      { category: "victim_geography", name: "middle_east", value: 0.7, confidence: 0.7, source: "Dragos reporting", lastObserved: Date.parse("2019-06-01"), observationCount: 3 },
      { category: "plc_vendor", name: "schneider_electric", value: 0.95, confidence: 0.95, source: "Triconex SIS targeting", lastObserved: Date.parse("2017-12-01"), observationCount: 2 },
      { category: "ics_protocol", name: "tristation", value: 0.95, confidence: 0.95, source: "TRITON malware protocol", lastObserved: Date.parse("2017-12-01"), observationCount: 2 },
      { category: "malware_family", name: "triton", value: 0.99, confidence: 0.99, source: "Defining malware", lastObserved: Date.parse("2017-12-01"), observationCount: 2 },
      { category: "attack_technique", name: "T0836", value: 0.95, confidence: 0.95, source: "Safety system manipulation", lastObserved: Date.parse("2017-12-01"), observationCount: 2 },
      { category: "impact_type", name: "safety_system_compromise", value: 0.99, confidence: 0.99, source: "Only known actor to target SIS", lastObserved: Date.parse("2017-12-01"), observationCount: 2 },
      { category: "dwell_time_pattern", name: "long_dwell", value: 0.85, confidence: 0.8, source: "Months inside OT network before SIS targeting", lastObserved: Date.parse("2017-12-01"), observationCount: 2 },
    ],
    tradecraftFingerprints: [
      {
        id: "xenotime-sis-attack",
        name: "Safety Instrumented System Compromise",
        sequence: [
          { order: 1, action: "Gain IT network access (spearphish or supply chain)", mitreTechnique: "T1566", detail: "Initial foothold in corporate network", typicalDwellMs: null },
          { order: 2, action: "Pivot to OT/DCS network", mitreTechnique: "T0866", detail: "Cross IT/OT boundary via engineering workstation", typicalDwellMs: 5184000000 },
          { order: 3, action: "Identify Safety Instrumented System", mitreTechnique: "T0846", detail: "Locate Triconex controllers on SIS network", typicalDwellMs: 2592000000 },
          { order: 4, action: "Deploy TRITON framework to engineering workstation", mitreTechnique: "T0862", detail: "Custom Python framework for TriStation protocol", typicalDwellMs: 1209600000 },
          { order: 5, action: "Inject malicious ladder logic into SIS controller", mitreTechnique: "T0836", detail: "Modify safety logic to allow unsafe conditions", typicalDwellMs: 604800000 },
          { order: 6, action: "Attempt to disable safety shutdown", mitreTechnique: "T0880", detail: "Prevent SIS from triggering on dangerous process state", typicalDwellMs: null },
        ],
        observationCount: 2,
        campaignIds: ["triton-saudi-2017"],
        confidence: 0.95,
      },
    ],
    infrastructurePatterns: [],
    malwareLineage: [
      { familyName: "TRITON", variant: "v1", parentVariant: null, sharedIndicators: { encryptionRoutine: true, mutex: false, configFormat: true, c2Protocol: true, stringTable: true, packerSignature: false }, firstSeen: Date.parse("2017-08-01"), lastSeen: Date.parse("2017-12-01"), source: "FireEye/Dragos" },
    ],
    campaigns: [
      { id: "triton-saudi-2017", name: "TRITON/TRISIS Safety System Attack", startDate: Date.parse("2017-06-01"), endDate: Date.parse("2017-12-01"), victimSectors: ["oil_gas"], victimCountries: ["SA"], techniques: ["T0836", "T0862", "T0846"], malware: ["TRITON"], infrastructure: [], impactType: "safety_system_compromise", source: "FireEye / Dragos / CISA" },
    ],
    profileCompleteness: 75,
    lastUpdated: Date.now(),
  },

  // ─── Handala (MOIS-linked persona) ────────────────────────────────────────
  {
    actorId: "handala",
    name: "Handala",
    aliases: ["Handala Hack", "Handala Team"],
    attribution: {
      technicalOperator: { name: "Unknown — possibly CyberAv3ngers or separate MOIS unit", confidence: 0.3, evidence: ["No independent technical verification", "Claims only via state media"] },
      publicPersona: { name: "Handala", confidence: 0.9, evidence: ["Iranian state media amplification", "Telegram channel", "Claims on multiple attacks"] },
      stateSponsor: { name: "Iran (MOIS — Ministry of Intelligence)", confidence: 0.6, evidence: ["State media promotion pattern", "Timing alignment with MOIS operations", "Distinct from IRGC-CEC groups"] },
    },
    origin: "Iran",
    motivation: ["propaganda", "influence_operations", "claim_amplification"],
    sophistication: "intermediate",
    firstSeen: Date.parse("2023-10-01"),
    lastActive: Date.parse("2026-07-30"),
    operationalTempo: {
      primaryUtcOffset: 3.5,
      secondaryUtcOffset: null,
      hourlyDistribution: [0,0,0,0,0,0.1,0.2,0.4,0.6,0.7,0.8,0.7,0.6,0.7,0.8,0.7,0.5,0.3,0.2,0.1,0,0,0,0],
      dailyDistribution: [0.3,0.7,0.7,0.7,0.7,0.2,0.1],
      avgCampaignIntervalDays: 30,
      avgCampaignDurationDays: 1,
      holidayCorrelation: [],
      geopoliticalTriggers: [
        { event: "Israeli military operations", responseDelayHours: 48, confidence: 0.8 },
        { event: "Other Iranian group attacks", responseDelayHours: 72, confidence: 0.7 },
      ],
    },
    genome: [
      { category: "victim_sector", name: "water_utility", value: 0.5, confidence: 0.3, source: "Claims only — unverified", lastObserved: Date.parse("2026-07-30"), observationCount: 3 },
      { category: "victim_geography", name: "united_states", value: 0.5, confidence: 0.3, source: "Claims only", lastObserved: Date.parse("2026-07-30"), observationCount: 3 },
      { category: "victim_geography", name: "israel", value: 0.7, confidence: 0.5, source: "Multiple claims", lastObserved: Date.parse("2026-07-30"), observationCount: 8 },
      { category: "propaganda_behavior", name: "post_hoc_claims", value: 0.95, confidence: 0.9, source: "Claims credit 48-72h after attacks by others", lastObserved: Date.parse("2026-07-30"), observationCount: 10 },
      { category: "propaganda_behavior", name: "state_media_amplification", value: 0.9, confidence: 0.85, source: "Iranian state media promotes claims", lastObserved: Date.parse("2026-07-30"), observationCount: 8 },
      { category: "impact_type", name: "influence_operation", value: 0.9, confidence: 0.85, source: "Primary function is information warfare", lastObserved: Date.parse("2026-07-30"), observationCount: 10 },
    ],
    tradecraftFingerprints: [],
    infrastructurePatterns: [],
    malwareLineage: [],
    campaigns: [
      { id: "handala-minnesota-claim-2026", name: "Minnesota Water Attack Claim (Unverified)", startDate: Date.parse("2026-07-26"), endDate: Date.parse("2026-07-30"), victimSectors: ["water"], victimCountries: ["US"], techniques: [], malware: [], infrastructure: [], impactType: "claim_only", source: "Iranian state media / Telegram" },
      { id: "handala-california-claim-2026", name: "California Water Service Claim", startDate: Date.parse("2026-07-01"), endDate: Date.parse("2026-07-05"), victimSectors: ["water"], victimCountries: ["US"], techniques: [], malware: [], infrastructure: [], impactType: "claim_only", source: "Telegram" },
    ],
    profileCompleteness: 45,
    lastUpdated: Date.now(),
  },
];

// ─── Scoring Engine ─────────────────────────────────────────────────────────────

/**
 * Score an incident observation against all actor profiles
 */
export function scoreIncident(
  incident: IncidentObservation,
  options?: {
    weights?: Partial<Record<FeatureCategory, number>>;
    minScore?: number;
    maxResults?: number;
  }
): AttributionReport {
  const weights = { ...DEFAULT_FEATURE_WEIGHTS, ...(options?.weights || {}) };
  const minScore = options?.minScore ?? 5;
  const maxResults = options?.maxResults ?? 10;

  // Auto-detect if ICS incident and adjust weights
  const isIcsIncident = incident.plcVendors.length > 0 || incident.icsProtocols.length > 0 || incident.safetySystemTargeted || incident.plcLogicChanged;
  const effectiveWeights = isIcsIncident ? { ...ICS_FEATURE_WEIGHTS, ...(options?.weights || {}) } : weights;

  const rankings: AttributionScore[] = [];

  for (const actor of ACTOR_GENOME_DB) {
    const score = scoreActorAgainstIncident(actor, incident, effectiveWeights);
    if (score.overallScore >= minScore) {
      rankings.push(score);
    }
  }

  // Sort by overall score descending
  rankings.sort((a, b) => b.overallScore - a.overallScore);
  const topResults = rankings.slice(0, maxResults);

  // Generate narrative explanation
  const narrative = generateNarrative(topResults, incident);

  // Compute campaign similarity
  const campaignSimilarity = computeCampaignSimilarity(incident);

  return {
    incidentId: incident.id,
    incidentTitle: incident.title,
    scoredAt: Date.now(),
    rankings: topResults,
    topCandidate: topResults[0] || createEmptyScore(),
    narrativeExplanation: narrative,
    analystNotes: generateAnalystNotes(topResults, incident),
    campaignSimilarity,
  };
}

/**
 * Score a single actor against an incident
 */
function scoreActorAgainstIncident(
  actor: ActorGenomeProfile,
  incident: IncidentObservation,
  weights: Record<FeatureCategory, number>
): AttributionScore {
  const evidence: EvidenceItem[] = [];
  const conflicting: EvidenceItem[] = [];
  const categoryScores: { category: FeatureCategory; score: number; maxPossible: number; weight: number }[] = [];

  let totalPoints = 0;
  let maxPossiblePoints = 0;

  // ─── Score each feature category ─────────────────────────────────────────

  // 1. Malware family matching
  const malwareScore = scoreMalwareMatch(actor, incident, weights.malware_family);
  categoryScores.push({ category: "malware_family", ...malwareScore });
  totalPoints += malwareScore.score;
  maxPossiblePoints += malwareScore.maxPossible;
  evidence.push(...malwareScore.evidence);
  conflicting.push(...malwareScore.conflicting);

  // 2. ATT&CK technique overlap
  const techniqueScore = scoreTechniqueOverlap(actor, incident, weights.attack_technique);
  categoryScores.push({ category: "attack_technique", ...techniqueScore });
  totalPoints += techniqueScore.score;
  maxPossiblePoints += techniqueScore.maxPossible;
  evidence.push(...techniqueScore.evidence);

  // 3. PLC vendor matching
  const plcScore = scorePlcVendorMatch(actor, incident, weights.plc_vendor);
  categoryScores.push({ category: "plc_vendor", ...plcScore });
  totalPoints += plcScore.score;
  maxPossiblePoints += plcScore.maxPossible;
  evidence.push(...plcScore.evidence);

  // 4. Initial access method
  const accessScore = scoreInitialAccess(actor, incident, weights.initial_access);
  categoryScores.push({ category: "initial_access", ...accessScore });
  totalPoints += accessScore.score;
  maxPossiblePoints += accessScore.maxPossible;
  evidence.push(...accessScore.evidence);

  // 5. Victim sector
  const sectorScore = scoreVictimSector(actor, incident, weights.victim_sector);
  categoryScores.push({ category: "victim_sector", ...sectorScore });
  totalPoints += sectorScore.score;
  maxPossiblePoints += sectorScore.maxPossible;
  evidence.push(...sectorScore.evidence);

  // 6. Victim geography
  const geoScore = scoreVictimGeography(actor, incident, weights.victim_geography);
  categoryScores.push({ category: "victim_geography", ...geoScore });
  totalPoints += geoScore.score;
  maxPossiblePoints += geoScore.maxPossible;
  evidence.push(...geoScore.evidence);

  // 7. Credential behavior
  const credScore = scoreCredentialBehavior(actor, incident, weights.credential_behavior);
  categoryScores.push({ category: "credential_behavior", ...credScore });
  totalPoints += credScore.score;
  maxPossiblePoints += credScore.maxPossible;
  evidence.push(...credScore.evidence);

  // 8. Propaganda behavior
  const propScore = scorePropagandaBehavior(actor, incident, weights.propaganda_behavior);
  categoryScores.push({ category: "propaganda_behavior", ...propScore });
  totalPoints += propScore.score;
  maxPossiblePoints += propScore.maxPossible;
  evidence.push(...propScore.evidence);
  conflicting.push(...propScore.conflicting);

  // 9. Impact type
  const impactScore = scoreImpactType(actor, incident, weights.impact_type);
  categoryScores.push({ category: "impact_type", ...impactScore });
  totalPoints += impactScore.score;
  maxPossiblePoints += impactScore.maxPossible;
  evidence.push(...impactScore.evidence);

  // 10. Operational timing
  const timingScore = scoreOperationalTiming(actor, incident, weights.operational_timing);
  categoryScores.push({ category: "operational_timing", ...timingScore });
  totalPoints += timingScore.score;
  maxPossiblePoints += timingScore.maxPossible;
  evidence.push(...timingScore.evidence);

  // 11. Tradecraft fingerprint matching
  const tradecraftBonus = scoreTradecraftMatch(actor, incident);
  totalPoints += tradecraftBonus.score;
  evidence.push(...tradecraftBonus.evidence);

  // 12. ICS protocol matching
  const protocolScore = scoreIcsProtocol(actor, incident, weights.ics_protocol);
  categoryScores.push({ category: "ics_protocol", ...protocolScore });
  totalPoints += protocolScore.score;
  maxPossiblePoints += protocolScore.maxPossible;
  evidence.push(...protocolScore.evidence);

  // 13. Dwell time pattern
  const dwellScore = scoreDwellTime(actor, incident, weights.dwell_time_pattern);
  categoryScores.push({ category: "dwell_time_pattern", ...dwellScore });
  totalPoints += dwellScore.score;
  maxPossiblePoints += dwellScore.maxPossible;
  evidence.push(...dwellScore.evidence);

  // Normalize to 0-100
  const overallScore = maxPossiblePoints > 0 ? Math.min(100, Math.round((totalPoints / maxPossiblePoints) * 100)) : 0;

  // Determine confidence
  const confidence: "high" | "moderate" | "low" =
    overallScore >= 75 && conflicting.length <= 1 ? "high" :
    overallScore >= 50 ? "moderate" : "low";

  // Three-layer scoring
  const layers = {
    technicalOperator: { score: overallScore, confidence: actor.attribution.technicalOperator.confidence },
    publicPersona: {
      score: incident.publicClaims.some(c => actor.aliases.some(a => a.toLowerCase().includes(c.persona.toLowerCase()))) ? 90 : 10,
      confidence: actor.attribution.publicPersona.confidence,
    },
    stateSponsor: { score: overallScore * actor.attribution.stateSponsor.confidence, confidence: actor.attribution.stateSponsor.confidence },
  };

  return {
    actorId: actor.actorId,
    actorName: actor.name,
    overallScore,
    confidence,
    layers,
    evidence: evidence.filter(e => e.disposition === "supporting"),
    categoryScores,
    conflictingEvidence: conflicting,
    alternativeHypotheses: generateAlternativeHypotheses(actor, incident, conflicting),
  };
}

// ─── Category Scoring Functions ─────────────────────────────────────────────────

interface CategoryScoreResult {
  score: number;
  maxPossible: number;
  weight: number;
  evidence: EvidenceItem[];
  conflicting: EvidenceItem[];
}

function scoreMalwareMatch(actor: ActorGenomeProfile, incident: IncidentObservation, weight: number): CategoryScoreResult {
  const evidence: EvidenceItem[] = [];
  const conflicting: EvidenceItem[] = [];
  let score = 0;
  const maxPossible = weight;

  if (incident.malwareObserved.length === 0) {
    // No malware observed — check if actor is known for LOTL
    const lotlFeature = actor.genome.find(f => f.category === "malware_family" && f.name.includes("none"));
    if (lotlFeature) {
      score = weight * 0.5 * lotlFeature.value;
      evidence.push({
        category: "malware_family",
        indicator: "No malware observed (consistent with LOTL actor)",
        pointsAwarded: score,
        maxPoints: weight,
        disposition: "supporting",
        explanation: `${actor.name} is known for living-off-the-land operations without custom malware`,
        source: lotlFeature.source,
        confidence: lotlFeature.confidence * 0.7,
      });
    } else {
      // No malware but actor uses malware — conflicting
      const malwareFeatures = actor.genome.filter(f => f.category === "malware_family" && !f.name.includes("none"));
      if (malwareFeatures.length > 0) {
        conflicting.push({
          category: "malware_family",
          indicator: `No malware recovered (${actor.name} typically deploys ${malwareFeatures[0].name})`,
          pointsAwarded: -weight * 0.3,
          maxPoints: weight,
          disposition: "conflicting",
          explanation: `Expected malware from ${actor.name} was not observed`,
          source: "Absence of evidence",
          confidence: 0.5,
        });
        score = -weight * 0.3;
      }
    }
  } else {
    // Match observed malware against actor's known families
    for (const observed of incident.malwareObserved) {
      const match = actor.genome.find(f =>
        f.category === "malware_family" &&
        f.name.toLowerCase().includes(observed.toLowerCase())
      );
      if (match) {
        const points = weight * match.value * match.confidence;
        score += points;
        evidence.push({
          category: "malware_family",
          indicator: observed,
          pointsAwarded: points,
          maxPoints: weight,
          disposition: "supporting",
          explanation: `${observed} is a known tool of ${actor.name} (observed ${match.observationCount} times)`,
          source: match.source,
          confidence: match.confidence,
        });
      }
    }
  }

  return { score: Math.max(0, score), maxPossible, weight, evidence, conflicting };
}

function scoreTechniqueOverlap(actor: ActorGenomeProfile, incident: IncidentObservation, weight: number): CategoryScoreResult {
  const evidence: EvidenceItem[] = [];
  let score = 0;
  const maxPossible = weight;

  if (incident.techniques.length === 0) return { score: 0, maxPossible, weight, evidence, conflicting: [] };

  const actorTechniques = actor.genome.filter(f => f.category === "attack_technique");
  let matchCount = 0;

  for (const technique of incident.techniques) {
    const match = actorTechniques.find(f => f.name === technique);
    if (match) {
      matchCount++;
      const points = (weight / Math.max(incident.techniques.length, 3)) * match.value * match.confidence;
      score += points;
      evidence.push({
        category: "attack_technique",
        indicator: technique,
        pointsAwarded: points,
        maxPoints: weight / incident.techniques.length,
        disposition: "supporting",
        explanation: `${technique} is used by ${actor.name} (confidence: ${Math.round(match.confidence * 100)}%)`,
        source: match.source,
        confidence: match.confidence,
      });
    }
  }

  // Bonus for high overlap percentage
  const overlapRatio = matchCount / incident.techniques.length;
  if (overlapRatio > 0.7) {
    score *= 1.2; // 20% bonus for strong overlap
  }

  return { score: Math.min(score, maxPossible), maxPossible, weight, evidence, conflicting: [] };
}

function scorePlcVendorMatch(actor: ActorGenomeProfile, incident: IncidentObservation, weight: number): CategoryScoreResult {
  const evidence: EvidenceItem[] = [];
  let score = 0;
  const maxPossible = weight;

  if (incident.plcVendors.length === 0) return { score: 0, maxPossible, weight, evidence, conflicting: [] };

  for (const vendor of incident.plcVendors) {
    const match = actor.genome.find(f =>
      f.category === "plc_vendor" &&
      f.name.toLowerCase().includes(vendor.toLowerCase())
    );
    if (match) {
      const points = weight * match.value * match.confidence;
      score += points;
      evidence.push({
        category: "plc_vendor",
        indicator: vendor,
        pointsAwarded: points,
        maxPoints: weight,
        disposition: "supporting",
        explanation: `${actor.name} has historically targeted ${vendor} PLCs (${match.observationCount} incidents)`,
        source: match.source,
        confidence: match.confidence,
      });
    }
  }

  return { score: Math.min(score, maxPossible), maxPossible, weight, evidence, conflicting: [] };
}

function scoreInitialAccess(actor: ActorGenomeProfile, incident: IncidentObservation, weight: number): CategoryScoreResult {
  const evidence: EvidenceItem[] = [];
  let score = 0;
  const maxPossible = weight;

  for (const access of incident.initialAccess) {
    const match = actor.genome.find(f =>
      f.category === "initial_access" &&
      (f.name.toLowerCase().includes(access.toLowerCase()) || access.toLowerCase().includes(f.name.toLowerCase()))
    );
    if (match) {
      const points = weight * match.value * match.confidence;
      score += points;
      evidence.push({
        category: "initial_access",
        indicator: access,
        pointsAwarded: points,
        maxPoints: weight,
        disposition: "supporting",
        explanation: `${access} is a preferred initial access method for ${actor.name}`,
        source: match.source,
        confidence: match.confidence,
      });
    }
  }

  return { score: Math.min(score, maxPossible), maxPossible, weight, evidence, conflicting: [] };
}

function scoreVictimSector(actor: ActorGenomeProfile, incident: IncidentObservation, weight: number): CategoryScoreResult {
  const evidence: EvidenceItem[] = [];
  let score = 0;
  const maxPossible = weight;

  const sectorFeatures = actor.genome.filter(f => f.category === "victim_sector");
  const match = sectorFeatures.find(f =>
    f.name.toLowerCase().includes(incident.victimSector.toLowerCase()) ||
    incident.victimSector.toLowerCase().includes(f.name.toLowerCase())
  );

  if (match) {
    score = weight * match.value * match.confidence;
    evidence.push({
      category: "victim_sector",
      indicator: incident.victimSector,
      pointsAwarded: score,
      maxPoints: weight,
      disposition: "supporting",
      explanation: `${actor.name} frequently targets the ${incident.victimSector} sector`,
      source: match.source,
      confidence: match.confidence,
    });
  }

  return { score, maxPossible, weight, evidence, conflicting: [] };
}

function scoreVictimGeography(actor: ActorGenomeProfile, incident: IncidentObservation, weight: number): CategoryScoreResult {
  const evidence: EvidenceItem[] = [];
  let score = 0;
  const maxPossible = weight;

  const geoFeatures = actor.genome.filter(f => f.category === "victim_geography");
  const match = geoFeatures.find(f =>
    f.name.toLowerCase().includes(incident.victimCountry.toLowerCase()) ||
    incident.victimCountry.toLowerCase().includes(f.name.toLowerCase())
  );

  if (match) {
    score = weight * match.value * match.confidence;
    evidence.push({
      category: "victim_geography",
      indicator: incident.victimCountry,
      pointsAwarded: score,
      maxPoints: weight,
      disposition: "supporting",
      explanation: `${actor.name} has targeted entities in ${incident.victimCountry}`,
      source: match.source,
      confidence: match.confidence,
    });
  }

  return { score, maxPossible, weight, evidence, conflicting: [] };
}

function scoreCredentialBehavior(actor: ActorGenomeProfile, incident: IncidentObservation, weight: number): CategoryScoreResult {
  const evidence: EvidenceItem[] = [];
  let score = 0;
  const maxPossible = weight;

  if (incident.credentialReuse) {
    const match = actor.genome.find(f => f.category === "credential_behavior");
    if (match) {
      score = weight * match.value * match.confidence;
      evidence.push({
        category: "credential_behavior",
        indicator: "Credential reuse/manipulation observed",
        pointsAwarded: score,
        maxPoints: weight,
        disposition: "supporting",
        explanation: `${actor.name} is known for ${match.name} behavior`,
        source: match.source,
        confidence: match.confidence,
      });
    }
  }

  return { score, maxPossible, weight, evidence, conflicting: [] };
}

function scorePropagandaBehavior(actor: ActorGenomeProfile, incident: IncidentObservation, weight: number): CategoryScoreResult {
  const evidence: EvidenceItem[] = [];
  const conflicting: EvidenceItem[] = [];
  let score = 0;
  const maxPossible = weight;

  const propagandaFeatures = actor.genome.filter(f => f.category === "propaganda_behavior");

  if (incident.propagandaLeft && propagandaFeatures.length > 0) {
    const bestMatch = propagandaFeatures.reduce((best, f) => f.value > best.value ? f : best, propagandaFeatures[0]);
    score = weight * bestMatch.value * bestMatch.confidence;
    evidence.push({
      category: "propaganda_behavior",
      indicator: "Propaganda/defacement observed",
      pointsAwarded: score,
      maxPoints: weight,
      disposition: "supporting",
      explanation: `${actor.name} is known for leaving propaganda (${bestMatch.name})`,
      source: bestMatch.source,
      confidence: bestMatch.confidence,
    });
  } else if (incident.propagandaLeft && propagandaFeatures.length === 0) {
    // Propaganda observed but actor doesn't do propaganda
    conflicting.push({
      category: "propaganda_behavior",
      indicator: "Propaganda observed but actor not known for it",
      pointsAwarded: -weight * 0.2,
      maxPoints: weight,
      disposition: "conflicting",
      explanation: `${actor.name} does not typically leave propaganda`,
      source: "Behavioral mismatch",
      confidence: 0.6,
    });
  } else if (!incident.propagandaLeft && propagandaFeatures.some(f => f.value > 0.8)) {
    // No propaganda but actor usually leaves it
    conflicting.push({
      category: "propaganda_behavior",
      indicator: `No propaganda observed (${actor.name} typically leaves messaging)`,
      pointsAwarded: -weight * 0.15,
      maxPoints: weight,
      disposition: "conflicting",
      explanation: `Expected propaganda from ${actor.name} was not observed`,
      source: "Absence of expected behavior",
      confidence: 0.5,
    });
  }

  return { score: Math.max(0, score), maxPossible, weight, evidence, conflicting };
}

function scoreImpactType(actor: ActorGenomeProfile, incident: IncidentObservation, weight: number): CategoryScoreResult {
  const evidence: EvidenceItem[] = [];
  let score = 0;
  const maxPossible = weight;

  const impactFeatures = actor.genome.filter(f => f.category === "impact_type");
  const match = impactFeatures.find(f =>
    f.name.toLowerCase().includes(incident.impactType.toLowerCase()) ||
    incident.impactType.toLowerCase().includes(f.name.toLowerCase())
  );

  if (match) {
    score = weight * match.value * match.confidence;
    evidence.push({
      category: "impact_type",
      indicator: incident.impactType,
      pointsAwarded: score,
      maxPoints: weight,
      disposition: "supporting",
      explanation: `${actor.name}'s typical impact is ${match.name}`,
      source: match.source,
      confidence: match.confidence,
    });
  }

  return { score, maxPossible, weight, evidence, conflicting: [] };
}

function scoreOperationalTiming(actor: ActorGenomeProfile, incident: IncidentObservation, weight: number): CategoryScoreResult {
  const evidence: EvidenceItem[] = [];
  let score = 0;
  const maxPossible = weight;

  if (incident.operatingHoursUtc && incident.operatingHoursUtc.length > 0) {
    // Check if incident hours align with actor's work hours
    const actorOffset = actor.operationalTempo.primaryUtcOffset;
    const localHours = incident.operatingHoursUtc.map(h => (h + actorOffset + 24) % 24);

    // Check how many fall within typical work hours (7-18)
    const workHourHits = localHours.filter(h => h >= 7 && h <= 18).length;
    const alignment = workHourHits / localHours.length;

    if (alignment > 0.6) {
      score = weight * alignment;
      evidence.push({
        category: "operational_timing",
        indicator: `Activity aligns with UTC+${actorOffset} work hours (${Math.round(alignment * 100)}% match)`,
        pointsAwarded: score,
        maxPoints: weight,
        disposition: "supporting",
        explanation: `Incident timing consistent with ${actor.name}'s operational hours (${actor.origin} timezone)`,
        source: "Temporal analysis",
        confidence: alignment * 0.8,
      });
    }
  }

  return { score, maxPossible, weight, evidence, conflicting: [] };
}

function scoreTradecraftMatch(actor: ActorGenomeProfile, incident: IncidentObservation): { score: number; evidence: EvidenceItem[] } {
  const evidence: EvidenceItem[] = [];
  let score = 0;

  for (const fingerprint of actor.tradecraftFingerprints) {
    let sequenceMatchCount = 0;
    const totalSteps = fingerprint.sequence.length;

    for (const step of fingerprint.sequence) {
      // Check if incident exhibits this step
      if (step.mitreTechnique && incident.techniques.includes(step.mitreTechnique)) {
        sequenceMatchCount++;
      } else if (step.action.toLowerCase().includes("credential") && incident.credentialReuse) {
        sequenceMatchCount++;
      } else if (step.action.toLowerCase().includes("propaganda") && incident.propagandaLeft) {
        sequenceMatchCount++;
      } else if (step.action.toLowerCase().includes("hmi") && incident.hmiModified) {
        sequenceMatchCount++;
      } else if (step.action.toLowerCase().includes("plc") && incident.plcLogicChanged) {
        sequenceMatchCount++;
      }
    }

    const matchRatio = sequenceMatchCount / totalSteps;
    if (matchRatio > 0.5) {
      const bonus = 15 * matchRatio * fingerprint.confidence;
      score += bonus;
      evidence.push({
        category: "attack_technique",
        indicator: `Tradecraft fingerprint: "${fingerprint.name}" (${Math.round(matchRatio * 100)}% match)`,
        pointsAwarded: bonus,
        maxPoints: 15,
        disposition: "supporting",
        explanation: `Attack sequence matches ${actor.name}'s known tradecraft "${fingerprint.name}" — observed in ${fingerprint.observationCount} previous incidents`,
        source: `Campaigns: ${fingerprint.campaignIds.join(", ")}`,
        confidence: matchRatio * fingerprint.confidence,
      });
    }
  }

  return { score, evidence };
}

function scoreIcsProtocol(actor: ActorGenomeProfile, incident: IncidentObservation, weight: number): CategoryScoreResult {
  const evidence: EvidenceItem[] = [];
  let score = 0;
  const maxPossible = weight;

  for (const protocol of incident.icsProtocols) {
    const match = actor.genome.find(f =>
      f.category === "ics_protocol" &&
      f.name.toLowerCase().includes(protocol.toLowerCase())
    );
    if (match) {
      const points = weight * match.value * match.confidence;
      score += points;
      evidence.push({
        category: "ics_protocol",
        indicator: protocol,
        pointsAwarded: points,
        maxPoints: weight,
        disposition: "supporting",
        explanation: `${actor.name} has used ${protocol} in previous operations`,
        source: match.source,
        confidence: match.confidence,
      });
    }
  }

  return { score: Math.min(score, maxPossible), maxPossible, weight, evidence, conflicting: [] };
}

function scoreDwellTime(actor: ActorGenomeProfile, incident: IncidentObservation, weight: number): CategoryScoreResult {
  const evidence: EvidenceItem[] = [];
  let score = 0;
  const maxPossible = weight;

  if (incident.dwellTimeDays !== null) {
    const dwellFeatures = actor.genome.filter(f => f.category === "dwell_time_pattern");
    for (const feature of dwellFeatures) {
      let matches = false;
      if (feature.name === "minimal_dwell" && incident.dwellTimeDays <= 3) matches = true;
      if (feature.name === "short_dwell" && incident.dwellTimeDays <= 14) matches = true;
      if (feature.name === "long_dwell" && incident.dwellTimeDays >= 30) matches = true;
      if (feature.name === "extreme_long_dwell" && incident.dwellTimeDays >= 180) matches = true;

      if (matches) {
        score = weight * feature.value * feature.confidence;
        evidence.push({
          category: "dwell_time_pattern",
          indicator: `Dwell time: ${incident.dwellTimeDays} days (matches "${feature.name}" pattern)`,
          pointsAwarded: score,
          maxPoints: weight,
          disposition: "supporting",
          explanation: `${actor.name}'s typical dwell time pattern is "${feature.name}"`,
          source: feature.source,
          confidence: feature.confidence,
        });
        break;
      }
    }
  }

  return { score, maxPossible, weight, evidence, conflicting: [] };
}

// ─── Narrative Generation ───────────────────────────────────────────────────────

function generateNarrative(rankings: AttributionScore[], incident: IncidentObservation): string {
  if (rankings.length === 0) return "Insufficient data to generate attribution assessment.";

  const top = rankings[0];
  const parts: string[] = [];

  parts.push(`${top.actorName} scored ${top.overallScore} because `);

  const topEvidence = top.evidence
    .sort((a, b) => b.pointsAwarded - a.pointsAwarded)
    .slice(0, 6);

  const explanations = topEvidence.map((e, i) => {
    const prefix = i === 0 ? "" : i === topEvidence.length - 1 ? "and " : "";
    return `${prefix}${e.explanation.toLowerCase()} (${Math.round(e.pointsAwarded)} points)`;
  });

  parts.push(explanations.join(", "));

  if (top.conflictingEvidence.length > 0) {
    const reductions = top.conflictingEvidence.map(e => e.explanation.toLowerCase());
    parts.push(`. Confidence was reduced because ${reductions.join(" and ")}`);
  }

  parts.push(".");

  if (rankings.length > 1) {
    parts.push(` Alternative candidates: ${rankings.slice(1, 3).map(r => `${r.actorName} (${r.overallScore}%)`).join(", ")}.`);
  }

  return parts.join("");
}

function generateAnalystNotes(rankings: AttributionScore[], incident: IncidentObservation): string[] {
  const notes: string[] = [];

  if (rankings.length >= 2 && rankings[0].overallScore - rankings[1].overallScore < 15) {
    notes.push(`CAUTION: Top two candidates (${rankings[0].actorName} and ${rankings[1].actorName}) are within 15 points — additional evidence needed for definitive attribution.`);
  }

  if (rankings[0]?.conflictingEvidence.length >= 2) {
    notes.push(`WARNING: Multiple conflicting indicators detected. Consider false flag or evolving tradecraft.`);
  }

  if (incident.publicClaims.length > 0) {
    const claimPersonas = incident.publicClaims.map(c => c.persona).join(", ");
    notes.push(`PUBLIC CLAIMS: ${claimPersonas} claimed responsibility. Note: public persona ≠ technical operator. Treat claims as one data point, not proof.`);
  }

  if (incident.dwellTimeDays !== null && incident.dwellTimeDays <= 1) {
    notes.push(`RAPID OPERATION: Sub-24h dwell time suggests either opportunistic attack or pre-staged access.`);
  }

  return notes;
}

function generateAlternativeHypotheses(actor: ActorGenomeProfile, incident: IncidentObservation, conflicting: EvidenceItem[]): string[] {
  const hypotheses: string[] = [];

  if (conflicting.length > 0) {
    hypotheses.push(`False flag: Another actor mimicking ${actor.name}'s tradecraft to mislead attribution.`);
  }

  if (actor.actorId === "handala" && incident.plcLogicChanged) {
    hypotheses.push(`Handala may be claiming credit for an operation conducted by CyberAv3ngers (common pattern in Iranian cyber operations).`);
  }

  hypotheses.push(`Evolving tradecraft: ${actor.name} may have adopted new techniques not yet in their profile.`);
  hypotheses.push(`Shared tooling: Multiple actors with access to the same exploit kit or infrastructure.`);

  return hypotheses;
}

// ─── Campaign Similarity ────────────────────────────────────────────────────────

function computeCampaignSimilarity(incident: IncidentObservation): CampaignSimilarityResult[] {
  const results: CampaignSimilarityResult[] = [];

  for (const actor of ACTOR_GENOME_DB) {
    for (const campaign of actor.campaigns) {
      const matching: string[] = [];
      const divergent: string[] = [];

      // Sector match
      if (campaign.victimSectors.some(s => s.toLowerCase().includes(incident.victimSector.toLowerCase()))) {
        matching.push(`Sector: ${incident.victimSector}`);
      } else {
        divergent.push(`Sector: incident=${incident.victimSector}, campaign=${campaign.victimSectors.join(",")}`);
      }

      // Country match
      if (campaign.victimCountries.some(c => c.toLowerCase() === incident.victimCountry.toLowerCase() || incident.victimCountry.toLowerCase().includes(c.toLowerCase()))) {
        matching.push(`Geography: ${incident.victimCountry}`);
      }

      // Technique overlap
      const techOverlap = incident.techniques.filter(t => campaign.techniques.includes(t));
      if (techOverlap.length > 0) {
        matching.push(`Techniques: ${techOverlap.join(", ")}`);
      }

      // Malware overlap
      const malwareOverlap = incident.malwareObserved.filter(m =>
        campaign.malware.some(cm => cm.toLowerCase().includes(m.toLowerCase()))
      );
      if (malwareOverlap.length > 0) {
        matching.push(`Malware: ${malwareOverlap.join(", ")}`);
      }

      // Impact type
      if (campaign.impactType.toLowerCase().includes(incident.impactType.toLowerCase())) {
        matching.push(`Impact: ${incident.impactType}`);
      }

      const similarity = Math.round((matching.length / (matching.length + divergent.length + 1)) * 100);

      if (similarity >= 40) {
        results.push({
          campaignId: campaign.id,
          campaignName: campaign.name,
          actorId: actor.actorId,
          actorName: actor.name,
          similarityPercent: similarity,
          matchingFeatures: matching,
          divergentFeatures: divergent,
        });
      }
    }
  }

  return results.sort((a, b) => b.similarityPercent - a.similarityPercent).slice(0, 10);
}

// ─── Helper ─────────────────────────────────────────────────────────────────────

function createEmptyScore(): AttributionScore {
  return {
    actorId: "unknown",
    actorName: "Unknown",
    overallScore: 0,
    confidence: "low",
    layers: {
      technicalOperator: { score: 0, confidence: 0 },
      publicPersona: { score: 0, confidence: 0 },
      stateSponsor: { score: 0, confidence: 0 },
    },
    evidence: [],
    categoryScores: [],
    conflictingEvidence: [],
    alternativeHypotheses: [],
  };
}

// ─── Public API ─────────────────────────────────────────────────────────────────

/** Get all actor genome profiles */
export function getAllActorProfiles(): ActorGenomeProfile[] {
  return ACTOR_GENOME_DB;
}

/** Get a specific actor's genome profile */
export function getActorProfile(actorId: string): ActorGenomeProfile | undefined {
  return ACTOR_GENOME_DB.find(a => a.actorId === actorId);
}

/** Get actor profile completeness scores */
export function getProfileCompleteness(): { actorId: string; name: string; completeness: number }[] {
  return ACTOR_GENOME_DB.map(a => ({
    actorId: a.actorId,
    name: a.name,
    completeness: a.profileCompleteness,
  }));
}

/** Get tradecraft fingerprints for an actor */
export function getActorTradecraft(actorId: string): TradecraftFingerprint[] {
  const actor = ACTOR_GENOME_DB.find(a => a.actorId === actorId);
  return actor?.tradecraftFingerprints || [];
}

/** Get temporal analysis for an actor */
export function getActorTemporalAnalysis(actorId: string): OperationalTempo | null {
  const actor = ACTOR_GENOME_DB.find(a => a.actorId === actorId);
  return actor?.operationalTempo || null;
}

/** Compare two actors' genomes */
export function compareActorGenomes(actorId1: string, actorId2: string): {
  actor1: string;
  actor2: string;
  overlapFeatures: string[];
  uniqueToActor1: string[];
  uniqueToActor2: string[];
  overlapPercent: number;
} {
  const actor1 = ACTOR_GENOME_DB.find(a => a.actorId === actorId1);
  const actor2 = ACTOR_GENOME_DB.find(a => a.actorId === actorId2);

  if (!actor1 || !actor2) {
    return { actor1: actorId1, actor2: actorId2, overlapFeatures: [], uniqueToActor1: [], uniqueToActor2: [], overlapPercent: 0 };
  }

  const features1 = new Set(actor1.genome.filter(f => f.value > 0.5).map(f => `${f.category}:${f.name}`));
  const features2 = new Set(actor2.genome.filter(f => f.value > 0.5).map(f => `${f.category}:${f.name}`));

  const overlap = [...features1].filter(f => features2.has(f));
  const unique1 = [...features1].filter(f => !features2.has(f));
  const unique2 = [...features2].filter(f => !features1.has(f));

  const total = new Set([...features1, ...features2]).size;
  const overlapPercent = total > 0 ? Math.round((overlap.length / total) * 100) : 0;

  return {
    actor1: actor1.name,
    actor2: actor2.name,
    overlapFeatures: overlap,
    uniqueToActor1: unique1,
    uniqueToActor2: unique2,
    overlapPercent,
  };
}

/** Get all campaigns across all actors */
export function getAllCampaigns(): (CampaignRecord & { actorId: string; actorName: string })[] {
  const campaigns: (CampaignRecord & { actorId: string; actorName: string })[] = [];
  for (const actor of ACTOR_GENOME_DB) {
    for (const campaign of actor.campaigns) {
      campaigns.push({ ...campaign, actorId: actor.actorId, actorName: actor.name });
    }
  }
  return campaigns.sort((a, b) => b.startDate - a.startDate);
}

/** Get feature weight presets */
export function getWeightPresets(): Record<string, Record<FeatureCategory, number>> {
  return {
    default: DEFAULT_FEATURE_WEIGHTS,
    ics_ot: ICS_FEATURE_WEIGHTS,
  };
}
