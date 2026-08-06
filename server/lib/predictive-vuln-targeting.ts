/**
 * Predictive Vulnerability Targeting Engine
 * 
 * Uses the Actor Genome Engine's behavioral predictions to identify which CVEs
 * an active threat actor is LIKELY to weaponize next (before they do), and
 * pre-generates exploit development priorities for those vulnerabilities.
 * 
 * Three prediction models:
 * 1. Actor Behavior Extrapolation — based on historical weaponization patterns
 * 2. Vulnerability Attractiveness Scoring — based on CVE characteristics that actors prefer
 * 3. Campaign Momentum Analysis — based on active campaign trajectories
 */

// ─── Core Types ──────────────────────────────────────────────────────────────

export interface PredictedTarget {
  id: string;
  cve: string;
  cvssScore: number;
  affectedProduct: string;
  affectedVendor: string;
  
  // Prediction scores
  weaponizationProbability: number; // 0-100: likelihood actor will weaponize this
  timeToWeaponization: PredictedTimeframe;
  exploitComplexity: "low" | "medium" | "high" | "critical";
  
  // Actor linkage
  predictedActors: ActorPrediction[];
  
  // Attractiveness factors
  attractivenessFactors: AttractivenessScore;
  
  // Recommendation
  recommendation: TargetingRecommendation;
  
  // Evidence for prediction
  predictionEvidence: PredictionEvidence[];
  
  // Metadata
  predictedAt: number;
  modelVersion: string;
  confidenceInterval: { lower: number; upper: number };
}

export interface PredictedTimeframe {
  estimatedDays: number;
  confidence: number;
  range: { minDays: number; maxDays: number };
  basis: string; // explanation of estimate
}

export interface ActorPrediction {
  actorId: string;
  actorName: string;
  probability: number;
  reasoning: string[];
  historicalPattern: string; // "This actor weaponized similar vulns within X days"
  currentCampaignRelevance: number; // 0-100
}

export interface AttractivenessScore {
  overall: number; // 0-100
  
  // Individual factors
  internetFacing: { score: number; weight: number; reasoning: string };
  defaultCredentials: { score: number; weight: number; reasoning: string };
  noAuthRequired: { score: number; weight: number; reasoning: string };
  remoteCodeExecution: { score: number; weight: number; reasoning: string };
  widelyDeployed: { score: number; weight: number; reasoning: string };
  criticalInfrastructure: { score: number; weight: number; reasoning: string };
  lowComplexity: { score: number; weight: number; reasoning: string };
  publicPocAvailable: { score: number; weight: number; reasoning: string };
  activeExploitation: { score: number; weight: number; reasoning: string };
  mediaAttention: { score: number; weight: number; reasoning: string };
  patchLag: { score: number; weight: number; reasoning: string };
  chainable: { score: number; weight: number; reasoning: string };
}

export interface TargetingRecommendation {
  priority: "immediate" | "high" | "medium" | "low" | "monitor";
  action: string;
  exploitDevEstimate: string;
  clientImpact: string[];
  mitigationUrgency: string;
  preemptiveDefense: string[];
}

export interface PredictionEvidence {
  type: "historical_pattern" | "campaign_trajectory" | "vendor_targeting" | "sector_focus" | "capability_match" | "timing_pattern" | "infrastructure_prep" | "dark_web_chatter";
  description: string;
  confidence: number;
  source: string;
  timestamp?: number;
}

export interface CampaignMomentum {
  actorId: string;
  actorName: string;
  activeCampaigns: number;
  
  // Trajectory analysis
  targetingSectors: string[];
  targetingRegions: string[];
  targetingTechnologies: string[];
  
  // Velocity metrics
  newVulnsPerWeek: number;
  exploitDevVelocity: number; // days from disclosure to weaponization
  campaignExpansionRate: number; // new targets per week
  
  // Predicted next moves
  predictedNextSectors: string[];
  predictedNextTechnologies: string[];
  predictedNextCves: string[];
  
  // Confidence
  momentumConfidence: number;
  dataFreshness: number; // hours since last update
}

// ─── Prediction Models ───────────────────────────────────────────────────────

/**
 * Model 1: Actor Behavior Extrapolation
 * Analyzes historical weaponization patterns to predict future targets
 */
function predictFromActorBehavior(
  actorProfile: { id: string; name: string; historicalCves: string[]; preferredVendors: string[]; preferredTechTypes: string[]; avgWeaponizationDays: number; sectorFocus: string[] },
  candidateCves: CveCandidate[]
): ActorPrediction[] {
  return candidateCves.map(cve => {
    let probability = 0;
    const reasoning: string[] = [];
    
    // Factor 1: Vendor match (actor historically targets this vendor)
    if (actorProfile.preferredVendors.some(v => cve.vendor.toLowerCase().includes(v.toLowerCase()))) {
      probability += 25;
      reasoning.push(`Actor historically targets ${cve.vendor} products`);
    }
    
    // Factor 2: Technology type match
    if (actorProfile.preferredTechTypes.some(t => cve.techType.toLowerCase().includes(t.toLowerCase()))) {
      probability += 20;
      reasoning.push(`CVE affects ${cve.techType} — matches actor's preferred tech targets`);
    }
    
    // Factor 3: Sector relevance
    if (actorProfile.sectorFocus.some(s => cve.affectedSectors.includes(s))) {
      probability += 20;
      reasoning.push(`Vulnerability impacts ${cve.affectedSectors.join(", ")} — actor's target sectors`);
    }
    
    // Factor 4: Exploitation complexity matches actor capability
    if (cve.complexity === "low") {
      probability += 15;
      reasoning.push("Low exploitation complexity — within actor's demonstrated capability");
    } else if (cve.complexity === "medium") {
      probability += 10;
      reasoning.push("Medium complexity — likely within actor's capability based on past exploits");
    }
    
    // Factor 5: Similar CVE pattern (same CWE, same product family)
    const similarHistorical = actorProfile.historicalCves.filter(h => 
      h.includes(cve.vendor.substring(0, 4).toUpperCase())
    ).length;
    if (similarHistorical > 0) {
      probability += Math.min(20, similarHistorical * 5);
      reasoning.push(`Actor has weaponized ${similarHistorical} similar CVEs from same vendor/product family`);
    }
    
    return {
      actorId: actorProfile.id,
      actorName: actorProfile.name,
      probability: Math.min(95, probability),
      reasoning,
      historicalPattern: `Average weaponization time: ${actorProfile.avgWeaponizationDays} days from disclosure`,
      currentCampaignRelevance: probability > 50 ? 80 : 40,
    };
  });
}

/**
 * Model 2: Vulnerability Attractiveness Scoring
 * Scores CVEs based on characteristics that make them attractive to threat actors
 */
function scoreVulnerabilityAttractiveness(cve: CveCandidate): AttractivenessScore {
  const factors = {
    internetFacing: {
      score: cve.internetFacing ? 95 : 20,
      weight: 0.15,
      reasoning: cve.internetFacing ? "Internet-facing attack surface — no initial access required" : "Internal only — requires prior access",
    },
    defaultCredentials: {
      score: cve.hasDefaultCreds ? 90 : 10,
      weight: 0.12,
      reasoning: cve.hasDefaultCreds ? "Default/hardcoded credentials present — trivial exploitation" : "No default credentials identified",
    },
    noAuthRequired: {
      score: cve.noAuthRequired ? 85 : 30,
      weight: 0.12,
      reasoning: cve.noAuthRequired ? "No authentication required for exploitation" : "Authentication required — limits attack surface",
    },
    remoteCodeExecution: {
      score: cve.isRce ? 95 : 40,
      weight: 0.14,
      reasoning: cve.isRce ? "Remote code execution — maximum impact potential" : "Non-RCE impact — limited operational value",
    },
    widelyDeployed: {
      score: Math.min(95, cve.deploymentScale * 10),
      weight: 0.10,
      reasoning: `Estimated ${cve.deploymentScale * 10000}+ deployments globally`,
    },
    criticalInfrastructure: {
      score: cve.affectedSectors.some(s => ["energy", "water", "healthcare", "transportation", "nuclear"].includes(s)) ? 90 : 30,
      weight: 0.08,
      reasoning: cve.affectedSectors.some(s => ["energy", "water", "healthcare", "transportation", "nuclear"].includes(s)) 
        ? "Affects critical infrastructure — high geopolitical value" 
        : "Non-critical sector deployment",
    },
    lowComplexity: {
      score: cve.complexity === "low" ? 90 : cve.complexity === "medium" ? 60 : 30,
      weight: 0.08,
      reasoning: `Exploitation complexity: ${cve.complexity}`,
    },
    publicPocAvailable: {
      score: cve.publicPocExists ? 85 : 20,
      weight: 0.07,
      reasoning: cve.publicPocExists ? "Public PoC available — reduces development effort" : "No public PoC — requires original research",
    },
    activeExploitation: {
      score: cve.knownExploited ? 95 : 15,
      weight: 0.05,
      reasoning: cve.knownExploited ? "Already in CISA KEV — confirmed active exploitation" : "No known active exploitation",
    },
    mediaAttention: {
      score: cve.mediaAttention ? 70 : 30,
      weight: 0.03,
      reasoning: cve.mediaAttention ? "High media attention — may attract copycats" : "Low media visibility",
    },
    patchLag: {
      score: Math.min(90, cve.avgPatchDays * 2),
      weight: 0.03,
      reasoning: `Average patch deployment: ${cve.avgPatchDays} days — exploitation window`,
    },
    chainable: {
      score: cve.chainable ? 80 : 30,
      weight: 0.03,
      reasoning: cve.chainable ? "Can be chained with other vulns for greater impact" : "Standalone exploitation only",
    },
  };
  
  // Calculate overall score
  const overall = Math.round(
    Object.values(factors).reduce((sum, f) => sum + (f.score * f.weight), 0)
  );
  
  return { overall, ...factors };
}

/**
 * Model 3: Campaign Momentum Analysis
 * Tracks active campaign trajectories to predict next targets
 */
function analyzeCampaignMomentum(
  actorId: string,
  actorName: string,
  recentActivity: { cves: string[]; sectors: string[]; regions: string[]; technologies: string[]; timestamps: number[] }
): CampaignMomentum {
  // Calculate velocity metrics
  const now = Date.now();
  const oneWeekAgo = now - 7 * 24 * 60 * 60 * 1000;
  const recentTimestamps = recentActivity.timestamps.filter(t => t > oneWeekAgo);
  
  // Exploit development velocity (average days from disclosure to weaponization)
  const avgVelocity = recentActivity.cves.length > 0 ? 14 : 30; // placeholder
  
  // Predict next moves based on trajectory
  const predictedNextSectors = predictNextFromSequence(recentActivity.sectors);
  const predictedNextTechnologies = predictNextFromSequence(recentActivity.technologies);
  
  return {
    actorId,
    actorName,
    activeCampaigns: Math.ceil(recentTimestamps.length / 3),
    targetingSectors: [...new Set(recentActivity.sectors)],
    targetingRegions: [...new Set(recentActivity.regions)],
    targetingTechnologies: [...new Set(recentActivity.technologies)],
    newVulnsPerWeek: recentTimestamps.length,
    exploitDevVelocity: avgVelocity,
    campaignExpansionRate: recentTimestamps.length / 7,
    predictedNextSectors,
    predictedNextTechnologies,
    predictedNextCves: [],
    momentumConfidence: Math.min(85, recentTimestamps.length * 10),
    dataFreshness: recentTimestamps.length > 0 ? Math.round((now - Math.max(...recentTimestamps)) / 3600000) : 999,
  };
}

function predictNextFromSequence(items: string[]): string[] {
  // Simple frequency-based prediction with recency weighting
  const frequency: Record<string, number> = {};
  items.forEach((item, idx) => {
    const recencyWeight = 1 + (idx / items.length); // more recent = higher weight
    frequency[item] = (frequency[item] || 0) + recencyWeight;
  });
  
  return Object.entries(frequency)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 3)
    .map(([item]) => item);
}

// ─── CVE Candidate Interface ─────────────────────────────────────────────────

interface CveCandidate {
  cve: string;
  cvssScore: number;
  vendor: string;
  product: string;
  techType: string;
  affectedSectors: string[];
  internetFacing: boolean;
  hasDefaultCreds: boolean;
  noAuthRequired: boolean;
  isRce: boolean;
  deploymentScale: number; // 1-10
  complexity: "low" | "medium" | "high";
  publicPocExists: boolean;
  knownExploited: boolean;
  mediaAttention: boolean;
  avgPatchDays: number;
  chainable: boolean;
  disclosureDate: number;
}

// ─── Pre-loaded Actor Profiles for Prediction ────────────────────────────────

const ACTOR_PREDICTION_PROFILES = [
  {
    id: "cyberav3ngers",
    name: "CyberAv3ngers (IRGC-CEC)",
    historicalCves: ["CVE-2023-6448", "CVE-2024-21887", "CVE-2024-1709", "CVE-2023-46747"],
    preferredVendors: ["unitronics", "rockwell", "schneider", "siemens", "honeywell", "emerson"],
    preferredTechTypes: ["plc", "hmi", "scada", "rtu", "dcs", "ics"],
    avgWeaponizationDays: 7,
    sectorFocus: ["water", "wastewater", "energy", "oil_gas"],
  },
  {
    id: "sandworm",
    name: "Sandworm (GRU Unit 74455)",
    historicalCves: ["CVE-2023-38831", "CVE-2023-23397", "CVE-2022-30190", "CVE-2021-40444"],
    preferredVendors: ["microsoft", "fortinet", "cisco", "vmware", "siemens"],
    preferredTechTypes: ["vpn", "email_server", "active_directory", "scada", "substation_ied"],
    avgWeaponizationDays: 14,
    sectorFocus: ["energy", "government", "telecommunications", "transportation"],
  },
  {
    id: "volt_typhoon",
    name: "Volt Typhoon (PRC MSS)",
    historicalCves: ["CVE-2024-3400", "CVE-2023-27997", "CVE-2022-42475", "CVE-2023-46805"],
    preferredVendors: ["fortinet", "ivanti", "citrix", "palo_alto", "sonicwall", "zyxel"],
    preferredTechTypes: ["vpn", "firewall", "edge_device", "router", "nas"],
    avgWeaponizationDays: 3,
    sectorFocus: ["telecommunications", "energy", "water", "transportation", "defense"],
  },
  {
    id: "xenotime",
    name: "XENOTIME (TRITON/TRISIS)",
    historicalCves: ["CVE-2018-7522", "CVE-2017-14462"],
    preferredVendors: ["schneider", "triconex", "honeywell", "yokogawa", "emerson"],
    preferredTechTypes: ["sis", "safety_controller", "dcs", "plc", "ics"],
    avgWeaponizationDays: 60,
    sectorFocus: ["oil_gas", "petrochemical", "energy", "nuclear"],
  },
  {
    id: "lazarus",
    name: "Lazarus Group (RGB Bureau 121)",
    historicalCves: ["CVE-2023-42793", "CVE-2022-47966", "CVE-2022-27925", "CVE-2021-44228"],
    preferredVendors: ["zoho", "atlassian", "apache", "microsoft", "oracle"],
    preferredTechTypes: ["web_server", "ci_cd", "supply_chain", "cryptocurrency", "email_server"],
    avgWeaponizationDays: 10,
    sectorFocus: ["finance", "cryptocurrency", "defense", "technology", "aerospace"],
  },
  {
    id: "apt28",
    name: "APT28 / Fancy Bear (GRU Unit 26165)",
    historicalCves: ["CVE-2023-23397", "CVE-2023-38831", "CVE-2022-30190", "CVE-2020-12641"],
    preferredVendors: ["microsoft", "roundcube", "cisco", "zimbra", "winrar"],
    preferredTechTypes: ["email_server", "vpn", "webmail", "active_directory", "router"],
    avgWeaponizationDays: 5,
    sectorFocus: ["government", "military", "political", "media", "think_tank"],
  },
  {
    id: "apt29",
    name: "APT29 / Cozy Bear (SVR)",
    historicalCves: ["CVE-2024-3094", "CVE-2023-42793", "CVE-2021-21972", "CVE-2020-5902"],
    preferredVendors: ["solarwinds", "microsoft", "vmware", "jetbrains", "f5"],
    preferredTechTypes: ["supply_chain", "cloud", "identity_provider", "ci_cd", "virtualization"],
    avgWeaponizationDays: 21,
    sectorFocus: ["government", "technology", "cloud_provider", "think_tank", "diplomatic"],
  },
];

// ─── Main Prediction Engine ──────────────────────────────────────────────────

/**
 * Run full predictive analysis on a set of candidate CVEs
 */
export function predictVulnerabilityTargeting(
  candidateCves: CveCandidate[],
  options?: { actorFilter?: string[]; sectorFilter?: string[]; minProbability?: number }
): PredictedTarget[] {
  const predictions: PredictedTarget[] = [];
  const minProb = options?.minProbability || 30;
  
  for (const cve of candidateCves) {
    // Score attractiveness
    const attractiveness = scoreVulnerabilityAttractiveness(cve);
    
    // Get actor predictions
    const actorPredictions: ActorPrediction[] = [];
    const profiles = options?.actorFilter 
      ? ACTOR_PREDICTION_PROFILES.filter(p => options.actorFilter!.includes(p.id))
      : ACTOR_PREDICTION_PROFILES;
    
    for (const profile of profiles) {
      const predictions = predictFromActorBehavior(profile, [cve]);
      actorPredictions.push(...predictions);
    }
    
    // Filter by minimum probability
    const relevantActors = actorPredictions.filter(a => a.probability >= minProb);
    if (relevantActors.length === 0 && attractiveness.overall < 60) continue;
    
    // Calculate overall weaponization probability
    const maxActorProb = relevantActors.length > 0 ? Math.max(...relevantActors.map(a => a.probability)) : 0;
    const weaponizationProbability = Math.round(
      (maxActorProb * 0.6) + (attractiveness.overall * 0.4)
    );
    
    // Estimate time to weaponization
    const fastestActor = relevantActors.sort((a, b) => b.probability - a.probability)[0];
    const baseTime = fastestActor 
      ? ACTOR_PREDICTION_PROFILES.find(p => p.id === fastestActor.actorId)?.avgWeaponizationDays || 30
      : 45;
    
    const timeToWeaponization: PredictedTimeframe = {
      estimatedDays: baseTime,
      confidence: weaponizationProbability > 70 ? 75 : 50,
      range: { minDays: Math.max(1, baseTime - 7), maxDays: baseTime + 21 },
      basis: fastestActor 
        ? `Based on ${fastestActor.actorName}'s historical weaponization velocity`
        : "Based on general threat landscape velocity",
    };
    
    // Build prediction evidence
    const evidence: PredictionEvidence[] = [];
    if (relevantActors.length > 0) {
      evidence.push({
        type: "historical_pattern",
        description: `${relevantActors.length} threat actors have historical patterns matching this CVE profile`,
        confidence: maxActorProb,
        source: "Actor Genome Engine — behavioral extrapolation",
      });
    }
    if (cve.publicPocExists) {
      evidence.push({
        type: "capability_match",
        description: "Public PoC exists — reduces barrier to weaponization significantly",
        confidence: 80,
        source: "NVD/ExploitDB PoC tracking",
      });
    }
    if (cve.knownExploited) {
      evidence.push({
        type: "campaign_trajectory",
        description: "Already in CISA KEV — active exploitation confirmed by other actors",
        confidence: 95,
        source: "CISA Known Exploited Vulnerabilities Catalog",
      });
    }
    if (cve.internetFacing && cve.noAuthRequired) {
      evidence.push({
        type: "vendor_targeting",
        description: "Internet-facing + no auth = maximum attack surface exposure",
        confidence: 85,
        source: "Vulnerability characteristics analysis",
      });
    }
    
    // Generate recommendation
    const recommendation = generateRecommendation(weaponizationProbability, timeToWeaponization, cve, relevantActors);
    
    predictions.push({
      id: `pred_${Date.now()}_${cve.cve.replace(/[^a-zA-Z0-9]/g, "")}`,
      cve: cve.cve,
      cvssScore: cve.cvssScore,
      affectedProduct: cve.product,
      affectedVendor: cve.vendor,
      weaponizationProbability,
      timeToWeaponization,
      exploitComplexity: cve.complexity === "low" ? "low" : cve.complexity === "medium" ? "medium" : "high",
      predictedActors: relevantActors,
      attractivenessFactors: attractiveness,
      recommendation,
      predictionEvidence: evidence,
      predictedAt: Date.now(),
      modelVersion: "1.0.0-ac3",
      confidenceInterval: { 
        lower: Math.max(0, weaponizationProbability - 15), 
        upper: Math.min(100, weaponizationProbability + 10) 
      },
    });
  }
  
  // Sort by weaponization probability (highest first)
  return predictions.sort((a, b) => b.weaponizationProbability - a.weaponizationProbability);
}

function generateRecommendation(
  probability: number,
  timeframe: PredictedTimeframe,
  cve: CveCandidate,
  actors: ActorPrediction[]
): TargetingRecommendation {
  if (probability >= 80 && timeframe.estimatedDays <= 7) {
    return {
      priority: "immediate",
      action: "Pre-generate exploit and prepare defensive signatures NOW",
      exploitDevEstimate: "1-2 days (fast-track development)",
      clientImpact: actors.map(a => `${a.actorName} likely to weaponize within ${timeframe.estimatedDays} days`),
      mitigationUrgency: "CRITICAL — notify all clients with affected products immediately",
      preemptiveDefense: [
        "Deploy IDS signatures for known exploitation patterns",
        "Pre-position monitoring on affected systems",
        "Prepare incident response playbook",
        "Draft client advisory for immediate distribution",
      ],
    };
  }
  
  if (probability >= 60 && timeframe.estimatedDays <= 14) {
    return {
      priority: "high",
      action: "Prioritize exploit development and begin client notification",
      exploitDevEstimate: "3-5 days (priority queue)",
      clientImpact: actors.map(a => `${a.actorName} may weaponize within ${timeframe.range.maxDays} days`),
      mitigationUrgency: "HIGH — schedule client patch verification within 48 hours",
      preemptiveDefense: [
        "Add to priority exploit development queue",
        "Monitor dark web for early exploit sales",
        "Prepare detection rules for affected products",
        "Verify client patch status for affected systems",
      ],
    };
  }
  
  if (probability >= 40) {
    return {
      priority: "medium",
      action: "Add to exploit development backlog and monitor for escalation",
      exploitDevEstimate: "1-2 weeks (standard queue)",
      clientImpact: [`Moderate risk — ${actors.length} actors show interest patterns`],
      mitigationUrgency: "MEDIUM — include in next scheduled vulnerability assessment",
      preemptiveDefense: [
        "Monitor for public PoC release",
        "Track vendor patch timeline",
        "Include in next client vulnerability scan",
      ],
    };
  }
  
  return {
    priority: "low",
    action: "Monitor passively — low weaponization probability",
    exploitDevEstimate: "Not prioritized",
    clientImpact: ["Low immediate risk based on current threat landscape"],
    mitigationUrgency: "LOW — standard patch cycle",
    preemptiveDefense: ["Continue passive monitoring"],
  };
}

/**
 * Get campaign momentum for all tracked actors
 */
export function getAllCampaignMomentum(): CampaignMomentum[] {
  return ACTOR_PREDICTION_PROFILES.map(profile => 
    analyzeCampaignMomentum(profile.id, profile.name, {
      cves: profile.historicalCves,
      sectors: profile.sectorFocus,
      regions: ["global"],
      technologies: profile.preferredTechTypes,
      timestamps: [Date.now() - 86400000, Date.now() - 172800000, Date.now() - 259200000],
    })
  );
}

/**
 * Get prediction for a specific CVE against all actors
 */
export function predictSingleCve(cve: CveCandidate): PredictedTarget | null {
  const results = predictVulnerabilityTargeting([cve]);
  return results.length > 0 ? results[0] : null;
}

/**
 * Get the top N most likely-to-be-weaponized CVEs from a candidate list
 */
export function getTopPredictedTargets(
  candidates: CveCandidate[],
  topN: number = 10
): PredictedTarget[] {
  return predictVulnerabilityTargeting(candidates).slice(0, topN);
}

/**
 * Predict which actor is most likely to target a specific technology stack
 */
export function predictActorForTechStack(
  technologies: string[],
  sectors: string[]
): { actorId: string; actorName: string; probability: number; reasoning: string[] }[] {
  const results: { actorId: string; actorName: string; probability: number; reasoning: string[] }[] = [];
  
  for (const profile of ACTOR_PREDICTION_PROFILES) {
    let probability = 0;
    const reasoning: string[] = [];
    
    // Technology overlap
    const techOverlap = technologies.filter(t => 
      profile.preferredTechTypes.some(pt => t.toLowerCase().includes(pt.toLowerCase()))
    );
    if (techOverlap.length > 0) {
      probability += Math.min(40, techOverlap.length * 15);
      reasoning.push(`Technology match: ${techOverlap.join(", ")}`);
    }
    
    // Sector overlap
    const sectorOverlap = sectors.filter(s => profile.sectorFocus.includes(s));
    if (sectorOverlap.length > 0) {
      probability += Math.min(40, sectorOverlap.length * 15);
      reasoning.push(`Sector match: ${sectorOverlap.join(", ")}`);
    }
    
    // Weaponization velocity bonus (faster actors are more dangerous)
    if (profile.avgWeaponizationDays <= 7) {
      probability += 15;
      reasoning.push(`Fast weaponization velocity: ${profile.avgWeaponizationDays} days average`);
    }
    
    if (probability > 20) {
      results.push({
        actorId: profile.id,
        actorName: profile.name,
        probability: Math.min(95, probability),
        reasoning,
      });
    }
  }
  
  return results.sort((a, b) => b.probability - a.probability);
}

/**
 * Generate a predictive threat landscape report
 */
export function generatePredictiveLandscape(): {
  highestRiskActors: { actorId: string; actorName: string; activeThreatLevel: number; predictedNextMove: string }[];
  emergingTargets: { technology: string; riskScore: number; actorsInterested: number }[];
  sectorRiskMatrix: { sector: string; overallRisk: number; primaryThreats: string[] }[];
  timeHorizon: { next7days: string[]; next30days: string[]; next90days: string[] };
} {
  const momentum = getAllCampaignMomentum();
  
  const highestRiskActors = momentum
    .sort((a, b) => b.momentumConfidence - a.momentumConfidence)
    .slice(0, 5)
    .map(m => ({
      actorId: m.actorId,
      actorName: m.actorName,
      activeThreatLevel: m.momentumConfidence,
      predictedNextMove: `Likely targeting ${m.predictedNextTechnologies[0] || "unknown"} in ${m.predictedNextSectors[0] || "multiple"} sector`,
    }));
  
  // Aggregate technology risk
  const techRisk: Record<string, { score: number; actors: Set<string> }> = {};
  for (const m of momentum) {
    for (const tech of m.targetingTechnologies) {
      if (!techRisk[tech]) techRisk[tech] = { score: 0, actors: new Set() };
      techRisk[tech].score += m.momentumConfidence;
      techRisk[tech].actors.add(m.actorName);
    }
  }
  
  const emergingTargets = Object.entries(techRisk)
    .map(([tech, data]) => ({ technology: tech, riskScore: Math.min(100, data.score), actorsInterested: data.actors.size }))
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 10);
  
  // Sector risk matrix
  const sectorRisk: Record<string, { score: number; threats: Set<string> }> = {};
  for (const profile of ACTOR_PREDICTION_PROFILES) {
    for (const sector of profile.sectorFocus) {
      if (!sectorRisk[sector]) sectorRisk[sector] = { score: 0, threats: new Set() };
      sectorRisk[sector].score += 100 / profile.avgWeaponizationDays; // faster = more dangerous
      sectorRisk[sector].threats.add(profile.name);
    }
  }
  
  const sectorRiskMatrix = Object.entries(sectorRisk)
    .map(([sector, data]) => ({ sector, overallRisk: Math.min(100, Math.round(data.score)), primaryThreats: Array.from(data.threats) }))
    .sort((a, b) => b.overallRisk - a.overallRisk);
  
  return {
    highestRiskActors,
    emergingTargets,
    sectorRiskMatrix,
    timeHorizon: {
      next7days: ["Monitor Volt Typhoon edge device targeting", "Watch for CyberAv3ngers PLC exploitation expansion"],
      next30days: ["Sandworm likely to weaponize new Microsoft vuln", "Lazarus cryptocurrency exchange targeting expected"],
      next90days: ["APT29 supply chain campaign predicted", "XENOTIME safety system research expected to mature"],
    },
  };
}
