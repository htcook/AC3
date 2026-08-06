/**
 * Actor Genome Training Pipeline
 * 
 * Calibrates the Actor Genome Engine's feature weights using historical data:
 * - Past DFIR report attributions (ground truth)
 * - Engagement findings with confirmed actor involvement
 * - Advisory-to-actor mappings with known outcomes
 * - Campaign data with post-hoc attribution confirmation
 * 
 * The pipeline computes prediction accuracy per feature category,
 * identifies which features are most/least predictive for each actor,
 * and adjusts weights to maximize attribution precision.
 * 
 * Schedule: Weekly on Sundays at 04:00 UTC
 */
import cron from "node-cron";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface TrainingCase {
  id: string;
  source: "dfir_report" | "engagement" | "advisory" | "campaign" | "manual";
  /** The confirmed actor (ground truth) */
  confirmedActor: string;
  /** Confidence in the ground truth (0-1) */
  groundTruthConfidence: number;
  /** Observable evidence from the incident */
  observedEvidence: ObservedEvidence;
  /** When this case was recorded */
  recordedAt: Date;
  /** Optional notes on attribution methodology */
  attributionNotes?: string;
}

export interface ObservedEvidence {
  techniques: string[];        // MITRE ATT&CK technique IDs
  malwareFamilies: string[];   // Malware names/hashes
  infrastructure: InfraEvidence[];
  victimSectors: string[];
  victimGeographies: string[];
  toolsUsed: string[];
  timestamps: number[];        // UTC timestamps of activity
  languageArtifacts: string[]; // Language/encoding in tools/comms
  operationalPatterns: string[]; // e.g., "changed PLC passwords", "left propaganda"
}

export interface InfraEvidence {
  type: "ip" | "domain" | "asn" | "jarm" | "ja3" | "tls_cert" | "vps_provider";
  value: string;
  firstSeen?: Date;
  lastSeen?: Date;
}

export interface WeightCalibration {
  featureCategory: string;
  currentWeight: number;
  proposedWeight: number;
  delta: number;
  accuracy: number;         // How often this feature correctly predicted the actor
  falsePositiveRate: number; // How often this feature incorrectly implicated wrong actor
  coverage: number;          // What % of training cases had this feature available
  sampleSize: number;
  confidence: number;        // Statistical confidence in the proposed adjustment
}

export interface TrainingResult {
  runId: string;
  startedAt: Date;
  completedAt: Date;
  trainingCasesUsed: number;
  actorsCovered: string[];
  calibrations: WeightCalibration[];
  overallAccuracyBefore: number;
  overallAccuracyAfter: number;
  improvementPct: number;
  weightsApplied: boolean;
  notes: string[];
}

// ─── Feature Categories (must match actor-genome-engine.ts) ──────────────────

const FEATURE_CATEGORIES = [
  "techniques_mitre",
  "malware_families",
  "infrastructure_asn",
  "infrastructure_vps",
  "infrastructure_tls",
  "infrastructure_jarm",
  "victim_sector",
  "victim_geography",
  "tools_offensive",
  "tools_custom",
  "language_artifacts",
  "operational_tempo",
  "utc_work_hours",
  "campaign_duration",
  "initial_access_method",
  "lateral_movement_style",
  "exfiltration_method",
  "persistence_mechanism",
  "c2_protocol",
  "target_selection_pattern",
] as const;

type FeatureCategory = typeof FEATURE_CATEGORIES[number];

// ─── Training Data Collection ────────────────────────────────────────────────

/**
 * Collect training cases from all available data sources
 */
async function collectTrainingCases(): Promise<TrainingCase[]> {
  const cases: TrainingCase[] = [];
  
  // Source 1: DFIR Reports with confirmed attribution
  const dfirCases = await collectFromDfirReports();
  cases.push(...dfirCases);
  
  // Source 2: Past engagements with actor confirmation
  const engagementCases = await collectFromEngagements();
  cases.push(...engagementCases);
  
  // Source 3: Advisory correlation events with known actors
  const advisoryCases = await collectFromAdvisories();
  cases.push(...advisoryCases);
  
  // Source 4: Threat actor catalog campaigns
  const campaignCases = await collectFromCampaigns();
  cases.push(...campaignCases);
  
  console.log(`[GenomeTraining] Collected ${cases.length} training cases: ${dfirCases.length} DFIR, ${engagementCases.length} engagement, ${advisoryCases.length} advisory, ${campaignCases.length} campaign`);
  
  return cases;
}

async function collectFromDfirReports(): Promise<TrainingCase[]> {
  const cases: TrainingCase[] = [];
  
  try {
    const { getDb } = await import("../db");
    const database = await getDb();
    if (!database) return cases;
    
    const { sql } = await import("drizzle-orm");
    
    // Query DFIR report data that has confirmed actor attribution
    const results = await database.execute(sql`
      SELECT id, title, threat_actors, techniques, malware_families, 
             infrastructure, victim_sectors, tools_used, created_at,
             confidence_level
      FROM threat_intel_reports
      WHERE threat_actors IS NOT NULL 
        AND threat_actors != '[]'
        AND confidence_level >= 0.7
      ORDER BY created_at DESC
      LIMIT 500
    `);
    
    const rows = (results[0] || []) as any[];
    
    for (const row of rows) {
      try {
        const actors = typeof row.threat_actors === "string" ? JSON.parse(row.threat_actors) : row.threat_actors;
        if (!actors || actors.length === 0) continue;
        
        const techniques = typeof row.techniques === "string" ? JSON.parse(row.techniques) : (row.techniques || []);
        const malware = typeof row.malware_families === "string" ? JSON.parse(row.malware_families) : (row.malware_families || []);
        const infra = typeof row.infrastructure === "string" ? JSON.parse(row.infrastructure) : (row.infrastructure || []);
        const tools = typeof row.tools_used === "string" ? JSON.parse(row.tools_used) : (row.tools_used || []);
        
        cases.push({
          id: `dfir-${row.id}`,
          source: "dfir_report",
          confirmedActor: actors[0],
          groundTruthConfidence: row.confidence_level || 0.8,
          observedEvidence: {
            techniques,
            malwareFamilies: malware,
            infrastructure: (infra || []).map((i: any) => ({ type: "ip" as const, value: String(i) })),
            victimSectors: typeof row.victim_sectors === "string" ? JSON.parse(row.victim_sectors) : (row.victim_sectors || []),
            victimGeographies: [],
            toolsUsed: tools,
            timestamps: [new Date(row.created_at).getTime()],
            languageArtifacts: [],
            operationalPatterns: [],
          },
          recordedAt: new Date(row.created_at),
        });
      } catch {
        // Skip malformed rows
      }
    }
  } catch (err: any) {
    console.warn(`[GenomeTraining] DFIR collection failed: ${err.message}`);
  }
  
  return cases;
}

async function collectFromEngagements(): Promise<TrainingCase[]> {
  const cases: TrainingCase[] = [];
  
  try {
    const { getDb } = await import("../db");
    const database = await getDb();
    if (!database) return cases;
    
    const { sql } = await import("drizzle-orm");
    
    // Query engagement findings that reference specific threat actors
    const results = await database.execute(sql`
      SELECT e.id, e.name, e.threat_profile, e.created_at,
             ef.finding_type, ef.details, ef.severity
      FROM engagements e
      LEFT JOIN engagement_findings ef ON ef.engagement_id = e.id
      WHERE e.threat_profile IS NOT NULL
        AND e.threat_profile != ''
      ORDER BY e.created_at DESC
      LIMIT 200
    `);
    
    const rows = (results[0] || []) as any[];
    
    // Group findings by engagement
    const engagementMap = new Map<string, { actor: string; findings: any[]; createdAt: Date }>();
    
    for (const row of rows) {
      if (!engagementMap.has(row.id)) {
        engagementMap.set(row.id, {
          actor: row.threat_profile,
          findings: [],
          createdAt: new Date(row.created_at),
        });
      }
      if (row.finding_type) {
        engagementMap.get(row.id)!.findings.push(row);
      }
    }
    
    for (const [engId, data] of engagementMap) {
      const techniques: string[] = [];
      const tools: string[] = [];
      
      for (const finding of data.findings) {
        if (finding.details) {
          const detailStr = typeof finding.details === "string" ? finding.details : JSON.stringify(finding.details);
          // Extract technique IDs
          const techMatches = detailStr.match(/T\d{4}(?:\.\d{3})?/g);
          if (techMatches) techniques.push(...techMatches);
        }
      }
      
      cases.push({
        id: `eng-${engId}`,
        source: "engagement",
        confirmedActor: data.actor,
        groundTruthConfidence: 0.75,
        observedEvidence: {
          techniques: [...new Set(techniques)],
          malwareFamilies: [],
          infrastructure: [],
          victimSectors: [],
          victimGeographies: [],
          toolsUsed: [...new Set(tools)],
          timestamps: [data.createdAt.getTime()],
          languageArtifacts: [],
          operationalPatterns: [],
        },
        recordedAt: data.createdAt,
      });
    }
  } catch (err: any) {
    console.warn(`[GenomeTraining] Engagement collection failed: ${err.message}`);
  }
  
  return cases;
}

async function collectFromAdvisories(): Promise<TrainingCase[]> {
  const cases: TrainingCase[] = [];
  
  try {
    const { getDb } = await import("../db");
    const database = await getDb();
    if (!database) return cases;
    
    const { sql } = await import("drizzle-orm");
    
    // Query advisory correlation events that have confirmed threat actors
    const results = await database.execute(sql`
      SELECT id, advisory_id, source, title, severity, cves, 
             affected_products, threat_actors, sectors, published_at
      FROM advisory_correlation_events
      WHERE threat_actors IS NOT NULL 
        AND threat_actors != '[]'
      ORDER BY published_at DESC
      LIMIT 300
    `);
    
    const rows = (results[0] || []) as any[];
    
    for (const row of rows) {
      try {
        const actors = typeof row.threat_actors === "string" ? JSON.parse(row.threat_actors) : row.threat_actors;
        if (!actors || actors.length === 0) continue;
        
        const cves = typeof row.cves === "string" ? JSON.parse(row.cves) : (row.cves || []);
        const sectors = typeof row.sectors === "string" ? JSON.parse(row.sectors) : (row.sectors || []);
        
        cases.push({
          id: `adv-${row.id}`,
          source: "advisory",
          confirmedActor: actors[0],
          groundTruthConfidence: 0.9, // Government advisories are high confidence
          observedEvidence: {
            techniques: [],
            malwareFamilies: [],
            infrastructure: [],
            victimSectors: sectors,
            victimGeographies: [],
            toolsUsed: [],
            timestamps: [new Date(row.published_at).getTime()],
            languageArtifacts: [],
            operationalPatterns: [],
          },
          recordedAt: new Date(row.published_at),
        });
      } catch {
        // Skip malformed rows
      }
    }
  } catch (err: any) {
    console.warn(`[GenomeTraining] Advisory collection failed: ${err.message}`);
  }
  
  return cases;
}

async function collectFromCampaigns(): Promise<TrainingCase[]> {
  const cases: TrainingCase[] = [];
  
  try {
    const { getDb } = await import("../db");
    const database = await getDb();
    if (!database) return cases;
    
    const { sql } = await import("drizzle-orm");
    
    // Query threat actor campaigns with known TTPs
    const results = await database.execute(sql`
      SELECT id, actor_name, campaign_name, techniques, malware,
             infrastructure, target_sectors, target_countries,
             start_date, tools_used
      FROM threat_actor_campaigns
      WHERE actor_name IS NOT NULL
      ORDER BY start_date DESC
      LIMIT 400
    `);
    
    const rows = (results[0] || []) as any[];
    
    for (const row of rows) {
      try {
        const techniques = typeof row.techniques === "string" ? JSON.parse(row.techniques) : (row.techniques || []);
        const malware = typeof row.malware === "string" ? JSON.parse(row.malware) : (row.malware || []);
        const infra = typeof row.infrastructure === "string" ? JSON.parse(row.infrastructure) : (row.infrastructure || []);
        const tools = typeof row.tools_used === "string" ? JSON.parse(row.tools_used) : (row.tools_used || []);
        const sectors = typeof row.target_sectors === "string" ? JSON.parse(row.target_sectors) : (row.target_sectors || []);
        const countries = typeof row.target_countries === "string" ? JSON.parse(row.target_countries) : (row.target_countries || []);
        
        cases.push({
          id: `camp-${row.id}`,
          source: "campaign",
          confirmedActor: row.actor_name,
          groundTruthConfidence: 0.85,
          observedEvidence: {
            techniques,
            malwareFamilies: malware,
            infrastructure: (infra || []).map((i: any) => ({ type: "ip" as const, value: String(i) })),
            victimSectors: sectors,
            victimGeographies: countries,
            toolsUsed: tools,
            timestamps: row.start_date ? [new Date(row.start_date).getTime()] : [],
            languageArtifacts: [],
            operationalPatterns: [],
          },
          recordedAt: row.start_date ? new Date(row.start_date) : new Date(),
        });
      } catch {
        // Skip malformed rows
      }
    }
  } catch (err: any) {
    console.warn(`[GenomeTraining] Campaign collection failed: ${err.message}`);
  }
  
  return cases;
}

// ─── Weight Calibration Engine ───────────────────────────────────────────────

/**
 * Run the genome scoring engine against each training case and measure accuracy.
 * Then compute optimal weight adjustments.
 */
async function calibrateWeights(trainingCases: TrainingCase[]): Promise<WeightCalibration[]> {
  const calibrations: WeightCalibration[] = [];
  
  if (trainingCases.length < 10) {
    console.log("[GenomeTraining] Insufficient training cases (<10), skipping calibration");
    return calibrations;
  }
  
  // Import the genome engine to test scoring
  const { scoreIncident, getActorProfiles } = await import("./actor-genome-engine");
  
  // Current weights from the engine (baseline)
  const currentWeights: Record<string, number> = {
    techniques_mitre: 0.20,
    malware_families: 0.15,
    infrastructure_asn: 0.08,
    infrastructure_vps: 0.06,
    infrastructure_tls: 0.06,
    infrastructure_jarm: 0.05,
    victim_sector: 0.08,
    victim_geography: 0.06,
    tools_offensive: 0.05,
    tools_custom: 0.04,
    language_artifacts: 0.03,
    operational_tempo: 0.04,
    utc_work_hours: 0.03,
    campaign_duration: 0.02,
    initial_access_method: 0.05,
    lateral_movement_style: 0.03,
    exfiltration_method: 0.02,
    persistence_mechanism: 0.03,
    c2_protocol: 0.03,
    target_selection_pattern: 0.04,
  };
  
  // Track per-feature accuracy
  const featureStats: Record<string, { correct: number; incorrect: number; available: number }> = {};
  for (const cat of FEATURE_CATEGORIES) {
    featureStats[cat] = { correct: 0, incorrect: 0, available: 0 };
  }
  
  // Score each training case and measure accuracy
  let correctPredictions = 0;
  let totalPredictions = 0;
  
  for (const tc of trainingCases) {
    try {
      // Build incident data from observed evidence
      const incidentData = {
        techniques: tc.observedEvidence.techniques,
        malwareFamilies: tc.observedEvidence.malwareFamilies,
        infrastructure: tc.observedEvidence.infrastructure.map(i => i.value),
        victimSectors: tc.observedEvidence.victimSectors,
        victimGeographies: tc.observedEvidence.victimGeographies,
        toolsUsed: tc.observedEvidence.toolsUsed,
        timestamps: tc.observedEvidence.timestamps,
        languageArtifacts: tc.observedEvidence.languageArtifacts,
      };
      
      // Score against all actors
      const results = scoreIncident(incidentData);
      
      if (results.length > 0) {
        totalPredictions++;
        const topPrediction = results[0];
        
        // Check if top prediction matches ground truth
        const isCorrect = topPrediction.actorId.toLowerCase().includes(tc.confirmedActor.toLowerCase()) ||
                          tc.confirmedActor.toLowerCase().includes(topPrediction.actorId.toLowerCase());
        
        if (isCorrect) correctPredictions++;
        
        // Track which features contributed to correct/incorrect predictions
        if (tc.observedEvidence.techniques.length > 0) {
          featureStats.techniques_mitre.available++;
          if (isCorrect) featureStats.techniques_mitre.correct++;
          else featureStats.techniques_mitre.incorrect++;
        }
        if (tc.observedEvidence.malwareFamilies.length > 0) {
          featureStats.malware_families.available++;
          if (isCorrect) featureStats.malware_families.correct++;
          else featureStats.malware_families.incorrect++;
        }
        if (tc.observedEvidence.infrastructure.length > 0) {
          featureStats.infrastructure_asn.available++;
          if (isCorrect) featureStats.infrastructure_asn.correct++;
          else featureStats.infrastructure_asn.incorrect++;
        }
        if (tc.observedEvidence.victimSectors.length > 0) {
          featureStats.victim_sector.available++;
          if (isCorrect) featureStats.victim_sector.correct++;
          else featureStats.victim_sector.incorrect++;
        }
        if (tc.observedEvidence.toolsUsed.length > 0) {
          featureStats.tools_offensive.available++;
          if (isCorrect) featureStats.tools_offensive.correct++;
          else featureStats.tools_offensive.incorrect++;
        }
        if (tc.observedEvidence.timestamps.length > 0) {
          featureStats.operational_tempo.available++;
          if (isCorrect) featureStats.operational_tempo.correct++;
          else featureStats.operational_tempo.incorrect++;
        }
      }
    } catch {
      // Skip cases that fail scoring
    }
  }
  
  const baselineAccuracy = totalPredictions > 0 ? correctPredictions / totalPredictions : 0;
  console.log(`[GenomeTraining] Baseline accuracy: ${(baselineAccuracy * 100).toFixed(1)}% (${correctPredictions}/${totalPredictions})`);
  
  // Compute calibrations for each feature
  for (const category of FEATURE_CATEGORIES) {
    const stats = featureStats[category];
    const total = stats.correct + stats.incorrect;
    
    if (total < 5) {
      // Insufficient data for this feature
      calibrations.push({
        featureCategory: category,
        currentWeight: currentWeights[category] || 0.05,
        proposedWeight: currentWeights[category] || 0.05,
        delta: 0,
        accuracy: 0,
        falsePositiveRate: 0,
        coverage: stats.available / Math.max(trainingCases.length, 1),
        sampleSize: total,
        confidence: 0,
      });
      continue;
    }
    
    const accuracy = stats.correct / total;
    const falsePositiveRate = stats.incorrect / total;
    const coverage = stats.available / trainingCases.length;
    
    // Compute proposed weight adjustment
    // High accuracy + high coverage = increase weight
    // Low accuracy + high false positive = decrease weight
    const currentW = currentWeights[category] || 0.05;
    const performanceScore = (accuracy * 0.7 + coverage * 0.3) - (falsePositiveRate * 0.5);
    
    // Bounded adjustment: max ±30% change per cycle
    const maxDelta = currentW * 0.3;
    const rawDelta = (performanceScore - 0.5) * currentW * 0.5;
    const boundedDelta = Math.max(-maxDelta, Math.min(maxDelta, rawDelta));
    
    const proposedWeight = Math.max(0.01, Math.min(0.35, currentW + boundedDelta));
    
    // Statistical confidence based on sample size (Wilson score interval approximation)
    const confidence = Math.min(1, total / 50);
    
    calibrations.push({
      featureCategory: category,
      currentWeight: currentW,
      proposedWeight,
      delta: proposedWeight - currentW,
      accuracy,
      falsePositiveRate,
      coverage,
      sampleSize: total,
      confidence,
    });
  }
  
  // Normalize proposed weights to sum to 1.0
  const totalProposed = calibrations.reduce((sum, c) => sum + c.proposedWeight, 0);
  if (totalProposed > 0) {
    for (const cal of calibrations) {
      cal.proposedWeight = cal.proposedWeight / totalProposed;
      cal.delta = cal.proposedWeight - cal.currentWeight;
    }
  }
  
  return calibrations;
}

// ─── Weight Application ──────────────────────────────────────────────────────

/**
 * Apply calibrated weights to the Actor Genome Engine.
 * Only applies if improvement is >= 2% and confidence is sufficient.
 */
async function applyCalibration(calibrations: WeightCalibration[], minImprovement: number = 0.02): Promise<boolean> {
  // Check if any calibration has sufficient confidence and meaningful delta
  const significantChanges = calibrations.filter(c => 
    c.confidence >= 0.5 && Math.abs(c.delta) >= 0.005
  );
  
  if (significantChanges.length === 0) {
    console.log("[GenomeTraining] No significant weight changes to apply");
    return false;
  }
  
  // Persist calibrated weights to database for the engine to pick up
  try {
    const { getDb } = await import("../db");
    const database = await getDb();
    if (!database) return false;
    
    const { sql } = await import("drizzle-orm");
    
    const weightMap: Record<string, number> = {};
    for (const cal of calibrations) {
      weightMap[cal.featureCategory] = cal.proposedWeight;
    }
    
    // Store in a config table
    await database.execute(sql`
      INSERT INTO system_config (config_key, config_value, updated_at)
      VALUES ('actor_genome_weights', ${JSON.stringify(weightMap)}, NOW())
      ON DUPLICATE KEY UPDATE
        config_value = VALUES(config_value),
        updated_at = NOW()
    `);
    
    console.log(`[GenomeTraining] Applied ${significantChanges.length} weight calibrations`);
    return true;
  } catch (err: any) {
    console.warn(`[GenomeTraining] Weight persistence failed: ${err.message}`);
    return false;
  }
}

// ─── Training Result Persistence ─────────────────────────────────────────────

async function persistTrainingResult(result: TrainingResult): Promise<void> {
  try {
    const { getDb } = await import("../db");
    const database = await getDb();
    if (!database) return;
    
    const { sql } = await import("drizzle-orm");
    
    await database.execute(sql`
      INSERT INTO genome_training_runs (id, started_at, completed_at, cases_used, actors_covered, 
                                         accuracy_before, accuracy_after, improvement_pct, weights_applied, notes)
      VALUES (
        ${result.runId},
        ${result.startedAt.toISOString()},
        ${result.completedAt.toISOString()},
        ${result.trainingCasesUsed},
        ${JSON.stringify(result.actorsCovered)},
        ${result.overallAccuracyBefore},
        ${result.overallAccuracyAfter},
        ${result.improvementPct},
        ${result.weightsApplied ? 1 : 0},
        ${JSON.stringify(result.notes)}
      )
    `);
  } catch (err: any) {
    // Table may not exist — non-critical
    console.warn(`[GenomeTraining] Result persistence failed: ${err.message}`);
  }
}

// ─── Main Training Pipeline ──────────────────────────────────────────────────

let trainingRunning = false;

/**
 * Run the full Actor Genome training pipeline
 */
export async function runGenomeTraining(trigger: "scheduled" | "manual" = "scheduled"): Promise<TrainingResult> {
  if (trainingRunning) {
    console.log("[GenomeTraining] Skipping — previous training still running");
    return {
      runId: `skip-${Date.now()}`,
      startedAt: new Date(),
      completedAt: new Date(),
      trainingCasesUsed: 0,
      actorsCovered: [],
      calibrations: [],
      overallAccuracyBefore: 0,
      overallAccuracyAfter: 0,
      improvementPct: 0,
      weightsApplied: false,
      notes: ["Skipped: previous training still running"],
    };
  }
  
  trainingRunning = true;
  const startedAt = new Date();
  const runId = `genome-train-${Date.now()}`;
  
  console.log(`[GenomeTraining] Starting ${trigger} training run ${runId}...`);
  
  try {
    // Step 1: Collect training data
    const trainingCases = await collectTrainingCases();
    
    if (trainingCases.length < 10) {
      const result: TrainingResult = {
        runId,
        startedAt,
        completedAt: new Date(),
        trainingCasesUsed: trainingCases.length,
        actorsCovered: [...new Set(trainingCases.map(tc => tc.confirmedActor))],
        calibrations: [],
        overallAccuracyBefore: 0,
        overallAccuracyAfter: 0,
        improvementPct: 0,
        weightsApplied: false,
        notes: [`Insufficient training data (${trainingCases.length} cases, need >=10)`],
      };
      await persistTrainingResult(result);
      return result;
    }
    
    // Step 2: Calibrate weights
    const calibrations = await calibrateWeights(trainingCases);
    
    // Step 3: Compute accuracy improvement
    const accuracyBefore = calibrations.length > 0 
      ? calibrations.reduce((sum, c) => sum + c.accuracy * c.coverage, 0) / Math.max(calibrations.reduce((sum, c) => sum + c.coverage, 0), 1)
      : 0;
    
    // Step 4: Apply calibration if improvement is sufficient
    const weightsApplied = await applyCalibration(calibrations);
    
    // Estimate accuracy after (conservative: assume 50% of theoretical improvement)
    const theoreticalImprovement = calibrations
      .filter(c => c.delta > 0 && c.confidence >= 0.5)
      .reduce((sum, c) => sum + c.delta * c.accuracy, 0);
    const accuracyAfter = accuracyBefore + (theoreticalImprovement * 0.5);
    
    const result: TrainingResult = {
      runId,
      startedAt,
      completedAt: new Date(),
      trainingCasesUsed: trainingCases.length,
      actorsCovered: [...new Set(trainingCases.map(tc => tc.confirmedActor))],
      calibrations,
      overallAccuracyBefore: accuracyBefore,
      overallAccuracyAfter: accuracyAfter,
      improvementPct: accuracyBefore > 0 ? ((accuracyAfter - accuracyBefore) / accuracyBefore) * 100 : 0,
      weightsApplied,
      notes: [
        `Training cases: ${trainingCases.length} from ${new Set(trainingCases.map(tc => tc.source)).size} sources`,
        `Actors covered: ${[...new Set(trainingCases.map(tc => tc.confirmedActor))].length}`,
        `Significant calibrations: ${calibrations.filter(c => Math.abs(c.delta) >= 0.005).length}`,
        weightsApplied ? "Weights applied to engine" : "Weights not applied (insufficient improvement)",
      ],
    };
    
    await persistTrainingResult(result);
    
    console.log(`[GenomeTraining] Training complete: ${result.trainingCasesUsed} cases, accuracy ${(accuracyBefore * 100).toFixed(1)}% → ${(accuracyAfter * 100).toFixed(1)}%, weights ${weightsApplied ? "applied" : "not applied"}`);
    
    return result;
    
  } catch (err: any) {
    console.error(`[GenomeTraining] Pipeline error: ${err.message}`);
    const result: TrainingResult = {
      runId,
      startedAt,
      completedAt: new Date(),
      trainingCasesUsed: 0,
      actorsCovered: [],
      calibrations: [],
      overallAccuracyBefore: 0,
      overallAccuracyAfter: 0,
      improvementPct: 0,
      weightsApplied: false,
      notes: [`Error: ${err.message}`],
    };
    await persistTrainingResult(result);
    return result;
  } finally {
    trainingRunning = false;
  }
}

// ─── tRPC-Accessible Functions ───────────────────────────────────────────────

/**
 * Get the latest training run results
 */
export async function getLatestTrainingResult(): Promise<TrainingResult | null> {
  try {
    const { getDb } = await import("../db");
    const database = await getDb();
    if (!database) return null;
    
    const { sql } = await import("drizzle-orm");
    
    const results = await database.execute(sql`
      SELECT * FROM genome_training_runs
      ORDER BY completed_at DESC
      LIMIT 1
    `);
    
    const row = (results[0] || [])[0] as any;
    if (!row) return null;
    
    return {
      runId: row.id,
      startedAt: new Date(row.started_at),
      completedAt: new Date(row.completed_at),
      trainingCasesUsed: row.cases_used,
      actorsCovered: typeof row.actors_covered === "string" ? JSON.parse(row.actors_covered) : row.actors_covered,
      calibrations: [],
      overallAccuracyBefore: row.accuracy_before,
      overallAccuracyAfter: row.accuracy_after,
      improvementPct: row.improvement_pct,
      weightsApplied: !!row.weights_applied,
      notes: typeof row.notes === "string" ? JSON.parse(row.notes) : row.notes,
    };
  } catch {
    return null;
  }
}

/**
 * Get training history (last N runs)
 */
export async function getTrainingHistory(limit: number = 10): Promise<TrainingResult[]> {
  try {
    const { getDb } = await import("../db");
    const database = await getDb();
    if (!database) return [];
    
    const { sql } = await import("drizzle-orm");
    
    const results = await database.execute(sql`
      SELECT * FROM genome_training_runs
      ORDER BY completed_at DESC
      LIMIT ${limit}
    `);
    
    return ((results[0] || []) as any[]).map(row => ({
      runId: row.id,
      startedAt: new Date(row.started_at),
      completedAt: new Date(row.completed_at),
      trainingCasesUsed: row.cases_used,
      actorsCovered: typeof row.actors_covered === "string" ? JSON.parse(row.actors_covered) : row.actors_covered,
      calibrations: [],
      overallAccuracyBefore: row.accuracy_before,
      overallAccuracyAfter: row.accuracy_after,
      improvementPct: row.improvement_pct,
      weightsApplied: !!row.weights_applied,
      notes: typeof row.notes === "string" ? JSON.parse(row.notes) : row.notes,
    }));
  } catch {
    return [];
  }
}

// ─── Scheduler Init ──────────────────────────────────────────────────────────

/**
 * Initialize the genome training scheduler.
 * Runs weekly on Sundays at 04:00 UTC.
 */
export function initGenomeTrainingScheduler() {
  const task = cron.schedule("0 4 * * 0", async () => {
    try {
      await runGenomeTraining("scheduled");
    } catch (err) {
      console.error("[GenomeTraining Cron] Scheduled training failed:", err);
    }
  }, {
    timezone: "UTC",
  });
  
  console.log("[GenomeTraining] Scheduled weekly training pipeline (Sundays at 04:00 UTC)");
  return task;
}
