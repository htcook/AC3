/**
 * Batch Domain Intelligence Scanner
 * Processes 124 domains through the auto-industry-carver module
 * to generate LLM training data and scoring logic tuning datasets.
 * 
 * Usage: cd /home/ubuntu/caldera-dashboard && npx tsx server/run-domain-scans.ts
 */
import {
  inferNaics,
  inferSector,
  buildExplainableRiskCard,
  getAllSectorProfiles,
  getAdjustedCarverPreset,
  computeHybridFusionScore,
  getSectorThreatLikelihood,
  getCalderaOperationPriority,
  CARVER_SHOCK_PRESETS,
  FEDRAMP_PROFILES,
  REGULATORY_OVERLAYS,
  NAICS_AUTO_MAPPING,
  THREAT_ACTOR_LIKELIHOOD,
  AUTO_BIA_ASSET_PRIORITY,
} from "./lib/auto-industry-carver.ts";

// Domain dataset organized by sector
const DOMAIN_DATASET = {
  banking_financial_services: {
    label: "Banking & Financial Services",
    regulatory: ["GLBA", "SOX", "FFIEC"],
    domains: [
      "jpmorganchase.com", "bankofamerica.com", "wellsfargo.com", "citigroup.com",
      "goldmansachs.com", "morganstanley.com", "capitalone.com", "usbank.com",
      "schwab.com", "americanexpress.com", "visa.com", "mastercard.com",
      "nasdaq.com", "cmegroup.com"
    ]
  },
  healthcare_providers: {
    label: "Healthcare & Life Sciences",
    regulatory: ["HIPAA", "HITECH"],
    domains: [
      "hcahealthcare.com", "mayo.edu", "clevelandclinic.org", "kaiserpermanente.org",
      "unitedhealthgroup.com", "cvshealth.com", "pfizer.com", "moderna.com",
      "johnsonandjohnson.com", "merck.com", "medtronic.com", "abbott.com"
    ]
  },
  defense_aerospace: {
    label: "Defense & Aerospace",
    regulatory: ["CMMC", "ITAR", "DFARS"],
    domains: [
      "lockheedmartin.com", "northropgrumman.com", "raytheon.com", "boeing.com",
      "generaldynamics.com", "bae-systems.com", "l3harris.com", "leidos.com", "saic.com"
    ]
  },
  federal_government: {
    label: "Government (Federal/State/Local)",
    regulatory: ["FISMA", "FedRAMP"],
    domains: [
      "whitehouse.gov", "treasury.gov", "defense.gov", "dhs.gov", "fbi.gov",
      "state.gov", "texas.gov", "ca.gov", "virginia.gov", "nyc.gov", "chicago.gov"
    ]
  },
  electric_gas_utilities: {
    label: "Energy & Utilities",
    regulatory: ["NERC_CIP"],
    domains: [
      "exeloncorp.com", "duke-energy.com", "southerncompany.com", "pgande.com",
      "coned.com", "nexteraenergy.com", "shell.com", "exxonmobil.com",
      "kindermorgan.com", "williams.com"
    ]
  },
  telecommunications: {
    label: "Telecommunications",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "att.com", "verizon.com", "tmobile.com", "comcast.com", "charter.com", "vodafone.com"
    ]
  },
  fintech: {
    label: "Payment Processors / FinTech",
    regulatory: ["GLBA"],
    sectorOverride: "banking_financial_services",
    domains: [
      "stripe.com", "squareup.com", "paypal.com", "adyen.com", "plaid.com"
    ]
  },
  education: {
    label: "Education",
    regulatory: [],
    sectorOverride: "federal_government",
    domains: [
      "harvard.edu", "mit.edu", "stanford.edu", "ucla.edu", "yale.edu", "k12.com"
    ]
  },
  chemical_manufacturing: {
    label: "Chemical & Industrial Manufacturing",
    regulatory: [],
    sectorOverride: "electric_gas_utilities",
    domains: [
      "dow.com", "dupont.com", "basf.com", "3m.com", "honeywell.com"
    ]
  },
  retail: {
    label: "Retail & E-Commerce",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "walmart.com", "target.com", "amazon.com", "bestbuy.com", "homedepot.com", "louisvuitton.com"
    ]
  },
  logistics: {
    label: "Logistics & Transportation",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "fedex.com", "ups.com", "dhl.com", "maersk.com", "delta.com", "united.com", "southwest.com"
    ]
  },
  hospitality: {
    label: "Hospitality",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "marriott.com", "hilton.com", "hyatt.com", "airbnb.com"
    ]
  },
  saas_tech: {
    label: "Technology / SaaS",
    regulatory: [],
    domains: [
      "microsoft.com", "google.com", "amazonaws.com", "salesforce.com", "oracle.com",
      "servicenow.com", "snowflake.com", "paloaltonetworks.com", "crowdstrike.com", "fortinet.com"
    ]
  },
  industrial_manufacturing: {
    label: "Industrial / Manufacturing",
    regulatory: [],
    sectorOverride: "electric_gas_utilities",
    domains: [
      "caterpillar.com", "john-deere.com", "siemens.com", "ge.com"
    ]
  },
  media: {
    label: "Media & Entertainment",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "netflix.com", "disney.com", "fox.com", "cnn.com", "nytimes.com"
    ]
  },
  construction: {
    label: "Construction & Infrastructure",
    regulatory: [],
    sectorOverride: "electric_gas_utilities",
    domains: [
      "bechtel.com", "kiewit.com", "jacobs.com"
    ]
  },
  agriculture: {
    label: "Agriculture & Food Production",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "cargill.com", "tysonfoods.com", "monsanto.com"
    ]
  },
  automotive: {
    label: "Automotive",
    regulatory: [],
    sectorOverride: "saas_tech",
    domains: [
      "ford.com", "gm.com", "tesla.com", "toyota.com"
    ]
  }
};

// ── Process all domains ──────────────────────────────────────────────

const results = [];
const sectorStats = {};
let totalProcessed = 0;

for (const [sectorKey, sectorData] of Object.entries(DOMAIN_DATASET)) {
  const sectorResults = [];
  
  for (const domain of sectorData.domains) {
    totalProcessed++;
    
    // Step 1: Run NAICS inference
    const naicsResult = inferNaics({ domain, keywords: sectorData.label.split(/\s+/) });
    
    // Step 2: Run sector inference
    const sectorResult = inferSector({ domain, keywords: sectorData.label.split(/\s+/) });
    
    // Step 3: Determine effective sector (use override if NAICS inference is weak)
    const effectiveSector = sectorData.sectorOverride || sectorResult.sector;
    
    // Step 4: Build explainable risk card
    const riskCard = buildExplainableRiskCard({
      assetId: `domain-${domain.replace(/\./g, '-')}`,
      assetLabel: domain,
      domain,
      keywords: sectorData.label.split(/\s+/),
      assetSignals: [],
      overrideSector: effectiveSector,
    });
    
    // Step 5: Get threat likelihood for the effective sector
    const threats = getSectorThreatLikelihood(effectiveSector);
    
    // Step 6: Get Caldera op priority
    const calderaOp = getCalderaOperationPriority({
      priorityTier: riskCard.scores.priorityTier,
      regulatory: riskCard.regulatoryProfile,
      sector: effectiveSector,
      assetSignals: [],
    });
    
    const entry = {
      domain,
      groundTruthSector: sectorKey,
      groundTruthLabel: sectorData.label,
      groundTruthRegulatory: sectorData.regulatory,
      naicsInference: {
        primaryNaics: naicsResult.primaryNaics,
        primaryLabel: naicsResult.primaryLabel,
        confidence: naicsResult.confidence,
        confidenceBand: naicsResult.confidenceBand,
        candidateCount: naicsResult.candidates.length,
        topCandidates: naicsResult.candidates.slice(0, 3),
        evidence: naicsResult.evidence,
      },
      sectorInference: {
        inferredSector: sectorResult.sector,
        inferredConfidence: sectorResult.confidence,
        effectiveSector,
        sectorOverrideApplied: !!sectorData.sectorOverride,
      },
      riskCard: {
        scores: riskCard.scores,
        regulatoryProfile: riskCard.regulatoryProfile,
        topDrivers: riskCard.topDrivers,
        threatLikelihood: riskCard.threatLikelihood,
        recommendedActions: riskCard.recommendedActions.slice(0, 5),
        calderaPriority: riskCard.calderaPriority,
        confidence: riskCard.confidence,
      },
      threatLikelihood: threats.slice(0, 5),
      calderaOp,
      timestamp: new Date().toISOString(),
    };
    
    sectorResults.push(entry);
    
    if (totalProcessed % 10 === 0) {
      console.error(`[Progress] Processed ${totalProcessed}/124 domains...`);
    }
  }
  
  // Sector statistics
  const avgHybrid = sectorResults.reduce((s, r) => s + r.riskCard.scores.hybrid, 0) / sectorResults.length;
  const avgCarver = sectorResults.reduce((s, r) => s + r.riskCard.scores.carverShock, 0) / sectorResults.length;
  const tierDist = { P0: 0, P1: 0, P2: 0, P3: 0 };
  sectorResults.forEach(r => tierDist[r.riskCard.scores.priorityTier]++);
  
  sectorStats[sectorKey] = {
    label: sectorData.label,
    domainCount: sectorData.domains.length,
    avgHybridScore: Math.round(avgHybrid * 100) / 100,
    avgCarverComposite: Math.round(avgCarver * 100) / 100,
    tierDistribution: tierDist,
    regulatory: sectorData.regulatory,
  };
  
  results.push(...sectorResults);
}

// ── Output ───────────────────────────────────────────────────────────

const output = {
  metadata: {
    generatedAt: new Date().toISOString(),
    totalDomains: results.length,
    sectorCount: Object.keys(DOMAIN_DATASET).length,
    purpose: "LLM training data for Auto-BIA + hybrid CARVER+SHOCK scoring baseline modeling",
    modules: ["auto-industry-carver v1", "auto-industry-carver v2", "NAICS inference", "FIPS 199", "FedRAMP profiles"],
  },
  sectorStatistics: sectorStats,
  domainResults: results,
  // Include reference data for LLM context
  referenceData: {
    carverPresets: CARVER_SHOCK_PRESETS,
    regulatoryOverlays: REGULATORY_OVERLAYS,
    fedRampProfiles: FEDRAMP_PROFILES,
    threatActorLikelihood: THREAT_ACTOR_LIKELIHOOD,
    biaAssetPriority: AUTO_BIA_ASSET_PRIORITY,
    sectorProfiles: getAllSectorProfiles(),
  },
};

// Write to stdout as JSON
console.log(JSON.stringify(output, null, 2));
console.error(`\n[Complete] Processed ${results.length} domains across ${Object.keys(DOMAIN_DATASET).length} sectors`);
