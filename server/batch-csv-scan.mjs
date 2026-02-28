/**
 * Batch CSV Domain Scanner
 * ────────────────────────
 * Reads the training domains CSV, runs CARVER scoring on each domain,
 * creates a named domain_intel_scan record per domain, and persists
 * CARVER risk cards to the carver_risk_cards table.
 *
 * Usage: npx tsx server/batch-csv-scan.mjs
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// ── CSV Parsing ──────────────────────────────────────────────────────────
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const csvPath = "/home/ubuntu/upload/ace_c3_training_domains_scan_ok.csv";
const csvContent = fs.readFileSync(csvPath, "utf-8");
const lines = csvContent.trim().split("\n");
const header = lines[0].split(",");

const domains = lines.slice(1).map((line) => {
  const cols = line.split(",");
  return {
    domain: cols[0]?.trim(),
    scanOk: cols[1]?.trim() === "True",
    sector: cols[2]?.trim(),
    subSector: cols[3]?.trim(),
    naicsCode: cols[4]?.trim(),
    regulatory: cols[5]?.trim(),
    country: cols[6]?.trim(),
  };
}).filter(d => d.domain && d.scanOk);

console.log(`Parsed ${domains.length} domains from CSV`);
console.log(`Header: ${header.join(", ")}`);

// ── Sector Mapping ───────────────────────────────────────────────────────
// Map CSV sector labels to CarverSector types
const SECTOR_MAP = {
  "Financial": "banking_financial_services",
  "Healthcare": "healthcare_providers",
  "Life Sciences": "pharmaceuticals_biotech",
  "Public Sector": "federal_government",
  "Defense": "defense_aerospace",
  "Energy": "electric_gas_utilities",
  "Telecom": "saas_tech",
  "Tech": "saas_tech",
  "Retail": "saas_tech",
  "Logistics": "saas_tech",
  "Transportation": "saas_tech",
  "Maritime": "saas_tech",
  "Education": "federal_government",
  "Research": "federal_government",
  "Industrial": "electric_gas_utilities",
  "Manufacturing": "electric_gas_utilities",
  "Media": "saas_tech",
  "Entertainment": "saas_tech",
  "Agriculture": "saas_tech",
  "Construction": "saas_tech",
  "Automotive": "electric_gas_utilities",
};

// ── Import CARVER Module ─────────────────────────────────────────────────
const carverModule = await import("./lib/auto-industry-carver.ts");
const {
  buildExplainableRiskCard,
  inferSector,
  inferNaics,
  getSectorThreatLikelihood,
  getCalderaOperationPriority,
} = carverModule;

// ── Generate batch ID ────────────────────────────────────────────────────
const batchId = `csv-training-${Date.now()}`;
console.log(`Batch ID: ${batchId}`);

// ── Process all domains ──────────────────────────────────────────────────
const results = [];
const errors = [];
const sectorStats = {};

for (let i = 0; i < domains.length; i++) {
  const d = domains[i];
  try {
    const overrideSector = SECTOR_MAP[d.sector] || undefined;
    
    // Build keywords from sector and sub-sector for better inference
    const keywords = [d.sector, d.subSector].filter(Boolean);
    
    // Parse regulatory tags
    const regulatoryTags = d.regulatory ? d.regulatory.split(";").filter(Boolean) : [];
    
    // Build the risk card
    const riskCard = buildExplainableRiskCard({
      assetId: d.domain,
      assetLabel: `${d.domain} (${d.subSector || d.sector})`,
      domain: d.domain,
      keywords,
      assetSignals: regulatoryTags,
      overrideSector,
    });

    // Build the DB record
    const record = {
      domain: d.domain,
      scanTitle: `${d.domain} — ${d.subSector || d.sector}`,
      inferredSector: riskCard.sector,
      sectorConfidence: riskCard.confidence >= 0.78 ? "high" : riskCard.confidence >= 0.55 ? "medium" : riskCard.confidence >= 0.35 ? "low" : "insufficient",
      naicsCode: d.naicsCode || riskCard.naics || null,
      naicsLabel: d.subSector || null,
      industry: d.sector,
      regulatoryTags: regulatoryTags.length > 0 ? regulatoryTags : riskCard.regulatoryProfile,
      country: d.country || "US",
      carverScores: {
        criticality: riskCard.scores?.carverShock || 0,
      },
      shockScores: null,
      hybridScore: riskCard.scores?.hybrid || 0,
      priorityTier: riskCard.scores?.priorityTier || "P3",
      confidenceBand: riskCard.confidence >= 0.78 ? "high" : riskCard.confidence >= 0.55 ? "medium" : "low",
      topDrivers: riskCard.topDrivers || [],
      recommendedActions: riskCard.recommendedActions || [],
      calderaOps: riskCard.calderaPriority || null,
      threatLikelihood: riskCard.threatLikelihood || null,
      fedRampProfile: null,
      fips199Category: null,
      fullRiskCard: riskCard,
      source: "csv_batch",
      batchId,
    };

    results.push(record);

    // Track sector stats
    const sKey = d.sector;
    if (!sectorStats[sKey]) sectorStats[sKey] = { count: 0, avgHybrid: 0, tiers: {} };
    sectorStats[sKey].count++;
    sectorStats[sKey].avgHybrid += (riskCard.scores?.hybrid || 0);
    const tier = riskCard.scores?.priorityTier || "P3";
    sectorStats[sKey].tiers[tier] = (sectorStats[sKey].tiers[tier] || 0) + 1;

    if ((i + 1) % 50 === 0) {
      console.log(`  Processed ${i + 1}/${domains.length}...`);
    }
  } catch (err) {
    errors.push({ domain: d.domain, error: err.message });
    console.error(`  ERROR: ${d.domain}: ${err.message}`);
  }
}

console.log(`\nScoring complete: ${results.length} success, ${errors.length} errors`);

// ── Sector Statistics ────────────────────────────────────────────────────
console.log("\n=== Sector Statistics ===");
for (const [sector, stats] of Object.entries(sectorStats)) {
  stats.avgHybrid = (stats.avgHybrid / stats.count).toFixed(2);
  console.log(`  ${sector}: ${stats.count} domains, avg hybrid: ${stats.avgHybrid}, tiers: ${JSON.stringify(stats.tiers)}`);
}

// ── Write results to JSON for DB insertion ───────────────────────────────
const outputPath = `/home/ubuntu/carver-batch-results-${Date.now()}.json`;
fs.writeFileSync(outputPath, JSON.stringify({ batchId, totalDomains: results.length, sectorStats, results, errors }, null, 2));
console.log(`\nResults written to: ${outputPath}`);
console.log(`Batch ID: ${batchId}`);
console.log(`Total risk cards: ${results.length}`);
