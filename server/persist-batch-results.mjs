/**
 * Persist Batch Results to Database
 * ──────────────────────────────────
 * Reads the batch results JSON and inserts all risk cards into the
 * carver_risk_cards table using the app's DB connection.
 *
 * Usage: npx tsx server/persist-batch-results.mjs
 */

import fs from "fs";
import { drizzle } from "drizzle-orm/mysql2";
import mysql from "mysql2/promise";

// Find the most recent batch results file
const files = fs.readdirSync("/home/ubuntu").filter(f => f.startsWith("carver-batch-results-"));
const latestFile = files.sort().pop();
if (!latestFile) {
  console.error("No batch results file found");
  process.exit(1);
}

const resultsPath = `/home/ubuntu/${latestFile}`;
console.log(`Loading results from: ${resultsPath}`);
const data = JSON.parse(fs.readFileSync(resultsPath, "utf-8"));
console.log(`Batch ID: ${data.batchId}, Total records: ${data.results.length}`);

// Connect to DB
const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
  console.error("DATABASE_URL not set");
  process.exit(1);
}

const connection = await mysql.createConnection({
  uri: dbUrl,
  ssl: { rejectUnauthorized: true },
});

console.log("Connected to database");

// Insert in batches of 50
const BATCH_SIZE = 50;
let inserted = 0;

for (let i = 0; i < data.results.length; i += BATCH_SIZE) {
  const batch = data.results.slice(i, i + BATCH_SIZE);
  
  const values = batch.map(r => [
    r.domain,
    r.scanTitle,
    null, // domain_intel_scan_id
    r.inferredSector,
    r.sectorConfidence,
    r.naicsCode || null,
    r.naicsLabel || null,
    r.industry || null,
    JSON.stringify(r.regulatoryTags || []),
    r.country || "US",
    JSON.stringify(r.carverScores || {}),
    JSON.stringify(r.shockScores || null),
    JSON.stringify(r.hybridScore || 0),
    r.priorityTier || "P3",
    r.confidenceBand || "low",
    JSON.stringify(r.topDrivers || []),
    JSON.stringify(r.recommendedActions || []),
    JSON.stringify(r.calderaOps || null),
    JSON.stringify(r.threatLikelihood || null),
    r.fedRampProfile || null,
    JSON.stringify(r.fips199Category || null),
    JSON.stringify(r.fullRiskCard || {}),
    r.source || "csv_batch",
    r.batchId || data.batchId,
    null, // created_by
  ]);

  const placeholders = values.map(() => "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").join(", ");
  const flatValues = values.flat();

  await connection.execute(
    `INSERT INTO carver_risk_cards (
      domain, scan_title, domain_intel_scan_id,
      inferred_sector, sector_confidence, naics_code, naics_label, industry,
      regulatory_tags, country,
      carver_scores, shock_scores, hybrid_score, priority_tier, confidence_band,
      top_drivers, recommended_actions, caldera_ops, threat_likelihood,
      fedramp_profile, fips_199_category, full_risk_card,
      source, batch_id, created_by
    ) VALUES ${placeholders}`,
    flatValues
  );

  inserted += batch.length;
  console.log(`  Inserted ${inserted}/${data.results.length}...`);
}

console.log(`\nDone! Inserted ${inserted} risk cards with batch ID: ${data.batchId}`);

// Verify
const [rows] = await connection.execute(
  "SELECT COUNT(*) as cnt FROM carver_risk_cards WHERE batch_id = ?",
  [data.batchId]
);
console.log(`Verification: ${rows[0].cnt} records in DB for batch ${data.batchId}`);

// Stats
const [sectorRows] = await connection.execute(
  "SELECT inferred_sector, COUNT(*) as cnt, AVG(JSON_EXTRACT(hybrid_score, '$')) as avg_hybrid FROM carver_risk_cards WHERE batch_id = ? GROUP BY inferred_sector ORDER BY cnt DESC",
  [data.batchId]
);
console.log("\n=== DB Sector Breakdown ===");
for (const row of sectorRows) {
  console.log(`  ${row.inferred_sector}: ${row.cnt} cards, avg hybrid: ${Number(row.avg_hybrid).toFixed(2)}`);
}

await connection.end();
