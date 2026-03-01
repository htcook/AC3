import { getDb } from "./server/db.ts";
import { domainIntelScans } from "./drizzle/schema.ts";
import { desc, sql, not, like, and, or, inArray, notInArray } from "drizzle-orm";

const db = await getDb();
if (!db) { console.error("No DB connection"); process.exit(1); }

// The 10 scan IDs to KEEP
const keepIds = [1410499, 1410498, 1410497, 1410001, 1380385, 1380384, 1380383, 1380382, 1380381, 1380380];
console.log("Keeping scan IDs:", keepIds);

// Get all scan IDs to delete
const allScans = await db.select({ id: domainIntelScans.id }).from(domainIntelScans);
const deleteIds = allScans.map(s => s.id).filter(id => !keepIds.includes(id));
console.log(`Total scans: ${allScans.length}, Keeping: ${keepIds.length}, Deleting: ${deleteIds.length}`);

if (deleteIds.length === 0) {
  console.log("Nothing to delete");
  process.exit(0);
}

// Delete related data in child tables first (in batches to avoid query size limits)
const batchSize = 100;
const tables = [
  "discovered_assets",
  "false_positive_findings", 
  "phishing_drafts",
  "scoring_audit_log",
  "validation_runs",
  "attack_chain_records",
  "web_crawl_results",
  "web_crawl_jobs",
];

for (const table of tables) {
  let col = "scanId";
  if (table === "validation_runs") col = "validationScanId";
  if (table === "attack_chain_records") col = "acr_scan_id";
  if (table === "web_app_findings") col = "scan_id";
  
  try {
    for (let i = 0; i < deleteIds.length; i += batchSize) {
      const batch = deleteIds.slice(i, i + batchSize);
      const placeholders = batch.map(() => "?").join(",");
      await db.execute(sql.raw(`DELETE FROM \`${table}\` WHERE \`${col}\` IN (${batch.join(",")})`));
    }
    console.log(`  Cleaned ${table}`);
  } catch (e) {
    console.log(`  Skipped ${table}: ${e.message?.substring(0, 80)}`);
  }
}

// Also clean engagement_pipelines that reference these scans
try {
  for (let i = 0; i < deleteIds.length; i += batchSize) {
    const batch = deleteIds.slice(i, i + batchSize);
    await db.execute(sql.raw(`DELETE FROM engagement_pipelines WHERE intelScanId IN (${batch.join(",")})`));
  }
  console.log("  Cleaned engagement_pipelines");
} catch (e) {
  console.log(`  Skipped engagement_pipelines: ${e.message?.substring(0, 80)}`);
}

// Clean web_app_scans that reference these scans
try {
  for (let i = 0; i < deleteIds.length; i += batchSize) {
    const batch = deleteIds.slice(i, i + batchSize);
    await db.execute(sql.raw(`DELETE FROM web_app_scans WHERE domain_intel_scan_id IN (${batch.join(",")})`));
  }
  console.log("  Cleaned web_app_scans");
} catch (e) {
  console.log(`  Skipped web_app_scans: ${e.message?.substring(0, 80)}`);
}

// Clean exploit_matches that reference these scans
try {
  for (let i = 0; i < deleteIds.length; i += batchSize) {
    const batch = deleteIds.slice(i, i + batchSize);
    await db.execute(sql.raw(`DELETE FROM exploit_matches WHERE exploitScanId IN (${batch.join(",")})`));
  }
  console.log("  Cleaned exploit_matches");
} catch (e) {
  console.log(`  Skipped exploit_matches: ${e.message?.substring(0, 80)}`);
}

// Finally delete the scans themselves
for (let i = 0; i < deleteIds.length; i += batchSize) {
  const batch = deleteIds.slice(i, i + batchSize);
  await db.execute(sql.raw(`DELETE FROM domain_intel_scans WHERE id IN (${batch.join(",")})`));
}
console.log(`\nDeleted ${deleteIds.length} scans. ${keepIds.length} scans remain.`);

// Verify
const remaining = await db.select({ 
  id: domainIntelScans.id, 
  domain: domainIntelScans.primaryDomain,
  status: domainIntelScans.status 
}).from(domainIntelScans).orderBy(desc(domainIntelScans.id));
console.log("\n=== Remaining Scans ===");
console.table(remaining);

process.exit(0);
