/**
 * Re-run enrichment pipeline to capture ExploitDB entries.
 * Uses the same pipeline as the scheduler but runs synchronously.
 */
import { createRequire } from "module";
const require = createRequire(import.meta.url);

// Set longer timeout for ExploitDB fetch
process.env.EXPLOITDB_TIMEOUT = "120000"; // 2 minutes

async function main() {
  console.log("=== Re-running Enrichment Pipeline ===");
  console.log("Time:", new Date().toISOString());
  
  // Get current catalog stats first
  const { getCatalogStats, runEnrichmentPipeline } = await import("./server/lib/exploit-catalog.ts");
  
  const beforeStats = await getCatalogStats();
  console.log("\n--- Before ---");
  console.log("Total entries:", beforeStats.total);
  console.log("By source:", JSON.stringify(beforeStats.bySource, null, 2));
  
  // Run the pipeline
  const calderaUrl = process.env.CALDERA_BASE_URL || "";
  console.log("\n--- Running Pipeline ---");
  console.log("Caldera URL:", calderaUrl || "(not set)");
  
  const result = await runEnrichmentPipeline(calderaUrl);
  
  console.log("\n--- Pipeline Result ---");
  console.log("Total processed:", result.totalProcessed);
  console.log("Metasploit added:", result.metasploitAdded);
  console.log("ExploitDB added:", result.exploitDbAdded);
  console.log("Caldera added:", result.calderaStockpileAdded);
  console.log("Phishing added:", result.phishingAdded);
  console.log("Errors:", result.errors.length);
  if (result.errors.length > 0) {
    console.log("Error details:", result.errors.slice(0, 5));
  }
  
  // Get updated stats
  const afterStats = await getCatalogStats();
  console.log("\n--- After ---");
  console.log("Total entries:", afterStats.total);
  console.log("By source:", JSON.stringify(afterStats.bySource, null, 2));
  console.log("\n--- Delta ---");
  console.log("New entries:", afterStats.total - beforeStats.total);
  
  process.exit(0);
}

main().catch((err) => {
  console.error("Pipeline failed:", err);
  process.exit(1);
});
