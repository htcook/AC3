import { runFullCatalogSync, getCatalogStats } from "./server/lib/threat-intel-connectors.ts";
import { runIocSync } from "./server/lib/ioc-sync.ts";
import { runVulnFeedSync } from "./server/lib/vuln-feed-sync.ts";
import { syncAllDarkwebFeeds } from "./server/lib/darkweb-feeds.ts";

const startTime = Date.now();
console.log("=== FULL DATA FEED SYNC ===");
console.log(`Started at: ${new Date().toISOString()}\n`);

// 1. Threat Intel Catalog (MITRE ATT&CK, Ransomware.live, Malpedia, Caldera)
console.log("--- [1/4] Threat Intel Catalog ---");
try {
  const catalogResult = await runFullCatalogSync();
  console.log("Catalog sync results:");
  for (const [source, result] of Object.entries(catalogResult.results)) {
    console.log(`  ${source}: ${JSON.stringify(result)}`);
  }
  const stats = await getCatalogStats();
  console.log(`  Total actors in DB: ${stats.totalActors}`);
} catch (err) {
  console.error("Catalog sync error:", err.message);
}

// 2. IOC Feeds (CISA KEV, URLhaus, ThreatFox)
console.log("\n--- [2/4] IOC Feeds ---");
try {
  const iocResult = await runIocSync("manual");
  console.log(`IOC sync: ${JSON.stringify(iocResult)}`);
} catch (err) {
  console.error("IOC sync error:", err.message);
}

// 3. Vulnerability Feeds (KEV, NVD, Project Zero, CIRCL, Exploit-DB)
console.log("\n--- [3/4] Vulnerability Feeds ---");
try {
  const vulnResult = await runVulnFeedSync("manual");
  console.log(`Vuln sync: ${JSON.stringify(vulnResult)}`);
} catch (err) {
  console.error("Vuln sync error:", err.message);
}

// 4. Darkweb Feeds (Access Brokers, IO Campaigns)
console.log("\n--- [4/4] Darkweb Feeds (IABs + IO Campaigns) ---");
try {
  const dwResult = await syncAllDarkwebFeeds();
  console.log(`Darkweb sync: ${JSON.stringify(dwResult)}`);
} catch (err) {
  console.error("Darkweb sync error:", err.message);
}

const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
console.log(`\n=== ALL FEEDS COMPLETE in ${elapsed}s ===`);
process.exit(0);
