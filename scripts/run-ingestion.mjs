/**
 * Script to trigger TTP Knowledge Base ingestion from GitHub repositories.
 * Calls the ttpEngine.ingest mutation via HTTP.
 */

const BASE_URL = process.env.BASE_URL || "http://localhost:3000";

async function runIngestion() {
  console.log("=== TTP Knowledge Base GitHub Ingestion ===");
  console.log(`Target: ${BASE_URL}`);
  console.log("Sources: ATT&CK STIX, Atomic Red Team, LOLBAS, Metasploit, Kali Tools");
  console.log("Starting...\n");

  const startTime = Date.now();

  try {
    const resp = await fetch(`${BASE_URL}/api/trpc/ttpEngine.ingest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ json: {} }),
    });

    if (!resp.ok) {
      const text = await resp.text();
      console.error(`HTTP ${resp.status}: ${text}`);
      process.exit(1);
    }

    const data = await resp.json();
    const result = data.result?.data?.json || data.result?.data || data;

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`\n=== Ingestion Complete (${elapsed}s) ===`);
    console.log(`Techniques Ingested: ${result.totalTechniquesIngested}`);
    
    if (result.attackStats) {
      console.log(`\nATT&CK STIX Data:`);
      console.log(`  Techniques: ${result.attackStats.techniques}`);
      console.log(`  Groups: ${result.attackStats.groups}`);
      console.log(`  Software: ${result.attackStats.software}`);
    }
    
    if (result.atomicStats) {
      console.log(`\nAtomic Red Team:`);
      console.log(`  Techniques with tests: ${result.atomicStats.techniquesWithTests}`);
    }
    
    if (result.lolbasStats) {
      console.log(`\nLOLBAS:`);
      console.log(`  Techniques with LOLBins: ${result.lolbasStats.techniquesWithLolbins}`);
      console.log(`  Total LOLBin entries: ${result.lolbasStats.totalLolbins}`);
    }
    
    if (result.metasploitStats) {
      console.log(`\nMetasploit:`);
      console.log(`  Exploits: ${result.metasploitStats.exploits}`);
      console.log(`  Auxiliary: ${result.metasploitStats.auxiliary}`);
      console.log(`  Post: ${result.metasploitStats.post}`);
      console.log(`  Total modules: ${result.metasploitStats.total}`);
    }
    
    if (result.kaliStats) {
      console.log(`\nKali Linux:`);
      console.log(`  Tools: ${result.kaliStats.tools}`);
      console.log(`  Categories: ${result.kaliStats.categories}`);
    }
    
    if (result.errors && result.errors.length > 0) {
      console.log(`\nErrors (${result.errors.length}):`);
      result.errors.slice(0, 10).forEach(e => console.log(`  - ${e}`));
      if (result.errors.length > 10) console.log(`  ... and ${result.errors.length - 10} more`);
    }

    return result;
  } catch (err) {
    console.error("Ingestion failed:", err.message);
    process.exit(1);
  }
}

runIngestion();
