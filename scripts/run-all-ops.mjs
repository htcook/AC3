/**
 * Script to run all 3 operations with authentication:
 * 1. GitHub TTP Ingestion
 * 2. Caldera Adversary Sync
 * 3. Domain Intel Scan on AceofCloud.com
 */
import jwt from "jsonwebtoken";

const BASE_URL = "http://localhost:3000";
const JWT_SECRET = process.env.CALDERA_JWT_SECRET || "caldera-dashboard-secret-key-2024";

// Create auth token
const token = jwt.sign(
  { username: "admin", role: "admin", loginTime: Date.now() },
  JWT_SECRET,
  { expiresIn: "2h" }
);

const COOKIE = `caldera_session=${token}`;

async function callTrpc(path, input = {}, timeout = 120000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  
  try {
    const resp = await fetch(`${BASE_URL}/api/trpc/${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: COOKIE,
      },
      body: JSON.stringify({ json: input }),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`HTTP ${resp.status}: ${text.slice(0, 500)}`);
    }

    const data = await resp.json();
    return data.result?.data?.json || data.result?.data || data;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

// ========== OPERATION 1: GitHub TTP Ingestion ==========
async function runIngestion() {
  console.log("\n" + "=".repeat(60));
  console.log("OPERATION 1: GitHub TTP Knowledge Base Ingestion");
  console.log("=".repeat(60));
  console.log("Sources: ATT&CK STIX, Atomic Red Team, LOLBAS, Metasploit, Kali");
  
  const start = Date.now();
  try {
    const result = await callTrpc("ttpEngine.ingest", {}, 300000); // 5 min timeout
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    
    console.log(`\n✅ Ingestion Complete (${elapsed}s)`);
    console.log(`   Techniques Ingested: ${result.totalTechniquesIngested || "N/A"}`);
    
    if (result.attackStats) {
      console.log(`   ATT&CK: ${result.attackStats.techniques} techniques, ${result.attackStats.groups} groups, ${result.attackStats.software} software`);
    }
    if (result.atomicStats) {
      console.log(`   Atomic Red Team: ${result.atomicStats.techniquesWithTests} techniques with tests`);
    }
    if (result.lolbasStats) {
      console.log(`   LOLBAS: ${result.lolbasStats.totalLolbins} LOLBin entries`);
    }
    if (result.metasploitStats) {
      console.log(`   Metasploit: ${result.metasploitStats.total} modules`);
    }
    if (result.kaliStats) {
      console.log(`   Kali: ${result.kaliStats.tools} tools in ${result.kaliStats.categories} categories`);
    }
    if (result.errors?.length > 0) {
      console.log(`   ⚠️  ${result.errors.length} non-critical errors`);
    }
    
    return result;
  } catch (err) {
    console.error(`\n❌ Ingestion Failed (${((Date.now() - start) / 1000).toFixed(1)}s): ${err.message}`);
    return null;
  }
}

// ========== OPERATION 2: Caldera Adversary Sync ==========
async function runCalderaSync() {
  console.log("\n" + "=".repeat(60));
  console.log("OPERATION 2: Caldera Adversary Sync");
  console.log("=".repeat(60));
  console.log("Syncing adversaries from Caldera into threat actor database...");
  
  const start = Date.now();
  try {
    const result = await callTrpc("threatActorDb.syncCaldera", {}, 120000);
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    
    console.log(`\n✅ Caldera Sync Complete (${elapsed}s)`);
    console.log(`   Total Caldera Adversaries: ${result.totalCalderaAdversaries || "N/A"}`);
    console.log(`   New Actors Created: ${result.created || 0}`);
    console.log(`   Existing Actors Updated: ${result.updated || 0}`);
    console.log(`   Skipped (already synced): ${result.skipped || 0}`);
    if (result.errors?.length > 0) {
      console.log(`   ⚠️  ${result.errors.length} errors`);
      result.errors.slice(0, 5).forEach(e => console.log(`      - ${e}`));
    }
    
    return result;
  } catch (err) {
    console.error(`\n❌ Caldera Sync Failed (${((Date.now() - start) / 1000).toFixed(1)}s): ${err.message}`);
    return null;
  }
}

// ========== OPERATION 3: Domain Intel Scan ==========
async function runDomainIntelScan() {
  console.log("\n" + "=".repeat(60));
  console.log("OPERATION 3: Domain Intel Scan - AceofCloud.com");
  console.log("=".repeat(60));
  console.log("Running full 4-stage pipeline with threat actor matching...");
  
  const start = Date.now();
  try {
    // Start the scan
    const scanResult = await callTrpc("domainIntel.startScan", {
      primaryDomain: "aceofcloud.com",
      clientType: "enterprise",
      sector: "Cloud & Cybersecurity Services",
      customerName: "AceofCloud",
      criticalFunctions: ["Cloud Infrastructure", "Cybersecurity Consulting", "Red Team Operations", "Managed Security"],
      complianceFlags: ["SOC2", "NIST"],
      notes: "Full end-to-end pipeline test with threat actor matching"
    }, 300000);
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    
    console.log(`\n✅ Domain Intel Scan Complete (${elapsed}s)`);
    console.log(`   Scan ID: ${scanResult.scanId || "N/A"}`);
    console.log(`   Domain: aceofcloud.com`);
    
    if (scanResult.stages) {
      console.log(`\n   Pipeline Stages:`);
      for (const [stage, data] of Object.entries(scanResult.stages)) {
        const status = data?.status || data?.completed ? "✅" : "⏳";
        console.log(`   ${status} ${stage}`);
      }
    }
    
    if (scanResult.threatActorMatches) {
      console.log(`\n   Threat Actor Matches: ${scanResult.threatActorMatches.length || 0}`);
      if (Array.isArray(scanResult.threatActorMatches)) {
        scanResult.threatActorMatches.slice(0, 10).forEach(m => {
          console.log(`   - ${m.name || m.actorName} (Score: ${m.score || m.matchScore || "N/A"})`);
        });
      }
    }
    
    if (scanResult.campaignRecommendations) {
      console.log(`\n   Campaign Recommendations: ${scanResult.campaignRecommendations.length || 0}`);
    }
    
    return scanResult;
  } catch (err) {
    console.error(`\n❌ Domain Intel Scan Failed (${((Date.now() - start) / 1000).toFixed(1)}s): ${err.message}`);
    return null;
  }
}

// ========== MAIN ==========
async function main() {
  console.log("╔══════════════════════════════════════════════════════════╗");
  console.log("║     Cyber Campaign Command - Operations Runner          ║");
  console.log("╚══════════════════════════════════════════════════════════╝");
  
  const overallStart = Date.now();
  
  // Run operations sequentially
  const ingestionResult = await runIngestion();
  const syncResult = await runCalderaSync();
  const scanResult = await runDomainIntelScan();
  
  const totalElapsed = ((Date.now() - overallStart) / 1000).toFixed(1);
  
  console.log("\n" + "=".repeat(60));
  console.log(`ALL OPERATIONS COMPLETE (${totalElapsed}s total)`);
  console.log("=".repeat(60));
  console.log(`  1. TTP Ingestion: ${ingestionResult ? "✅ Success" : "❌ Failed"}`);
  console.log(`  2. Caldera Sync:  ${syncResult ? "✅ Success" : "❌ Failed"}`);
  console.log(`  3. Domain Intel:  ${scanResult ? "✅ Success" : "❌ Failed"}`);
}

main().catch(console.error);
