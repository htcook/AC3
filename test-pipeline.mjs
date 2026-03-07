/**
 * Pipeline Integration Test Script
 * Tests the full LLM + scanner pipeline against the Vianova engagement
 */
import jwt from "jsonwebtoken";

const BASE = "http://localhost:3000/api/trpc";
const JWT_SECRET = process.env.CALDERA_JWT_SECRET || "caldera-dashboard-secret-key-2024";
const ENGAGEMENT_ID = 1350014;

const token = jwt.sign(
  { username: "admin", role: "admin", loginTime: Date.now() },
  JWT_SECRET,
  { expiresIn: "1h" }
);

const headers = {
  "Content-Type": "application/json",
  Cookie: `caldera_session=${token}`,
};

async function query(procedure, input) {
  const url = input
    ? `${BASE}/${procedure}?input=${encodeURIComponent(JSON.stringify({ json: input }))}`
    : `${BASE}/${procedure}`;
  const res = await fetch(url, { headers });
  const data = await res.json();
  if (data.error) throw new Error(`${procedure}: ${data.error.json?.message || JSON.stringify(data.error)}`);
  return data.result?.data?.json ?? data.result?.data;
}

async function mutate(procedure, input) {
  const res = await fetch(`${BASE}/${procedure}`, {
    method: "POST",
    headers,
    body: JSON.stringify({ json: input }),
  });
  const data = await res.json();
  if (data.error) throw new Error(`${procedure}: ${data.error.json?.message || JSON.stringify(data.error)}`);
  return data.result?.data?.json ?? data.result?.data;
}

function trunc(obj, len = 300) {
  const s = typeof obj === "string" ? obj : JSON.stringify(obj);
  return s?.length > len ? s.slice(0, len) + "..." : s;
}

async function main() {
  console.log("=== Caldera Pipeline Integration Test (Vianova) ===\n");

  // 1. Check scan server health
  console.log("1. Checking scan server health...");
  try {
    const health = await query("scanServer.health");
    console.log(`   ✓ Scan server: ${trunc(health)}`);
  } catch (e) {
    console.log(`   ✗ Scan server: ${trunc(e.message)}`);
  }

  // 2. Get engagement state
  console.log("\n2. Getting engagement state...");
  let state;
  try {
    state = await query("engagementOps.getState", { engagementId: ENGAGEMENT_ID });
    console.log(`   ✓ Phase: ${state?.currentPhase}, Running: ${state?.isRunning}`);
    console.log(`   Assets: ${state?.assets?.length || 0}`);
    const totalVulns = (state?.assets || []).reduce((sum, a) => sum + (a.vulns?.length || 0), 0);
    console.log(`   Total vulns across assets: ${totalVulns}`);
    if (state?.stats) {
      console.log(`   Stats: scansRun=${state.stats.scansRun}, vulnsFound=${state.stats.vulnsFound}, exploitsAttempted=${state.stats.exploitsAttempted}`);
    }
    // Show asset details
    for (const asset of (state?.assets || []).slice(0, 5)) {
      console.log(`   - ${asset.hostname}: ${asset.ports?.length || 0} ports, ${asset.vulns?.length || 0} vulns, ${asset.technologies?.length || 0} techs`);
    }
  } catch (e) {
    console.log(`   ✗ ${trunc(e.message)}`);
  }

  // 3. Test passive scan (Domain Intel)
  console.log("\n3. Starting passive scan (Domain Intel)...");
  try {
    const passiveResult = await mutate("engagementOps.startPassiveScan", {
      engagementId: ENGAGEMENT_ID,
    });
    console.log(`   ✓ Passive scan: ${trunc(passiveResult)}`);
  } catch (e) {
    console.log(`   ✗ Passive scan: ${trunc(e.message)}`);
  }

  // Wait a bit for passive scan to populate some data
  console.log("   Waiting 10s for passive scan data...");
  await new Promise(r => setTimeout(r, 10000));

  // 4. Re-check state after passive scan
  console.log("\n4. Re-checking state after passive scan...");
  try {
    state = await query("engagementOps.getState", { engagementId: ENGAGEMENT_ID });
    const totalVulns = (state?.assets || []).reduce((sum, a) => sum + (a.vulns?.length || 0), 0);
    console.log(`   ✓ Assets: ${state?.assets?.length || 0}, Vulns: ${totalVulns}`);
    for (const asset of (state?.assets || []).slice(0, 5)) {
      console.log(`   - ${asset.hostname}: ${asset.ports?.length || 0} ports, ${asset.vulns?.length || 0} vulns`);
    }
  } catch (e) {
    console.log(`   ✗ ${trunc(e.message)}`);
  }

  // 5. Test LLM vulnerability analysis
  console.log("\n5. Running LLM vulnerability analysis...");
  try {
    const analysis = await mutate("engagementOps.runVulnAnalysis", {
      engagementId: ENGAGEMENT_ID,
    });
    console.log(`   ✓ LLM analysis: ${trunc(analysis)}`);
  } catch (e) {
    console.log(`   ✗ LLM analysis: ${trunc(e.message)}`);
  }

  // 6. Test active scan
  console.log("\n6. Starting active scan...");
  try {
    const activeResult = await mutate("engagementOps.startActiveScan", {
      engagementId: ENGAGEMENT_ID,
    });
    console.log(`   ✓ Active scan: ${trunc(activeResult)}`);
  } catch (e) {
    console.log(`   ✗ Active scan: ${trunc(e.message)}`);
  }

  // Wait for active scan
  console.log("   Waiting 15s for active scan data...");
  await new Promise(r => setTimeout(r, 15000));

  // 7. Re-check state after active scan
  console.log("\n7. Re-checking state after active scan...");
  try {
    state = await query("engagementOps.getState", { engagementId: ENGAGEMENT_ID });
    const totalVulns = (state?.assets || []).reduce((sum, a) => sum + (a.vulns?.length || 0), 0);
    console.log(`   ✓ Assets: ${state?.assets?.length || 0}, Vulns: ${totalVulns}`);
    if (state?.stats) {
      console.log(`   Stats: scansRun=${state.stats.scansRun}, vulnsFound=${state.stats.vulnsFound}`);
    }
  } catch (e) {
    console.log(`   ✗ ${trunc(e.message)}`);
  }

  // 8. Test functional exploit generation
  console.log("\n8. Testing functional exploit generation...");
  try {
    state = state || await query("engagementOps.getState", { engagementId: ENGAGEMENT_ID });
    const assetWithVulns = (state?.assets || []).find(a => a.vulns?.length > 0);
    if (assetWithVulns) {
      console.log(`   Target: ${assetWithVulns.hostname} (${assetWithVulns.vulns.length} vulns)`);
      const exploit = await mutate("engagementOps.generateFunctionalExploit", {
        engagementId: ENGAGEMENT_ID,
        targetAsset: assetWithVulns.hostname,
        language: "python",
        includeEvasion: false,
      });
      console.log(`   ✓ Exploit generated: ${exploit?.filename} (confidence: ${exploit?.confidence}%)`);
      console.log(`   Description: ${trunc(exploit?.description, 200)}`);
      console.log(`   Code preview:\n${exploit?.code?.slice(0, 400)}`);

      // 9. Validate the exploit
      console.log("\n9. Validating generated exploit...");
      const validation = await mutate("engagementOps.validateExploit", {
        engagementId: ENGAGEMENT_ID,
        exploitIndex: 0,
      });
      console.log(`   ✓ Valid: ${validation?.isValid}, Quality: ${validation?.codeQuality}, Would work: ${validation?.wouldWork}`);
      if (validation?.issues?.length > 0) {
        console.log(`   Issues: ${validation.issues.join(", ")}`);
      }
      if (validation?.suggestions?.length > 0) {
        console.log(`   Suggestions: ${validation.suggestions.slice(0, 3).join("; ")}`);
      }
    } else {
      console.log("   ⚠ No assets with vulns yet — triggering full pipeline re-run");
      const rerun = await mutate("engagementOps.rerunFullPipeline", {
        engagementId: ENGAGEMENT_ID,
        phases: { passive: true, active: true, llmAnalysis: true, exploitGeneration: true },
      });
      console.log(`   ✓ Pipeline re-run: ${trunc(rerun)}`);
    }
  } catch (e) {
    console.log(`   ✗ Exploit generation: ${trunc(e.message)}`);
  }

  // 10. Check all generated exploits
  console.log("\n10. Checking all generated exploits...");
  try {
    const exploits = await query("engagementOps.getGeneratedExploits", { engagementId: ENGAGEMENT_ID });
    console.log(`   ✓ Total exploits: ${exploits?.exploits?.length || 0}`);
    for (const ex of (exploits?.exploits || []).slice(0, 5)) {
      console.log(`     - ${ex.filename} [${ex.language}] → ${ex.targetAsset} (${ex.confidence}% confidence)`);
    }
  } catch (e) {
    console.log(`   ✗ Get exploits: ${trunc(e.message)}`);
  }

  // 11. Check exploit plan history
  console.log("\n11. Checking exploit plan history...");
  try {
    const plans = await query("engagementOps.getExploitPlanHistory", { engagementId: ENGAGEMENT_ID });
    console.log(`   ✓ Exploit plans: ${trunc(plans)}`);
  } catch (e) {
    console.log(`   ✗ Exploit plans: ${trunc(e.message)}`);
  }

  // 12. Check feedback loop state
  console.log("\n12. Checking LLM feedback loop state...");
  try {
    const feedback = await query("engagementOps.getFeedbackLoopState", { engagementId: ENGAGEMENT_ID });
    console.log(`   ✓ Feedback loop: ${trunc(feedback)}`);
  } catch (e) {
    console.log(`   ✗ Feedback loop: ${trunc(e.message)}`);
  }

  console.log("\n=== Pipeline Test Complete ===");
}

main().catch(console.error);
