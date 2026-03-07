/**
 * Full Pipeline Test against testphp.vulnweb.com
 * 
 * This intentionally vulnerable site has known vulns:
 * - SQL Injection (login page, search, artist pages)
 * - Cross-Site Scripting (XSS) (search, guestbook, comments)
 * - File Inclusion (LFI/RFI)
 * - CRLF Injection
 * - Directory Traversal
 * - Server-Side Request Forgery (SSRF)
 * - XML External Entity (XXE)
 * - Weak authentication
 * - Information disclosure
 * - Insecure direct object references
 * 
 * We test: passive scan → active scan → LLM analysis → exploit generation
 */
import jwt from "jsonwebtoken";

const BASE = "http://localhost:3000/api/trpc";
const token = jwt.sign(
  { username: "admin", role: "admin", loginTime: Date.now() },
  "caldera-dashboard-secret-key-2024",
  { expiresIn: "2h" }
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

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// Known vulns in testphp.vulnweb.com that we expect to find
const EXPECTED_VULNS = [
  "SQL Injection",
  "Cross-Site Scripting",
  "Directory Traversal",
  "Information Disclosure",
  "Weak Authentication",
  "Server Misconfiguration",
];

const ENGAGEMENT_ID = 1350014; // Vianova engagement (has testphp.vulnweb.com as target)

async function main() {
  console.log("=== Full Pipeline Test: testphp.vulnweb.com ===\n");
  
  // ─── Step 1: Check infrastructure ───
  console.log("1. Checking infrastructure...");
  try {
    const health = await query("scanServer.health");
    console.log(`   Scan server: ${health.status} (${health.host})`);
  } catch (e) {
    console.log(`   ✗ Scan server: ${e.message}`);
  }
  
  // Test LLM
  try {
    const llmTest = await mutate("engagementOps.runVulnAnalysis", { engagementId: ENGAGEMENT_ID });
    console.log(`   LLM: connected (analysis result: ${JSON.stringify(llmTest).substring(0, 100)})`);
  } catch (e) {
    // "No vulnerabilities" is OK - means LLM is reachable
    if (e.message.includes("No vulnerabilities")) {
      console.log("   LLM: connected (no vulns to analyze yet - expected)");
    } else {
      console.log(`   ✗ LLM: ${e.message.substring(0, 200)}`);
    }
  }
  
  // ─── Step 2: Get current engagement state ───
  console.log("\n2. Getting engagement state...");
  let state;
  try {
    state = await query("engagementOps.getState", { engagementId: ENGAGEMENT_ID });
    console.log(`   Phase: ${state.phase}, Running: ${state.running}`);
    console.log(`   Assets: ${state.assets?.length || 0}`);
    const vulnwebAsset = state.assets?.find(a => a.hostname?.includes("testphp.vulnweb.com"));
    if (vulnwebAsset) {
      console.log(`   testphp.vulnweb.com: ${vulnwebAsset.ports?.length || 0} ports, ${vulnwebAsset.vulns?.length || 0} vulns`);
    } else {
      console.log("   ⚠ testphp.vulnweb.com not found in assets");
    }
    const totalVulns = state.assets?.reduce((sum, a) => sum + (a.vulns?.length || 0), 0) || 0;
    console.log(`   Total vulns across all assets: ${totalVulns}`);
    console.log(`   Stats: vulnsFound=${state.stats?.vulnsFound || 0}, exploitsAttempted=${state.stats?.exploitsAttempted || 0}`);
  } catch (e) {
    console.log(`   ✗ ${e.message.substring(0, 200)}`);
  }
  
  // ─── Step 3: Start passive scan if not running ───
  console.log("\n3. Starting passive scan...");
  try {
    if (state?.running) {
      console.log("   Scan already running, waiting for data...");
    } else {
      const passiveResult = await mutate("engagementOps.startPassiveScan", { engagementId: ENGAGEMENT_ID });
      console.log(`   ✓ Passive scan started: ${JSON.stringify(passiveResult).substring(0, 100)}`);
    }
  } catch (e) {
    console.log(`   ${e.message.includes("already running") ? "⚠ Already running" : "✗ " + e.message.substring(0, 200)}`);
  }
  
  // Wait for passive scan to gather data
  console.log("   Waiting 45s for passive scan data...");
  await sleep(45000);
  
  // ─── Step 4: Check passive scan results ───
  console.log("\n4. Checking passive scan results...");
  try {
    state = await query("engagementOps.getState", { engagementId: ENGAGEMENT_ID });
    const vulnwebAsset = state.assets?.find(a => a.hostname?.includes("testphp.vulnweb.com"));
    if (vulnwebAsset) {
      console.log(`   testphp.vulnweb.com:`);
      console.log(`     Ports: ${vulnwebAsset.ports?.length || 0}`);
      console.log(`     Vulns: ${vulnwebAsset.vulns?.length || 0}`);
      console.log(`     Technologies: ${vulnwebAsset.technologies?.length || 0}`);
      if (vulnwebAsset.ports?.length > 0) {
        console.log(`     Port details: ${vulnwebAsset.ports.map(p => `${p.port}/${p.service}`).join(", ")}`);
      }
      if (vulnwebAsset.vulns?.length > 0) {
        console.log(`     Vuln details:`);
        vulnwebAsset.vulns.forEach(v => {
          console.log(`       - [${v.severity || v.risk}] ${v.title || v.name}: ${(v.description || '').substring(0, 100)}`);
        });
      }
      if (vulnwebAsset.technologies?.length > 0) {
        console.log(`     Technologies: ${vulnwebAsset.technologies.map(t => t.name || t).join(", ")}`);
      }
    }
    // Check all assets
    const totalVulns = state.assets?.reduce((sum, a) => sum + (a.vulns?.length || 0), 0) || 0;
    const totalPorts = state.assets?.reduce((sum, a) => sum + (a.ports?.length || 0), 0) || 0;
    console.log(`   Total across all assets: ${totalPorts} ports, ${totalVulns} vulns`);
    console.log(`   Logs: ${state.logs?.length || 0} entries`);
  } catch (e) {
    console.log(`   ✗ ${e.message.substring(0, 200)}`);
  }
  
  // ─── Step 5: Start active scan ───
  console.log("\n5. Starting active scan...");
  try {
    const activeResult = await mutate("engagementOps.startActiveScan", { engagementId: ENGAGEMENT_ID });
    console.log(`   ✓ Active scan started: ${JSON.stringify(activeResult).substring(0, 100)}`);
  } catch (e) {
    console.log(`   ${e.message.includes("already running") ? "⚠ Already running" : "✗ " + e.message.substring(0, 200)}`);
  }
  
  // Wait for active scan
  console.log("   Waiting 90s for active scan results...");
  await sleep(90000);
  
  // ─── Step 6: Check active scan results ───
  console.log("\n6. Checking active scan results...");
  try {
    state = await query("engagementOps.getState", { engagementId: ENGAGEMENT_ID });
    const vulnwebAsset = state.assets?.find(a => a.hostname?.includes("testphp.vulnweb.com"));
    if (vulnwebAsset) {
      console.log(`   testphp.vulnweb.com after active scan:`);
      console.log(`     Ports: ${vulnwebAsset.ports?.length || 0}`);
      console.log(`     Vulns: ${vulnwebAsset.vulns?.length || 0}`);
      if (vulnwebAsset.vulns?.length > 0) {
        console.log(`     Vulnerability details:`);
        vulnwebAsset.vulns.forEach(v => {
          console.log(`       - [${v.severity || v.risk || 'unknown'}] ${v.title || v.name}`);
        });
      }
    }
    const totalVulns = state.assets?.reduce((sum, a) => sum + (a.vulns?.length || 0), 0) || 0;
    console.log(`   Total vulns: ${totalVulns}`);
    console.log(`   Stats: vulnsFound=${state.stats?.vulnsFound || 0}, scansRun=${state.stats?.hostsScanned || 0}`);
  } catch (e) {
    console.log(`   ✗ ${e.message.substring(0, 200)}`);
  }
  
  // ─── Step 7: Run LLM vulnerability analysis ───
  console.log("\n7. Running LLM vulnerability analysis...");
  try {
    const analysis = await mutate("engagementOps.runVulnAnalysis", { engagementId: ENGAGEMENT_ID });
    console.log(`   ✓ LLM analysis complete`);
    if (analysis?.analysisResults) {
      console.log(`   Results: ${analysis.analysisResults.length} vulnerabilities analyzed`);
      analysis.analysisResults.forEach(r => {
        console.log(`     - ${r.vulnTitle || r.title}: severity=${r.severity}, exploitable=${r.exploitable}`);
        if (r.poc) console.log(`       PoC: ${r.poc.substring(0, 100)}...`);
      });
    } else {
      console.log(`   Raw result: ${JSON.stringify(analysis).substring(0, 500)}`);
    }
  } catch (e) {
    console.log(`   ✗ ${e.message.substring(0, 300)}`);
  }
  
  // ─── Step 8: Check LLM feedback loop ───
  console.log("\n8. Checking LLM feedback loop state...");
  try {
    const feedback = await query("engagementOps.getFeedbackLoopState", { engagementId: ENGAGEMENT_ID });
    console.log(`   Feedback loop: ${JSON.stringify(feedback).substring(0, 300)}`);
  } catch (e) {
    console.log(`   ✗ ${e.message.substring(0, 200)}`);
  }
  
  // ─── Step 9: Generate functional exploits ───
  console.log("\n9. Generating functional exploits...");
  try {
    // First get the current state to find vulns
    state = await query("engagementOps.getState", { engagementId: ENGAGEMENT_ID });
    const allVulns = [];
    for (const asset of (state.assets || [])) {
      for (const vuln of (asset.vulns || [])) {
        allVulns.push({ asset: asset.hostname, vuln });
      }
    }
    
    if (allVulns.length > 0) {
      console.log(`   Found ${allVulns.length} vulns to generate exploits for`);
      // Try generating exploit for the first vuln
      const firstVuln = allVulns[0];
      try {
        const exploit = await mutate("engagementOps.generateFunctionalExploit", {
          engagementId: ENGAGEMENT_ID,
          assetHostname: firstVuln.asset,
          vulnTitle: firstVuln.vuln.title || firstVuln.vuln.name,
          language: "python"
        });
        console.log(`   ✓ Exploit generated for ${firstVuln.vuln.title || firstVuln.vuln.name}:`);
        console.log(`     Language: ${exploit.language}`);
        console.log(`     Code preview: ${(exploit.code || exploit.script || '').substring(0, 200)}...`);
        console.log(`     Validation: ${exploit.validation || 'N/A'}`);
      } catch (e) {
        console.log(`   ✗ Exploit generation: ${e.message.substring(0, 200)}`);
      }
    } else {
      console.log("   ⚠ No vulns found yet — cannot generate exploits");
      console.log("   Trying re-run pipeline...");
      try {
        const rerun = await mutate("engagementOps.rerunFullPipeline", { engagementId: ENGAGEMENT_ID });
        console.log(`   Pipeline re-run: ${JSON.stringify(rerun).substring(0, 200)}`);
      } catch (e) {
        console.log(`   ✗ Re-run: ${e.message.substring(0, 200)}`);
      }
    }
  } catch (e) {
    console.log(`   ✗ ${e.message.substring(0, 200)}`);
  }
  
  // ─── Step 10: Check all generated exploits ───
  console.log("\n10. Checking all generated exploits...");
  try {
    const exploits = await query("engagementOps.getGeneratedExploits", { engagementId: ENGAGEMENT_ID });
    console.log(`   Total exploits: ${exploits?.length || 0}`);
    if (exploits?.length > 0) {
      exploits.forEach(e => {
        console.log(`     - ${e.vulnTitle}: ${e.language}, validated=${e.validated}`);
      });
    }
  } catch (e) {
    console.log(`   ✗ ${e.message.substring(0, 200)}`);
  }
  
  // ─── Step 11: Check exploit plan history ───
  console.log("\n11. Checking exploit plan history...");
  try {
    const plans = await query("engagementOps.getExploitPlanHistory", { engagementId: ENGAGEMENT_ID });
    console.log(`   Exploit plans: ${plans?.length || 0}`);
    if (plans?.length > 0) {
      plans.slice(0, 3).forEach(p => {
        console.log(`     - Gate: ${p.gateId}, Status: ${p.status}`);
        if (p.llmReasoning) console.log(`       LLM reasoning: ${p.llmReasoning.substring(0, 150)}...`);
      });
    }
  } catch (e) {
    console.log(`   ✗ ${e.message.substring(0, 200)}`);
  }
  
  // ─── Summary ───
  console.log("\n=== ACCURACY REPORT ===");
  try {
    state = await query("engagementOps.getState", { engagementId: ENGAGEMENT_ID });
    const vulnwebAsset = state.assets?.find(a => a.hostname?.includes("testphp.vulnweb.com"));
    const vulns = vulnwebAsset?.vulns || [];
    const vulnTitles = vulns.map(v => (v.title || v.name || '').toLowerCase());
    
    console.log(`\nDetected vulnerabilities for testphp.vulnweb.com: ${vulns.length}`);
    vulns.forEach(v => {
      console.log(`  [${v.severity || v.risk || '?'}] ${v.title || v.name}`);
    });
    
    console.log(`\nExpected vulnerability categories:`);
    let found = 0;
    for (const expected of EXPECTED_VULNS) {
      const detected = vulnTitles.some(t => t.includes(expected.toLowerCase()));
      console.log(`  ${detected ? '✓' : '✗'} ${expected}`);
      if (detected) found++;
    }
    console.log(`\nAccuracy: ${found}/${EXPECTED_VULNS.length} (${Math.round(found/EXPECTED_VULNS.length*100)}%)`);
    
    const totalVulns = state.assets?.reduce((sum, a) => sum + (a.vulns?.length || 0), 0) || 0;
    console.log(`Total vulns across all assets: ${totalVulns}`);
    console.log(`Stats: vulnsFound=${state.stats?.vulnsFound || 0}, exploitsAttempted=${state.stats?.exploitsAttempted || 0}, exploitsSucceeded=${state.stats?.exploitsSucceeded || 0}`);
  } catch (e) {
    console.log(`Error: ${e.message}`);
  }
  
  console.log("\n=== Pipeline Test Complete ===");
}

main().catch(console.error);
