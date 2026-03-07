/**
 * Full Pipeline Integration Test
 * Tests passive recon → active scan → LLM analysis → exploit generation
 * against training targets (testphp.vulnweb.com, demo.testfire.net, demo.owasp-juice.shop)
 */
import jwt from "jsonwebtoken";

const BASE = "http://localhost:3000/api/trpc";
const JWT_SECRET = "caldera-dashboard-secret-key-2024";
const ENGAGEMENT_ID = 1350014;

const token = jwt.sign(
  { username: "admin", role: "admin", loginTime: Date.now() },
  JWT_SECRET,
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

async function getState() {
  return query("engagementOps.getState", { engagementId: ENGAGEMENT_ID });
}

function printAssets(state) {
  for (const asset of (state?.assets || [])) {
    const ports = asset.ports?.length || 0;
    const vulns = asset.vulns?.length || 0;
    const techs = asset.passiveRecon?.technologies?.length || 0;
    const services = asset.passiveRecon?.services?.length || 0;
    const signals = asset.passiveRecon?.riskSignals?.length || 0;
    console.log(`  ${asset.hostname}: ${ports} ports, ${vulns} vulns, ${techs} techs, ${services} services, ${signals} signals, status=${asset.status}`);
    if (vulns > 0) {
      for (const v of asset.vulns.slice(0, 10)) {
        console.log(`    [${v.severity}] ${v.title}${v.cve ? ` (${v.cve})` : ''}`);
      }
      if (vulns > 10) console.log(`    ... and ${vulns - 10} more`);
    }
  }
}

async function waitForCompletion(maxWaitMs = 600000) {
  const start = Date.now();
  let lastPhase = '';
  while (Date.now() - start < maxWaitMs) {
    await sleep(15000);
    const state = await getState();
    const elapsed = Math.round((Date.now() - start) / 1000);
    
    if (state?.phase !== lastPhase) {
      console.log(`\n[${elapsed}s] Phase changed: ${lastPhase || 'start'} → ${state?.phase}`);
      lastPhase = state?.phase;
    }
    
    const totalPorts = (state?.assets || []).reduce((s, a) => s + (a.ports?.length || 0), 0);
    const totalVulns = (state?.assets || []).reduce((s, a) => s + (a.vulns?.length || 0), 0);
    console.log(`[${elapsed}s] Phase: ${state?.phase}, Running: ${state?.isRunning}, Assets: ${state?.assets?.length || 0}, Ports: ${totalPorts}, Vulns: ${totalVulns}`);
    
    // Print recent logs
    const recentLogs = (state?.log || []).slice(-3);
    for (const log of recentLogs) {
      console.log(`  [${log.type}] ${log.title}`);
    }
    
    if (!state?.isRunning) {
      return state;
    }
  }
  console.log('⚠ Timeout waiting for pipeline completion');
  return getState();
}

async function main() {
  console.log("=== Full Pipeline Integration Test ===\n");
  console.log("Training targets: testphp.vulnweb.com, demo.testfire.net, demo.owasp-juice.shop\n");

  // 1. Trigger full pipeline with all phases
  console.log("1. Triggering FULL pipeline (passive + active + LLM + exploits)...");
  try {
    const result = await mutate("engagementOps.rerunFullPipeline", {
      engagementId: ENGAGEMENT_ID,
      phases: { passive: true, active: true, llmAnalysis: true, exploitGeneration: true },
      resetState: true,
    });
    console.log(`   ✓ ${result.message}`);
  } catch (e) {
    console.log(`   ✗ ${e.message}`);
    return;
  }

  // 2. Wait for completion
  console.log("\n2. Monitoring pipeline progress...");
  const finalState = await waitForCompletion(600000); // 10 min max

  // 3. Print final results
  console.log("\n\n=== FINAL RESULTS ===\n");
  console.log(`Phase: ${finalState?.phase}`);
  console.log(`Assets: ${finalState?.assets?.length || 0}`);
  printAssets(finalState);

  const totalPorts = (finalState?.assets || []).reduce((s, a) => s + (a.ports?.length || 0), 0);
  const totalVulns = (finalState?.assets || []).reduce((s, a) => s + (a.vulns?.length || 0), 0);
  console.log(`\nTotal ports: ${totalPorts}`);
  console.log(`Total vulns: ${totalVulns}`);

  // 4. Check generated exploits
  console.log("\n=== GENERATED EXPLOITS ===");
  try {
    const exploits = await query("engagementOps.getGeneratedExploits", { engagementId: ENGAGEMENT_ID });
    console.log(`Total exploits: ${exploits?.exploits?.length || 0}`);
    for (const ex of (exploits?.exploits || [])) {
      console.log(`  ${ex.filename} [${ex.language}] → ${ex.targetAsset} (${ex.confidence}% confidence)`);
      console.log(`    ${ex.description?.slice(0, 200)}`);
    }
  } catch (e) {
    console.log(`  ✗ ${e.message}`);
  }

  // 5. Accuracy assessment for training targets
  console.log("\n=== ACCURACY ASSESSMENT ===");
  const trainingTargets = {
    'testphp.vulnweb.com': ['SQL Injection', 'XSS', 'File Inclusion', 'CRLF Injection', 'Directory Traversal'],
    'demo.testfire.net': ['SQL Injection', 'XSS', 'Authentication Bypass', 'Information Disclosure'],
    'demo.owasp-juice.shop': ['SQL Injection', 'XSS', 'Broken Authentication', 'Sensitive Data Exposure'],
  };

  for (const [target, expectedVulns] of Object.entries(trainingTargets)) {
    const asset = (finalState?.assets || []).find(a => a.hostname === target);
    if (!asset) {
      console.log(`\n${target}: NOT FOUND in assets`);
      continue;
    }
    console.log(`\n${target}:`);
    console.log(`  Ports: ${asset.ports?.length || 0}`);
    console.log(`  Vulns: ${asset.vulns?.length || 0}`);
    console.log(`  Technologies: ${asset.passiveRecon?.technologies?.join(', ') || 'none'}`);
    console.log(`  Risk Signals: ${asset.passiveRecon?.riskSignals?.length || 0}`);
    
    // Check which expected vulns were found
    const foundVulnTitles = (asset.vulns || []).map(v => v.title.toLowerCase());
    const allSignals = (asset.passiveRecon?.riskSignals || []).map(s => s.rationale.toLowerCase());
    const allText = [...foundVulnTitles, ...allSignals].join(' ');
    
    let found = 0;
    for (const expected of expectedVulns) {
      const keywords = expected.toLowerCase().split(' ');
      const isFound = keywords.some(kw => allText.includes(kw));
      console.log(`  ${isFound ? '✓' : '✗'} ${expected}`);
      if (isFound) found++;
    }
    console.log(`  Coverage: ${found}/${expectedVulns.length} (${Math.round(found/expectedVulns.length*100)}%)`);
  }

  // 6. Print all logs
  console.log("\n=== FULL LOG ===");
  for (const log of (finalState?.log || []).slice(-30)) {
    console.log(`[${log.type}] ${log.title}: ${(log.detail || '').slice(0, 200)}`);
  }
}

main().catch(console.error);
