/**
 * Quick LLM Synthesis Test
 * Tests passive recon → LLM vuln synthesis (skips active scanning to save time)
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

async function main() {
  console.log("=== LLM Vuln Synthesis Test (Passive Only) ===\n");

  // Trigger pipeline with ONLY passive + LLM analysis + exploit gen (skip active)
  console.log("1. Triggering pipeline (passive + llmAnalysis + exploitGeneration, NO active)...");
  try {
    const result = await mutate("engagementOps.rerunFullPipeline", {
      engagementId: ENGAGEMENT_ID,
      phases: { passive: true, active: false, llmAnalysis: true, exploitGeneration: true },
      resetState: true,
    });
    console.log(`   ✓ ${result.message}`);
  } catch (e) {
    console.log(`   ✗ ${e.message}`);
    return;
  }

  // Wait for completion (should be faster without active scanning)
  console.log("\n2. Monitoring pipeline progress...");
  const start = Date.now();
  let lastPhase = '';
  while (Date.now() - start < 600000) {
    await sleep(10000);
    const state = await getState();
    const elapsed = Math.round((Date.now() - start) / 1000);
    
    if (state?.phase !== lastPhase) {
      console.log(`\n[${elapsed}s] Phase changed: ${lastPhase || 'start'} → ${state?.phase}`);
      lastPhase = state?.phase;
    }
    
    const totalPorts = (state?.assets || []).reduce((s, a) => s + (a.ports?.length || 0), 0);
    const totalVulns = (state?.assets || []).reduce((s, a) => s + (a.vulns?.length || 0), 0);
    console.log(`[${elapsed}s] Phase: ${state?.phase}, Running: ${state?.isRunning}, Assets: ${state?.assets?.length || 0}, Ports: ${totalPorts}, Vulns: ${totalVulns}`);
    
    const recentLogs = (state?.log || []).slice(-3);
    for (const log of recentLogs) {
      console.log(`  [${log.type}] ${log.title}`);
    }
    
    if (!state?.isRunning) {
      // Print final results
      console.log("\n\n=== FINAL RESULTS ===\n");
      console.log(`Phase: ${state?.phase}`);
      for (const asset of (state?.assets || [])) {
        const ports = asset.ports?.length || 0;
        const vulns = asset.vulns?.length || 0;
        const signals = asset.passiveRecon?.riskSignals?.length || 0;
        console.log(`\n${asset.hostname}: ${ports} ports, ${vulns} vulns, ${signals} signals`);
        if (vulns > 0) {
          for (const v of asset.vulns) {
            console.log(`  [${v.severity}] ${v.title}${v.cve ? ` (${v.cve})` : ''} [${v.tool}] conf=${v.confidence || 'N/A'}`);
          }
        }
      }
      
      const totalVulns2 = (state?.assets || []).reduce((s, a) => s + (a.vulns?.length || 0), 0);
      console.log(`\nTotal vulns: ${totalVulns2}`);
      
      // Check exploits
      try {
        const exploits = await query("engagementOps.getGeneratedExploits", { engagementId: ENGAGEMENT_ID });
        console.log(`Total exploits: ${exploits?.exploits?.length || 0}`);
        for (const ex of (exploits?.exploits || []).slice(0, 10)) {
          console.log(`  ${ex.filename} [${ex.language}] → ${ex.targetAsset} (${ex.confidence}% confidence)`);
        }
      } catch (e) {
        console.log(`  Exploits: ${e.message}`);
      }
      
      // Accuracy
      console.log("\n=== ACCURACY ===");
      const targets = {
        'testphp.vulnweb.com': ['SQL Injection', 'XSS', 'File Inclusion', 'CRLF Injection', 'Directory Traversal'],
        'demo.testfire.net': ['SQL Injection', 'XSS', 'Authentication Bypass', 'Information Disclosure'],
        'demo.owasp-juice.shop': ['SQL Injection', 'XSS', 'Broken Authentication', 'Sensitive Data Exposure'],
      };
      for (const [target, expected] of Object.entries(targets)) {
        const asset = (state?.assets || []).find(a => a.hostname === target);
        if (!asset) { console.log(`${target}: NOT FOUND`); continue; }
        const allText = [
          ...(asset.vulns || []).map(v => v.title.toLowerCase() + ' ' + (v.description || '').toLowerCase()),
          ...(asset.passiveRecon?.riskSignals || []).map(s => (s.rationale || '').toLowerCase()),
        ].join(' ');
        let found = 0;
        for (const exp of expected) {
          const kws = exp.toLowerCase().split(' ');
          const isFound = kws.some(kw => allText.includes(kw));
          console.log(`  ${isFound ? '✓' : '✗'} ${exp}`);
          if (isFound) found++;
        }
        console.log(`  ${target}: ${found}/${expected.length} (${Math.round(found/expected.length*100)}%)`);
      }
      
      return;
    }
  }
  console.log('⚠ Timeout');
}

main().catch(console.error);
