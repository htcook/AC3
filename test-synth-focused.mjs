/**
 * Focused LLM Synthesis Test - Only 3 training targets
 * Runs passive recon + LLM synthesis + exploit generation
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
  console.log("=== Focused LLM Vuln Synthesis Test ===\n");

  // Trigger pipeline
  console.log("1. Triggering pipeline (passive + llmAnalysis + exploitGeneration)...");
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

  // Wait for completion
  console.log("\n2. Monitoring pipeline...");
  const start = Date.now();
  let lastPhase = '';
  let lastVulns = 0;
  while (Date.now() - start < 900000) { // 15 min timeout
    await sleep(15000);
    const state = await getState();
    const elapsed = Math.round((Date.now() - start) / 1000);
    
    const totalVulns = (state?.assets || []).reduce((s, a) => s + (a.vulns?.length || 0), 0);
    
    if (state?.phase !== lastPhase || totalVulns !== lastVulns) {
      console.log(`[${elapsed}s] Phase: ${state?.phase}, Assets: ${state?.assets?.length || 0}, Vulns: ${totalVulns}, Running: ${state?.isRunning}`);
      lastPhase = state?.phase;
      lastVulns = totalVulns;
      
      // Show latest logs
      const recentLogs = (state?.log || []).slice(-3);
      for (const log of recentLogs) {
        console.log(`  [${log.type}] ${log.title}${log.detail ? ': ' + log.detail.slice(0, 80) : ''}`);
      }
    }
    
    if (!state?.isRunning) {
      // Print final results
      console.log("\n\n========================================");
      console.log("         FINAL RESULTS");
      console.log("========================================\n");
      
      const trainingTargets = ['testphp.vulnweb.com', 'demo.testfire.net', 'demo.owasp-juice.shop'];
      
      for (const asset of (state?.assets || [])) {
        const isTraining = trainingTargets.includes(asset.hostname);
        const ports = asset.ports?.length || 0;
        const vulns = asset.vulns?.length || 0;
        const signals = asset.passiveRecon?.riskSignals?.length || 0;
        console.log(`\n${isTraining ? '🎯' : '  '} ${asset.hostname}: ${ports} ports, ${vulns} vulns, ${signals} signals`);
        if (vulns > 0) {
          for (const v of asset.vulns) {
            console.log(`    [${v.severity}] ${v.title}${v.cve ? ` (${v.cve})` : ''} [${v.tool}] conf=${v.confidence || 'N/A'}`);
          }
        }
      }
      
      // Check exploits
      console.log("\n\n========================================");
      console.log("         GENERATED EXPLOITS");
      console.log("========================================\n");
      try {
        const exploits = await query("engagementOps.getGeneratedExploits", { engagementId: ENGAGEMENT_ID });
        console.log(`Total exploits: ${exploits?.length || 0}`);
        for (const ex of (exploits || []).slice(0, 15)) {
          console.log(`  ${ex.filename} [${ex.language}] → ${ex.asset} (${ex.confidence}% confidence)`);
        }
      } catch (e) {
        console.log(`  Error: ${e.message}`);
      }
      
      // Accuracy assessment
      console.log("\n\n========================================");
      console.log("         ACCURACY ASSESSMENT");
      console.log("========================================\n");
      const targets = {
        'testphp.vulnweb.com': {
          expected: ['SQL Injection', 'XSS', 'File Inclusion', 'CRLF Injection', 'Directory Traversal'],
          keywords: {
            'SQL Injection': ['sql injection', 'sqli', 'sql'],
            'XSS': ['xss', 'cross-site scripting', 'cross site scripting'],
            'File Inclusion': ['file inclusion', 'lfi', 'rfi', 'local file', 'remote file'],
            'CRLF Injection': ['crlf', 'header injection', 'http response splitting'],
            'Directory Traversal': ['directory traversal', 'path traversal', 'directory listing', 'dir traversal'],
          }
        },
        'demo.testfire.net': {
          expected: ['SQL Injection', 'XSS', 'Authentication Bypass', 'Information Disclosure'],
          keywords: {
            'SQL Injection': ['sql injection', 'sqli', 'sql'],
            'XSS': ['xss', 'cross-site scripting', 'cross site scripting'],
            'Authentication Bypass': ['authentication', 'auth bypass', 'broken auth', 'login bypass', 'credential', 'session'],
            'Information Disclosure': ['information disclosure', 'info disclosure', 'data exposure', 'sensitive data', 'data leak'],
          }
        },
        'demo.owasp-juice.shop': {
          expected: ['SQL Injection', 'XSS', 'Broken Authentication', 'Sensitive Data Exposure'],
          keywords: {
            'SQL Injection': ['sql injection', 'sqli', 'sql', 'nosql'],
            'XSS': ['xss', 'cross-site scripting', 'cross site scripting'],
            'Broken Authentication': ['authentication', 'auth', 'broken auth', 'login', 'credential', 'session', 'password'],
            'Sensitive Data Exposure': ['sensitive data', 'data exposure', 'data leak', 'information disclosure', 'pii', 'credential'],
          }
        },
      };
      
      let totalExpected = 0;
      let totalFound = 0;
      
      for (const [target, config] of Object.entries(targets)) {
        const asset = (state?.assets || []).find(a => a.hostname === target);
        if (!asset) { console.log(`${target}: NOT FOUND`); continue; }
        
        // Search in vulns AND risk signals
        const allText = [
          ...(asset.vulns || []).map(v => (v.title + ' ' + (v.description || '') + ' ' + (v.category || '')).toLowerCase()),
          ...(asset.passiveRecon?.riskSignals || []).map(s => ((s.rationale || '') + ' ' + (s.title || '')).toLowerCase()),
        ].join(' | ');
        
        let found = 0;
        console.log(`\n${target}:`);
        for (const exp of config.expected) {
          const kws = config.keywords[exp];
          const isFound = kws.some(kw => allText.includes(kw));
          console.log(`  ${isFound ? '✅' : '❌'} ${exp}${isFound ? '' : ' (keywords: ' + kws.join(', ') + ')'}`);
          if (isFound) found++;
        }
        console.log(`  Score: ${found}/${config.expected.length} (${Math.round(found/config.expected.length*100)}%)`);
        totalExpected += config.expected.length;
        totalFound += found;
      }
      
      console.log(`\n========================================`);
      console.log(`OVERALL ACCURACY: ${totalFound}/${totalExpected} (${Math.round(totalFound/totalExpected*100)}%)`);
      console.log(`========================================`);
      
      // Print all logs
      console.log("\n\n=== FULL LOG ===");
      for (const log of (state?.log || [])) {
        console.log(`[${log.type}] ${log.title}${log.detail ? ': ' + log.detail.slice(0, 100) : ''}`);
      }
      
      return;
    }
  }
  console.log('⚠ Timeout');
}

main().catch(console.error);
