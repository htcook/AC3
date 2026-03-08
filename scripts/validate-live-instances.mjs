/**
 * Live Instance Validation Scanner
 * 
 * Launches deep scans against all 3 self-hosted training instances:
 * 1. OWASP Juice Shop (scan server :3001)
 * 2. DVWA (scan server :3002)
 * 3. Google Gruyere (sandboxed instance)
 * 
 * Monitors pipeline, collects F1 scores, and produces benchmark report.
 */
import jwt from 'jsonwebtoken';
import http from 'http';
import https from 'https';

const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';
const BASE_URL = 'http://localhost:3000';

const token = jwt.sign(
  { username: 'admin', role: 'admin', loginTime: Date.now() },
  CALDERA_JWT_SECRET,
  { expiresIn: '2h' }
);

const COOKIE = `caldera_session=${token}`;

function trpcMutation(path, input) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ json: input });
    const req = http.request(`${BASE_URL}/api/trpc/${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': COOKIE,
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) reject(new Error(`tRPC error: ${JSON.stringify(parsed.error).slice(0, 300)}`));
          else resolve(parsed.result?.data?.json ?? parsed.result?.data);
        } catch (e) {
          reject(new Error(`Parse error: ${data.slice(0, 200)}`));
        }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function trpcQuery(path, input) {
  return new Promise((resolve, reject) => {
    const inputStr = input ? encodeURIComponent(JSON.stringify({ json: input })) : '';
    const url = input ? `${BASE_URL}/api/trpc/${path}?input=${inputStr}` : `${BASE_URL}/api/trpc/${path}`;
    const req = http.request(url, {
      method: 'GET',
      headers: { 'Cookie': COOKIE },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) reject(new Error(`tRPC error: ${JSON.stringify(parsed.error).slice(0, 300)}`));
          else resolve(parsed.result?.data?.json ?? parsed.result?.data);
        } catch (e) {
          reject(new Error(`Parse error: ${data.slice(0, 200)}`));
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// Collect detailed results from a completed session
async function collectSessionResults(sessionId, targetName) {
  const results = {
    name: targetName,
    sessionId,
    status: 'unknown',
    vulnCount: 0,
    assetCount: 0,
    vulns: [],
    findings: [],
    attackChains: [],
    accuracy: null,
    toolResults: [],
    riskScore: null,
  };

  try {
    const session = await trpcQuery('trainingLab.getSession', { sessionId });
    if (session) {
      results.status = session.labStatus || session.status || 'unknown';
      results.vulnCount = session.vulns?.length || 0;
      results.assetCount = session.assets?.length || 0;
      results.vulns = (session.vulns || []).map(v => ({
        title: v.title,
        severity: v.severity,
        tool: v.tool || 'LLM',
      }));
      results.toolResults = session.toolResults || [];
      
      // Extract LLM findings
      if (session.llmAnalysis) {
        results.findings = session.llmAnalysis.findings || [];
        results.attackChains = session.llmAnalysis.attackChains || [];
        results.riskScore = session.llmAnalysis.riskScore || null;
      }
    }
  } catch (e) {
    console.log(`  ⚠️  Error collecting session data: ${e.message}`);
  }

  // Get accuracy score
  try {
    const accuracy = await trpcQuery('trainingLab.sessionAccuracy', { sessionId });
    if (accuracy) {
      results.accuracy = {
        precision: accuracy.precision,
        recall: accuracy.recall,
        f1Score: accuracy.f1Score,
        overallScore: accuracy.overallScore,
        truePositives: accuracy.truePositives,
        falsePositives: accuracy.falsePositives,
        falseNegatives: accuracy.falseNegatives,
        matchedVulns: accuracy.matchedVulns || [],
        missedVulns: accuracy.missedVulns || [],
      };
    }
  } catch (e) {
    console.log(`  ℹ️  Accuracy not available: ${e.message.slice(0, 100)}`);
  }

  return results;
}

async function monitorSession(sessionId, name, maxMinutes = 12) {
  console.log(`\n📡 Monitoring: ${name} (${sessionId})`);
  let lastPhase = '';
  let lastProgress = 0;
  const maxAttempts = (maxMinutes * 60) / 5;
  let attempts = 0;

  while (attempts < maxAttempts) {
    try {
      const session = await trpcQuery('trainingLab.getSession', { sessionId });
      if (!session) {
        await sleep(5000);
        attempts++;
        continue;
      }

      const phase = session.phase || 'unknown';
      const progress = session.progress || 0;
      const status = session.labStatus || session.status || 'unknown';

      if (phase !== lastPhase || Math.abs(progress - lastProgress) >= 5) {
        const toolCount = session.toolResults?.length || 0;
        const vulnCount = session.vulns?.length || 0;
        console.log(`  [${new Date().toLocaleTimeString()}] ${phase} ${progress}% | tools: ${toolCount} | vulns: ${vulnCount} | status: ${status}`);
        lastPhase = phase;
        lastProgress = progress;
      }

      if (status === 'completed' || status === 'done' || status === 'failed' || progress >= 100) {
        console.log(`  ✅ ${name}: ${status === 'failed' ? 'FAILED' : 'COMPLETED'}`);
        return await collectSessionResults(sessionId, name);
      }
    } catch (err) {
      // Silently retry
    }

    await sleep(5000);
    attempts++;
  }

  console.log(`  ⏰ ${name}: Timed out after ${maxMinutes} minutes — collecting partial results`);
  return await collectSessionResults(sessionId, name);
}

async function main() {
  console.log('╔═══════════════════════════════════════════════════════════════════╗');
  console.log('║  🔬 CALDERA Training Lab — Live Instance Validation Suite        ║');
  console.log('║  📅 March 8, 2026 — Self-Hosted Instance Benchmark              ║');
  console.log('╚═══════════════════════════════════════════════════════════════════╝\n');

  // Verify targets
  const targets = await trpcQuery('trainingLab.targets');
  const liveTargets = targets.filter(t => t.liveInstanceUrl);
  console.log(`📋 Total targets: ${targets.length} | Live instances: ${liveTargets.length}`);
  for (const t of liveTargets) {
    console.log(`   🟢 ${t.name} → ${t.liveInstanceUrl}`);
  }

  const scans = [
    { targetId: 'juice-shop', name: 'OWASP Juice Shop (Live)', groundTruth: 10 },
    { targetId: 'dvwa', name: 'DVWA (Live)', groundTruth: 14 },
    { targetId: 'google-gruyere', name: 'Google Gruyere (Sandbox)', groundTruth: 5 },
  ];

  const sessions = [];

  // Launch all 3 scans
  for (const scan of scans) {
    console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    console.log(`  🎯 Launching: ${scan.name}`);
    console.log(`  📋 Ground truth: ${scan.groundTruth} known vulnerabilities`);
    console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);

    try {
      // First acknowledge RoE
      try {
        await trpcMutation('trainingLab.acknowledgeRoE', {
          targetId: scan.targetId,
          operatorName: 'Caldera Validation Suite',
          rulesAccepted: ['All applicable RoE rules acknowledged for automated validation'],
        });
        console.log(`  ✅ RoE acknowledged for ${scan.name}`);
      } catch (e) {
        console.log(`  ℹ️  RoE acknowledgment: ${e.message.slice(0, 100)}`);
      }

      const session = await trpcMutation('trainingLab.startSession', {
        targetId: scan.targetId,
        scanProfile: 'deep',
        name: `${scan.name} - Live Instance Validation (March 8)`,
      });
      console.log(`  ✅ Scan launched: ${session.sessionId}`);
      console.log(`  🌐 Target URL: ${session.targetUrl}`);
      sessions.push({ ...scan, sessionId: session.sessionId });
    } catch (e) {
      console.error(`  ❌ Failed to launch: ${e.message.slice(0, 200)}`);
    }

    // Small delay between launches
    await sleep(3000);
  }

  // Monitor all scans sequentially
  console.log('\n╔═══════════════════════════════════════════════════════════════════╗');
  console.log('║  📡 Monitoring scan pipelines...                                 ║');
  console.log('╚═══════════════════════════════════════════════════════════════════╝');

  const allResults = [];
  for (const s of sessions) {
    const result = await monitorSession(s.sessionId, s.name, 12);
    if (result) {
      result.groundTruthCount = s.groundTruth;
      allResults.push(result);
    }
  }

  // ═══ BENCHMARK REPORT ═══
  console.log('\n\n╔═══════════════════════════════════════════════════════════════════╗');
  console.log('║  📊 LIVE INSTANCE BENCHMARK REPORT                               ║');
  console.log('╚═══════════════════════════════════════════════════════════════════╝\n');

  console.log('┌─────────────────────────┬────────┬───────┬──────────┬──────────┬──────────┬──────────┬────────┐');
  console.log('│ Target                  │ Status │ Vulns │ GT Vulns │ Prec.    │ Recall   │ F1       │ Risk   │');
  console.log('├─────────────────────────┼────────┼───────┼──────────┼──────────┼──────────┼──────────┼────────┤');

  for (const r of allResults) {
    const name = r.name.slice(0, 23).padEnd(23);
    const status = (r.status || '?').slice(0, 6).padEnd(6);
    const vulns = String(r.vulnCount).padEnd(5);
    const gt = String(r.groundTruthCount).padEnd(8);
    const prec = r.accuracy ? `${(r.accuracy.precision * 100).toFixed(1)}%`.padEnd(8) : 'N/A     ';
    const recall = r.accuracy ? `${(r.accuracy.recall * 100).toFixed(1)}%`.padEnd(8) : 'N/A     ';
    const f1 = r.accuracy ? `${(r.accuracy.f1Score * 100).toFixed(1)}%`.padEnd(8) : 'N/A     ';
    const risk = r.riskScore ? `${r.riskScore}/10`.padEnd(6) : 'N/A   ';
    console.log(`│ ${name} │ ${status} │ ${vulns} │ ${gt} │ ${prec} │ ${recall} │ ${f1} │ ${risk} │`);
  }

  console.log('└─────────────────────────┴────────┴───────┴──────────┴──────────┴──────────┴──────────┴────────┘');

  // Detailed findings per target
  for (const r of allResults) {
    console.log(`\n━━━ ${r.name} ━━━`);
    
    if (r.vulns.length > 0) {
      console.log(`  Vulnerabilities detected (${r.vulns.length}):`);
      for (const v of r.vulns) {
        console.log(`    [${(v.severity || '?').toUpperCase().padEnd(8)}] ${v.title} (${v.tool})`);
      }
    }

    if (r.findings.length > 0) {
      console.log(`  LLM Findings (${r.findings.length}):`);
      for (const f of r.findings) {
        const title = f.title || f.vulnerability || 'Unknown';
        const sev = f.severity || f.risk || '?';
        console.log(`    [${String(sev).toUpperCase().padEnd(8)}] ${title}`);
      }
    }

    if (r.attackChains && r.attackChains.length > 0) {
      console.log(`  Attack Chains (${r.attackChains.length}):`);
      for (const ac of r.attackChains) {
        console.log(`    🔗 ${ac.name || ac.title || 'Chain'}: ${ac.description || ac.steps?.join(' → ') || 'N/A'}`);
      }
    }

    if (r.accuracy) {
      console.log(`  Accuracy Breakdown:`);
      console.log(`    True Positives:  ${r.accuracy.truePositives}`);
      console.log(`    False Positives: ${r.accuracy.falsePositives}`);
      console.log(`    False Negatives: ${r.accuracy.falseNegatives}`);
      if (r.accuracy.matchedVulns?.length > 0) {
        console.log(`    Matched: ${r.accuracy.matchedVulns.join(', ')}`);
      }
      if (r.accuracy.missedVulns?.length > 0) {
        console.log(`    Missed:  ${r.accuracy.missedVulns.join(', ')}`);
      }
    }

    // Tool results summary
    if (r.toolResults.length > 0) {
      console.log(`  Tool Results (${r.toolResults.length}):`);
      for (const tr of r.toolResults) {
        const count = tr.results?.length || tr.resultCount || 0;
        console.log(`    ${(tr.tool || '?').padEnd(12)} → ${count} results`);
      }
    }
  }

  // Aggregate stats
  const withAccuracy = allResults.filter(r => r.accuracy);
  if (withAccuracy.length > 0) {
    const avgF1 = withAccuracy.reduce((s, r) => s + r.accuracy.f1Score, 0) / withAccuracy.length;
    const avgPrec = withAccuracy.reduce((s, r) => s + r.accuracy.precision, 0) / withAccuracy.length;
    const avgRecall = withAccuracy.reduce((s, r) => s + r.accuracy.recall, 0) / withAccuracy.length;
    const totalTP = withAccuracy.reduce((s, r) => s + r.accuracy.truePositives, 0);
    const totalFP = withAccuracy.reduce((s, r) => s + r.accuracy.falsePositives, 0);
    const totalFN = withAccuracy.reduce((s, r) => s + r.accuracy.falseNegatives, 0);

    console.log('\n╔═══════════════════════════════════════════════════════════════════╗');
    console.log('║  📈 AGGREGATE METRICS                                            ║');
    console.log('╚═══════════════════════════════════════════════════════════════════╝');
    console.log(`  Average F1 Score:    ${(avgF1 * 100).toFixed(1)}%`);
    console.log(`  Average Precision:   ${(avgPrec * 100).toFixed(1)}%`);
    console.log(`  Average Recall:      ${(avgRecall * 100).toFixed(1)}%`);
    console.log(`  Total True Pos:      ${totalTP}`);
    console.log(`  Total False Pos:     ${totalFP}`);
    console.log(`  Total False Neg:     ${totalFN}`);
    console.log(`  Targets scored:      ${withAccuracy.length} / ${allResults.length}`);
  }

  console.log('\n═══════════════════════════════════════════════════════════════════');
  console.log('  ✅ Live Instance Validation Suite Complete');
  console.log('═══════════════════════════════════════════════════════════════════');
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
