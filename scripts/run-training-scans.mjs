/**
 * Training Lab Scan Runner
 * 
 * Launches scans against Broken Crystals and Gin & Juice Shop,
 * monitors progress, and collects accuracy results.
 */
import jwt from 'jsonwebtoken';
import http from 'http';

const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';
const BASE_URL = 'http://localhost:3000';

// Generate a valid session cookie
const token = jwt.sign(
  { username: 'admin', role: 'admin', loginTime: Date.now() },
  CALDERA_JWT_SECRET,
  { expiresIn: '1h' }
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
          if (parsed.error) {
            reject(new Error(`tRPC error: ${JSON.stringify(parsed.error)}`));
          } else {
            resolve(parsed.result?.data?.json ?? parsed.result?.data);
          }
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
          if (parsed.error) {
            reject(new Error(`tRPC error: ${JSON.stringify(parsed.error)}`));
          } else {
            resolve(parsed.result?.data?.json ?? parsed.result?.data);
          }
        } catch (e) {
          reject(new Error(`Parse error: ${data.slice(0, 200)}`));
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function monitorSession(sessionId, name) {
  console.log(`\n📡 Monitoring: ${name} (${sessionId})`);
  let lastPhase = '';
  let lastProgress = 0;
  let attempts = 0;
  const maxAttempts = 120; // 10 minutes max

  while (attempts < maxAttempts) {
    try {
      const session = await trpcQuery('trainingLab.getSession', { sessionId });
      if (!session) {
        console.log(`  ⏳ Session not ready yet...`);
        await sleep(5000);
        attempts++;
        continue;
      }

      const phase = session.phase || 'unknown';
      const progress = session.progress || 0;
      const status = session.labStatus || session.status || 'unknown';

      if (phase !== lastPhase || progress !== lastProgress) {
        console.log(`  [${new Date().toLocaleTimeString()}] Phase: ${phase} | Progress: ${progress}% | Status: ${status}`);
        lastPhase = phase;
        lastProgress = progress;
      }

      if (status === 'completed' || status === 'done' || status === 'failed' || progress >= 100) {
        console.log(`\n✅ ${name} scan ${status === 'failed' ? 'FAILED' : 'COMPLETED'}`);
        
        // Get final results
        if (session.vulns) {
          console.log(`  📊 Vulnerabilities found: ${session.vulns.length}`);
          for (const v of session.vulns.slice(0, 10)) {
            console.log(`    - [${v.severity?.toUpperCase()}] ${v.title}`);
          }
          if (session.vulns.length > 10) {
            console.log(`    ... and ${session.vulns.length - 10} more`);
          }
        }

        if (session.assets) {
          console.log(`  🖥️  Assets discovered: ${session.assets.length}`);
        }

        // Get accuracy score if available
        try {
          const accuracy = await trpcQuery('trainingLab.sessionAccuracy', { sessionId });
          if (accuracy) {
            console.log(`\n  🎯 Accuracy Score:`);
            console.log(`    Precision: ${(accuracy.precision * 100).toFixed(1)}%`);
            console.log(`    Recall: ${(accuracy.recall * 100).toFixed(1)}%`);
            console.log(`    F1 Score: ${(accuracy.f1Score * 100).toFixed(1)}%`);
            console.log(`    Overall: ${(accuracy.overallScore * 100).toFixed(1)}%`);
          }
        } catch (e) {
          console.log(`  ℹ️  Accuracy score not yet available`);
        }

        return session;
      }
    } catch (err) {
      console.log(`  ⚠️  Monitor error: ${err.message}`);
    }

    await sleep(5000);
    attempts++;
  }

  console.log(`  ⏰ Monitoring timed out after ${maxAttempts * 5}s`);
  return null;
}

async function main() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  🔬 CALDERA Training Lab - Scan Validation Suite');
  console.log('  📅 March 7, 2026 - Knowledge Module Wiring Validation');
  console.log('═══════════════════════════════════════════════════════════════\n');

  // Verify targets are available
  try {
    const targets = await trpcQuery('trainingLab.targets');
    console.log(`✅ Training catalog loaded: ${targets.length} targets available\n`);
  } catch (e) {
    console.error(`❌ Failed to load targets: ${e.message}`);
    process.exit(1);
  }

  // Launch Broken Crystals scan
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  🎯 Target 1: Broken Crystals (brokencrystals.com)');
  console.log('  📋 Expected: 18 ground truth vulns (JWT, SSRF, SSTI, GraphQL...)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  let bcSession;
  try {
    bcSession = await trpcMutation('trainingLab.startSession', {
      targetId: 'broken-crystals',
      scanProfile: 'deep',
      name: 'Broken Crystals - Knowledge Validation (March 7)',
    });
    console.log(`✅ Scan launched: ${bcSession.sessionId}`);
  } catch (e) {
    console.error(`❌ Failed to launch Broken Crystals scan: ${e.message}`);
  }

  // Launch Gin & Juice Shop scan
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  🎯 Target 2: Gin & Juice Shop (ginandjuice.shop)');
  console.log('  📋 Expected: 14 ground truth vulns (HTTP Smuggling, Deserialization...)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  let gjSession;
  try {
    gjSession = await trpcMutation('trainingLab.startSession', {
      targetId: 'gin-juice-shop',
      scanProfile: 'deep',
      name: 'Gin & Juice Shop - Knowledge Validation (March 7)',
    });
    console.log(`✅ Scan launched: ${gjSession.sessionId}`);
  } catch (e) {
    console.error(`❌ Failed to launch Gin & Juice Shop scan: ${e.message}`);
  }

  // Monitor both scans
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('  📡 Monitoring scan progress...');
  console.log('═══════════════════════════════════════════════════════════════');

  const results = {};

  if (bcSession) {
    results.brokenCrystals = await monitorSession(bcSession.sessionId, 'Broken Crystals');
  }

  if (gjSession) {
    results.ginJuice = await monitorSession(gjSession.sessionId, 'Gin & Juice Shop');
  }

  // Summary
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('  📊 SCAN VALIDATION SUMMARY');
  console.log('═══════════════════════════════════════════════════════════════\n');

  for (const [name, result] of Object.entries(results)) {
    if (result) {
      const vulnCount = result.vulns?.length || 0;
      const assetCount = result.assets?.length || 0;
      const status = result.labStatus || result.status || 'unknown';
      console.log(`  ${name}:`);
      console.log(`    Status: ${status}`);
      console.log(`    Vulns found: ${vulnCount}`);
      console.log(`    Assets discovered: ${assetCount}`);
      console.log('');
    }
  }

  // Get ground truth comparison
  console.log('  Ground Truth Comparison:');
  try {
    const gtTargets = await trpcQuery('trainingLab.groundTruthTargets');
    const bcGt = gtTargets.find(t => t.targetPreset === 'broken-crystals');
    const gjGt = gtTargets.find(t => t.targetPreset === 'gin-juice-shop');
    if (bcGt) console.log(`    Broken Crystals: ${bcGt.vulnCount} ground truth vulns`);
    if (gjGt) console.log(`    Gin & Juice Shop: ${gjGt.vulnCount} ground truth vulns`);
  } catch (e) {
    console.log(`    ⚠️  Could not fetch ground truth: ${e.message}`);
  }

  // Get accuracy trend
  console.log('\n  Accuracy Trend:');
  try {
    const trend = await trpcQuery('trainingLab.accuracyTrend', { limit: 10 });
    if (trend && trend.length > 0) {
      for (const entry of trend) {
        console.log(`    [${new Date(entry.scoredAt).toLocaleDateString()}] ${entry.targetPreset}: F1=${(entry.f1Score * 100).toFixed(1)}% Overall=${(entry.overallScore * 100).toFixed(1)}%`);
      }
    } else {
      console.log('    No previous accuracy data (this is the first run with new targets)');
    }
  } catch (e) {
    console.log(`    ⚠️  Could not fetch accuracy trend: ${e.message}`);
  }

  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('  ✅ Validation suite complete');
  console.log('═══════════════════════════════════════════════════════════════');
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
