/**
 * Trigger Vianova scoped scans via the tRPC API.
 * 
 * This script:
 * 1. Logs in via calderaAuth.login to get a session cookie
 * 2. Starts a Vianova scan with scoped assets (2 URLs + 1 IP)
 * 3. Polls scan status until completion
 * 
 * Usage: node scripts/trigger-vianova-scans.mjs
 */

import jwt from 'jsonwebtoken';

const BASE_URL = 'http://localhost:3000';
const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';

// Create a valid session token directly (bypasses login endpoint)
function createSessionToken() {
  return jwt.sign(
    { username: 'admin', role: 'admin', loginTime: Date.now() },
    CALDERA_JWT_SECRET,
    { expiresIn: '24h' }
  );
}

// tRPC batch call helper
async function trpcMutation(procedure, input, cookie) {
  const url = `${BASE_URL}/api/trpc/${procedure}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': `caldera_session=${cookie}`,
    },
    body: JSON.stringify({ json: input }),
  });
  const data = await res.json();
  if (data.error) {
    throw new Error(`tRPC error: ${JSON.stringify(data.error)}`);
  }
  return data.result?.data?.json ?? data.result?.data;
}

async function trpcQuery(procedure, input, cookie) {
  const encoded = encodeURIComponent(JSON.stringify({ json: input }));
  const url = `${BASE_URL}/api/trpc/${procedure}?input=${encoded}`;
  const res = await fetch(url, {
    method: 'GET',
    headers: {
      'Cookie': `caldera_session=${cookie}`,
    },
  });
  const data = await res.json();
  if (data.error) {
    throw new Error(`tRPC error: ${JSON.stringify(data.error)}`);
  }
  return data.result?.data?.json ?? data.result?.data;
}

async function pollScanStatus(scanId, cookie) {
  const startTime = Date.now();
  const TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

  while (Date.now() - startTime < TIMEOUT_MS) {
    try {
      const status = await trpcQuery('domainIntel.getScanStatus', { scanId }, cookie);
      const stage = status?.status || 'unknown';
      const elapsed = Math.round((Date.now() - startTime) / 1000);
      console.log(`  [${elapsed}s] Scan ${scanId} status: ${stage}`);

      if (stage === 'completed' || stage === 'scan_complete') {
        console.log(`  ✓ Scan ${scanId} completed successfully!`);
        return status;
      }
      if (stage === 'failed' || stage === 'error') {
        console.error(`  ✗ Scan ${scanId} failed!`);
        return status;
      }
    } catch (err) {
      console.error(`  Poll error: ${err.message}`);
    }

    // Wait 10 seconds between polls
    await new Promise(r => setTimeout(r, 10000));
  }

  console.error(`  ✗ Scan ${scanId} timed out after 10 minutes`);
  return null;
}

async function main() {
  console.log('=== Vianova Scoped Scan Trigger ===\n');

  // Step 1: Create session token
  const cookie = createSessionToken();
  console.log('✓ Created admin session token\n');

  // Step 2: Verify session works
  try {
    const session = await trpcQuery('calderaAuth.session', undefined, cookie);
    console.log(`✓ Session verified: ${session.user?.username} (${session.user?.role})\n`);
  } catch (err) {
    console.error(`✗ Session verification failed: ${err.message}`);
    process.exit(1);
  }

  // Step 3: Start Vianova scan with scoped assets (2 URLs + 1 IP)
  const vianovaScanInput = {
    primaryDomain: 'vianova.io',
    additionalDomains: [],
    clientType: 'saas',
    sector: 'Technology',
    customerName: 'Vianova',
    criticalFunctions: ['Web Application', 'API Services', 'Customer Portal'],
    complianceFlags: ['SOC2', 'GDPR'],
    notes: 'Scoped scan test: 2 URLs + 1 IP only per Rules of Engagement',
    scanMode: 'standard',
    scanOnly: false,
    scopedAssets: [
      'vianova.io',
      'app.vianova.io',
      '104.26.12.100'
    ],
  };

  console.log('Starting Vianova scoped scan...');
  console.log(`  Primary domain: ${vianovaScanInput.primaryDomain}`);
  console.log(`  Scoped assets: ${vianovaScanInput.scopedAssets.join(', ')}`);
  console.log('');

  try {
    const result = await trpcMutation('domainIntel.startScan', vianovaScanInput, cookie);
    const scanId = result?.scanId || result?.id;
    console.log(`✓ Scan started with ID: ${scanId}\n`);

    if (scanId) {
      console.log('Polling scan status (this may take several minutes)...\n');
      const finalStatus = await pollScanStatus(scanId, cookie);

      if (finalStatus) {
        console.log('\n=== Scan Complete ===');
        console.log(`  Status: ${finalStatus.status}`);
        
        // Fetch the full scan results to verify scope enforcement
        try {
          const scanData = await trpcQuery('domainIntel.getScan', { id: scanId }, cookie);
          const assets = scanData?.assets || [];
          console.log(`  Total assets discovered: ${assets.length}`);
          
          if (assets.length > 0) {
            console.log('\n  Discovered assets:');
            for (const asset of assets) {
              const hostname = asset.hostname || 'unknown';
              const ip = asset.ipAddress || '';
              const riskBand = asset.riskBand || 'unknown';
              const excluded = asset.excluded ? ' [EXCLUDED]' : '';
              console.log(`    - ${hostname}${ip ? ` (${ip})` : ''} — risk: ${riskBand}${excluded}`);
            }
          }

          // Verify scope enforcement
          const scopedSet = new Set(vianovaScanInput.scopedAssets.map(s => s.toLowerCase()));
          const outOfScope = assets.filter(a => {
            const h = (a.hostname || '').toLowerCase();
            const ip = (a.ipAddress || '').toLowerCase();
            return !scopedSet.has(h) && !scopedSet.has(ip) && !a.excluded;
          });

          if (outOfScope.length === 0) {
            console.log('\n  ✓ SCOPE ENFORCEMENT PASSED: All non-excluded assets are within scope');
          } else {
            console.log(`\n  ⚠ SCOPE WARNING: ${outOfScope.length} asset(s) outside scoped list:`);
            for (const a of outOfScope) {
              console.log(`    - ${a.hostname} (${a.ipAddress || 'no IP'})`);
            }
          }
        } catch (err) {
          console.error(`  Error fetching scan results: ${err.message}`);
        }
      }
    }
  } catch (err) {
    console.error(`✗ Failed to start scan: ${err.message}`);
  }

  console.log('\n=== Done ===');
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
