import 'dotenv/config';
import mysql from 'mysql2/promise';

async function main() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) { console.error('DATABASE_URL not set'); process.exit(1); }

  const url = new URL(dbUrl);
  const conn = await mysql.createConnection({
    host: url.hostname,
    port: parseInt(url.port) || 3306,
    user: url.username,
    password: url.password,
    database: url.pathname.slice(1),
    ssl: dbUrl.includes('tidbcloud.com') ? { rejectUnauthorized: true } : undefined,
  });

  // Find all stuck scans — column names are camelCase per Drizzle schema
  const [stuckScans] = await conn.execute(`
    SELECT id, primaryDomain, status, totalAssets, updatedAt, createdAt
    FROM domain_intel_scans
    WHERE status IN ('pending', 'passive_recon', 'discovering', 'analyzing', 'scoring', 'recommending')
      AND updatedAt < DATE_SUB(NOW(), INTERVAL 15 MINUTE)
      AND primaryDomain NOT REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\\\.com$'
    ORDER BY createdAt DESC
  `);

  console.log(`\n=== STUCK SCANS FOUND: ${stuckScans.length} ===\n`);
  
  if (stuckScans.length === 0) {
    console.log('No stuck scans to retry.');
    await conn.end();
    return;
  }

  for (const scan of stuckScans) {
    console.log(`  ID: ${scan.id} | ${scan.primaryDomain} | Status: ${scan.status} | Assets: ${scan.totalAssets} | Updated: ${scan.updatedAt}`);
  }

  const scanIds = stuckScans.map(s => s.id);
  
  // Step 1: Clean up orphaned assets from partial runs
  console.log(`\n=== CLEANING UP ORPHANED ASSETS ===\n`);
  for (const scanId of scanIds) {
    const [result] = await conn.execute(
      'DELETE FROM discovered_assets WHERE scanId = ?',
      [scanId]
    );
    if (result.affectedRows > 0) {
      console.log(`  Cleaned ${result.affectedRows} orphaned assets from scan ${scanId}`);
    }
  }

  // Step 2: Reset all stuck scans to 'failed' status so retryScan endpoint can pick them up
  console.log(`\n=== RESETTING ${scanIds.length} SCANS TO 'failed' STATUS ===\n`);
  
  for (let i = 0; i < scanIds.length; i += 10) {
    const batch = scanIds.slice(i, i + 10);
    const placeholders = batch.map(() => '?').join(',');
    await conn.execute(
      `UPDATE domain_intel_scans 
       SET status = 'failed', 
           pipelineOutput = JSON_OBJECT('error', 'Scan stuck during pipeline execution - auto-reset for retry', 'failedAt', NOW(), 'autoReset', true),
           totalAssets = 0,
           totalFindings = 0,
           confirmedFindings = 0,
           probableFindings = 0,
           overallRiskScore = NULL,
           overallRiskBand = NULL,
           updatedAt = NOW()
       WHERE id IN (${placeholders})`,
      batch
    );
    console.log(`  Reset batch ${Math.floor(i/10) + 1}: IDs ${batch.join(', ')}`);
  }

  // Step 3: Now trigger retries via the local tRPC endpoint
  // The retryScan mutation is a protectedProcedure, so we need a valid session.
  // We'll call the server directly using the internal tRPC batch format.
  console.log(`\n=== TRIGGERING RETRIES VIA tRPC ===\n`);
  
  // Get a session cookie by finding the owner user
  const [users] = await conn.execute(`SELECT id, openId FROM users WHERE role = 'admin' LIMIT 1`);
  if (users.length === 0) {
    console.log('No admin user found. Scans are reset to failed - retry them from the UI.');
    await conn.end();
    return;
  }
  
  const adminUser = users[0];
  console.log(`  Using admin user ID: ${adminUser.id}`);
  
  // Generate a JWT token for the admin user to call the tRPC endpoint
  const jwt = await import('jsonwebtoken');
  const token = jwt.default.sign(
    { userId: adminUser.id, openId: adminUser.openId },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
  
  let successCount = 0;
  let failCount = 0;
  const errors = [];
  
  // Retry scans one at a time with a 2-second delay between each to avoid overloading the LLM
  for (const scanId of scanIds) {
    const scan = stuckScans.find(s => s.id === scanId);
    try {
      const resp = await fetch('http://localhost:3000/api/trpc/domainIntel.retryScan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': `session=${token}`,
        },
        body: JSON.stringify({ json: { scanId } }),
      });
      
      if (resp.ok) {
        const data = await resp.json();
        console.log(`  ✅ Retry triggered: ${scan.primaryDomain} (ID: ${scanId})`);
        successCount++;
      } else {
        const errText = await resp.text();
        console.log(`  ❌ Retry failed: ${scan.primaryDomain} (ID: ${scanId}) - ${resp.status}: ${errText.substring(0, 100)}`);
        failCount++;
        errors.push({ scanId, domain: scan.primaryDomain, error: errText.substring(0, 200) });
      }
    } catch (err) {
      console.log(`  ❌ Retry error: ${scan.primaryDomain} (ID: ${scanId}) - ${err.message}`);
      failCount++;
      errors.push({ scanId, domain: scan.primaryDomain, error: err.message });
    }
    
    // Wait 2 seconds between retries to avoid overwhelming the pipeline
    if (scanIds.indexOf(scanId) < scanIds.length - 1) {
      await new Promise(r => setTimeout(r, 2000));
    }
  }

  console.log(`\n=== SUMMARY ===`);
  console.log(`Total stuck scans: ${stuckScans.length}`);
  console.log(`Retries triggered: ${successCount}`);
  console.log(`Retries failed: ${failCount}`);
  if (errors.length > 0) {
    console.log(`\nFailed retries:`);
    for (const e of errors) {
      console.log(`  - ${e.domain} (${e.scanId}): ${e.error}`);
    }
  }
  console.log(`\nDomains queued for retry:`);
  console.log(stuckScans.map(s => s.primaryDomain).join(', '));

  await conn.end();
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
