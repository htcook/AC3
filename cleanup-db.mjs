import mysql2 from 'mysql2/promise';

const conn = await mysql2.createConnection({
  uri: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true }
});

console.log('=== DB CLEANUP: Removing empty/test scans ===\n');

// Step 1: Identify scans to delete
// Delete all scans with 0 assets AND 0 findings (empty test scans)
const [emptyScans] = await conn.execute(
  `SELECT id FROM domain_intel_scans WHERE totalAssets = 0 AND totalFindings = 0`
);
console.log(`Found ${emptyScans.length} empty scans (0 assets, 0 findings)`);

// Also delete test-domain scans that have synthetic data patterns
const testPatterns = [
  'enterprise-%', 'update-%', 'trpc-%', 'ack-test-%', 
  'test-%', 'changes-test-%', 'get-test-%', 'test-monitor-%',
  'mixed_hosting-%', 'paas-%', 'asset-test-%'
];
const patternConditions = testPatterns.map(p => `primaryDomain LIKE '${p}'`).join(' OR ');
const [testScans] = await conn.execute(
  `SELECT id, primaryDomain FROM domain_intel_scans WHERE (${patternConditions}) AND totalAssets > 0`
);
console.log(`Found ${testScans.length} test-domain scans with synthetic data`);

// Combine all scan IDs to delete
const emptyIds = emptyScans.map(s => s.id);
const testIds = testScans.map(s => s.id);
const allDeleteIds = [...new Set([...emptyIds, ...testIds])];
console.log(`Total scans to delete: ${allDeleteIds.length}`);

if (allDeleteIds.length === 0) {
  console.log('Nothing to delete.');
  await conn.end();
  process.exit(0);
}

// Step 2: Show what we're keeping
const [keepScans] = await conn.execute(
  `SELECT id, primaryDomain, status, totalAssets, totalFindings, overallRiskScore 
   FROM domain_intel_scans 
   WHERE id NOT IN (${allDeleteIds.join(',')})
   ORDER BY createdAt DESC`
);
console.log(`\nScans to KEEP: ${keepScans.length}`);
console.table(keepScans);

// Step 3: Delete discovered_assets for those scans
const batchSize = 100;
let totalAssetsDeleted = 0;
for (let i = 0; i < allDeleteIds.length; i += batchSize) {
  const batch = allDeleteIds.slice(i, i + batchSize);
  const [result] = await conn.execute(
    `DELETE FROM discovered_assets WHERE scanId IN (${batch.join(',')})`
  );
  totalAssetsDeleted += result.affectedRows;
}
console.log(`\nDeleted ${totalAssetsDeleted} discovered_assets`);

// Step 4: Delete the scans themselves
let totalScansDeleted = 0;
for (let i = 0; i < allDeleteIds.length; i += batchSize) {
  const batch = allDeleteIds.slice(i, i + batchSize);
  const [result] = await conn.execute(
    `DELETE FROM domain_intel_scans WHERE id IN (${batch.join(',')})`
  );
  totalScansDeleted += result.affectedRows;
}
console.log(`Deleted ${totalScansDeleted} domain_intel_scans`);

// Step 5: Verify
const [remaining] = await conn.execute(
  `SELECT COUNT(*) as remaining FROM domain_intel_scans`
);
const [remainingAssets] = await conn.execute(
  `SELECT COUNT(*) as remaining FROM discovered_assets`
);
console.log(`\n=== POST-CLEANUP ===`);
console.log(`Remaining scans: ${remaining[0].remaining}`);
console.log(`Remaining assets: ${remainingAssets[0].remaining}`);

await conn.end();
console.log('\nCleanup complete!');
