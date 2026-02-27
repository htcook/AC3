import mysql2 from 'mysql2/promise';
const conn = await mysql2.createConnection({ uri: process.env.DATABASE_URL, ssl: { rejectUnauthorized: true } });

const [counts] = await conn.execute(`
  SELECT 
    COUNT(*) as total_scans,
    SUM(CASE WHEN totalAssets = 0 AND totalFindings = 0 THEN 1 ELSE 0 END) as empty_scans,
    SUM(CASE WHEN totalAssets > 0 OR totalFindings > 0 THEN 1 ELSE 0 END) as real_scans,
    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_scans,
    SUM(CASE WHEN primaryDomain LIKE '%test%' THEN 1 ELSE 0 END) as test_domain_scans
  FROM domain_intel_scans
`);
console.log('=== SCAN COUNTS ===');
console.table(counts);

// Show the real scans we want to keep
const [realScans] = await conn.execute(`
  SELECT id, primaryDomain, status, totalAssets, totalFindings, overallRiskScore
  FROM domain_intel_scans
  WHERE totalAssets > 0 OR totalFindings > 0
  ORDER BY createdAt DESC
`);
console.log('\n=== REAL SCANS TO KEEP ===');
console.table(realScans);

// Show sample of empty scans
const [emptyScans] = await conn.execute(`
  SELECT id, primaryDomain, status, totalAssets, totalFindings
  FROM domain_intel_scans
  WHERE totalAssets = 0 AND totalFindings = 0
  ORDER BY createdAt DESC
  LIMIT 20
`);
console.log('\n=== SAMPLE EMPTY SCANS TO DELETE (showing 20 of many) ===');
console.table(emptyScans);

// Check for orphaned discovered_assets
const [orphanedAssets] = await conn.execute(`
  SELECT COUNT(*) as orphaned_assets
  FROM discovered_assets da
  LEFT JOIN domain_intel_scans dis ON da.scanId = dis.id
  WHERE dis.id IS NULL
`);
console.log('\n=== ORPHANED ASSETS ===');
console.table(orphanedAssets);

// Check chain_runs and chain_stage_results
const [chainCounts] = await conn.execute(`SELECT COUNT(*) as chain_runs FROM chain_runs`);
const [stageCounts] = await conn.execute(`SELECT COUNT(*) as stage_results FROM chain_stage_results`);
console.log('\n=== CHAIN DATA ===');
console.log('Chain runs:', chainCounts[0]);
console.log('Stage results:', stageCounts[0]);

await conn.end();
