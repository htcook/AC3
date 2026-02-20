import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
dotenv.config();

const conn = await mysql.createConnection(process.env.DATABASE_URL);

// Check scan statuses
const [scans] = await conn.query(`
  SELECT id, primaryDomain, status, overallRiskScore, totalAssets, totalFindings,
         JSON_EXTRACT(pipelineOutput, '$.error') as pipelineError,
         createdAt, updatedAt
  FROM domain_intel_scans 
  ORDER BY id DESC LIMIT 10
`);
console.log('\n=== Recent Scans ===');
console.table(scans);

// Check for failed scans
const [failed] = await conn.query(`
  SELECT id, primaryDomain, status, 
         LEFT(JSON_EXTRACT(pipelineOutput, '$.error'), 200) as errorMsg,
         LEFT(JSON_EXTRACT(pipelineOutput, '$.stack'), 300) as errorStack
  FROM domain_intel_scans 
  WHERE status = 'failed' OR status LIKE '%error%'
  ORDER BY id DESC LIMIT 5
`);
if (failed.length > 0) {
  console.log('\n=== Failed Scans ===');
  console.table(failed);
}

// Check for stuck scans
const [stuck] = await conn.query(`
  SELECT id, primaryDomain, status, createdAt, updatedAt
  FROM domain_intel_scans 
  WHERE status NOT IN ('completed', 'scan_complete', 'failed')
  ORDER BY id DESC LIMIT 5
`);
if (stuck.length > 0) {
  console.log('\n=== Stuck/In-Progress Scans ===');
  console.table(stuck);
}

// Check discovered assets count
const [assetCounts] = await conn.query(`
  SELECT scanId, COUNT(*) as assetCount 
  FROM discovered_assets 
  GROUP BY scanId 
  ORDER BY scanId DESC LIMIT 10
`);
console.log('\n=== Asset Counts by Scan ===');
console.table(assetCounts);

await conn.end();
