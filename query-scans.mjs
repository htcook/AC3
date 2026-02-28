import 'dotenv/config';
import mysql from 'mysql2/promise';

const conn = await mysql.createConnection(process.env.DATABASE_URL);

// Get status breakdown
const [statusRows] = await conn.execute(`
  SELECT status, COUNT(*) as cnt, 
    MIN(totalAssets) as min_assets, MAX(totalAssets) as max_assets,
    MIN(totalFindings) as min_findings, MAX(totalFindings) as max_findings
  FROM domain_intel_scans GROUP BY status
`);
console.log('\n=== Status Breakdown ===');
console.table(statusRows);

// Get recent scans with data
const [recentRows] = await conn.execute(`
  SELECT id, primaryDomain, status, totalAssets, totalFindings, clientType, sector, createdAt
  FROM domain_intel_scans 
  ORDER BY createdAt DESC LIMIT 30
`);
console.log('\n=== Recent 30 Scans ===');
console.table(recentRows);

// Find empty/test scans (0 assets, 0 findings)
const [emptyRows] = await conn.execute(`
  SELECT id, primaryDomain, status, totalAssets, totalFindings, createdAt
  FROM domain_intel_scans 
  WHERE (totalAssets = 0 OR totalAssets IS NULL) AND (totalFindings = 0 OR totalFindings IS NULL)
  ORDER BY createdAt DESC LIMIT 20
`);
console.log('\n=== Empty/Test Scans (0 assets, 0 findings) ===');
console.table(emptyRows);

// Count total
const [totalRows] = await conn.execute(`SELECT COUNT(*) as total FROM domain_intel_scans`);
console.log('\nTotal scans:', totalRows[0].total);

// Check scans with pipeline_output
const [pipelineRows] = await conn.execute(`
  SELECT id, primaryDomain, status, totalAssets, totalFindings,
    CASE WHEN pipelineOutput IS NOT NULL AND pipelineOutput != '{}' AND pipelineOutput != 'null' THEN 'YES' ELSE 'NO' END as has_pipeline
  FROM domain_intel_scans 
  WHERE status IN ('completed', 'scan_complete')
  ORDER BY createdAt DESC LIMIT 20
`);
console.log('\n=== Completed Scans with Pipeline Data ===');
console.table(pipelineRows);

await conn.end();
