import 'dotenv/config';
import mysql from 'mysql2/promise';

const conn = await mysql.createConnection(process.env.DATABASE_URL);
const [rows] = await conn.execute(
  `SELECT id, primaryDomain, status, totalAssets, totalFindings, overallRiskScore, overallRiskBand, 
          createdAt, updatedAt,
          TIMESTAMPDIFF(SECOND, createdAt, updatedAt) as durationSec
   FROM domain_intel_scans 
   ORDER BY createdAt DESC LIMIT 20`
);
console.log('=== Recent Domain Intel Scans ===');
for (const r of rows) {
  console.log(`ID: ${r.id} | Domain: ${r.primaryDomain} | Status: ${r.status} | Assets: ${r.totalAssets} | Findings: ${r.totalFindings} | Risk: ${r.overallRiskScore} (${r.overallRiskBand}) | Duration: ${r.durationSec}s | Created: ${r.createdAt} | Updated: ${r.updatedAt}`);
}

// Check for failed scans
const [failed] = await conn.execute(
  `SELECT id, primaryDomain, status, pipelineOutput FROM domain_intel_scans WHERE status = 'failed' ORDER BY createdAt DESC LIMIT 5`
);
if (failed.length > 0) {
  console.log('\n=== Failed Scans ===');
  for (const f of failed) {
    const output = typeof f.pipelineOutput === 'string' ? JSON.parse(f.pipelineOutput) : f.pipelineOutput;
    console.log(`ID: ${f.id} | Domain: ${f.primaryDomain} | Status: ${f.status}`);
    if (output?.error) console.log(`  Error: ${JSON.stringify(output.error).substring(0, 500)}`);
    if (output?.failedStage) console.log(`  Failed Stage: ${output.failedStage}`);
  }
}

// Check for stuck scans (not completed, older than 10 min)
const [stuck] = await conn.execute(
  `SELECT id, primaryDomain, status, createdAt, updatedAt 
   FROM domain_intel_scans 
   WHERE status NOT IN ('completed', 'scan_complete', 'failed') 
   AND createdAt < DATE_SUB(NOW(), INTERVAL 10 MINUTE)
   ORDER BY createdAt DESC LIMIT 10`
);
if (stuck.length > 0) {
  console.log('\n=== Stuck Scans (not completed, >10 min old) ===');
  for (const s of stuck) {
    console.log(`ID: ${s.id} | Domain: ${s.primaryDomain} | Status: ${s.status} | Created: ${s.createdAt}`);
  }
}

await conn.end();
