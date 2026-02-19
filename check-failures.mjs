import 'dotenv/config';
import mysql from 'mysql2/promise';

const conn = await mysql.createConnection(process.env.DATABASE_URL);

// Get the failed aceofcloud.com scan
const [failed] = await conn.execute(
  `SELECT id, primaryDomain, status, totalAssets, totalFindings, pipelineOutput, executiveSummary, createdAt, updatedAt 
   FROM domain_intel_scans WHERE id = 750020`
);
if (failed.length > 0) {
  const f = failed[0];
  console.log('=== Failed Scan: aceofcloud.com (ID 750020) ===');
  console.log(`Status: ${f.status} | Assets: ${f.totalAssets} | Findings: ${f.totalFindings}`);
  console.log(`Created: ${f.createdAt} | Updated: ${f.updatedAt}`);
  const output = typeof f.pipelineOutput === 'string' ? JSON.parse(f.pipelineOutput) : f.pipelineOutput;
  if (output) {
    console.log(`Pipeline output keys: ${Object.keys(output).join(', ')}`);
    if (output.error) console.log(`Error: ${JSON.stringify(output.error).substring(0, 2000)}`);
    if (output.failedStage) console.log(`Failed Stage: ${output.failedStage}`);
    if (output.errorMessage) console.log(`Error Message: ${output.errorMessage}`);
    // Check for any error-like keys
    for (const [k, v] of Object.entries(output)) {
      if (k.toLowerCase().includes('error') || k.toLowerCase().includes('fail')) {
        console.log(`  ${k}: ${JSON.stringify(v).substring(0, 500)}`);
      }
    }
  } else {
    console.log('No pipeline output stored');
  }
}

// Get the stuck databank.com scan (scoring status)
const [stuck] = await conn.execute(
  `SELECT id, primaryDomain, status, totalAssets, totalFindings, pipelineOutput, createdAt, updatedAt 
   FROM domain_intel_scans WHERE id = 750019`
);
if (stuck.length > 0) {
  const s = stuck[0];
  console.log('\n=== Stuck Scan: databank.com (ID 750019) ===');
  console.log(`Status: ${s.status} | Assets: ${s.totalAssets} | Findings: ${s.totalFindings}`);
  console.log(`Created: ${s.createdAt} | Updated: ${s.updatedAt}`);
  const output = typeof s.pipelineOutput === 'string' ? JSON.parse(s.pipelineOutput) : s.pipelineOutput;
  if (output) {
    console.log(`Pipeline output keys: ${Object.keys(output).join(', ')}`);
    if (output.error) console.log(`Error: ${JSON.stringify(output.error).substring(0, 2000)}`);
    if (output.failedStage) console.log(`Failed Stage: ${output.failedStage}`);
    if (output.errorMessage) console.log(`Error Message: ${output.errorMessage}`);
    for (const [k, v] of Object.entries(output)) {
      if (k.toLowerCase().includes('error') || k.toLowerCase().includes('fail')) {
        console.log(`  ${k}: ${JSON.stringify(v).substring(0, 500)}`);
      }
    }
  } else {
    console.log('No pipeline output stored');
  }
}

// Also check the first completed databank.com scan for comparison
const [completed] = await conn.execute(
  `SELECT id, primaryDomain, status, totalAssets, totalFindings, overallRiskScore, createdAt, updatedAt 
   FROM domain_intel_scans WHERE id = 750001`
);
if (completed.length > 0) {
  const c = completed[0];
  console.log('\n=== Completed Scan: databank.com (ID 750001) for comparison ===');
  console.log(`Status: ${c.status} | Assets: ${c.totalAssets} | Findings: ${c.totalFindings} | Risk: ${c.overallRiskScore}`);
  console.log(`Created: ${c.createdAt} | Updated: ${c.updatedAt}`);
}

await conn.end();
