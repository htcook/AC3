import 'dotenv/config';
import mysql from 'mysql2/promise';

const conn = await mysql.createConnection(process.env.DATABASE_URL);

// 1. Total scans in DB
const [totalRows] = await conn.execute('SELECT COUNT(*) as cnt FROM domain_intel_scans');
console.log('=== TOTAL SCANS IN DB ===');
console.log('Total:', totalRows[0].cnt);

// 2. Status breakdown
console.log('\n=== STATUS BREAKDOWN ===');
const [statusBreakdown] = await conn.execute(
  'SELECT status, COUNT(*) as cnt FROM domain_intel_scans GROUP BY status ORDER BY cnt DESC'
);
console.table(statusBreakdown);

// 3. Auto-test vs real scan counts
const [autoTest] = await conn.execute(
  "SELECT COUNT(*) as cnt FROM domain_intel_scans WHERE primaryDomain REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$'"
);
const [realScans] = await conn.execute(
  "SELECT COUNT(*) as cnt FROM domain_intel_scans WHERE NOT (primaryDomain REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$')"
);
console.log('\n=== AUTO-TEST vs REAL ===');
console.log('Auto-test pattern scans:', autoTest[0].cnt);
console.log('Real domain scans:', realScans[0].cnt);

// 4. Completed/scan_complete scans (the ones user expects to see)
const [completedAll] = await conn.execute(
  "SELECT COUNT(*) as cnt FROM domain_intel_scans WHERE status IN ('completed', 'scan_complete')"
);
const [completedReal] = await conn.execute(
  "SELECT COUNT(*) as cnt FROM domain_intel_scans WHERE status IN ('completed', 'scan_complete') AND NOT (primaryDomain REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$')"
);
const [completedAutoTest] = await conn.execute(
  "SELECT COUNT(*) as cnt FROM domain_intel_scans WHERE status IN ('completed', 'scan_complete') AND primaryDomain REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$'"
);
console.log('\n=== COMPLETED SCANS ===');
console.log('Total completed (all):', completedAll[0].cnt);
console.log('Completed real domains:', completedReal[0].cnt);
console.log('Completed auto-test:', completedAutoTest[0].cnt);

// 5. List ALL completed real scans
console.log('\n=== ALL COMPLETED REAL DOMAIN SCANS ===');
const [completedList] = await conn.execute(
  "SELECT id, primaryDomain, status, totalAssets, totalFindings, overallRiskScore, createdAt FROM domain_intel_scans WHERE status IN ('completed', 'scan_complete') AND NOT (primaryDomain REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$') ORDER BY createdAt DESC"
);
console.table(completedList);

// 6. Scans stuck in non-terminal states
console.log('\n=== SCANS IN NON-TERMINAL STATES (not completed/scan_complete/failed) ===');
const [stuckScans] = await conn.execute(
  "SELECT id, primaryDomain, status, totalAssets, totalFindings, createdAt, updatedAt FROM domain_intel_scans WHERE status NOT IN ('completed', 'scan_complete', 'failed') AND NOT (primaryDomain REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$') ORDER BY createdAt DESC"
);
console.table(stuckScans);

// 7. Databank.com scan specifically
console.log('\n=== DATABANK.COM SCAN ===');
const [databank] = await conn.execute(
  "SELECT id, primaryDomain, status, totalAssets, totalFindings, overallRiskScore, pipelineOutput, createdAt, updatedAt FROM domain_intel_scans WHERE primaryDomain = 'databank.com' ORDER BY createdAt DESC"
);
for (const row of databank) {
  console.log('ID:', row.id);
  console.log('Status:', row.status);
  console.log('Assets:', row.totalAssets);
  console.log('Findings:', row.totalFindings);
  console.log('Risk Score:', row.overallRiskScore);
  console.log('Created:', row.createdAt);
  console.log('Updated:', row.updatedAt);
  if (row.pipelineOutput) {
    const output = typeof row.pipelineOutput === 'string' ? JSON.parse(row.pipelineOutput) : row.pipelineOutput;
    console.log('Pipeline Output Keys:', Object.keys(output));
    if (output.error) console.log('ERROR:', output.error);
    if (output.failedStage) console.log('Failed Stage:', output.failedStage);
    if (output.lastError) console.log('Last Error:', output.lastError);
  } else {
    console.log('Pipeline Output: null');
  }
  console.log('---');
}

// 8. Check for scans with 0 assets that are completed
console.log('\n=== COMPLETED SCANS WITH 0 ASSETS (potential issues) ===');
const [emptyCompleted] = await conn.execute(
  "SELECT id, primaryDomain, status, totalAssets, totalFindings FROM domain_intel_scans WHERE status IN ('completed', 'scan_complete') AND (totalAssets = 0 OR totalAssets IS NULL) AND NOT (primaryDomain REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$') ORDER BY createdAt DESC"
);
console.table(emptyCompleted);

// 9. Time range of scans from last night
console.log('\n=== SCAN TIME RANGE ===');
const [timeRange] = await conn.execute(
  "SELECT MIN(createdAt) as earliest, MAX(createdAt) as latest FROM domain_intel_scans WHERE NOT (primaryDomain REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$')"
);
console.log('Earliest scan:', timeRange[0].earliest);
console.log('Latest scan:', timeRange[0].latest);

// 10. Check if the REGEXP filter is accidentally catching real domains
console.log('\n=== DOMAINS CAUGHT BY AUTO-TEST FILTER ===');
const [filteredDomains] = await conn.execute(
  "SELECT id, primaryDomain, status, totalAssets FROM domain_intel_scans WHERE primaryDomain REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$' ORDER BY createdAt DESC LIMIT 20"
);
console.table(filteredDomains);

await conn.end();
