import mysql from 'mysql2/promise';

const conn = await mysql.createConnection(process.env.DATABASE_URL);

// 1. Check the raw Nuclei output from scan_results
console.log('=== NUCLEI SCAN RESULTS (engagement 1350014) ===');
const [scanRows] = await conn.execute(
  `SELECT id, target, finding_count, severity_summary, 
   LENGTH(raw_output) as output_len, 
   SUBSTRING(raw_output, 1, 2000) as output_preview,
   phase, created_at 
   FROM scan_results WHERE tool = 'nuclei' AND engagement_id = 1350014 
   ORDER BY created_at DESC`
);
for (const r of scanRows) {
  console.log(`\n--- Scan #${r.id} | target: ${r.target} | findings: ${r.finding_count} | phase: ${r.phase} ---`);
  console.log('Severity:', JSON.stringify(r.severity_summary));
  console.log('Output length:', r.output_len);
  console.log('Output preview:', r.output_preview?.slice(0, 500));
}

// 2. Check the ops snapshot for asset vulns
console.log('\n\n=== OPS SNAPSHOT (engagement 1350014) ===');
const [snapRows] = await conn.execute(
  `SELECT id, phase, is_running, asset_count, 
   JSON_EXTRACT(state_json, '$.stats.vulnsFound') as vulns_found,
   JSON_LENGTH(JSON_EXTRACT(state_json, '$.assets')) as num_assets,
   updated_at
   FROM engagement_ops_snapshots WHERE engagement_id = 1350014 
   ORDER BY updated_at DESC LIMIT 1`
);
for (const r of snapRows) {
  console.log(`Snapshot #${r.id} | phase: ${r.phase} | running: ${r.is_running} | assets: ${r.asset_count} | vulnsFound: ${r.vulns_found}`);
}

// 3. Extract per-asset vuln counts from the snapshot
console.log('\n=== PER-ASSET VULNS FROM SNAPSHOT ===');
const [assetRows] = await conn.execute(
  `SELECT 
   JSON_EXTRACT(asset.val, '$.hostname') as hostname,
   JSON_LENGTH(JSON_EXTRACT(asset.val, '$.vulns')) as vuln_count,
   JSON_LENGTH(JSON_EXTRACT(asset.val, '$.toolResults')) as tool_count,
   JSON_EXTRACT(asset.val, '$.status') as status
   FROM engagement_ops_snapshots s,
   JSON_TABLE(s.state_json, '$.assets[*]' COLUMNS(val JSON PATH '$')) as asset
   WHERE s.engagement_id = 1350014
   ORDER BY s.updated_at DESC LIMIT 20`
);
for (const r of assetRows) {
  console.log(`  ${r.hostname} | vulns: ${r.vuln_count} | tools: ${r.tool_count} | status: ${r.status}`);
}

// 4. Check if there are any scan results with actual findings (non-zero)
console.log('\n=== ALL SCAN RESULTS WITH FINDINGS > 0 (engagement 1350014) ===');
const [findingRows] = await conn.execute(
  `SELECT id, tool, target, finding_count, severity_summary, phase
   FROM scan_results WHERE engagement_id = 1350014 AND finding_count > 0
   ORDER BY finding_count DESC LIMIT 20`
);
if (findingRows.length === 0) {
  console.log('  NO scan results have finding_count > 0');
} else {
  for (const r of findingRows) {
    console.log(`  #${r.id} | ${r.tool} | ${r.target} | findings: ${r.finding_count} | ${JSON.stringify(r.severity_summary)} | phase: ${r.phase}`);
  }
}

// 5. Check the total vulnsFound in the stats from the snapshot
console.log('\n=== FULL STATS FROM SNAPSHOT ===');
const [statsRows] = await conn.execute(
  `SELECT JSON_EXTRACT(state_json, '$.stats') as stats
   FROM engagement_ops_snapshots WHERE engagement_id = 1350014 
   ORDER BY updated_at DESC LIMIT 1`
);
for (const r of statsRows) {
  console.log(JSON.stringify(JSON.parse(r.stats), null, 2));
}

// 6. Check the raw nuclei output for the latest scan to see what nuclei actually returned
console.log('\n=== RAW NUCLEI OUTPUT (latest scan, first 3000 chars) ===');
const [rawRows] = await conn.execute(
  `SELECT raw_output FROM scan_results 
   WHERE tool = 'nuclei' AND engagement_id = 1350014 
   AND LENGTH(raw_output) > 100
   ORDER BY created_at DESC LIMIT 1`
);
for (const r of rawRows) {
  console.log(r.raw_output?.slice(0, 3000));
}

await conn.end();
