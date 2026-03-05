import mysql from 'mysql2/promise';

const conn = await mysql.createConnection(process.env.DATABASE_URL);

// Get the full snapshot state_json and parse it in JS
console.log('=== OPS SNAPSHOT ASSET DETAILS (engagement 1350014) ===');
const [snapRows] = await conn.execute(
  `SELECT state_json FROM engagement_ops_snapshots 
   WHERE engagement_id = 1350014 ORDER BY updated_at DESC LIMIT 1`
);

if (snapRows.length === 0) {
  console.log('No snapshot found');
  await conn.end();
  process.exit(0);
}

const state = typeof snapRows[0].state_json === 'string' 
  ? JSON.parse(snapRows[0].state_json) 
  : snapRows[0].state_json;

console.log('Phase:', state.phase);
console.log('Stats:', JSON.stringify(state.stats, null, 2));
console.log('Total assets:', state.assets?.length);

for (const a of (state.assets || [])) {
  console.log(`\n--- Asset: ${a.hostname} (${a.ip || 'no IP'}) | type: ${a.type} | status: ${a.status} ---`);
  console.log(`  Ports: ${(a.ports || []).length} | Vulns: ${(a.vulns || []).length} | ToolResults: ${(a.toolResults || []).length}`);
  
  // Show vulns
  if ((a.vulns || []).length > 0) {
    console.log('  VULNS:');
    for (const v of a.vulns.slice(0, 10)) {
      console.log(`    [${v.severity}] ${v.title} ${v.cve || ''}`);
    }
    if (a.vulns.length > 10) console.log(`    ... and ${a.vulns.length - 10} more`);
  }
  
  // Show tool results summary
  if ((a.toolResults || []).length > 0) {
    console.log('  TOOL RESULTS:');
    for (const tr of a.toolResults) {
      console.log(`    ${tr.tool} | phase: ${tr.phase} | findings: ${tr.findingCount} | exit: ${tr.exitCode} | timedOut: ${tr.timedOut}`);
      if (tr.findings && tr.findings.length > 0) {
        for (const f of tr.findings.slice(0, 3)) {
          console.log(`      -> [${f.severity}] ${f.title}`);
        }
        if (tr.findings.length > 3) console.log(`      ... and ${tr.findings.length - 3} more`);
      }
      if (tr.outputPreview) {
        console.log(`    Output preview (${tr.outputPreview.length} chars): ${tr.outputPreview.slice(0, 200)}`);
      }
    }
  }
}

// Check nuclei-specific log entries
console.log('\n=== NUCLEI LOG ENTRIES ===');
const nucleiLogs = (state.log || []).filter(l => 
  l.title?.toLowerCase().includes('nuclei') || 
  l.detail?.toLowerCase().includes('nuclei')
);
console.log(`Found ${nucleiLogs.length} nuclei-related log entries`);
for (const l of nucleiLogs) {
  console.log(`  [${l.type}] ${l.title}`);
  console.log(`    Detail: ${l.detail}`);
  if (l.data?.findings) {
    console.log(`    Findings in log data: ${l.data.findings.length}`);
    for (const f of l.data.findings.slice(0, 3)) {
      console.log(`      -> [${f.severity}] ${f.title}`);
    }
  }
}

// Check the scan_results for any tool that has findings
console.log('\n=== ALL SCAN RESULTS WITH FINDINGS > 0 ===');
const [allFindings] = await conn.execute(
  `SELECT tool, target, finding_count, severity_summary, phase, LENGTH(raw_output) as output_len
   FROM scan_results WHERE engagement_id = 1350014 AND finding_count > 0
   ORDER BY finding_count DESC LIMIT 20`
);
if (allFindings.length === 0) {
  console.log('  NO scan results have finding_count > 0 in the database');
} else {
  for (const r of allFindings) {
    console.log(`  ${r.tool} | ${r.target} | findings: ${r.finding_count} | output: ${r.output_len} bytes | ${r.phase}`);
  }
}

// Check total scan results for this engagement
const [countRows] = await conn.execute(
  `SELECT tool, COUNT(*) as cnt, SUM(finding_count) as total_findings, SUM(LENGTH(raw_output)) as total_output
   FROM scan_results WHERE engagement_id = 1350014 GROUP BY tool ORDER BY total_findings DESC`
);
console.log('\n=== SCAN RESULTS SUMMARY BY TOOL ===');
for (const r of countRows) {
  console.log(`  ${r.tool}: ${r.cnt} scans, ${r.total_findings} total findings, ${r.total_output} bytes output`);
}

await conn.end();
