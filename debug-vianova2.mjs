// Use tsx to run with TypeScript support
// This script uses the project's DB connection
import 'dotenv/config';
import mysql from 'mysql2/promise';

const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
  console.error("DATABASE_URL not set");
  process.exit(1);
}

async function main() {
  const conn = await mysql.createConnection(dbUrl);

  // 1. Find the Vianova engagement
  console.log("=== VIANOVA ENGAGEMENT ===");
  const [engRows] = await conn.query(
    "SELECT id, name, status, targetDomain FROM engagements WHERE name LIKE '%ianova%' LIMIT 1"
  );
  console.log(JSON.stringify(engRows, null, 2));

  if (engRows.length === 0) {
    console.log("No Vianova engagement found");
    await conn.end();
    return;
  }

  const engId = engRows[0].id;
  console.log(`\nEngagement ID: ${engId}, Target: ${engRows[0].targetDomain}`);

  // 2. Scan results summary by tool
  console.log("\n=== SCAN RESULTS BY TOOL ===");
  const [toolSummary] = await conn.query(
    `SELECT tool, COUNT(*) as scan_count, SUM(finding_count) as total_findings,
            SUM(CASE WHEN exit_code = 0 THEN 1 ELSE 0 END) as success_count,
            SUM(CASE WHEN exit_code != 0 THEN 1 ELSE 0 END) as fail_count,
            AVG(duration_ms) as avg_duration
     FROM scan_results 
     WHERE engagement_id = ? 
     GROUP BY tool 
     ORDER BY total_findings DESC`,
    [engId]
  );
  console.log(JSON.stringify(toolSummary, null, 2));

  // 3. Recent scan results (last 20)
  console.log("\n=== RECENT SCAN RESULTS (last 20) ===");
  const [recentScans] = await conn.query(
    `SELECT id, tool, target, finding_count, exit_code, duration_ms, 
            LENGTH(raw_output) as output_len, phase, created_at 
     FROM scan_results 
     WHERE engagement_id = ? 
     ORDER BY created_at DESC 
     LIMIT 20`,
    [engId]
  );
  console.log(JSON.stringify(recentScans, null, 2));

  // 4. Failed scans
  console.log("\n=== FAILED SCANS (exit_code != 0) ===");
  const [failedScans] = await conn.query(
    `SELECT tool, target, exit_code, duration_ms, finding_count, 
            LENGTH(raw_output) as output_len, LENGTH(raw_stderr) as stderr_len,
            timed_out, phase, created_at
     FROM scan_results 
     WHERE engagement_id = ? AND (exit_code != 0 OR exit_code IS NULL)
     ORDER BY created_at DESC LIMIT 20`,
    [engId]
  );
  console.log(JSON.stringify(failedScans, null, 2));

  // 5. Scans with output but 0 findings (parsing issues)
  console.log("\n=== SCANS WITH OUTPUT BUT 0 FINDINGS ===");
  const [parseMissed] = await conn.query(
    `SELECT tool, target, finding_count, exit_code, duration_ms, 
            LENGTH(raw_output) as output_len, phase, created_at
     FROM scan_results 
     WHERE engagement_id = ? AND finding_count = 0 AND LENGTH(raw_output) > 100
     ORDER BY output_len DESC LIMIT 15`,
    [engId]
  );
  console.log(JSON.stringify(parseMissed, null, 2));

  // 6. Check ops snapshot
  console.log("\n=== OPS SNAPSHOT ===");
  const [snapshots] = await conn.query(
    `SELECT id, LENGTH(state_json) as state_size, created_at, updated_at 
     FROM engagement_ops_snapshots 
     WHERE engagement_id = ?`,
    [engId]
  );
  console.log(JSON.stringify(snapshots, null, 2));

  if (snapshots.length > 0) {
    const [stateRows] = await conn.query(
      `SELECT state_json FROM engagement_ops_snapshots WHERE engagement_id = ? LIMIT 1`,
      [engId]
    );
    if (stateRows.length > 0 && stateRows[0].state_json) {
      const state = JSON.parse(stateRows[0].state_json);
      console.log("\n=== OPS STATE SUMMARY ===");
      console.log("Phase:", state.phase);
      console.log("Status:", state.status);
      console.log("Stats:", JSON.stringify(state.stats, null, 2));
      console.log("Asset count:", state.assets?.length || 0);
      
      if (state.assets) {
        for (const asset of state.assets) {
          console.log(`\n  Asset: ${asset.target}`);
          console.log(`    Vulns: ${asset.vulns?.length || 0}`);
          console.log(`    Services: ${asset.services?.length || 0}`);
          console.log(`    Technologies: ${asset.technologies?.length || 0}`);
          if (asset.vulns && asset.vulns.length > 0) {
            console.log(`    Sample vulns (first 5):`);
            asset.vulns.slice(0, 5).forEach(v => {
              console.log(`      - [${v.severity}] ${v.title} (CVE: ${v.cve || 'none'})`);
            });
          }
        }
      }

      // Check tool results
      const toolResultCount = state.toolResults?.length || 0;
      console.log(`\n  Tool results count: ${toolResultCount}`);
      if (state.toolResults) {
        const byTool = {};
        state.toolResults.forEach(tr => {
          byTool[tr.tool] = (byTool[tr.tool] || 0) + 1;
        });
        console.log("  Tool results by tool:", JSON.stringify(byTool));
      }

      // Check error logs
      const errorLogs = (state.logs || []).filter(l => 
        (l.message || '').toLowerCase().includes('error') || 
        (l.message || '').toLowerCase().includes('fail') ||
        (l.message || '').toLowerCase().includes('timeout') ||
        (l.message || '').toLowerCase().includes('0 findings') ||
        l.level === 'error'
      );
      console.log(`\n  Error/failure/timeout logs: ${errorLogs.length}`);
      errorLogs.slice(0, 20).forEach(l => {
        console.log(`    [${l.timestamp || l.ts || ''}] ${l.message || JSON.stringify(l)}`);
      });
    }
  }

  // 7. Check today's scan count vs total
  console.log("\n=== SCAN TIMELINE ===");
  const [timeline] = await conn.query(
    `SELECT DATE(created_at) as scan_date, COUNT(*) as scan_count, 
            SUM(finding_count) as total_findings
     FROM scan_results 
     WHERE engagement_id = ?
     GROUP BY DATE(created_at)
     ORDER BY scan_date DESC`,
    [engId]
  );
  console.log(JSON.stringify(timeline, null, 2));

  await conn.end();
}

main().catch(console.error);
