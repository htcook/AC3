import mysql from 'mysql2/promise';
import { readFileSync } from 'fs';

const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
  // Read from .env file
  const envContent = readFileSync('/home/ubuntu/caldera-dashboard/.env', 'utf8');
  const match = envContent.match(/DATABASE_URL=(.+)/);
  if (match) process.env.DATABASE_URL = match[1];
}

async function main() {
  const conn = await mysql.createConnection(process.env.DATABASE_URL);

  // 1. Find the Vianova engagement
  console.log("=== VIANOVA ENGAGEMENT ===");
  const [engagements] = await conn.query(
    "SELECT id, name, status, created_at, updated_at FROM engagements WHERE name LIKE '%ianova%' OR name LIKE '%VIANOVA%'"
  );
  console.log(engagements);

  if (engagements.length === 0) {
    console.log("No Vianova engagement found");
    await conn.end();
    return;
  }

  const engId = engagements[0].id;
  console.log(`\nEngagement ID: ${engId}`);

  // 2. Check scan_results for this engagement
  console.log("\n=== SCAN RESULTS (latest 20) ===");
  const [scanResults] = await conn.query(
    `SELECT id, tool_name, target, finding_count, exit_code, duration_ms, 
            LENGTH(raw_output) as output_len, created_at 
     FROM scan_results 
     WHERE engagement_id = ? 
     ORDER BY created_at DESC 
     LIMIT 20`,
    [engId]
  );
  console.table(scanResults);

  // 3. Check total findings per tool
  console.log("\n=== FINDINGS PER TOOL ===");
  const [findingsPerTool] = await conn.query(
    `SELECT tool_name, COUNT(*) as scan_count, SUM(finding_count) as total_findings,
            AVG(duration_ms) as avg_duration_ms, MIN(created_at) as first_scan, MAX(created_at) as last_scan
     FROM scan_results 
     WHERE engagement_id = ? 
     GROUP BY tool_name 
     ORDER BY total_findings DESC`,
    [engId]
  );
  console.table(findingsPerTool);

  // 4. Check the ops snapshot
  console.log("\n=== OPS SNAPSHOT ===");
  const [snapshots] = await conn.query(
    `SELECT id, LENGTH(state_json) as state_size, created_at, updated_at 
     FROM engagement_ops_snapshots 
     WHERE engagement_id = ?`,
    [engId]
  );
  console.table(snapshots);

  if (snapshots.length > 0) {
    const [stateRows] = await conn.query(
      `SELECT state_json FROM engagement_ops_snapshots WHERE engagement_id = ? LIMIT 1`,
      [engId]
    );
    if (stateRows.length > 0) {
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
            console.log(`    First 5 vulns:`);
            asset.vulns.slice(0, 5).forEach(v => {
              console.log(`      - [${v.severity}] ${v.title} (CVE: ${v.cve || 'none'})`);
            });
          }
        }
      }

      // Check tool results
      console.log(`\n  Tool results count: ${state.toolResults?.length || 0}`);
      if (state.toolResults) {
        const byTool = {};
        state.toolResults.forEach(tr => {
          byTool[tr.tool] = (byTool[tr.tool] || 0) + 1;
        });
        console.log("  Tool results by tool:", byTool);
      }

      // Check logs for errors
      const errorLogs = (state.logs || []).filter(l => 
        l.message?.toLowerCase().includes('error') || 
        l.message?.toLowerCase().includes('fail') ||
        l.message?.toLowerCase().includes('timeout') ||
        l.level === 'error'
      );
      console.log(`\n  Error/failure logs: ${errorLogs.length}`);
      errorLogs.slice(0, 10).forEach(l => {
        console.log(`    [${l.timestamp || ''}] ${l.message}`);
      });
    }
  }

  // 5. Check scan results from today vs yesterday
  console.log("\n=== TODAY vs YESTERDAY SCAN RESULTS ===");
  const [todayScans] = await conn.query(
    `SELECT tool_name, COUNT(*) as count, SUM(finding_count) as findings
     FROM scan_results 
     WHERE engagement_id = ? AND DATE(created_at) = CURDATE()
     GROUP BY tool_name ORDER BY findings DESC`,
    [engId]
  );
  console.log("Today:");
  console.table(todayScans);

  const [yesterdayScans] = await conn.query(
    `SELECT tool_name, COUNT(*) as count, SUM(finding_count) as findings
     FROM scan_results 
     WHERE engagement_id = ? AND DATE(created_at) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)
     GROUP BY tool_name ORDER BY findings DESC`,
    [engId]
  );
  console.log("Yesterday:");
  console.table(yesterdayScans);

  // 6. Check for scans with exit_code != 0 (failures)
  console.log("\n=== FAILED SCANS (exit_code != 0) ===");
  const [failedScans] = await conn.query(
    `SELECT tool_name, target, exit_code, duration_ms, finding_count, 
            LENGTH(raw_output) as output_len, created_at
     FROM scan_results 
     WHERE engagement_id = ? AND exit_code != 0
     ORDER BY created_at DESC LIMIT 20`,
    [engId]
  );
  console.table(failedScans);

  // 7. Check for scans with 0 findings but non-zero output (parsing issue?)
  console.log("\n=== SCANS WITH OUTPUT BUT 0 FINDINGS (potential parsing issues) ===");
  const [parseMissed] = await conn.query(
    `SELECT tool_name, target, finding_count, exit_code, duration_ms, 
            LENGTH(raw_output) as output_len, created_at
     FROM scan_results 
     WHERE engagement_id = ? AND finding_count = 0 AND LENGTH(raw_output) > 100
     ORDER BY output_len DESC LIMIT 15`,
    [engId]
  );
  console.table(parseMissed);

  await conn.end();
}

main().catch(console.error);
