import 'dotenv/config';
import mysql from 'mysql2/promise';

async function main() {
  const conn = await mysql.createConnection(process.env.DATABASE_URL);
  const [rows] = await conn.query(
    "SELECT tool, target, exit_code, duration_ms, raw_stderr, command FROM scan_results WHERE engagement_id = 1350014 ORDER BY created_at DESC LIMIT 6"
  );
  for (const r of rows) {
    console.log('---');
    console.log(`Tool: ${r.tool} | Target: ${r.target} | Exit: ${r.exit_code} | Duration: ${r.duration_ms}ms`);
    console.log(`Stderr: ${r.raw_stderr || '(empty)'}`);
    console.log(`Command: ${(r.command || '(empty)').substring(0, 200)}`);
  }

  // Also check the ops snapshot for error logs
  const [snapRows] = await conn.query(
    "SELECT state_json FROM engagement_ops_snapshots WHERE engagement_id = 1350014 LIMIT 1"
  );
  if (snapRows.length > 0 && snapRows[0].state_json) {
    const state = JSON.parse(snapRows[0].state_json);
    console.log('\n=== OPS STATE ===');
    console.log('Phase:', state.phase);
    console.log('Status:', state.status);
    console.log('Stats:', JSON.stringify(state.stats));
    console.log('Assets:', state.assets?.length || 0);
    
    // Show all logs
    console.log('\n=== ALL LOGS (last 30) ===');
    const logs = state.logs || [];
    logs.slice(-30).forEach(l => {
      console.log(`  [${l.ts || l.timestamp || ''}] ${l.message || JSON.stringify(l)}`);
    });
    
    // Show tool results
    console.log('\n=== TOOL RESULTS ===');
    const trs = state.toolResults || [];
    trs.forEach(tr => {
      console.log(`  ${tr.tool} → ${tr.target} | exit: ${tr.exitCode} | findings: ${tr.findingCount || 0} | output: ${(tr.stdout || '').length} chars`);
      if (tr.stderr) console.log(`    stderr: ${tr.stderr.substring(0, 200)}`);
      if (tr.error) console.log(`    error: ${tr.error.substring(0, 200)}`);
    });
  }

  await conn.end();
}

main().catch(console.error);
