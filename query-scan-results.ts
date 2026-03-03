import mysql from 'mysql2/promise';

async function main() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    console.log('No DATABASE_URL found');
    return;
  }
  const conn = await mysql.createConnection(dbUrl);
  
  // Get latest scan results for engagement 1350014
  const [rows] = await conn.execute(
    `SELECT id, tool, target, LEFT(command, 200) as cmd, exit_code, finding_count, 
     LEFT(raw_stderr, 300) as stderr_preview, LEFT(raw_output, 300) as stdout_preview, phase 
     FROM scan_results WHERE engagement_id = 1350014 ORDER BY created_at DESC LIMIT 25`
  ) as any;
  
  console.log('=== SCAN RESULTS FOR ENGAGEMENT 1350014 ===');
  for (const r of rows) {
    console.log(`\n--- ${r.tool} | target: ${r.target} | phase: ${r.phase} | exit: ${r.exit_code} | findings: ${r.finding_count} ---`);
    console.log(`CMD: ${r.cmd}`);
    if (r.stderr_preview) console.log(`STDERR: ${r.stderr_preview}`);
    if (r.stdout_preview) console.log(`STDOUT: ${r.stdout_preview?.slice(0, 200)}`);
  }
  
  await conn.end();
}

main().catch(e => console.error(e));
