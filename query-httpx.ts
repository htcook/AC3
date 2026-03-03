import mysql from 'mysql2/promise';

async function main() {
  const conn = await mysql.createConnection(process.env.DATABASE_URL as string);
  const [rows] = await conn.execute(
    "SELECT id, tool, target, finding_count, LEFT(findings, 500) as findings_preview FROM scan_results WHERE engagement_id = 1350014 AND tool = 'httpx' ORDER BY created_at DESC LIMIT 3"
  ) as any;
  for (const r of rows) {
    console.log('---', r.tool, '| target:', r.target, '| finding_count:', r.finding_count);
    console.log('findings_preview:', r.findings_preview);
  }
  
  // Also check the engagement ops state to see what the live feed shows
  const [opsRows] = await conn.execute(
    "SELECT id, LEFT(state, 2000) as state_preview FROM engagement_ops WHERE engagement_id = 1350014 ORDER BY id DESC LIMIT 1"
  ) as any;
  if (opsRows.length > 0) {
    console.log('\n=== OPS STATE (first 2000 chars) ===');
    console.log(opsRows[0].state_preview);
  }
  
  await conn.end();
}

main().catch(e => console.error(e));
