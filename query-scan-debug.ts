import { getDb } from "./server/db";
import { sql } from "drizzle-orm";

async function main() {
  const db = await getDb();
  
  // Get latest scan results with all details
  const results = await db.execute(sql`
    SELECT id, engagement_id, tool, command, exit_code, duration_ms, finding_count, phase,
           LEFT(raw_output, 2000) as output_preview,
           created_at
    FROM scan_results 
    ORDER BY created_at DESC 
    LIMIT 30
  `);
  
  console.log("=== Latest Scan Results ===");
  for (const r of results.rows || results) {
    const row = r as any;
    console.log(`\n--- ${row.tool} (ID: ${row.id}) ---`);
    console.log(`  Phase: ${row.phase}`);
    console.log(`  Command: ${(row.command || '').substring(0, 300)}`);
    console.log(`  Exit code: ${row.exit_code}`);
    console.log(`  Duration: ${row.duration_ms}ms`);
    console.log(`  Findings: ${row.finding_count}`);
    console.log(`  Output preview: ${(row.output_preview || '(empty)').substring(0, 500)}`);
    console.log(`  Created: ${row.created_at}`);
  }
  
  // Check for nikto specifically
  const nikto = await db.execute(sql`
    SELECT id, tool, command, exit_code, duration_ms, finding_count, phase, LEFT(raw_output, 1000) as output_preview
    FROM scan_results 
    WHERE tool LIKE '%nikto%' OR command LIKE '%nikto%'
    ORDER BY created_at DESC 
    LIMIT 5
  `);
  
  console.log("\n=== Nikto Results ===");
  const niktoRows = nikto.rows || nikto;
  if ((niktoRows as any[]).length === 0) {
    console.log("  No Nikto results found in scan_results!");
  }
  for (const r of niktoRows) {
    const row = r as any;
    console.log(`  Tool: ${row.tool}, Exit: ${row.exit_code}, Duration: ${row.duration_ms}ms, Findings: ${row.finding_count}`);
    console.log(`  Command: ${row.command}`);
    console.log(`  Output: ${(row.output_preview || '(empty)').substring(0, 500)}`);
  }

  // Check for httpx and nuclei specifically
  const timedOut = await db.execute(sql`
    SELECT id, tool, command, exit_code, duration_ms, finding_count, phase, LEFT(raw_output, 1000) as output_preview
    FROM scan_results 
    WHERE (tool LIKE '%nuclei%' OR tool LIKE '%httpx%') AND exit_code = -1
    ORDER BY created_at DESC 
    LIMIT 10
  `);
  
  console.log("\n=== Timed Out nuclei/httpx Results ===");
  for (const r of timedOut.rows || timedOut) {
    const row = r as any;
    console.log(`\n  Tool: ${row.tool}, Exit: ${row.exit_code}, Duration: ${row.duration_ms}ms, Phase: ${row.phase}`);
    console.log(`  Command: ${(row.command || '').substring(0, 400)}`);
    console.log(`  Output: ${(row.output_preview || '(empty)').substring(0, 500)}`);
  }
  
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });
