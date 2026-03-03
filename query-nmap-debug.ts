import { drizzle } from 'drizzle-orm/mysql2';
import mysql from 'mysql2/promise';
import { sql } from 'drizzle-orm';

async function main() {
  const conn = await mysql.createConnection(process.env.DATABASE_URL!);
  const db = drizzle(conn);

  // Get the latest engagement scan results
  console.log('=== LATEST SCAN RESULTS (last 10) ===');
  const results = await db.execute(sql`
    SELECT id, engagement_id, tool, command, finding_count, 
           SUBSTRING(raw_output, 1, 500) as raw_output_preview,
           SUBSTRING(parsed_data, 1, 500) as parsed_data_preview,
           created_at
    FROM scan_results 
    ORDER BY created_at DESC 
    LIMIT 10
  `);
  for (const row of (results as any)[0]) {
    console.log('\n--- Scan Result ID:', row.id, '---');
    console.log('Engagement:', row.engagement_id);
    console.log('Tool:', row.tool);
    console.log('Command:', row.command);
    console.log('Finding Count:', row.finding_count);
    console.log('Raw Output Preview:', row.raw_output_preview);
    console.log('Parsed Data Preview:', row.parsed_data_preview);
    console.log('Created:', row.created_at);
  }

  // Check for nmap-specific results
  console.log('\n\n=== NMAP RESULTS (last 5) ===');
  const nmapResults = await db.execute(sql`
    SELECT id, engagement_id, command, finding_count,
           raw_output,
           SUBSTRING(parsed_data, 1, 1000) as parsed_data_preview,
           created_at
    FROM scan_results 
    WHERE tool = 'nmap'
    ORDER BY created_at DESC 
    LIMIT 5
  `);
  for (const row of (nmapResults as any)[0]) {
    console.log('\n--- Nmap Result ID:', row.id, '---');
    console.log('Engagement:', row.engagement_id);
    console.log('Command:', row.command);
    console.log('Finding Count:', row.finding_count);
    console.log('Raw Output Length:', row.raw_output?.length || 0);
    console.log('Raw Output:', row.raw_output);
    console.log('Parsed Data:', row.parsed_data_preview);
    console.log('Created:', row.created_at);
  }

  // Check engagement state
  console.log('\n\n=== LATEST ENGAGEMENTS ===');
  const engagements = await db.execute(sql`
    SELECT id, name, status, 
           SUBSTRING(scan_plan, 1, 500) as scan_plan_preview,
           updated_at
    FROM engagements 
    ORDER BY updated_at DESC 
    LIMIT 3
  `);
  for (const row of (engagements as any)[0]) {
    console.log('\n--- Engagement ID:', row.id, '---');
    console.log('Name:', row.name);
    console.log('Status:', row.status);
    console.log('Scan Plan:', row.scan_plan_preview);
    console.log('Updated:', row.updated_at);
  }

  await conn.end();
}

main().catch(console.error);
