/**
 * Import Burp Suite Professional scan results into the Stell-Engineering engagement (ID: 38)
 * on the AC3 production platform via direct database insert.
 */
import { readFileSync } from 'fs';
import { createConnection } from 'mysql2/promise';

// Load the prepared payload
const payload = JSON.parse(readFileSync('/home/ubuntu/burp-scan-results-payload.json', 'utf-8'));

// Connect to the production database
// The DATABASE_URL is available in the environment
const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
  console.error('DATABASE_URL not set');
  process.exit(1);
}

// Parse the DATABASE_URL
const url = new URL(dbUrl);
const connection = await createConnection({
  host: url.hostname,
  port: parseInt(url.port || '3306'),
  user: url.username,
  password: url.password,
  database: url.pathname.slice(1),
  ssl: { rejectUnauthorized: false },
});

console.log('Connected to database');

// Insert scan results for each host
for (const sr of payload) {
  const [existing] = await connection.execute(
    'SELECT id FROM scan_results WHERE engagement_id = ? AND tool = ? AND target = ? LIMIT 1',
    [sr.engagementId, sr.tool, sr.target]
  );
  
  if (existing.length > 0) {
    // Update existing
    await connection.execute(
      `UPDATE scan_results SET 
        command = ?,
        findings = ?,
        finding_count = ?,
        severity_summary = ?,
        phase = ?
      WHERE id = ?`,
      [
        sr.command,
        JSON.stringify(sr.findings),
        sr.findingCount,
        JSON.stringify(sr.severitySummary),
        sr.phase,
        existing[0].id,
      ]
    );
    console.log(`Updated existing scan_result for ${sr.target} (ID: ${existing[0].id})`);
  } else {
    // Insert new
    await connection.execute(
      `INSERT INTO scan_results (engagement_id, tool, target, command, findings, finding_count, severity_summary, phase)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        sr.engagementId,
        sr.tool,
        sr.target,
        sr.command,
        JSON.stringify(sr.findings),
        sr.findingCount,
        JSON.stringify(sr.severitySummary),
        sr.phase,
      ]
    );
    console.log(`Inserted scan_result for ${sr.target}`);
  }
}

// Verify
const [results] = await connection.execute(
  'SELECT id, tool, target, finding_count FROM scan_results WHERE engagement_id = 38 AND tool = ?',
  ['burpsuite_professional']
);
console.log(`\nVerification - Burp scan results for engagement 38:`);
for (const r of results) {
  console.log(`  ID: ${r.id} | Target: ${r.target} | Findings: ${r.finding_count}`);
}

await connection.end();
console.log('\nDone. Burp Suite findings imported successfully.');
