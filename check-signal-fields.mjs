import mysql2 from 'mysql2/promise';
const conn = await mysql2.createConnection({ uri: process.env.DATABASE_URL, ssl: { rejectUnauthorized: true } });

const [rows] = await conn.execute(`
  SELECT id, primaryDomain,
    CAST(JSON_EXTRACT(pipelineOutput, '$.passiveRecon.riskSignals[0]') AS CHAR) as sig0,
    CAST(JSON_EXTRACT(pipelineOutput, '$.passiveRecon.riskSignals[1]') AS CHAR) as sig1,
    CAST(JSON_EXTRACT(pipelineOutput, '$.passiveRecon.riskSignals[2]') AS CHAR) as sig2,
    CAST(JSON_EXTRACT(pipelineOutput, '$.passiveRecon.summary') AS CHAR) as summary,
    JSON_LENGTH(pipelineOutput->'$.passiveRecon.riskSignals') as signalCount
  FROM domain_intel_scans 
  WHERE primaryDomain = 'vianova.ai' AND pipelineOutput IS NOT NULL
  ORDER BY createdAt DESC LIMIT 1
`);

for (const row of rows) {
  console.log(`Scan ${row.id} (${row.primaryDomain}), ${row.signalCount} signals:`);
  for (let i = 0; i <= 2; i++) {
    const raw = row[`sig${i}`];
    if (raw) {
      const sig = JSON.parse(raw);
      console.log(`\n  Signal ${i} fields:`, Object.keys(sig).join(', '));
      console.log(`  Full:`, JSON.stringify(sig, null, 2));
    }
  }
  if (row.summary) {
    console.log('\nSummary:', JSON.parse(row.summary));
  }
}

await conn.end();
