import { createConnection } from 'mysql2/promise';

const conn = await createConnection(process.env.DATABASE_URL);

// Check risk scores for completed scans
const [scans] = await conn.execute(`
  SELECT primaryDomain, overallRiskScore, status, 
    CASE WHEN pipelineOutput IS NOT NULL THEN 'yes' ELSE 'no' END as has_output,
    JSON_EXTRACT(pipelineOutput, '$.riskScore') as pipeline_risk_score,
    JSON_EXTRACT(pipelineOutput, '$.carverRiskCard.overallScore') as carver_score
  FROM domain_intel_scans 
  WHERE status IN ('completed', 'scan_complete')
  ORDER BY createdAt DESC
  LIMIT 15
`);

for (const s of scans) {
  console.log(`${s.primaryDomain}: overallRisk=${s.overallRiskScore}, pipelineRisk=${s.pipeline_risk_score}, carver=${s.carver_score}, hasOutput=${s.has_output}`);
}

// Count how many have risk scores
const [counts] = await conn.execute(`
  SELECT 
    COUNT(*) as total,
    SUM(CASE WHEN overallRiskScore > 0 THEN 1 ELSE 0 END) as with_db_risk,
    SUM(CASE WHEN JSON_EXTRACT(pipelineOutput, '$.riskScore') > 0 THEN 1 ELSE 0 END) as with_pipeline_risk,
    SUM(CASE WHEN JSON_EXTRACT(pipelineOutput, '$.carverRiskCard.overallScore') > 0 THEN 1 ELSE 0 END) as with_carver
  FROM domain_intel_scans 
  WHERE status IN ('completed', 'scan_complete')
`);

console.log('\nCounts:', counts[0]);

await conn.end();
