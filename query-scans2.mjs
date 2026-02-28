import 'dotenv/config';
import mysql from 'mysql2/promise';

const conn = await mysql.createConnection(process.env.DATABASE_URL);

// Get real scans (completed with actual data)
const [realScans] = await conn.execute(`
  SELECT id, primaryDomain, status, totalAssets, totalFindings, clientType, sector, createdAt
  FROM domain_intel_scans 
  WHERE status IN ('completed', 'scan_complete') AND totalAssets > 0
  ORDER BY createdAt DESC LIMIT 30
`);
console.log('\n=== Real Scans (completed with assets > 0) ===');
console.table(realScans);

// Check for test domain patterns
const [testPatterns] = await conn.execute(`
  SELECT 
    CASE 
      WHEN primaryDomain REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$' THEN 'auto-test-pattern'
      WHEN primaryDomain LIKE 'test%' THEN 'test-prefix'
      ELSE 'real-domain'
    END as domain_type,
    COUNT(*) as cnt,
    SUM(CASE WHEN totalAssets > 0 THEN 1 ELSE 0 END) as with_assets,
    SUM(CASE WHEN totalFindings > 0 THEN 1 ELSE 0 END) as with_findings
  FROM domain_intel_scans
  GROUP BY domain_type
`);
console.log('\n=== Domain Type Breakdown ===');
console.table(testPatterns);

// Get in-progress scans
const [inProgress] = await conn.execute(`
  SELECT id, primaryDomain, status, totalAssets, totalFindings, createdAt
  FROM domain_intel_scans 
  WHERE status NOT IN ('completed', 'scan_complete', 'failed')
  ORDER BY createdAt DESC
`);
console.log('\n=== In-Progress Scans ===');
console.table(inProgress);

// Show all real domain scans (not auto-test pattern)
const [realDomains] = await conn.execute(`
  SELECT id, primaryDomain, status, totalAssets, totalFindings, createdAt
  FROM domain_intel_scans 
  WHERE primaryDomain NOT REGEXP '^(msp|enterprise|saas|paas|iaas|mixed_hosting|other)-[0-9]+\\.com$'
  ORDER BY createdAt DESC LIMIT 30
`);
console.log('\n=== Real Domain Scans (not auto-test pattern) ===');
console.table(realDomains);

await conn.end();
