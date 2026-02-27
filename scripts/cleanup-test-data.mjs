import mysql from 'mysql2/promise';

async function main() {
  const conn = await mysql.createConnection(process.env.DATABASE_URL);
  
  // Delete test scans using LIKE patterns (TiDB-compatible)
  const patterns = [
    'test-%', 'get-%', 'trpc-%', 'threat-model-%', 'campaigns-%',
    'update-%', 'asset-test-%', 'multi-asset-%', 'scores-%', 'findings-%',
    'get-scan-%'
  ];
  // Also numeric-suffixed client type patterns
  const clientPatterns = [
    'enterprise-1%', 'msp-1%', 'saas-1%', 'paas-1%', 'iaas-1%',
    'mixed_hosting-1%', 'other-1%'
  ];
  const allPatterns = [...patterns, ...clientPatterns];
  
  const whereClauses = allPatterns.map(p => `primaryDomain LIKE '${p}'`).join(' OR ');
  
  // Delete associated assets first
  const assetSql = `DELETE FROM discovered_assets WHERE scanId IN (SELECT id FROM domain_intel_scans WHERE ${whereClauses})`;
  const [r1] = await conn.execute(assetSql);
  console.log('Deleted test assets:', r1.affectedRows);
  
  // Delete test scans
  const scanSql = `DELETE FROM domain_intel_scans WHERE ${whereClauses}`;
  const [r2] = await conn.execute(scanSql);
  console.log('Deleted test scans:', r2.affectedRows);
  
  // Delete test OSINT monitors
  const monitorPatterns = ['test-%', 'get-%', 'update-%', 'delete-%', 'changes-%', 'ack-%'];
  const monWhere = monitorPatterns.map(p => `domain LIKE '${p}'`).join(' OR ');
  const [r3] = await conn.execute(`DELETE FROM osint_monitors WHERE ${monWhere}`);
  console.log('Deleted test monitors:', r3.affectedRows);
  
  // Delete test engagements created by vitest
  const [r4] = await conn.execute(`DELETE FROM engagements WHERE name LIKE 'Report %Test%' OR name LIKE 'Client Type Test%'`);
  console.log('Deleted test engagements:', r4.affectedRows);
  
  // Delete test engagement reports
  const [r5] = await conn.execute(`DELETE FROM engagement_reports WHERE preparedFor LIKE '%Test Corp%' OR title LIKE '%Test%'`);
  console.log('Deleted test reports:', r5.affectedRows);
  
  // Verify remaining
  const [scans] = await conn.execute('SELECT COUNT(*) as c FROM domain_intel_scans');
  console.log('Remaining scans:', scans[0].c);
  const [monitors] = await conn.execute('SELECT COUNT(*) as c FROM osint_monitors');
  console.log('Remaining monitors:', monitors[0].c);
  const [engagements] = await conn.execute('SELECT COUNT(*) as c FROM engagements');
  console.log('Remaining engagements:', engagements[0].c);
  
  // Show remaining scan domains
  const [remaining] = await conn.execute('SELECT id, primaryDomain, status FROM domain_intel_scans ORDER BY id DESC');
  console.table(remaining);
  
  await conn.end();
}

main().catch(console.error);
