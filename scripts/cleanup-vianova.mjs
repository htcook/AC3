import mysql from 'mysql2/promise';

const conn = await mysql.createConnection(process.env.DATABASE_URL);
const engId = 1350014;
const scanIds = [1740003, 1740004];

console.log('=== FINDING ALL RELATED DATA ===\n');

// Check all tables that might reference domain_intel_scans or the engagement
const relatedTables = [
  ['domain_intel_results', 'domainIntelScanId'],
  ['domain_intel_results', 'domain_intel_scan_id'],
  ['pipeline_runs', 'domainIntelScanId'],
  ['pipeline_runs', 'domain_intel_scan_id'],
  ['pipeline_findings', 'domainIntelScanId'],
  ['pipeline_findings', 'domain_intel_scan_id'],
  ['discovery_chain_runs', 'domainIntelScanId'],
  ['discovery_chain_runs', 'domain_intel_scan_id'],
  ['discovery_chain_stages', 'domainIntelScanId'],
  ['discovery_chain_stages', 'domain_intel_scan_id'],
  ['accuracy_validations', 'domainIntelScanId'],
  ['accuracy_validations', 'domain_intel_scan_id'],
  ['carver_risk_cards', 'domainIntelScanId'],
  ['carver_risk_cards', 'domain_intel_scan_id'],
  ['osint_findings', 'engagementId'],
  ['osint_recon_scans', 'engagementId'],
  ['engagement_findings', 'engagementId'],
  ['engagement_reports', 'engagementId'],
  ['engagement_timeline_events', 'engagementId'],
  ['engagement_shares', 'engagementId'],
  ['campaign_engagements', 'engagementId'],
  ['ssil_observations', 'engagementId'],
  ['nmap_scans', 'engagementId'],
  ['nmap_scan_results', 'engagementId'],
  ['nuclei_scans', 'engagementId'],
  ['nuclei_results', 'engagementId'],
  ['dast_scans', 'engagementId'],
  ['dast_findings', 'engagementId'],
  ['amass_scans', 'engagementId'],
  ['amass_results', 'engagementId'],
];

const toDelete = [];

for (const [table, col] of relatedTables) {
  try {
    const refIds = col.includes('engagementId') ? [engId] : scanIds;
    const placeholders = refIds.map(() => '?').join(',');
    const [rows] = await conn.execute(
      `SELECT COUNT(*) as cnt FROM \`${table}\` WHERE \`${col}\` IN (${placeholders})`,
      refIds
    );
    if (rows[0].cnt > 0) {
      console.log(`  ${table}.${col}: ${rows[0].cnt} rows`);
      toDelete.push({ table, col, ids: refIds, count: rows[0].cnt });
    }
  } catch (e) {
    // Table or column doesn't exist, skip
  }
}

console.log(`\n=== DELETING ${toDelete.length} table groups ===\n`);

// Delete in reverse dependency order (children first)
// First delete scan-related data, then engagement-related data
for (const { table, col, ids, count } of toDelete) {
  if (table === 'engagement_reports' || table === 'domain_intel_scans') continue; // delete last
  try {
    const placeholders = ids.map(() => '?').join(',');
    const [result] = await conn.execute(
      `DELETE FROM \`${table}\` WHERE \`${col}\` IN (${placeholders})`,
      ids
    );
    console.log(`  Deleted ${result.affectedRows} rows from ${table}`);
  } catch (e) {
    console.log(`  Error deleting from ${table}: ${e.message}`);
  }
}

// Delete engagement reports
try {
  const [result] = await conn.execute(
    'DELETE FROM engagement_reports WHERE engagementId = ?',
    [engId]
  );
  console.log(`  Deleted ${result.affectedRows} rows from engagement_reports`);
} catch (e) {
  console.log(`  Error deleting from engagement_reports: ${e.message}`);
}

// Delete domain intel scans last
try {
  const [result] = await conn.execute(
    'DELETE FROM domain_intel_scans WHERE id IN (?, ?)',
    scanIds
  );
  console.log(`  Deleted ${result.affectedRows} rows from domain_intel_scans`);
} catch (e) {
  console.log(`  Error deleting from domain_intel_scans: ${e.message}`);
}

// Verify engagement still exists
const [eng] = await conn.execute('SELECT id, name, status FROM engagements WHERE id = ?', [engId]);
console.log(`\n=== VERIFICATION ===`);
console.log(`Engagement preserved: ${eng.length > 0 ? 'YES' : 'NO'} - ${eng[0]?.name} (${eng[0]?.status})`);

// Verify scans are gone
const [scans] = await conn.execute('SELECT COUNT(*) as cnt FROM domain_intel_scans WHERE engagementId = ?', [engId]);
console.log(`Remaining scans: ${scans[0].cnt}`);

// Verify reports are gone
const [reports] = await conn.execute('SELECT COUNT(*) as cnt FROM engagement_reports WHERE engagementId = ?', [engId]);
console.log(`Remaining reports: ${reports[0].cnt}`);

await conn.end();
console.log('\nDone! Engagement is clean and ready for fresh discovery.');
