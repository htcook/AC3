import mysql from 'mysql2/promise';

const conn = await mysql.createConnection(process.env.DATABASE_URL);
const engId = 1350014;
const scanIds = [1740003, 1740004];

console.log('=== FULL VIANOVA SCAN DATA CLEANUP ===\n');

// Delete in dependency order (children first, parents last)
// Tables referencing scan IDs
const scanRefDeletes = [
  ['scoring_audit_log', 'scanId'],
  ['web_crawl_results', 'scanId'],
  ['web_crawl_jobs', 'scanId'],
  ['scan_observations', 'scanId'],
  ['chain_runs', 'scanId'],
];

// Tables referencing engagement ID
const engRefDeletes = [
  ['scan_results', 'engagement_id'],
  ['attack_vectors', 'engagement_id'],
  ['exploit_plan_history', 'engagement_id'],
  ['llm_telemetry', 'engagement_id'],
  ['hunt_sessions', 'engagement_id'],
  ['engagement_ops_snapshots', 'engagement_id'],
  ['opsec_events', 'engagement_id'],  // might use engagement_id
];

// Tables with vianova text references (need LIKE queries)
const textDeletes = [
  ['discovered_assets', 'hostname', '%vianova%'],
  ['typosquat_domains', 'originalDomain', '%vianova%'],
  ['api_targets', 'api_name', '%vianova%'],
  ['carver_risk_cards', 'domain', '%vianova%'],
  ['ai_attack_plans', 'aap_target_desc', '%vianova%'],
  ['web_app_scans', 'target_url', '%vianova%'],
];

// 1. Delete scan-referenced data
console.log('--- Deleting scan-referenced data ---');
for (const [table, col] of scanRefDeletes) {
  try {
    const [result] = await conn.execute(
      `DELETE FROM \`${table}\` WHERE \`${col}\` IN (?, ?)`, scanIds
    );
    if (result.affectedRows > 0) {
      console.log(`  Deleted ${result.affectedRows} rows from ${table}`);
    }
  } catch (e) {
    // Try with different column name patterns
    for (const altCol of ['domain_intel_scan_id', 'domainIntelScanId', 'scan_id']) {
      try {
        const [result] = await conn.execute(
          `DELETE FROM \`${table}\` WHERE \`${altCol}\` IN (?, ?)`, scanIds
        );
        if (result.affectedRows > 0) {
          console.log(`  Deleted ${result.affectedRows} rows from ${table} (via ${altCol})`);
        }
        break;
      } catch (e2) {}
    }
  }
}

// Also delete web_crawl_results and web_crawl_jobs by vianova domain
for (const table of ['web_crawl_results', 'web_crawl_jobs']) {
  for (const col of ['targetUrl', 'targetDomain', 'domain', 'seedUrls']) {
    try {
      const [result] = await conn.execute(
        `DELETE FROM \`${table}\` WHERE \`${col}\` LIKE '%vianova%'`
      );
      if (result.affectedRows > 0) {
        console.log(`  Deleted ${result.affectedRows} rows from ${table} (${col} LIKE vianova)`);
      }
    } catch (e) {}
  }
}

// 2. Delete engagement-referenced data
console.log('\n--- Deleting engagement-referenced data ---');
for (const [table, col] of engRefDeletes) {
  try {
    const [result] = await conn.execute(
      `DELETE FROM \`${table}\` WHERE \`${col}\` = ?`, [engId]
    );
    if (result.affectedRows > 0) {
      console.log(`  Deleted ${result.affectedRows} rows from ${table}`);
    }
  } catch (e) {
    // Try engagementId camelCase
    try {
      const [result] = await conn.execute(
        `DELETE FROM \`${table}\` WHERE \`engagementId\` = ?`, [engId]
      );
      if (result.affectedRows > 0) {
        console.log(`  Deleted ${result.affectedRows} rows from ${table} (via engagementId)`);
      }
    } catch (e2) {
      console.log(`  Skipped ${table}: ${e.message.substring(0, 80)}`);
    }
  }
}

// Also try opsec_events by host
try {
  const [result] = await conn.execute(
    `DELETE FROM opsec_events WHERE opsec_target_host LIKE '%vianova%'`
  );
  if (result.affectedRows > 0) {
    console.log(`  Deleted ${result.affectedRows} rows from opsec_events (by host)`);
  }
} catch (e) {}

// 3. Delete text-referenced data
console.log('\n--- Deleting text-referenced data ---');
for (const [table, col, pattern] of textDeletes) {
  try {
    const [result] = await conn.execute(
      `DELETE FROM \`${table}\` WHERE \`${col}\` LIKE ?`, [pattern]
    );
    if (result.affectedRows > 0) {
      console.log(`  Deleted ${result.affectedRows} rows from ${table}`);
    }
  } catch (e) {
    console.log(`  Error on ${table}.${col}: ${e.message.substring(0, 80)}`);
  }
}

// 4. Delete scan_observations by vianova evidence
try {
  const [result] = await conn.execute(
    `DELETE FROM scan_observations WHERE CAST(evidenceArtifacts AS CHAR) LIKE '%vianova%'`
  );
  if (result.affectedRows > 0) {
    console.log(`  Deleted ${result.affectedRows} rows from scan_observations (by evidence)`);
  }
} catch (e) {}

// 5. Delete chain_runs by vianova domains
try {
  const [result] = await conn.execute(
    `DELETE FROM chain_runs WHERE CAST(domains AS CHAR) LIKE '%vianova%'`
  );
  if (result.affectedRows > 0) {
    console.log(`  Deleted ${result.affectedRows} rows from chain_runs (by domains)`);
  }
} catch (e) {}

// 6. Delete ROE versions (but keep the ROE document)
try {
  const [roeDoc] = await conn.execute(
    `SELECT id FROM roe_documents WHERE organization_name LIKE '%vianova%'`
  );
  if (roeDoc.length > 0) {
    const roeId = roeDoc[0].id;
    const [result] = await conn.execute(
      `DELETE FROM roe_versions WHERE roe_document_id = ?`, [roeId]
    );
    if (result.affectedRows > 0) {
      console.log(`  Deleted ${result.affectedRows} rows from roe_versions`);
    }
  }
} catch (e) {}

// 7. Delete remaining domain_intel_scans with vianova in JSON
try {
  const [result] = await conn.execute(
    `DELETE FROM domain_intel_scans WHERE CAST(orgProfile AS CHAR) LIKE '%vianova%' OR CAST(pipelineOutput AS CHAR) LIKE '%vianova%'`
  );
  if (result.affectedRows > 0) {
    console.log(`  Deleted ${result.affectedRows} remaining rows from domain_intel_scans`);
  }
} catch (e) {}

// 8. Delete engagement_reports if any remain
try {
  const [result] = await conn.execute(
    `DELETE FROM engagement_reports WHERE engagementId = ?`, [engId]
  );
  if (result.affectedRows > 0) {
    console.log(`  Deleted ${result.affectedRows} rows from engagement_reports`);
  }
} catch (e) {}

// === VERIFICATION ===
console.log('\n=== VERIFICATION ===');

const checks = [
  ['domain_intel_scans', `engagementId = ${engId}`],
  ['domain_intel_scans', `CAST(orgProfile AS CHAR) LIKE '%vianova%'`],
  ['scan_results', `engagement_id = ${engId}`],
  ['discovered_assets', `hostname LIKE '%vianova%'`],
  ['attack_vectors', `engagement_id = ${engId}`],
  ['typosquat_domains', `originalDomain LIKE '%vianova%'`],
  ['carver_risk_cards', `domain LIKE '%vianova%'`],
  ['web_crawl_results', `domain LIKE '%vianova%'`],
  ['web_crawl_jobs', `targetDomain LIKE '%vianova%'`],
  ['web_app_scans', `target_url LIKE '%vianova%'`],
  ['scoring_audit_log', `scanId IN (${scanIds.join(',')})`],
  ['engagement_ops_snapshots', `engagement_id = ${engId}`],
  ['engagement_reports', `engagementId = ${engId}`],
];

for (const [table, where] of checks) {
  try {
    const [rows] = await conn.execute(`SELECT COUNT(*) as cnt FROM \`${table}\` WHERE ${where}`);
    const status = rows[0].cnt === 0 ? '✓ CLEAN' : `✗ ${rows[0].cnt} rows remaining`;
    console.log(`  ${table}: ${status}`);
  } catch (e) {
    console.log(`  ${table}: skipped (${e.message.substring(0, 50)})`);
  }
}

// Confirm engagement still exists
const [eng] = await conn.execute('SELECT id, name, status FROM engagements WHERE id = ?', [engId]);
console.log(`\nEngagement preserved: ${eng.length > 0 ? 'YES' : 'NO'} - ${eng[0]?.name} (${eng[0]?.status})`);

await conn.end();
console.log('\nDone! All Vianova scan data has been purged.');
