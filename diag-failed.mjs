import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
dotenv.config();

const conn = await mysql.createConnection(process.env.DATABASE_URL);

// All scans
const [scans] = await conn.execute('SELECT id, status, primaryDomain, overallRiskScore, totalAssets, totalFindings, updatedAt FROM domain_intel_scans ORDER BY id DESC LIMIT 10');
console.log('\n=== Recent Scans ===');
for (const s of scans) {
  console.log(`  #${s.id} [${s.status}] ${s.primaryDomain} — risk=${s.overallRiskScore}, assets=${s.totalAssets}, findings=${s.totalFindings}, updated=${s.updatedAt}`);
}

// Failed scans with error
const [failed] = await conn.execute("SELECT id, primaryDomain, pipelineOutput FROM domain_intel_scans WHERE status = 'failed' ORDER BY id DESC LIMIT 3");
if (failed.length > 0) {
  console.log('\n=== Failed Scans ===');
  for (const f of failed) {
    const po = typeof f.pipelineOutput === 'string' ? JSON.parse(f.pipelineOutput) : f.pipelineOutput;
    console.log(`  #${f.id} ${f.primaryDomain}`);
    console.log(`    Error: ${po?.error || 'unknown'}`);
    console.log(`    Stack: ${(po?.stack || '').substring(0, 300)}`);
    console.log(`    Failed at: ${po?.failedAt || 'unknown'}`);
  }
}

// Stuck scans (in-progress for > 15 min)
const [stuck] = await conn.execute("SELECT id, status, primaryDomain, updatedAt FROM domain_intel_scans WHERE status IN ('passive_recon','discovering','analyzing','scoring','recommending') AND updatedAt < DATE_SUB(NOW(), INTERVAL 15 MINUTE) ORDER BY id DESC LIMIT 5");
if (stuck.length > 0) {
  console.log('\n=== Stuck Scans ===');
  for (const s of stuck) {
    console.log(`  #${s.id} [${s.status}] ${s.primaryDomain} — last updated ${s.updatedAt}`);
  }
}

// Check discovered_assets count per scan for recent scans
const [assetCounts] = await conn.execute('SELECT scanId, COUNT(*) as cnt FROM discovered_assets GROUP BY scanId ORDER BY scanId DESC LIMIT 10');
console.log('\n=== Asset Counts per Scan ===');
for (const a of assetCounts) {
  console.log(`  Scan #${a.scanId}: ${a.cnt} assets`);
}

await conn.end();
