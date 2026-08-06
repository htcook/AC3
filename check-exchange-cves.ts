import { getDb } from './server/db.ts';
import { discoveredAssets } from './drizzle/schema.ts';
import { like } from 'drizzle-orm';

const db = (await getDb())!;

// Check outlook.com asset findings
const assets = await db.select().from(discoveredAssets).where(like(discoveredAssets.hostname, '%outlook%'));
for (const a of assets) {
  const findings = JSON.parse(a.postureFindings || '[]');
  console.log(`\n=== Asset: ${a.hostname} (${findings.length} findings) ===`);
  for (const f of findings) {
    const cve = f.cveIds?.[0] || f.title?.match(/CVE-\d+-\d+/)?.[0] || 'none';
    console.log(`  CVE: ${cve}`);
    console.log(`    versionMatchConfirmed: ${f.versionMatchConfirmed}`);
    console.log(`    detectedVersion: ${f.detectedVersion}`);
    console.log(`    corroborationTier: ${f.corroborationTier}`);
    console.log(`    evidenceBasis: ${f.evidenceBasis}`);
    console.log(`    severity: ${f.severity}`);
    console.log(`    source: ${f.source}`);
  }
}

// Also check all assets for Exchange-related findings
console.log('\n\n=== All Exchange-related findings across all assets ===');
const allAssets = await db.select().from(discoveredAssets);
for (const a of allAssets) {
  const findings = JSON.parse(a.postureFindings || '[]');
  const exchangeFindings = findings.filter((f: any) => {
    const title = (f.title || f.finding || '').toLowerCase();
    return title.includes('exchange') || title.includes('outlook');
  });
  if (exchangeFindings.length > 0) {
    console.log(`\n  Asset: ${a.hostname} (${exchangeFindings.length} Exchange findings)`);
    for (const f of exchangeFindings) {
      const cve = f.cveIds?.[0] || f.title?.match(/CVE-\d+-\d+/)?.[0] || 'none';
      console.log(`    ${cve}: versionConfirmed=${f.versionMatchConfirmed}, version=${f.detectedVersion}, tier=${f.corroborationTier}, basis=${f.evidenceBasis}`);
    }
  }
}

process.exit(0);
