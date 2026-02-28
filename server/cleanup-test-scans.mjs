/**
 * Cleanup script to delete test scan records from domain_intel_scans
 * These are auto-generated scans with timestamp-based domain names
 */
import { createRequire } from 'module';

// Use tsx to run this with proper TypeScript support
async function main() {
  // Dynamic import of the db module
  const { getDomainIntelScans, deleteDomainIntelScan } = await import('./db.ts');
  
  const allScans = await getDomainIntelScans();
  console.log(`Total scans in database: ${allScans.length}`);
  
  // Pattern: domains like "enterprise-1772241007822.com", "saas-1772241007834.com", etc.
  const testPattern = /^(enterprise|msp|saas|paas|iaas|mixed_hosting|other)-\d{10,}\./;
  
  const testScans = allScans.filter(s => testPattern.test(s.primaryDomain));
  console.log(`Test scans found: ${testScans.length}`);
  
  if (testScans.length === 0) {
    console.log('No test scans to delete.');
    process.exit(0);
  }
  
  console.log('Test scan domains:');
  testScans.forEach(s => console.log(`  [${s.id}] ${s.primaryDomain} (${s.status})`));
  
  // Delete each test scan
  let deleted = 0;
  for (const scan of testScans) {
    try {
      await deleteDomainIntelScan(scan.id);
      deleted++;
      console.log(`  Deleted scan ${scan.id}: ${scan.primaryDomain}`);
    } catch (err) {
      console.error(`  Failed to delete scan ${scan.id}: ${err.message}`);
    }
  }
  
  console.log(`\nDeleted ${deleted}/${testScans.length} test scans.`);
  
  // Verify
  const remaining = await getDomainIntelScans();
  const remainingTest = remaining.filter(s => testPattern.test(s.primaryDomain));
  console.log(`Remaining total scans: ${remaining.length}`);
  console.log(`Remaining test scans: ${remainingTest.length}`);
  
  process.exit(0);
}

main().catch(err => {
  console.error('Cleanup failed:', err);
  process.exit(1);
});
