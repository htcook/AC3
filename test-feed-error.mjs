// Test each feed individually to find which one throws "string did not match the expected pattern"
import { getVulnFeedStats, getRecentZeroDays, getWeaponizedCves } from './server/lib/vuln-feeds.ts';

async function testFeed(name, fn) {
  console.log(`\n=== Testing ${name} ===`);
  try {
    const result = await fn();
    console.log(`✅ ${name}: OK`);
    if (result?.totalCves !== undefined) console.log(`   Total CVEs: ${result.totalCves}`);
    if (Array.isArray(result)) console.log(`   Entries: ${result.length}`);
    return true;
  } catch (err) {
    console.log(`❌ ${name}: FAILED`);
    console.log(`   Error: ${err.message}`);
    console.log(`   Stack: ${err.stack?.split('\n').slice(0, 5).join('\n')}`);
    return false;
  }
}

async function main() {
  console.log('Testing individual feed fetchers...\n');
  
  // Test individual fetchers
  try {
    const { fetchKevCatalog, fetchProjectZero, fetchNvdRecent, fetchCirclRecent, fetchExploitDb } = await import('./server/lib/vuln-feeds.ts');
    
    await testFeed('CISA KEV', fetchKevCatalog);
    await testFeed('Project Zero', fetchProjectZero);
    await testFeed('NVD Recent', () => fetchNvdRecent(30));
    await testFeed('CIRCL Recent', fetchCirclRecent);
    await testFeed('ExploitDB', fetchExploitDb);
  } catch (err) {
    console.log('Failed to import individual fetchers:', err.message);
  }
  
  console.log('\n\nTesting composite endpoints...\n');
  
  await testFeed('getVulnFeedStats', getVulnFeedStats);
  await testFeed('getRecentZeroDays', () => getRecentZeroDays(50));
  await testFeed('getWeaponizedCves', () => getWeaponizedCves(50));
  
  // Also test IOC feed
  try {
    const { listIocs, getIocStats } = await import('./server/lib/ioc-feeds.ts');
    await testFeed('IOC listIocs', () => listIocs({}));
    await testFeed('IOC getIocStats', getIocStats);
  } catch (err) {
    console.log('Failed to import IOC feeds:', err.message);
  }
  
  process.exit(0);
}

main();
