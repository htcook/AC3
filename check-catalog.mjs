import { getDb } from './server/db.ts';
import { unifiedExploitCatalog } from './drizzle/schema.ts';
import { sql } from 'drizzle-orm';

async function main() {
  const db = await getDb();
  if (!db) { console.log('DB connection failed'); process.exit(1); }
  
  const total = await db.select({ count: sql`count(*)` }).from(unifiedExploitCatalog);
  const bySource = await db.select({ 
    source: unifiedExploitCatalog.source, 
    count: sql`count(*)` 
  }).from(unifiedExploitCatalog).groupBy(unifiedExploitCatalog.source);
  
  console.log('Total catalog entries:', total[0].count);
  console.log('By source:');
  for (const r of bySource) {
    console.log(`  ${r.source}: ${r.count}`);
  }
  process.exit(0);
}

main();
