import { getDb } from "./server/db.ts";
import { domainIntelScans } from "./drizzle/schema.ts";
import { desc, sql, not, like, and, or } from "drizzle-orm";

const db = await getDb();
if (!db) { console.error("No DB connection"); process.exit(1); }

const realScans = await db.select({
  id: domainIntelScans.id,
  domain: domainIntelScans.primaryDomain,
  status: domainIntelScans.status,
}).from(domainIntelScans)
  .where(and(
    not(like(domainIntelScans.primaryDomain, '%177%')),
    not(like(domainIntelScans.primaryDomain, 'msp-%')),
    not(like(domainIntelScans.primaryDomain, 'enterprise-%')),
    not(like(domainIntelScans.primaryDomain, 'saas-%')),
    not(like(domainIntelScans.primaryDomain, 'paas-%')),
    not(like(domainIntelScans.primaryDomain, 'iaas-%')),
    not(like(domainIntelScans.primaryDomain, 'mixed_hosting-%')),
    not(like(domainIntelScans.primaryDomain, 'other-%')),
  ))
  .orderBy(desc(domainIntelScans.id));

console.log("Total real scans:", realScans.length);
const domains = [...new Set(realScans.map(s => s.domain))];
console.log("Unique domains:", domains.length);
domains.forEach(d => console.log(" ", d));

// Show the last 10 real scans (most recent by ID)
console.log("\n=== LAST 10 REAL SCANS (to keep) ===");
const last10 = realScans.slice(0, 10);
last10.forEach(s => console.log(`  ID ${s.id}: ${s.domain} [${s.status}]`));

console.log("\n=== SCANS TO DELETE ===");
const toDelete = realScans.slice(10);
console.log(`  ${toDelete.length} older real scans`);

process.exit(0);
