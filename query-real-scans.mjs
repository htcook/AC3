import { getDb } from "./server/db.ts";
import { domainIntelScans } from "./drizzle/schema.ts";
import { desc, sql, not, like, and, or } from "drizzle-orm";

const db = await getDb();
if (!db) { console.error("No DB connection"); process.exit(1); }

// Find real scans - exclude test domains with timestamps in the name
const realScans = await db.select({
  id: domainIntelScans.id,
  domain: domainIntelScans.primaryDomain,
  status: domainIntelScans.status,
  assets: domainIntelScans.totalAssets,
  findings: domainIntelScans.totalFindings,
  risk: domainIntelScans.overallRiskScore,
  sector: domainIntelScans.sector,
}).from(domainIntelScans)
  .where(
    and(
      not(like(domainIntelScans.primaryDomain, '%177%')),
      not(like(domainIntelScans.primaryDomain, 'msp-%')),
      not(like(domainIntelScans.primaryDomain, 'enterprise-%')),
      not(like(domainIntelScans.primaryDomain, 'saas-%')),
      not(like(domainIntelScans.primaryDomain, 'paas-%')),
      not(like(domainIntelScans.primaryDomain, 'iaas-%')),
      not(like(domainIntelScans.primaryDomain, 'mixed_hosting-%')),
      not(like(domainIntelScans.primaryDomain, 'other-%')),
    )
  )
  .orderBy(desc(domainIntelScans.id))
  .limit(30);

console.log("=== Real Domain Scans (most recent 30) ===");
console.table(realScans);
console.log("Real scan count:", realScans.length);

// Also count test scans
const testCount = await db.select({ count: sql`COUNT(*)` }).from(domainIntelScans)
  .where(
    or(
      like(domainIntelScans.primaryDomain, '%177%'),
      like(domainIntelScans.primaryDomain, 'msp-%'),
      like(domainIntelScans.primaryDomain, 'enterprise-%'),
      like(domainIntelScans.primaryDomain, 'saas-%'),
      like(domainIntelScans.primaryDomain, 'paas-%'),
      like(domainIntelScans.primaryDomain, 'iaas-%'),
      like(domainIntelScans.primaryDomain, 'mixed_hosting-%'),
      like(domainIntelScans.primaryDomain, 'other-%'),
    )
  );
console.log("Test/generated scans:", testCount[0].count);

process.exit(0);
