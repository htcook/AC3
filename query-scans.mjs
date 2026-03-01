import { getDb } from "./server/db.ts";
import { domainIntelScans } from "./drizzle/schema.ts";
import { desc, sql } from "drizzle-orm";

const db = await getDb();
if (!db) { console.error("No DB connection"); process.exit(1); }

const scans = await db.select({
  id: domainIntelScans.id,
  domain: domainIntelScans.primaryDomain,
  status: domainIntelScans.status,
  assets: domainIntelScans.totalAssets,
  risk: domainIntelScans.overallRiskScore,
}).from(domainIntelScans).orderBy(desc(domainIntelScans.id)).limit(15);

console.table(scans);

const total = await db.select({ count: sql`COUNT(*)` }).from(domainIntelScans);
console.log("Total scans:", total[0].count);

process.exit(0);
