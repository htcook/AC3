import mysql from 'mysql2/promise';

// Read DATABASE_URL from process env (passed via command line)
const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
  console.error("DATABASE_URL not set");
  process.exit(1);
}

const conn = await mysql.createConnection({
  uri: dbUrl,
  ssl: { rejectUnauthorized: true },
});

const [rows] = await conn.execute(
  `SELECT id, name, customerName, status, engagementType, targetDomain, targetIpRange, roe_status 
   FROM engagements ORDER BY id LIMIT 30`
);
console.log("=== First 30 engagements ===");
for (const r of rows) {
  console.log(`ID:${r.id} | "${r.name}" | customer="${r.customerName}" | status=${r.status} | roe=${r.roe_status} | domain=${r.targetDomain || 'none'}`);
}

const [counts] = await conn.execute(
  `SELECT customerName, COUNT(*) as cnt FROM engagements GROUP BY customerName ORDER BY cnt DESC`
);
console.log("\n=== Customer counts ===");
for (const r of counts) {
  console.log(`  ${r.customerName}: ${r.cnt}`);
}

const [total] = await conn.execute(`SELECT COUNT(*) as total FROM engagements`);
console.log(`\nTotal engagements: ${total[0].total}`);

await conn.end();
