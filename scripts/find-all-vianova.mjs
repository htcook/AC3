import mysql from 'mysql2/promise';

const conn = await mysql.createConnection(process.env.DATABASE_URL);
const engId = 1350014;
const scanIds = [1740003, 1740004];

console.log('=== EXHAUSTIVE SEARCH FOR VIANOVA DATA ===\n');

// Get ALL tables in the database
const [allTables] = await conn.execute(
  "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'"
);

console.log(`Total tables in database: ${allTables.length}\n`);

// For each table, check ALL columns that could reference the engagement or scans
for (const { TABLE_NAME: table } of allTables) {
  const [columns] = await conn.execute(
    "SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND TABLE_SCHEMA = DATABASE()",
    [table]
  );

  for (const { COLUMN_NAME: col, DATA_TYPE: dtype } of columns) {
    // Check for engagement ID references
    if (col.toLowerCase().includes('engagement') && (dtype === 'int' || dtype === 'bigint')) {
      try {
        const [rows] = await conn.execute(
          `SELECT COUNT(*) as cnt FROM \`${table}\` WHERE \`${col}\` = ?`, [engId]
        );
        if (rows[0].cnt > 0) {
          console.log(`FOUND: ${table}.${col} = ${engId} → ${rows[0].cnt} rows`);
        }
      } catch (e) {}
    }

    // Check for scan ID references
    if ((col.toLowerCase().includes('scan') || col.toLowerCase().includes('domain_intel')) && (dtype === 'int' || dtype === 'bigint')) {
      try {
        const [rows] = await conn.execute(
          `SELECT COUNT(*) as cnt FROM \`${table}\` WHERE \`${col}\` IN (?, ?)`, scanIds
        );
        if (rows[0].cnt > 0) {
          console.log(`FOUND: ${table}.${col} IN (${scanIds}) → ${rows[0].cnt} rows`);
        }
      } catch (e) {}
    }

    // Check for Vianova text references in varchar/text columns
    if (['varchar', 'text', 'longtext', 'mediumtext'].includes(dtype) && 
        (col.toLowerCase().includes('domain') || col.toLowerCase().includes('name') || col.toLowerCase().includes('target') || col.toLowerCase().includes('url'))) {
      try {
        const [rows] = await conn.execute(
          `SELECT COUNT(*) as cnt FROM \`${table}\` WHERE \`${col}\` LIKE '%vianova%'`, []
        );
        if (rows[0].cnt > 0) {
          console.log(`FOUND: ${table}.${col} LIKE '%vianova%' → ${rows[0].cnt} rows`);
        }
      } catch (e) {}
    }
  }
}

// Also check for JSON columns that might contain vianova data
console.log('\n=== CHECKING JSON COLUMNS FOR VIANOVA REFERENCES ===\n');
for (const { TABLE_NAME: table } of allTables) {
  const [columns] = await conn.execute(
    "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND TABLE_SCHEMA = DATABASE() AND DATA_TYPE = 'json'",
    [table]
  );
  for (const { COLUMN_NAME: col } of columns) {
    try {
      const [rows] = await conn.execute(
        `SELECT COUNT(*) as cnt FROM \`${table}\` WHERE JSON_CONTAINS(LOWER(CAST(\`${col}\` AS CHAR)), '"vianova"') OR CAST(\`${col}\` AS CHAR) LIKE '%vianova%'`, []
      );
      if (rows[0].cnt > 0) {
        console.log(`FOUND JSON: ${table}.${col} contains 'vianova' → ${rows[0].cnt} rows`);
      }
    } catch (e) {
      // Try simpler approach
      try {
        const [rows] = await conn.execute(
          `SELECT COUNT(*) as cnt FROM \`${table}\` WHERE CAST(\`${col}\` AS CHAR) LIKE '%vianova%'`, []
        );
        if (rows[0].cnt > 0) {
          console.log(`FOUND JSON: ${table}.${col} contains 'vianova' → ${rows[0].cnt} rows`);
        }
      } catch (e2) {}
    }
  }
}

// Double-check domain_intel_scans is really empty
const [remaining] = await conn.execute('SELECT COUNT(*) as cnt FROM domain_intel_scans WHERE engagementId = ?', [engId]);
console.log(`\n=== VERIFICATION ===`);
console.log(`domain_intel_scans for engagement ${engId}: ${remaining[0].cnt} rows`);

await conn.end();
