#!/usr/bin/env node
/**
 * Direct SQL migration runner - bypasses drizzle-kit CLI
 * Reads the SQL migration file and executes it statement by statement
 */
import mysql from 'mysql2/promise';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('[migrate] DATABASE_URL not set');
  process.exit(1);
}

// Parse DATABASE_URL
const url = new URL(DATABASE_URL);
const config = {
  host: url.hostname,
  port: parseInt(url.port) || 3306,
  user: url.username,
  password: url.password,
  database: url.pathname.slice(1),
  ssl: { rejectUnauthorized: false },
  multipleStatements: false,
  connectTimeout: 30000,
};

console.log(`[migrate] Connecting to ${config.host}:${config.port}/${config.database}...`);

async function run() {
  const conn = await mysql.createConnection(config);
  console.log('[migrate] Connected successfully');

  // Create migrations tracking table if not exists
  await conn.query(`
    CREATE TABLE IF NOT EXISTS __drizzle_migrations (
      id SERIAL PRIMARY KEY,
      hash TEXT NOT NULL,
      created_at BIGINT
    )
  `);

  // Check which migrations have been applied
  const [applied] = await conn.query('SELECT hash FROM __drizzle_migrations');
  const appliedHashes = new Set(applied.map(r => r.hash));
  console.log(`[migrate] ${appliedHashes.size} migrations already applied`);

  // Read the journal
  const journal = JSON.parse(readFileSync(join('drizzle', 'meta', '_journal.json'), 'utf8'));
  
  for (const entry of journal.entries) {
    const sqlFile = join('drizzle', `${entry.tag}.sql`);
    const hash = entry.tag;
    
    if (appliedHashes.has(hash)) {
      console.log(`[migrate] Skipping ${entry.tag} (already applied)`);
      continue;
    }

    console.log(`[migrate] Applying ${entry.tag}...`);
    const sql = readFileSync(sqlFile, 'utf8');
    
    // Split by statement breakpoint marker
    const statements = sql.split('--> statement-breakpoint')
      .map(s => s.trim())
      .filter(s => s.length > 0);
    
    console.log(`[migrate] ${statements.length} statements to execute`);
    
    let success = 0;
    let skipped = 0;
    let errors = 0;
    
    for (const stmt of statements) {
      try {
        await conn.query(stmt);
        success++;
      } catch (err) {
        if (err.code === 'ER_TABLE_EXISTS_ERROR' || err.errno === 1050) {
          skipped++;
        } else if (err.code === 'ER_DUP_KEYNAME' || err.errno === 1061) {
          skipped++;
        } else {
          errors++;
          console.error(`[migrate] Error executing statement: ${err.message}`);
          console.error(`[migrate] Statement (first 200 chars): ${stmt.substring(0, 200)}`);
        }
      }
    }
    
    console.log(`[migrate] ${entry.tag}: ${success} ok, ${skipped} skipped (already exist), ${errors} errors`);
    
    // Record migration as applied
    await conn.query('INSERT INTO __drizzle_migrations (hash, created_at) VALUES (?, ?)', [hash, Date.now()]);
  }

  // Verify tables
  const [tables] = await conn.query('SHOW TABLES');
  console.log(`[migrate] Total tables in database: ${tables.length}`);
  
  await conn.end();
  console.log('[migrate] Done');
}

run().catch(err => {
  console.error(`[migrate] Fatal error: ${err.message}`);
  process.exit(1);
});
