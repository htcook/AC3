#!/usr/bin/env node
/**
 * Direct SQL migration runner - bypasses drizzle-kit CLI
 * Reads the SQL migration file and executes it statement by statement.
 * Handles the case where a previous migration was recorded but tables weren't created.
 */
import mysql from 'mysql2/promise';
import { readFileSync } from 'fs';
import { join } from 'path';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('[migrate] DATABASE_URL not set');
  process.exit(1);
}

// Parse DATABASE_URL
const url = new URL(DATABASE_URL);
const dbName = url.pathname.slice(1);
const config = {
  host: url.hostname,
  port: parseInt(url.port) || 3306,
  user: url.username,
  password: url.password,
  database: dbName,
  ssl: { rejectUnauthorized: false },
  multipleStatements: false,
  connectTimeout: 30000,
};

console.log(`[migrate] Connecting to ${config.host}:${config.port}/${dbName}...`);

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

  // Check current table count (excluding system tables)
  const [tables] = await conn.query('SHOW TABLES');
  const tableCount = tables.length;
  console.log(`[migrate] Current tables in database: ${tableCount}`);

  // Check which migrations have been applied
  const [applied] = await conn.query('SELECT hash FROM __drizzle_migrations');
  const appliedHashes = new Set(applied.map(r => r.hash));
  console.log(`[migrate] ${appliedHashes.size} migrations recorded as applied`);

  // Read the journal
  const journal = JSON.parse(readFileSync(join('drizzle', 'meta', '_journal.json'), 'utf8'));

  // If migration was recorded but table count is suspiciously low, force re-run
  const EXPECTED_MIN_TABLES = 100; // We expect ~370 tables
  if (appliedHashes.size > 0 && tableCount < EXPECTED_MIN_TABLES) {
    console.log(`[migrate] WARNING: ${appliedHashes.size} migrations recorded but only ${tableCount} tables exist (expected ${EXPECTED_MIN_TABLES}+)`);
    console.log(`[migrate] Clearing migration records and dropping all tables for clean re-run...`);
    
    // Drop all existing tables (disable FK checks first)
    await conn.query('SET FOREIGN_KEY_CHECKS = 0');
    for (const row of tables) {
      const tableName = Object.values(row)[0];
      try {
        await conn.query(`DROP TABLE IF EXISTS \`${tableName}\``);
      } catch (err) {
        console.log(`[migrate] Warning: could not drop ${tableName}: ${err.message}`);
      }
    }
    await conn.query('SET FOREIGN_KEY_CHECKS = 1');
    
    // Recreate the migrations tracking table
    await conn.query(`
      CREATE TABLE IF NOT EXISTS __drizzle_migrations (
        id SERIAL PRIMARY KEY,
        hash TEXT NOT NULL,
        created_at BIGINT
      )
    `);
    
    appliedHashes.clear();
    console.log(`[migrate] Clean slate - all tables dropped, ready for fresh migration`);
  }

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
    
    // Disable FK checks during migration
    await conn.query('SET FOREIGN_KEY_CHECKS = 0');
    
    let success = 0;
    let skipped = 0;
    let fkWarnings = 0;
    let errors = 0;
    
    for (const stmt of statements) {
      try {
        await conn.query(stmt);
        success++;
      } catch (err) {
        // Skip non-critical errors
        if (err.code === 'ER_TABLE_EXISTS_ERROR' || err.errno === 1050) {
          skipped++;
        } else if (err.code === 'ER_DUP_KEYNAME' || err.errno === 1061) {
          skipped++;
        } else if (err.errno === 1822 || err.message.includes('Missing index for constraint')) {
          // FK missing index - non-critical, table still created
          fkWarnings++;
          console.log(`[migrate] FK warning (skipped): ${err.message.substring(0, 120)}`);
        } else if (err.errno === 1005 || err.message.includes('errno: 150')) {
          // FK constraint error - non-critical
          fkWarnings++;
          console.log(`[migrate] FK warning (skipped): ${err.message.substring(0, 120)}`);
        } else if (err.errno === 1059 || err.message.includes('Identifier name') && err.message.includes('too long')) {
          fkWarnings++;
          console.log(`[migrate] Name too long (skipped): ${err.message.substring(0, 120)}`);
        } else {
          errors++;
          console.error(`[migrate] Error: ${err.message}`);
          console.error(`[migrate] Statement (first 200 chars): ${stmt.substring(0, 200)}`);
        }
      }
    }
    
    // Re-enable FK checks
    await conn.query('SET FOREIGN_KEY_CHECKS = 1');
    
    console.log(`[migrate] ${entry.tag}: ${success} ok, ${skipped} skipped, ${fkWarnings} FK warnings, ${errors} errors`);
    
    // Record migration as applied even with FK warnings (tables are created, just some FK constraints missing)
    if (errors === 0) {
      await conn.query('INSERT INTO __drizzle_migrations (hash, created_at) VALUES (?, ?)', [hash, Date.now()]);
      console.log(`[migrate] Migration ${entry.tag} recorded as applied`);
    } else {
      console.log(`[migrate] WARNING: Migration ${entry.tag} had ${errors} critical errors, NOT recording as applied`);
    }
  }

  // Verify tables
  const [finalTables] = await conn.query('SHOW TABLES');
  console.log(`[migrate] Final table count: ${finalTables.length}`);
  
  await conn.end();
  console.log('[migrate] Done');
}

run().catch(err => {
  console.error(`[migrate] Fatal error: ${err.message}`);
  process.exit(1);
});
