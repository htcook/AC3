/**
 * AC3 Platform — Account Seeder
 * 
 * Creates all team accounts if they don't exist.
 * Run after migrations on first boot.
 * 
 * Required env vars:
 *   DATABASE_URL - MySQL connection string
 *   AC3_ADMIN_PASSWORD - Default password for all seeded accounts
 */
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';

const DATABASE_URL = process.env.DATABASE_URL;
const DEFAULT_PASSWORD = process.env.AC3_ADMIN_PASSWORD;

if (!DATABASE_URL) {
  console.log('[seed] DATABASE_URL not set, skipping account seed.');
  process.exit(0);
}

if (!DEFAULT_PASSWORD) {
  console.log('[seed] AC3_ADMIN_PASSWORD not set, skipping account seed.');
  process.exit(0);
}

// All accounts from DO production (aceofcloud.io)
const ACCOUNTS = [
  { email: 'harrison.cook@aceofcloud.com', name: 'Harrison Cook', role: 'admin' },
  { email: 'nathaniel.cook@aceofcloud.com', name: 'Nathaniel Cook', role: 'admin' },
  { email: 'jflem70@gmail.com', name: 'J. Fleming', role: 'admin' },
  { email: 'salman@aceofcloud.com', name: 'Salman', role: 'admin' },
  { email: 'josh.rector@aceofcloud.com', name: 'Josh Rector', role: 'admin' },
  { email: 'anwar@aceofcloud.com', name: 'Anwar', role: 'admin' },
  { email: 'ahmed@aceofcloud.com', name: 'Ahmed', role: 'admin' },
  { email: 'donjet.shabi@aceofcloud.com', name: 'Donjet Shabi', role: 'operator' },
  { email: 'rafael.gutierrez@aceofcloud.com', name: 'Rafael Gutierrez', role: 'operator' },
  { email: 'harrison.cook@gmail.com', name: 'Harrison Cook', role: 'operator' },
];

async function seed() {
  const url = new URL(DATABASE_URL.replace('mysql://', 'http://'));
  const connection = await mysql.createConnection({
    host: url.hostname,
    port: parseInt(url.port || '3306'),
    user: url.username,
    password: decodeURIComponent(url.password),
    database: url.pathname.slice(1),
    ssl: { rejectUnauthorized: false },
  });

  try {
    // Hash the default password once (12 rounds, NIST SP 800-63B)
    const passwordHash = await bcrypt.hash(DEFAULT_PASSWORD, 12);
    let created = 0;
    let skipped = 0;

    for (const account of ACCOUNTS) {
      // Check if account already exists
      const [rows] = await connection.execute(
        'SELECT id FROM caldera_accounts WHERE email = ?',
        [account.email]
      );

      if (rows.length > 0) {
        console.log(`[seed] Account ${account.email} already exists (id: ${rows[0].id}). Skipping.`);
        skipped++;
        continue;
      }

      // Insert account
      const [result] = await connection.execute(
        `INSERT INTO caldera_accounts (email, password_hash, display_name, account_role, account_status, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'active', NOW(), NOW())`,
        [account.email, passwordHash, account.name, account.role]
      );

      console.log(`[seed] ✓ Created: ${account.email} (${account.role}, id: ${result.insertId})`);
      created++;
    }

    console.log(`[seed] Done. Created: ${created}, Skipped: ${skipped}, Total: ${ACCOUNTS.length}`);
  } catch (err) {
    if (err.code === 'ER_NO_SUCH_TABLE') {
      console.log('[seed] caldera_accounts table does not exist yet. Migrations may not have run.');
      process.exit(0);
    }
    throw err;
  } finally {
    await connection.end();
  }
}

seed()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('[seed] Error:', err.message);
    process.exit(1);
  });
