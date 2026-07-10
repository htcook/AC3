/**
 * PBS Security Platform — Test Account Seeder
 * 
 * Creates all PBS test role accounts with the standardized naming convention.
 * Run after migrations on first boot or when updating test accounts.
 * 
 * Naming Convention: PBSPlatform<Role>@pbs.org
 * Password Complexity: Min 16 chars, uppercase, lowercase, numbers, special chars
 * 
 * Required env vars:
 *   DATABASE_URL - MySQL connection string
 * 
 * Author: Harrison Cook | AceofCloud
 */
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.log('[pbs-seed] DATABASE_URL not set, skipping PBS account seed.');
  process.exit(0);
}

/**
 * PBS Platform Test Accounts
 * 
 * All accounts follow the naming convention: PBSPlatform<Role>@pbs.org
 * Each account has a unique complex password meeting the following requirements:
 *   - Minimum 16 characters
 *   - At least 1 uppercase letter
 *   - At least 1 lowercase letter
 *   - At least 2 numbers
 *   - At least 2 special characters
 *   - No dictionary words
 */
const PBS_TEST_ACCOUNTS = [
  {
    email: 'PBSPlatformAdmin@pbs.org',
    name: 'PBS Platform Admin',
    role: 'admin',
    password: 'Kx9#mVp2$nLq8!wR'
  },
  {
    email: 'PBSPlatformOperator@pbs.org',
    name: 'PBS Platform Operator',
    role: 'operator',
    password: 'Tz4&jHc7@bWf3*yN'
  },
  {
    email: 'PBSPlatformAnalyst@pbs.org',
    name: 'PBS Platform Analyst',
    role: 'analyst',
    password: 'Qm6!rXs9#dPk2$vJ'
  },
  {
    email: 'PBSPlatformTeamLead@pbs.org',
    name: 'PBS Platform Team Lead',
    role: 'team_lead',
    password: 'Bw3@nYg8!hLc5#tF'
  },
  {
    email: 'PBSPlatformExecutive@pbs.org',
    name: 'PBS Platform Executive',
    role: 'executive',
    password: 'Gf7$kRz1&mXp4!qS'
  },
  {
    email: 'PBSPlatformClient@pbs.org',
    name: 'PBS Platform Client',
    role: 'client',
    password: 'Hn2!wTv6#jBm9@cD'
  },
  {
    email: 'PBSPlatformSOC@pbs.org',
    name: 'PBS Platform SOC',
    role: 'soc',
    password: 'Lp8#xKf3$rNw5!yA'
  },
  {
    email: 'PBSPlatformViewer@pbs.org',
    name: 'PBS Platform Viewer',
    role: 'viewer',
    password: 'Vc5&dMj2!sQh7@nE'
  },
];

async function seedPBSAccounts() {
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
    let created = 0;
    let updated = 0;
    let skipped = 0;

    for (const account of PBS_TEST_ACCOUNTS) {
      // Hash password with bcrypt (12 rounds, NIST SP 800-63B compliant)
      const passwordHash = await bcrypt.hash(account.password, 12);

      // Check if account already exists
      const [rows] = await connection.execute(
        'SELECT id, email FROM caldera_accounts WHERE email = ?',
        [account.email]
      );

      if (rows.length > 0) {
        // Update existing account password and ensure active status
        await connection.execute(
          `UPDATE caldera_accounts 
           SET password_hash = ?, display_name = ?, account_role = ?, account_status = 'active', updated_at = NOW()
           WHERE email = ?`,
          [passwordHash, account.name, account.role, account.email]
        );
        console.log(`[pbs-seed] ↻ Updated: ${account.email} (${account.role}, id: ${rows[0].id})`);
        updated++;
        continue;
      }

      // Also check for old-style accounts (e.g., admin@pbs.org) and deactivate them
      const oldEmail = account.role === 'team_lead' 
        ? 'teamlead@pbs.org' 
        : `${account.role}@pbs.org`;
      
      const [oldRows] = await connection.execute(
        'SELECT id FROM caldera_accounts WHERE email = ?',
        [oldEmail]
      );

      if (oldRows.length > 0) {
        await connection.execute(
          `UPDATE caldera_accounts SET account_status = 'deactivated', updated_at = NOW() WHERE email = ?`,
          [oldEmail]
        );
        console.log(`[pbs-seed] ⊘ Deactivated old account: ${oldEmail}`);
      }

      // Insert new account
      const [result] = await connection.execute(
        `INSERT INTO caldera_accounts (email, password_hash, display_name, account_role, account_status, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'active', NOW(), NOW())`,
        [account.email, passwordHash, account.name, account.role]
      );

      console.log(`[pbs-seed] ✓ Created: ${account.email} (${account.role}, id: ${result.insertId})`);
      created++;
    }

    console.log(`[pbs-seed] Done. Created: ${created}, Updated: ${updated}, Skipped: ${skipped}, Total: ${PBS_TEST_ACCOUNTS.length}`);
  } catch (err) {
    if (err.code === 'ER_NO_SUCH_TABLE') {
      console.log('[pbs-seed] caldera_accounts table does not exist yet. Migrations may not have run.');
      process.exit(0);
    }
    throw err;
  } finally {
    await connection.end();
  }
}

seedPBSAccounts()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('[pbs-seed] Error:', err.message);
    process.exit(1);
  });
