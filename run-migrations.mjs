#!/usr/bin/env node
/**
 * Production SQL migration runner.
 *
 * Migrations are declared in a tracked, checksummed manifest rather than the
 * Drizzle metadata journal (which is ignored in this repository). This runner
 * never drops tables, disables foreign-key checks, or records a migration that
 * did not complete and pass its object verification.
 */
import { createHash } from "crypto";
import { readFileSync } from "fs";
import mysql from "mysql2/promise";
import { join } from "path";

const DATABASE_URL = process.env.DATABASE_URL;
const MANIFEST_PATH = join("drizzle", "production-migrations.json");
const LOCK_NAME = "ac3_production_schema_migrations";
const LOCK_TIMEOUT_SECONDS = 60;

if (!DATABASE_URL) {
  console.error("[migrate] DATABASE_URL not set");
  process.exit(1);
}

const url = new URL(DATABASE_URL);
const dbName = url.pathname.slice(1);
const config = {
  host: url.hostname,
  port: parseInt(url.port, 10) || 3306,
  user: decodeURIComponent(url.username),
  password: decodeURIComponent(url.password),
  database: dbName,
  ssl: { rejectUnauthorized: false },
  multipleStatements: false,
  connectTimeout: 30000,
};

function requireIdentifier(value, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_]+$/.test(value)) {
    throw new Error(`Invalid ${label} in ${MANIFEST_PATH}`);
  }
  return value;
}

function requireMigrationFile(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_]+\.sql$/.test(value)) {
    throw new Error(`Invalid migration file in ${MANIFEST_PATH}`);
  }
  return value;
}

function loadManifest() {
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, "utf8"));
  if (manifest.version !== 1 || !Array.isArray(manifest.migrations) || manifest.migrations.length === 0) {
    throw new Error(`${MANIFEST_PATH} must contain a non-empty version 1 migrations array`);
  }

  const seenTags = new Set();
  return manifest.migrations.map((entry) => {
    const tag = requireIdentifier(entry.tag, "migration tag");
    const file = requireMigrationFile(entry.file);
    if (seenTags.has(tag)) throw new Error(`Duplicate migration tag in ${MANIFEST_PATH}: ${tag}`);
    seenTags.add(tag);
    if (file !== `${tag}.sql`) throw new Error(`Migration ${tag} must use file ${tag}.sql`);
    if (typeof entry.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(entry.sha256)) {
      throw new Error(`Migration ${tag} has an invalid SHA-256 checksum`);
    }

    const sqlFile = join("drizzle", file);
    const sql = readFileSync(sqlFile, "utf8");
    const actualChecksum = createHash("sha256").update(sql).digest("hex");
    if (actualChecksum !== entry.sha256) {
      throw new Error(`Checksum mismatch for ${tag}; expected ${entry.sha256}, got ${actualChecksum}`);
    }

    const verify = entry.verify ?? {};
    const columns = Array.isArray(verify.columns) ? verify.columns.map((item) => ({
      table: requireIdentifier(item.table, "verification table"),
      column: requireIdentifier(item.column, "verification column"),
    })) : [];
    const indexes = Array.isArray(verify.indexes) ? verify.indexes.map((item) => ({
      table: requireIdentifier(item.table, "verification table"),
      index: requireIdentifier(item.index, "verification index"),
    })) : [];
    const notNullColumns = Array.isArray(verify.notNullColumns) ? verify.notNullColumns.map((item) => ({
      table: requireIdentifier(item.table, "verification table"),
      column: requireIdentifier(item.column, "verification column"),
    })) : [];
    const foreignKeys = Array.isArray(verify.foreignKeys) ? verify.foreignKeys.map((item) => ({
      table: requireIdentifier(item.table, "verification table"),
      constraint: requireIdentifier(item.constraint, "foreign-key constraint"),
    })) : [];

    return {
      tag,
      sql,
      columns,
      indexes,
      notNullColumns,
      foreignKeys,
      requireCleanAgentTenantData: entry.requireCleanAgentTenantData === true,
    };
  });
}

async function verifyMigrationObjects(conn, migration) {
  for (const expected of migration.columns) {
    const [rows] = await conn.query(
      `SELECT COUNT(*) AS count FROM information_schema.columns
       WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?`,
      [expected.table, expected.column],
    );
    if (Number(rows[0]?.count) !== 1) {
      throw new Error(`Verification failed for ${migration.tag}: missing column ${expected.table}.${expected.column}`);
    }
  }

  for (const expected of migration.indexes) {
    const [rows] = await conn.query(
      `SELECT COUNT(*) AS count FROM information_schema.statistics
       WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`,
      [expected.table, expected.index],
    );
    if (Number(rows[0]?.count) < 1) {
      throw new Error(`Verification failed for ${migration.tag}: missing index ${expected.index} on ${expected.table}`);
    }
  }

  for (const expected of migration.notNullColumns) {
    const [rows] = await conn.query(
      `SELECT COUNT(*) AS count FROM information_schema.columns
       WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? AND is_nullable = 'NO'`,
      [expected.table, expected.column],
    );
    if (Number(rows[0]?.count) !== 1) {
      throw new Error(`Verification failed for ${migration.tag}: ${expected.table}.${expected.column} is nullable`);
    }
  }

  for (const expected of migration.foreignKeys) {
    const [rows] = await conn.query(
      `SELECT COUNT(*) AS count FROM information_schema.table_constraints
       WHERE constraint_schema = DATABASE() AND table_name = ?
         AND constraint_name = ? AND constraint_type = 'FOREIGN KEY'`,
      [expected.table, expected.constraint],
    );
    if (Number(rows[0]?.count) !== 1) {
      throw new Error(`Verification failed for ${migration.tag}: missing foreign key ${expected.constraint} on ${expected.table}`);
    }
  }
}

async function assertAgentTenantDataClean(conn, migrationTag) {
  const [rows] = await conn.query(`
    SELECT
      (SELECT COUNT(*) FROM agent_deployments WHERE tenant_id IS NULL) AS unresolvedDeployments,
      (SELECT COUNT(*) FROM agent_tasks WHERE tenant_id IS NULL) AS unresolvedTasks,
      (
        SELECT COUNT(*) FROM agent_deployments AS deployment
        INNER JOIN engagements AS engagement ON engagement.id = deployment.engagementId
        WHERE deployment.tenant_id <> engagement.eng_tenant_id OR engagement.eng_tenant_id IS NULL
      ) AS deploymentTenantMismatches,
      (
        SELECT COUNT(*) FROM agent_tasks AS task
        LEFT JOIN agent_deployments AS deployment ON deployment.id = task.agentId
        WHERE deployment.id IS NULL OR task.tenant_id <> deployment.tenant_id
      ) AS orphanOrMismatchedTasks,
      (
        SELECT COUNT(*) FROM (
          SELECT tenant_id FROM agent_deployments WHERE tenant_id IS NOT NULL
          UNION ALL
          SELECT tenant_id FROM agent_tasks WHERE tenant_id IS NOT NULL
        ) AS tenant_references
        LEFT JOIN tenants ON tenants.id = tenant_references.tenant_id
        WHERE tenants.id IS NULL
      ) AS missingTenantReferences
  `);
  const problems = Object.entries(rows[0] ?? {}).filter(([, value]) => Number(value) > 0);
  if (problems.length > 0) {
    const detail = problems.map(([name, value]) => `${name}=${value}`).join(", ");
    throw new Error(`Migration ${migrationTag} preflight failed: agent tenant data is not clean (${detail}). Resolve ownership through the reviewed runbook; do not assign a default tenant.`);
  }
}

async function run() {
  const migrations = loadManifest();
  console.log(`[migrate] Connecting to ${config.host}:${config.port}/${dbName}...`);
  const conn = await mysql.createConnection(config);
  let lockHeld = false;

  try {
    console.log("[migrate] Connected successfully");
    const [lockRows] = await conn.query("SELECT GET_LOCK(?, ?) AS acquired", [LOCK_NAME, LOCK_TIMEOUT_SECONDS]);
    if (Number(lockRows[0]?.acquired) !== 1) {
      throw new Error(`Could not acquire migration advisory lock within ${LOCK_TIMEOUT_SECONDS} seconds`);
    }
    lockHeld = true;

    await conn.query(`
      CREATE TABLE IF NOT EXISTS __drizzle_migrations (
        id SERIAL PRIMARY KEY,
        hash VARCHAR(255) NOT NULL,
        created_at BIGINT
      )
    `);

    const [applied] = await conn.query("SELECT hash FROM __drizzle_migrations");
    const appliedHashes = new Set(applied.map((row) => row.hash));
    console.log(`[migrate] ${appliedHashes.size} migrations recorded as applied`);

    for (const migration of migrations) {
      if (appliedHashes.has(migration.tag)) {
        await verifyMigrationObjects(conn, migration);
        console.log(`[migrate] Verified ${migration.tag} (already applied)`);
        continue;
      }

      if (migration.requireCleanAgentTenantData) {
        await assertAgentTenantDataClean(conn, migration.tag);
      }

      const statements = migration.sql
        .split("--> statement-breakpoint")
        .map((statement) => statement.trim())
        .filter((statement) => statement.length > 0);
      if (statements.length === 0) throw new Error(`Migration ${migration.tag} has no executable statements`);

      console.log(`[migrate] Applying ${migration.tag} (${statements.length} statements)...`);
      for (const statement of statements) {
        try {
          await conn.query(statement);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          throw new Error(`Migration ${migration.tag} failed: ${message}. No migration record was written; inspect the database and repair forward from a backup.`);
        }
      }

      await verifyMigrationObjects(conn, migration);
      await conn.query("INSERT INTO __drizzle_migrations (hash, created_at) VALUES (?, ?)", [migration.tag, Date.now()]);
      console.log(`[migrate] Applied and verified ${migration.tag}`);
    }

    console.log("[migrate] All production-manifest migrations are verified");
  } finally {
    if (lockHeld) {
      await conn.query("SELECT RELEASE_LOCK(?)", [LOCK_NAME]).catch(() => undefined);
    }
    await conn.end();
  }
}

run().catch((error) => {
  console.error(`[migrate] Fatal error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
