#!/usr/bin/env node
/**
 * Read-only pre-deployment verifier for migration 0023.
 *
 * It intentionally refuses to approve a release if any historical agent or
 * task record remains unassigned, orphaned, or disagrees with its parent.
 */
import mysql from "mysql2/promise";

const DATABASE_URL = process.env.DATABASE_URL;
const MIGRATION_TAGS = ["0023_agent_tenant_isolation", "0024_agent_tenant_isolation_contract"];
const EXPECTED_COLUMNS = [
  ["agent_deployments", "tenant_id"],
  ["agent_tasks", "tenant_id"],
];
const EXPECTED_INDEXES = [
  ["agent_deployments", "agent_deployments_tenant_created_idx"],
  ["agent_deployments", "agent_deployments_id_tenant_unique"],
  ["agent_tasks", "agent_tasks_tenant_status_idx"],
  ["agent_tasks", "agent_tasks_agent_tenant_queued_idx"],
];
const EXPECTED_FOREIGN_KEYS = [
  ["agent_deployments", "agent_deployments_tenant_fk"],
  ["agent_tasks", "agent_tasks_deployment_tenant_fk"],
];

if (!DATABASE_URL) {
  console.error("[tenant-verify] DATABASE_URL not set");
  process.exit(1);
}

const url = new URL(DATABASE_URL);
const config = {
  host: url.hostname,
  port: parseInt(url.port, 10) || 3306,
  user: decodeURIComponent(url.username),
  password: decodeURIComponent(url.password),
  database: url.pathname.slice(1),
  ssl: { rejectUnauthorized: false },
  connectTimeout: 30000,
};

async function countObject(conn, sql, values) {
  const [rows] = await conn.query(sql, values);
  return Number(rows[0]?.count ?? 0);
}

async function run() {
  const conn = await mysql.createConnection(config);
  try {
    const migrationRecords = await countObject(
      conn,
      "SELECT COUNT(DISTINCT hash) AS count FROM __drizzle_migrations WHERE hash IN (?, ?)",
      MIGRATION_TAGS,
    );

    const missingColumns = [];
    for (const [table, column] of EXPECTED_COLUMNS) {
      const exists = await countObject(
        conn,
        `SELECT COUNT(*) AS count FROM information_schema.columns
         WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? AND is_nullable = 'NO'`,
        [table, column],
      );
      if (exists !== 1) missingColumns.push(`${table}.${column}`);
    }

    const missingIndexes = [];
    for (const [table, index] of EXPECTED_INDEXES) {
      const exists = await countObject(
        conn,
        `SELECT COUNT(*) AS count FROM information_schema.statistics
         WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`,
        [table, index],
      );
      if (exists < 1) missingIndexes.push(`${table}.${index}`);
    }

    const missingForeignKeys = [];
    for (const [table, constraint] of EXPECTED_FOREIGN_KEYS) {
      const exists = await countObject(
        conn,
        `SELECT COUNT(*) AS count FROM information_schema.table_constraints
         WHERE constraint_schema = DATABASE() AND table_name = ?
           AND constraint_name = ? AND constraint_type = 'FOREIGN KEY'`,
        [table, constraint],
      );
      if (exists !== 1) missingForeignKeys.push(`${table}.${constraint}`);
    }

    const [rows] = await conn.query(`
      SELECT
        (SELECT COUNT(*) FROM agent_deployments WHERE tenant_id IS NULL) AS unresolvedDeployments,
        (SELECT COUNT(*) FROM agent_tasks WHERE tenant_id IS NULL) AS unresolvedTasks,
        (
          SELECT COUNT(*)
          FROM agent_deployments AS deployment
          INNER JOIN engagements AS engagement ON engagement.id = deployment.engagementId
          WHERE deployment.tenant_id <> engagement.eng_tenant_id
             OR engagement.eng_tenant_id IS NULL
        ) AS deploymentTenantMismatches,
        (
          SELECT COUNT(*)
          FROM agent_tasks AS task
          LEFT JOIN agent_deployments AS deployment ON deployment.id = task.agentId
          WHERE deployment.id IS NULL
             OR task.tenant_id <> deployment.tenant_id
        ) AS orphanOrMismatchedTasks,
        (
          SELECT COUNT(*)
          FROM (
            SELECT tenant_id FROM agent_deployments WHERE tenant_id IS NOT NULL
            UNION ALL
            SELECT tenant_id FROM agent_tasks WHERE tenant_id IS NOT NULL
          ) AS tenant_references
          LEFT JOIN tenants ON tenants.id = tenant_references.tenant_id
          WHERE tenants.id IS NULL
        ) AS missingTenantReferences
    `);
    const counts = rows[0] ?? {};
    const dataProblems = Object.entries(counts)
      .filter(([, value]) => Number(value) > 0)
      .map(([name, value]) => `${name}=${value}`);

    console.log("[tenant-verify] migration records:", migrationRecords === MIGRATION_TAGS.length ? "present" : `invalid (${migrationRecords}/${MIGRATION_TAGS.length})`);
    console.log("[tenant-verify] missing non-null columns:", missingColumns.length ? missingColumns.join(", ") : "none");
    console.log("[tenant-verify] missing indexes:", missingIndexes.length ? missingIndexes.join(", ") : "none");
    console.log("[tenant-verify] missing foreign keys:", missingForeignKeys.length ? missingForeignKeys.join(", ") : "none");
    console.log("[tenant-verify] data integrity:", dataProblems.length ? dataProblems.join(", ") : "clean");

    if (migrationRecords !== MIGRATION_TAGS.length || missingColumns.length || missingIndexes.length || missingForeignKeys.length || dataProblems.length) {
      throw new Error("Agent tenant-isolation verification failed. Keep AC3_LIVE_ENGAGEMENT_EXECUTION_ENABLED disabled and remediate ownership data before release.");
    }
    console.log("[tenant-verify] PASS: tenant isolation is ready for live engagement execution");
  } finally {
    await conn.end();
  }
}

run().catch((error) => {
  console.error(`[tenant-verify] FAIL: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
