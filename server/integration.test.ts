/**
 * Integration Tests — Real Database
 *
 * These tests hit the actual database to verify:
 * 1. Foreign key constraints are enforced
 * 2. Schema migrations match runtime expectations
 * 3. Transaction rollback works correctly
 * 4. Credential encryption round-trips through the DB
 * 5. Cascade delete behavior
 *
 * These tests require DATABASE_URL to be set. They are skipped
 * in CI environments where no database is available.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { drizzle } from "drizzle-orm/mysql2";
import { sql } from "drizzle-orm";
import mysql from "mysql2/promise";

const DATABASE_URL = process.env.DATABASE_URL;
const shouldRun = !!DATABASE_URL;

async function createTestDb() {
  if (!DATABASE_URL) throw new Error("DATABASE_URL not set");
  const pool = mysql.createPool({
    uri: DATABASE_URL,
    waitForConnections: true,
    connectionLimit: 3,
    ssl: { rejectUnauthorized: false },
  });
  const db = drizzle(pool);
  return { db, pool };
}

// ─── 1. Database Connection ──────────────────────────────────────────

describe.skipIf(!shouldRun)("Integration: Database Connection", () => {
  let db: ReturnType<typeof drizzle>;
  let pool: mysql.Pool;

  beforeAll(async () => {
    const conn = await createTestDb();
    db = conn.db;
    pool = conn.pool;
  });

  afterAll(async () => {
    await pool?.end();
  });

  it("should connect and execute a simple query", async () => {
    const result = await db.execute(sql`SELECT 1 as val`);
    expect(result).toBeDefined();
  });

  it("should verify the users table exists with expected columns", async () => {
    const [rows] = await pool.execute(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' 
       ORDER BY ORDINAL_POSITION`
    );
    const columns = (rows as any[]).map((r: any) => r.COLUMN_NAME);
    expect(columns).toContain("id");
    expect(columns).toContain("openId");
    expect(columns).toContain("name");
    expect(columns).toContain("role");
  });

  it("should verify the server_configs table exists", async () => {
    const [rows] = await pool.execute(
      `SELECT COUNT(*) as cnt FROM INFORMATION_SCHEMA.TABLES 
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'server_configs'`
    );
    expect((rows as any[])[0].cnt).toBe(1);
  });
});

// ─── 2. Foreign Key Constraints ──────────────────────────────────────

describe.skipIf(!shouldRun)("Integration: Foreign Key Constraints", () => {
  let pool: mysql.Pool;

  beforeAll(async () => {
    const conn = await createTestDb();
    pool = conn.pool;
  });

  afterAll(async () => {
    await pool?.end();
  });

  it("should list all foreign key constraints in the database", async () => {
    const [rows] = await pool.execute(
      `SELECT TABLE_NAME, COLUMN_NAME, CONSTRAINT_NAME, 
              REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
       FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
       WHERE TABLE_SCHEMA = DATABASE() 
         AND REFERENCED_TABLE_NAME IS NOT NULL
       ORDER BY TABLE_NAME`
    );
    const fks = rows as any[];
    expect(fks.length).toBeGreaterThanOrEqual(5);

    const fkNames = fks.map((f: any) =>
      `${f.TABLE_NAME}.${f.COLUMN_NAME} → ${f.REFERENCED_TABLE_NAME}.${f.REFERENCED_COLUMN_NAME}`
    );
    console.log(`[FK Audit] ${fks.length} foreign keys found:\n  ${fkNames.join("\n  ")}`);
  });

  it("should enforce FK on agent_tasks → agent_deployments (agentId)", async () => {
    try {
      await pool.execute(
        `INSERT INTO agent_tasks (id, agentId, techniqueId, c2Source, commandEncrypted, taskStatus, queuedAt, assignedBy) 
         VALUES (?, 'nonexistent-agent-id-12345', 'T1059', 'caldera', 'whoami', 'queued', UNIX_TIMESTAMP()*1000, 0)`,
        [`fk-test-task-${Date.now()}`]
      );
      expect.fail("FK constraint should have prevented insert with non-existent agentId");
    } catch (err: any) {
      expect(
        err.errno === 1452 ||
        err.message.includes("foreign key") ||
        err.message.includes("FOREIGN KEY") ||
        err.message.includes("Cannot add or update a child row")
      ).toBe(true);
    }
  });

  it("should enforce FK on agent_audit_log → agent_deployments (agentId)", async () => {
    try {
      await pool.execute(
        `INSERT INTO agent_audit_log (agentId, eventType, details, recordHash, previousHash, createdAt)
         VALUES ('nonexistent-agent-id-99999', 'heartbeat', '{}', 'testhash', 'prevhash', UNIX_TIMESTAMP()*1000)`
      );
      expect.fail("FK constraint should have prevented insert");
    } catch (err: any) {
      expect(
        err.errno === 1452 ||
        err.message.includes("foreign key") ||
        err.message.includes("Cannot add or update a child row")
      ).toBe(true);
    }
  });

  it("should enforce FK on server_credentials → server_configs (serverId)", async () => {
    try {
      await pool.execute(
        `INSERT INTO server_credentials (serverId, credentialType, username, createdAt)
         VALUES (999999, 'red_api_key', 'test', NOW())`
      );
      expect.fail("FK constraint should have prevented insert");
    } catch (err: any) {
      expect(
        err.errno === 1452 ||
        err.message.includes("foreign key") ||
        err.message.includes("Cannot add or update a child row")
      ).toBe(true);
    }
  });

  it("should allow valid FK inserts (agent_deployments → agent_tasks)", async () => {
    const agentId = `integ-test-agent-${Date.now()}`;
    const taskId = `integ-test-task-${Date.now()}`;

    // Insert a valid agent first
    await pool.execute(
      `INSERT INTO agent_deployments (id, name, targetPlatform, c2Protocol, agentStatus, requestedBy, createdAt, updatedAt)
       VALUES (?, 'Integration Test Agent', 'linux', 'caldera', 'active', 0, NOW(), NOW())`,
      [agentId]
    );

    // Insert a task referencing that agent — should succeed
    await pool.execute(
      `INSERT INTO agent_tasks (id, agentId, techniqueId, c2Source, commandEncrypted, taskStatus, queuedAt, assignedBy)
       VALUES (?, ?, 'T1059', 'caldera', 'whoami', 'queued', UNIX_TIMESTAMP()*1000, 0)`,
      [taskId, agentId]
    );

    // Clean up (order matters due to FK)
    await pool.execute(`DELETE FROM agent_tasks WHERE id = ?`, [taskId]);
    await pool.execute(`DELETE FROM agent_deployments WHERE id = ?`, [agentId]);
  });
});

// ─── 3. Transaction Rollback ─────────────────────────────────────────

describe.skipIf(!shouldRun)("Integration: Transaction Rollback", () => {
  let pool: mysql.Pool;

  beforeAll(async () => {
    const conn = await createTestDb();
    pool = conn.pool;
  });

  afterAll(async () => {
    await pool?.end();
  });

  it("should rollback a transaction on error", async () => {
    const connection = await pool.getConnection();
    const agentId = `rollback-test-${Date.now()}`;

    try {
      await connection.beginTransaction();

      await connection.execute(
       `INSERT INTO agent_deployments (id, name, targetPlatform, c2Protocol, agentStatus, requestedBy, createdAt, updatedAt)
       VALUES (?, 'Rollback Test Agent', 'linux', 'caldera', 'active', 0, NOW(), NOW())`,
        [agentId]
      );

      // Force duplicate key error
      await connection.execute(
        `INSERT INTO agent_deployments (id, name, targetPlatform, c2Protocol, agentStatus, requestedBy, createdAt, updatedAt)
         VALUES (?, 'Duplicate Agent', 'linux', 'caldera', 'active', 0, NOW(), NOW())`,
        [agentId]
      );

      await connection.commit();
      expect.fail("Should have thrown on duplicate key");
    } catch {
      await connection.rollback();
    } finally {
      connection.release();
    }

    // Verify the agent was NOT inserted (transaction rolled back)
    const [rows] = await pool.execute(
      `SELECT COUNT(*) as cnt FROM agent_deployments WHERE id = ?`,
      [agentId]
    );
    expect((rows as any[])[0].cnt).toBe(0);
  });
});

// ─── 4. Schema Completeness ─────────────────────────────────────────

describe.skipIf(!shouldRun)("Integration: Schema Completeness", () => {
  let pool: mysql.Pool;

  beforeAll(async () => {
    const conn = await createTestDb();
    pool = conn.pool;
  });

  afterAll(async () => {
    await pool?.end();
  });

  it("should have all expected core tables", async () => {
    const [rows] = await pool.execute(
      `SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES 
       WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME`
    );
    const tables = (rows as any[]).map((r: any) => r.TABLE_NAME);

    const expectedTables = [
      "users",
      "server_configs",
      "server_credentials",
      "activity_logs",
      "agent_deployments",
      "agent_tasks",
      "agent_audit_log",
      "c2_servers",
      "mtls_certificates",
    ];

    for (const table of expectedTables) {
      expect(tables).toContain(table);
    }

    console.log(`[Schema Audit] ${tables.length} tables found in database`);
  });

  it("should have the correct columns for agent_deployments", async () => {
    const [rows] = await pool.execute(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'agent_deployments'
       ORDER BY ORDINAL_POSITION`
    );
    const columns = (rows as any[]).map((r: any) => r.COLUMN_NAME);

    // Drizzle uses camelCase column names
    expect(columns).toContain("id");
    expect(columns).toContain("name");
    expect(columns).toContain("c2Protocol");
    expect(columns).toContain("agentStatus");
    expect(columns).toContain("createdAt");
    expect(columns).toContain("watchdogSeconds");
    expect(columns).toContain("lastHeartbeat");
  });

  it("should have the correct columns for mtls_certificates", async () => {
    const [rows] = await pool.execute(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'mtls_certificates'
       ORDER BY ORDINAL_POSITION`
    );
    const columns = (rows as any[]).map((r: any) => r.COLUMN_NAME);
    expect(columns).toContain("id");
    expect(columns).toContain("type");
    expect(columns).toContain("commonName");
    expect(columns).toContain("certificate");
    expect(columns).toContain("encryptedPrivateKey");
    expect(columns).toContain("c2ServerId");
  });

  it("should have at least 100 tables (platform scale check)", async () => {
    const [rows] = await pool.execute(
      `SELECT COUNT(*) as cnt FROM INFORMATION_SCHEMA.TABLES 
       WHERE TABLE_SCHEMA = DATABASE()`
    );
    const count = (rows as any[])[0].cnt;
    expect(count).toBeGreaterThanOrEqual(100);
    console.log(`[Scale Audit] Database has ${count} tables`);
  });

  it("should have at least 5 foreign key constraints", async () => {
    const [rows] = await pool.execute(
      `SELECT COUNT(*) as cnt FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS 
       WHERE TABLE_SCHEMA = DATABASE() AND CONSTRAINT_TYPE = 'FOREIGN KEY'`
    );
    const count = (rows as any[])[0].cnt;
    expect(count).toBeGreaterThanOrEqual(5);
    console.log(`[FK Audit] Database has ${count} foreign key constraints`);
  });
});

// ─── 5. Credential Encryption Round-Trip ─────────────────────────────

describe.skipIf(!shouldRun)("Integration: Credential Encryption Round-Trip", () => {
  let pool: mysql.Pool;

  beforeAll(async () => {
    const conn = await createTestDb();
    pool = conn.pool;
  });

  afterAll(async () => {
    await pool?.end();
  });

  it("should encrypt and decrypt credentials correctly", async () => {
    const { encryptCredential, decryptCredential } = await import("./lib/credential-crypto");

    const plaintext = "super-secret-api-key-12345";
    const encrypted = encryptCredential(plaintext);

    // encryptCredential returns an EncryptedPayload object
    expect(encrypted).toBeDefined();
    expect(typeof encrypted).toBe("object");
    expect(encrypted).toHaveProperty("iv");
    expect(encrypted).toHaveProperty("encryptedData");
    expect(encrypted).toHaveProperty("tag");

    // Verify round-trip decryption
    const decrypted = decryptCredential(encrypted);
    expect(decrypted).toBe(plaintext);
  });

  it("should store encrypted credential as JSON in DB and retrieve it", async () => {
    const { encryptCredential, decryptCredential } = await import("./lib/credential-crypto");

    const testApiKey = `test-key-${Date.now()}`;
    const encrypted = encryptCredential(testApiKey);
    const encryptedJson = JSON.stringify(encrypted);

    // Get a server_config to reference
    const [serverRows] = await pool.execute(`SELECT id FROM server_configs LIMIT 1`);
    const serverList = serverRows as any[];

    let serverId: number;
    if (serverList.length === 0) {
      const [insertResult] = await pool.execute(
        `INSERT INTO server_configs (name, ipAddress, status, createdAt)
         VALUES ('Integration Test Server', '127.0.0.1', 'offline', NOW())`
      );
      serverId = (insertResult as any).insertId;
    } else {
      serverId = serverList[0].id;
    }

    // Insert encrypted credential as JSON string
    await pool.execute(
      `INSERT INTO server_credentials (serverId, credentialType, username, apiKey, createdAt)
       VALUES (?, 'red_api_key', 'integration_test', ?, NOW())`,
      [serverId, encryptedJson]
    );

    // Retrieve and decrypt
    const [credRows] = await pool.execute(
      `SELECT apiKey FROM server_credentials 
       WHERE serverId = ? AND username = 'integration_test'
       ORDER BY id DESC LIMIT 1`,
      [serverId]
    );
    const storedEncrypted = (credRows as any[])[0].apiKey;
    const parsed = JSON.parse(storedEncrypted);
    const decrypted = decryptCredential(parsed);
    expect(decrypted).toBe(testApiKey);

    // Clean up
    await pool.execute(
      `DELETE FROM server_credentials WHERE serverId = ? AND username = 'integration_test'`,
      [serverId]
    );
  });
});

// ─── 6. Cascade Behavior ────────────────────────────────────────────

describe.skipIf(!shouldRun)("Integration: Cascade Behavior", () => {
  let pool: mysql.Pool;

  beforeAll(async () => {
    const conn = await createTestDb();
    pool = conn.pool;
  });

  afterAll(async () => {
    await pool?.end();
  });

  it("should cascade delete agent_tasks when agent_deployment is deleted", async () => {
    const agentId = `cascade-test-${Date.now()}`;
    const taskId = `cascade-task-${Date.now()}`;

    // Create agent
    await pool.execute(
      `INSERT INTO agent_deployments (id, name, targetPlatform, c2Protocol, agentStatus, requestedBy, createdAt, updatedAt)
       VALUES (?, 'Cascade Test Agent', 'linux', 'caldera', 'active', 0, NOW(), NOW())`,
      [agentId]
    );

    // Create task referencing agent
    await pool.execute(
      `INSERT INTO agent_tasks (id, agentId, techniqueId, c2Source, commandEncrypted, taskStatus, queuedAt, assignedBy)
       VALUES (?, ?, 'T1059', 'caldera', 'whoami', 'queued', UNIX_TIMESTAMP()*1000, 0)`,
      [taskId, agentId]
    );

    // Verify task exists
    const [beforeRows] = await pool.execute(
      `SELECT COUNT(*) as cnt FROM agent_tasks WHERE id = ?`, [taskId]
    );
    expect((beforeRows as any[])[0].cnt).toBe(1);

    // Delete the agent — should cascade to tasks
    await pool.execute(`DELETE FROM agent_deployments WHERE id = ?`, [agentId]);

    // Verify task was cascaded
    const [afterRows] = await pool.execute(
      `SELECT COUNT(*) as cnt FROM agent_tasks WHERE id = ?`, [taskId]
    );
    expect((afterRows as any[])[0].cnt).toBe(0);
  });

  it("should cascade delete agent_audit_log when agent_deployment is deleted", async () => {
    const agentId = `cascade-audit-${Date.now()}`;

    // Create agent
    await pool.execute(
      `INSERT INTO agent_deployments (id, name, targetPlatform, c2Protocol, agentStatus, requestedBy, createdAt, updatedAt)
       VALUES (?, 'Cascade Audit Agent', 'linux', 'caldera', 'active', 0, NOW(), NOW())`,
      [agentId]
    );

    // Create audit log entry
    await pool.execute(
      `INSERT INTO agent_audit_log (agentId, eventType, details, recordHash, previousHash, createdAt)
       VALUES (?, 'heartbeat', '{"old":"active","new":"lost"}', 'testhash', 'prevhash', UNIX_TIMESTAMP()*1000)`,
      [agentId]
    );

    // Verify audit log exists
    const [beforeRows] = await pool.execute(
      `SELECT COUNT(*) as cnt FROM agent_audit_log WHERE agentId = ?`, [agentId]
    );
    expect((beforeRows as any[])[0].cnt).toBe(1);

    // Delete the agent — should cascade to audit logs
    await pool.execute(`DELETE FROM agent_deployments WHERE id = ?`, [agentId]);

    // Verify audit log was cascaded
    const [afterRows] = await pool.execute(
      `SELECT COUNT(*) as cnt FROM agent_audit_log WHERE agentId = ?`, [agentId]
    );
    expect((afterRows as any[])[0].cnt).toBe(0);
  });
});
