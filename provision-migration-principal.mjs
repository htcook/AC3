#!/usr/bin/env node
/**
 * One-off provisioning utility for the AC3 schema migration principal.
 *
 * Run only from the isolated migration task with the managed RDS master
 * credential injected as DATABASE_PASSWORD and the generated migration
 * credential injected as AC3_MIGRATION_DB_PASSWORD. It never logs either.
 */
import mysql from "mysql2/promise";
import { resolveDatabaseUrl } from "./database-runtime-config.mjs";

const migrationUsername = process.env.AC3_MIGRATION_DB_USERNAME;
const migrationPassword = process.env.AC3_MIGRATION_DB_PASSWORD;
const databaseUrl = resolveDatabaseUrl();

if (!databaseUrl) throw new Error("Database connection is not configured");
if (typeof migrationUsername !== "string" || !/^[A-Za-z0-9_]{1,32}$/.test(migrationUsername)) {
  throw new Error("AC3_MIGRATION_DB_USERNAME must be a simple MySQL username");
}
if (typeof migrationPassword !== "string" || migrationPassword.length < 32) {
  throw new Error("AC3_MIGRATION_DB_PASSWORD must be a strong generated secret");
}

const url = new URL(databaseUrl);
const databaseName = decodeURIComponent(url.pathname.slice(1));
if (!/^[A-Za-z0-9_]+$/.test(databaseName)) {
  throw new Error("DATABASE_NAME must be a simple MySQL identifier");
}

function quoteString(value) {
  return `'${value
    .replaceAll("\\", "\\\\")
    .replaceAll("'", "\\'")
    .replaceAll("\u0000", "\\0")
    .replaceAll("\n", "\\n")
    .replaceAll("\r", "\\r")
    .replaceAll("\u001a", "\\Z")}'`;
}

const principal = `${quoteString(migrationUsername)}@'%'`;
const password = quoteString(migrationPassword);
const database = `\`${databaseName}\``;
const config = {
  host: url.hostname,
  port: parseInt(url.port, 10) || 3306,
  user: decodeURIComponent(url.username),
  password: decodeURIComponent(url.password),
  database: databaseName,
  ssl: { rejectUnauthorized: false },
  connectTimeout: 30000,
};

const conn = await mysql.createConnection(config);
try {
  await conn.query(`CREATE USER IF NOT EXISTS ${principal} IDENTIFIED BY ${password} REQUIRE SSL`);
  await conn.query(`ALTER USER ${principal} IDENTIFIED BY ${password} REQUIRE SSL`);
  await conn.query(
    `GRANT SELECT, INSERT, UPDATE, CREATE, ALTER, INDEX, REFERENCES ON ${database}.* TO ${principal}`,
  );
  const [rows] = await conn.query(`SHOW GRANTS FOR ${principal}`);
  if (!Array.isArray(rows) || rows.length === 0) {
    throw new Error("Migration principal grant verification failed");
  }
  console.log("[migration-principal] Dedicated SSL-required migration principal provisioned and verified");
} finally {
  await conn.end();
}
