#!/usr/bin/env node
/**
 * Production bootstrap for the distroless AC3 platform runtime.
 *
 * ECS supplies the RDS connection as separate host/user/password/name values.
 * Construct DATABASE_URL only in this process before application modules load;
 * never log the resulting URL or credential values. Schema work is intentionally
 * rejected here and must run through the reviewed one-off release task.
 */
import { access } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { resolveDatabaseUrl } from "./database-runtime-config.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));

function redactConnectionLikeText(value) {
  return value.replace(/\/\/[^@/\s]*@/g, "//[REDACTED]@");
}

function configureDatabaseUrl() {
  if (process.env.DATABASE_URL?.trim()) return;
  const databaseUrl = resolveDatabaseUrl();
  if (databaseUrl) {
    process.env.DATABASE_URL = databaseUrl;
    console.log("[bootstrap] Database runtime configured from split ECS values");
  }
}

async function resolveBuiltServerEntry() {
  const candidates = [
    resolve(ROOT, "dist", "server", "index.js"),
    resolve(ROOT, "dist", "_server.js"),
    resolve(ROOT, "dist", "index.js"),
  ];
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Continue to the next supported build output.
    }
  }
  throw new Error("no compiled server entry exists in the immutable runtime image");
}

async function start() {
  if (process.env.RUN_DATABASE_MIGRATIONS === "true") {
    throw new Error("runtime schema migration is prohibited; use the controlled one-off release task");
  }

  configureDatabaseUrl();
  const serverEntry = await resolveBuiltServerEntry();
  console.log("[bootstrap] Starting compiled application server");
  await import(pathToFileURL(serverEntry).href);
}

start().catch((error) => {
  const message = error instanceof Error ? redactConnectionLikeText(error.message) : "unknown bootstrap failure";
  console.error(`[bootstrap] Startup aborted: ${message}`);
  process.exit(1);
});
