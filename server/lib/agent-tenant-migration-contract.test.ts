import { createHash } from "crypto";
import { readFileSync } from "fs";
import { resolve } from "path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const migrationPath = resolve(repositoryRoot, "drizzle/0023_agent_tenant_isolation.sql");
const contractPath = resolve(repositoryRoot, "drizzle/0024_agent_tenant_isolation_contract.sql");
const manifestPath = resolve(repositoryRoot, "drizzle/production-migrations.json");

describe("agent tenant-isolation production migrations", () => {
  it("pins the reviewed migration contents in the tracked manifest", () => {
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    for (const migration of manifest.migrations) {
      const contents = readFileSync(resolve(repositoryRoot, "drizzle", migration.file), "utf8");
      const checksum = createHash("sha256").update(contents).digest("hex");
      expect(migration.sha256).toBe(checksum);
    }
  });

  it("uses deterministic backfills and no destructive/default-tenant fallback", () => {
    const sql = readFileSync(migrationPath, "utf8");
    expect(sql).toContain("engagement`.`eng_tenant_id");
    expect(sql).toContain("deployment`.`tenant_id");
    expect(sql).not.toMatch(/DROP\s+(TABLE|DATABASE)/i);
    expect(sql).not.toMatch(/FOREIGN_KEY_CHECKS/i);
    expect(sql).not.toMatch(/DEFAULT\s+\d+/i);
  });

  it("requires a separate, database-enforced contract phase", () => {
    const sql = readFileSync(contractPath, "utf8");
    expect(sql).toMatch(/tenant_id` INT NOT NULL/i);
    expect(sql).toContain("agent_deployments_tenant_fk");
    expect(sql).toContain("agent_tasks_deployment_tenant_fk");
    expect(sql).toContain("REFERENCES `agent_deployments` (`id`, `tenant_id`)");
  });
});
