import { readFileSync } from "fs";
import { resolve } from "path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const readSource = (relativePath: string) =>
  readFileSync(resolve(repositoryRoot, relativePath), "utf8");

describe("engagement-route tenant isolation contracts", () => {
  it("does not ship unauthenticated raw test handlers", () => {
    const server = readSource("server/_core/index.ts");
    const engagementUi = readSource("client/src/pages/EngagementOps.tsx");
    expect(server).not.toContain("/api/_test");
    expect(server).not.toContain("trigger-banking");
    expect(server).not.toContain("trigger-juiceshop");
    expect(engagementUi).not.toContain("trpc.liveTrigger");
  });

  it("requires tenant identity for aggregate telemetry and exploit-plan metrics", () => {
    const router = readSource("server/routers/engagement-ops-core.ts");
    const database = readSource("server/db.ts");

    expect(router).toMatch(/getExploitPlanStats:\s*tenantProcedure/);
    expect(router).toMatch(/getGlobalHotPaths:\s*tenantProcedure/);
    expect(router).toContain("getExploitPlanStats(ctx.tenant.tenantId)");
    expect(router).toContain("getGlobalLlmTelemetryRaw(ctx.tenant.tenantId, input.windowHours)");
    expect(database).toContain("engagement.eng_tenant_id = ${tenantId}");
    expect(database).toContain("INNER JOIN engagements AS engagement ON engagement.id = plan.engagement_id");
  });

  it("fails closed for tenant-unsafe dark-web persistence and automated training execution", () => {
    const router = readSource("server/routers/engagement-ops-core.ts");
    const automation = readSource("server/routers/engagement-automation.ts");

    expect(router).toMatch(/runDarkwebCredentialSync:\s*tenantEngagementProcedure/);
    expect(router).not.toContain("return runDomainDarkwebSync(input.domain)");
    expect(automation).toMatch(/launchTrainingLab:\s*tenantProcedure/);
    expect(automation).toMatch(/batchTrainingRun:\s*tenantProcedure/);
    expect(automation).toContain("Automated training-lab execution is disabled");
    expect(automation).toContain("Automated batch training execution is disabled");
  });

  it("keeps pipeline mutation and automation record views tenant-bound", () => {
    const automation = readSource("server/routers/engagement-automation.ts");

    expect(automation).toMatch(/advancePipeline:\s*tenantProcedure/);
    expect(automation).toContain("getPipelineForTenant(db, input.pipelineId, ctx.tenant.tenantId)");
    expect(automation).toMatch(/listAutomatedEngagements:\s*tenantProcedure/);
    expect(automation).toMatch(/getDashboardStats:\s*tenantProcedure/);
    expect(automation).toMatch(/getBatchTrainingStatus:\s*tenantProcedure/);
  });
});
