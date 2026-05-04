import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Round 6 Feature Tests
 * 
 * 1. Bug Bounty Live Feed Connectors (HackerOne + Bugcrowd API clients)
 * 2. Monitoring Stack Deployment Automation (deploy-monitoring.sh)
 * 3. GitHub Workflows Permission Helper (setup + push scripts)
 * 4. Integration Registry catalog entries for H1/BC
 */

// ─── 1. Bug Bounty Feed Library Tests ──────────────────────────────────────

const importFeeds = () => import("./lib/bug-bounty-feeds");

describe("Bug Bounty Live Feed Connectors", () => {
  describe("HackerOneClient", () => {
    it("should construct with API identifier and token", async () => {
      const { HackerOneClient } = await importFeeds();
      const client = new HackerOneClient("test-id", "test-token");
      expect(client).toBeDefined();
    });

    it("should have getPrograms method", async () => {
      const { HackerOneClient } = await importFeeds();
      const client = new HackerOneClient("test-id", "test-token");
      expect(typeof client.getPrograms).toBe("function");
    });

    it("should have getProgramByHandle method", async () => {
      const { HackerOneClient } = await importFeeds();
      const client = new HackerOneClient("test-id", "test-token");
      expect(typeof client.getProgramByHandle).toBe("function");
    });

    it("should have getProgramScope method", async () => {
      const { HackerOneClient } = await importFeeds();
      const client = new HackerOneClient("test-id", "test-token");
      expect(typeof client.getProgramScope).toBe("function");
    });

    it("should have getDisclosedReports method", async () => {
      const { HackerOneClient } = await importFeeds();
      const client = new HackerOneClient("test-id", "test-token");
      expect(typeof client.getDisclosedReports).toBe("function");
    });
  });

  describe("BugcrowdClient", () => {
    it("should construct with API token", async () => {
      const { BugcrowdClient } = await importFeeds();
      const client = new BugcrowdClient("test-token");
      expect(client).toBeDefined();
    });

    it("should have getPrograms method", async () => {
      const { BugcrowdClient } = await importFeeds();
      const client = new BugcrowdClient("test-token");
      expect(typeof client.getPrograms).toBe("function");
    });

    it("should have getProgramByCode method", async () => {
      const { BugcrowdClient } = await importFeeds();
      const client = new BugcrowdClient("test-token");
      expect(typeof client.getProgramByCode).toBe("function");
    });

    it("should have getTargets method", async () => {
      const { BugcrowdClient } = await importFeeds();
      const client = new BugcrowdClient("test-token");
      expect(typeof client.getTargets).toBe("function");
    });

    it("should have getSubmissions method", async () => {
      const { BugcrowdClient } = await importFeeds();
      const client = new BugcrowdClient("test-token");
      expect(typeof client.getSubmissions).toBe("function");
    });
  });

  describe("BugBountyFeedAggregator", () => {
    it("should create aggregator without any API keys configured", async () => {
      const { BugBountyFeedAggregator } = await importFeeds();
      const aggregator = new BugBountyFeedAggregator({});
      expect(aggregator.isConfigured).toBe(false);
      expect(aggregator.configuredPlatforms).toEqual([]);
    });

    it("should detect HackerOne when both identifier and token provided", async () => {
      const { BugBountyFeedAggregator } = await importFeeds();
      const aggregator = new BugBountyFeedAggregator({
        hackeroneApiIdentifier: "test-id",
        hackeroneApiToken: "test-token",
      });
      expect(aggregator.isConfigured).toBe(true);
      expect(aggregator.configuredPlatforms).toContain("hackerone");
    });

    it("should detect Bugcrowd when token provided", async () => {
      const { BugBountyFeedAggregator } = await importFeeds();
      const aggregator = new BugBountyFeedAggregator({
        bugcrowdApiToken: "test-token",
      });
      expect(aggregator.isConfigured).toBe(true);
      expect(aggregator.configuredPlatforms).toContain("bugcrowd");
    });

    it("should detect both platforms when all keys provided", async () => {
      const { BugBountyFeedAggregator } = await importFeeds();
      const aggregator = new BugBountyFeedAggregator({
        hackeroneApiIdentifier: "test-id",
        hackeroneApiToken: "test-token",
        bugcrowdApiToken: "test-token",
      });
      expect(aggregator.isConfigured).toBe(true);
      expect(aggregator.configuredPlatforms).toHaveLength(2);
      expect(aggregator.configuredPlatforms).toContain("hackerone");
      expect(aggregator.configuredPlatforms).toContain("bugcrowd");
    });

    it("should not configure HackerOne with only identifier (no token)", async () => {
      const { BugBountyFeedAggregator } = await importFeeds();
      const aggregator = new BugBountyFeedAggregator({
        hackeroneApiIdentifier: "test-id",
      });
      expect(aggregator.configuredPlatforms).not.toContain("hackerone");
    });

    it("should return healthy feed state initially", async () => {
      const { BugBountyFeedAggregator } = await importFeeds();
      const aggregator = new BugBountyFeedAggregator({});
      const state = aggregator.getFeedState();
      expect(state.feedHealth).toBe("healthy");
      expect(state.lastFetchedAt).toBeNull();
      expect(state.totalPrograms).toBe(0);
      expect(state.activePrograms).toBe(0);
      expect(state.totalDisclosures).toBe(0);
      expect(state.recentScopeChanges).toBe(0);
      expect(state.errorMessage).toBeNull();
    });

    it("should return empty programs when not configured", async () => {
      const { BugBountyFeedAggregator } = await importFeeds();
      const aggregator = new BugBountyFeedAggregator({});
      const result = await aggregator.fetchPrograms();
      expect(result.programs).toEqual([]);
      expect(result.total).toBe(0);
    });

    it("should return empty reports when not configured", async () => {
      const { BugBountyFeedAggregator } = await importFeeds();
      const aggregator = new BugBountyFeedAggregator({});
      const reports = await aggregator.fetchDisclosedReports();
      expect(reports).toEqual([]);
    });

    it("should return empty feed events when not configured", async () => {
      const { BugBountyFeedAggregator } = await importFeeds();
      const aggregator = new BugBountyFeedAggregator({});
      const events = await aggregator.generateFeedEvents();
      expect(events).toEqual([]);
    });

    it("should return empty cached programs initially", async () => {
      const { BugBountyFeedAggregator } = await importFeeds();
      const aggregator = new BugBountyFeedAggregator({});
      expect(aggregator.getCachedPrograms()).toEqual([]);
    });

    it("should return empty cached feed initially", async () => {
      const { BugBountyFeedAggregator } = await importFeeds();
      const aggregator = new BugBountyFeedAggregator({});
      expect(aggregator.getCachedFeed()).toEqual([]);
    });
  });

  describe("Singleton Factory", () => {
    it("should create aggregator via getBugBountyFeedAggregator", async () => {
      const { getBugBountyFeedAggregator, resetFeedAggregator } = await importFeeds();
      resetFeedAggregator();
      const aggregator = getBugBountyFeedAggregator();
      expect(aggregator).toBeDefined();
      expect(typeof aggregator.isConfigured).toBe("boolean");
    });

    it("should return same instance on repeated calls", async () => {
      const { getBugBountyFeedAggregator, resetFeedAggregator } = await importFeeds();
      resetFeedAggregator();
      const a1 = getBugBountyFeedAggregator();
      const a2 = getBugBountyFeedAggregator();
      expect(a1).toBe(a2);
    });

    it("should create new instance after reset", async () => {
      const { getBugBountyFeedAggregator, resetFeedAggregator } = await importFeeds();
      resetFeedAggregator();
      const a1 = getBugBountyFeedAggregator();
      resetFeedAggregator();
      const a2 = getBugBountyFeedAggregator();
      expect(a1).not.toBe(a2);
    });
  });

  describe("Type Exports", () => {
    it("should export BountyProgram type shape", async () => {
      const { BugBountyFeedAggregator } = await importFeeds();
      const aggregator = new BugBountyFeedAggregator({
        hackeroneApiIdentifier: "id",
        hackeroneApiToken: "token",
      });
      // Verify the aggregator has the expected interface
      expect(typeof aggregator.fetchPrograms).toBe("function");
      expect(typeof aggregator.fetchDisclosedReports).toBe("function");
      expect(typeof aggregator.detectScopeChanges).toBe("function");
      expect(typeof aggregator.generateFeedEvents).toBe("function");
      expect(typeof aggregator.getFeedState).toBe("function");
      expect(typeof aggregator.getCachedPrograms).toBe("function");
      expect(typeof aggregator.getCachedFeed).toBe("function");
    });
  });
});

// ─── 2. Integration Registry Catalog Tests ─────────────────────────────────

const importCatalog = () => import("./lib/integration-registry/builtin-catalog");

describe("Integration Registry — Bug Bounty Catalog Entries", () => {
  it("should include hackerone in the builtin catalog", async () => {
    const { BUILTIN_CATALOG } = await importCatalog();
    const h1 = BUILTIN_CATALOG.find(e => e.id === "hackerone");
    expect(h1).toBeDefined();
    expect(h1!.displayName).toBe("HackerOne");
    expect(h1!.category).toBe("osint");
  });

  it("should include bugcrowd in the builtin catalog", async () => {
    const { BUILTIN_CATALOG } = await importCatalog();
    const bc = BUILTIN_CATALOG.find(e => e.id === "bugcrowd");
    expect(bc).toBeDefined();
    expect(bc!.displayName).toBe("Bugcrowd");
    expect(bc!.category).toBe("osint");
  });

  it("should have correct env var keys for HackerOne", async () => {
    const { CATALOG_BY_ID } = await importCatalog();
    const h1 = CATALOG_BY_ID.get("hackerone");
    expect(h1).toBeDefined();
    expect(h1!.envVarKeys).toContain("HACKERONE_API_USERNAME");
    expect(h1!.envVarKeys).toContain("HACKERONE_API_KEY");
  });

  it("should have correct env var keys for Bugcrowd", async () => {
    const { CATALOG_BY_ID } = await importCatalog();
    const bc = CATALOG_BY_ID.get("bugcrowd");
    expect(bc).toBeDefined();
    expect(bc!.envVarKeys).toContain("BUGCROWD_API_TOKEN");
  });

  it("should have HackerOne using basic_auth method", async () => {
    const { CATALOG_BY_ID } = await importCatalog();
    const h1 = CATALOG_BY_ID.get("hackerone");
    expect(h1!.authMethod).toBe("basic_auth");
  });

  it("should have Bugcrowd using bearer_token method", async () => {
    const { CATALOG_BY_ID } = await importCatalog();
    const bc = CATALOG_BY_ID.get("bugcrowd");
    expect(bc!.authMethod).toBe("bearer_token");
  });

  it("should include bug_bounty tag on both entries", async () => {
    const { CATALOG_BY_ID } = await importCatalog();
    const h1 = CATALOG_BY_ID.get("hackerone");
    const bc = CATALOG_BY_ID.get("bugcrowd");
    expect(h1!.tags).toContain("bug_bounty");
    expect(bc!.tags).toContain("bug_bounty");
  });

  it("should mark both as passive-only (no active probing)", async () => {
    const { CATALOG_BY_ID } = await importCatalog();
    const h1 = CATALOG_BY_ID.get("hackerone");
    const bc = CATALOG_BY_ID.get("bugcrowd");
    expect(h1!.supportsPassiveOnly).toBe(true);
    expect(h1!.requiresActiveProbing).toBe(false);
    expect(bc!.supportsPassiveOnly).toBe(true);
    expect(bc!.requiresActiveProbing).toBe(false);
  });

  it("should include recon and reporting pipeline stages", async () => {
    const { CATALOG_BY_ID } = await importCatalog();
    const h1 = CATALOG_BY_ID.get("hackerone");
    const bc = CATALOG_BY_ID.get("bugcrowd");
    expect(h1!.pipelineStages).toContain("recon");
    expect(h1!.pipelineStages).toContain("reporting");
    expect(bc!.pipelineStages).toContain("recon");
    expect(bc!.pipelineStages).toContain("reporting");
  });

  it("should be findable via getCatalogByCategory('osint')", async () => {
    const { getCatalogByCategory } = await importCatalog();
    const osintEntries = getCatalogByCategory("osint");
    const ids = osintEntries.map(e => e.id);
    expect(ids).toContain("hackerone");
    expect(ids).toContain("bugcrowd");
  });

  it("should be findable via getCatalogByStage('recon')", async () => {
    const { getCatalogByStage } = await importCatalog();
    const reconEntries = getCatalogByStage("recon");
    const ids = reconEntries.map(e => e.id);
    expect(ids).toContain("hackerone");
    expect(ids).toContain("bugcrowd");
  });

  it("should appear in getPaidIntegrations", async () => {
    const { getPaidIntegrations } = await importCatalog();
    const paid = getPaidIntegrations();
    const ids = paid.map(e => e.id);
    expect(ids).toContain("hackerone");
    expect(ids).toContain("bugcrowd");
  });

  it("should have correct rate limits", async () => {
    const { CATALOG_BY_ID } = await importCatalog();
    const h1 = CATALOG_BY_ID.get("hackerone");
    const bc = CATALOG_BY_ID.get("bugcrowd");
    expect(h1!.rateLimit).toBe(600);
    expect(bc!.rateLimit).toBe(300);
  });
});

// ─── 3. Monitoring Deployment Script Tests ─────────────────────────────────

import { readFileSync, existsSync } from "fs";
import { join } from "path";

describe("Monitoring Stack Deployment Automation", () => {
  const infraDir = join(__dirname, "..", "infrastructure");

  it("should have deploy-monitoring.sh script", () => {
    const scriptPath = join(infraDir, "scripts", "deploy-monitoring.sh");
    expect(existsSync(scriptPath)).toBe(true);
  });

  it("should have .env.monitoring.template file", () => {
    const templatePath = join(infraDir, "scripts", ".env.monitoring.template");
    expect(existsSync(templatePath)).toBe(true);
  });

  it("deploy-monitoring.sh should have executable shebang", () => {
    const content = readFileSync(join(infraDir, "scripts", "deploy-monitoring.sh"), "utf-8");
    expect(content.startsWith("#!/usr/bin/env bash")).toBe(true);
  });

  it("deploy-monitoring.sh should support --env flag", () => {
    const content = readFileSync(join(infraDir, "scripts", "deploy-monitoring.sh"), "utf-8");
    expect(content).toContain("--env)");
    expect(content).toContain("ENVIRONMENT=");
  });

  it("deploy-monitoring.sh should support --slack-webhook flag", () => {
    const content = readFileSync(join(infraDir, "scripts", "deploy-monitoring.sh"), "utf-8");
    expect(content).toContain("--slack-webhook)");
    expect(content).toContain("SLACK_WEBHOOK_URL");
  });

  it("deploy-monitoring.sh should support --dry-run flag", () => {
    const content = readFileSync(join(infraDir, "scripts", "deploy-monitoring.sh"), "utf-8");
    expect(content).toContain("--dry-run)");
    expect(content).toContain("DRY_RUN=true");
  });

  it("deploy-monitoring.sh should reference ac3-monitoring.yaml template", () => {
    const content = readFileSync(join(infraDir, "scripts", "deploy-monitoring.sh"), "utf-8");
    expect(content).toContain("ac3-monitoring.yaml");
  });

  it("deploy-monitoring.sh should auto-discover ALB", () => {
    const content = readFileSync(join(infraDir, "scripts", "deploy-monitoring.sh"), "utf-8");
    expect(content).toContain("describe-load-balancers");
    expect(content).toContain("ALB_ARN");
  });

  it("deploy-monitoring.sh should validate CloudFormation template", () => {
    const content = readFileSync(join(infraDir, "scripts", "deploy-monitoring.sh"), "utf-8");
    expect(content).toContain("validate-template");
  });

  it("deploy-monitoring.sh should use CAPABILITY_IAM", () => {
    const content = readFileSync(join(infraDir, "scripts", "deploy-monitoring.sh"), "utf-8");
    expect(content).toContain("CAPABILITY_IAM");
  });

  it(".env.monitoring.template should have all configurable thresholds", () => {
    const content = readFileSync(join(infraDir, "scripts", ".env.monitoring.template"), "utf-8");
    expect(content).toContain("CPU_THRESHOLD");
    expect(content).toContain("MEMORY_THRESHOLD");
    expect(content).toContain("ALB_5XX_THRESHOLD");
    expect(content).toContain("ALB_4XX_THRESHOLD");
    expect(content).toContain("RESPONSE_TIME_THRESHOLD");
  });

  it("OPERATOR-RUNBOOK.md should include Step 4 monitoring section", () => {
    const content = readFileSync(join(infraDir, "OPERATOR-RUNBOOK.md"), "utf-8");
    expect(content).toContain("Step 4: Deploy Monitoring & Alerting Stack");
    expect(content).toContain("deploy-monitoring.sh");
  });

  it("OPERATOR-RUNBOOK.md file reference should include monitoring files", () => {
    const content = readFileSync(join(infraDir, "OPERATOR-RUNBOOK.md"), "utf-8");
    expect(content).toContain("deploy-monitoring.sh");
    expect(content).toContain(".env.monitoring.template");
    expect(content).toContain("ac3-monitoring.yaml");
  });
});

// ─── 4. GitHub Workflows Permission Tests ──────────────────────────────────

describe("GitHub Workflows Permission Automation", () => {
  const scriptsDir = join(__dirname, "..", "infrastructure", "scripts");
  const docsDir = join(__dirname, "..", "infrastructure", "docs");

  it("should have setup-github-workflows-permission.sh script", () => {
    expect(existsSync(join(scriptsDir, "setup-github-workflows-permission.sh"))).toBe(true);
  });

  it("should have push-workflow-files.sh script", () => {
    expect(existsSync(join(scriptsDir, "push-workflow-files.sh"))).toBe(true);
  });

  it("should have github-workflows-permission.md documentation", () => {
    expect(existsSync(join(docsDir, "github-workflows-permission.md"))).toBe(true);
  });

  it("setup script should check for gh CLI", () => {
    const content = readFileSync(join(scriptsDir, "setup-github-workflows-permission.sh"), "utf-8");
    expect(content).toContain("gh auth status");
  });

  it("setup script should check token scopes", () => {
    const content = readFileSync(join(scriptsDir, "setup-github-workflows-permission.sh"), "utf-8");
    expect(content).toContain("x-oauth-scopes");
    expect(content).toContain("workflow");
  });

  it("setup script should detect token types (classic, fine-grained, app)", () => {
    const content = readFileSync(join(scriptsDir, "setup-github-workflows-permission.sh"), "utf-8");
    expect(content).toContain("ghp_");
    expect(content).toContain("github_pat_");
    expect(content).toContain("ghs_");
  });

  it("setup script should check repository permissions", () => {
    const content = readFileSync(join(scriptsDir, "setup-github-workflows-permission.sh"), "utf-8");
    expect(content).toContain("repos/$REPO");
    expect(content).toContain("permissions");
  });

  it("push script should support --dry-run flag", () => {
    const content = readFileSync(join(scriptsDir, "push-workflow-files.sh"), "utf-8");
    expect(content).toContain("--dry-run)");
    expect(content).toContain("DRY_RUN=true");
  });

  it("push script should handle workflow permission error gracefully", () => {
    const content = readFileSync(join(scriptsDir, "push-workflow-files.sh"), "utf-8");
    expect(content).toContain("workflow");
    expect(content).toContain("setup-github-workflows-permission.sh");
  });

  it("push script should detect workflow file changes", () => {
    const content = readFileSync(join(scriptsDir, "push-workflow-files.sh"), "utf-8");
    expect(content).toContain(".github/workflows/");
    expect(content).toContain("git diff");
  });

  it("documentation should cover all auth methods", () => {
    const content = readFileSync(join(docsDir, "github-workflows-permission.md"), "utf-8");
    expect(content).toContain("Classic Personal Access Token");
    expect(content).toContain("Fine-Grained Personal Access Token");
    expect(content).toContain("GitHub App");
  });

  it("documentation should include troubleshooting section", () => {
    const content = readFileSync(join(docsDir, "github-workflows-permission.md"), "utf-8");
    expect(content).toContain("Troubleshooting");
    expect(content).toContain("Resource not accessible by integration");
  });

  it("documentation should reference the helper scripts", () => {
    const content = readFileSync(join(docsDir, "github-workflows-permission.md"), "utf-8");
    expect(content).toContain("setup-github-workflows-permission.sh");
    expect(content).toContain("push-workflow-files.sh");
  });
});
