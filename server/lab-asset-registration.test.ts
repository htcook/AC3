/**
 * Lab Asset Auto-Registration & Out-of-Scope Removal Tests
 *
 * Tests for:
 * 1. autoRegisterLabAsset helper — adds lab target, removes nextcloud.com
 * 2. removeOutOfScopeNextcloudAssets helper — standalone removal
 * 3. deployTestLab endpoint — calls autoRegisterLabAsset on success
 * 4. extractScopeUrls — resolves lab IP from updated engagement
 */

import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

// ─── P1: autoRegisterLabAsset function exists and has correct logic ───────────

describe("autoRegisterLabAsset helper", () => {
  const routerPath = path.join(__dirname, "routers/bug-bounty.ts");
  const routerSource = fs.readFileSync(routerPath, "utf-8");

  it("autoRegisterLabAsset function is defined before the router", () => {
    expect(routerSource).toContain("async function autoRegisterLabAsset(");
  });

  it("accepts engagementId, labUrl, and scanServerHost parameters", () => {
    const fnMatch = routerSource.match(
      /async function autoRegisterLabAsset\(\s*engagementId:\s*number,\s*labUrl:\s*string,\s*scanServerHost:\s*string/
    );
    expect(fnMatch).not.toBeNull();
  });

  it("updates engagement targetDomain and targetIpRange", () => {
    const fnBody = extractFunctionBody(routerSource, "autoRegisterLabAsset");
    expect(fnBody).toContain("targetDomain: host");
    expect(fnBody).toContain("targetIpRange: scanServerHost");
  });

  it("loads and filters ops state snapshot assets", () => {
    const fnBody = extractFunctionBody(routerSource, "autoRegisterLabAsset");
    expect(fnBody).toContain("engagementOpsSnapshots");
    expect(fnBody).toContain("filteredAssets");
  });

  it("removes nextcloud.com and *.nextcloud.com domains", () => {
    const fnBody = extractFunctionBody(routerSource, "autoRegisterLabAsset");
    expect(fnBody).toContain("nextcloud.com");
    expect(fnBody).toContain(".nextcloud.com");
    expect(fnBody).toContain("removedOutOfScope.push");
  });

  it("adds lab asset with correct structure (hostname, ports, passiveRecon)", () => {
    const fnBody = extractFunctionBody(routerSource, "autoRegisterLabAsset");
    expect(fnBody).toContain("hostname: `${scanServerHost}:8443`");
    expect(fnBody).toContain("type: 'web_app'");
    expect(fnBody).toContain("inScope: true");
    expect(fnBody).toContain("labDeployed: true");
    expect(fnBody).toContain("port: 8443");
    expect(fnBody).toContain("port: 8444");
  });

  it("checks for duplicate lab asset before adding", () => {
    const fnBody = extractFunctionBody(routerSource, "autoRegisterLabAsset");
    expect(fnBody).toContain("labAssetExists");
    expect(fnBody).toContain("includes(scanServerHost)");
  });

  it("creates a timeline event for the registration", () => {
    const fnBody = extractFunctionBody(routerSource, "autoRegisterLabAsset");
    expect(fnBody).toContain("engagementTimelineEvents");
    expect(fnBody).toContain("Test Lab Auto-Registered as Target");
  });

  it("returns registered status and removed domains list", () => {
    const fnBody = extractFunctionBody(routerSource, "autoRegisterLabAsset");
    expect(fnBody).toContain("return { registered: true, removedOutOfScope }");
  });
});

// ─── P2: removeOutOfScopeNextcloudAssets function ─────────────────────────────

describe("removeOutOfScopeNextcloudAssets helper", () => {
  const routerPath = path.join(__dirname, "routers/bug-bounty.ts");
  const routerSource = fs.readFileSync(routerPath, "utf-8");

  it("removeOutOfScopeNextcloudAssets function is defined", () => {
    expect(routerSource).toContain("async function removeOutOfScopeNextcloudAssets(");
  });

  it("accepts engagementId parameter", () => {
    const fnMatch = routerSource.match(
      /async function removeOutOfScopeNextcloudAssets\(\s*engagementId:\s*number/
    );
    expect(fnMatch).not.toBeNull();
  });

  it("filters out nextcloud.com and *.nextcloud.com hostnames", () => {
    const fnBody = extractFunctionBody(routerSource, "removeOutOfScopeNextcloudAssets");
    expect(fnBody).toContain("nextcloud.com");
    expect(fnBody).toContain(".nextcloud.com");
  });

  it("updates ops snapshot with filtered assets", () => {
    const fnBody = extractFunctionBody(routerSource, "removeOutOfScopeNextcloudAssets");
    expect(fnBody).toContain("state.assets = filteredAssets");
    expect(fnBody).toContain("assetCount: filteredAssets.length");
  });

  it("creates timeline event when assets are removed", () => {
    const fnBody = extractFunctionBody(routerSource, "removeOutOfScopeNextcloudAssets");
    expect(fnBody).toContain("Out-of-Scope Assets Removed");
    expect(fnBody).toContain("engagementTimelineEvents");
  });

  it("returns removed domains and remaining count", () => {
    const fnBody = extractFunctionBody(routerSource, "removeOutOfScopeNextcloudAssets");
    expect(fnBody).toContain("return { removed, remainingCount: filteredAssets.length }");
  });
});

// ─── P3: deployTestLab endpoint calls autoRegisterLabAsset ────────────────────

describe("deployTestLab endpoint auto-registration wiring", () => {
  const routerPath = path.join(__dirname, "routers/bug-bounty.ts");
  const routerSource = fs.readFileSync(routerPath, "utf-8");

  it("deployTestLab endpoint exists", () => {
    expect(routerSource).toContain("deployTestLab: protectedProcedure");
  });

  it("calls autoRegisterLabAsset after successful deploy", () => {
    // Extract the deployTestLab mutation body
    const deploySection = routerSource.slice(
      routerSource.indexOf("deployTestLab: protectedProcedure"),
      routerSource.indexOf("getLabDeploymentStatus:")
    );
    expect(deploySection).toContain("autoRegisterLabAsset");
  });

  it("only auto-registers when status is running and labUrl exists", () => {
    const deploySection = routerSource.slice(
      routerSource.indexOf("deployTestLab: protectedProcedure"),
      routerSource.indexOf("getLabDeploymentStatus:")
    );
    expect(deploySection).toContain('state.status === "running"');
    expect(deploySection).toContain("state.labUrl");
  });

  it("catches and logs auto-register errors without failing deploy", () => {
    const deploySection = routerSource.slice(
      routerSource.indexOf("deployTestLab: protectedProcedure"),
      routerSource.indexOf("getLabDeploymentStatus:")
    );
    expect(deploySection).toContain("catch (err");
    expect(deploySection).toContain("[DeployTestLab] Auto-register failed");
  });
});

// ─── P4: tRPC endpoints for manual asset management ──────────────────────────

describe("Lab asset management tRPC endpoints", () => {
  const routerPath = path.join(__dirname, "routers/bug-bounty.ts");
  const routerSource = fs.readFileSync(routerPath, "utf-8");

  it("removeOutOfScopeAssets endpoint exists", () => {
    expect(routerSource).toContain("removeOutOfScopeAssets: protectedProcedure");
  });

  it("removeOutOfScopeAssets accepts engagementId input", () => {
    const section = routerSource.slice(
      routerSource.indexOf("removeOutOfScopeAssets: protectedProcedure"),
      routerSource.indexOf("registerLabAsset:")
    );
    expect(section).toContain("engagementId: z.number()");
  });

  it("registerLabAsset endpoint exists", () => {
    expect(routerSource).toContain("registerLabAsset: protectedProcedure");
  });

  it("registerLabAsset accepts engagementId, labUrl, scanServerHost", () => {
    const section = routerSource.slice(
      routerSource.indexOf("registerLabAsset: protectedProcedure"),
      routerSource.indexOf("// ─── Burp ↔ Test Lab Bridge")
    );
    expect(section).toContain("engagementId: z.number()");
    expect(section).toContain("labUrl: z.string()");
    expect(section).toContain("scanServerHost: z.string()");
  });
});

// ─── P5: extractScopeUrls resolves lab IP from ops state ──────────────────────

describe("extractScopeUrls resolves lab target", () => {
  it("extractScopeUrls is exported from burp-auto-scan", async () => {
    const { extractScopeUrls } = await import("./lib/burp-auto-scan");
    expect(typeof extractScopeUrls).toBe("function");
  });

  it("resolves lab IP from engagement targetDomain", async () => {
    const { extractScopeUrls } = await import("./lib/burp-auto-scan");
    const engagement = {
      targetDomain: "159.223.152.190",
    };
    const urls = extractScopeUrls(engagement);
    expect(urls).toContain("https://159.223.152.190");
  });

  it("resolves lab asset hostname from ops state", async () => {
    const { extractScopeUrls } = await import("./lib/burp-auto-scan");
    const engagement = {};
    const opsState = {
      assets: [
        { hostname: "159.223.152.190:8443" },
      ],
    };
    const urls = extractScopeUrls(engagement, opsState);
    expect(urls).toContain("https://159.223.152.190:8443");
  });

  it("does NOT include nextcloud.com when removed from ops state", async () => {
    const { extractScopeUrls } = await import("./lib/burp-auto-scan");
    const engagement = {
      targetDomain: "159.223.152.190",
    };
    const opsState = {
      assets: [
        { hostname: "159.223.152.190:8443" },
        // nextcloud.com is NOT here — it was removed
      ],
    };
    const urls = extractScopeUrls(engagement, opsState);
    expect(urls).not.toContain("https://nextcloud.com");
    expect(urls.some((u: string) => u.includes("nextcloud.com"))).toBe(false);
  });
});

// ─── P6: getLabScanTargets resolves from config ──────────────────────────────

describe("getLabScanTargets uses scanServerHost", () => {
  it("getLabScanTargets is exported from test-lab-deployer", async () => {
    const { getLabScanTargets } = await import("./lib/test-lab-deployer");
    expect(typeof getLabScanTargets).toBe("function");
  });

  it("generates URLs using scanServerHost when provided", async () => {
    const { getLabScanTargets } = await import("./lib/test-lab-deployer");
    const config = {
      nextcloudVersion: "30.0.6",
      adminUser: "admin",
      adminPassword: "test",
      labName: "test-lab",
      hostPort: 8443,
      enableCollabora: true,
      enableClamAV: true,
      enableLDAP: true,
      enableKeycloak: true,
      enableElasticsearch: true,
      enableMinIO: true,
      enableMailhog: true,
      enableCoturn: true,
      scanServerHost: "159.223.152.190",
    };
    const targets = getLabScanTargets(config);
    expect(targets.length).toBeGreaterThan(0);
    expect(targets[0]).toBe("https://159.223.152.190:8443");
    expect(targets.every((t: string) => t.includes("159.223.152.190"))).toBe(true);
    expect(targets.some((t: string) => t.includes("nextcloud.com"))).toBe(false);
  });

  it("falls back to localhost when no scanServerHost", async () => {
    const { getLabScanTargets } = await import("./lib/test-lab-deployer");
    const config = {
      nextcloudVersion: "30.0.6",
      adminUser: "admin",
      adminPassword: "test",
      labName: "test-lab",
      hostPort: 8443,
      enableCollabora: false,
      enableClamAV: false,
      enableLDAP: false,
      enableKeycloak: false,
      enableElasticsearch: false,
      enableMinIO: false,
      enableMailhog: false,
      enableCoturn: false,
    };
    const targets = getLabScanTargets(config);
    expect(targets[0]).toBe("https://localhost:8443");
  });
});

// ─── P7: Lab asset structure validation ──────────────────────────────────────

describe("Lab asset data structure", () => {
  const routerPath = path.join(__dirname, "routers/bug-bounty.ts");
  const routerSource = fs.readFileSync(routerPath, "utf-8");

  it("lab asset includes Nextcloud tech stack in passiveRecon", () => {
    const fnBody = extractFunctionBody(routerSource, "autoRegisterLabAsset");
    expect(fnBody).toContain("Nextcloud");
    expect(fnBody).toContain("MariaDB");
    expect(fnBody).toContain("Redis");
    expect(fnBody).toContain("Collabora");
    expect(fnBody).toContain("OpenLDAP");
    expect(fnBody).toContain("Keycloak");
    expect(fnBody).toContain("MinIO");
    expect(fnBody).toContain("ClamAV");
  });

  it("lab asset includes DigitalOcean as cloud provider", () => {
    const fnBody = extractFunctionBody(routerSource, "autoRegisterLabAsset");
    expect(fnBody).toContain("DigitalOcean");
  });

  it("lab asset has AC3 Test Lab Deployer as source", () => {
    const fnBody = extractFunctionBody(routerSource, "autoRegisterLabAsset");
    expect(fnBody).toContain("AC3 Test Lab Deployer");
  });

  it("notes mention HackerOne program rules for out-of-scope removal", () => {
    const fnBody = extractFunctionBody(routerSource, "autoRegisterLabAsset");
    expect(fnBody).toContain("HackerOne program rules");
  });
});

// ─── Utility ─────────────────────────────────────────────────────────────────

function extractFunctionBody(source: string, fnName: string): string {
  const start = source.indexOf(`async function ${fnName}(`);
  if (start === -1) return "";
  // Find the opening brace of the function body (skip return type braces)
  // Look for the pattern ") {" or ">\n{" that starts the actual function body
  const afterParams = source.indexOf(") {", start);
  const afterReturnType = source.indexOf("> {", start);
  // Use whichever comes second (after the return type closing >)
  let braceStart: number;
  if (afterReturnType !== -1 && afterReturnType < afterParams + 500) {
    braceStart = source.indexOf("{", afterReturnType + 2);
  } else if (afterParams !== -1) {
    braceStart = source.indexOf("{", afterParams + 2);
  } else {
    return "";
  }
  if (braceStart === -1) return "";
  // Count braces to find the end
  let depth = 0;
  let end = braceStart;
  for (let i = braceStart; i < source.length; i++) {
    if (source[i] === "{") depth++;
    if (source[i] === "}") depth--;
    if (depth === 0) {
      end = i + 1;
      break;
    }
  }
  return source.slice(start, end);
}
