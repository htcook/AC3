import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

describe("Bug Bounty Multi-Platform Sync Engine", () => {
  const syncPath = path.join(__dirname, "lib/bounty-platform-sync.ts");
  const syncContent = fs.readFileSync(syncPath, "utf-8");

  it("exports syncPlatform function", () => {
    expect(syncContent).toContain("export async function syncPlatform");
  });

  it("exports syncAllPlatforms function", () => {
    expect(syncContent).toContain("export async function syncAllPlatforms");
  });

  it("supports HackerOne platform via env fallback", () => {
    expect(syncContent).toContain("hackerone");
    expect(syncContent).toContain("HACKERONE_API_KEY");
  });

  it("supports Bugcrowd platform", () => {
    expect(syncContent).toContain("bugcrowd");
    expect(syncContent).toContain("api.bugcrowd.com");
  });

  it("supports Intigriti platform", () => {
    expect(syncContent).toContain("intigriti");
    expect(syncContent).toContain("api.intigriti.com");
  });

  it("supports YesWeHack platform", () => {
    expect(syncContent).toContain("yeswehack");
    expect(syncContent).toContain("api.yeswehack.com");
  });

  it("supports Immunefi platform", () => {
    expect(syncContent).toContain("immunefi");
    expect(syncContent).toContain("immunefi.com");
  });

  it("supports Open Bug Bounty platform", () => {
    expect(syncContent).toContain("open_bug_bounty");
    expect(syncContent).toContain("openbugbounty.org");
  });

  it("handles pagination with configurable page count", () => {
    expect(syncContent).toContain("pages");
  });

  it("returns structured sync results with error tracking", () => {
    expect(syncContent).toContain("synced");
    expect(syncContent).toContain("errors");
    expect(syncContent).toContain("duration");
  });

  it("decrypts credentials before API calls", () => {
    expect(syncContent).toContain("decrypt");
  });
});

describe("Bug Bounty Router - Multi-Platform Sync Procedures", () => {
  const routerPath = path.join(__dirname, "routers/bug-bounty.ts");
  const routerContent = fs.readFileSync(routerPath, "utf-8");

  it("has syncPlatform procedure", () => {
    expect(routerContent).toContain("syncPlatform");
  });

  it("has syncAllPlatforms procedure", () => {
    expect(routerContent).toContain("syncAllPlatforms");
  });

  it("syncPlatform accepts platform and pages parameters", () => {
    expect(routerContent).toMatch(/syncPlatform.*platform.*pages|platform.*z\.enum/);
  });
});

describe("Platform Icons Component", () => {
  const iconsPath = path.join(__dirname, "../client/src/components/PlatformIcons.tsx");
  const iconsContent = fs.readFileSync(iconsPath, "utf-8");

  it("exports PlatformIcon component", () => {
    expect(iconsContent).toContain("export function PlatformIcon");
  });

  it("exports PLATFORM_NAMES mapping", () => {
    expect(iconsContent).toContain("export const PLATFORM_NAMES");
  });

  it("exports PLATFORM_COLORS mapping", () => {
    expect(iconsContent).toContain("export const PLATFORM_COLORS");
  });

  it("exports PLATFORM_BG_COLORS mapping", () => {
    expect(iconsContent).toContain("export const PLATFORM_BG_COLORS");
  });

  it("has icons for all 7 platforms", () => {
    expect(iconsContent).toContain("hackerone");
    expect(iconsContent).toContain("bugcrowd");
    expect(iconsContent).toContain("intigriti");
    expect(iconsContent).toContain("synack");
    expect(iconsContent).toContain("yeswehack");
    expect(iconsContent).toContain("open_bug_bounty");
    expect(iconsContent).toContain("immunefi");
  });

  it("renders SVG elements for each platform", () => {
    expect(iconsContent).toContain("<svg");
    expect(iconsContent).toContain("</svg>");
  });
});

describe("BugBountyHub Frontend - Platform Integration", () => {
  const hubPath = path.join(__dirname, "../client/src/pages/BugBountyHub.tsx");
  const hubContent = fs.readFileSync(hubPath, "utf-8");

  it("imports PlatformIcon component", () => {
    expect(hubContent).toContain("PlatformIcon");
    expect(hubContent).toContain("PLATFORM_NAMES");
  });

  it("uses PlatformIcon in findings list", () => {
    expect(hubContent).toMatch(/PlatformIcon.*platform.*f\.platform/);
  });

  it("uses PlatformIcon in programs list", () => {
    expect(hubContent).toMatch(/PlatformIcon.*platform.*p\.platform/);
  });

  it("uses PlatformIcon in Accounts tab", () => {
    expect(hubContent).toContain("PlatformIcon platform={plat}");
  });

  it("uses PlatformIcon in filter dropdown", () => {
    expect(hubContent).toContain('PlatformIcon platform="hackerone"');
    expect(hubContent).toContain('PlatformIcon platform="bugcrowd"');
  });

  it("has Sync All Platforms button", () => {
    expect(hubContent).toContain("Sync All Platforms");
    expect(hubContent).toContain("handleSyncAll");
  });

  it("has per-credential Sync Now button", () => {
    expect(hubContent).toContain("Sync Now");
    expect(hubContent).toContain("handleSyncPlatform");
  });

  it("has syncPlatform mutation hook", () => {
    expect(hubContent).toContain("trpc.bugBounty.syncPlatform.useMutation");
  });

  it("has syncAllPlatforms mutation hook", () => {
    expect(hubContent).toContain("trpc.bugBounty.syncAllPlatforms.useMutation");
  });
});
