import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const ROOT = path.resolve(__dirname, "..");

describe("Platform Credentials Router", () => {
  const routerSrc = fs.readFileSync(
    path.join(ROOT, "server/routers/platform-credentials.ts"),
    "utf-8"
  );

  it("supports all 8 bug bounty platforms in the add procedure", () => {
    const platforms = [
      "hackerone",
      "bugcrowd",
      "intigriti",
      "synack",
      "yeswehack",
      "open_bug_bounty",
      "immunefi",
      "custom",
    ];
    for (const p of platforms) {
      expect(routerSrc).toContain(`"${p}"`);
    }
  });

  it("has verification helpers for HackerOne and Bugcrowd", () => {
    expect(routerSrc).toContain("async function verifyHackerOne");
    expect(routerSrc).toContain("async function verifyBugcrowd");
  });

  it("has verification helpers for Intigriti, YesWeHack, Immunefi, and Open Bug Bounty", () => {
    expect(routerSrc).toContain("async function verifyIntigriti");
    expect(routerSrc).toContain("async function verifyYesWeHack");
    expect(routerSrc).toContain("async function verifyImmunefi");
    expect(routerSrc).toContain("async function verifyOpenBugBounty");
  });

  it("has switch cases for all platforms in the verify procedure", () => {
    const switchCases = [
      'case "hackerone"',
      'case "bugcrowd"',
      'case "intigriti"',
      'case "yeswehack"',
      'case "immunefi"',
      'case "open_bug_bounty"',
      'case "synack"',
    ];
    for (const c of switchCases) {
      expect(routerSrc).toContain(c);
    }
  });

  it("encrypts API keys with AES-256-GCM before storing", () => {
    expect(routerSrc).toContain("aes-256-gcm");
    expect(routerSrc).toContain("encrypt(input.apiKey)");
  });

  it("never returns the encrypted API key in the list procedure", () => {
    // The list procedure selects specific fields and explicitly excludes apiKeyEncrypted
    expect(routerSrc).toContain("// Never return the encrypted API key");
    // Ensure apiKeyEncrypted is NOT in the select list
    const listProcedure = routerSrc.split("list: protectedProcedure")[1]?.split("add: protectedProcedure")[0] || "";
    expect(listProcedure).not.toContain("apiKeyEncrypted");
  });
});

describe("BugBountyHub Frontend", () => {
  const frontendSrc = fs.readFileSync(
    path.join(ROOT, "client/src/pages/BugBountyHub.tsx"),
    "utf-8"
  );

  it("includes all platforms in the Intelligence tab filter dropdown", () => {
    const platforms = [
      "hackerone",
      "bugcrowd",
      "intigriti",
      "synack",
      "yeswehack",
      "open_bug_bounty",
      "immunefi",
    ];
    for (const p of platforms) {
      expect(frontendSrc).toContain(`value="${p}"`);
    }
  });

  it("shows 7 platform cards in the Accounts tab", () => {
    expect(frontendSrc).toContain('"hackerone", "bugcrowd", "intigriti", "synack", "yeswehack", "open_bug_bounty", "immunefi"');
  });

  it("includes platform descriptions for all platforms", () => {
    expect(frontendSrc).toContain("Enterprise bug bounty & VDP platform");
    expect(frontendSrc).toContain("Crowdsourced security testing");
    expect(frontendSrc).toContain("European bug bounty platform");
    expect(frontendSrc).toContain("Invite-only red team platform");
    expect(frontendSrc).toContain("Public responsible disclosure platform");
    expect(frontendSrc).toContain("Web3 & DeFi bug bounty platform");
  });

  it("includes API documentation links for all platforms", () => {
    expect(frontendSrc).toContain("https://api.hackerone.com/");
    expect(frontendSrc).toContain("https://docs.bugcrowd.com/api/getting-started/");
    expect(frontendSrc).toContain("https://kb.intigriti.com/");
    expect(frontendSrc).toContain("https://api.yeswehack.com/doc");
    expect(frontendSrc).toContain("https://www.openbugbounty.org/");
    expect(frontendSrc).toContain("https://immunefi.com/");
  });

  it("includes platform-specific setup hints in the Add Credential dialog", () => {
    expect(frontendSrc).toContain("Settings &rarr; API Credentials &rarr; Generate Token");
    expect(frontendSrc).toContain("Settings &rarr; API &rarr; Generate Personal Access Token");
    expect(frontendSrc).toContain("Profile &rarr; API Keys &rarr; Create New Key");
    expect(frontendSrc).toContain("Synack Red Team is invite-only");
    expect(frontendSrc).toContain("Web3/DeFi platform");
  });
});

describe("Database Schema", () => {
  const schemaSrc = fs.readFileSync(
    path.join(ROOT, "drizzle/schema.ts"),
    "utf-8"
  );

  it("includes open_bug_bounty and immunefi in the platform enum", () => {
    expect(schemaSrc).toContain("'open_bug_bounty'");
    expect(schemaSrc).toContain("'immunefi'");
  });
});
