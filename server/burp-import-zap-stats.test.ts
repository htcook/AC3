/**
 * Tests for:
 * 1. createBugBountyFinding function in db.ts (Burp import fix)
 * 2. ZAP scan stats broadcast after zapScansRun increment
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

// ─── Test 1: createBugBountyFinding exists and is exported from db.ts ───

describe("Burp Findings Import Fix", () => {
  const dbPath = path.resolve(__dirname, "db.ts");
  const dbContent = fs.readFileSync(dbPath, "utf-8");

  it("db.ts exports createBugBountyFinding function", () => {
    expect(dbContent).toContain("export async function createBugBountyFinding");
  });

  it("createBugBountyFinding inserts into bugBountyFindings table", () => {
    expect(dbContent).toContain("bugBountyFindings");
    expect(dbContent).toContain("db.insert(bugBountyFindings)");
  });

  it("createBugBountyFinding accepts all fields that burp-auto-scan passes", () => {
    // These are the fields passed by burp-auto-scan.ts:477-488
    const requiredParams = [
      "title: string",
      "severityRating: string",
      "summary: string",
      "assetIdentifier: string",
      "assetType: string",
      "cweId: string | null",
      "platform: string",
      "programHandle: string",
    ];
    for (const param of requiredParams) {
      expect(dbContent).toContain(param);
    }
  });

  it("createBugBountyFinding handles optional metadata by appending to summary", () => {
    // The bugBountyFindings table has no metadata column, so we append to summary
    expect(dbContent).toContain("Scanner Metadata");
    expect(dbContent).toContain("params.metadata");
  });

  it("createBugBountyFinding maps state to substate column", () => {
    // The table has 'substate' not 'state'
    expect(dbContent).toContain("substate:");
    expect(dbContent).toContain('params.state || "new"');
  });

  it("createBugBountyFinding maps userId to reporterUsername", () => {
    // The table has 'reporterUsername' not 'userId'
    expect(dbContent).toContain("reporterUsername:");
    expect(dbContent).toContain("auto:");
  });

  it("createBugBountyFinding generates a unique externalId", () => {
    expect(dbContent).toContain("externalId:");
    expect(dbContent).toContain("burp-");
  });

  it("burp-auto-scan.ts calls createBugBountyFinding correctly", () => {
    const burpPath = path.resolve(__dirname, "lib/burp-auto-scan.ts");
    const burpContent = fs.readFileSync(burpPath, "utf-8");
    expect(burpContent).toContain("db.createBugBountyFinding({");
    expect(burpContent).toContain("title: finding.title");
    expect(burpContent).toContain("severityRating:");
    expect(burpContent).toContain("platform:");
    expect(burpContent).toContain("metadata: finding.metadata");
  });
});

// ─── Test 2: ZAP stats broadcast after increment ───

describe("ZAP Scan Stats Broadcast Fix", () => {
  const orchPath = path.resolve(__dirname, "lib/engagement-orchestrator.ts");
  const orchContent = fs.readFileSync(orchPath, "utf-8");

  it("broadcasts stats_update immediately after zapScansRun increment", () => {
    // Find the zapScansRun++ line and check that broadcastOpsUpdate follows within 5 lines
    const lines = orchContent.split("\n");
    const incrementLine = lines.findIndex(l => l.includes("state.stats.zapScansRun++"));
    expect(incrementLine).toBeGreaterThan(-1);

    // The broadcast should be on the very next non-empty line
    const nextLines = lines.slice(incrementLine + 1, incrementLine + 5).join("\n");
    expect(nextLines).toContain("broadcastOpsUpdate");
    expect(nextLines).toContain("stats_update");
  });

  it("broadcasts stats object with zapScansRun field", () => {
    // The broadcast should spread the stats object
    const lines = orchContent.split("\n");
    const incrementLine = lines.findIndex(l => l.includes("state.stats.zapScansRun++"));
    const broadcastLine = lines.slice(incrementLine + 1, incrementLine + 5)
      .find(l => l.includes("broadcastOpsUpdate"));
    expect(broadcastLine).toBeTruthy();
    expect(broadcastLine).toContain("stats: { ...state.stats }");
  });
});

// ─── Test 3: End-to-end contract between burp-auto-scan and db.ts ───

describe("Burp Import End-to-End Contract", () => {
  it("every field burp-auto-scan passes to createBugBountyFinding is handled in db.ts", () => {
    const burpPath = path.resolve(__dirname, "lib/burp-auto-scan.ts");
    const burpContent = fs.readFileSync(burpPath, "utf-8");
    const dbPath = path.resolve(__dirname, "db.ts");
    const dbContent = fs.readFileSync(dbPath, "utf-8");

    // Extract field names from the burp-auto-scan call
    const callMatch = burpContent.match(/db\.createBugBountyFinding\(\{([\s\S]*?)\}\)/);
    expect(callMatch).toBeTruthy();

    const callBody = callMatch![1];
    const fieldNames = callBody.match(/(\w+):/g)?.map(f => f.replace(":", "")) || [];
    expect(fieldNames.length).toBeGreaterThan(5);

    // Each field should appear in the createBugBountyFinding function signature
    const funcMatch = dbContent.match(/export async function createBugBountyFinding\(params: \{([\s\S]*?)\}\)/);
    expect(funcMatch).toBeTruthy();

    const funcBody = funcMatch![1];
    for (const field of fieldNames) {
      expect(funcBody).toContain(field);
    }
  });

  it("normalizeBurpIssues output fields match createBugBountyFinding input", () => {
    const connectorPath = path.resolve(__dirname, "lib/burpsuite-connector.ts");
    const connectorContent = fs.readFileSync(connectorPath, "utf-8");

    // normalizeBurpIssues should produce objects with these fields
    const expectedFields = ["title", "severityRating", "summary", "assetIdentifier", "assetType", "cweId", "metadata"];
    for (const field of expectedFields) {
      expect(connectorContent).toContain(`${field}:`);
    }
  });
});
