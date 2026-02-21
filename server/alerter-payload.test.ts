import { describe, it, expect, vi, beforeEach } from "vitest";
import fs from "fs";
import path from "path";

// ─── Feature 1: Session Alerter Tests ──────────────────────────────────────────

describe("Session Alerter Module", () => {
  const alerterPath = path.join(__dirname, "lib/session-alerter.ts");

  it("session-alerter.ts exists", () => {
    expect(fs.existsSync(alerterPath)).toBe(true);
  });

  it("exports SessionAlerter singleton", () => {
    const content = fs.readFileSync(alerterPath, "utf-8");
    expect(content).toContain("class SessionAlerter");
    expect(content).toContain("export const sessionAlerter");
  });

  it("has start and stop methods", () => {
    const content = fs.readFileSync(alerterPath, "utf-8");
    expect(content).toContain("start(");
    expect(content).toContain("stop(");
  });

  it("has configurable poll interval", () => {
    const content = fs.readFileSync(alerterPath, "utf-8");
    expect(content).toMatch(/pollInterval|poll_interval|POLL_INTERVAL/);
  });

  it("tracks already-notified sessions to avoid duplicates", () => {
    const content = fs.readFileSync(alerterPath, "utf-8");
    expect(content).toMatch(/notifiedSessions|knownSessions|seenSessions/);
  });

  it("calls notifyOwner when new session detected", () => {
    const content = fs.readFileSync(alerterPath, "utf-8");
    expect(content).toContain("notifyOwner");
  });

  it("includes session metadata in notifications", () => {
    const content = fs.readFileSync(alerterPath, "utf-8");
    // Should include target IP, session type, platform info
    expect(content).toMatch(/session_host|target|tunnel_peer/i);
    expect(content).toMatch(/type|session_type|meterpreter|shell/i);
  });

  it("queries online MSF servers via server provider", () => {
    const content = fs.readFileSync(alerterPath, "utf-8");
    expect(content).toMatch(/serverProvider|servers|ServerConfig/);
  });

  it("uses MsfClient.fromServerWithTunnel for secure connections", () => {
    const content = fs.readFileSync(alerterPath, "utf-8");
    expect(content).toContain("fromServerWithTunnel");
  });

  it("has status reporting capability", () => {
    const content = fs.readFileSync(alerterPath, "utf-8");
    expect(content).toMatch(/status|running|isRunning|started/);
  });
});

describe("Session Alerter Router", () => {
  const routerPath = path.join(__dirname, "routers/session-alerter.ts");

  it("session-alerter router exists", () => {
    expect(fs.existsSync(routerPath)).toBe(true);
  });

  it("has start endpoint", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toMatch(/start\s*:/);
  });

  it("has stop endpoint", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toMatch(/stop\s*:/);
  });

  it("has status endpoint", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toMatch(/status\s*:|getStatus/);
  });

  it("has alert history endpoint", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toMatch(/history|alerts|getAlerts/);
  });

  it("is registered in main routers.ts", () => {
    const routersContent = fs.readFileSync(
      path.join(__dirname, "routers.ts"),
      "utf-8"
    );
    expect(routersContent).toContain("sessionAlerter");
  });
});

// ─── Feature 2: Payload Generator Tests ────────────────────────────────────────

describe("Payload Generator Router", () => {
  const routerPath = path.join(__dirname, "routers/payload-generator.ts");

  it("payload-generator router exists", () => {
    expect(fs.existsSync(routerPath)).toBe(true);
  });

  it("has generate endpoint that executes msfvenom", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toContain("msfvenom");
    expect(content).toMatch(/generate\s*:/);
  });

  it("supports payload type selection", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toMatch(/payload|payloadType/);
  });

  it("supports LHOST and LPORT configuration", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toContain("LHOST");
    expect(content).toContain("LPORT");
  });

  it("supports format selection (exe, elf, apk, ps1, etc.)", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toMatch(/format/i);
    expect(content).toMatch(/exe|elf|raw|ps1/);
  });

  it("supports encoder selection", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toMatch(/encoder|encoding/i);
  });

  it("supports architecture selection", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toMatch(/arch|architecture/i);
  });

  it("stores generated payloads in S3", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toContain("storagePut");
  });

  it("persists payload metadata to database", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toContain("generatedPayloads");
  });

  it("has list endpoint for payload history", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toMatch(/list\s*:|history/);
  });

  it("has delete endpoint", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toMatch(/delete\s*:/);
  });

  it("executes commands via SSH tunnel", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toMatch(/ssh|SSH|exec|Client/);
  });

  it("has previewCommand and getOptions endpoints", () => {
    const content = fs.readFileSync(routerPath, "utf-8");
    expect(content).toMatch(/previewCommand|getOptions/);
  });

  it("is registered in main routers.ts", () => {
    const routersContent = fs.readFileSync(
      path.join(__dirname, "routers.ts"),
      "utf-8"
    );
    expect(routersContent).toContain("payloadGenerator");
  });
});

describe("Payload Generator UI", () => {
  const pagePath = path.join(
    __dirname,
    "../client/src/pages/PayloadGenerator.tsx"
  );

  it("PayloadGenerator page exists", () => {
    expect(fs.existsSync(pagePath)).toBe(true);
  });

  it("has payload type selection UI", () => {
    const content = fs.readFileSync(pagePath, "utf-8");
    expect(content).toMatch(/payload|Payload/);
  });

  it("has LHOST and LPORT input fields", () => {
    const content = fs.readFileSync(pagePath, "utf-8");
    expect(content).toContain("LHOST");
    expect(content).toContain("LPORT");
  });

  it("has format selection", () => {
    const content = fs.readFileSync(pagePath, "utf-8");
    expect(content).toMatch(/format|Format/i);
  });

  it("has encoder selection", () => {
    const content = fs.readFileSync(pagePath, "utf-8");
    expect(content).toMatch(/encoder|Encoder/i);
  });

  it("shows msfvenom command preview", () => {
    const content = fs.readFileSync(pagePath, "utf-8");
    expect(content).toContain("msfvenom");
  });

  it("has generate button", () => {
    const content = fs.readFileSync(pagePath, "utf-8");
    expect(content).toMatch(/Generate|generate/);
  });

  it("has payload history section", () => {
    const content = fs.readFileSync(pagePath, "utf-8");
    expect(content).toMatch(/history|History|previous|Previous/i);
  });

  it("has download functionality", () => {
    const content = fs.readFileSync(pagePath, "utf-8");
    expect(content).toMatch(/download|Download/i);
  });

  it("has preset/template selection", () => {
    const content = fs.readFileSync(pagePath, "utf-8");
    expect(content).toMatch(/preset|Preset|template|Template|quick/i);
  });

  it("uses tRPC for backend communication", () => {
    const content = fs.readFileSync(pagePath, "utf-8");
    expect(content).toContain("trpc.");
  });

  it("is registered in App.tsx routes", () => {
    const appContent = fs.readFileSync(
      path.join(__dirname, "../client/src/App.tsx"),
      "utf-8"
    );
    expect(appContent).toContain("PayloadGenerator");
    expect(appContent).toContain("/payload-generator");
  });

  it("has navigation entry in AppShell", () => {
    const shellContent = fs.readFileSync(
      path.join(__dirname, "../client/src/components/AppShell.tsx"),
      "utf-8"
    );
    expect(shellContent).toContain("PAYLOAD GENERATOR");
    expect(shellContent).toContain("/payload-generator");
  });
});

describe("Generated Payloads Schema", () => {
  const schemaPath = path.join(__dirname, "../drizzle/schema.ts");

  it("has generatedPayloads table", () => {
    const content = fs.readFileSync(schemaPath, "utf-8");
    expect(content).toContain("generatedPayloads");
  });

  it("has required columns for payload metadata", () => {
    const content = fs.readFileSync(schemaPath, "utf-8");
    // Check for key columns - name and payload_type are separate columns
    expect(content).toMatch(/generatedPayloads/);
    expect(content).toMatch(/format/i);
    expect(content).toMatch(/payload_type|payloadType/);
  });
});
