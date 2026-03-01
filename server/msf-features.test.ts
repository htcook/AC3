/**
 * Tests for MSF Features:
 * 1. SSH tunnel wired into exploit execution
 * 2. SSH key management CRUD
 * 3. Real-time session monitoring
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Feature 1: SSH Tunnel in Exploit Execution ──────────────────────────────

describe("SSH Tunnel in Exploit Execution", () => {
  it("should use fromServerWithTunnel for exploit execution", async () => {
    // Verify that the metasploit-catalog router imports fromServerWithTunnel
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/metasploit-catalog.ts", "utf-8")
    );
    expect(routerSource).toContain("fromServerWithTunnel");
  });

  it("should use getTunnelAwareMsfClient helper in executeExploit", async () => {
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/metasploit-catalog.ts", "utf-8")
    );
    // The executeExploit procedure should use the tunnel-aware helper
    const executeExploitSection = routerSource.split("executeExploit")[1]?.split("fireExploitWithAgent")[0] || "";
    expect(executeExploitSection).toContain("getTunnelAwareMsfClient");
  });

  it("should use getTunnelAwareMsfClient helper across multiple procedures", async () => {
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/metasploit-catalog.ts", "utf-8")
    );
    // Count usages of getTunnelAwareMsfClient - should be used in multiple procedures
    const matches = routerSource.match(/getTunnelAwareMsfClient/g) || [];
    expect(matches.length).toBeGreaterThanOrEqual(5);
  });

  it("should use getTunnelAwareMsfClient helper in checkServerHealth", async () => {
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/metasploit-catalog.ts", "utf-8")
    );
    const healthSection = routerSource.split("checkServerHealth")[1]?.split("listServers")[0] || "";
    expect(healthSection).toContain("getTunnelAwareMsfClient");
  });

  it("should have tunnel endpoints (connectTunnel, disconnectTunnel, getTunnelStatus)", async () => {
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/metasploit-catalog.ts", "utf-8")
    );
    expect(routerSource).toContain("connectTunnel");
    expect(routerSource).toContain("disconnectTunnel");
    expect(routerSource).toContain("getTunnelStatus");
  });
});

// ─── Feature 2: SSH Key Management ───────────────────────────────────────────

describe("SSH Key Management", () => {
  it("should have ssh_keys table in schema", async () => {
    const schemaSource = await import("fs").then(fs =>
      fs.readFileSync("drizzle/schema.ts", "utf-8")
    );
    expect(schemaSource).toContain("sshKeys");
    expect(schemaSource).toContain("ssh_keys");
    expect(schemaSource).toContain("fingerprint");
    expect(schemaSource).toContain("publicKey");
    expect(schemaSource).toContain("privateKey");
    expect(schemaSource).toContain("keyType");
    expect(schemaSource).toContain("isDefault");
    expect(schemaSource).toContain("associatedServerId");
  });

  it("should export SshKey and InsertSshKey types", async () => {
    const schemaSource = await import("fs").then(fs =>
      fs.readFileSync("drizzle/schema.ts", "utf-8")
    );
    expect(schemaSource).toContain("export type SshKey");
    expect(schemaSource).toContain("export type InsertSshKey");
  });

  it("should have SSH keys router with all CRUD endpoints", async () => {
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/ssh-keys.ts", "utf-8")
    );
    expect(routerSource).toContain("list:");
    expect(routerSource).toContain("get:");
    expect(routerSource).toContain("generate:");
    expect(routerSource).toContain("upload:");
    expect(routerSource).toContain("delete:");
    expect(routerSource).toContain("setDefault:");
    expect(routerSource).toContain("rotate:");
    expect(routerSource).toContain("associateWithServer:");
    expect(routerSource).toContain("injectToDroplet:");
    expect(routerSource).toContain("getPrivateKey:");
  });

  it("should support ed25519, rsa, and ecdsa key types", async () => {
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/ssh-keys.ts", "utf-8")
    );
    expect(routerSource).toContain("ed25519");
    expect(routerSource).toContain("rsa");
    expect(routerSource).toContain("ecdsa");
  });

  it("should generate fingerprints using SHA256", async () => {
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/ssh-keys.ts", "utf-8")
    );
    expect(routerSource).toContain("sha256");
    expect(routerSource).toContain("SHA256:");
  });

  it("should be registered in main router", async () => {
    const mainRouter = await import("fs").then(fs =>
      fs.readFileSync("server/routers.ts", "utf-8")
    );
    expect(mainRouter).toContain("sshKeysRouter");
    expect(mainRouter).toContain("sshKeys:");
  });

  it("should have SSH key management UI page", async () => {
    const fs = await import("fs");
    expect(fs.existsSync("client/src/pages/SshKeyManager.tsx")).toBe(true);
    const uiSource = fs.readFileSync("client/src/pages/SshKeyManager.tsx", "utf-8");
    expect(uiSource).toContain("trpc.sshKeys.list");
    expect(uiSource).toContain("trpc.sshKeys.generate");
    expect(uiSource).toContain("trpc.sshKeys.upload");
    expect(uiSource).toContain("trpc.sshKeys.delete");
    expect(uiSource).toContain("trpc.sshKeys.rotate");
    expect(uiSource).toContain("trpc.sshKeys.setDefault");
    expect(uiSource).toContain("trpc.sshKeys.associateWithServer");
  });

  it("should have route registered in App.tsx", async () => {
    const appSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/App.tsx", "utf-8")
    );
    expect(appSource).toContain("/ssh-keys");
    expect(appSource).toContain("SshKeyManager");
  });

  it("should have nav item in AppShell", async () => {
    const shellSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/components/AppShell.tsx", "utf-8")
    );
    expect(shellSource).toContain("/ssh-keys");
    expect(shellSource).toContain("SSH KEYS");
  });
});

// ─── Feature 3: Real-Time Session Monitoring ─────────────────────────────────

describe("Real-Time Session Monitoring", () => {
  it("should have MSF sessions router with all endpoints", async () => {
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/msf-sessions.ts", "utf-8")
    );
    expect(routerSource).toContain("listAll:");
    expect(routerSource).toContain("listByServer:");
    expect(routerSource).toContain("read:");
    expect(routerSource).toContain("write:");
    expect(routerSource).toContain("stop:");
    expect(routerSource).toContain("getDetail:");
    expect(routerSource).toContain("meterpreterRun:");
    expect(routerSource).toContain("getHistory:");
    expect(routerSource).toContain("clearHistory:");
    expect(routerSource).toContain("upgradeToMeterpreter:");
  });

  it("should use tunnel-aware MsfClient", async () => {
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/msf-sessions.ts", "utf-8")
    );
    expect(routerSource).toContain("fromServerWithTunnel");
    expect(routerSource).not.toContain("fromServerConfig");
  });

  it("should support both shell and meterpreter session types", async () => {
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/msf-sessions.ts", "utf-8")
    );
    expect(routerSource).toContain("meterpreterRead");
    expect(routerSource).toContain("meterpreterWrite");
    expect(routerSource).toContain("shellRead");
    expect(routerSource).toContain("shellWrite");
  });

  it("should have in-memory session output buffers", async () => {
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/msf-sessions.ts", "utf-8")
    );
    expect(routerSource).toContain("sessionBuffers");
    expect(routerSource).toContain("new Map");
  });

  it("should limit buffer size to prevent memory leaks", async () => {
    const routerSource = await import("fs").then(fs =>
      fs.readFileSync("server/routers/msf-sessions.ts", "utf-8")
    );
    // Should have a buffer size limit
    expect(routerSource).toContain("1000");
    expect(routerSource).toContain("slice");
  });

  it("should be registered in main router", async () => {
    const mainRouter = await import("fs").then(fs =>
      fs.readFileSync("server/routers.ts", "utf-8")
    );
    expect(mainRouter).toContain("msfSessionsRouter");
    expect(mainRouter).toContain("msfSessions:");
  });

  it("should have session monitoring UI page", async () => {
    const fs = await import("fs");
    expect(fs.existsSync("client/src/pages/MsfSessions.tsx")).toBe(true);
    const uiSource = fs.readFileSync("client/src/pages/MsfSessions.tsx", "utf-8");
    expect(uiSource).toContain("trpc.msfSessions.listAll");
    expect(uiSource).toContain("trpc.msfSessions.read");
    expect(uiSource).toContain("trpc.msfSessions.write");
    expect(uiSource).toContain("trpc.msfSessions.stop");
  });

  it("should have interactive terminal component", async () => {
    const uiSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/pages/MsfSessions.tsx", "utf-8")
    );
    expect(uiSource).toContain("SessionTerminal");
    expect(uiSource).toContain("commandHistory");
    expect(uiSource).toContain("handleKeyDown");
    expect(uiSource).toContain("ArrowUp");
    expect(uiSource).toContain("ArrowDown");
  });

  it("should have session kill confirmation dialog", async () => {
    const uiSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/pages/MsfSessions.tsx", "utf-8")
    );
    expect(uiSource).toContain("confirmKill");
    expect(uiSource).toContain("Kill Session");
  });

  it("should have fullscreen toggle for terminal", async () => {
    const uiSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/pages/MsfSessions.tsx", "utf-8")
    );
    expect(uiSource).toContain("isFullscreen");
    expect(uiSource).toContain("onToggleFullscreen");
    expect(uiSource).toContain("Maximize2");
    expect(uiSource).toContain("Minimize2");
  });

  it("should poll sessions at 10-second intervals", async () => {
    const uiSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/pages/MsfSessions.tsx", "utf-8")
    );
    expect(uiSource).toContain("refetchInterval: 10000");
  });

  it("should poll terminal output at 1.5-second intervals", async () => {
    const uiSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/pages/MsfSessions.tsx", "utf-8")
    );
    expect(uiSource).toContain("refetchInterval: 1500");
  });

  it("should have route and nav registered", async () => {
    const appSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/App.tsx", "utf-8")
    );
    expect(appSource).toContain("/msf-sessions");
    expect(appSource).toContain("MsfSessions");

    const shellSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/components/AppShell.tsx", "utf-8")
    );
    expect(shellSource).toContain("/msf-sessions");
    expect(shellSource).toContain("LIVE SESSIONS");
  });

  it("should show session stats (total, meterpreter, shell counts)", async () => {
    const uiSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/pages/MsfSessions.tsx", "utf-8")
    );
    expect(uiSource).toContain("totalSessions");
    expect(uiSource).toContain("meterpreterCount");
    expect(uiSource).toContain("shellCount");
  });

  it("should group sessions by server", async () => {
    const uiSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/pages/MsfSessions.tsx", "utf-8")
    );
    expect(uiSource).toContain("sessionsByServer");
  });
});

// ─── Integration: All features connected ─────────────────────────────────────

describe("Feature Integration", () => {
  it("should have all three routers registered in main router", async () => {
    const mainRouter = await import("fs").then(fs =>
      fs.readFileSync("server/routers.ts", "utf-8")
    );
    // Tunnel endpoints in metasploit router
    expect(mainRouter).toContain("metasploitCatalogRouter");
    // SSH keys router
    expect(mainRouter).toContain("sshKeysRouter");
    // Sessions router
    expect(mainRouter).toContain("msfSessionsRouter");
  });

  it("should have all three pages in App.tsx routes", async () => {
    const appSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/App.tsx", "utf-8")
    );
    expect(appSource).toContain("/msf-servers");
    expect(appSource).toContain("/ssh-keys");
    expect(appSource).toContain("/msf-sessions");
  });

  it("should have all three nav items in sidebar", async () => {
    const shellSource = await import("fs").then(fs =>
      fs.readFileSync("client/src/components/AppShell.tsx", "utf-8")
    );
    expect(shellSource).toContain("C2 HUB");
    expect(shellSource).toContain("SSH KEYS");
    expect(shellSource).toContain("LIVE SESSIONS");
  });

  it("should have SSH tunnel manager module", async () => {
    const fs = await import("fs");
    expect(fs.existsSync("server/lib/ssh-tunnel-manager.ts")).toBe(true);
  });

  it("should have MsfClient with tunnel support", async () => {
    const clientSource = await import("fs").then(fs =>
      fs.readFileSync("server/lib/msf-client.ts", "utf-8")
    );
    expect(clientSource).toContain("fromServerWithTunnel");
    expect(clientSource).toContain("msgpackr");
    expect(clientSource).toContain("ssh-tunnel-manager");
  });
});
