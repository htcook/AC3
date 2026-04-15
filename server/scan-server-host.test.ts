import { describe, it, expect } from "vitest";

describe("SCAN_SERVER_HOST secret", () => {
  it("should be set to a valid IP address", () => {
    const host = process.env.SCAN_SERVER_HOST;
    expect(host).toBeDefined();
    expect(host).toBeTruthy();
    // Validate it's a valid IPv4 address
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    expect(host).toMatch(ipv4Regex);
  });

  it("should be the new scan server IP (137.184.211.238)", () => {
    const host = process.env.SCAN_SERVER_HOST;
    expect(host).toBe("137.184.211.238");
  });

  it("should be reachable via SSH port", async () => {
    const host = process.env.SCAN_SERVER_HOST;
    if (!host) throw new Error("SCAN_SERVER_HOST not set");

    // Test TCP connectivity to SSH port (22)
    const net = await import("net");
    const isReachable = await new Promise<boolean>((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(5000);
      socket.on("connect", () => {
        socket.destroy();
        resolve(true);
      });
      socket.on("timeout", () => {
        socket.destroy();
        resolve(false);
      });
      socket.on("error", () => {
        socket.destroy();
        resolve(false);
      });
      socket.connect(22, host);
    });

    expect(isReachable).toBe(true);
  });
});
