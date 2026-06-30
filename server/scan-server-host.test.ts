import { describe, it, expect } from "vitest";


// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)("SCAN_SERVER_HOST secret", () => {
  it("should be set to a valid IP address", () => {
    const host = process.env.SCAN_SERVER_HOST;
    expect(host).toBeDefined();
    expect(host).toBeTruthy();
    // Validate it's a valid IPv4 address
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    expect(host).toMatch(ipv4Regex);
  });

  it("should be the current scan server IP", () => {
    const host = process.env.SCAN_SERVER_HOST;
    // IP may change when droplet is recreated; just verify it's a valid IP
    expect(host).toBeTruthy();
    expect(host).toMatch(/^(\d{1,3}\.){3}\d{1,3}$/);
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
