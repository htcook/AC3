import { describe, it, expect } from "vitest";

/**
 * These tests validate the scan server SSH configuration.
 * The SCAN_SERVER_HOST was updated to 137.184.211.238 after the droplet
 * was recreated. The .env update is handled by webdev_request_secrets
 * and applied at deployment time.
 */
describe("Scan Server SSH Secrets", () => {
  it("SCAN_SERVER_HOST should be a valid IP address", () => {
    const host = process.env.SCAN_SERVER_HOST;
    expect(host).toBeDefined();
    expect(host).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
  });

  it("SCAN_SERVER_SSH_KEY should be set and decodable", () => {
    const key = process.env.SCAN_SERVER_SSH_KEY ?? "";
    expect(key.length).toBeGreaterThan(50);

    // Accept base64, URL, or raw PEM
    const isBase64 = !key.startsWith("-----") && !key.startsWith("http");
    const isUrl = key.startsWith("http://") || key.startsWith("https://");
    const isRawPem = key.startsWith("-----BEGIN");

    expect(isBase64 || isUrl || isRawPem).toBe(true);

    if (isBase64) {
      const decoded = Buffer.from(key, "base64").toString("utf8");
      expect(decoded).toContain("PRIVATE KEY");
    }
  });

  it("getScanServerConfig should resolve with valid host and key", async () => {
    const { getScanServerConfig } = await import(
      "./lib/scan-server-executor.js"
    );
    const config = await getScanServerConfig();
    expect(config.host).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
    expect(config.username).toBe("root");
    expect(config.privateKey).toContain("PRIVATE KEY");
  });

  it("new scan server IP 137.184.211.238 should be reachable", async () => {
    // Simple TCP connectivity check to SSH port
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
        resolve(false);
      });
      socket.connect(22, "137.184.211.238");
    });
    expect(isReachable).toBe(true);
  });
});
