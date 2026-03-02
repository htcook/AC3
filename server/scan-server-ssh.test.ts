import { describe, it, expect } from "vitest";

describe("Scan Server SSH Key", () => {
  it("SCAN_SERVER_HOST env var is set", () => {
    expect(process.env.SCAN_SERVER_HOST).toBeDefined();
    expect(process.env.SCAN_SERVER_HOST!.length).toBeGreaterThan(0);
  });

  it("SCAN_SERVER_SSH_KEY env var is set", () => {
    const key = process.env.SCAN_SERVER_SSH_KEY;
    expect(key).toBeDefined();
    expect(key!.length).toBeGreaterThan(10);
  });

  it("RSA key fallback URL is downloadable and contains a valid PEM key", async () => {
    const keyUrl = "https://files.manuscdn.com/user_upload_by_module/session_file/310419663028432609/hHJfIBSNDxDiefRC";
    const resp = await fetch(keyUrl);
    expect(resp.ok).toBe(true);
    const keyContent = await resp.text();
    expect(keyContent).toContain("-----BEGIN RSA PRIVATE KEY-----");
    expect(keyContent).toContain("-----END RSA PRIVATE KEY-----");
  });

  it("getScanServerConfig resolves with valid RSA key (via fallback if needed)", async () => {
    const mod = await import("./lib/scan-server-executor");
    const config = await mod.getScanServerConfigForNmap();
    expect(config.host).toBe(process.env.SCAN_SERVER_HOST);
    expect(config.username).toBe("root");
    // Should resolve to RSA key either directly or via S3 fallback
    expect(config.privateKey).toContain("-----BEGIN RSA PRIVATE KEY-----");
    expect(config.port).toBe(22);
  });
});
