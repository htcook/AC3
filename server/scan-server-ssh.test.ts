import { describe, it, expect } from "vitest";

describe("Scan Server SSH Key Validation", () => {
  it("SCAN_SERVER_HOST is set to the new IP", () => {
    expect(process.env.SCAN_SERVER_HOST).toBe("159.223.152.190");
  });

  it("SCAN_SERVER_SSH_KEY is set and contains valid OpenSSH header", () => {
    const key = process.env.SCAN_SERVER_SSH_KEY || "";
    expect(key.length).toBeGreaterThan(200);
    const decoded = key.replace(/\\n/g, "\n");
    expect(decoded).toContain("-----BEGIN OPENSSH PRIVATE KEY-----");
    expect(decoded).toContain("-----END OPENSSH PRIVATE KEY-----");
  });

  it("SCAN_SERVER_SSH_KEY has correct line structure (no truncation)", () => {
    const key = process.env.SCAN_SERVER_SSH_KEY || "";
    const decoded = key.replace(/\\n/g, "\n");
    const lines = decoded
      .split("\n")
      .filter((l) => l.length > 0 && !l.startsWith("-----"));
    // All base64 lines should be <= 70 chars
    for (const line of lines) {
      expect(line.length).toBeLessThanOrEqual(70);
    }
    // Should have at least 5 base64 lines for a valid ed25519 key
    expect(lines.length).toBeGreaterThanOrEqual(5);
  });

  it("SCAN_SERVER_SSH_KEY decodes to valid openssh-key-v1 format with correct size", () => {
    const key = process.env.SCAN_SERVER_SSH_KEY || "";
    const decoded = key.replace(/\\n/g, "\n");
    const lines = decoded
      .split("\n")
      .filter((l) => l.length > 0 && !l.startsWith("-----"));
    const b64 = lines.join("");
    const buf = Buffer.from(b64, "base64");
    // Should start with openssh-key-v1 magic
    const magic = buf.subarray(0, 15).toString();
    expect(magic).toBe("openssh-key-v1\0");
    // A valid ed25519 key should be ~258 bytes (the old corrupted one was 251)
    expect(buf.length).toBeGreaterThan(255);
  });

  it("SSH connection to scan server succeeds", async () => {
    const { Client } = await import("ssh2");
    const key = (process.env.SCAN_SERVER_SSH_KEY || "").replace(/\\n/g, "\n");
    const host = process.env.SCAN_SERVER_HOST || "";

    const result = await new Promise<string>((resolve, reject) => {
      const conn = new Client();
      const timeout = setTimeout(() => {
        conn.end();
        reject(new Error("SSH connection timeout"));
      }, 15000);

      conn
        .on("ready", () => {
          conn.exec("echo SSH_OK && hostname", (err, stream) => {
            if (err) {
              clearTimeout(timeout);
              conn.end();
              reject(err);
              return;
            }
            let output = "";
            stream.on("data", (d: Buffer) => {
              output += d.toString();
            });
            stream.on("close", () => {
              clearTimeout(timeout);
              conn.end();
              resolve(output.trim());
            });
          });
        })
        .on("error", (err) => {
          clearTimeout(timeout);
          reject(err);
        })
        .connect({
          host,
          port: 22,
          username: process.env.SCAN_SERVER_USER || "root",
          privateKey: key,
          readyTimeout: 15000,
        });
    });

    expect(result).toContain("SSH_OK");
    expect(result).toContain("caldera-scan-server");
  }, 20000);
});
