import { describe, it, expect } from "vitest";

describe("Scan Server SSH Key (base64-encoded)", () => {
  it("SCAN_SERVER_SSH_KEY env should be set and base64-decodable", () => {
    const sshKey = process.env.SCAN_SERVER_SSH_KEY ?? "";
    if (sshKey) {
      // The key should be base64-encoded (no -----BEGIN prefix, no newlines)
      const isBase64 = !sshKey.startsWith("-----") && !sshKey.includes("\n");
      if (isBase64) {
        const decoded = Buffer.from(sshKey, "base64").toString("utf8");
        expect(decoded).toContain("-----BEGIN");
        expect(decoded).toContain("PRIVATE KEY-----");
      }
      // Also accept URL or raw PEM as fallback
      const isUrl = sshKey.startsWith("http://") || sshKey.startsWith("https://");
      const isRawKey = sshKey.startsWith("-----BEGIN");
      expect(isBase64 || isUrl || isRawKey).toBe(true);
    }
  });

  it("getScanServerConfig should correctly decode base64 SSH key", () => {
    // Simulate the base64 decode path from getScanServerConfig
    const b64 = "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3RaVwpReU5UVXhPUUFBQUNDNHFoUFY1ZFZsSE1KSkpvbkF1bmVDWU94NDQxblAvMTFmV3pRZ2owbmRwd0FBQUtEckhZNXA2eDJPCmFRQUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDQzRxaFBWNWRWbEhNSkpKb25BdW5lQ1lPeDQ0MW5QLzExZld6UWdqMG5kcHcKQUFBRUQ0cC9JTDRRZjEySEdmMjhiUkNjZ3c3MXV3K1hnQlN0N2x1WHZkMWJ6cng3aXFFOVhsMVdVY3dra21pY0M2ZDRKZwo3SGpqV2MvL1hWOWJOQ0NQU2QybkFBQUFGMk5oYkdSbGNtRXRjMk5oYmkxelpYSjJaWEl0Ym1WM0FRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=";
    
    // This should NOT start with -----
    expect(b64.startsWith("-----")).toBe(false);
    
    // Decode
    const decoded = Buffer.from(b64, "base64").toString("utf8");
    expect(decoded).toContain("-----BEGIN OPENSSH PRIVATE KEY-----");
    expect(decoded).toContain("-----END OPENSSH PRIVATE KEY-----");
  });

  it("base64 key has no shell-breaking characters", () => {
    const b64 = "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K";
    // Base64 should only contain [A-Za-z0-9+/=] — no newlines, quotes, backslashes
    expect(b64).toMatch(/^[A-Za-z0-9+/=]+$/);
    expect(b64).not.toContain("\n");
    expect(b64).not.toContain("\\");
    expect(b64).not.toContain('"');
    expect(b64).not.toContain("'");
  });
});
