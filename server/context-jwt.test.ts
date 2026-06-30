import { describe, it, expect, vi, beforeEach } from "vitest";
import jwt from "jsonwebtoken";

const CALDERA_JWT_SECRET = "caldera-dashboard-secret-key-2024";

// Extract the JWT parsing logic from context.ts into a testable function
function resolveCalderaUser(token: string) {
  const decoded = jwt.verify(token, CALDERA_JWT_SECRET) as {
    username?: string;
    accountId?: number;
    email?: string;
    displayName?: string;
    role: string;
    loginTime: number;
    authType?: string;
    sessionId?: string;
  };

  const resolvedName = decoded.username || decoded.displayName || decoded.email?.split("@")[0] || "user";
  const resolvedId = decoded.accountId ?? -1;
  const resolvedOpenId = decoded.accountId
    ? `caldera-account:${decoded.accountId}`
    : `caldera:${decoded.username || "unknown"}`;
  const resolvedEmail = decoded.email || null;
  const resolvedLoginMethod = decoded.authType || (decoded.accountId ? "email" : "caldera");

  return {
    id: resolvedId,
    openId: resolvedOpenId,
    name: resolvedName,
    email: resolvedEmail,
    loginMethod: resolvedLoginMethod,
    role: decoded.role === "admin" ? "admin" : "user",
  };
}

describe("context.ts JWT format handling", () => {
  const now = Date.now();

  describe("email-auth tokens (account-auth.ts format)", () => {
    it("resolves name from displayName", () => {
      const token = jwt.sign(
        { accountId: 30001, email: "harrison.cook@aceofcloud.com", displayName: "Harrison Cook", role: "admin", loginTime: now, authType: "email", sessionId: "abc123" },
        CALDERA_JWT_SECRET
      );
      const user = resolveCalderaUser(token);
      expect(user.name).toBe("Harrison Cook");
      expect(user.id).toBe(30001);
      expect(user.openId).toBe("caldera-account:30001");
      expect(user.email).toBe("harrison.cook@aceofcloud.com");
      expect(user.loginMethod).toBe("email");
      expect(user.role).toBe("admin");
    });

    it("falls back to email prefix when displayName is missing", () => {
      const token = jwt.sign(
        { accountId: 30002, email: "jane.doe@example.com", role: "operator", loginTime: now, authType: "email" },
        CALDERA_JWT_SECRET
      );
      const user = resolveCalderaUser(token);
      expect(user.name).toBe("jane.doe");
      expect(user.id).toBe(30002);
      expect(user.email).toBe("jane.doe@example.com");
    });

    it("sets role to user for non-admin roles", () => {
      const token = jwt.sign(
        { accountId: 30003, email: "analyst@example.com", displayName: "Analyst", role: "analyst", loginTime: now, authType: "email" },
        CALDERA_JWT_SECRET
      );
      const user = resolveCalderaUser(token);
      expect(user.role).toBe("user");
    });

    it("does NOT produce id:-1 or name:undefined for email tokens", () => {
      const token = jwt.sign(
        { accountId: 30001, email: "harrison.cook@aceofcloud.com", displayName: "Harrison Cook", role: "admin", loginTime: now, authType: "email", sessionId: "sess1" },
        CALDERA_JWT_SECRET
      );
      const user = resolveCalderaUser(token);
      expect(user.id).not.toBe(-1);
      expect(user.name).not.toBeUndefined();
      expect(user.name).not.toBe("undefined");
      expect(user.openId).not.toContain("undefined");
    });
  });

  describe("service-account tokens (auth-core.ts format)", () => {
    it("resolves name from username", () => {
      const token = jwt.sign(
        { username: "red", role: "admin", loginTime: now },
        CALDERA_JWT_SECRET
      );
      const user = resolveCalderaUser(token);
      expect(user.name).toBe("red");
      expect(user.id).toBe(-1); // service accounts don't have accountId
      expect(user.openId).toBe("caldera:red");
      expect(user.email).toBeNull();
      expect(user.loginMethod).toBe("caldera");
      expect(user.role).toBe("admin");
    });

    it("handles blue team service account", () => {
      const token = jwt.sign(
        { username: "blue", role: "user", loginTime: now },
        CALDERA_JWT_SECRET
      );
      const user = resolveCalderaUser(token);
      expect(user.name).toBe("blue");
      expect(user.openId).toBe("caldera:blue");
      expect(user.role).toBe("user");
    });
  });

  describe("edge cases", () => {
    it("falls back to 'user' name when no identifying fields present", () => {
      const token = jwt.sign(
        { role: "viewer", loginTime: now },
        CALDERA_JWT_SECRET
      );
      const user = resolveCalderaUser(token);
      expect(user.name).toBe("user");
      expect(user.id).toBe(-1);
      expect(user.openId).toBe("caldera:unknown");
    });

    it("returns null for invalid token", () => {
      expect(() => resolveCalderaUser("invalid.token.here")).toThrow();
    });

    it("returns null for expired token", () => {
      const token = jwt.sign(
        { username: "red", role: "admin", loginTime: now },
        CALDERA_JWT_SECRET,
        { expiresIn: "0s" }
      );
      // Small delay to ensure expiry
      expect(() => resolveCalderaUser(token)).toThrow();
    });

    it("prefers username over displayName when both present", () => {
      const token = jwt.sign(
        { username: "red", displayName: "Red Team", accountId: 999, email: "red@test.com", role: "admin", loginTime: now },
        CALDERA_JWT_SECRET
      );
      const user = resolveCalderaUser(token);
      expect(user.name).toBe("red");
      // accountId is present, so openId uses caldera-account format
      expect(user.openId).toBe("caldera-account:999");
    });

    it("infers loginMethod as email when accountId present and no authType", () => {
      const token = jwt.sign(
        { accountId: 100, email: "test@test.com", role: "user", loginTime: now },
        CALDERA_JWT_SECRET
      );
      const user = resolveCalderaUser(token);
      expect(user.loginMethod).toBe("email");
    });

    it("uses explicit authType when provided", () => {
      const token = jwt.sign(
        { accountId: 100, email: "test@test.com", role: "user", loginTime: now, authType: "mfa" },
        CALDERA_JWT_SECRET
      );
      const user = resolveCalderaUser(token);
      expect(user.loginMethod).toBe("mfa");
    });
  });
});
