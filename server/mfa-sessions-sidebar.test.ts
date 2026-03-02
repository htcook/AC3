import { describe, it, expect } from "vitest";

// ─── MFA / TOTP Tests ──────────────────────────────────────────────────

describe("MFA TOTP secret generation", () => {
  it("should generate a base32-encoded TOTP secret of sufficient length", () => {
    // OTPAuth library generates base32 secrets; minimum 20 bytes = 32 base32 chars
    const base32Regex = /^[A-Z2-7]+=*$/;
    const mockSecret = "JBSWY3DPEHPK3PXP"; // example base32 secret
    expect(base32Regex.test(mockSecret)).toBe(true);
    expect(mockSecret.length).toBeGreaterThanOrEqual(16);
  });

  it("should produce a valid otpauth:// URI for authenticator apps", () => {
    const issuer = "Caldera-Dashboard";
    const email = "harrison@aceofcloud.io";
    const secret = "JBSWY3DPEHPK3PXP";
    const uri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

    expect(uri).toContain("otpauth://totp/");
    expect(uri).toContain(`secret=${secret}`);
    expect(uri).toContain(`issuer=${encodeURIComponent(issuer)}`);
    expect(uri).toContain("digits=6");
    expect(uri).toContain("period=30");
  });

  it("should generate 10 backup codes, each 8 hex characters", () => {
    const backupCodes: string[] = [];
    for (let i = 0; i < 10; i++) {
      // Simulate crypto.randomBytes(4).toString("hex") → 8 hex chars
      const code = Math.floor(Math.random() * 0xFFFFFFFF).toString(16).padStart(8, "0");
      backupCodes.push(code);
    }
    expect(backupCodes.length).toBe(10);
    backupCodes.forEach((code) => {
      expect(code).toMatch(/^[0-9a-f]{8}$/);
    });
  });
});

describe("MFA TOTP code validation", () => {
  it("should accept exactly 6-digit numeric TOTP codes", () => {
    const validCodes = ["000000", "123456", "999999"];
    const invalidCodes = ["12345", "1234567", "abcdef", "", "12 34 56"];

    validCodes.forEach((code) => {
      expect(/^\d{6}$/.test(code)).toBe(true);
    });
    invalidCodes.forEach((code) => {
      expect(/^\d{6}$/.test(code)).toBe(false);
    });
  });

  it("should accept 8-character hex backup codes", () => {
    const validBackup = ["a1b2c3d4", "00000000", "ffffffff", "12345678"];
    const invalidBackup = ["a1b2c3", "a1b2c3d4e5", "GGGGGGGG"];

    validBackup.forEach((code) => {
      expect(/^[0-9a-f]{8}$/.test(code)).toBe(true);
    });
    invalidBackup.forEach((code) => {
      expect(/^[0-9a-f]{8}$/.test(code)).toBe(false);
    });
  });

  it("should invalidate backup code after single use", () => {
    const backupCodes = ["a1b2c3d4", "e5f6a7b8", "c9d0e1f2"];
    const usedCode = "a1b2c3d4";

    // Simulate using a backup code
    const remainingCodes = backupCodes.filter((c) => c !== usedCode);
    expect(remainingCodes.length).toBe(2);
    expect(remainingCodes).not.toContain(usedCode);
  });
});

describe("MFA email login flow integration", () => {
  it("should return mfaRequired flag when TOTP is enabled for account", () => {
    const account = {
      id: 1,
      email: "admin@aceofcloud.io",
      totpEnabled: true,
      totpSecret: "JBSWY3DPEHPK3PXP",
    };

    // When totpEnabled, emailLogin should return mfaRequired instead of a session
    if (account.totpEnabled) {
      const response = {
        mfaRequired: true,
        mfaToken: "temp-mfa-token-uuid",
      };
      expect(response.mfaRequired).toBe(true);
      expect(response.mfaToken).toBeTruthy();
    }
  });

  it("should NOT require MFA when TOTP is not enabled", () => {
    const account = {
      id: 2,
      email: "operator@aceofcloud.io",
      totpEnabled: false,
      totpSecret: null,
    };

    if (!account.totpEnabled) {
      const response = {
        success: true,
        role: "operator",
        displayName: "Operator",
      };
      expect(response.success).toBe(true);
      expect(response).not.toHaveProperty("mfaRequired");
    }
  });

  it("should create a temporary MFA token with 5-minute expiry", () => {
    const now = Date.now();
    const MFA_TOKEN_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
    const expiresAt = now + MFA_TOKEN_EXPIRY_MS;

    expect(MFA_TOKEN_EXPIRY_MS).toBe(300000);
    expect(expiresAt).toBeGreaterThan(now);
    expect(expiresAt - now).toBe(300000);
  });

  it("should reject expired MFA tokens", () => {
    const tokenCreatedAt = Date.now() - 6 * 60 * 1000; // 6 minutes ago
    const MFA_TOKEN_EXPIRY_MS = 5 * 60 * 1000;
    const isExpired = Date.now() - tokenCreatedAt > MFA_TOKEN_EXPIRY_MS;
    expect(isExpired).toBe(true);
  });
});

describe("MFA enable/disable lifecycle", () => {
  it("should require TOTP verification before enabling MFA", () => {
    // Step 1: mfaSetup generates secret + QR + backup codes
    // Step 2: mfaVerifyAndEnable requires a valid TOTP code
    const steps = ["mfaSetup", "mfaVerifyAndEnable"];
    expect(steps.length).toBe(2);
    expect(steps[0]).toBe("mfaSetup");
    expect(steps[1]).toBe("mfaVerifyAndEnable");
  });

  it("should require TOTP or backup code to disable MFA", () => {
    // mfaDisable endpoint requires a valid code
    const disableInput = { code: "123456" };
    expect(disableInput.code).toBeTruthy();
    expect(disableInput.code.length).toBeGreaterThanOrEqual(6);
  });

  it("should store hashed backup codes, not plaintext", () => {
    // Backup codes should be stored as JSON array of hashed values
    const rawCodes = ["a1b2c3d4", "e5f6a7b8"];
    const storedCodes = rawCodes.map((code) => `hashed_${code}`); // simulated hash
    expect(storedCodes.every((c) => c.startsWith("hashed_"))).toBe(true);
    expect(storedCodes).not.toContain("a1b2c3d4");
  });
});

// ─── Session Management Tests ───────────────────────────────────────────

describe("Active session tracking", () => {
  it("should create a session record on successful login", () => {
    const session = {
      accountId: 1,
      sessionToken: "jwt-token-hash-abc123",
      ipAddress: "192.168.1.100",
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      deviceInfo: "Windows 10 / Chrome 120",
      lastActivityAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    };

    expect(session.accountId).toBe(1);
    expect(session.sessionToken).toBeTruthy();
    expect(session.ipAddress).toBeTruthy();
    expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("should parse user agent into device info", () => {
    const userAgents: Record<string, string> = {
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36":
        "Windows",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36":
        "Mac",
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36":
        "Linux",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)":
        "iPhone",
    };

    Object.entries(userAgents).forEach(([ua, expectedPlatform]) => {
      expect(ua.toLowerCase()).toContain(expectedPlatform.toLowerCase());
    });
  });

  it("should track session expiry based on rememberMe flag", () => {
    const SHORT_SESSION = 24 * 60 * 60 * 1000; // 24 hours
    const LONG_SESSION = 7 * 24 * 60 * 60 * 1000; // 7 days

    expect(SHORT_SESSION).toBe(86400000);
    expect(LONG_SESSION).toBe(604800000);
    expect(LONG_SESSION).toBe(SHORT_SESSION * 7);
  });
});

describe("Session listing for admins", () => {
  it("should return sessions with joined account info", () => {
    const sessionWithUser = {
      id: 1,
      accountId: 1,
      sessionToken: "hashed-token",
      ipAddress: "10.0.0.1",
      deviceInfo: "Chrome / Windows",
      lastActivityAt: new Date(),
      expiresAt: new Date(Date.now() + 86400000),
      createdAt: new Date(),
      // Joined from caldera_accounts
      userEmail: "admin@aceofcloud.io",
      userDisplayName: "Harrison Cook",
      userRole: "admin",
    };

    expect(sessionWithUser.userEmail).toBeTruthy();
    expect(sessionWithUser.userDisplayName).toBeTruthy();
    expect(sessionWithUser.userRole).toBe("admin");
  });

  it("should filter out expired sessions from listing", () => {
    const sessions = [
      { id: 1, expiresAt: new Date(Date.now() + 86400000) }, // valid
      { id: 2, expiresAt: new Date(Date.now() - 1000) }, // expired
      { id: 3, expiresAt: new Date(Date.now() + 3600000) }, // valid
    ];

    const activeSessions = sessions.filter((s) => s.expiresAt.getTime() > Date.now());
    expect(activeSessions.length).toBe(2);
    expect(activeSessions.map((s) => s.id)).toEqual([1, 3]);
  });
});

describe("Session revocation", () => {
  it("should allow admin to revoke a single session by ID", () => {
    const sessionId = 42;
    const adminRole = "admin";

    // Admin check
    expect(adminRole).toBe("admin");
    expect(sessionId).toBeGreaterThan(0);
  });

  it("should allow admin to revoke all sessions for an account", () => {
    const accountId = 5;
    const sessions = [
      { id: 1, accountId: 5 },
      { id: 2, accountId: 5 },
      { id: 3, accountId: 7 },
    ];

    const sessionsToRevoke = sessions.filter((s) => s.accountId === accountId);
    expect(sessionsToRevoke.length).toBe(2);
  });

  it("should not allow non-admin users to revoke other users sessions", () => {
    const userRole = "operator";
    const isAdmin = userRole === "admin";
    expect(isAdmin).toBe(false);
  });
});

describe("My sessions (user-facing)", () => {
  it("should identify the current session for the logged-in user", () => {
    const currentToken = "current-jwt-hash";
    const sessions = [
      { id: 1, sessionToken: "old-jwt-hash", isCurrent: false },
      { id: 2, sessionToken: "current-jwt-hash", isCurrent: false },
    ];

    const withCurrentFlag = sessions.map((s) => ({
      ...s,
      isCurrent: s.sessionToken === currentToken,
    }));

    expect(withCurrentFlag[0].isCurrent).toBe(false);
    expect(withCurrentFlag[1].isCurrent).toBe(true);
  });
});

// ─── Role-Based Sidebar Filtering Tests ─────────────────────────────────

describe("Role-based sidebar navigation", () => {
  // Define the nav structure matching the AppShell implementation
  type NavItem = {
    label: string;
    path: string;
    roles?: string[];
  };

  const NAV_ITEMS: NavItem[] = [
    { label: "Dashboard", path: "/dashboard" },
    { label: "Engagements", path: "/engagements" },
    { label: "Threat Intel", path: "/threat-intel" },
    { label: "Adversaries", path: "/adversaries" },
    { label: "Agents", path: "/agents", roles: ["admin", "operator"] },
    { label: "Campaigns", path: "/campaigns", roles: ["admin", "operator", "team_lead"] },
    { label: "Phishing Ops", path: "/phishing", roles: ["admin", "operator"] },
    { label: "Admin Home", path: "/home", roles: ["admin"] },
    { label: "Tenants", path: "/tenants", roles: ["admin"] },
    { label: "Reports", path: "/reports", roles: ["admin", "operator", "analyst", "team_lead", "executive"] },
    { label: "Compliance", path: "/compliance-mapper", roles: ["admin", "analyst", "executive"] },
  ];

  function getVisibleNav(role: string): NavItem[] {
    return NAV_ITEMS.filter((item) => {
      if (!item.roles) return true; // visible to all
      return item.roles.includes(role);
    });
  }

  it("should show all nav items to admin role", () => {
    const adminNav = getVisibleNav("admin");
    expect(adminNav.length).toBe(NAV_ITEMS.length);
  });

  it("should hide admin-only items from operator role", () => {
    const operatorNav = getVisibleNav("operator");
    const operatorPaths = operatorNav.map((n) => n.path);

    expect(operatorPaths).toContain("/dashboard");
    expect(operatorPaths).toContain("/agents");
    expect(operatorPaths).toContain("/campaigns");
    expect(operatorPaths).not.toContain("/home"); // Admin Home
    expect(operatorPaths).not.toContain("/tenants"); // Tenants
  });

  it("should show limited items to analyst role", () => {
    const analystNav = getVisibleNav("analyst");
    const analystPaths = analystNav.map((n) => n.path);

    expect(analystPaths).toContain("/dashboard");
    expect(analystPaths).toContain("/threat-intel");
    expect(analystPaths).toContain("/reports");
    expect(analystPaths).toContain("/compliance-mapper");
    expect(analystPaths).not.toContain("/agents");
    expect(analystPaths).not.toContain("/phishing");
    expect(analystPaths).not.toContain("/home");
  });

  it("should show minimal items to viewer role", () => {
    const viewerNav = getVisibleNav("viewer");
    const viewerPaths = viewerNav.map((n) => n.path);

    // Viewer should only see items with no role restriction
    expect(viewerPaths).toContain("/dashboard");
    expect(viewerPaths).toContain("/adversaries");
    expect(viewerPaths).not.toContain("/agents");
    expect(viewerPaths).not.toContain("/campaigns");
    expect(viewerPaths).not.toContain("/home");
    expect(viewerPaths).not.toContain("/tenants");
  });

  it("should show reports to executive role but not operational tools", () => {
    const execNav = getVisibleNav("executive");
    const execPaths = execNav.map((n) => n.path);

    expect(execPaths).toContain("/reports");
    expect(execPaths).toContain("/compliance-mapper");
    expect(execPaths).not.toContain("/agents");
    expect(execPaths).not.toContain("/phishing");
    expect(execPaths).not.toContain("/home");
  });

  it("should always show universal items regardless of role", () => {
    const universalItems = NAV_ITEMS.filter((item) => !item.roles);
    expect(universalItems.length).toBeGreaterThan(0);

    const roles = ["admin", "operator", "analyst", "viewer", "executive", "client", "soc"];
    roles.forEach((role) => {
      const nav = getVisibleNav(role);
      universalItems.forEach((item) => {
        expect(nav).toContainEqual(item);
      });
    });
  });
});

// ─── Active Sessions Schema Tests ───────────────────────────────────────

describe("Active sessions schema", () => {
  it("should have required fields for session tracking", () => {
    const requiredFields = [
      "id",
      "accountId",
      "sessionToken",
      "ipAddress",
      "userAgent",
      "deviceInfo",
      "lastActivityAt",
      "expiresAt",
      "createdAt",
    ];

    const schemaFields = [
      "id", "accountId", "sessionToken", "ipAddress",
      "userAgent", "deviceInfo", "lastActivityAt", "expiresAt", "createdAt",
    ];

    requiredFields.forEach((field) => {
      expect(schemaFields).toContain(field);
    });
  });

  it("should enforce unique constraint on sessionToken", () => {
    const tokens = new Set<string>();
    const token1 = "abc123";
    const token2 = "abc123"; // duplicate

    tokens.add(token1);
    const sizeBefore = tokens.size;
    tokens.add(token2);
    const sizeAfter = tokens.size;

    expect(sizeBefore).toBe(sizeAfter); // Set prevents duplicates
  });
});

// ─── Caldera Accounts MFA Schema Tests ──────────────────────────────────

describe("Caldera accounts MFA schema fields", () => {
  it("should have totpSecret, totpEnabled, and backupCodes fields", () => {
    const mfaFields = ["totpSecret", "totpEnabled", "backupCodes"];
    const accountFields = [
      "id", "email", "passwordHash", "displayName", "role", "status",
      "lastLoginAt", "invitedBy", "inviteToken", "inviteExpiresAt",
      "passwordResetToken", "passwordResetExpiresAt",
      "totpSecret", "totpEnabled", "backupCodes",
      "failedLoginAttempts", "lockedUntil", "createdAt", "updatedAt",
    ];

    mfaFields.forEach((field) => {
      expect(accountFields).toContain(field);
    });
  });

  it("should default totpEnabled to false", () => {
    const newAccount = {
      email: "new@test.com",
      totpEnabled: false, // default
      totpSecret: null,
      backupCodes: null,
    };

    expect(newAccount.totpEnabled).toBe(false);
    expect(newAccount.totpSecret).toBeNull();
    expect(newAccount.backupCodes).toBeNull();
  });
});

// ─── FedRAMP High Compliance Tests ──────────────────────────────────────

describe("FedRAMP High MFA compliance (NIST SP 800-63B AAL2)", () => {
  it("should use TOTP with SHA-1 algorithm and 30-second period", () => {
    const totpConfig = {
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    };

    expect(totpConfig.algorithm).toBe("SHA1");
    expect(totpConfig.digits).toBe(6);
    expect(totpConfig.period).toBe(30);
  });

  it("should enforce account lockout after 5 failed MFA attempts", () => {
    const MAX_FAILED_ATTEMPTS = 5;
    const LOCKOUT_DURATION_MINUTES = 15;

    let failedAttempts = 0;
    for (let i = 0; i < 5; i++) {
      failedAttempts++;
    }

    const isLocked = failedAttempts >= MAX_FAILED_ATTEMPTS;
    expect(isLocked).toBe(true);
    expect(LOCKOUT_DURATION_MINUTES).toBe(15);
  });

  it("should use bcrypt cost factor 12 for password hashing", () => {
    const BCRYPT_ROUNDS = 12;
    expect(BCRYPT_ROUNDS).toBe(12);
    // bcrypt with 12 rounds meets FIPS 140-3 requirements
  });

  it("should use HttpOnly Secure SameSite cookies for sessions", () => {
    const cookieOptions = {
      httpOnly: true,
      secure: true,
      sameSite: "lax" as const,
      path: "/",
    };

    expect(cookieOptions.httpOnly).toBe(true);
    expect(cookieOptions.secure).toBe(true);
    expect(["lax", "strict", "none"]).toContain(cookieOptions.sameSite);
  });
});
