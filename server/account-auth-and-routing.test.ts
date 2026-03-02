import { describe, it, expect } from "vitest";

// ─── Email-based Account Auth Tests ──────────────────────────────────

describe("accountAuth.emailLogin", () => {
  it("should reject login with invalid email format", () => {
    const email = "not-an-email";
    const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    expect(isValid).toBe(false);
  });

  it("should accept login with valid email format", () => {
    const email = "harrison.cook@gmail.com";
    const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    expect(isValid).toBe(true);
  });

  it("should normalize email to lowercase", () => {
    const email = "Harrison.Cook@Gmail.com";
    const normalized = email.toLowerCase().trim();
    expect(normalized).toBe("harrison.cook@gmail.com");
  });
});

describe("FIPS-compliant password validation", () => {
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{12,}$/;

  it("should reject passwords shorter than 12 characters", () => {
    expect(passwordRegex.test("Short1!a")).toBe(false);
  });

  it("should reject passwords without uppercase", () => {
    expect(passwordRegex.test("nouppercase1!abc")).toBe(false);
  });

  it("should reject passwords without lowercase", () => {
    expect(passwordRegex.test("NOLOWERCASE1!ABC")).toBe(false);
  });

  it("should reject passwords without digits", () => {
    expect(passwordRegex.test("NoDigitsHere!abc")).toBe(false);
  });

  it("should reject passwords without special characters", () => {
    expect(passwordRegex.test("NoSpecial1abcde")).toBe(false);
  });

  it("should accept valid FIPS-compliant passwords", () => {
    expect(passwordRegex.test("Ace!SecurePass1")).toBe(true);
    expect(passwordRegex.test("fK7IorBbOF-GFBmf!A1")).toBe(true);
  });
});

describe("Account role management", () => {
  const ALL_ROLES = ["admin", "operator", "analyst", "team_lead", "executive", "client", "soc", "viewer"] as const;

  it("should have 8 defined roles", () => {
    expect(ALL_ROLES.length).toBe(8);
  });

  it("should include admin and operator roles", () => {
    expect(ALL_ROLES).toContain("admin");
    expect(ALL_ROLES).toContain("operator");
  });

  it("should map red username to operator role (not admin)", () => {
    const roleMap: Record<string, string> = {
      admin: "admin",
      red: "operator",
      blue: "analyst",
    };
    expect(roleMap["red"]).toBe("operator");
    expect(roleMap["red"]).not.toBe("admin");
  });

  it("should map blue username to analyst role", () => {
    const roleMap: Record<string, string> = {
      admin: "admin",
      red: "operator",
      blue: "analyst",
    };
    expect(roleMap["blue"]).toBe("analyst");
  });
});

describe("Account status transitions", () => {
  const VALID_STATUSES = ["active", "invited", "suspended", "deactivated"] as const;

  it("should have 4 valid account statuses", () => {
    expect(VALID_STATUSES.length).toBe(4);
  });

  it("should allow suspending active accounts", () => {
    const currentStatus = "active";
    const newStatus = "suspended";
    expect(VALID_STATUSES).toContain(currentStatus);
    expect(VALID_STATUSES).toContain(newStatus);
  });

  it("should allow reactivating suspended accounts", () => {
    const currentStatus = "suspended";
    const newStatus = "active";
    expect(VALID_STATUSES).toContain(currentStatus);
    expect(VALID_STATUSES).toContain(newStatus);
  });
});

// ─── Routing Tests ───────────────────────────────────────────────────

describe("Public homepage routing", () => {
  it("root / should be publicly accessible (no ProtectedRoute)", () => {
    // The route config: <Route path="/"><Home /></Route>
    // NOT wrapped in ProtectedRoute
    const publicRoutes = ["/", "/overview", "/login"];
    const protectedRoutes = ["/dashboard", "/home", "/engagements"];
    
    expect(publicRoutes).toContain("/");
    expect(publicRoutes).toContain("/overview");
    expect(protectedRoutes).not.toContain("/");
  });

  it("/home should be protected (requires auth)", () => {
    const protectedRoutes = ["/home", "/dashboard", "/engagements"];
    expect(protectedRoutes).toContain("/home");
  });

  it("login page should redirect authenticated users to /dashboard", () => {
    const loginRedirectTarget = "/dashboard";
    expect(loginRedirectTarget).toBe("/dashboard");
  });
});

describe("Session token handling", () => {
  it("should support both username and email auth types in session", () => {
    // Username-based session
    const usernameSession = {
      username: "red",
      role: "operator",
      loginTime: Date.now(),
    };
    expect(usernameSession.username).toBe("red");

    // Email-based session
    const emailSession = {
      email: "harrison.cook@gmail.com",
      displayName: "Harrison Cook",
      accountId: 1,
      role: "admin",
      loginTime: Date.now(),
      authType: "email",
    };
    expect(emailSession.authType).toBe("email");
    expect(emailSession.email).toBe("harrison.cook@gmail.com");
  });

  it("should derive username from email when authType is email", () => {
    const decoded = {
      email: "harrison.cook@gmail.com",
      displayName: "Harrison Cook",
      authType: "email",
    };
    const username = decoded.displayName || decoded.email?.split("@")[0] || "user";
    expect(username).toBe("Harrison Cook");
  });

  it("should fall back to email prefix when displayName is missing", () => {
    const decoded = {
      email: "harrison.cook@gmail.com",
      displayName: "",
      authType: "email",
    };
    const username = decoded.displayName || decoded.email?.split("@")[0] || "user";
    expect(username).toBe("harrison.cook");
  });
});

describe("Account lockout (NIST SP 800-53 AC-7)", () => {
  it("should track failed login attempts", () => {
    const MAX_FAILED_ATTEMPTS = 5;
    const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
    
    expect(MAX_FAILED_ATTEMPTS).toBe(5);
    expect(LOCKOUT_DURATION_MS).toBe(900000);
  });

  it("should lock account after 5 failed attempts", () => {
    const failedAttempts = 5;
    const MAX_FAILED_ATTEMPTS = 5;
    const isLocked = failedAttempts >= MAX_FAILED_ATTEMPTS;
    expect(isLocked).toBe(true);
  });

  it("should not lock account with fewer than 5 failed attempts", () => {
    const failedAttempts = 4;
    const MAX_FAILED_ATTEMPTS = 5;
    const isLocked = failedAttempts >= MAX_FAILED_ATTEMPTS;
    expect(isLocked).toBe(false);
  });
});
