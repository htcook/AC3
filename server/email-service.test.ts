/**
 * Email Service & Templates Tests
 *
 * Tests for:
 *   - Email template generation (invite, password reset, activation, alerts, daily summary)
 *   - Email service configuration detection
 *   - Template content correctness
 */
import { describe, it, expect } from "vitest";
import {
  teamInviteEmail,
  passwordResetEmail,
  accountActivatedEmail,
  newRegistrationAlertEmail,
  securityAlertEmail,
  dailySummaryEmail,
  type InviteEmailParams,
  type PasswordResetEmailParams,
  type AccountActivatedEmailParams,
  type NewRegistrationAlertParams,
  type SecurityAlertEmailParams,
  type DailySummaryEmailParams,
} from "./lib/email-templates";

// ─── Team Invite Email ──────────────────────────────────────────────────────

describe("teamInviteEmail", () => {
  const baseParams: InviteEmailParams = {
    recipientEmail: "newuser@example.com",
    inviterName: "Harrison Cook",
    role: "operator",
    inviteToken: "test-token-abc123",
    baseUrl: "https://ac3.aceofcloud.io",
    expiresInHours: 72,
  };

  it("generates subject with inviter name", () => {
    const result = teamInviteEmail(baseParams);
    expect(result.subject).toContain("Harrison Cook");
    expect(result.subject).toContain("AC3");
  });

  it("generates HTML with invite URL containing token", () => {
    const result = teamInviteEmail(baseParams);
    expect(result.html).toContain("accept-invite?token=test-token-abc123");
    expect(result.html).toContain("https://ac3.aceofcloud.io");
  });

  it("includes role in HTML body", () => {
    const result = teamInviteEmail(baseParams);
    expect(result.html).toContain("Operator");
  });

  it("includes expiry hours in HTML body", () => {
    const result = teamInviteEmail(baseParams);
    expect(result.html).toContain("72 hours");
  });

  it("includes personal message when provided", () => {
    const result = teamInviteEmail({
      ...baseParams,
      personalMessage: "Welcome to the team!",
    });
    expect(result.html).toContain("Welcome to the team!");
  });

  it("generates plain text version with invite URL", () => {
    const result = teamInviteEmail(baseParams);
    expect(result.text).toContain("accept-invite?token=test-token-abc123");
    expect(result.text).toContain("Harrison Cook");
  });

  it("includes recipient name when provided", () => {
    const result = teamInviteEmail({
      ...baseParams,
      recipientName: "Alice",
    });
    expect(result.html).toContain("Hello Alice,");
  });

  it("uses generic greeting when no recipient name", () => {
    const result = teamInviteEmail(baseParams);
    expect(result.html).toContain("Hello,");
  });

  it("formats multi-word roles correctly", () => {
    const result = teamInviteEmail({ ...baseParams, role: "team_lead" });
    expect(result.html).toContain("Team Lead");
  });
});

// ─── Password Reset Email ───────────────────────────────────────────────────

describe("passwordResetEmail", () => {
  const baseParams: PasswordResetEmailParams = {
    recipientEmail: "user@example.com",
    resetToken: "reset-token-xyz789",
    baseUrl: "https://ac3.aceofcloud.io",
    expiresInMinutes: 30,
  };

  it("generates subject line for password reset", () => {
    const result = passwordResetEmail(baseParams);
    expect(result.subject).toContain("Password Reset");
  });

  it("generates HTML with reset URL containing token", () => {
    const result = passwordResetEmail(baseParams);
    expect(result.html).toContain("reset-password?token=reset-token-xyz789");
  });

  it("includes expiry minutes in HTML body", () => {
    const result = passwordResetEmail(baseParams);
    expect(result.html).toContain("30 minutes");
  });

  it("includes IP address when provided", () => {
    const result = passwordResetEmail({
      ...baseParams,
      ipAddress: "192.168.1.100",
    });
    expect(result.html).toContain("192.168.1.100");
  });

  it("includes user agent when provided", () => {
    const result = passwordResetEmail({
      ...baseParams,
      ipAddress: "10.0.0.1",
      userAgent: "Mozilla/5.0 Chrome",
    });
    expect(result.html).toContain("Mozilla/5.0 Chrome");
  });

  it("generates plain text version", () => {
    const result = passwordResetEmail(baseParams);
    expect(result.text).toContain("reset-password?token=reset-token-xyz789");
    expect(result.text).toContain("30 minutes");
  });
});

// ─── Account Activated Email ────────────────────────────────────────────────

describe("accountActivatedEmail", () => {
  const baseParams: AccountActivatedEmailParams = {
    recipientEmail: "alice@example.com",
    recipientName: "Alice Johnson",
    role: "operator",
    baseUrl: "https://ac3.aceofcloud.io",
  };

  it("generates welcome subject", () => {
    const result = accountActivatedEmail(baseParams);
    expect(result.subject).toContain("Welcome");
    expect(result.subject).toContain("Account Activated");
  });

  it("includes user name in greeting", () => {
    const result = accountActivatedEmail(baseParams);
    expect(result.html).toContain("Alice Johnson");
  });

  it("includes role and email in details", () => {
    const result = accountActivatedEmail(baseParams);
    expect(result.html).toContain("alice@example.com");
    expect(result.html).toContain("Operator");
  });

  it("includes login URL", () => {
    const result = accountActivatedEmail(baseParams);
    expect(result.html).toContain("https://ac3.aceofcloud.io/login");
  });

  it("includes MFA security tip", () => {
    const result = accountActivatedEmail(baseParams);
    expect(result.html).toContain("Multi-Factor Authentication");
  });
});

// ─── New Registration Alert Email ───────────────────────────────────────────

describe("newRegistrationAlertEmail", () => {
  const baseParams: NewRegistrationAlertParams = {
    newUserEmail: "newguy@example.com",
    newUserName: "New Guy",
    newUserRole: "analyst",
    registrationTime: new Date("2026-05-13T12:00:00Z"),
    baseUrl: "https://ac3.aceofcloud.io",
  };

  it("generates subject with user name and role", () => {
    const result = newRegistrationAlertEmail(baseParams);
    expect(result.subject).toContain("New Guy");
    expect(result.subject).toContain("Analyst");
  });

  it("includes registration details in HTML", () => {
    const result = newRegistrationAlertEmail(baseParams);
    expect(result.html).toContain("newguy@example.com");
    expect(result.html).toContain("New Guy");
    expect(result.html).toContain("Analyst");
  });

  it("includes inviter when provided", () => {
    const result = newRegistrationAlertEmail({
      ...baseParams,
      invitedBy: "Harrison Cook",
    });
    expect(result.html).toContain("Harrison Cook");
  });

  it("includes IP address when provided", () => {
    const result = newRegistrationAlertEmail({
      ...baseParams,
      ipAddress: "203.0.113.42",
    });
    expect(result.html).toContain("203.0.113.42");
  });

  it("links to team settings", () => {
    const result = newRegistrationAlertEmail(baseParams);
    expect(result.html).toContain("/settings/team");
  });
});

// ─── Security Alert Email ───────────────────────────────────────────────────

describe("securityAlertEmail", () => {
  const baseParams: SecurityAlertEmailParams = {
    alertType: "lockout",
    severity: "high",
    userEmail: "suspect@example.com",
    details: "Account locked after 5 failed login attempts",
    timestamp: new Date("2026-05-13T14:30:00Z"),
    baseUrl: "https://ac3.aceofcloud.io",
  };

  it("generates subject with severity and alert type", () => {
    const result = securityAlertEmail(baseParams);
    expect(result.subject).toContain("HIGH");
    expect(result.subject).toContain("Account Lockout");
  });

  it("includes alert details in HTML", () => {
    const result = securityAlertEmail(baseParams);
    expect(result.html).toContain("5 failed login attempts");
    expect(result.html).toContain("suspect@example.com");
  });

  it("uses correct severity styling for critical", () => {
    const result = securityAlertEmail({ ...baseParams, severity: "critical" });
    expect(result.html).toContain("alert-box");
    expect(result.html).toContain("CRITICAL");
  });

  it("uses warning styling for medium", () => {
    const result = securityAlertEmail({ ...baseParams, severity: "medium" });
    expect(result.html).toContain("warning-box");
  });

  it("includes IP address when provided", () => {
    const result = securityAlertEmail({
      ...baseParams,
      ipAddress: "198.51.100.23",
    });
    expect(result.html).toContain("198.51.100.23");
  });

  it("includes user name when provided", () => {
    const result = securityAlertEmail({
      ...baseParams,
      userName: "John Doe",
    });
    expect(result.html).toContain("John Doe");
  });

  it("links to audit log", () => {
    const result = securityAlertEmail(baseParams);
    expect(result.html).toContain("/settings/audit-log");
  });

  it("handles all alert types", () => {
    const types = ["lockout", "mfa_failure", "suspicious_login", "password_change", "role_change", "deactivation"] as const;
    for (const alertType of types) {
      const result = securityAlertEmail({ ...baseParams, alertType });
      expect(result.subject).toBeTruthy();
      expect(result.html).toBeTruthy();
      expect(result.text).toBeTruthy();
    }
  });
});

// ─── Daily Summary Email ────────────────────────────────────────────────────

describe("dailySummaryEmail", () => {
  const baseParams: DailySummaryEmailParams = {
    date: new Date("2026-05-13"),
    stats: {
      totalLogins: 42,
      failedLogins: 3,
      lockouts: 0,
      newRegistrations: 2,
      passwordResets: 1,
      activeUsers: 15,
    },
    recentAlerts: [
      { type: "Failed Login", user: "test@example.com", time: "14:30 UTC" },
    ],
    baseUrl: "https://ac3.aceofcloud.io",
  };

  it("generates subject with date", () => {
    const result = dailySummaryEmail(baseParams);
    expect(result.subject).toContain("Daily Security Summary");
  });

  it("includes stats in HTML", () => {
    const result = dailySummaryEmail(baseParams);
    expect(result.html).toContain("42");  // totalLogins
    expect(result.html).toContain("15");  // activeUsers
  });

  it("includes recent alerts in table", () => {
    const result = dailySummaryEmail(baseParams);
    expect(result.html).toContain("test@example.com");
    expect(result.html).toContain("Failed Login");
  });

  it("shows no alerts message when empty", () => {
    const result = dailySummaryEmail({ ...baseParams, recentAlerts: [] });
    expect(result.html).toContain("No security alerts today");
  });

  it("highlights high failed login counts", () => {
    const result = dailySummaryEmail({
      ...baseParams,
      stats: { ...baseParams.stats, failedLogins: 15 },
    });
    expect(result.html).toContain("#ef4444"); // red color for high failed logins
  });

  it("links to dashboard", () => {
    const result = dailySummaryEmail(baseParams);
    expect(result.html).toContain("/dashboard");
  });
});

// ─── Template Structure Tests ───────────────────────────────────────────────

describe("email template structure", () => {
  it("all templates include AC3 branding", () => {
    const invite = teamInviteEmail({
      recipientEmail: "a@b.com", inviterName: "X", role: "user",
      inviteToken: "t", baseUrl: "https://ac3.aceofcloud.io", expiresInHours: 72,
    });
    const reset = passwordResetEmail({
      recipientEmail: "a@b.com", resetToken: "t",
      baseUrl: "https://ac3.aceofcloud.io", expiresInMinutes: 30,
    });
    const activated = accountActivatedEmail({
      recipientEmail: "a@b.com", recipientName: "A", role: "user",
      baseUrl: "https://ac3.aceofcloud.io",
    });

    for (const email of [invite, reset, activated]) {
      expect(email.html).toContain("AC3");
      expect(email.html).toContain("AceofCloud");
      expect(email.html).toContain("ac3.aceofcloud.io");
    }
  });

  it("all templates have both HTML and plain text versions", () => {
    const invite = teamInviteEmail({
      recipientEmail: "a@b.com", inviterName: "X", role: "user",
      inviteToken: "t", baseUrl: "https://ac3.aceofcloud.io", expiresInHours: 72,
    });
    expect(invite.html).toContain("<!DOCTYPE html>");
    expect(invite.text).not.toContain("<");
  });

  it("all templates include do-not-reply notice", () => {
    const invite = teamInviteEmail({
      recipientEmail: "a@b.com", inviterName: "X", role: "user",
      inviteToken: "t", baseUrl: "https://ac3.aceofcloud.io", expiresInHours: 72,
    });
    expect(invite.html).toContain("do not reply");
  });
});
