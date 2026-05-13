/**
 * AC3 Platform Email Templates
 * 
 * Professional HTML email templates for:
 *   - Team member invitations
 *   - Password reset
 *   - Account activation confirmation
 *   - Admin security alerts
 *   - New registration notifications
 */

// ─── Base Layout ────────────────────────────────────────────────────────────

const BRAND_COLOR = "#0ea5e9"; // Sky-500
const BRAND_DARK = "#0284c7";  // Sky-600
const BG_COLOR = "#0f172a";    // Slate-900
const CARD_BG = "#1e293b";     // Slate-800
const TEXT_COLOR = "#e2e8f0";  // Slate-200
const MUTED_COLOR = "#94a3b8"; // Slate-400
const BORDER_COLOR = "#334155"; // Slate-700

function baseLayout(content: string, preheader?: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>AC3 Platform</title>
  ${preheader ? `<span style="display:none;font-size:1px;color:#0f172a;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;">${preheader}</span>` : ""}
  <style>
    body { margin: 0; padding: 0; background-color: ${BG_COLOR}; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }
    .container { max-width: 600px; margin: 0 auto; padding: 40px 20px; }
    .card { background-color: ${CARD_BG}; border: 1px solid ${BORDER_COLOR}; border-radius: 12px; padding: 32px; }
    .logo { text-align: center; margin-bottom: 24px; }
    .logo-text { font-size: 28px; font-weight: 700; color: ${BRAND_COLOR}; letter-spacing: -0.5px; }
    .logo-sub { font-size: 12px; color: ${MUTED_COLOR}; text-transform: uppercase; letter-spacing: 2px; margin-top: 4px; }
    h1 { color: ${TEXT_COLOR}; font-size: 22px; font-weight: 600; margin: 0 0 16px 0; }
    p { color: ${MUTED_COLOR}; font-size: 15px; line-height: 1.6; margin: 0 0 16px 0; }
    .btn { display: inline-block; background-color: ${BRAND_COLOR}; color: #ffffff !important; text-decoration: none; padding: 12px 28px; border-radius: 8px; font-size: 15px; font-weight: 600; margin: 8px 0; }
    .btn:hover { background-color: ${BRAND_DARK}; }
    .btn-center { text-align: center; margin: 24px 0; }
    .info-box { background-color: rgba(14, 165, 233, 0.1); border: 1px solid rgba(14, 165, 233, 0.2); border-radius: 8px; padding: 16px; margin: 16px 0; }
    .info-box p { color: ${TEXT_COLOR}; margin: 0; font-size: 14px; }
    .info-label { color: ${MUTED_COLOR}; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }
    .info-value { color: ${TEXT_COLOR}; font-size: 16px; font-weight: 600; font-family: 'Courier New', monospace; word-break: break-all; }
    .warning-box { background-color: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 8px; padding: 16px; margin: 16px 0; }
    .warning-box p { color: #fbbf24; margin: 0; font-size: 14px; }
    .alert-box { background-color: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 8px; padding: 16px; margin: 16px 0; }
    .alert-box p { color: #f87171; margin: 0; font-size: 14px; }
    .divider { border: 0; border-top: 1px solid ${BORDER_COLOR}; margin: 24px 0; }
    .footer { text-align: center; margin-top: 24px; }
    .footer p { color: ${MUTED_COLOR}; font-size: 12px; line-height: 1.5; }
    .footer a { color: ${BRAND_COLOR}; text-decoration: none; }
    .detail-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid ${BORDER_COLOR}; }
    .detail-label { color: ${MUTED_COLOR}; font-size: 13px; }
    .detail-value { color: ${TEXT_COLOR}; font-size: 13px; font-weight: 500; }
    table.details { width: 100%; border-collapse: collapse; margin: 16px 0; }
    table.details td { padding: 8px 0; font-size: 14px; vertical-align: top; }
    table.details td.label { color: ${MUTED_COLOR}; width: 140px; }
    table.details td.value { color: ${TEXT_COLOR}; font-weight: 500; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">
      <div class="logo-text">AC3</div>
      <div class="logo-sub">Automated Cyber Command &amp; Control</div>
    </div>
    <div class="card">
      ${content}
    </div>
    <div class="footer">
      <p>
        AceofCloud &mdash; AC3 Platform<br>
        <a href="https://ac3.aceofcloud.io">ac3.aceofcloud.io</a>
      </p>
      <p>This is an automated message from the AC3 platform.<br>
      Please do not reply directly to this email.</p>
    </div>
  </div>
</body>
</html>`;
}

// ─── Team Invitation ────────────────────────────────────────────────────────

export interface InviteEmailParams {
  recipientEmail: string;
  recipientName?: string;
  inviterName: string;
  role: string;
  inviteToken: string;
  baseUrl: string;
  expiresInHours: number;
  personalMessage?: string;
}

export function teamInviteEmail(params: InviteEmailParams): { subject: string; html: string; text: string } {
  const inviteUrl = `${params.baseUrl}/accept-invite?token=${encodeURIComponent(params.inviteToken)}`;
  const greeting = params.recipientName ? `Hello ${params.recipientName},` : "Hello,";
  const roleDisplay = params.role.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

  const content = `
    <h1>You're Invited to AC3</h1>
    <p>${greeting}</p>
    <p><strong>${params.inviterName}</strong> has invited you to join the AC3 platform as a <strong>${roleDisplay}</strong>.</p>
    ${params.personalMessage ? `
    <div class="info-box">
      <p class="info-label">Message from ${params.inviterName}</p>
      <p>${params.personalMessage}</p>
    </div>` : ""}
    <p>AC3 (Automated Cyber Command &amp; Control) is an advanced offensive security platform for penetration testing, vulnerability assessment, and security operations.</p>
    <div class="btn-center">
      <a href="${inviteUrl}" class="btn">Accept Invitation</a>
    </div>
    <div class="warning-box">
      <p>&#9888; This invitation expires in <strong>${params.expiresInHours} hours</strong>. After that, you'll need to request a new invitation from your administrator.</p>
    </div>
    <hr class="divider">
    <p style="font-size: 13px;">If the button doesn't work, copy and paste this URL into your browser:</p>
    <p style="font-size: 12px; word-break: break-all; color: ${BRAND_COLOR};">${inviteUrl}</p>
  `;

  const text = `You're Invited to AC3

${greeting}

${params.inviterName} has invited you to join the AC3 platform as a ${roleDisplay}.

${params.personalMessage ? `Message: ${params.personalMessage}\n` : ""}
Accept your invitation: ${inviteUrl}

This invitation expires in ${params.expiresInHours} hours.

---
AceofCloud — AC3 Platform
https://ac3.aceofcloud.io`;

  return {
    subject: `You're invited to join AC3 by ${params.inviterName}`,
    html: baseLayout(content, `${params.inviterName} invited you to join the AC3 platform as a ${roleDisplay}`),
    text,
  };
}

// ─── Password Reset ─────────────────────────────────────────────────────────

export interface PasswordResetEmailParams {
  recipientEmail: string;
  recipientName?: string;
  resetToken: string;
  baseUrl: string;
  expiresInMinutes: number;
  ipAddress?: string;
  userAgent?: string;
}

export function passwordResetEmail(params: PasswordResetEmailParams): { subject: string; html: string; text: string } {
  const resetUrl = `${params.baseUrl}/reset-password?token=${encodeURIComponent(params.resetToken)}`;
  const greeting = params.recipientName ? `Hello ${params.recipientName},` : "Hello,";

  const content = `
    <h1>Password Reset Request</h1>
    <p>${greeting}</p>
    <p>We received a request to reset your AC3 account password. Click the button below to create a new password.</p>
    <div class="btn-center">
      <a href="${resetUrl}" class="btn">Reset Password</a>
    </div>
    <div class="warning-box">
      <p>&#9888; This link expires in <strong>${params.expiresInMinutes} minutes</strong>. If you didn't request this reset, you can safely ignore this email — your password will remain unchanged.</p>
    </div>
    ${params.ipAddress ? `
    <table class="details">
      <tr><td class="label">Request IP</td><td class="value">${params.ipAddress}</td></tr>
      ${params.userAgent ? `<tr><td class="label">Browser</td><td class="value">${params.userAgent}</td></tr>` : ""}
      <tr><td class="label">Time</td><td class="value">${new Date().toUTCString()}</td></tr>
    </table>` : ""}
    <hr class="divider">
    <p style="font-size: 13px;">If the button doesn't work, copy and paste this URL into your browser:</p>
    <p style="font-size: 12px; word-break: break-all; color: ${BRAND_COLOR};">${resetUrl}</p>
  `;

  const text = `Password Reset Request

${greeting}

We received a request to reset your AC3 account password.

Reset your password: ${resetUrl}

This link expires in ${params.expiresInMinutes} minutes.

If you didn't request this, you can safely ignore this email.

---
AceofCloud — AC3 Platform
https://ac3.aceofcloud.io`;

  return {
    subject: "AC3 Password Reset Request",
    html: baseLayout(content, "Reset your AC3 account password"),
    text,
  };
}

// ─── Account Activation Confirmation ────────────────────────────────────────

export interface AccountActivatedEmailParams {
  recipientEmail: string;
  recipientName: string;
  role: string;
  baseUrl: string;
}

export function accountActivatedEmail(params: AccountActivatedEmailParams): { subject: string; html: string; text: string } {
  const roleDisplay = params.role.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  const loginUrl = `${params.baseUrl}/login`;

  const content = `
    <h1>Welcome to AC3, ${params.recipientName}!</h1>
    <p>Your account has been successfully activated. You can now sign in and start using the AC3 platform.</p>
    <table class="details">
      <tr><td class="label">Email</td><td class="value">${params.recipientEmail}</td></tr>
      <tr><td class="label">Role</td><td class="value">${roleDisplay}</td></tr>
    </table>
    <div class="btn-center">
      <a href="${loginUrl}" class="btn">Sign In to AC3</a>
    </div>
    <div class="info-box">
      <p><strong>Security Tip:</strong> We recommend enabling Multi-Factor Authentication (MFA) in your account settings for enhanced security.</p>
    </div>
  `;

  const text = `Welcome to AC3, ${params.recipientName}!

Your account has been activated.

Email: ${params.recipientEmail}
Role: ${roleDisplay}

Sign in: ${loginUrl}

Security Tip: Enable MFA in your account settings for enhanced security.

---
AceofCloud — AC3 Platform
https://ac3.aceofcloud.io`;

  return {
    subject: "Welcome to AC3 — Account Activated",
    html: baseLayout(content, `Welcome to AC3, ${params.recipientName}! Your account is ready.`),
    text,
  };
}

// ─── Admin: New Registration Notification ───────────────────────────────────

export interface NewRegistrationAlertParams {
  newUserEmail: string;
  newUserName: string;
  newUserRole: string;
  invitedBy?: string;
  registrationTime: Date;
  ipAddress?: string;
  baseUrl: string;
}

export function newRegistrationAlertEmail(params: NewRegistrationAlertParams): { subject: string; html: string; text: string } {
  const roleDisplay = params.newUserRole.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  const adminUrl = `${params.baseUrl}/settings/team`;

  const content = `
    <h1>New Team Member Registered</h1>
    <p>A new user has completed their account registration on the AC3 platform.</p>
    <table class="details">
      <tr><td class="label">Name</td><td class="value">${params.newUserName}</td></tr>
      <tr><td class="label">Email</td><td class="value">${params.newUserEmail}</td></tr>
      <tr><td class="label">Role</td><td class="value">${roleDisplay}</td></tr>
      ${params.invitedBy ? `<tr><td class="label">Invited By</td><td class="value">${params.invitedBy}</td></tr>` : ""}
      <tr><td class="label">Registered At</td><td class="value">${params.registrationTime.toUTCString()}</td></tr>
      ${params.ipAddress ? `<tr><td class="label">IP Address</td><td class="value">${params.ipAddress}</td></tr>` : ""}
    </table>
    <div class="btn-center">
      <a href="${adminUrl}" class="btn">View Team Settings</a>
    </div>
  `;

  const text = `New Team Member Registered

Name: ${params.newUserName}
Email: ${params.newUserEmail}
Role: ${roleDisplay}
${params.invitedBy ? `Invited By: ${params.invitedBy}` : ""}
Registered: ${params.registrationTime.toUTCString()}

View team: ${adminUrl}

---
AceofCloud — AC3 Platform`;

  return {
    subject: `[AC3] New Registration: ${params.newUserName} (${roleDisplay})`,
    html: baseLayout(content, `${params.newUserName} just registered as ${roleDisplay}`),
    text,
  };
}

// ─── Admin: Security Alert ──────────────────────────────────────────────────

export interface SecurityAlertEmailParams {
  alertType: "lockout" | "mfa_failure" | "suspicious_login" | "password_change" | "role_change" | "deactivation";
  severity: "critical" | "high" | "medium" | "low";
  userEmail: string;
  userName?: string;
  details: string;
  ipAddress?: string;
  timestamp: Date;
  baseUrl: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

const ALERT_TYPE_LABELS: Record<string, string> = {
  lockout: "Account Lockout",
  mfa_failure: "MFA Verification Failed",
  suspicious_login: "Suspicious Login Attempt",
  password_change: "Password Changed",
  role_change: "Role Modified",
  deactivation: "Account Deactivated",
};

export function securityAlertEmail(params: SecurityAlertEmailParams): { subject: string; html: string; text: string } {
  const severityColor = SEVERITY_COLORS[params.severity] || SEVERITY_COLORS.medium;
  const alertLabel = ALERT_TYPE_LABELS[params.alertType] || params.alertType;
  const auditUrl = `${params.baseUrl}/settings/audit-log`;

  const content = `
    <h1 style="color: ${severityColor};">&#9888; Security Alert: ${alertLabel}</h1>
    <p>A security event has been detected on the AC3 platform that requires your attention.</p>
    <div class="${params.severity === "critical" || params.severity === "high" ? "alert-box" : "warning-box"}">
      <p><strong>Severity:</strong> ${params.severity.toUpperCase()}</p>
      <p>${params.details}</p>
    </div>
    <table class="details">
      <tr><td class="label">Event Type</td><td class="value">${alertLabel}</td></tr>
      <tr><td class="label">User</td><td class="value">${params.userName || params.userEmail}</td></tr>
      <tr><td class="label">Email</td><td class="value">${params.userEmail}</td></tr>
      ${params.ipAddress ? `<tr><td class="label">IP Address</td><td class="value">${params.ipAddress}</td></tr>` : ""}
      <tr><td class="label">Timestamp</td><td class="value">${params.timestamp.toUTCString()}</td></tr>
    </table>
    <div class="btn-center">
      <a href="${auditUrl}" class="btn">View Audit Log</a>
    </div>
  `;

  const text = `Security Alert: ${alertLabel}

Severity: ${params.severity.toUpperCase()}
${params.details}

User: ${params.userName || params.userEmail}
Email: ${params.userEmail}
${params.ipAddress ? `IP: ${params.ipAddress}` : ""}
Time: ${params.timestamp.toUTCString()}

View audit log: ${auditUrl}

---
AceofCloud — AC3 Platform`;

  return {
    subject: `[AC3 ${params.severity.toUpperCase()}] ${alertLabel}: ${params.userEmail}`,
    html: baseLayout(content, `Security alert: ${alertLabel} for ${params.userEmail}`),
    text,
  };
}

// ─── Admin: Daily Summary ───────────────────────────────────────────────────

export interface DailySummaryEmailParams {
  date: Date;
  stats: {
    totalLogins: number;
    failedLogins: number;
    lockouts: number;
    newRegistrations: number;
    passwordResets: number;
    activeUsers: number;
  };
  recentAlerts: Array<{ type: string; user: string; time: string }>;
  baseUrl: string;
}

export function dailySummaryEmail(params: DailySummaryEmailParams): { subject: string; html: string; text: string } {
  const dateStr = params.date.toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" });
  const dashboardUrl = `${params.baseUrl}/dashboard`;

  const alertRows = params.recentAlerts.length > 0
    ? params.recentAlerts.map((a) => `<tr><td class="value">${a.type}</td><td class="value">${a.user}</td><td class="value">${a.time}</td></tr>`).join("")
    : `<tr><td colspan="3" class="label" style="text-align: center; padding: 16px;">No security alerts today</td></tr>`;

  const content = `
    <h1>Daily Security Summary</h1>
    <p>${dateStr}</p>
    <table class="details">
      <tr><td class="label">Total Logins</td><td class="value">${params.stats.totalLogins}</td></tr>
      <tr><td class="label">Failed Logins</td><td class="value" style="color: ${params.stats.failedLogins > 10 ? "#ef4444" : TEXT_COLOR};">${params.stats.failedLogins}</td></tr>
      <tr><td class="label">Account Lockouts</td><td class="value" style="color: ${params.stats.lockouts > 0 ? "#f97316" : TEXT_COLOR};">${params.stats.lockouts}</td></tr>
      <tr><td class="label">New Registrations</td><td class="value">${params.stats.newRegistrations}</td></tr>
      <tr><td class="label">Password Resets</td><td class="value">${params.stats.passwordResets}</td></tr>
      <tr><td class="label">Active Users</td><td class="value">${params.stats.activeUsers}</td></tr>
    </table>
    <hr class="divider">
    <h1 style="font-size: 18px;">Recent Alerts</h1>
    <table style="width: 100%; border-collapse: collapse;">
      <thead>
        <tr style="border-bottom: 1px solid ${BORDER_COLOR};">
          <th style="text-align: left; padding: 8px 0; color: ${MUTED_COLOR}; font-size: 12px;">Type</th>
          <th style="text-align: left; padding: 8px 0; color: ${MUTED_COLOR}; font-size: 12px;">User</th>
          <th style="text-align: left; padding: 8px 0; color: ${MUTED_COLOR}; font-size: 12px;">Time</th>
        </tr>
      </thead>
      <tbody>${alertRows}</tbody>
    </table>
    <div class="btn-center">
      <a href="${dashboardUrl}" class="btn">Open Dashboard</a>
    </div>
  `;

  const text = `Daily Security Summary — ${dateStr}

Logins: ${params.stats.totalLogins} | Failed: ${params.stats.failedLogins} | Lockouts: ${params.stats.lockouts}
New Registrations: ${params.stats.newRegistrations} | Resets: ${params.stats.passwordResets} | Active: ${params.stats.activeUsers}

Dashboard: ${dashboardUrl}

---
AceofCloud — AC3 Platform`;

  return {
    subject: `[AC3] Daily Security Summary — ${dateStr}`,
    html: baseLayout(content, `AC3 daily summary: ${params.stats.totalLogins} logins, ${params.stats.failedLogins} failed`),
    text,
  };
}
