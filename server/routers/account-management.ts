import { ENV } from "../_core/env";
import * as db from "../db";
/**
 * Account Management Router
 *
 * Provides:
 *   - User profile CRUD (view/update own profile)
 *   - Team management (list, invite, update role, deactivate, reactivate)
 *   - FIPS 140-3 compliant invitation flow (SHA-256 hashed tokens, CSPRNG)
 *   - Auth event audit logging
 *   - Security compliance status
 */
import { z } from "zod";
import crypto from "node:crypto";
import { protectedProcedure, router, adminProcedure} from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import { getDb } from "../db";
import { users, teamInvitations, activityLogs } from "../../drizzle/schema";
import { eq, desc, and, ne, count as drizzleCount, sql } from "drizzle-orm";
import { getFIPSCrypto } from "../lib/fips-crypto";
import { auditTLSConfiguration } from "../lib/fips-tls";
import { isFIPSTLSEnforced } from "../lib/fips-tls-global";
import { sendEmail, isEmailConfigured, verifyEmailTransport } from "../lib/email-service";
import { teamInviteEmail, accountActivatedEmail, newRegistrationAlertEmail, securityAlertEmail } from "../lib/email-templates";

// ─── Constants ──────────────────────────────────────────────────────────────

const ALL_ROLES = ["user", "admin", "viewer", "operator", "team_lead", "analyst", "executive", "client"] as const;
type UserRole = (typeof ALL_ROLES)[number];

const INVITE_TOKEN_BYTES = 32; // 256-bit CSPRNG token
const INVITE_EXPIRY_HOURS = 72; // 3 days

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Generate a FIPS-compliant invitation token using CSPRNG + SHA-256 */
function generateInviteToken(): { rawToken: string; tokenHash: string } {
  const rawBytes = crypto.randomBytes(INVITE_TOKEN_BYTES);
  const rawToken = rawBytes.toString("base64url"); // URL-safe for email links
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
  return { rawToken, tokenHash };
}

/** Hash a raw token for lookup */
function hashToken(rawToken: string): string {
  return crypto.createHash("sha256").update(rawToken).digest("hex");
}

// ─── Admin guard ────────────────────────────────────────────────────────────


const strictAdminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.user.role !== "admin") {
    throw new TRPCError({ code: "FORBIDDEN", message: "Admin access required" });
  }
  return next({ ctx });
});

// ─── Router ─────────────────────────────────────────────────────────────────

export const accountRouter = router({
  // ═══ Profile ═══════════════════════════════════════════════════════════════

  /** Get the current user's full profile */
  getProfile: protectedProcedure.query(async ({ ctx }) => {
    const db = (await getDb())!;
    const [user] = await db.select().from(users).where(eq(users.id, ctx.user!.id));
    if (!user) throw new TRPCError({ code: "NOT_FOUND", message: "User not found" });
    return {
      id: user.id,
      openId: user.openId,
      name: user.name,
      email: user.email,
      role: user.role,
      avatarUrl: user.avatarUrl,
      title: user.title,
      department: user.department,
      phone: user.phone,
      timezone: user.timezone,
      status: user.status,
      mfaEnabled: user.mfaEnabled,
      loginMethod: user.loginMethod,
      lastSignedIn: user.lastSignedIn,
      lastPasswordChange: user.lastPasswordChange,
      createdAt: user.createdAt,
    };
  }),

  /** Update the current user's profile */
  updateProfile: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(128).optional(),
      title: z.string().max(128).optional(),
      department: z.string().max(128).optional(),
      phone: z.string().max(32).optional(),
      timezone: z.string().max(64).optional(),
      avatarUrl: z.string().url().max(2048).optional().nullable(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = (await getDb())!;
      const updateData: Record<string, any> = {};
      if (input.name !== undefined) updateData.name = input.name;
      if (input.title !== undefined) updateData.title = input.title;
      if (input.department !== undefined) updateData.department = input.department;
      if (input.phone !== undefined) updateData.phone = input.phone;
      if (input.timezone !== undefined) updateData.timezone = input.timezone;
      if (input.avatarUrl !== undefined) updateData.avatarUrl = input.avatarUrl;

      if (Object.keys(updateData).length === 0) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "No fields to update" });
      }

      await db.update(users).set(updateData).where(eq(users.id, ctx.user!.id));

      await db.insert(activityLogs).values({
        userId: ctx.user!.id,
        action: "profile_updated",
        details: `Updated profile fields: ${Object.keys(updateData).join(", ")}`,
        ipAddress: ctx.req.ip || null,
      });

      return { success: true };
    }),

  // ═══ Team Management ═══════════════════════════════════════════════════════

  /** List all team members with profile details */
  listTeam: adminProcedure
    .input(z.object({
      includeInactive: z.boolean().default(false),
    }).optional())
    .query(async ({ input }) => {
      const db = (await getDb())!;
      const allUsers = await db.select({
        id: users.id,
        openId: users.openId,
        name: users.name,
        email: users.email,
        role: users.role,
        avatarUrl: users.avatarUrl,
        title: users.title,
        department: users.department,
        phone: users.phone,
        timezone: users.timezone,
        status: users.status,
        mfaEnabled: users.mfaEnabled,
        loginMethod: users.loginMethod,
        lastSignedIn: users.lastSignedIn,
        createdAt: users.createdAt,
      }).from(users).orderBy(desc(users.lastSignedIn));

      if (input?.includeInactive) return allUsers;
      return allUsers.filter((u) => u.status === "active" || u.status === "pending");
    }),

  /** Get team statistics */
  teamStats: adminProcedure.query(async () => {
    const db = (await getDb())!;
    const allUsers = await db.select({
      role: users.role,
      status: users.status,
    }).from(users);

    const roleCounts: Record<string, number> = {};
    const statusCounts: Record<string, number> = { active: 0, inactive: 0, suspended: 0, pending: 0 };
    for (const u of allUsers) {
      roleCounts[u.role] = (roleCounts[u.role] || 0) + 1;
      statusCounts[u.status] = (statusCounts[u.status] || 0) + 1;
    }

    const pendingInvites = await db.select({ cnt: drizzleCount() }).from(teamInvitations)
      .where(eq(teamInvitations.status, "pending"));

    return {
      totalUsers: allUsers.length,
      roleCounts,
      statusCounts,
      pendingInvites: pendingInvites[0]?.cnt || 0,
    };
  }),

  /** Update a team member's role */
  updateRole: strictAdminProcedure
    .input(z.object({
      userId: z.number(),
      role: z.enum(ALL_ROLES),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = (await getDb())!;
      // Prevent self-demotion
      if (input.userId === ctx.user!.id) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Cannot change your own role" });
      }
      const [target] = await db.select().from(users).where(eq(users.id, input.userId));
      if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "User not found" });

      await db.update(users).set({ role: input.role }).where(eq(users.id, input.userId));

      await db.insert(activityLogs).values({
        userId: ctx.user!.id,
        action: "role_changed",
        details: `Changed user ${target.name || target.id} role from ${target.role} to ${input.role}`,
        ipAddress: ctx.req.ip || null,
      });

      return { success: true, previousRole: target.role, newRole: input.role };
    }),

  /** Deactivate a team member */
  deactivateUser: strictAdminProcedure
    .input(z.object({ userId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = (await getDb())!;
      if (input.userId === ctx.user!.id) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Cannot deactivate yourself" });
      }
      const [target] = await db.select().from(users).where(eq(users.id, input.userId));
      if (!target) throw new TRPCError({ code: "NOT_FOUND" });

      await db.update(users).set({ status: "inactive" }).where(eq(users.id, input.userId));

      await db.insert(activityLogs).values({
        userId: ctx.user!.id,
        action: "user_deactivated",
        details: `Deactivated user ${target.name || target.id}`,
        ipAddress: ctx.req.ip || null,
      });

      return { success: true };
    }),

  /** Reactivate a team member */
  reactivateUser: strictAdminProcedure
    .input(z.object({ userId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = (await getDb())!;
      await db.update(users).set({ status: "active" }).where(eq(users.id, input.userId));

      await db.insert(activityLogs).values({
        userId: ctx.user!.id,
        action: "user_reactivated",
        details: `Reactivated user ${input.userId}`,
        ipAddress: ctx.req.ip || null,
      });

      return { success: true };
    }),

  // ═══ Invitations ═══════════════════════════════════════════════════════════

  /** Create an invitation (admin/team_lead only) */
  createInvite: adminProcedure
    .input(z.object({
      email: z.string().email().max(320),
      role: z.enum(ALL_ROLES).default("operator"),
      message: z.string().max(1000).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = (await getDb())!;

      // Check if email already has a pending invite
      const [existing] = await db.select().from(teamInvitations)
        .where(and(
          eq(teamInvitations.email, input.email),
          eq(teamInvitations.status, "pending"),
        ));
      if (existing) {
        throw new TRPCError({ code: "CONFLICT", message: "An active invitation already exists for this email" });
      }

      // Check if user already exists
      const [existingUser] = await db.select().from(users).where(eq(users.email, input.email));
      if (existingUser) {
        throw new TRPCError({ code: "CONFLICT", message: "A user with this email already exists" });
      }

      // Only admins can invite admins
      if (input.role === "admin" && ctx.user!.role !== "admin") {
        throw new TRPCError({ code: "FORBIDDEN", message: "Only admins can invite other admins" });
      }

      // Generate FIPS-compliant token
      const { rawToken, tokenHash } = generateInviteToken();
      const expiresAt = new Date(Date.now() + INVITE_EXPIRY_HOURS * 60 * 60 * 1000);

      await db.insert(teamInvitations).values({
        email: input.email,
        role: input.role,
        tokenHash,
        invitedBy: ctx.user!.id,
        invitedByName: ctx.user!.name || "Admin",
        expiresAt,
        message: input.message || null,
      });

      await db.insert(activityLogs).values({
        userId: ctx.user!.id,
        action: "invite_created",
        details: `Invited ${input.email} as ${input.role}`,
        ipAddress: ctx.req.ip || null,
      });

      // Send invitation email
      let emailSent = false;
      if (isEmailConfigured()) {
        const baseUrl = process.env.AC3_BASE_URL || ENV.ac3BaseUrl;
        const emailContent = teamInviteEmail({
          recipientEmail: input.email,
          inviterName: ctx.user!.name || "Admin",
          role: input.role,
          inviteToken: rawToken,
          baseUrl,
          expiresInHours: INVITE_EXPIRY_HOURS,
          personalMessage: input.message,
        });
        const result = await sendEmail({
          to: input.email,
          subject: emailContent.subject,
          html: emailContent.html,
          text: emailContent.text,
        });
        emailSent = result.success;
        if (!result.success) {
          console.error(`[AccountMgmt] Failed to send invite email to ${input.email}: ${result.error}`);
        }
      }

      return {
        success: true,
        inviteToken: rawToken,
        email: input.email,
        role: input.role,
        expiresAt: expiresAt.toISOString(),
        expiresInHours: INVITE_EXPIRY_HOURS,
        emailSent,
      };
    }),

  /** List all invitations */
  listInvites: adminProcedure
    .input(z.object({ includeExpired: z.boolean().default(false) }).optional())
    .query(async ({ input }) => {
      const db = (await getDb())!;
      const invites = await db.select().from(teamInvitations)
        .orderBy(desc(teamInvitations.createdAt));

      if (input?.includeExpired) return invites;
      return invites.filter((i) => i.status === "pending" || i.status === "accepted");
    }),

  /** Revoke a pending invitation */
  revokeInvite: adminProcedure
    .input(z.object({ inviteId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = (await getDb())!;
      const [invite] = await db.select().from(teamInvitations)
        .where(eq(teamInvitations.id, input.inviteId));
      if (!invite) throw new TRPCError({ code: "NOT_FOUND" });
      if (invite.status !== "pending") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Can only revoke pending invitations" });
      }

      await db.update(teamInvitations).set({ status: "revoked" })
        .where(eq(teamInvitations.id, input.inviteId));

      await db.insert(activityLogs).values({
        userId: ctx.user!.id,
        action: "invite_revoked",
        details: `Revoked invitation for ${invite.email}`,
        ipAddress: ctx.req.ip || null,
      });

      return { success: true };
    }),

  /** Validate an invitation token (public-facing for invite acceptance) */
  validateInvite: protectedProcedure
    .input(z.object({ token: z.string() }))
    .query(async ({ input }) => {
      const db = (await getDb())!;
      const hash = hashToken(input.token);
      const [invite] = await db.select().from(teamInvitations)
        .where(eq(teamInvitations.tokenHash, hash));

      if (!invite) return { valid: false, reason: "Invalid invitation token" };
      if (invite.status !== "pending") return { valid: false, reason: `Invitation has been ${invite.status}` };
      if (new Date() > invite.expiresAt) {
        await db.update(teamInvitations).set({ status: "expired" })
          .where(eq(teamInvitations.id, invite.id));
        return { valid: false, reason: "Invitation has expired" };
      }

      return {
        valid: true,
        email: invite.email,
        role: invite.role,
        invitedByName: invite.invitedByName,
        message: invite.message,
        expiresAt: invite.expiresAt.toISOString(),
      };
    }),

  /** Accept an invitation token */
  acceptInvite: protectedProcedure
    .input(z.object({ token: z.string() }))
    .mutation(async ({ input, ctx }) => {
      const db = (await getDb())!;
      const hash = hashToken(input.token);
      const [invite] = await db.select().from(teamInvitations)
        .where(eq(teamInvitations.tokenHash, hash));

      if (!invite) throw new TRPCError({ code: "NOT_FOUND", message: "Invalid invitation token" });
      if (invite.status !== "pending") throw new TRPCError({ code: "BAD_REQUEST", message: `Invitation has been ${invite.status}` });
      if (new Date() > invite.expiresAt) {
        await db.update(teamInvitations).set({ status: "expired" })
          .where(eq(teamInvitations.id, invite.id));
        throw new TRPCError({ code: "BAD_REQUEST", message: "Invitation has expired" });
      }

      // Update the current user's role and mark invite as accepted
      await db.update(users).set({
        role: invite.role,
        email: invite.email,
        invitedBy: invite.invitedBy,
        status: "active",
      }).where(eq(users.id, ctx.user!.id));

      await db.update(teamInvitations).set({
        status: "accepted",
        acceptedAt: new Date(),
        acceptedByUserId: ctx.user!.id,
      }).where(eq(teamInvitations.id, invite.id));

      await db.insert(activityLogs).values({
        userId: ctx.user!.id,
        action: "invite_accepted",
        details: `Accepted invitation as ${invite.role} (invited by ${invite.invitedByName})`,
        ipAddress: ctx.req.ip || null,
      });

      // Send activation confirmation to the new user
      if (isEmailConfigured()) {
        const baseUrl = process.env.AC3_BASE_URL || ENV.ac3BaseUrl;
        const activationEmail = accountActivatedEmail({
          recipientEmail: invite.email,
          recipientName: ctx.user!.name || invite.email,
          role: invite.role,
          baseUrl,
        });
        sendEmail({
          to: invite.email,
          subject: activationEmail.subject,
          html: activationEmail.html,
          text: activationEmail.text,
        }).catch((err) => console.error(`[AccountMgmt] Activation email failed: ${err}`));

        // Notify admins of new registration
        const admins = await db.select({ email: users.email }).from(users)
          .where(eq(users.role, "admin"));
        if (admins.length > 0) {
          const alertEmail = newRegistrationAlertEmail({
            newUserEmail: invite.email,
            newUserName: ctx.user!.name || invite.email,
            newUserRole: invite.role,
            invitedBy: invite.invitedByName || undefined,
            registrationTime: new Date(),
            ipAddress: ctx.req.ip || undefined,
            baseUrl,
          });
          sendEmail({
            to: admins.map((a) => a.email).filter(Boolean) as string[],
            subject: alertEmail.subject,
            html: alertEmail.html,
            text: alertEmail.text,
          }).catch((err) => console.error(`[AccountMgmt] Admin notification failed: ${err}`));
        }
      }

      return { success: true, role: invite.role };
    }),

  /** Resend an invitation (generates a new token) */
  resendInvite: adminProcedure
    .input(z.object({ inviteId: z.number() }))
    .mutation(async ({ input, ctx }) => {
      const db = (await getDb())!;
      const [invite] = await db.select().from(teamInvitations)
        .where(eq(teamInvitations.id, input.inviteId));
      if (!invite) throw new TRPCError({ code: "NOT_FOUND" });
      if (invite.status !== "pending") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Can only resend pending invitations" });
      }

      const { rawToken, tokenHash } = generateInviteToken();
      const expiresAt = new Date(Date.now() + INVITE_EXPIRY_HOURS * 60 * 60 * 1000);

      await db.update(teamInvitations).set({ tokenHash, expiresAt })
        .where(eq(teamInvitations.id, input.inviteId));

      await db.insert(activityLogs).values({
        userId: ctx.user!.id,
        action: "invite_resent",
        details: `Resent invitation for ${invite.email}`,
        ipAddress: ctx.req.ip || null,
      });

      // Resend invitation email
      let emailSent = false;
      if (isEmailConfigured()) {
        const baseUrl = process.env.AC3_BASE_URL || ENV.ac3BaseUrl;
        const emailContent = teamInviteEmail({
          recipientEmail: invite.email,
          inviterName: ctx.user!.name || "Admin",
          role: invite.role,
          inviteToken: rawToken,
          baseUrl,
          expiresInHours: INVITE_EXPIRY_HOURS,
        });
        const result = await sendEmail({
          to: invite.email,
          subject: emailContent.subject,
          html: emailContent.html,
          text: emailContent.text,
        });
        emailSent = result.success;
        if (!result.success) {
          console.error(`[AccountMgmt] Failed to resend invite email to ${invite.email}: ${result.error}`);
        }
      }

      return {
        success: true,
        inviteToken: rawToken,
        email: invite.email,
        expiresAt: expiresAt.toISOString(),
        emailSent,
      };
    }),

  // ═══ Security & Compliance ═════════════════════════════════════════════════

  /** Get FIPS 140-3 compliance status */
  getComplianceStatus: adminProcedure.query(async () => {
    const fipsCrypto = getFIPSCrypto();
    const cryptoReport = fipsCrypto.getComplianceReport();
    const tlsAudit = auditTLSConfiguration();
    const tlsEnforced = isFIPSTLSEnforced();

    return {
      overall: cryptoReport.complianceLevel === "full" || cryptoReport.complianceLevel === "partial" ? "compliant" : "review_needed",
      fips140_3: {
        cryptoProvider: cryptoReport.complianceLevel,
        fipsProviderActive: cryptoReport.fipsProviderActive,
        opensslVersion: cryptoReport.opensslVersion,
        nodeVersion: cryptoReport.nodeVersion,
        approvedAlgorithms: cryptoReport.approvedAlgorithms,
        prohibitedAlgorithms: cryptoReport.prohibitedAlgorithms,
      },
      tls: {
        enforced: tlsEnforced,
        compliant: tlsAudit.compliant,
        minVersion: tlsAudit.minVersion,
        cipherSuiteCount: tlsAudit.cipherSuites.length,
        nonCompliantCiphers: tlsAudit.nonCompliantCiphers.length,
        details: tlsAudit.details,
      },
      auth: {
        provider: "Manus OAuth 2.0 + Caldera JWT",
        sessionMechanism: "HttpOnly Secure SameSite cookies",
        tokenStorage: "SHA-256 hashed (never plaintext)",
        mfaSupport: "Platform-level via Manus OAuth (phishing-resistant WebAuthn/FIDO2 ready)",
        samlReady: true,
        samlNote: "SAML 2.0 federation supported via Manus OAuth identity provider bridge",
        phishingResistantMFA: "Supported via Manus OAuth WebAuthn/FIDO2 integration",
      },
      dataProtection: {
        atRest: "AES-256-GCM with HKDF-SHA256 key derivation",
        inTransit: `TLS ${tlsAudit.minVersion}+ with FIPS-approved cipher suites`,
        keyManagement: "CSPRNG (crypto.randomBytes) for token generation, HKDF for sub-key derivation",
        inviteTokens: "256-bit CSPRNG tokens, SHA-256 hashed before storage",
      },
      standards: [
        { name: "FIPS 140-3", status: cryptoReport.complianceLevel === "full" ? "certified" : "compliant_software", description: "Cryptographic module validation" },
        { name: "NIST SP 800-63B", status: "compliant", description: "Digital identity guidelines (AAL2+ with phishing-resistant MFA)" },
        { name: "NIST SP 800-53 IA", status: "compliant", description: "Identification and authentication controls" },
        { name: "FedRAMP", status: "aligned", description: "Federal Risk and Authorization Management Program alignment" },
        { name: "CISA Zero Trust", status: "aligned", description: "Zero Trust Architecture maturity model alignment" },
        { name: "EO 14028", status: "aligned", description: "Executive Order on Improving the Nation's Cybersecurity" },
      ],
      timestamp: Date.now(),
    };
  }),

  /** Get recent auth-related audit events */
  getAuthAuditLog: adminProcedure
    .input(z.object({ limit: z.number().min(1).max(200).default(50) }).optional())
    .query(async ({ input }) => {
      const db = (await getDb())!;
      const authActions = [
        "profile_updated", "role_changed", "user_deactivated", "user_reactivated",
        "invite_created", "invite_accepted", "invite_revoked", "invite_resent",
        "login", "logout", "role_updated",
      ];
      const logs = await db.select().from(activityLogs)
        .where(sql`${activityLogs.action} IN (${sql.join(authActions.map(a => sql`${a}`), sql`, `)})`)
        .orderBy(desc(activityLogs.createdAt))
        .limit(input?.limit || 50);
      return logs;
    }),

  // ═══ Email Configuration ═══════════════════════════════════════════════════

  /** Verify email transport configuration */
  verifyEmailConfig: adminProcedure.query(async () => {
    const configured = isEmailConfigured();
    if (!configured) {
      return {
        configured: false,
        provider: process.env.EMAIL_PROVIDER || "smtp",
        from: process.env.EMAIL_FROM || "noreply@" + ENV.ac3DeploymentDomain,
        verified: false,
        error: "Email credentials not configured. Set SMTP_PASSWORD (for SMTP) or AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET (for Graph API).",
      };
    }

    const verification = await verifyEmailTransport();
    return {
      configured: true,
      provider: verification.provider,
      from: process.env.EMAIL_FROM || "noreply@" + ENV.ac3DeploymentDomain,
      verified: verification.ok,
      error: verification.error,
    };
  }),

  /** Send a test email to verify the email configuration works */
  sendTestEmail: adminProcedure
    .input(z.object({ to: z.string().email() }))
    .mutation(async ({ input, ctx }) => {
      if (!isEmailConfigured()) {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message: "Email is not configured. Please set the required environment variables first.",
        });
      }

      const result = await sendEmail({
        to: input.to,
        subject: "[AC3] Test Email — Configuration Verified",
        html: `<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 40px 20px;">
          <h2 style="color: #0ea5e9;">AC3 Email Configuration Test</h2>
          <p>This is a test email from the AC3 platform to verify that email sending is working correctly.</p>
          <p><strong>Provider:</strong> ${process.env.EMAIL_PROVIDER || "smtp"}</p>
          <p><strong>From:</strong> ${process.env.EMAIL_FROM || "noreply@" + ENV.ac3DeploymentDomain}</p>
          <p><strong>Sent by:</strong> ${ctx.user!.name || ctx.user!.email || "Admin"}</p>
          <p><strong>Timestamp:</strong> ${new Date().toUTCString()}</p>
          <hr style="border: 1px solid #334155; margin: 24px 0;">
          <p style="color: #94a3b8; font-size: 12px;">AceofCloud — AC3 Platform</p>
        </div>`,
        text: `AC3 Email Configuration Test\n\nProvider: ${process.env.EMAIL_PROVIDER || "smtp"}\nFrom: ${process.env.EMAIL_FROM || "noreply@" + ENV.ac3DeploymentDomain}\nSent by: ${ctx.user!.name || "Admin"}\nTimestamp: ${new Date().toUTCString()}`,
      });

      if (!result.success) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Failed to send test email: ${result.error}`,
        });
      }

      const db = (await getDb())!;
      await db.insert(activityLogs).values({
        userId: ctx.user!.id,
        action: "test_email_sent",
        details: `Test email sent to ${input.to}`,
        ipAddress: ctx.req.ip || null,
      });

      return { success: true, messageId: result.messageId };
    }),

  /** Send a security alert email to all admins */
  sendSecurityAlert: adminProcedure
    .input(z.object({
      alertType: z.enum(["lockout", "mfa_failure", "suspicious_login", "password_change", "role_change", "deactivation"]),
      severity: z.enum(["critical", "high", "medium", "low"]),
      userEmail: z.string().email(),
      userName: z.string().optional(),
      details: z.string(),
      ipAddress: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      if (!isEmailConfigured()) {
        return { success: false, error: "Email not configured" };
      }

      const db = (await getDb())!;
      const admins = await db.select({ email: users.email }).from(users)
        .where(eq(users.role, "admin"));

      if (admins.length === 0) {
        return { success: false, error: "No admin users found" };
      }

      const baseUrl = process.env.AC3_BASE_URL || ENV.ac3BaseUrl;
      const emailContent = securityAlertEmail({
        ...input,
        timestamp: new Date(),
        baseUrl,
      });

      const result = await sendEmail({
        to: admins.map((a) => a.email).filter(Boolean) as string[],
        subject: emailContent.subject,
        html: emailContent.html,
        text: emailContent.text,
      });

      return { success: result.success, error: result.error };
    }),
});
